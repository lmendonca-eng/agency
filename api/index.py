import os
import json
import time
import base64
import hashlib
import hmac
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, quote, urlparse, parse_qs
from http.server import BaseHTTPRequestHandler

import requests
from cryptography.fernet import Fernet, InvalidToken

# --- Configuration ---
CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
DATAFORSEO_AUTH = os.environ.get("DATAFORSEO_AUTH", "")  # optional: base64("login:password")
SCOPES = "openid email profile https://www.googleapis.com/auth/webmasters.readonly"
TOKEN_URL = "https://oauth2.googleapis.com/token"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
GSC_API = "https://www.googleapis.com/webmasters/v3"
GSC_SEARCH_ANALYTICS = "https://searchconsole.googleapis.com/webmasters/v3"
DATAFORSEO_VOLUME_URL = "https://api.dataforseo.com/v3/keywords_data/google_ads/search_volume/live"
SESSION_TTL = 86400 * 7
GSC_DATA_DELAY_DAYS = 3  # GSC data lags 2-3 days
CLIENTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "clients.json")


def secret_configured() -> bool:
    return len(JWT_SECRET) >= 16 and JWT_SECRET != "change-me-in-production"


def get_redirect_uri(headers):
    proto = headers.get("x-forwarded-proto", "https")
    host = headers.get("x-forwarded-host") or headers.get("host", "localhost:3000")
    return f"{proto}://{host}/api/auth/callback"


# --- Encrypted session helpers ---
# The session holds Google OAuth tokens, so it is encrypted (Fernet: AES + HMAC), not just signed.
def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(JWT_SECRET.encode()).digest())
    return Fernet(key)


def session_encode(payload: dict) -> str:
    return _fernet().encrypt(json.dumps(payload).encode()).decode()


def session_decode(token: str) -> dict | None:
    try:
        return json.loads(_fernet().decrypt(token.encode(), ttl=SESSION_TTL))
    except (InvalidToken, ValueError):
        return None


# --- Cookie helpers ---
def parse_cookies(cookie_header: str) -> dict:
    cookies = {}
    if cookie_header:
        for item in cookie_header.split(";"):
            item = item.strip()
            if "=" in item:
                k, v = item.split("=", 1)
                cookies[k.strip()] = v.strip()
    return cookies


def set_cookie(name, value, max_age=SESSION_TTL):
    return f"{name}={value}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age={max_age}"


def clear_cookie(name):
    return f"{name}=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0"


# --- Token refresh ---
def refresh_access_token(refresh_token: str) -> dict | None:
    resp = requests.post(TOKEN_URL, data={
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }, timeout=20)
    if resp.status_code == 200:
        return resp.json()
    return None


def get_valid_access_token(session: dict) -> tuple[str | None, bool]:
    """Return (access_token, refreshed). Refreshes and updates the session if expired."""
    expires_at = session.get("token_expires_at", 0)
    if time.time() < expires_at - 60:
        return session.get("access_token"), False
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        return None, False
    new_tokens = refresh_access_token(refresh_token)
    if not new_tokens:
        return None, False
    session["access_token"] = new_tokens["access_token"]
    session["token_expires_at"] = time.time() + new_tokens.get("expires_in", 3600)
    return new_tokens["access_token"], True


# --- Date periods ---
def period(days: int, periods_back: int = 0) -> tuple[str, str]:
    """Inclusive (start, end) covering exactly `days` days; periods_back=1 is the period right before."""
    end = datetime.now(timezone.utc).date() - timedelta(days=GSC_DATA_DELAY_DAYS + periods_back * days)
    start = end - timedelta(days=days - 1)
    return start.isoformat(), end.isoformat()


def parse_days(params: dict) -> int:
    try:
        days = int(params.get("days", "28"))
    except ValueError:
        days = 28
    return max(1, min(days, 480))


# --- GSC API helpers ---
def gsc_list_sites(access_token: str) -> list:
    resp = requests.get(f"{GSC_API}/sites", headers={"Authorization": f"Bearer {access_token}"}, timeout=30)
    if resp.status_code == 200:
        return resp.json().get("siteEntry", [])
    return []


def gsc_query(access_token: str, site_url: str, start_date: str, end_date: str,
              dimensions: list, row_limit: int = 25, start_row: int = 0,
              dimension_filters: list = None) -> dict:
    body = {
        "startDate": start_date,
        "endDate": end_date,
        "dimensions": dimensions,
        "rowLimit": row_limit,
        "startRow": start_row,
    }
    if dimension_filters:
        body["dimensionFilterGroups"] = [{"filters": dimension_filters}]
    encoded_site = quote(site_url, safe="")
    resp = requests.post(
        f"{GSC_SEARCH_ANALYTICS}/sites/{encoded_site}/searchAnalytics/query",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        json=body,
        timeout=60,
    )
    if resp.status_code == 200:
        return resp.json()
    return {"rows": [], "error": resp.text}


def gsc_totals(result: dict) -> dict:
    """Totals from a dimensionless query; GSC already weights position by impressions."""
    rows = result.get("rows") or []
    if not rows:
        return {"clicks": 0, "impressions": 0, "ctr": 0, "position": 0}
    r = rows[0]
    return {k: r.get(k, 0) for k in ("clicks", "impressions", "ctr", "position")}


def run_parallel(tasks: dict) -> dict:
    """Run {name: callable} concurrently and return {name: result}."""
    with ThreadPoolExecutor(max_workers=min(8, len(tasks))) as pool:
        futures = {name: pool.submit(fn) for name, fn in tasks.items()}
        return {name: f.result() for name, f in futures.items()}


def combine(metrics: list) -> dict:
    """Sum clicks/impressions across rows; impression-weighted position."""
    clicks = sum(m.get("clicks", 0) for m in metrics)
    impressions = sum(m.get("impressions", 0) for m in metrics)
    weighted = sum(m.get("position", 0) * m.get("impressions", 0) for m in metrics)
    return {
        "clicks": clicks,
        "impressions": impressions,
        "ctr": clicks / impressions if impressions else 0,
        "position": weighted / impressions if impressions else 0,
    }


# --- Clients & tracked pages ---
def load_clients() -> list:
    """Client roster from the CLIENTS_JSON env var (keeps it out of the public repo), else api/clients.json."""
    try:
        raw = os.environ.get("CLIENTS_JSON")
        if raw:
            return json.loads(raw).get("clients", [])
        with open(CLIENTS_FILE, encoding="utf-8") as f:
            return json.load(f).get("clients", [])
    except (OSError, ValueError):
        return []


def site_host(site_url: str) -> str:
    if site_url.startswith("sc-domain:"):
        return site_url[len("sc-domain:"):].lower()
    host = (urlparse(site_url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def match_client(site_url: str, clients: list) -> dict | None:
    host = site_host(site_url)
    domain_property = site_url.startswith("sc-domain:")
    for c in clients:
        for d in c.get("domains", []):
            d = d.lower()
            if host == d or host.endswith("." + d) or (domain_property and d.endswith("." + host)):
                return c
    return None


def page_path(url: str) -> str:
    return (urlparse(url).path.rstrip("/") or "/").lower()


# --- DataForSEO (optional) ---
def fetch_volumes(keywords: list, location_code: int) -> dict:
    resp = requests.post(
        DATAFORSEO_VOLUME_URL,
        headers={"Authorization": f"Basic {DATAFORSEO_AUTH}", "Content-Type": "application/json"},
        json=[{"keywords": keywords, "location_code": location_code, "language_code": "en"}],
        timeout=120,
    )
    data = resp.json()
    task = (data.get("tasks") or [{}])[0]
    if task.get("status_code") != 20000:
        raise RuntimeError(task.get("status_message") or data.get("status_message") or "DataForSEO error")
    return {item["keyword"]: item.get("search_volume") for item in task.get("result") or []}


# --- Request handler ---
class handler(BaseHTTPRequestHandler):

    def _send_json(self, data, status=200, cookies=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        for c in (cookies or []) + ([self._session_cookie] if getattr(self, "_session_cookie", None) else []):
            self.send_header("Set-Cookie", c)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_redirect(self, url, cookies=None):
        self.send_response(302)
        self.send_header("Location", url)
        for c in cookies or []:
            self.send_header("Set-Cookie", c)
        self.end_headers()

    def _get_session(self) -> dict | None:
        cookies = parse_cookies(self.headers.get("Cookie", ""))
        token = cookies.get("gsc_session")
        if not token:
            return None
        return session_decode(token)

    def _require_auth(self):
        session = self._get_session()
        if not session:
            self._send_json({"error": "Not authenticated"}, 401)
            return None
        access_token, refreshed = get_valid_access_token(session)
        if not access_token:
            self._send_json({"error": "Token expired, please login again"}, 401)
            return None
        if refreshed:
            # Persist the refreshed token so we don't refresh on every request
            self._session_cookie = set_cookie("gsc_session", session_encode(session))
        return session

    def _get_query_params(self) -> dict:
        parsed = urlparse(self.path)
        return {k: v[0] for k, v in parse_qs(parsed.query).items()}

    def do_GET(self):
        path = urlparse(self.path).path
        params = self._get_query_params()

        if not secret_configured():
            self._send_json({"error": "Server misconfigured: set JWT_SECRET (16+ random characters)"}, 500)
            return

        # --- Auth routes ---
        if path == "/api/auth/login":
            return self._handle_login()
        elif path == "/api/auth/callback":
            return self._handle_callback(params)
        elif path == "/api/auth/logout":
            return self._handle_logout()
        elif path == "/api/auth/user":
            return self._handle_user()
        # --- Data routes ---
        elif path == "/api/sites":
            return self._handle_sites()
        elif path == "/api/clients":
            return self._handle_clients()
        elif path == "/api/dashboard":
            return self._handle_dashboard(params)
        elif path == "/api/report":
            return self._handle_report(params)
        elif path == "/api/opportunities":
            return self._handle_opportunities(params)
        elif path == "/api/tracked":
            return self._handle_tracked(params)
        elif path == "/api/volumes":
            return self._handle_volumes(params)
        else:
            self._send_json({"error": "Not found"}, 404)

    # --- Auth handlers ---
    def _handle_login(self):
        redirect_uri = get_redirect_uri(self.headers)
        state = secrets.token_urlsafe(24)
        params = urlencode({
            "client_id": CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": SCOPES,
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        })
        self._send_redirect(f"{AUTH_URL}?{params}", cookies=[set_cookie("oauth_state", state, max_age=600)])

    def _handle_callback(self, params):
        expected_state = parse_cookies(self.headers.get("Cookie", "")).get("oauth_state", "")
        if not expected_state or not hmac.compare_digest(expected_state, params.get("state", "")):
            self._send_json({"error": "Invalid login state, please try signing in again"}, 400,
                            cookies=[clear_cookie("oauth_state")])
            return
        code = params.get("code")
        if not code:
            self._send_json({"error": "No code provided"}, 400)
            return
        redirect_uri = get_redirect_uri(self.headers)
        token_resp = requests.post(TOKEN_URL, data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }, timeout=20)
        if token_resp.status_code != 200:
            self._send_json({"error": "Token exchange failed"}, 400)
            return

        tokens = token_resp.json()
        access_token = tokens["access_token"]

        # Fetch user info
        user_resp = requests.get(USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"}, timeout=20)
        user_info = user_resp.json() if user_resp.status_code == 200 else {}

        session = {
            "access_token": access_token,
            "refresh_token": tokens.get("refresh_token", ""),
            "token_expires_at": time.time() + tokens.get("expires_in", 3600),
            "email": user_info.get("email", ""),
            "name": user_info.get("name", ""),
            "picture": user_info.get("picture", ""),
        }
        self._send_redirect("/", cookies=[set_cookie("gsc_session", session_encode(session)),
                                          clear_cookie("oauth_state")])

    def _handle_logout(self):
        self._send_redirect("/", cookies=[clear_cookie("gsc_session")])

    def _handle_user(self):
        session = self._get_session()
        if not session:
            self._send_json({"authenticated": False})
            return
        self._send_json({
            "authenticated": True,
            "email": session.get("email", ""),
            "name": session.get("name", ""),
            "picture": session.get("picture", ""),
            "volumes_enabled": bool(DATAFORSEO_AUTH),
        })

    # --- Data handlers ---
    def _handle_sites(self):
        session = self._require_auth()
        if not session:
            return
        sites = gsc_list_sites(session["access_token"])
        self._send_json({"sites": sites})

    def _handle_clients(self):
        session = self._require_auth()
        if not session:
            return
        self._send_json({"clients": load_clients()})

    def _handle_dashboard(self, params):
        session = self._require_auth()
        if not session:
            return
        site_url = params.get("site")
        days = parse_days(params)
        if not site_url:
            self._send_json({"error": "Missing site parameter"}, 400)
            return

        start_date, end_date = period(days)
        at = session["access_token"]
        q = lambda dims, limit: lambda: gsc_query(at, site_url, start_date, end_date, dims, row_limit=limit)

        r = run_parallel({
            "totals": q([], 1),
            "daily": q(["date"], 5000),
            "top_queries": q(["query"], 20),
            "top_pages": q(["page"], 20),
            "devices": q(["device"], 10),
            "countries": q(["country"], 10),
        })

        self._send_json({
            "totals": gsc_totals(r["totals"]),
            "daily": r["daily"].get("rows", []),
            "top_queries": r["top_queries"].get("rows", []),
            "top_pages": r["top_pages"].get("rows", []),
            "devices": r["devices"].get("rows", []),
            "countries": r["countries"].get("rows", []),
            "period": {"start": start_date, "end": end_date, "days": days},
        })

    def _handle_report(self, params):
        session = self._require_auth()
        if not session:
            return
        site_url = params.get("site")
        days = parse_days(params)
        if not site_url:
            self._send_json({"error": "Missing site parameter"}, 400)
            return

        at = session["access_token"]
        start_date, end_date = period(days)
        prev_start, prev_end = period(days, periods_back=1)

        r = run_parallel({
            "current": lambda: gsc_query(at, site_url, start_date, end_date, [], row_limit=1),
            "previous": lambda: gsc_query(at, site_url, prev_start, prev_end, [], row_limit=1),
            "current_queries": lambda: gsc_query(at, site_url, start_date, end_date, ["query"], row_limit=1000),
            "prev_queries": lambda: gsc_query(at, site_url, prev_start, prev_end, ["query"], row_limit=1000),
        })

        # Top movers: compare both periods, including queries that are new or lost
        cur_map = {row["keys"][0]: row for row in r["current_queries"].get("rows", [])}
        prev_map = {row["keys"][0]: row for row in r["prev_queries"].get("rows", [])}
        movers = []
        for key in cur_map.keys() | prev_map.keys():
            cur, prev = cur_map.get(key), prev_map.get(key)
            clicks = cur["clicks"] if cur else 0
            prev_clicks = prev["clicks"] if prev else 0
            movers.append({
                "query": key,
                "clicks": clicks,
                "prev_clicks": prev_clicks,
                "delta": clicks - prev_clicks,
                "impressions": cur["impressions"] if cur else 0,
                "ctr": cur["ctr"] if cur else 0,
                "position": cur["position"] if cur else None,
                "status": "new" if not prev else "lost" if not cur else "",
            })
        movers.sort(key=lambda x: abs(x["delta"]), reverse=True)

        self._send_json({
            "current": gsc_totals(r["current"]),
            "previous": gsc_totals(r["previous"]),
            "period": {"start": start_date, "end": end_date, "days": days},
            "previous_period": {"start": prev_start, "end": prev_end},
            "top_movers": movers[:25],
        })

    def _handle_opportunities(self, params):
        session = self._require_auth()
        if not session:
            return
        site_url = params.get("site")
        days = parse_days(params)
        if not site_url:
            self._send_json({"error": "Missing site parameter"}, 400)
            return

        at = session["access_token"]
        start_date, end_date = period(days)

        # Get a large set of queries
        all_queries = gsc_query(at, site_url, start_date, end_date, ["query"], row_limit=1000)
        rows = all_queries.get("rows", [])

        # 1. Quick wins: high impressions, position 4-20 (could move to page 1)
        quick_wins = [
            {**r, "query": r["keys"][0]}
            for r in rows
            if 4 <= r.get("position", 0) <= 20 and r.get("impressions", 0) >= 50
        ]
        quick_wins.sort(key=lambda x: x["impressions"], reverse=True)

        # 2. CTR opportunities: high impressions, low CTR (< 3%) — improve titles/descriptions
        ctr_opps = [
            {**r, "query": r["keys"][0]}
            for r in rows
            if r.get("ctr", 0) < 0.03 and r.get("impressions", 0) >= 100 and r.get("position", 0) <= 10
        ]
        ctr_opps.sort(key=lambda x: x["impressions"], reverse=True)

        # 3. Content gaps: high impressions, no/low clicks — potential new content topics
        content_gaps = [
            {**r, "query": r["keys"][0]}
            for r in rows
            if r.get("clicks", 0) <= 2 and r.get("impressions", 0) >= 50 and r.get("position", 0) > 10
        ]
        content_gaps.sort(key=lambda x: x["impressions"], reverse=True)

        # 4. Striking distance: position 11-20 with decent impressions
        striking = [
            {**r, "query": r["keys"][0]}
            for r in rows
            if 11 <= r.get("position", 0) <= 20 and r.get("impressions", 0) >= 30
        ]
        striking.sort(key=lambda x: x["impressions"], reverse=True)

        self._send_json({
            "quick_wins": quick_wins[:20],
            "ctr_opportunities": ctr_opps[:20],
            "content_gaps": content_gaps[:30],
            "striking_distance": striking[:20],
            "total_queries_analyzed": len(rows),
            "period": {"start": start_date, "end": end_date, "days": days},
        })

    def _handle_tracked(self, params):
        """Performance of the content pages we published for the client that owns this site."""
        session = self._require_auth()
        if not session:
            return
        site_url = params.get("site")
        days = parse_days(params)
        if not site_url:
            self._send_json({"error": "Missing site parameter"}, 400)
            return

        client = match_client(site_url, load_clients())
        tracked = (client or {}).get("pages", [])
        if not tracked:
            self._send_json({"client": client and {"id": client["id"], "name": client["name"]}, "pages": []})
            return

        at = session["access_token"]
        start_date, end_date = period(days)
        prev_start, prev_end = period(days, periods_back=1)
        slugs = sorted({p["path"].strip("/") for p in tracked if p["path"].strip("/")})
        page_filter = [{"dimension": "page", "operator": "includingRegex",
                        "expression": "/(" + "|".join(slugs) + ")/?$"}]
        r = run_parallel({
            "current": lambda: gsc_query(at, site_url, start_date, end_date, ["page"], 1000, dimension_filters=page_filter),
            "previous": lambda: gsc_query(at, site_url, prev_start, prev_end, ["page"], 1000, dimension_filters=page_filter),
        })

        def by_path(result):
            grouped = {}
            for row in result.get("rows", []):
                grouped.setdefault(page_path(row["keys"][0]), []).append(row)
            return {path: combine(rows) for path, rows in grouped.items()}

        cur, prev = by_path(r["current"]), by_path(r["previous"])
        empty = combine([])
        pages = []
        for p in tracked:
            key = page_path(p["path"])
            pages.append({**p, "current": cur.get(key, empty), "previous": prev.get(key, empty)})

        self._send_json({
            "client": {"id": client["id"], "name": client["name"]},
            "pages": pages,
            "period": {"start": start_date, "end": end_date, "days": days},
            "previous_period": {"start": prev_start, "end": prev_end},
        })

    def _handle_volumes(self, params):
        session = self._require_auth()
        if not session:
            return
        if not DATAFORSEO_AUTH:
            self._send_json({"error": "Keyword volumes are not configured (set DATAFORSEO_AUTH)"}, 501)
            return
        keywords = list(dict.fromkeys(k.strip().lower() for k in params.get("keywords", "").split(",") if k.strip()))
        keywords = [k for k in keywords if len(k) <= 80][:200]
        if not keywords:
            self._send_json({"error": "Missing keywords parameter"}, 400)
            return
        try:
            location = int(params.get("location", "2840"))  # 2840 = United States
            self._send_json({"volumes": fetch_volumes(keywords, location), "location": location})
        except (RuntimeError, ValueError, requests.RequestException) as e:
            self._send_json({"error": str(e)}, 502)

    def log_message(self, format, *args):
        pass  # Suppress default logging in production

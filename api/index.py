import os
import json
import time
import hashlib
import hmac
import base64
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote
from http.server import BaseHTTPRequestHandler

import requests

# --- Configuration ---
CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "change-me-in-production")
SCOPES = "openid email profile https://www.googleapis.com/auth/webmasters.readonly"
TOKEN_URL = "https://oauth2.googleapis.com/token"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
GSC_API = "https://www.googleapis.com/webmasters/v3"
GSC_SEARCH_ANALYTICS = "https://searchconsole.googleapis.com/webmasters/v3"


def get_redirect_uri(headers):
    proto = headers.get("x-forwarded-proto", "https")
    host = headers.get("x-forwarded-host") or headers.get("host", "localhost:3000")
    return f"{proto}://{host}/api/auth/callback"


# --- JWT helpers (minimal, no pyjwt dependency) ---
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def jwt_encode(payload: dict) -> str:
    header = b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64url_encode(json.dumps(payload).encode())
    sig = hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    return f"{header}.{body}.{b64url_encode(sig)}"


def jwt_decode(token: str) -> dict | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        sig = hmac.new(JWT_SECRET.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
        if b64url_encode(sig) != parts[2]:
            return None
        payload = json.loads(b64url_decode(parts[1]))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
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


def set_cookie(name, value, max_age=86400 * 7):
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
    })
    if resp.status_code == 200:
        return resp.json()
    return None


def get_valid_access_token(session: dict) -> str | None:
    """Return a valid access token, refreshing if expired."""
    expires_at = session.get("token_expires_at", 0)
    if time.time() < expires_at - 60:
        return session.get("access_token")
    refresh_token = session.get("refresh_token")
    if not refresh_token:
        return None
    new_tokens = refresh_access_token(refresh_token)
    if not new_tokens:
        return None
    session["access_token"] = new_tokens["access_token"]
    session["token_expires_at"] = time.time() + new_tokens.get("expires_in", 3600)
    return new_tokens["access_token"]


# --- GSC API helpers ---
def gsc_list_sites(access_token: str) -> list:
    resp = requests.get(f"{GSC_API}/sites", headers={"Authorization": f"Bearer {access_token}"})
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
    )
    if resp.status_code == 200:
        return resp.json()
    return {"rows": [], "error": resp.text}


# --- Request handler ---
class handler(BaseHTTPRequestHandler):

    def _send_json(self, data, status=200, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _send_redirect(self, url, extra_headers=None):
        self.send_response(302)
        self.send_header("Location", url)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()

    def _get_session(self) -> dict | None:
        cookies = parse_cookies(self.headers.get("Cookie", ""))
        token = cookies.get("gsc_session")
        if not token:
            return None
        return jwt_decode(token)

    def _require_auth(self):
        session = self._get_session()
        if not session:
            self._send_json({"error": "Not authenticated"}, 401)
            return None
        access_token = get_valid_access_token(session)
        if not access_token:
            self._send_json({"error": "Token expired, please login again"}, 401)
            return None
        session["access_token"] = access_token
        return session

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _get_query_params(self) -> dict:
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.path)
        return {k: v[0] for k, v in parse_qs(parsed.query).items()}

    def do_GET(self):
        from urllib.parse import urlparse
        path = urlparse(self.path).path
        params = self._get_query_params()

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
        elif path == "/api/dashboard":
            return self._handle_dashboard(params)
        elif path == "/api/report":
            return self._handle_report(params)
        elif path == "/api/opportunities":
            return self._handle_opportunities(params)
        else:
            self._send_json({"error": "Not found"}, 404)

    # --- Auth handlers ---
    def _handle_login(self):
        redirect_uri = get_redirect_uri(self.headers)
        params = urlencode({
            "client_id": CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": SCOPES,
            "access_type": "offline",
            "prompt": "consent",
        })
        self._send_redirect(f"{AUTH_URL}?{params}")

    def _handle_callback(self, params):
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
        })
        if token_resp.status_code != 200:
            self._send_json({"error": "Token exchange failed"}, 400)
            return

        tokens = token_resp.json()
        access_token = tokens["access_token"]

        # Fetch user info
        user_resp = requests.get(USERINFO_URL, headers={"Authorization": f"Bearer {access_token}"})
        user_info = user_resp.json() if user_resp.status_code == 200 else {}

        session = {
            "access_token": access_token,
            "refresh_token": tokens.get("refresh_token", ""),
            "token_expires_at": time.time() + tokens.get("expires_in", 3600),
            "email": user_info.get("email", ""),
            "name": user_info.get("name", ""),
            "picture": user_info.get("picture", ""),
            "exp": time.time() + 86400 * 7,
        }
        cookie_val = jwt_encode(session)
        self._send_redirect("/", extra_headers={"Set-Cookie": set_cookie("gsc_session", cookie_val)})

    def _handle_logout(self):
        self._send_redirect("/", extra_headers={"Set-Cookie": clear_cookie("gsc_session")})

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
        })

    # --- Data handlers ---
    def _handle_sites(self):
        session = self._require_auth()
        if not session:
            return
        sites = gsc_list_sites(session["access_token"])
        self._send_json({"sites": sites})

    def _handle_dashboard(self, params):
        session = self._require_auth()
        if not session:
            return
        site_url = params.get("site")
        days = int(params.get("days", "28"))
        if not site_url:
            self._send_json({"error": "Missing site parameter"}, 400)
            return

        end_date = (datetime.utcnow() - timedelta(days=3)).strftime("%Y-%m-%d")
        start_date = (datetime.utcnow() - timedelta(days=days + 3)).strftime("%Y-%m-%d")
        at = session["access_token"]

        # Daily trend
        daily = gsc_query(at, site_url, start_date, end_date, ["date"], row_limit=5000)

        # Top queries
        top_queries = gsc_query(at, site_url, start_date, end_date, ["query"], row_limit=20)

        # Top pages
        top_pages = gsc_query(at, site_url, start_date, end_date, ["page"], row_limit=20)

        # Device breakdown
        devices = gsc_query(at, site_url, start_date, end_date, ["device"], row_limit=10)

        # Country breakdown
        countries = gsc_query(at, site_url, start_date, end_date, ["country"], row_limit=10)

        self._send_json({
            "daily": daily.get("rows", []),
            "top_queries": top_queries.get("rows", []),
            "top_pages": top_pages.get("rows", []),
            "devices": devices.get("rows", []),
            "countries": countries.get("rows", []),
            "period": {"start": start_date, "end": end_date},
        })

    def _handle_report(self, params):
        session = self._require_auth()
        if not session:
            return
        site_url = params.get("site")
        days = int(params.get("days", "28"))
        if not site_url:
            self._send_json({"error": "Missing site parameter"}, 400)
            return

        at = session["access_token"]

        # Current period
        end_date = (datetime.utcnow() - timedelta(days=3)).strftime("%Y-%m-%d")
        start_date = (datetime.utcnow() - timedelta(days=days + 3)).strftime("%Y-%m-%d")

        # Previous period for comparison
        prev_end = (datetime.utcnow() - timedelta(days=days + 3)).strftime("%Y-%m-%d")
        prev_start = (datetime.utcnow() - timedelta(days=2 * days + 3)).strftime("%Y-%m-%d")

        current_daily = gsc_query(at, site_url, start_date, end_date, ["date"], row_limit=5000)
        prev_daily = gsc_query(at, site_url, prev_start, prev_end, ["date"], row_limit=5000)

        def aggregate(rows):
            total = {"clicks": 0, "impressions": 0, "ctr": 0, "position": 0, "count": 0}
            for r in rows:
                total["clicks"] += r.get("clicks", 0)
                total["impressions"] += r.get("impressions", 0)
                total["position"] += r.get("position", 0)
                total["count"] += 1
            if total["impressions"] > 0:
                total["ctr"] = total["clicks"] / total["impressions"]
            if total["count"] > 0:
                total["position"] = total["position"] / total["count"]
            return total

        current_agg = aggregate(current_daily.get("rows", []))
        prev_agg = aggregate(prev_daily.get("rows", []))

        # Top movers (queries with biggest change)
        current_queries = gsc_query(at, site_url, start_date, end_date, ["query"], row_limit=100)
        prev_queries = gsc_query(at, site_url, prev_start, prev_end, ["query"], row_limit=100)

        prev_map = {}
        for r in prev_queries.get("rows", []):
            key = r["keys"][0]
            prev_map[key] = r

        movers = []
        for r in current_queries.get("rows", []):
            key = r["keys"][0]
            prev = prev_map.get(key)
            if prev:
                delta_clicks = r["clicks"] - prev["clicks"]
                movers.append({
                    "query": key,
                    "clicks": r["clicks"],
                    "prev_clicks": prev["clicks"],
                    "delta": delta_clicks,
                    "impressions": r["impressions"],
                    "ctr": r["ctr"],
                    "position": r["position"],
                })

        movers.sort(key=lambda x: abs(x["delta"]), reverse=True)

        self._send_json({
            "current": current_agg,
            "previous": prev_agg,
            "period": {"start": start_date, "end": end_date, "days": days},
            "top_movers": movers[:15],
        })

    def _handle_opportunities(self, params):
        session = self._require_auth()
        if not session:
            return
        site_url = params.get("site")
        if not site_url:
            self._send_json({"error": "Missing site parameter"}, 400)
            return

        at = session["access_token"]
        end_date = (datetime.utcnow() - timedelta(days=3)).strftime("%Y-%m-%d")
        start_date = (datetime.utcnow() - timedelta(days=31)).strftime("%Y-%m-%d")

        # Get a large set of queries
        all_queries = gsc_query(at, site_url, start_date, end_date, ["query"], row_limit=500)
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
            "period": {"start": start_date, "end": end_date},
        })

    def log_message(self, format, *args):
        pass  # Suppress default logging in production

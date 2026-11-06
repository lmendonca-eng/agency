# GSC Explorer

A Python web app that connects to Google Search Console via OAuth2 and provides:

- **Dashboard** — clicks, impressions, CTR, and position trends with charts; top queries, pages, devices, and countries
- **Report** — period-over-period comparison with the biggest query movers
- **Opportunities** — automated analysis of quick wins, CTR gaps, content gaps, and striking-distance keywords, with optional monthly search volume
- **Published content** — clicks, impressions, CTR and position for the content pages we published for each client, vs. the previous period
- **Client mapping** — Search Console properties are labeled with the client ID and name (filterable), from the private client roster
- **CSV export** — every table can be downloaded as CSV

Deployed as a Vercel serverless function.

---

## Setup

### 1. Create Google OAuth2 credentials

1. Go to [Google Cloud Console → APIs & Services → Credentials](https://console.cloud.google.com/apis/credentials)
2. Create a new project (or select an existing one)
3. Click **Create Credentials → OAuth client ID**
4. Application type: **Web application**
5. Add **Authorized redirect URIs**:
   - For local dev: `http://localhost:3000/api/auth/callback`
   - For production: `https://your-app.vercel.app/api/auth/callback`
6. Copy the **Client ID** and **Client Secret**

### 2. Enable the Search Console API

1. In the same project, go to **APIs & Services → Library**
2. Search for **Google Search Console API**
3. Click **Enable**

### 3. Configure the OAuth consent screen

1. Go to **APIs & Services → OAuth consent screen**
2. Choose **External** (or Internal if using Google Workspace)
3. Fill in the app name, support email, and developer email
4. Add the scope: `https://www.googleapis.com/auth/webmasters.readonly`
5. Add test users (while the app is in "Testing" status, only listed test users can log in)

### 4. Deploy to Vercel

```bash
# Install Vercel CLI if you don't have it
npm i -g vercel

# From the project directory
vercel

# Set environment variables
vercel env add GOOGLE_CLIENT_ID
vercel env add GOOGLE_CLIENT_SECRET
vercel env add JWT_SECRET
vercel env add DATAFORSEO_AUTH   # optional, enables search volume on Opportunities

# Deploy to production
vercel --prod
```

After deploying, add the production URL to your Google OAuth redirect URIs:
```
https://your-app.vercel.app/api/auth/callback
```

### 5. Local development

```bash
# Install vercel CLI
npm i -g vercel

# Link to your project
vercel link

# Pull environment variables
vercel env pull .env.local

# Run locally
vercel dev
```

---

## Project structure

```
├── api/
│   ├── index.py          # Serverless handler (OAuth + GSC API)
│   └── clients.example.json  # Format of the client roster (real one is private)
├── public/
│   └── index.html         # Frontend SPA (vanilla JS + Chart.js)
├── vercel.json            # Vercel routing config
├── requirements.txt       # Python dependencies
└── .env.example           # Environment variable template
```

## Environment variables

| Variable | Description |
|---|---|
| `GOOGLE_CLIENT_ID` | OAuth2 client ID from Google Cloud Console |
| `GOOGLE_CLIENT_SECRET` | OAuth2 client secret |
| `JWT_SECRET` | **Required.** Random string (16+ characters) used to encrypt session cookies. The app refuses to run without it |
| `CLIENTS_JSON` | Client roster as JSON (format: `api/clients.example.json`). Kept in Vercel, not in this public repo. Locally you can use `api/clients.json` instead (git-ignored) |
| `DATAFORSEO_AUTH` | Optional. Base64 of `login:password` for DataForSEO; enables the "Add monthly search volume" button on Opportunities |

## Updating clients and tracked pages

The roster lives in the `CLIENTS_JSON` environment variable in Vercel (or a git-ignored `api/clients.json` locally), so client names and domains are never committed to this public repo. Each client has an `id`, `name`, `domains` (matched against Search Console property hostnames, including `sc-domain:` properties), and `pages` (`path`, `month`, `title`, `type`) shown on the **Published content** tab. Add next month's pages there after they are published, then update the env var (`vercel env rm CLIENTS_JSON production && vercel env add CLIENTS_JSON production`) and redeploy.

## Notes

- GSC data has a 2–3 day delay, so the app queries up to 3 days ago
- Periods are exact (e.g. 28 days), and the comparison period is the 28 days immediately before, with no overlap
- Totals and average position come straight from Search Console (impression-weighted), so they match the GSC UI
- Session cookies are encrypted; Google tokens are never readable from the browser
- The OAuth consent screen must be verified by Google for apps with more than 100 users
- While in "Testing" mode, only users you add as test users can log in

# GSC Explorer

A Python web app that connects to Google Search Console via OAuth2 and provides:

- **Dashboard** — clicks, impressions, CTR, and position trends with charts; top queries, pages, devices, and countries
- **Report** — period-over-period comparison with the biggest query movers
- **Opportunities** — automated analysis of quick wins, CTR gaps, content gaps, and striking-distance keywords

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
│   └── index.py          # Flask-like serverless handler (OAuth + GSC API)
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
| `JWT_SECRET` | Random string for signing session cookies |

## Notes

- GSC data has a 2–3 day delay, so the app queries up to 3 days ago
- The OAuth consent screen must be verified by Google for apps with more than 100 users
- While in "Testing" mode, only users you add as test users can log in

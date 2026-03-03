# Frontend — Progress Report

**Technology:** React 18, React Router v6, Axios, Context API
**Port:** 3000
**Location:** `PhishNet-main/frontend/`

---

## Folder Structure

```
frontend/
├── public/
└── src/
    ├── App.js               ← routing
    ├── index.js             ← React entry point
    ├── apiConfig.js         ← base URL config (http://localhost:8800)
    ├── context/
    │   └── AuthContext.js   ← global user state (login/logout)
    ├── services/
    │   └── authService.js   ← token/cookie helpers
    ├── Components/          ← shared UI components
    └── Pages/
        ├── home/            ← landing page
        ├── Login/           ← login form
        ├── Register/        ← registration form
        ├── dashboard/       ← user dashboard
        ├── result/          ← URL scan results (main page)
        ├── scanhistory/     ← past scan table
        ├── allreports/      ← admin/user reports list
        ├── report/          ← single report detail
        ├── statistics/      ← charts and stats
        └── payment/         ← premium upgrade
```

---

## Pages

### Home Page (`Pages/home/`)
- Landing page with PhishNet branding
- URL input box — user types or pastes a URL
- "Scan" button triggers a POST to `/api/phishing/analyze`
- Shows loading spinner while waiting for result
- Redirects to `/result` with the scan data

### Login Page (`Pages/Login/`)
- Email + password form
- On success: JWT stored as an HTTP-only cookie by the backend
- Redirects to `/dashboard`
- Uses `AuthContext` to set the global user state

### Register Page (`Pages/Register/`)
- Name, email, password fields
- Calls `POST /api/auth/register`
- Redirects to `/login` on success

### Dashboard (`Pages/dashboard/`)
- Welcome message with username
- Summary cards: total scans, phishing detected, reports submitted
- Quick scan form (same as home)
- Links to scan history and reports

### Result Page (`Pages/result/` — most complex page)

This is where PhishNet explains its verdict. It was heavily upgraded during development.

**What it shows:**

1. **Verdict banner** — big red "PHISHING DETECTED" or green "LEGITIMATE" header
2. **Detection source badge** — shows whether the verdict came from:
   - `Blacklist` — domain was in MongoDB blacklist
   - `Rule Engine` — heuristic rules fired
   - `ML Ensemble` — machine learning models decided
   - `Trusted` — known safe domain
3. **Confidence score** — percentage confidence from ML models
4. **Risk level** — LOW / MEDIUM / HIGH / CRITICAL
5. **Rule violations** — list of specific rules that fired (e.g. "IP address in domain", "No HTTPS")
6. **Feature details** — UCI or REALISTIC feature values shown conditionally
   - Detects model type by checking whether `PhishingSignalCount` is present in response
   - UCI model: shows 9 categorical features (-1/0/1) + computed signals
   - REALISTIC model: shows key URL features, content features, risk indicators
7. **Model consensus card** — shows how each of the 4 models voted and their confidence
8. **SHAP explainability card** — bar chart showing which features pushed the decision toward phishing or legitimate (only shown when ML was used and SHAP data is available)
9. **Analysis summary** — human-readable breakdown in three sections:
   - Security indicators
   - Content quality
   - Risk factors
10. **Action buttons** — Scan Another URL, Report This Site, View Scan History

**SHAP card implementation:**
```jsx
{hasMLData && analysisResult.shap_explanation?.top_features?.length > 0 && (
    <div className="shap-card">
        <h3>AI Decision Explanation</h3>
        {/* horizontal bar chart of top-10 SHAP values */}
        {/* red bars = pushes toward Phishing */}
        {/* green bars = pushes toward Legitimate */}
    </div>
)}
```

### Scan History (`Pages/scanhistory/`)
- Table of all past scans for the logged-in user
- Columns: URL, verdict, confidence, risk level, timestamp
- Click any row to see full result detail
- Pagination

### Statistics Page (`Pages/statistics/`)
- Pie chart: phishing vs legitimate ratio
- Line chart: scans over time
- Bar chart: detection source breakdown
- Uses `recharts` library

### Reports Page (`Pages/allreports/` and `Pages/report/`)
- List of user-submitted reports
- Admin can see all reports; regular users see their own
- Each report has: URL, description, status (pending/reviewed/resolved)

### Payment Page (`Pages/payment/`)
- Razorpay integration for premium subscription
- Premium users get higher API rate limits (500 scans/15 min vs 50 for free)

---

## Authentication Flow

```
User logs in → POST /api/auth/login
             → Backend sets access_token HTTP-only cookie
             → AuthContext stores user object in React state
             → Protected routes check AuthContext

User refreshes → GET /api/auth/user (cookie sent automatically)
              → Returns {status: true, user: {...}}
              → AuthContext restored

User logs out → POST /api/auth/logout
             → Cookie cleared by backend
             → AuthContext reset to null
             → Redirect to /login
```

**Key files:**
- `context/AuthContext.js` — React context holding `{user, loading, setUser}`
- Every page that needs auth wraps in `<AuthContext.Consumer>` or uses `useContext(AuthContext)`

---

## API Communication

All API calls go through `apiConfig.js`:
```js
export const BASE_URL = "http://localhost:8800";
```

Axios is used with `withCredentials: true` to send the JWT cookie:
```js
const res = await axios.post(`${BASE_URL}/api/phishing/analyze`,
    { url },
    { withCredentials: true }
);
```

---

## Key Dependencies

```json
{
  "react": "^18.x",
  "react-router-dom": "^6.x",
  "axios": "^1.x",
  "recharts": "^2.x",
  "react-chartjs-2": "^5.x",
  "chart.js": "^4.x"
}
```

---

## What Was Built / Changed

| Component | Work Done |
|-----------|-----------|
| Result.jsx | Complete rewrite — added UCI vs REALISTIC display, model consensus card, SHAP card, analysis summary |
| Result.css | Full new stylesheet for all new Result.jsx sections |
| App.js | Route for `/result` passes scan data via React Router state |
| Dashboard | Summary stats cards added |
| Scan History | Table with pagination and click-to-detail |

# Chrome Extension — Progress Report

**Technology:** Chrome Extension Manifest V3, vanilla JS, chrome.storage API
**Location:** `PhishNet-main/chrome_extension/`
**API:** Express backend at `http://localhost:8800/api`

---

## Files

```
chrome_extension/
├── manifest.json     ← extension config (MV3)
├── popup.html        ← popup UI (360px wide)
├── popup.css         ← dark theme styles
├── popup.js          ← popup logic (auth + scan)
├── background.js     ← service worker (badge + auto-scan)
└── logo.svg          ← PhishNet shield icon
```

---

## What the Extension Does

1. **When you navigate to a URL** — the background service worker automatically scans it and updates the extension badge:
   - `!` red background → Phishing detected
   - `✓` green background → Looks legitimate
   - `…` purple background → Scanning in progress
   - _(empty)_ → Not a web URL (chrome://, file://, etc.)

2. **When you click the extension icon** — a 360px popup opens showing:
   - The current URL being analysed
   - If not logged in: a login form
   - If the URL is not scannable (e.g. chrome://settings): "Not Available" state
   - If an error occurs: error message
   - If scan result available: full verdict card with confidence, risk level, detection source, and any rule violations

---

## Manifest V3 Configuration

```json
{
  "name": "PhishNet",
  "version": "2.0.0",
  "manifest_version": 3,
  "permissions": ["tabs", "activeTab", "storage"],
  "host_permissions": ["http://localhost:8800/*"],
  "background": { "service_worker": "background.js" },
  "action": {
    "default_popup": "popup.html",
    "default_title": "PhishNet — Phishing Detector"
  }
}
```

**Permissions used:**
- `tabs` — read URL of current tab
- `activeTab` — interact with the active tab
- `storage` — persist JWT token and scan cache (`chrome.storage.local` and `chrome.storage.session`)

---

## Authentication Flow

The Chrome extension uses a **self-contained login form** — no dependency on browser cookies.

```
User opens popup (not logged in)
    └─ Shows login form (email + password)
    └─ User clicks "Sign In"

POST /api/auth/login { email, password }
    └─ Backend returns { ...user, _ext_token: "jwt_token_here" }

Extension stores token:
    chrome.storage.local.set({ phishnet_token: token })

Extension notifies background service worker:
    chrome.runtime.sendMessage({ type: 'TOKEN_UPDATED', token })

Background stores token in memory (cachedToken) for fast access
```

**Why not use cookies?**
The JWT cookie uses `SameSite=Lax` by default. This prevents it from being sent in cross-site fetch requests from a `chrome-extension://` origin. To avoid this complication, the extension reads the token directly from the login response body (`_ext_token`) and stores it in `chrome.storage.local` instead.

**Sign out:**
```
User clicks "Sign out" in popup footer
    └─ chrome.storage.local.remove(['phishnet_token', 'phishnet_user'])
    └─ chrome.runtime.sendMessage({ type: 'TOKEN_CLEARED' })
    └─ Background sets cachedToken = null
    └─ Popup shows login form
```

---

## Scan Flow (popup.js)

```
run() called on DOMContentLoaded
    ├─ showOnly(stateLoading)
    ├─ Get current tab URL via chrome.tabs.query
    ├─ If not http:// or https:// → showOnly(stateNA)
    ├─ getToken() from chrome.storage.local
    │   └─ No token → showOnly(stateLogin)
    ├─ verifyToken() → GET /api/auth/user with Authorization: Bearer
    │   └─ Invalid/expired → clearAuth() → showOnly(stateLogin)
    ├─ getCached(url) from chrome.storage.local (5-min TTL)
    │   └─ Cache hit → renderResult(cached)
    └─ scanUrl(url, token) → POST /api/phishing/analyze
        ├─ Success → setCached(url, data) → renderResult(data)
        │            notifyBackground({ type: 'SCAN_RESULT', url, data })
        ├─ AUTH error (401/403) → clearAuth() → showOnly(stateLogin)
        ├─ RATE_LIMIT (429) → showOnly(stateError) "Daily limit reached"
        └─ Other error → showOnly(stateError) "Cannot reach backend"
```

---

## Background Service Worker (background.js)

The service worker runs in the background and automatically scans URLs when tabs are navigated or switched.

**Token management:**
- Keeps `cachedToken` in memory for fast access
- Reads from `chrome.storage.local` if in-memory cache is empty
- Updated/cleared via messages from popup

**Cache:**
- Uses `chrome.storage.session` (cleared when browser closes)
- 5-minute TTL per URL
- Maximum 80 entries (oldest evicted)

**Event listeners:**

| Event | Action |
|-------|--------|
| `chrome.tabs.onUpdated` (status=complete, active) | Scan the URL, update badge |
| `chrome.tabs.onActivated` | Show cached badge instantly; scan if not cached |
| `chrome.runtime.onMessage` (SCAN_RESULT) | Update session cache and badge from popup result |
| `chrome.runtime.onMessage` (TOKEN_UPDATED) | Update in-memory token |
| `chrome.runtime.onMessage` (TOKEN_CLEARED) | Set cachedToken = null |

---

## Result Display (popup.js `renderResult()`)

The popup shows a compact version of the full scan result:

| Element | What it shows |
|---------|--------------|
| Verdict card | Green "Looks Legitimate" or Red "Phishing Detected" or Dark Red "Blacklisted Site" |
| Confidence | % confidence from ML models |
| Risk level | LOW / MEDIUM / HIGH / CRITICAL |
| Detection source | Blacklist / Rule Engine / ML Model / Trusted |
| Confidence bar | Visual bar (green = safe, red = phishing) |
| Rule violations | Up to 5 rule violation messages |
| Rescan button | Clears cache for this URL and rescans |
| History button | Opens `http://localhost:3000/scan-history` in a new tab |

---

## CORS Fix Required

Because the extension origin is `chrome-extension://...` (not a regular HTTP origin), two CORS configs in the backend had to be updated:

**`backend/server.js`** (primary CORS):
```js
origin: (origin, callback) => {
    if (!origin || allowedOrigins.includes(origin) ||
        origin.startsWith('chrome-extension://')) {
        callback(null, true);
    } else {
        callback(new Error('Not allowed by CORS'));
    }
}
```

**`backend/middleware/security.js`** (secondary CORS — this was overriding the primary):
```js
// Allow Chrome extension origins
if (origin.startsWith('chrome-extension://')) return callback(null, true);
```

Both had to be updated because `security.js` applies its own `cors()` middleware **after** `server.js`, overriding it.

---

## How to Install the Extension

1. Open Chrome and go to `chrome://extensions`
2. Enable **Developer mode** (toggle in top right)
3. Click **Load unpacked**
4. Select the `PhishNet-main/chrome_extension/` folder
5. The PhishNet icon appears in the toolbar

> Make sure the Express backend is running on port 8800 before using the extension.

---

## Popup UI States

| State ID | Shown when |
|----------|-----------|
| `stateLoading` | Initial load / scanning |
| `stateLogin` | No token stored, or token expired |
| `stateNA` | Current tab is not an HTTP/HTTPS URL |
| `stateError` | Backend unreachable, rate limit hit |
| `stateResult` | Scan completed successfully |

---

## Summary of Work Done

| Task | Details |
|------|---------|
| Manifest V3 rewrite | New manifest.json with correct permissions |
| Popup UI | Full dark-theme HTML/CSS redesign with all states |
| Self-contained auth | Inline login form, storage.local, no cookies |
| Badge management | `!` / `✓` / `…` badges via background service worker |
| Result display | Verdict card, confidence bar, violations, stats |
| Cache system | 5-min TTL in storage.local (popup) and storage.session (background) |
| CORS fix | Two places in backend updated for chrome-extension:// origins |
| Bearer auth | Backend verifyToken.js and auth.js updated to accept Bearer header |
| `_ext_token` | Login response body includes token for extension to read |
| Token sync | Popup ↔ background messaging for TOKEN_UPDATED / TOKEN_CLEARED |

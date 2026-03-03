# Backend — Progress Report

**Technology:** Node.js 20, Express 4, MongoDB/Mongoose 7
**Port:** 8800
**Location:** `PhishNet-main/backend/`

---

## Folder Structure

```
backend/
├── server.js               ← Express app entry point
├── package.json
├── .env                    ← PORT, MONGO_URL, JWT secret, NODE_ENV
├── config/
├── controllers/
│   ├── auth.js             ← register, login, logout, userVerification
│   ├── phishing.js         ← analyzeUrl (main scan controller)
│   ├── user.js             ← profile, update
│   ├── reportDomain.js     ← submit/view domain reports
│   ├── domainPage.js       ← public domain info
│   └── contact.js          ← contact form
├── routes/
│   ├── auth.js
│   ├── phishing.js
│   ├── users.js
│   └── reportDomain.js
├── models/
│   ├── User.js             ← user schema
│   ├── ScanHistory.js      ← scan result storage
│   ├── Blacklist.js        ← blacklisted domains
│   ├── reportDomain.js     ← user reports
│   ├── DomainPage.js       ← domain info
│   └── contact.js
├── middleware/
│   └── security.js         ← rate limiters, helmet, CORS, sanitization
└── utils/
    └── verifyToken.js      ← JWT auth middleware
```

---

## API Endpoints

### Authentication — `/api/auth`

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/api/auth/register` | Create new account | No |
| POST | `/api/auth/login` | Login, receive JWT cookie | No |
| POST | `/api/auth/logout` | Clear cookie | Yes |
| GET | `/api/auth/user` | Get current user info | Yes |

**Login response includes `_ext_token`** for the Chrome Extension:
```js
res.status(200)
   .cookie("access_token", token, option)
   .json({ ...userInfo, _ext_token: token });
```
The web app uses the cookie; the Chrome extension reads `_ext_token` from the JSON body and stores it in `chrome.storage.local`.

### Phishing Analysis — `/api/phishing`

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/api/phishing/analyze` | Scan a URL | Yes |
| GET | `/api/phishing/history` | Get scan history | Yes |
| POST | `/api/phishing/report` | Report a URL as phishing | Yes |
| GET | `/api/phishing/blacklist` | View blacklist (admin) | Yes |

**POST `/api/phishing/analyze` — Full scan flow:**

```
1. Check Blacklist.isBlacklisted(url) → MongoDB lookup
   └─ If found: return { prediction: 'Phishing', detection_source: 'blacklist' }

2. Check rule engine result (sent back from Flask as 'rule_engine')
   └─ If rules fired: return { prediction: 'Phishing', detection_source: 'rule_engine' }

3. Call Flask ML service: POST http://localhost:5002/analyze { url }
   └─ Flask returns ensemble prediction + confidence + SHAP values

4. If prediction is 'Phishing' and not trusted → auto-add to Blacklist
   └─ status: 'confirmed', source: 'ml_high_confidence', expires in 90 days

5. Save to ScanHistory (async, non-blocking)

6. Return full result to client
```

**Auto-blacklist logic** (`controllers/phishing.js` ~line 247):
```js
if (mlResult.prediction === 'Phishing' && !mlResult.is_trusted) {
    await Blacklist.findOneAndUpdate(
        { url: normalizedUrl },
        { url: normalizedUrl, domain: domain, status: 'confirmed',
          source: 'ml_high_confidence', confidence: mlResult.confidence },
        { upsert: true, new: true }
    );
}
```
This means every phishing detection is automatically blacklisted so future scans of the same domain return instantly from Layer 0.

### Users — `/api/users`

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/api/users/:id` | Get user profile | Yes |
| PUT | `/api/users/:id` | Update profile | Yes |
| DELETE | `/api/users/:id` | Delete account | Yes |

### Reports — `/api/reportdomain`

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/api/reportdomain` | Submit a domain report | Yes |
| GET | `/api/reportdomain` | List reports (admin sees all) | Yes |
| PATCH | `/api/reportdomain/:id` | Update report status | Yes |

---

## Database Models

### User (`models/User.js`)
```js
{
  username: String,
  email: String (unique),
  password: String (bcrypt hashed),
  photo: String (Cloudinary URL),
  isPremium: Boolean,
  createdAt: Date
}
```

### ScanHistory (`models/ScanHistory.js`)
```js
{
  userId: ObjectId → User,
  url: String,
  prediction: String,        // 'Phishing' | 'Legitimate'
  confidence: Number,
  riskLevel: String,
  detectionSource: String,   // 'blacklist' | 'rule_engine' | 'ml_ensemble' | 'trusted'
  modelResults: Object,      // individual model votes
  scannedAt: Date
}
```

### Blacklist (`models/Blacklist.js`)
```js
{
  url: String (unique),
  domain: String,
  status: String,      // 'confirmed' | 'suspected' | 'cleared'
  source: String,      // 'ml_high_confidence' | 'user_report' | 'manual'
  confidence: Number,
  expiresAt: Date,     // auto-set to 90 days by pre-save hook
  createdAt: Date
}

// Static method:
Blacklist.isBlacklisted(url) → Promise<Boolean>
```

---

## Security Middleware (`middleware/security.js`)

Applies in order via `applySecurityMiddleware(app)`:

| # | Middleware | What it does |
|---|-----------|-------------|
| 1 | `helmet` | Sets 12 HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) |
| 2 | `cors` | Allows `localhost:3000`, `localhost:5500`, `chrome-extension://` origins |
| 3 | `express-mongo-sanitize` | Strips `$` and `.` from MongoDB queries (NoSQL injection prevention) |
| 4 | `xss-clean` | Strips HTML tags from request body (XSS prevention) |
| 5 | `hpp` | Prevents HTTP parameter pollution |
| 6 | `abuseDetection` | Blocks requests with `../`, `<script>`, `union select`, `javascript:` |
| 7 | `securityLogger` | Logs auth/report/admin endpoint accesses |
| 8 | `generalLimiter` | 300 requests / 15 min per IP (disabled in development) |

### Rate Limiters (all disabled in development via `skip: () => process.env.NODE_ENV !== 'production'`)

| Limiter | Limit | Window | Applied to |
|---------|-------|--------|-----------|
| `generalLimiter` | 300 req | 15 min | All `/api/` routes |
| `analyzeRateLimiter` | 50 req (free) / 500 (premium) | 15 min | `/api/phishing/analyze` |
| `reportRateLimiter` | 10 req | 1 hour | `/api/reportdomain` |
| `authRateLimiter` | 10 req (skip success) | 15 min | `/api/auth/login` |
| `registerRateLimiter` | 3 req | 1 hour | `/api/auth/register` |

---

## Authentication (`utils/verifyToken.js`)

JWT verification middleware applied to all protected routes.

**Accepts two token sources** (added for Chrome Extension support):
```js
// Cookie (web app)
let token = req.cookies.access_token;

// Authorization header (Chrome Extension)
if (!token && req.headers.authorization?.startsWith('Bearer ')) {
    token = req.headers.authorization.slice(7);
}
```

JWT is signed with `process.env.JWT` secret. Expiry is 30 days.

---

## CORS Configuration

Two CORS configs exist (both must allow the same origins):

1. **`server.js`** — primary CORS applied before all other middleware
2. **`middleware/security.js`** — secondary CORS inside `applySecurityMiddleware()`

Both accept:
- `http://localhost:3000` (React dev)
- `http://localhost:5500` (live server)
- Any `chrome-extension://` origin (Chrome extension)
- Requests with no origin (Postman, mobile apps)

---

## Environment Variables (`.env`)

```env
PORT=8800
MONGO_URL=mongodb://localhost:27017/phishnet
JWT=your_jwt_secret_here
NODE_ENV=development
FRONTEND_URL=http://localhost:3000
```

---

## Key Changes Made During Development

| File | Change |
|------|--------|
| `server.js` | CORS updated to dynamic function accepting `chrome-extension://` |
| `middleware/security.js` | CORS origin function extended to accept `chrome-extension://` |
| `utils/verifyToken.js` | Bearer token support added for Chrome Extension |
| `controllers/auth.js` | Login returns `_ext_token` in body; `userVerification` accepts Bearer header |
| `controllers/phishing.js` | 3-layer detection pipeline; auto-blacklist on phishing detection |
| `models/Blacklist.js` | `isBlacklisted()` static method; 90-day pre-save expiry hook |
| `routes/phishing.js` | `analyzeRateLimiter` applied per-route |

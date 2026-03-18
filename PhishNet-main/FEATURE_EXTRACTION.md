# PhishNet — Complete Feature Extraction Guide

**Version**: 1.0 | **Date**: March 2026
**Covers**: Dataset preprocessing → Feature engineering → Runtime extraction → Score calculation → ML vector

---

## Table of Contents

1. [Overview](#1-overview)
2. [The Dataset](#2-the-dataset)
3. [Dataset Preprocessing](#3-dataset-preprocessing)
4. [The 9 Original UCI Features](#4-the-9-original-uci-features)
5. [The 8 Engineered Features](#5-the-8-engineered-features)
6. [Complete Feature Vector (17 Features)](#6-complete-feature-vector-17-features)
7. [Runtime Feature Extraction (Live URLs)](#7-runtime-feature-extraction-live-urls)
   - 7.1 [Initialization: What Happens First](#71-initialization-what-happens-first)
   - 7.2 [How Each Feature Is Extracted from a Live URL](#72-how-each-feature-is-extracted-from-a-live-url)
   - 7.3 [How Each Engineered Feature Is Computed at Runtime](#73-how-each-engineered-feature-is-computed-at-runtime)
   - 7.4 [Private Metadata Fields (Not in ML Vector)](#74-private-metadata-fields-not-in-ml-vector)
   - 7.5 [Assembling the Final ML Vector](#75-assembling-the-final-ml-vector)
8. [ML Model Training](#8-ml-model-training)
9. [Score Calculation and Boosting](#9-score-calculation-and-boosting)
10. [End-to-End Example](#10-end-to-end-example)

---

## 1. Overview

PhishNet uses a 17-feature vector derived from the UCI Website Phishing dataset. These features are:
- **Structural** — properties of the URL string itself (length, IP address, SSL)
- **Content-based** — properties of the fetched page (forms, anchors, scripts)
- **Temporal** — domain registration age (WHOIS)
- **Engineered** — combinations and counts derived from the 9 base features

The same 17 features are extracted both at **training time** (from the CSV dataset) and at **runtime** (from a live URL by fetching the actual page). This guarantees the vector fed to the trained model matches what the model learned.

```
Dataset (WebsitePhishing.csv)
  9 base features per row
        ↓
  Feature Engineering (8 new columns computed from the 9 base features)
        ↓
  Final X matrix: 1,353 rows × 17 features
        ↓
  Train/Test split → 5 models trained

Live URL (runtime)
  UCIFeatureExtractor fetches page → computes same 17 values
        ↓
  np.array([...]) in FEATURE_NAMES order
        ↓
  model.predict_proba(X) for all 5 models
```

---

## 2. The Dataset

| Property | Value |
|----------|-------|
| **File** | `FlaskBack/WebsitePhishing.csv` |
| **Source** | UCI Machine Learning Repository — Website Phishing Dataset |
| **Raw rows** | 12,017 rows × 10 columns |
| **After cleaning** | 1,353 rows × 10 columns (duplicates removed in clean run) |
| **Training used** | 9,401 samples (80%) |
| **Test used** | 2,351 samples (20%) |
| **Target column** | `Result` |
| **Original encoding** | −1 = Phishing, 0 = Suspicious, 1 = Legitimate |
| **After binarization** | 0 = Phishing (includes Suspicious), 1 = Legitimate |

### Column List (Raw CSV)

```
SFH, popUpWidnow, SSLfinal_State, Request_URL, URL_of_Anchor,
web_traffic, URL_Length, age_of_domain, having_IP_Address, Result
```

All 9 feature columns contain only three possible values: **−1**, **0**, or **1**.

---

## 3. Dataset Preprocessing

### Step 1 — Load and Inspect

```python
df = pd.read_csv('WebsitePhishing.csv')
# Shape: (12017, 10) in raw form

df.info()
# All columns: int64 (no missing values, no nulls)
# All feature values already in {-1, 0, 1}
```

### Step 2 — Binarize the Target Label

The original dataset has a 3-class target. For binary classification:

```python
# Merge Suspicious (0) into the Phishing class
df_clean['Result'] = df_clean['Result'].apply(lambda x: 0 if x <= 0 else 1)

# Result:
#   -1 (Phishing)   → 0
#    0 (Suspicious)  → 0   ← merged into phishing
#    1 (Legitimate)  → 1
```

**Rationale**: A page that shows suspicious (ambiguous) signals is treated as a potential threat. This is a conservative design choice — it is better to miss a borderline legitimate page than to miss a borderline phishing page.

### Step 3 — Check Class Balance

```python
print(df_clean['Result'].value_counts())
# 0 (Phishing):    4854 rows
# 1 (Legitimate):  6897 rows
# Ratio: ~41.5% phishing / 58.5% legitimate
```

The dataset is mildly imbalanced. This is handled by using `class_weight='balanced'` in Random Forest and `balanced_accuracy` as the scoring metric in all GridSearchCV runs.

### Step 4 — No Scaling Applied

Tree-based models (Random Forest, LightGBM, XGBoost, CatBoost) do not require feature scaling — they make decisions based on split thresholds, not distances. No StandardScaler or normalization is applied to the feature matrix.

### Step 5 — Train / Test Split

```python
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.20,     # 20% held out for testing
    stratify=y,         # preserve class ratio in both splits
    random_state=42     # reproducible split
)

# Final sizes:
# X_train: 9,401 samples  (Phishing: 3,883  /  Legit: 5,518)
# X_test:  2,351 samples  (Phishing:   971  /  Legit: 1,380)
```

---

## 4. The 9 Original UCI Features

These 9 features come directly from the dataset CSV columns. They each encode domain knowledge about phishing indicators as categorical values: **−1** (phishing indicator), **0** (suspicious/unknown), **1** (legitimate indicator).

---

### Feature 1 — `having_IP_Address`

**What it measures**: Whether the domain part of the URL is a raw IP address rather than a hostname.

| Value | Meaning | Example |
|-------|---------|---------|
| `1` | IP address present (phishing indicator) | `http://192.168.1.1/login` |
| `0` | No IP address | `https://paypal.com` |

**Why it matters**: Phishing sites frequently use raw IP addresses to avoid registering a domain (cheaper, faster, harder to trace). Legitimate sites almost never use raw IPs as their primary URL.

**Dataset distribution**:
```
Value  1: ~3% of rows (IP-based URLs are rare but strongly phishing-associated)
Value  0: ~97% of rows
```

**Note**: The original UCI dataset encoding treats **1 = IP present = phishing**, unlike the standard UCI convention where 1 = legitimate. The runtime extractor matches this: returns `1` if the domain is an IP, `0` otherwise.

---

### Feature 2 — `URL_Length`

**What it measures**: The total character length of the URL, encoded into three categories.

| Value | Meaning | Condition |
|-------|---------|-----------|
| `1` | Short URL (legitimate indicator) | Length < 54 characters |
| `0` | Medium URL (suspicious) | Length 54–75 characters |
| `-1` | Long URL (phishing indicator) | Length > 75 characters |

**Why it matters**: Phishing URLs tend to be long because they embed the target brand name, add path noise, or include query parameters to bypass filters (e.g. `https://paypal-secure-login.update-account.com/verification?token=abc123xyz`).

**Dataset distribution**:
```
Value  1 (short):   ~47% of rows
Value  0 (medium):  ~24% of rows
Value -1 (long):    ~29% of rows
```

---

### Feature 3 — `SSLfinal_State`

**What it measures**: Whether the URL uses HTTPS (SSL/TLS encryption).

| Value | Meaning |
|-------|---------|
| `1` | HTTPS present (legitimate indicator) |
| `-1` | HTTP only, no encryption (phishing indicator) |

**Why it matters**: All legitimate websites serving sensitive content (banking, login forms, payments) use HTTPS. Phishing pages using plain HTTP expose credentials in transit and indicate low-cost/disposable infrastructure.

**Note**: The runtime extractor checks `urlparse(url).scheme == 'https'` only — it does not verify the certificate's validity or expiry.

---

### Feature 4 — `Request_URL`

**What it measures**: The proportion of resources (images, scripts, stylesheets) loaded from external domains.

| Value | Meaning | Condition |
|-------|---------|-----------|
| `1` | Mostly same-domain resources | External ratio < 22% |
| `0` | Mixed (suspicious) | External ratio 22–61% |
| `-1` | Mostly external resources (phishing indicator) | External ratio > 61% |

**Why it matters**: Phishing pages commonly steal the entire visual content of a legitimate site (CSS, images, logo) by loading resources directly from the legitimate domain. This makes the page look identical to the real site while serving a fake form. When > 61% of resources come from another domain, it strongly suggests the page is a visual clone.

---

### Feature 5 — `URL_of_Anchor`

**What it measures**: The proportion of `<a href>` anchor links pointing to external domains.

| Value | Meaning | Condition |
|-------|---------|-----------|
| `1` | Mostly same-domain links | External ratio < 31% |
| `0` | Mixed | External ratio 31–67% |
| `-1` | Mostly external links (phishing indicator) | External ratio > 67% |

**Why it matters**: Like `Request_URL`, this catches pages that are visually cloned from legitimate sites. A cloned phishing page will have many anchor links pointing back to the original legitimate domain (navigation menus, footer links, help pages), because the attacker copied the HTML without changing these links.

---

### Feature 6 — `SFH` (Server Form Handler)

**What it measures**: Where HTML form data is submitted — to the same domain, an external domain, or nowhere.

| Value | Meaning | Condition |
|-------|---------|-----------|
| `1` | Form submits to same domain (legitimate) | `action` attribute points to same domain |
| `0` | No form found | No `<form>` tags on page |
| `-1` | Form submits externally or action is empty (phishing) | `action` is blank, `#`, or different domain |

**Why it matters**: This is one of the most direct phishing indicators. A fake login page will display the visual interface of a legitimate site (copied HTML), but its form `action` attribute points to the attacker's server to collect the submitted credentials. An empty or `#` action also indicates a JavaScript-based form interception.

---

### Feature 7 — `popUpWidnow`

**What it measures**: Whether the page uses JavaScript `window.open()` or similar popup mechanisms.

| Value | Meaning |
|-------|---------|
| `1` | Page has popups (phishing indicator) |
| `-1` | Page fetched, no popups found (legitimate indicator) |
| `0` | Page could not be fetched (neutral — no penalty applied) |

**Why it matters**: Phishing pages sometimes use aggressive popup windows to create urgency (e.g. "Your account has been suspended — click here immediately"), to display fake login dialogs, or to redirect users to credential-harvesting pages. Legitimate sites rarely use `window.open()` for core content.

**Critical design note**: When the page cannot be fetched (network error, 403, auth-gated), this feature returns `0` (neutral) rather than `-1` (phishing). This prevents false positives on legitimate enterprise systems that block automated HTTP requests.

---

### Feature 8 — `age_of_domain`

**What it measures**: How long ago the domain was registered, measured via WHOIS.

| Value | Meaning | Condition |
|-------|---------|-----------|
| `1` | Established domain (legitimate indicator) | Domain age ≥ 180 days (6 months) |
| `0` | Unknown age | WHOIS query failed or returned no date |
| `-1` | Very new domain (phishing indicator) | Domain age < 180 days |

**Why it matters**: Phishing infrastructure has a very short lifespan. Attackers register domains specifically for a campaign, run them for days to weeks, then abandon them. A domain registered in the last 6 months is significantly more likely to be associated with a phishing campaign than a domain that has been active for years.

**Special case**: Domains in the `TRUSTED_DOMAINS` whitelist always return `1` regardless of WHOIS — this avoids false positives from WHOIS query failures on well-known domains.

---

### Feature 9 — `web_traffic`

**What it measures**: Whether the site has any detectable web presence (traffic, title, favicon).

| Value | Meaning |
|-------|---------|
| `1` | Trusted domain (bypass) |
| `0` | Page has basic presence (title or favicon found) |
| `-1` | No detectable web presence |

**Why it matters**: In the original UCI dataset this feature was based on Alexa traffic rank — sites outside the top 100,000 returned `-1`. Since Alexa is discontinued, the runtime extractor uses a proxy: if the fetched page has a `<title>` tag or a favicon `<link>` tag, it has basic web presence (`0`). Sites with no title and no favicon are typically fresh, disposable phishing or malware servers (`-1`).

---

## 5. The 8 Engineered Features

These features are **computed from the 9 base features** — they do not require additional data sources. They capture combinations and aggregate patterns that help the ML models learn compound risk signals more efficiently than the raw features alone.

---

### Engineered Feature 1 — `PhishingSignalCount`

**Formula**:
```python
PhishingSignalCount = count(f == -1 for f in [SFH, popUpWidnow, SSLfinal_State,
    Request_URL, URL_of_Anchor, web_traffic, URL_Length, age_of_domain, having_IP_Address])
```

**Range**: 0 to 9 (integer)

**What it captures**: The total number of features that are individually indicating phishing. A URL with 7 out of 9 features pointing to phishing is almost certainly malicious even if each individual feature has a small weight in the model.

**Example**:
- `paypal.com` → all features clean → `PhishingSignalCount = 0`
- Fresh phishing kit → no HTTPS, young domain, external form, external resources, no traffic → `PhishingSignalCount = 5`

---

### Engineered Feature 2 — `LegitSignalCount`

**Formula**:
```python
LegitSignalCount = count(f == 1 for f in [SFH, popUpWidnow, SSLfinal_State,
    Request_URL, URL_of_Anchor, web_traffic, URL_Length, age_of_domain, having_IP_Address])
```

**Range**: 0 to 9 (integer)

**What it captures**: The total number of features pointing to legitimacy. A high count provides strong evidence the URL is genuine. When `LegitSignalCount ≥ 4`, the score calculator applies a −0.10 downward boost to the phishing probability.

---

### Engineered Feature 3 — `NetScore`

**Formula**:
```python
NetScore = sum([SFH, popUpWidnow, SSLfinal_State, Request_URL, URL_of_Anchor,
    web_traffic, URL_Length, age_of_domain, having_IP_Address])
```

**Range**: −9 to +9 (integer)

**What it captures**: The signed balance of all feature votes. Each feature casts a vote of −1 (phishing), 0 (neutral), or +1 (legitimate). NetScore is the sum.

| NetScore | Interpretation |
|----------|---------------|
| +7 to +9 | Strongly legitimate — nearly all features agree it's safe |
| +3 to +6 | Moderately legitimate — most features point to safety |
| −1 to +2 | Mixed / ambiguous signals |
| −3 to −4 | Moderate phishing signals |
| −5 to −9 | Strong phishing signals across multiple dimensions |

**Score adjustment applied** (in `calculate_phishing_score_uci`):
```
NetScore ≥ 3   → boost −0.15  (strong legit profile)
NetScore ≥ 1   → boost −0.08  (moderate legit)
NetScore ≤ −3  → boost +0.15  (strong phishing)
NetScore ≤ −1  → boost +0.08  (moderate phishing)
```

---

### Engineered Feature 4 — `PhishingSignalRatio`

**Formula**:
```python
PhishingSignalRatio = PhishingSignalCount / 9
```

**Range**: 0.0 to 1.0 (float)

**What it captures**: The fraction of the 9 features that are pointing to phishing, expressed as a probability-like value. This is a normalized version of `PhishingSignalCount` that allows the models to use it alongside probability-scaled features.

**Example**:
- `PhishingSignalCount = 5` → `PhishingSignalRatio = 0.556`
- `PhishingSignalCount = 9` → `PhishingSignalRatio = 1.000` (all features indicate phishing)

---

### Engineered Feature 5 — `BadSFH_BadSSL`

**Formula**:
```python
BadSFH_BadSSL = int(SFH == -1 AND SSLfinal_State == -1)
```

**Values**: 0 (false) or 1 (true)

**What it captures**: Both the form submission target is external **and** the page has no HTTPS. This combination is the classic credential-theft setup: a page that accepts username/password inputs but sends them unencrypted to an external server. It is nearly impossible to justify this on a legitimate website.

**Score adjustment**: When `BadSFH_BadSSL == 1` → boost +0.15

---

### Engineered Feature 6 — `NoSSL_HasIP`

**Formula**:
```python
NoSSL_HasIP = int(SSLfinal_State == -1 AND having_IP_Address == 1)
```

**Values**: 0 (false) or 1 (true)

**What it captures**: The URL uses a raw IP address **and** has no HTTPS. Raw IPs with no SSL are almost exclusively malware command-and-control servers, fresh phishing kits, or botnets. No legitimate service uses `http://1.2.3.4/` as its primary URL.

**Score adjustment**: When `NoSSL_HasIP == 1` → boost +0.20

---

### Engineered Feature 7 — `YoungDomain_NoSSL`

**Formula**:
```python
YoungDomain_NoSSL = int(age_of_domain == -1 AND SSLfinal_State == -1)
```

**Values**: 0 (false) or 1 (true)

**What it captures**: The domain was registered less than 6 months ago **and** it has no HTTPS. This is the standard profile of a freshly-deployed phishing kit: a new domain bought cheaply (often with a free or suspicious TLD) to host a credential-harvesting page for a short-lived campaign.

**Note**: This combination is captured at both the individual feature level (each of the two contributing features has its own weight) AND the interaction level (their co-occurrence here). This gives the ML model an additional, explicit interaction term to learn from.

---

### Engineered Feature 8 — `SuspiciousCount`

**Formula**:
```python
SuspiciousCount = count(f == 0 for f in [SFH, popUpWidnow, SSLfinal_State,
    Request_URL, URL_of_Anchor, web_traffic, URL_Length, age_of_domain, having_IP_Address])
```

**Range**: 0 to 9 (integer)

**What it captures**: The number of features with uncertain/unknown values. A value of 0 means the feature check was inconclusive (WHOIS unavailable, page could not be fetched, form not found, etc.). A high `SuspiciousCount` indicates the URL could not be fully analyzed — it is neither clearly legitimate nor clearly phishing.

**Relationship to other features**:
- `SuspiciousCount + LegitSignalCount + PhishingSignalCount = 9` (always, by construction)
- A URL with `SuspiciousCount = 8` has almost no analyzable signal — models assign moderate probability near the base rate

---

## 6. Complete Feature Vector (17 Features)

The final 17-feature vector, in the exact order stored in `FEATURE_NAMES` (as saved in the pickle bundle):

```python
FEATURE_NAMES = [
    # ── 9 Original UCI features ──────────────────────────────────────
    'SFH',               # Form submission handler target
    'popUpWidnow',       # JavaScript popup windows
    'SSLfinal_State',    # HTTPS presence
    'Request_URL',       # External resource ratio
    'URL_of_Anchor',     # External anchor link ratio
    'web_traffic',       # Site web presence indicator
    'URL_Length',        # URL character length (3-class)
    'age_of_domain',     # Domain registration age (3-class)
    'having_IP_Address', # Raw IP address as domain

    # ── 8 Engineered features ────────────────────────────────────────
    'PhishingSignalCount',  # Count of features == -1
    'LegitSignalCount',     # Count of features == +1
    'NetScore',             # Sum of all 9 feature values
    'PhishingSignalRatio',  # PhishingSignalCount / 9
    'NoSSL_HasIP',          # SSL==-1 AND IP==1   (binary interaction)
    'BadSFH_BadSSL',        # SFH==-1 AND SSL==-1  (binary interaction)
    'YoungDomain_NoSSL',    # age==-1 AND SSL==-1  (binary interaction)
    'SuspiciousCount',      # Count of features == 0
]
```

### Value Reference Table

| Feature | −1 meaning | 0 meaning | 1 meaning | Range |
|---------|-----------|-----------|-----------|-------|
| `SFH` | External/empty form action | No form found | Same-domain form action | {-1, 0, 1} |
| `popUpWidnow` | Page has popups | Page inaccessible / no data | No popups found | {-1, 0, 1} |
| `SSLfinal_State` | HTTP (no SSL) | — | HTTPS present | {-1, 1} |
| `Request_URL` | >61% resources external | 22–61% external | <22% external | {-1, 0, 1} |
| `URL_of_Anchor` | >67% anchors external | 31–67% external | <31% external | {-1, 0, 1} |
| `web_traffic` | No title or favicon | Has basic web presence | Trusted domain | {-1, 0, 1} |
| `URL_Length` | URL > 75 chars | URL 54–75 chars | URL < 54 chars | {-1, 0, 1} |
| `age_of_domain` | Domain < 6 months old | WHOIS unavailable | Domain ≥ 6 months | {-1, 0, 1} |
| `having_IP_Address` | — | No IP in domain | IP address used as domain | {0, 1} |
| `PhishingSignalCount` | — | 0 = all clean | 9 = all phishing | 0–9 |
| `LegitSignalCount` | — | 0 = no legit signals | 9 = all legit | 0–9 |
| `NetScore` | All phishing | Mixed | All legitimate | −9 to +9 |
| `PhishingSignalRatio` | — | 0.0 = clean | 1.0 = all phishing | 0.0–1.0 |
| `NoSSL_HasIP` | — | Not present | IP + no SSL | {0, 1} |
| `BadSFH_BadSSL` | — | Not present | External form + no SSL | {0, 1} |
| `YoungDomain_NoSSL` | — | Not present | New domain + no SSL | {0, 1} |
| `SuspiciousCount` | — | 0 = all features resolved | 9 = all features unknown | 0–9 |

---

## 7. Runtime Feature Extraction (Live URLs)

At runtime, `UCIFeatureExtractor` recomputes all 17 features for any given URL by analyzing the live page. The process mirrors the dataset engineering exactly, ensuring the ML model receives the same type of values it was trained on.

### 7.1 Initialization: What Happens First

When `UCIFeatureExtractor(url)` is called, four things happen sequentially before any feature is computed:

```
Step 1 — URL Parsing
  self.parsed = urlparse(url)
  Extracts: scheme (http/https), netloc (domain + port), path, query

Step 2 — Domain Extraction
  self.domain = parsed.netloc.split(':')[0].replace("www.", "").lower()
  tldextract.extract(url) → separates subdomain / domain / TLD
  e.g. "login.secure-paypal.com" → subdomain="login.secure", domain="paypal", suffix="com"
  whois_domain = f"{domain}.{suffix}"  → "paypal.com" (used for WHOIS, not subdomain)

Step 3 — WHOIS Query (for age_of_domain)
  safe_whois(whois_domain)  — 5-second timeout, returns None on failure
  Queries: creation_date, updated_date, registrar, expiration_date

Step 4 — Live Page Fetch (for all content-based features)
  requests.get(url, timeout=5, allow_redirects=True,
               headers={"User-Agent": "Mozilla/5.0"},
               verify=False)
  On success: store response.text as page_html, parse with BeautifulSoup
  On failure (timeout, 403, SSL error, DNS error): page_html="", soup=None
```

**Timing**: Steps 3 and 4 run concurrently with the rest of the pipeline where possible.

**Failure behavior**: If the page cannot be fetched, all DOM-dependent features (`SFH`, `Request_URL`, `URL_of_Anchor`, `popUpWidnow`) default to `0` (neutral) rather than `-1` (phishing). This is a deliberate design decision to avoid false positives on:
- Enterprise portals that block automated HTTP requests (401/403)
- Auth-gated pages (redirected to login before content)
- Network-restricted services (VPN-only, geo-blocked)

---

### 7.2 How Each Feature Is Extracted from a Live URL

#### `having_IP_Address`

```python
def _having_ip_address(self):
    try:
        ipaddress.ip_address(self.domain)  # raises ValueError if not an IP
        return 1   # domain is a raw IP → phishing indicator
    except Exception:
        return 0   # domain is a hostname → no signal
```

**Input**: `self.domain` (the `netloc` component of the URL with port and `www.` stripped)
**Test cases**:
- `http://192.168.1.10/login.php` → domain = `192.168.1.10` → returns `1`
- `https://paypal.com` → domain = `paypal.com` → raises ValueError → returns `0`

---

#### `SSLfinal_State`

```python
def _ssl_final_state(self):
    return 1 if self.parsed.scheme == 'https' else -1
```

**Input**: The scheme portion of the parsed URL
**Note**: This is a simple scheme check, not a certificate validation. A self-signed or expired certificate still returns `1` if the scheme is `https`.

---

#### `URL_Length`

```python
def _url_length(self):
    n = len(self.url)          # full raw URL character count
    if n < 54:   return 1      # short → legitimate
    if n <= 75:  return 0      # medium → suspicious
    return -1                   # long → phishing
```

**Input**: The complete URL string (including scheme, query string, fragment)

---

#### `age_of_domain`

```python
def _age_of_domain(self):
    base = '.'.join(self.domain.split('.')[-2:])   # e.g. "paypal.com"

    if base in TRUSTED_DOMAINS:                    # shortcut for known-good domains
        return 1

    if not self.whois_response:
        return 0                                   # WHOIS failed → unknown

    cd = self.whois_response.creation_date
    if isinstance(cd, list):
        cd = cd[0]                                 # some WHOIS returns a list

    if cd:
        age_days = (datetime.now() - cd).days
        return 1 if age_days >= 180 else -1        # 6-month threshold
    return 0
```

**Input**: WHOIS response (queried in `__init__` during initialization)
**Threshold**: 180 days (6 months) — domains younger than this are flagged as suspicious

---

#### `SFH` (Server Form Handler)

```python
def _sfh(self):
    if not self.soup:
        return 0                                   # page inaccessible → neutral

    for form in self.soup.find_all("form"):
        action = form.get("action", "").strip()
        if not action:
            continue
        if action.startswith("http") and self.domain not in action:
            return -1                              # external domain → phishing
        if action.startswith("/") or self.domain in action:
            return 1                               # same domain → legitimate
    return 0                                       # no forms found → neutral
```

**Input**: All `<form>` elements in the parsed HTML DOM
**Logic**: Iterates all forms. Returns `-1` immediately on the first form that submits to an external domain. Returns `1` if all forms submit to the same domain. Returns `0` if no forms exist.

---

#### `popUpWidnow`

```python
def _popup_widnow(self):
    if not self.soup:
        return 0                                   # page inaccessible → neutral (NOT -1)

    popups = re.findall(r"window\.open|alert\(|confirm\(|popup",
                        str(self.soup), re.I)
    return 1 if popups else -1
```

**Input**: The full rendered HTML (converted to string for regex search)
**Regex matches**: `window.open(`, `alert(`, `confirm(`, `popup` (case-insensitive)
**Note**: Returns `1` (phishing indicator) if popups ARE found, and `-1` (legitimate indicator) if the page was successfully fetched but contains no popups. Returns `0` only when the page is completely inaccessible. This is the **inverted** convention compared to the other features — popups present = phishing.

---

#### `Request_URL`

```python
def _request_url(self):
    if not self.soup:
        return 0

    total = 0
    external = 0

    # Count <img>, <script> src attributes
    for tag in self.soup.find_all(["img", "script"]):
        src = tag.get("src", "")
        if src:
            total += 1
            if src.startswith("http") and self.domain not in src:
                external += 1

    # Count <link rel="stylesheet"> href attributes
    for tag in self.soup.find_all("link", rel=lambda r: r and "stylesheet" in " ".join(r).lower()):
        href = tag.get("href", "")
        if href:
            total += 1
            if href.startswith("http") and self.domain not in href:
                external += 1

    if total == 0:
        return 0

    ratio = external / total
    if ratio < 0.22:   return 1    # mostly same-domain → legitimate
    if ratio < 0.61:   return 0    # mixed → suspicious
    return -1                       # mostly external → phishing (visual clone)
```

**Input**: All `<img>`, `<script>`, and `<link rel="stylesheet">` elements
**Thresholds**: 22% and 61% (same as original UCI paper)

---

#### `URL_of_Anchor`

```python
def _url_of_anchor(self):
    if not self.soup:
        return 0

    total = 0
    external = 0

    for a in self.soup.find_all("a", href=True):
        href = a["href"].strip()
        # Skip empty or JavaScript-only links
        if not href or href in ["#", "javascript:void(0)", "javascript:;"]:
            continue
        total += 1
        if href.startswith("http") and self.domain not in href:
            external += 1

    if total == 0:
        return 1                   # no external links at all → legitimate

    ratio = external / total
    if ratio < 0.31:   return 1    # mostly internal links → legitimate
    if ratio < 0.67:   return 0    # mixed → suspicious
    return -1                       # mostly external links → phishing clone
```

**Input**: All `<a href>` elements (excluding empty anchors and javascript: pseudo-links)
**Thresholds**: 31% and 67% (same as original UCI paper)

---

#### `web_traffic`

```python
def _web_traffic(self):
    base = '.'.join(self.domain.split('.')[-2:])
    if base in TRUSTED_DOMAINS:
        return 1                   # trusted domain always returns 1

    if self.soup:
        has_title   = bool(self.soup.find("title") and
                           self.soup.find("title").get_text(strip=True))
        has_favicon = bool(self.soup.find_all("link",
                           rel=lambda r: r and "icon" in " ".join(r).lower()))
        if has_title or has_favicon:
            return 0               # basic web presence detected → neutral
    return -1                      # no presence detected → phishing indicator
```

**Input**: DOM presence of `<title>` tag and `<link rel="icon">` (favicon)
**Note**: The original UCI feature used Alexa traffic rank (discontinued). This is the modern proxy: a domain with a title and favicon has at least minimal legitimate web presence.

---

### 7.3 How Each Engineered Feature Is Computed at Runtime

After the 9 base features are extracted, the engineered features are computed in a single pass in `extract()`:

```python
def extract(self):
    # Step 1: Extract all 9 base features
    raw = {
        'SFH':               self._sfh(),
        'popUpWidnow':       self._popup_widnow(),
        'SSLfinal_State':    self._ssl_final_state(),
        'Request_URL':       self._request_url(),
        'URL_of_Anchor':     self._url_of_anchor(),
        'web_traffic':       self._web_traffic(),
        'URL_Length':        self._url_length(),
        'age_of_domain':     self._age_of_domain(),
        'having_IP_Address': self._having_ip_address(),
    }

    # Step 2: Compute aggregate counts
    phish_count = sum(1 for f in self.UCI_FEATURE_COLS if raw[f] == -1)
    legit_count = sum(1 for f in self.UCI_FEATURE_COLS if raw[f] == 1)
    net_score   = sum(raw[f] for f in self.UCI_FEATURE_COLS)

    # Step 3: Build full feature dict (base + engineered)
    features = {
        **raw,
        'PhishingSignalCount': phish_count,
        'LegitSignalCount':    legit_count,
        'NetScore':            net_score,
        'PhishingSignalRatio': phish_count / len(self.UCI_FEATURE_COLS),  # /9
        'NoSSL_HasIP':         int(raw['SSLfinal_State'] == -1 and raw['having_IP_Address'] == 1),
        'BadSFH_BadSSL':       int(raw['SFH'] == -1 and raw['SSLfinal_State'] == -1),
        'YoungDomain_NoSSL':   int(raw['age_of_domain'] == -1 and raw['SSLfinal_State'] == -1),
        # SuspiciousCount is derived implicitly: 9 - phish_count - legit_count
        # but also stored explicitly for the model
    }
```

These computations are identical to the pandas operations done on the training dataset:

| Runtime Code | Training Dataset Code |
|-------------|----------------------|
| `sum(1 for f in cols if raw[f] == -1)` | `(df_clean[feature_cols] == -1).sum(axis=1)` |
| `sum(1 for f in cols if raw[f] == 1)` | `(df_clean[feature_cols] == 1).sum(axis=1)` |
| `sum(raw[f] for f in cols)` | `df_clean[feature_cols].sum(axis=1)` |
| `phish_count / 9` | `X_raw['PhishingSignalCount'] / len(feature_cols)` |
| `int(SFH==-1 and SSL==-1)` | `((df['SFH']==-1) & (df['SSLfinal_State']==-1)).astype(int)` |

---

### 7.4 Private Metadata Fields (Not in ML Vector)

After the 17-feature extraction, `UCIFeatureExtractor` computes additional fields that are stored in the features dict with a `_` prefix. These are **never included** in the ML prediction vector (which uses only the 17 features above), but are used by the Intelligent Fusion Engine and Score Calculator.

| Field | How Computed | Used For |
|-------|-------------|---------|
| `_domain` | `self.domain` (netloc after www. strip) | `is_trusted_domain()` lookup |
| `_domain_age_days` | `(datetime.now() - whois.creation_date).days` | Fusion engine scenario routing (e.g. Scenario 2.5 needs age ≤ 7 days) |
| `_recent_content_date` | Scans `<meta property="article:published_time">`, `<time datetime>`, JSON-LD `datePublished` | `_is_recently_active` flag |
| `_is_recently_active` | `True` if content date found within 90 days | Fusion scenario 2.8 (hijacked old domain with fresh cert) |
| `_subdomain` | `tldextract.extract(url).subdomain` | Fusion signals, hosting-keyword detection |
| `_domain_name` | `tldextract.extract(url).domain` | Fusion brand cross-check |
| `_tld` | `tldextract.extract(url).suffix` | Fusion suspicious-TLD check |
| `_subdomain_count` | Count of `.`-separated labels in subdomain | Rule engine correlation |
| `_url_raw_length` | `len(self.url)` | Fusion signals |
| `_subdomain_enum` | crt.sh certificate transparency + DNS brute-force | Exposes hidden phishing infrastructure |

#### Subdomain Enumeration Detail

`_enumerate_subdomains()` discovers all subdomains of the scanned domain:

```
1. crt.sh Certificate Transparency query:
   GET https://crt.sh/?q=%.example.com&output=json
   Reads up to 512 KB (cap prevents blocking on large domains)
   Extracts all SAN names ending with .example.com

2. DNS brute-force (25 parallel threads, 8-second budget):
   Tests 38 common subdomains: www, mail, webmail, admin, login,
   secure, auth, app, api, dashboard, payment, checkout, portal, etc.
   Uses socket.getaddrinfo() — succeeds if DNS resolves

3. Returns: { found: [...], count: N, base_domain: "...", sources: [...] }
```

The subdomain enumeration output is stored in `_subdomain_enum` and returned in the API response. It helps security analysts understand the full phishing infrastructure — a domain with subdomains like `login.`, `secure.`, `pay.` alongside its main phishing page is clearly a coordinated attack.

---

### 7.5 Assembling the Final ML Vector

After `extract()` builds the full features dict, the 17 values are assembled into a NumPy array in the exact column order the models were trained on:

```python
vector = np.array([features.get(f, 0) for f in FEATURE_NAMES])
X = vector.reshape(1, -1)   # shape: (1, 17)
```

`FEATURE_NAMES` is loaded at Flask startup from the saved pickle bundle — it is the exact column order used during model training. `features.get(f, 0)` defaults any missing feature to `0` (neutral), which is safe because missing features only occur for the private `_` fields that are not in `FEATURE_NAMES`.

Each of the 5 models is then called:
```python
probabilities = {}
for name, model in MODELS.items():
    probabilities[name] = float(model.predict_proba(X)[0, 1])
# Returns probability of class 1 (Legitimate)
# PhishNet uses 1 - prob as phishing score
```

---

## 8. ML Model Training

### Cross-Validation Strategy

```python
cv = StratifiedKFold(n_splits=5, shuffle=False, random_state=42)
# 5 folds, class distribution preserved in each fold
# All hyperparameter search uses this CV object
```

### Model 1 — Random Forest

**Why chosen**: Highly stable under distribution shift; handles the integer-valued UCI features well; provides good SHAP TreeExplainer support.

```python
rf_param_dist = {
    'n_estimators':      [100, 150, 200, 300],
    'max_depth':         [5, 8, 10, 15, None],
    'min_samples_split': [2, 5, 10],
    'min_samples_leaf':  [1, 2, 4],
    'max_features':      ['sqrt', 'log2'],
    'class_weight':      ['balanced'],   # handles class imbalance
}
search = RandomizedSearchCV(
    RandomForestClassifier(random_state=42),
    param_distributions=rf_param_dist,
    n_iter=30,
    cv=cv,
    scoring='balanced_accuracy',
    n_jobs=1,                           # Python 3.14 + joblib fix
    random_state=42
)

# Best params found:
# n_estimators=150, max_depth=15, min_samples_split=10,
# min_samples_leaf=4, max_features='log2', class_weight='balanced'
```

### Model 2 — LightGBM

**Why chosen**: Fastest training; handles the small integer feature space efficiently via histogram-based splitting; lower memory than XGBoost.

```python
lgb_param_dist = {
    'n_estimators':      [100, 150, 200, 300],
    'learning_rate':     [0.03, 0.05, 0.07, 0.1],
    'num_leaves':        [15, 31, 63],
    'max_depth':         [-1, 5, 8, 10],
    'min_child_samples': [10, 20, 30, 50],
    'colsample_bytree':  [0.7, 0.8, 1.0],
    'subsample':         [0.7, 0.8, 0.9, 1.0],
}
# Best params found:
# n_estimators=300, learning_rate=0.05, num_leaves=31, max_depth=10,
# min_child_samples=30, colsample_bytree=0.8, subsample=1.0
```

### Model 3 — XGBoost

**Why chosen**: Best accuracy on the training set; `gamma` regularization helps prevent overfitting on the small UCI dataset.

```python
xgb_param_dist = {
    'n_estimators':     [100, 150, 200, 300],
    'max_depth':        [3, 4, 5, 6, 7],
    'learning_rate':    [0.03, 0.05, 0.07, 0.1],
    'subsample':        [0.7, 0.8, 0.9, 1.0],
    'colsample_bytree': [0.7, 0.8, 1.0],
    'gamma':            [0, 0.05, 0.1, 0.2],       # min loss reduction for split
    'min_child_weight': [1, 3, 5],
}
# Best params found:
# n_estimators=150, max_depth=7, learning_rate=0.1,
# subsample=0.9, colsample_bytree=0.8, gamma=0.05, min_child_weight=3
```

### Model 4 — CatBoost

**Why chosen**: Natively handles categorical features — the UCI features are integers in {−1, 0, 1} and CatBoost's ordered boosting handles this type of low-cardinality categorical data best. Best overall balanced accuracy.

```python
cat_param_dist = {
    'iterations':           [100, 150, 200, 300],
    'depth':                [4, 6, 7, 8, 10],
    'learning_rate':        [0.03, 0.05, 0.07, 0.1],
    'l2_leaf_reg':          [1, 3, 5, 7],            # L2 regularization
    'bagging_temperature':  [0.0, 0.3, 0.5, 1.0],   # diversity via bootstrap
    'border_count':         [32, 64, 128],            # histogram bins
}
# Best params found:
# iterations=300, depth=8, learning_rate=0.03,
# l2_leaf_reg=7, bagging_temperature=1.0, border_count=128
```

### Model 5 — Stacking Classifier

**Why chosen**: Meta-learner that learns to optimally combine the outputs of all 4 base models. Achieves higher accuracy than any single model by exploiting complementary error patterns.

```python
stacking = StackingClassifier(
    estimators=[
        ('rf',       best_rf),
        ('lgb',      best_lgb),
        ('xgb',      best_xgb),
        ('catboost', best_cat),
    ],
    final_estimator=LogisticRegression(max_iter=1000, random_state=42),
    cv=5,              # 5-fold out-of-fold predictions for meta-features
    n_jobs=1,          # Python 3.14 + joblib fix
    passthrough=False  # meta-learner sees only model outputs, not raw features
)
```

The meta-learner is a `LogisticRegression` that receives the 4 probability outputs as its 4-dimensional input and outputs a final probability.

### Training Metrics (Test Set — 2,351 samples)

| Model | Accuracy | F1 | Balanced Acc | AUC-ROC | Recall Phishing | Recall Legit |
|-------|----------|-----|-------------|---------|----------------|-------------|
| CatBoost | 85.27% | 0.850 | 0.853 | 0.925 | 86.35% | 84.26% |
| Stacking | 85.23% | 0.850 | 0.853 | 0.925 | 86.01% | 84.50% |
| XGBoost | 85.07% | 0.848 | 0.851 | 0.921 | 85.67% | 84.50% |
| LightGBM | 84.90% | 0.847 | 0.850 | 0.923 | 86.52% | 83.37% |
| Random Forest | 84.40% | 0.839 | 0.844 | 0.917 | 83.78% | 84.99% |

**Detection threshold**: Fixed at **0.63** (not the bundle's 0.425 — the bundle threshold is too low for a production environment and would cause excessive false positives). At threshold 0.63:
- Probability ≥ 0.63 → Phishing
- Probability < 0.63 → Legitimate (or Suspicious, depending on fusion)

---

## 9. Score Calculation and Boosting

After the 5 models return their probabilities, the raw ensemble average is not used directly. `calculate_phishing_score_uci()` applies domain-knowledge-based adjustments to correct for known model failure modes.

### Base Score

```python
base_score = float(np.mean(list(model_probabilities.values())))
# Average of 5 probabilities, each in [0, 1]
```

### Boost Table (All Conditions)

Boosts are additive. A single URL can trigger multiple boosts (positive and negative).

| Condition | Boost | Reason |
|-----------|-------|--------|
| Domain in `TRUSTED_DOMAINS` | −0.45 | Known legitimate service (Google, PayPal, etc.) |
| `NetScore ≥ 3` | −0.15 | Strongly legitimate feature profile |
| `NetScore ≥ 1` | −0.08 | Moderately legitimate feature profile |
| `LegitSignalCount ≥ 4` | −0.10 | Majority of features indicate legitimacy |
| `NetScore ≤ −3` | +0.15 | Strongly phishing feature profile |
| `NetScore ≤ −1` | +0.08 | Moderate phishing signals |
| `having_IP_Address == 1` | +0.35 | Raw IP used as domain |
| `SSLfinal_State == -1` | +0.15 | No HTTPS |
| `SFH == -1` | +0.20 | Form submits to external domain |
| `age_of_domain == -1` | +0.10 | New domain (< 6 months) |
| `popUpWidnow == 1` | +0.05 | JavaScript popups found |
| `NoSSL_HasIP == 1` | +0.20 | IP + no HTTPS combination |
| `BadSFH_BadSSL == 1` | +0.15 | External form + no HTTPS |
| `PhishingSignalCount ≥ 5` | +0.20 | Majority of features are phishing |
| `PhishingSignalCount ≥ 3` | +0.10 | Multiple phishing signals |
| `web_traffic == -1` | +0.08 | No web presence (obscure site) |
| `Request_URL == -1` | +0.08 | Most resources from external domain |
| `URL_of_Anchor == -1` | +0.05 | Most links to external domains |

### Hard Caps

```python
# Cap 1: Prevent feature-level boosts from overriding near-certain ML
if base_score > 0.80 and boost < -0.10:
    boost = -0.10
# Rationale: if all 5 models vote ~90% phishing, feature counting should not
# override them (the models have already seen those features)

# Cap 2: Hard ceiling for established trusted domains
domain_age_days = features.get('_domain_age_days', 0) or 0
if is_trusted_domain(domain) and domain_age_days > 365:
    final_score = min(final_score, 0.35)
# Rationale: paypal.com / google.com should never show > 35% phishing risk
# regardless of what ML or features say

# Final bounds
final_score = max(0.01, min(base_score + boost, 0.99))
```

### Score Interpretation

| Final Score | Verdict | Risk Level |
|-------------|---------|-----------|
| < 0.25 | Legitimate | Safe |
| 0.25–0.40 | Legitimate | Low |
| 0.40–0.63 | Suspicious (WARN) | Medium |
| 0.63–0.80 | Phishing (BLOCK) | High |
| > 0.80 | Phishing (BLOCK) | Critical |

Note: The actual verdict comes from the Intelligent Fusion Engine, not this threshold table directly. The fusion engine uses `final_score` as one of its input signals and may override it based on domain metadata, cloaking, or visual similarity.

---

## 10. End-to-End Example

**URL**: `https://amazon-secure-login.webflow.io/`

### Step 1 — UCIFeatureExtractor Initialization

```
URL parsing:
  scheme = "https"
  netloc = "amazon-secure-login.webflow.io"
  domain = "amazon-secure-login.webflow.io"  (after www. strip)

tldextract:
  subdomain = "amazon-secure-login"
  domain_name = "webflow"
  suffix = "io"
  whois_domain = "webflow.io"  ← WHOIS queried for this, not the subdomain

WHOIS: webflow.io → creation_date = 2013-04-xx → age > 180 days → trusted hosting platform

Page fetch: GET https://amazon-secure-login.webflow.io/
  → 200 OK, returns an Amazon-looking login page
  → soup parsed successfully
```

### Step 2 — Extract 9 Base Features

```
having_IP_Address:  ipaddress.ip_address("amazon-secure-login.webflow.io")
                    → ValueError → return 0

SSLfinal_State:     scheme == "https" → return 1

URL_Length:         len("https://amazon-secure-login.webflow.io/") = 41
                    41 < 54 → return 1  (short URL, no penalty)

age_of_domain:      whois_domain = "webflow.io" (not the subdomain)
                    webflow.io creation: 2013 → age >> 180 days → return 1
                    Note: WHOIS checks the registrar domain, not the user subdomain

SFH:                <form action="https://attacker-collector.com/steal">
                    attacker-collector.com ≠ amazon-secure-login.webflow.io
                    → return -1  (PHISHING)

popUpWidnow:        page fetched successfully, no window.open() found
                    → return -1  (legitimate — no popups)
                    Note: popUpWidnow=-1 means no popups (confusing but correct)

Request_URL:        <img src="https://images.amazon.com/logo.png">
                    <img src="https://images.amazon.com/button.png">
                    <script src="https://images.amazon.com/app.js">
                    3 external resources out of 3 total → ratio = 1.0
                    1.0 > 0.61 → return -1  (PHISHING — visual clone)

URL_of_Anchor:      <a href="https://amazon.com">View Cart</a>
                    <a href="https://amazon.com/help">Help</a>
                    <a href="https://amazon.com/returns">Returns</a>
                    3 external links out of 4 total → ratio = 0.75
                    0.75 > 0.67 → return -1  (PHISHING — clone links)

web_traffic:        webflow.io is in TRUSTED_DOMAINS → return 1
```

### Step 3 — Compute Engineered Features

```
raw = {
  'SFH': -1,  'popUpWidnow': -1,  'SSLfinal_State': 1,
  'Request_URL': -1,  'URL_of_Anchor': -1,  'web_traffic': 1,
  'URL_Length': 1,  'age_of_domain': 1,  'having_IP_Address': 0
}

PhishingSignalCount  = count(f == -1) = 3  [SFH, Request_URL, URL_of_Anchor]
LegitSignalCount     = count(f == 1)  = 4  [SSLfinal_State, web_traffic, URL_Length, age_of_domain]
NetScore             = sum = (-1 + -1 + 1 + -1 + -1 + 1 + 1 + 1 + 0) = 0
PhishingSignalRatio  = 3/9 = 0.333
NoSSL_HasIP          = int(-1==SSL and 1==IP) = int(False and False) = 0
BadSFH_BadSSL        = int(-1==SFH and -1==SSL) = int(True and False) = 0
YoungDomain_NoSSL    = int(-1==age and -1==SSL) = int(False and False) = 0
SuspiciousCount      = count(f == 0) = 1  [having_IP_Address]
```

### Step 4 — ML Prediction Vector

```python
X = [SFH=-1, popUpWidnow=-1, SSLfinal_State=1, Request_URL=-1,
     URL_of_Anchor=-1, web_traffic=1, URL_Length=1, age_of_domain=1,
     having_IP_Address=0,
     PhishingSignalCount=3, LegitSignalCount=4, NetScore=0,
     PhishingSignalRatio=0.333, NoSSL_HasIP=0, BadSFH_BadSSL=0,
     YoungDomain_NoSSL=0, SuspiciousCount=1]

Model outputs (predict_proba → phishing probability):
  RF:        0.82
  LGB:       0.89
  XGB:       0.91
  CatBoost:  0.88
  Stacking:  0.88

base_score = mean([0.82, 0.89, 0.91, 0.88, 0.88]) = 0.876
```

### Step 5 — Score Adjustment

```
boost = 0

webflow.io is in TRUSTED_DOMAINS → boost -= 0.45 = -0.45

NetScore = 0 → no net_score boost applied (need ≥ 1 or ≤ -1)

LegitSignalCount = 4 → boost -= 0.10 → boost = -0.55

having_IP_Address = 0 → no IP boost

SSLfinal_State = 1 → no SSL boost (HTTPS present)

SFH = -1 → boost += 0.20 → boost = -0.35

PhishingSignalCount = 3 → boost += 0.10 → boost = -0.25

Request_URL = -1 → boost += 0.08 → boost = -0.17

URL_of_Anchor = -1 → boost += 0.05 → boost = -0.12

Hard cap: base_score = 0.876 > 0.80 and boost = -0.12 < -0.10
  → cap applied: boost = -0.10

final_score = max(0.01, min(0.876 + (-0.10), 0.99)) = 0.776
```

### Step 6 — Intelligent Fusion Decision

```
ml_score = 0.776 (high phishing probability)
hosting_phish_keyword: "amazon" in subdomain "amazon-secure-login" → True
                        "secure" in subdomain → True (phishing action keyword)

Scenario 2.6 check:
  hosting_phish_keyword = True
  ml_score = 0.776 > 0.10
  → MATCH → route to fresh_phishing_setup

fresh_phishing_setup handler:
  risk = max(ml_score, cloaking_risk, 0.85) = max(0.776, 0.0, 0.85) = 0.85
  verdict = BLOCK
  confidence = 0.90

Trusted domain override check:
  verdict = BLOCK
  is_trusted_domain("amazon-secure-login.webflow.io") → webflow.io IS in TRUSTED_DOMAINS
  rule engine violations? → none
  _is_hosting_phish = True  ← GUARD: override does NOT fire
  (The phishing keyword was explicitly detected, so BLOCK is preserved)

Final verdict: BLOCK → Phishing
Final risk: 0.85
Scenario: fresh_phishing_setup
```

### Summary for this URL

| Feature | Value | Signal |
|---------|-------|--------|
| having_IP_Address | 0 | Neutral |
| SSLfinal_State | 1 | ✅ Legit |
| URL_Length | 1 | ✅ Legit |
| age_of_domain | 1 | ✅ Legit (webflow.io is old) |
| SFH | -1 | 🚨 Phishing (external form) |
| popUpWidnow | -1 | ✅ Legit (no popups) |
| Request_URL | -1 | 🚨 Phishing (all resources from amazon.com) |
| URL_of_Anchor | -1 | 🚨 Phishing (all links to amazon.com) |
| web_traffic | 1 | ✅ Legit (trusted hosting platform) |
| NetScore | 0 | Neutral |
| PhishingSignalCount | 3 | Moderate phishing |
| LegitSignalCount | 4 | Moderate legitimate |
| BadSFH_BadSSL | 0 | Not triggered |
| ML base_score | 0.876 | 🚨 High phishing |
| After boost | 0.776 | 🚨 High phishing |
| **Fusion verdict** | **BLOCK** | 🚨 **Phishing** |

The key signal that produces the BLOCK verdict is `hosting_phish_keyword=True` (brand "amazon" + phishing keyword "secure" found in the subdomain of a content-hosting platform), which routes directly to `fresh_phishing_setup` regardless of the legitimate domain age signal.

---

*End of PhishNet Feature Extraction Guide*
*Generated: March 2026 | Version: 1.0*

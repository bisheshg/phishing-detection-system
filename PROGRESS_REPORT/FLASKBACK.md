# Flask ML Service — Progress Report

**Technology:** Python 3.x, Flask 3, scikit-learn, LightGBM, XGBoost, CatBoost, SHAP
**Port:** 5002
**Location:** `PhishNet-main/FlaskBack/`

---

## Folder Structure

```
FlaskBack/
├── app.py                              ← Main Flask service
├── rule_engine.py                      ← Heuristic rule checks
├── requirements.txt                    ← Python dependencies
├── models/
│   ├── phishing_model_bundle_websitephishing.pkl   ← UCI model (preferred)
│   ├── phishing_model_bundle_REALISTIC_v3.pkl      ← Realistic model (fallback)
│   └── ... (other model iterations)
├── PhishNet_WebsitePhishing_Analysis.ipynb         ← UCI training notebook
├── Improved_Phishing_Detection.ipynb               ← Realistic training notebook
├── WebsitePhishing.csv                             ← UCI dataset (1353 rows)
├── phishurl.csv                                    ← Realistic dataset (235K rows)
├── catboost_info/                                  ← CatBoost training logs
├── feature_importance_improved.png                 ← Feature importance chart
├── model_comparison_improved.png                   ← Model comparison chart
└── roc_curves_improved.png                         ← ROC curves chart
```

---

## How the Flask Service Works

The Express backend calls Flask at `POST http://localhost:5002/analyze` with `{ "url": "..." }`.

Flask runs the URL through three layers:

```
POST /analyze  { url }
     │
     ├── Layer 0: is_trusted_domain(url)?
     │   └── YES → { prediction: 'Legitimate', detection_source: 'trusted', confidence: 99 }
     │
     ├── Layer 1: rule_engine.check(url)
     │   └── Rules fired? → { prediction: 'Phishing', detection_source: 'rule_engine',
     │                         rule_violations: [...], confidence: 85-100 }
     │
     └── Layer 2: ML Ensemble
         ├── Extract features (UCIFeatureExtractor or RealisticFeatureExtractor)
         ├── Run through 4 models: lgb, xgb, catboost, rf
         ├── Compute ensemble probability (weighted average)
         ├── Apply threshold (0.630 for UCI bundle)
         ├── Compute SHAP explanation
         └── Return full result
```

---

## Rule Engine (`rule_engine.py`)

The rule engine checks for 15+ heuristic patterns. If any fire, the URL is flagged without running ML (saves time).

**Rules implemented:**

| Rule | What it checks |
|------|---------------|
| IP Address | Domain is an IP (e.g. `192.168.1.1/bank`) |
| No HTTPS | URL uses `http://` |
| URL too long | URL length > 75 characters |
| Too many subdomains | More than 3 dot-separated parts |
| Suspicious keywords | "login", "verify", "secure", "account", "update", "banking", etc. |
| URL shortener | bit.ly, tinyurl, etc. |
| Port in URL | Non-standard ports like `:8080` in the domain |
| @ symbol | `user@phishing.com/page` style URLs |
| Double slash | `//` after domain path |
| Typosquatting | Similar to known trusted domains using Levenshtein distance |
| Punycode domain | Internationalized domain abuse (`xn--`) |
| Data URI | `data:text/html` scheme |
| Free hosting | netlify, github.io, weebly, etc. |
| Excessive subdomains | Domain like `secure.bank.login.phish.com` |

Each rule that fires adds a message to `rule_violations` list in the response.

---

## Machine Learning Models

### Active Bundle: `phishing_model_bundle_websitephishing.pkl` (UCI)

Trained on the **UCI WebsitePhishing dataset** (1,353 URLs, 9 original features).

**Models in the bundle:**

| Model | Library | Role |
|-------|---------|------|
| `lgb` | LightGBM | Ensemble member |
| `xgb` | XGBoost | Ensemble member |
| `catboost` | CatBoost | Ensemble member |
| `rf` | RandomForest (sklearn) | Ensemble member |
| `stacking` | StackingClassifier (sklearn) | Stacking meta-learner |

**Decision threshold:** 0.630 (loaded from bundle — optimized during training to maximize G-Mean)

**Ensemble voting:** Weighted average of `predict_proba` from each model. If `P(phishing) ≥ 0.630` → Phishing.

### Fallback Bundle: `phishing_model_bundle_REALISTIC_v3.pkl`

Trained on **phishurl.csv** (235,795 URLs, 50+ features). Requires full HTTP page fetch.

---

## Feature Extraction

### UCI Features (16 total)

The UCI model uses 9 categorical features encoded as `-1` (bad), `0` (neutral), `1` (good), plus 7 engineered features:

| Feature | Description |
|---------|-------------|
| `SFH` | Server Form Handler — does the form submit to an external server? |
| `popUpWidnow` | Does the page open popup windows? |
| `SSLfinal_State` | Is HTTPS enabled with a valid cert? |
| `Request_URL` | What % of embedded resources load from external domains? |
| `URL_of_Anchor` | What % of anchor tags point externally? |
| `web_traffic` | Alexa/traffic rank — high rank = more trusted |
| `URL_Length` | Length of the full URL |
| `age_of_domain` | How old is the domain? Young = suspicious |
| `having_IP_Address` | Is there an IP in the URL? |
| `PhishingSignalCount` | Number of phishing indicators found |
| `LegitSignalCount` | Number of legitimate indicators found |
| `NetScore` | LegitSignalCount - PhishingSignalCount |
| `PhishingSignalRatio` | Phishing signals / total signals |
| `NoSSL_HasIP` | Interaction: No HTTPS AND has IP (very suspicious) |
| `BadSFH_BadSSL` | Interaction: Bad form handler AND bad SSL |
| `YoungDomain_NoSSL` | Interaction: New domain AND no SSL |

### Realistic Features (63 total)

The realistic model extracts features by fetching the page content:
- URL structure features (length, special chars, subdomains, etc.)
- Page content features (title, favicon, forms, password fields, iframes)
- Social signals (copyright info, social network links)
- Engineered interactions (ObfuscationIPRisk, InsecurePasswordField, etc.)

---

## SHAP Explainability (Phase 2)

SHAP (SHapley Additive exPlanations) explains why the ML models made their decision. For each URL scan, it returns the top 10 most influential features.

### How it works

1. At Flask startup, `shap.TreeExplainer` is created for each tree model (lgb, xgb, catboost, rf)
2. On each scan, SHAP values are computed for all 16 features
3. Values from all available models are averaged
4. Top 10 features by |SHAP value| are returned

**SHAP value meaning:**
- **Positive value** (red bar in frontend) → this feature pushed the model toward "Phishing"
- **Negative value** (green bar in frontend) → this feature pushed the model toward "Legitimate"
- **Larger absolute value** → more influential

### Response format
```json
{
  "shap_explanation": {
    "top_features": [
      { "feature": "SSLfinal_State", "shap_value": -0.3241, "direction": "legitimate" },
      { "feature": "having_IP_Address", "shap_value": 0.2891, "direction": "phishing" },
      ...
    ],
    "total_features": 16,
    "models_averaged": 4
  }
}
```

### SHAP is best-effort
If SHAP computation fails for any model, that model is silently skipped. If all fail, `shap_explanation` is `null` and the frontend simply hides the SHAP card.

---

## API Response Format

**Full response from `POST /analyze`:**
```json
{
  "success": true,
  "url": "http://example.com/login",
  "prediction": "Phishing",
  "confidence": 87.3,
  "risk_level": "HIGH",
  "detection_source": "ml_ensemble",
  "is_trusted": false,
  "rule_violations": [],
  "model_results": {
    "lgb":      { "prediction": "Phishing", "confidence": 0.89 },
    "xgb":      { "prediction": "Phishing", "confidence": 0.85 },
    "catboost": { "prediction": "Phishing", "confidence": 0.91 },
    "rf":       { "prediction": "Phishing", "confidence": 0.83 }
  },
  "features": {
    "SSLfinal_State": -1,
    "having_IP_Address": 1,
    ...
  },
  "PhishingSignalCount": 5,
  "LegitSignalCount": 1,
  "NetScore": -4,
  "shap_explanation": {
    "top_features": [...],
    "total_features": 16,
    "models_averaged": 4
  }
}
```

---

## Training Notebooks

### `PhishNet_WebsitePhishing_Analysis.ipynb` (UCI)
- Dataset: `WebsitePhishing.csv` (1,353 rows, 9 features)
- Models: LightGBM, XGBoost, CatBoost, RandomForest, StackingClassifier
- Hyperparameter tuning: Optuna
- Target metric: G-Mean = √(Recall_phishing × Recall_legitimate)
- Output: `models/phishing_model_bundle_websitephishing.pkl`

### `Improved_Phishing_Detection.ipynb` (Realistic)
- Dataset: `phishurl.csv` (235,795 rows, 50+ features)
- Feature engineering: 6 interaction features, log transforms for heavy-tailed columns
- Models: LightGBM, XGBoost, CatBoost, RandomForest + soft-voting + stacking ensembles
- Note: Shows 100% accuracy, suspected data leakage in some feature columns

---

## Python Dependencies

```
Flask==3.0.0
Flask-Cors==4.0.0
numpy==2.4.0
pandas==2.3.3
scikit-learn==1.8.0
lightgbm>=4.1.0
xgboost>=1.7.0
catboost==1.2.0
shap>=0.43.0
optuna>=3.4.0
beautifulsoup4==4.12.2
requests==2.31.0
tldextract==5.3.0
whois==1.20240129.2
python-Levenshtein>=0.21.0
```

---

## Key Implementation Notes

- **`n_jobs=1` everywhere** — Python 3.14 + joblib/loky has a RecursionError bug with multiprocessing; `n_jobs=1` fixes it
- **Auto model detection** — `app.py` checks which bundle file exists and sets `MODEL_TYPE = 'uci'` or `'realistic'` at startup
- **Trusted domains** — hardcoded list of ~50 top domains (google.com, github.com, etc.) that always return Legitimate instantly without running ML
- **No scaler for UCI** — UCI features are categorical (-1/0/1), no scaling needed; realistic model uses RobustScaler

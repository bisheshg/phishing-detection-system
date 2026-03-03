# PhishNet — Project Progress Report

**Project:** Advanced Phishing Detection System (Major Project)
**Date:** March 2026
**Repository:** https://github.com/bisheshg/phishing-detection-system

---

## What is PhishNet?

PhishNet is a full-stack phishing detection system that analyses URLs in real time and tells the user whether a website is a phishing site or a legitimate one. It combines three layers of detection:

1. **Blacklist lookup** — instant check against known bad domains stored in MongoDB
2. **Rule engine** — fast heuristic checks (IP in URL, no HTTPS, suspicious words, etc.)
3. **Machine learning ensemble** — four trained tree-based models vote on the URL

Users interact with PhishNet through a **React web app** or a **Chrome Extension**. Both talk to an **Express backend** which proxies ML requests to a **Flask ML service**.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        USER                                  │
│           React App (port 3000)    Chrome Extension          │
└───────────────────┬────────────────────────┬────────────────┘
                    │ HTTP REST              │ HTTP REST
                    ▼                        ▼
         ┌──────────────────────────────────────────┐
         │       Express Backend  (port 8800)        │
         │   JWT auth  •  Rate limiting  •  CORS     │
         │   Blacklist check  •  Security middleware │
         └──────────────────┬───────────────────────┘
                            │ axios POST /analyze
             ┌──────────────┴──────────────────┐
             │                                 │
             ▼                                 ▼
  ┌─────────────────────┐            ┌─────────────────────┐
  │  Flask ML Service   │            │  MongoDB (port 27017)│
  │  (port 5002)        │            │  Users • ScanHistory │
  │  Rule Engine        │            │  Blacklist • Reports │
  │  Feature Extractor  │            └─────────────────────┘
  │  4-Model Ensemble   │
  │  SHAP Explainer     │
  └─────────────────────┘
```

---

## Report Index

| File | What it covers |
|------|---------------|
| [FRONTEND.md](FRONTEND.md) | React web application — pages, components, auth, API calls |
| [BACKEND.md](BACKEND.md) | Express API server — routes, controllers, models, security |
| [FLASKBACK.md](FLASKBACK.md) | Flask ML service — feature extraction, models, rule engine, SHAP |
| [CHROME_EXTENSION.md](CHROME_EXTENSION.md) | Chrome extension — popup, background worker, auth flow |

---

## Technology Stack Summary

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, React Router v6, Axios, recharts, react-chartjs-2 |
| Backend | Node.js 20, Express 4, Mongoose 7, JWT, bcryptjs, Helmet, express-rate-limit |
| Database | MongoDB 7 (local) |
| ML Service | Python 3.x, Flask 3, LightGBM, XGBoost, CatBoost, RandomForest, SHAP |
| Chrome Extension | Manifest V3, chrome.storage, fetch API |

---

## Completed Phases

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Rule engine + ML ensemble (4 models) + security middleware + blacklist | ✅ Complete |
| Phase 2 | SHAP explainability — AI decision explanations shown in results page | ✅ Complete |
| Phase 3 | Scan history, reports, statistics page enhancements | ✅ Complete |
| Phase 4 | Chrome Extension (Manifest V3) with real-time badge and popup | ✅ Complete |

---

## How to Run

```bash
# 1. MongoDB (make sure it's running)
mongod

# 2. Flask ML service
cd PhishNet-main/FlaskBack
source venv/bin/activate
python app.py          # runs on port 5002

# 3. Express backend
cd PhishNet-main/backend
npm start              # runs on port 8800

# 4. React frontend
cd PhishNet-main/frontend
npm start              # runs on port 3000

# 5. Chrome Extension
# Open chrome://extensions → Load unpacked → select PhishNet-main/chrome_extension/
```

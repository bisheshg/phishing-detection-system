# 🛡️ PhishNet - Advanced Phishing Detection System

[![ML Accuracy](https://img.shields.io/badge/ML%20Accuracy-99.97%25-success)](https://github.com/yourusername/PhishNet)
[![Models](https://img.shields.io/badge/Models-LightGBM%20%7C%20RandomForest-blue)](https://github.com/yourusername/PhishNet)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Enterprise-grade phishing URL detection powered by machine learning with transparent, explainable AI.**

---

## 🚀 Features

### 🤖 **Advanced ML Detection**
- **99.97% Balanced Accuracy** (G-Mean metric)
- **2-Model Ensemble**: LightGBM + Random Forest
- **67 Features** extracted from URL structure and page content
- Real-time analysis in <3 seconds

### 🔍 **Comprehensive Analysis**
- **Security Indicators**: HTTPS, IP detection, URL obfuscation
- **Content Quality**: Title, copyright, favicon analysis
- **Risk Assessment**: External forms, popups, financial keywords
- **Transparent Explanations**: Shows WHY a URL is flagged

### 🎨 **Modern Web Interface**
- React.js frontend with real-time results
- User authentication and scan history
- Statistics dashboard with charts
- Mobile-responsive design

### 📊 **User Management**
- Rate limiting: 50 scans/day (free) | 1000 scans/day (premium)
- Scan history with MongoDB storage
- User statistics and analytics
- JWT-based authentication

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    React Frontend                        │
│                 (Port 3000)                              │
└──────────────────┬──────────────────────────────────────┘
                   │ HTTP/REST
┌──────────────────▼──────────────────────────────────────┐
│              Express.js Backend                          │
│         (Port 8800) + MongoDB                            │
│   • Authentication • Rate Limiting • History             │
└──────────────────┬──────────────────────────────────────┘
                   │ HTTP/REST
┌──────────────────▼──────────────────────────────────────┐
│          Flask ML Service (Port 5002)                    │
│   • Feature Extraction • Model Inference                │
│   • LightGBM + Random Forest Ensemble                   │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 Installation

### Prerequisites
- **Node.js** 14+ and npm
- **Python** 3.8+
- **MongoDB** 4.4+

### 1. Clone Repository
```bash
git clone https://github.com/yourusername/PhishNet.git
cd PhishNet
```

### 2. Backend Setup (Express)
```bash
cd PhishNet-main/backend
npm install

# Create .env file
cat > .env << EOF
MONGO_URL=mongodb://localhost:27017/phishnet
JWT_SECRET=your-secret-key-here
PORT=8800
EOF

npm start
```

### 3. ML Service Setup (Flask)
```bash
cd PhishNet-main/FlaskBack
pip install -r requirements.txt

python app.py
```

### 4. Frontend Setup (React)
```bash
cd PhishNet-main/frontend
npm install
npm start
```

### 5. Database Setup (MongoDB)
```bash
# Start MongoDB
mongod

# Database will be created automatically on first run
```

---

## 🧪 Quick Test

```bash
# Terminal 1: MongoDB
mongod

# Terminal 2: Express Backend
cd PhishNet-main/backend && npm start

# Terminal 3: Flask ML Service
cd PhishNet-main/FlaskBack && python app.py

# Terminal 4: React Frontend
cd PhishNet-main/frontend && npm start
```

**Open**: http://localhost:3000

**Test URLs**:
- ✅ Legitimate: `https://google.com`
- ⚠️ Suspicious: `http://192.168.1.1/login`
- 🔴 Phishing: `http://secure-bank-login.tk`

---

## 📊 ML Model Details

### Training Dataset
- **Source**: phishurl.csv (235,795 URLs)
- **Features**: 67 (50 base + 6 interaction + 11 log-transformed)
- **Split**: 80/20 train/test (stratified)
- **Scaler**: RobustScaler (handles outliers)

### Model Performance

| Model | Accuracy | G-Mean | Recall (Phishing) | Recall (Legit) |
|-------|----------|--------|-------------------|----------------|
| **LightGBM** | 99.998% | 99.9975% | 99.995% | 100% |
| **Random Forest** | 99.97% | 99.97% | 99.94% | 100% |
| **Ensemble** | 99.97% | 99.97% | 99.97% | 99.97% |

### Key Features
1. **URL Structure**: Length, domain, TLD, subdomains
2. **Security**: HTTPS, IP address, obfuscation
3. **Page Content**: Title, copyright, favicon, scripts
4. **Risk Indicators**: External forms, popups, financial keywords

### Data Leakage Fix
❌ **Removed**: URLSimilarityIndex (caused 100% fake accuracy)
✅ **Result**: Realistic 99.97% accuracy with proper validation

### CatBoost Removal
❌ **Problem**: CatBoost predicted google.com as phishing (51.68%)
🔍 **Cause**: Training data had 0 google.com-like sites (TLD bias)
✅ **Solution**: Removed CatBoost, kept LightGBM + Random Forest

---

## 🎯 API Endpoints

### Authentication
```http
POST   /api/auth/register       # Register new user
POST   /api/auth/login          # Login user
GET    /api/auth/user           # Get current user
```

### Phishing Detection
```http
POST   /api/phishing/analyze    # Analyze URL
GET    /api/phishing/history    # Get scan history
GET    /api/phishing/statistics # Get user statistics
DELETE /api/phishing/:scanId    # Delete scan
```

### Example Request
```bash
curl -X POST http://localhost:8800/api/phishing/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}' \
  --cookie "jwt=YOUR_JWT_TOKEN"
```

### Example Response
```json
{
  "success": true,
  "data": {
    "prediction": "Legitimate",
    "confidence": 99.8,
    "risk_level": "Safe",
    "ensemble": {
      "agreement": "0/2",
      "individual_probabilities": {
        "gradient_boosting": 0.0002,
        "random_forest": 0.3455
      }
    }
  },
  "userInfo": {
    "remainingScans": 49,
    "totalScans": 1
  }
}
```

---

## 📸 Screenshots

### Home Page
Clean URL scanner interface with real-time validation.

### Analysis Results
Comprehensive breakdown showing:
- ✅ Security indicators (HTTPS, IP, obfuscation)
- 📊 Content quality score (0-5)
- ⚠️ Risk factors detected
- 🤖 Individual model predictions

### Statistics Dashboard
- Total scans, today's scans
- Phishing detection rate
- Risk distribution chart
- Recent detections

### Scan History
Paginated table with all scans, confidence scores, and timestamps.

---

## 🔧 Configuration

### Rate Limits
```javascript
// backend/controllers/phishing.js
FREE_USER_LIMIT = 50    // scans per day
PREMIUM_USER_LIMIT = 1000
```

### Model Threshold
```python
# FlaskBack/app.py
THRESHOLD = 0.5  # Adjust for false positive/negative trade-off
```

### Trusted Domains Whitelist
```python
# FlaskBack/app.py - Line 59
TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', ...
}
```

---

## 📚 Documentation

- **[QUICK_START.md](QUICK_START.md)** - Fast setup guide
- **[IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md)** - Full technical details
- **[MODEL_FIX_SUMMARY.md](MODEL_FIX_SUMMARY.md)** - CatBoost issue resolution
- **[FRONTEND_ENHANCEMENTS.md](FRONTEND_ENHANCEMENTS.md)** - UI improvements

---

## 🐛 Troubleshooting

### "ML_SERVICE_DOWN" Error
```bash
# Check Flask is running
curl http://localhost:5002/

# Restart Flask
cd PhishNet-main/FlaskBack
python app.py
```

### "Please login to scan URLs"
- Ensure JWT cookie is set
- Try logging out and back in
- Clear browser cookies

### MongoDB Connection Error
```bash
# Check MongoDB is running
pgrep mongod

# Start MongoDB
mongod --dbpath /path/to/data
```

---

## 🚀 Future Enhancements

- [ ] Chrome Extension for real-time URL checking
- [ ] Bulk URL scanning (CSV upload)
- [ ] Email alerts for phishing detections
- [ ] API key generation for developers
- [ ] Webhook notifications
- [ ] Multi-language support
- [ ] Mobile app (React Native)

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Bishesh Gautam**

- GitHub: [@yourusername](https://github.com/yourusername)
- Email: your.email@example.com

---

## 🙏 Acknowledgments

- **Dataset**: PhishURL dataset (235K URLs)
- **ML Models**: scikit-learn, LightGBM
- **Backend**: Express.js, MongoDB
- **Frontend**: React.js
- **AI Assistant**: Claude Sonnet 4.5

---

## 📊 Project Stats

- **Languages**: JavaScript, Python, HTML, CSS
- **Files**: 229
- **Lines of Code**: 320,607
- **Models Accuracy**: 99.97%
- **Detection Time**: <3 seconds
- **Features Extracted**: 67

---

## ⭐ Star This Repo!

If this project helped you, please give it a ⭐️ on GitHub!

---

**Built with ❤️ and AI-powered insights**

# 🚀 PhishNet Quick Start Guide

## ⚡ 30-Second Setup

```bash
# Terminal 1 - MongoDB
mongod

# Terminal 2 - Express Backend
cd PhishNet-main/backend && npm start

# Terminal 3 - Flask ML Service
cd PhishNet-main/FlaskBack && python app.py

# Terminal 4 - React Frontend
cd PhishNet-main/frontend && npm start
```

Then open: **http://localhost:3000**

---

## 🎯 New URLs to Test

### Frontend Pages
- **Home**: http://localhost:3000/
- **Login**: http://localhost:3000/login
- **Statistics**: http://localhost:3000/statistics ⭐ **NEW**
- **Scan History**: http://localhost:3000/scan-history ⭐ **NEW**
- **Dashboard**: http://localhost:3000/dashboard
- **Premium**: http://localhost:3000/getpremium

### API Endpoints (Backend)
- **Analyze URL**: `POST http://localhost:8800/api/phishing/analyze`
- **Statistics**: `GET http://localhost:8800/api/phishing/statistics`
- **History**: `GET http://localhost:8800/api/phishing/history`
- **Detections**: `GET http://localhost:8800/api/phishing/detections`

---

## ✅ Verification Checklist

### Backend
- [ ] MongoDB running (default port 27017)
- [ ] Express server running on port 8800
- [ ] Flask ML service running on port 5002
- [ ] Can access: http://localhost:8800/api/auth/user

### Frontend
- [ ] React app running on port 3000
- [ ] Can login successfully
- [ ] Can scan a URL (e.g., https://google.com)
- [ ] Scan result shows remaining scans banner ⭐ **NEW**
- [ ] Can access `/statistics` page ⭐ **NEW**
- [ ] Can access `/scan-history` page ⭐ **NEW**

### Database
- [ ] MongoDB has `phishnet` database
- [ ] `users` collection exists
- [ ] `scanhistories` collection created after first scan ⭐ **NEW**

### ML Service
- [ ] Flask loads `phishing_model_bundle_FIXED.pkl` ⭐ **NEW**
- [ ] Console shows "99.99% accuracy" message
- [ ] No errors about missing model file

---

## 🧪 Quick Test Script

```bash
# 1. Login (save cookies)
curl -X POST http://localhost:8800/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  -c cookies.txt

# 2. Analyze a URL
curl -X POST http://localhost:8800/api/phishing/analyze \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"url":"https://google.com"}'

# 3. Check statistics
curl http://localhost:8800/api/phishing/statistics -b cookies.txt

# 4. View scan history
curl http://localhost:8800/api/phishing/history -b cookies.txt
```

---

## 🎨 UI Tour

### 1. **Home Page**
- Enter URL
- See scan limit banner (if logged in) ⭐ **NEW**
- Click "Scan"

### 2. **Result Page**
- Shows prediction (Phishing/Legitimate)
- Shows confidence percentage
- Shows remaining scans banner ⭐ **NEW**
- Displays risk level

### 3. **Statistics Page** ⭐ **NEW**
- 6 stat cards (total scans, today's scans, etc.)
- Risk distribution chart
- Recent phishing detections
- Premium upgrade banner (free users)

### 4. **Scan History Page** ⭐ **NEW**
- Table of all scans
- Pagination
- Delete individual scans
- Filter by date/risk

---

## 🔑 Test Accounts

Create a test user:
```bash
# Via frontend: /login → "Register"
# Or via curl:
curl -X POST http://localhost:8800/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email":"test@phishnet.com",
    "password":"Test123!",
    "name":"Test User",
    "phone":"1234567890"
  }'
```

Make user premium (in MongoDB):
```javascript
db.users.updateOne(
  { email: "test@phishnet.com" },
  { $set: { isPremium: true } }
)
```

---

## 🎯 Test URLs

### Legitimate (Should Pass)
- `https://google.com`
- `https://github.com`
- `https://stackoverflow.com`
- `https://wikipedia.org`

### Suspicious (Should Detect as Phishing)
- `http://paypal-secure-login.com`
- `http://192.168.1.1/admin`
- `http://secure-bank-verify.com`
- `http://amaz0n-customer-support.com`

---

## 📊 Expected Results

### After First Scan
- ✅ Scan result displayed
- ✅ "Scans remaining: 49 of 50" banner shown
- ✅ Entry in `/scan-history`
- ✅ Statistics updated

### After 50 Scans (Free User)
- ✅ Error: "Daily scan limit reached"
- ✅ Upgrade prompt shown
- ✅ "0 scans remaining"

### Premium User
- ✅ Daily limit: 1000
- ✅ Premium badge shown
- ✅ No upgrade prompts

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
- Check JWT cookie is set
- Try logging out and back in
- Clear browser cookies

### "Daily scan limit reached"
```javascript
// Reset in MongoDB
db.scanhistories.deleteMany({ userId: ObjectId("YOUR_USER_ID") })
```

### CORS Errors
- Ensure frontend is on `localhost:3000`
- Ensure backend allows `localhost:3000` in CORS

---

## 📈 Success Indicators

✅ Flask console shows: "🚀 PHISHING DETECTION API v5.0"
✅ Flask console shows: "✅ Loaded 3 models"
✅ Express console shows: "Server running on port 8800"
✅ MongoDB console shows: "MongoDB connected"
✅ React shows no console errors
✅ First scan returns result in < 5 seconds
✅ Statistics page loads without errors
✅ Scan history shows all scans

---

## 🎉 You're Ready!

Your PhishNet application is fully integrated with:
- ✅ 99.99% accurate ML model
- ✅ Complete user tracking
- ✅ Scan history & statistics
- ✅ Rate limiting (50/1000 per day)
- ✅ Premium tier support

**Start scanning and protecting users from phishing! 🛡️**

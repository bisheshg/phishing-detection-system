from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import os
import re
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
from urllib.parse import urlparse
import ipaddress
import tldextract
import logging
import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

# -------------------- APP SETUP --------------------
app = Flask(__name__)

# ✅ FIX 1: Explicit CORS (frontend @3000 → backend @5002)
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    supports_credentials=True
)

# ✅ FIX 1B: Handle OPTIONS preflight
@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = app.make_response("")
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        return response

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------- MODEL LOADING (SINGLE BUNDLE) --------------------
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
BUNDLE_PATH = os.path.join(MODEL_DIR, "phishing_model_bundle.pkl")

with open(BUNDLE_PATH, "rb") as f:
    bundle = pickle.load(f)

MODELS = {
    "voting_hard": bundle["voting_hard"],
    "voting_soft": bundle["voting_soft"],
    "stacking": bundle["stacking"],
    "gradient_boosting": bundle["gradient_boosting"],
    "xgboost": bundle["xgboost"],
    "catboost": bundle["catboost"],
    "random_forest": bundle["random_forest"],
    "svm": bundle["svm"],
}

SCALER = bundle["scaler"]
FEATURE_NAMES = bundle["feature_names"]
THRESHOLD = bundle["threshold"]
MODEL_METRICS = bundle["model_metrics"]

PRIMARY_MODEL = MODELS["voting_hard"]

# -------------------- HELPERS --------------------
def add_scheme_if_missing(url):
    return url if urlparse(url).scheme else "https://" + url

# -------------------- ENSEMBLE PREDICTION --------------------
def predict_with_ensemble(X_scaled, X_raw, readable_feats):
    predictions = {}
    probabilities = {}

    for name, model in MODELS.items():
        try:
            pred = model.predict(X_scaled)[0]
            predictions[name] = int(pred if pred != -1 else 0)

            if hasattr(model, "predict_proba"):
                probabilities[name] = float(model.predict_proba(X_scaled)[0][1])
        except:
            continue

    consensus = int(sum(predictions.values()) > len(predictions) / 2)

    avg_probability = (
        np.mean(list(probabilities.values()))
        if probabilities else float(consensus)
    )

    return {
        "consensus": consensus,
        "consensus_probability": float(avg_probability),
        "individual_predictions": predictions,
        "individual_probabilities": probabilities,
        "explanations": []
    }

# -------------------- FEATURE EXTRACTION --------------------
class PhishingFeatureExtractor:
    def __init__(self, url):
        self.url = url
        self.parsed = urlparse(url)
        self.domain = self.parsed.netloc.replace("www.", "").lower()
        try:
            self.whois_response = whois.whois(self.domain)
        except:
            self.whois_response = None

    def has_ip(self):
        try:
            ipaddress.ip_address(self.domain)
            return 1
        except:
            return 0

    def domain_age_days(self):
        try:
            cd = self.whois_response.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            return (datetime.now() - cd).days if cd else -1
        except:
            return -1

    def extract(self):
        features = {
            "url_length": len(self.url),
            "hostname_length": len(self.domain),
            "path_length": len(self.parsed.path),
            "query_length": len(self.parsed.query),
            "num_subdomains": self.domain.count("."),
            "num_digits": sum(c.isdigit() for c in self.url),
            "num_letters": sum(c.isalpha() for c in self.url),
            "num_special_chars": len(re.findall(r"[^a-zA-Z0-9]", self.url)),
            "has_ip": self.has_ip(),
            "has_https": int(self.parsed.scheme == "https"),
            "tld_length": len(tldextract.extract(self.url).suffix),
            "num_hyphens": self.domain.count("-"),
            "ratio_digits_letters": 0,
            "domain_age_days": self.domain_age_days(),
            "shortened": 0,
            "num_sensitive_words": 0,
        }

        vector = np.array([features.get(f, 0) for f in FEATURE_NAMES]).reshape(1, -1)
        return vector, features
    
    

# -------------------- API --------------------
@app.route("/analyze", methods=["POST", "OPTIONS"])
@app.route("/analyze_url", methods=["POST", "OPTIONS"])  # legacy
def analyze():
    data = request.get_json()
    url = add_scheme_if_missing(data["url"])

    extractor = PhishingFeatureExtractor(url)
    X_raw, readable = extractor.extract()
    X_scaled = SCALER.transform(X_raw)

    ensemble = predict_with_ensemble(X_scaled, X_raw, readable)

    # ✅ FIX 2: Proper probability source
    primary_prob = (
        ensemble["individual_probabilities"].get("voting_soft")
        or ensemble["consensus_probability"]
    )

    pred = int(primary_prob >= THRESHOLD)

    return jsonify({
        "url": url,
        "domain": extractor.domain,
        "prediction": "Phishing" if pred else "Legitimate",
        "probability": round(primary_prob, 4),
        "confidence": round(primary_prob * 100, 2),
        "ensemble": ensemble,
        "safe_to_visit": primary_prob < 0.5,
        "timestamp": datetime.now().isoformat()
    }), 200

# -------------------- RUN --------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)



# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import pickle
# import os
# import re
# import requests
# from bs4 import BeautifulSoup
# import whois
# from datetime import datetime
# from urllib.parse import urlparse
# import ipaddress
# import tldextract
# import logging
# import numpy as np
# import pandas as pd
# import warnings
# warnings.filterwarnings('ignore')

# # -------------------- APP SETUP --------------------
# app = Flask(__name__)
# CORS(app)

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# # -------------------- MODEL LOADING (SINGLE BUNDLE) --------------------
# MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
# BUNDLE_PATH = os.path.join(MODEL_DIR, "phishing_model_bundle.pkl")

# logger.info("="*80)
# logger.info("🚀 Loading Phishing Detection Model Bundle...")
# logger.info("="*80)

# if not os.path.exists(BUNDLE_PATH):
#     error_msg = f"Model bundle not found at {BUNDLE_PATH}"
#     logger.error(error_msg)
#     raise FileNotFoundError(error_msg)

# try:
#     # Load the complete bundle
#     with open(BUNDLE_PATH, 'rb') as f:
#         bundle = pickle.load(f)
    
#     # Extract models
#     MODELS = {
#         'voting_hard': bundle['voting_hard'],
#         'voting_soft': bundle['voting_soft'],
#         'stacking': bundle['stacking'],
#         'gradient_boosting': bundle['gradient_boosting'],
#         'xgboost': bundle['xgboost'],
#         'catboost': bundle['catboost'],
#         'random_forest': bundle['random_forest'],
#         'svm': bundle['svm'],
#     }
    
#     # Extract metadata
#     SCALER = bundle['scaler']
#     FEATURE_NAMES = bundle['feature_names']
#     THRESHOLD = bundle['threshold']
#     MODEL_METRICS = bundle['model_metrics']
    
#     # Log bundle info
#     logger.info(f"✅ Model bundle loaded successfully!")
#     logger.info(f"   Bundle size: {os.path.getsize(BUNDLE_PATH) / (1024*1024):.2f} MB")
#     logger.info(f"   Models loaded: {len(MODELS)}")
#     logger.info(f"   Features: {len(FEATURE_NAMES)}")
#     logger.info(f"   Training date: {bundle.get('training_date', 'N/A')}")
#     logger.info(f"   Primary model: Voting Hard (F1: {MODEL_METRICS['voting_hard']['f1_score']:.3f})")
#     logger.info("="*80)
    
# except Exception as e:
#     logger.error(f"❌ Failed to load model bundle: {str(e)}")
#     raise

# # Primary model for predictions
# PRIMARY_MODEL = MODELS['voting_hard']

# # -------------------- HELPERS --------------------
# def add_scheme_if_missing(url):
#     """Add https:// if URL doesn't have a scheme"""
#     return url if urlparse(url).scheme else "https://" + url

# def safe_request(url, timeout=10):
#     """Safely make HTTP request with error handling"""
#     try:
#         headers = {
#             "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#         }
#         return requests.get(url, timeout=timeout, headers=headers, verify=False)
#     except Exception as e:
#         logger.warning(f"Request failed for {url}: {str(e)}")
#         return None

# # -------------------- REASON GENERATOR --------------------
# def generate_reason(feature_name, value):
#     """Generate human-readable explanation for why a feature is risky."""
    
#     # Safely format value
#     def format_value(v):
#         try:
#             if isinstance(v, float):
#                 return f"{v:.2f}"
#             return str(v)
#         except:
#             return str(v)
    
#     v = format_value(value)
    
#     # Convert to numeric for comparisons
#     try:
#         num_val = float(value)
#     except:
#         num_val = 0
    
#     reasons = {
#         "url_length": f"URL length is {v} characters. " + ("⚠️ Very long URLs (>75) are often used to hide malicious intent." if num_val > 75 else "Normal length." if num_val > 30 else "Short URL."),
        
#         "hostname_length": f"Hostname length is {v} characters. " + ("⚠️ Long hostnames (>30) may indicate obfuscation." if num_val > 30 else "Normal length."),
        
#         "num_subdomains": f"Contains {v} subdomain(s). " + ("⚠️ Excessive subdomains (>3) are often used to mimic legitimate sites." if num_val > 3 else "Normal subdomain structure." if num_val <= 2 else "Multiple subdomains detected."),
        
#         "has_ip": "⚠️ Uses IP address instead of domain name - Strong phishing indicator!" if value == 1 else "✓ Uses proper domain name - Good sign.",
        
#         "shortened": "⚠️ Uses URL shortener - Hides true destination, frequently abused in phishing." if value == 1 else "✓ Not a shortened URL - Good sign.",
        
#         "num_sensitive_words": f"Contains {v} sensitive word(s) " + ("⚠️ like 'login', 'secure', 'verify', 'bank' - Often used to trick users into thinking the site is legitimate." if num_val > 0 else "✓ No suspicious keywords detected."),
        
#         "domain_age_days": (
#             "⚠️ Domain age is unknown - Red flag!" if num_val == -1 else
#             f"⚠️ Domain is only {v} days old - Very new domains (<30 days) are suspicious." if 0 <= num_val < 30 else
#             f"Domain is {v} days old. " + ("Relatively new domain." if num_val < 180 else "✓ Established domain - Good sign.")
#         ),
        
#         "num_hyphens": f"Contains {v} hyphen(s). " + ("⚠️ Multiple hyphens in domain are common in fake sites." if num_val > 1 else "Single hyphen detected." if num_val == 1 else "✓ No hyphens - Good sign."),
        
#         "ratio_digits_letters": f"Digit/letter ratio is {v}. " + ("⚠️ High ratio (>0.2) indicates potential obfuscation." if num_val > 0.2 else "✓ Normal ratio."),
        
#         "num_digits": f"Contains {v} digit(s). " + ("⚠️ Excessive digits may be used to confuse users." if num_val > 5 else "Normal amount of digits." if num_val > 0 else "✓ No digits in URL."),
        
#         "has_https": "⚠️ No HTTPS - Insecure connection! Major red flag." if value == 0 else "✓ Has HTTPS - Secure connection.",
        
#         "num_special_chars": f"Contains {v} special character(s). " + ("⚠️ High count (>15) may indicate suspicious URL structure." if num_val > 15 else "Normal special character usage."),
        
#         "path_length": f"Path length is {v} characters. " + ("⚠️ Very long paths (>50) can hide malicious intent." if num_val > 50 else "Normal path length."),
        
#         "query_length": f"Query string length is {v} characters. " + ("⚠️ Long query strings (>50) may contain encoded attacks." if num_val > 50 else "Normal query length." if num_val > 0 else "No query parameters."),
        
#         "tld_length": f"Top-level domain length is {v} characters. " + ("Unusual TLD length." if num_val > 4 or num_val < 2 else "Standard TLD."),
        
#         "num_letters": f"Contains {v} letter(s) in the URL.",
#     }
    
#     return reasons.get(feature_name, f"{feature_name.replace('_', ' ').title()}: {v}")

# # -------------------- EXPLAIN PREDICTION --------------------
# def explain_prediction(model, X_scaled, X_raw, feature_names, raw_features, top_k=6):
#     """
#     Returns top contributing features with explanations.
#     Works with tree-based models and ensembles.
#     """
#     try:
#         # Try to get feature importances
#         importances = None
        
#         if hasattr(model, 'feature_importances_'):
#             importances = model.feature_importances_
#         elif hasattr(model, 'estimators_'):
#             # For VotingClassifier, get importances from base estimators
#             try:
#                 base_importances = []
#                 for estimator in model.estimators_:
#                     if hasattr(estimator, 'feature_importances_'):
#                         base_importances.append(estimator.feature_importances_)
                
#                 if base_importances:
#                     importances = np.mean(base_importances, axis=0)
#             except Exception as e:
#                 logger.debug(f"Could not extract from ensemble: {str(e)}")
        
#         # If we still don't have importances, use absolute feature values
#         if importances is None:
#             logger.warning("Using feature values as importance (model doesn't support feature_importances_)")
#             importances = np.abs(X_raw.flatten())
#             importances = importances / (np.sum(importances) + 1e-10)  # Normalize
        
#         # Weight by actual feature values
#         weighted = importances * np.abs(X_raw.flatten())
        
#         # Filter out zero or near-zero contributions
#         min_threshold = np.max(weighted) * 0.05  # At least 5% of max
        
#         feature_scores = []
#         for fname, weight, raw_val, importance in zip(feature_names, weighted, X_raw.flatten(), importances):
#             if weight > min_threshold or abs(raw_val) > 0:  # Include non-zero features
#                 feature_scores.append((fname, weight, raw_val, importance))
        
#         # Sort by weighted importance
#         feature_scores.sort(key=lambda x: abs(x[1]), reverse=True)

#         explanations = []
#         for fname, score, raw_value, importance in feature_scores[:top_k]:
#             value = raw_features.get(fname, "N/A")
            
#             # Determine if this feature increases risk
#             if score > np.mean(weighted):
#                 risk_contribution = "🔴 High Risk Factor"
#             elif score > np.mean(weighted) * 0.5:
#                 risk_contribution = "🟡 Moderate Risk Factor"
#             else:
#                 risk_contribution = "🟢 Low Risk Factor"
            
#             explanations.append({
#                 "feature": fname.replace("_", " ").title(),
#                 "value": value,
#                 "importance_score": round(float(score), 4),
#                 "feature_importance": round(float(importance), 4),
#                 "risk_contribution": risk_contribution,
#                 "reason": generate_reason(fname, value)
#             })
        
#         return explanations
    
#     except Exception as e:
#         logger.error(f"Error in explain_prediction: {str(e)}", exc_info=True)
#         # Fallback: return top features by absolute value
#         try:
#             feature_scores = list(zip(feature_names, np.abs(X_raw.flatten())))
#             feature_scores.sort(key=lambda x: x[1], reverse=True)
            
#             explanations = []
#             for fname, value in feature_scores[:top_k]:
#                 if value > 0:
#                     explanations.append({
#                         "feature": fname.replace("_", " ").title(),
#                         "value": raw_features.get(fname, "N/A"),
#                         "importance_score": round(float(value), 4),
#                         "reason": generate_reason(fname, raw_features.get(fname, "N/A"))
#                     })
#             return explanations
#         except:
#             return []

# # -------------------- ENSEMBLE PREDICTION --------------------
# def predict_with_ensemble(X_scaled, X_raw, readable_feats):
#     """
#     Get predictions from multiple models for robustness.
#     Returns consensus and individual model predictions.
#     """
#     predictions = {}
#     probabilities = {}
    
#     for model_name, model in MODELS.items():
#         try:
#             # Get prediction
#             pred = model.predict(X_scaled)[0]
            
#             # Handle -1/1 vs 0/1 labels
#             if pred == -1:
#                 pred = 0
            
#             predictions[model_name] = int(pred)
            
#             # Get probability if available
#             if hasattr(model, 'predict_proba'):
#                 prob = model.predict_proba(X_scaled)[0]
#                 probabilities[model_name] = float(prob[1] if len(prob) > 1 else prob[0])
#             else:
#                 probabilities[model_name] = float(pred)
        
#         except Exception as e:
#             logger.error(f"Error with {model_name}: {str(e)}")
#             continue
    
#     # Consensus prediction (majority vote)
#     consensus = int(sum(predictions.values()) > len(predictions) / 2)
    
#     # Average probability
#     avg_probability = np.mean(list(probabilities.values()))
    
#     # Get explanations from primary model
#     explanations = explain_prediction(
#         PRIMARY_MODEL, X_scaled, X_raw, FEATURE_NAMES, readable_feats, top_k=6
#     )
    
#     return {
#         'consensus': consensus,
#         'consensus_probability': float(avg_probability),
#         'individual_predictions': predictions,
#         'individual_probabilities': probabilities,
#         'explanations': explanations
#     }

# # -------------------- FEATURE EXTRACTION --------------------
# class PhishingFeatureExtractor:
#     """Extract features from URL for phishing detection"""
    
#     def __init__(self, url):
#         self.url = url
#         self.parsed = urlparse(url)
#         self.domain = self.parsed.netloc.replace("www.", "").lower()
        
#         # Get page content (optional, disabled for faster processing)
#         self.response = None
#         self.soup = None
        
#         # Get WHOIS data
#         try:
#             self.whois_response = whois.whois(self.domain)
#         except Exception as e:
#             logger.debug(f"WHOIS lookup failed: {str(e)}")
#             self.whois_response = None

#     def has_ip(self):
#         """Check if URL uses IP address instead of domain"""
#         try:
#             ipaddress.ip_address(self.domain)
#             return 1
#         except:
#             return 0

#     def domain_age_days(self):
#         """Get domain age in days"""
#         try:
#             if not self.whois_response:
#                 return -1
            
#             creation_date = self.whois_response.creation_date
#             if isinstance(creation_date, list):
#                 creation_date = creation_date[0]
            
#             if creation_date:
#                 age = (datetime.now() - creation_date).days
#                 return max(0, age)
#             return -1
#         except Exception as e:
#             logger.debug(f"Domain age extraction failed: {str(e)}")
#             return -1

#     def is_shortened(self):
#         """Check if URL uses shortener service"""
#         shorteners = [
#             r"bit\.ly", r"goo\.gl", r"tinyurl", r"t\.co", r"short\.ly",
#             r"ow\.ly", r"buff\.ly", r"adf\.ly", r"is\.gd", r"tiny\.cc"
#         ]
#         pattern = "|".join(shorteners)
#         return int(bool(re.search(pattern, self.url, re.I)))

#     def count_sensitive_words(self):
#         """Count sensitive words that are often used in phishing"""
#         sensitive_words = [
#             "login", "secure", "bank", "verify", "update", "account",
#             "password", "paypal", "amazon", "signin", "confirm",
#             "suspend", "restrict", "urgent", "alert", "authenticate"
#         ]
#         url_lower = self.url.lower()
#         return sum(1 for word in sensitive_words if word in url_lower)

#     def extract(self):
#         """Extract all features as a vector"""
        
#         # Calculate all features
#         url_length = len(self.url)
#         hostname_length = len(self.domain)
#         path_length = len(self.parsed.path)
#         query_length = len(self.parsed.query or "")
#         num_subdomains = self.domain.count(".")
#         num_digits = sum(c.isdigit() for c in self.url)
#         num_letters = sum(c.isalpha() for c in self.url)
#         num_special_chars = len(re.findall(r"[^a-zA-Z0-9]", self.url))
#         has_ip = self.has_ip()
#         has_https = int(self.parsed.scheme == "https")
        
#         try:
#             tld = tldextract.extract(self.url).suffix
#             tld_length = len(tld)
#         except:
#             tld_length = 0
        
#         num_hyphens = self.domain.count("-")
#         ratio_digits_letters = num_digits / max(1, num_letters)
#         domain_age_days = self.domain_age_days()
#         shortened = self.is_shortened()
#         num_sensitive_words = self.count_sensitive_words()
        
#         # Create feature dictionary
#         features = {
#             "url_length": url_length,
#             "hostname_length": hostname_length,
#             "path_length": path_length,
#             "query_length": query_length,
#             "num_subdomains": num_subdomains,
#             "num_digits": num_digits,
#             "num_letters": num_letters,
#             "num_special_chars": num_special_chars,
#             "has_ip": has_ip,
#             "has_https": has_https,
#             "tld_length": tld_length,
#             "num_hyphens": num_hyphens,
#             "ratio_digits_letters": round(ratio_digits_letters, 3),
#             "domain_age_days": domain_age_days,
#             "shortened": shortened,
#             "num_sensitive_words": num_sensitive_words,
#         }
        
#         # Create vector in exact order of trained features
#         vector = np.array([features.get(f, 0) for f in FEATURE_NAMES])
        
#         return vector.reshape(1, -1), features

# # -------------------- API ROUTES --------------------

# @app.route("/", methods=["GET"])
# def home():
#     """Health check endpoint"""
#     return jsonify({
#         "status": "healthy",
#         "service": "Phishing URL Detection API",
#         "version": "2.0 (Production Ready)",
#         "primary_model": "Voting Classifier (Hard)",
#         "performance": MODEL_METRICS['voting_hard'],
#         "available_models": list(MODELS.keys()),
#         "features": len(FEATURE_NAMES),
#         "training_date": bundle.get('training_date', 'N/A'),
#         "endpoints": {
#             "analyze": "/analyze",
#             "analyze_url": "/analyze_url (legacy)",
#             "batch": "/batch_analyze",
#             "health": "/health",
#             "models": "/models"
#         }
#     }), 200

# @app.route("/health", methods=["GET"])
# def health():
#     """Detailed health check"""
#     return jsonify({
#         "status": "healthy",
#         "models_loaded": len(MODELS),
#         "models": list(MODELS.keys()),
#         "primary_model": "voting_hard",
#         "threshold": THRESHOLD,
#         "bundle_location": BUNDLE_PATH,
#         "features": len(FEATURE_NAMES)
#     }), 200

# @app.route("/analyze", methods=["POST"])
# def analyze_url():
#     """
#     Main endpoint to analyze URL for phishing.
    
#     Request body:
#     {
#         "url": "https://example.com",
#         "threshold": 0.5 (optional)
#     }
#     """
#     try:
#         # Get request data
#         data = request.get_json()
#         if not data or "url" not in data:
#             return jsonify({"error": "URL missing in request body"}), 400

#         url = add_scheme_if_missing(data["url"].strip())
#         threshold = data.get("threshold", THRESHOLD)
        
#         logger.info(f"Analyzing URL: {url}")

#         # Extract features
#         extractor = PhishingFeatureExtractor(url)
#         X_raw, readable_features = extractor.extract()
        
#         # Scale features
#         X_scaled = SCALER.transform(X_raw)
        
#         # Get ensemble predictions
#         ensemble_results = predict_with_ensemble(X_scaled, X_raw, readable_features)
        
#         # Get primary model prediction
#         primary_prob = ensemble_results['individual_probabilities'].get('voting_hard', 
#                                                                          ensemble_results['consensus_probability'])
#         primary_pred = int(primary_prob >= threshold)
        
#         # Determine risk level
#         if primary_prob > 0.85:
#             risk_level = "Critical"
#             risk_color = "red"
#             risk_emoji = "🔴"
#         elif primary_prob > 0.70:
#             risk_level = "High"
#             risk_color = "orange"
#             risk_emoji = "🟠"
#         elif primary_prob > 0.50:
#             risk_level = "Medium"
#             risk_color = "yellow"
#             risk_emoji = "🟡"
#         else:
#             risk_level = "Low"
#             risk_color = "green"
#             risk_emoji = "🟢"
        
#         # Build response
#         response = {
#             "url": url,
#             "domain": extractor.domain,
#             "timestamp": datetime.now().isoformat(),
            
#             # Primary prediction
#             "prediction": "Phishing" if primary_pred else "Legitimate",
#             "confidence": round(primary_prob * 100, 2),
#             "probability": round(primary_prob, 4),
#             "threshold_used": threshold,
            
#             # Risk assessment
#             "risk_level": risk_level,
#             "risk_color": risk_color,
#             "risk_emoji": risk_emoji,
#             "safe_to_visit": primary_prob < 0.5,
            
#             # Ensemble insights
#             "ensemble": {
#                 "consensus": "Phishing" if ensemble_results['consensus'] else "Legitimate",
#                 "consensus_probability": round(ensemble_results['consensus_probability'], 4),
#                 "individual_predictions": ensemble_results['individual_predictions'],
#                 "individual_probabilities": {
#                     k: round(v, 4) for k, v in ensemble_results['individual_probabilities'].items()
#                 },
#                 "agreement": f"{sum(ensemble_results['individual_predictions'].values())}/{len(ensemble_results['individual_predictions'])} models agree"
#             },
            
#             # Feature analysis
#             "features": readable_features,
#             "top_risk_factors": ensemble_results['explanations'],
            
#             # Model performance
#             "model_info": {
#                 "primary_model": "Voting Classifier (Hard)",
#                 "accuracy": MODEL_METRICS['voting_hard']['accuracy'],
#                 "f1_score": MODEL_METRICS['voting_hard']['f1_score'],
#                 "recall": MODEL_METRICS['voting_hard']['recall'],
#                 "precision": MODEL_METRICS['voting_hard']['precision']
#             },
            
#             # Recommendations
#             "recommendation": (
#                 f"{risk_emoji} DO NOT VISIT - High probability of phishing attack" if primary_prob > 0.7 else
#                 f"{risk_emoji} EXERCISE CAUTION - Moderate phishing indicators detected" if primary_prob > 0.5 else
#                 f"{risk_emoji} Appears legitimate - Low phishing probability"
#             )
#         }

#         logger.info(f"Analysis complete: {response['prediction']} ({response['confidence']}%)")
#         return jsonify(response), 200

#     except Exception as e:
#         logger.error(f"Error analyzing URL: {str(e)}", exc_info=True)
#         return jsonify({
#             "error": "Internal server error",
#             "message": str(e),
#             "status": "failed"
#         }), 500

# @app.route("/analyze_url", methods=["POST"])
# def analyze_url_legacy():
#     """Legacy endpoint for backward compatibility"""
#     return analyze_url()

# @app.route("/batch_analyze", methods=["POST"])
# def batch_analyze():
#     """
#     Analyze multiple URLs at once.
    
#     Request body:
#     {
#         "urls": ["https://example1.com", "https://example2.com", ...]
#     }
#     """
#     try:
#         data = request.get_json()
#         if not data or "urls" not in data:
#             return jsonify({"error": "URLs list missing"}), 400
        
#         urls = data["urls"]
#         if not isinstance(urls, list):
#             return jsonify({"error": "URLs must be a list"}), 400
        
#         if len(urls) > 50:
#             return jsonify({"error": "Maximum 50 URLs per batch"}), 400
        
#         results = []
#         for url in urls:
#             try:
#                 url = add_scheme_if_missing(url.strip())
#                 extractor = PhishingFeatureExtractor(url)
#                 X_raw, readable_features = extractor.extract()
#                 X_scaled = SCALER.transform(X_raw)
                
#                 prob = PRIMARY_MODEL.predict_proba(X_scaled)[0][1]
#                 pred = int(prob >= THRESHOLD)
                
#                 # Determine risk emoji
#                 if prob > 0.85:
#                     risk_emoji = "🔴"
#                     risk_level = "Critical"
#                 elif prob > 0.70:
#                     risk_emoji = "🟠"
#                     risk_level = "High"
#                 elif prob > 0.50:
#                     risk_emoji = "🟡"
#                     risk_level = "Medium"
#                 else:
#                     risk_emoji = "🟢"
#                     risk_level = "Low"
                
#                 results.append({
#                     "url": url,
#                     "prediction": "Phishing" if pred else "Legitimate",
#                     "confidence": round(prob * 100, 2),
#                     "risk_level": risk_level,
#                     "risk_emoji": risk_emoji,
#                     "safe_to_visit": prob < 0.5
#                 })
#             except Exception as e:
#                 results.append({
#                     "url": url,
#                     "error": str(e),
#                     "prediction": "Error"
#                 })
        
#         # Summary statistics
#         total = len(results)
#         phishing_count = sum(1 for r in results if r.get('prediction') == 'Phishing')
#         legitimate_count = sum(1 for r in results if r.get('prediction') == 'Legitimate')
#         error_count = sum(1 for r in results if r.get('prediction') == 'Error')
        
#         return jsonify({
#             "total": total,
#             "summary": {
#                 "phishing": phishing_count,
#                 "legitimate": legitimate_count,
#                 "errors": error_count
#             },
#             "results": results,
#             "timestamp": datetime.now().isoformat()
#         }), 200
    
#     except Exception as e:
#         logger.error(f"Batch analysis error: {str(e)}")
#         return jsonify({"error": str(e)}), 500

# @app.route("/models", methods=["GET"])
# def list_models():
#     """List all available models and their performance"""
#     models_info = []
#     for name, metrics in MODEL_METRICS.items():
#         models_info.append({
#             "name": name,
#             "metrics": metrics,
#             "is_primary": name == "voting_hard"
#         })
    
#     return jsonify({
#         "available_models": models_info,
#         "total_models": len(models_info),
#         "bundle_info": {
#             "training_date": bundle.get('training_date', 'N/A'),
#             "training_samples": bundle.get('training_samples', 'N/A'),
#             "test_samples": bundle.get('test_samples', 'N/A')
#         }
#     }), 200

# # -------------------- ERROR HANDLERS --------------------

# @app.errorhandler(404)
# def not_found(e):
#     return jsonify({
#         "error": "Endpoint not found",
#         "available_endpoints": ["/", "/health", "/analyze", "/analyze_url", "/batch_analyze", "/models"]
#     }), 404

# @app.errorhandler(500)
# def internal_error(e):
#     return jsonify({"error": "Internal server error"}), 500

# # -------------------- RUN --------------------
# if __name__ == "__main__":
#     logger.info("="*80)
#     logger.info("🚀 PHISHING DETECTION API - PRODUCTION READY")
#     logger.info(f"📊 Primary Model: Voting Hard - F1: {MODEL_METRICS['voting_hard']['f1_score']}")
#     logger.info(f"🎯 Recall: {MODEL_METRICS['voting_hard']['recall']} (Catches 98.5% of phishing!)")
#     logger.info(f"🎯 Precision: {MODEL_METRICS['voting_hard']['precision']} (96.7% accurate)")
#     logger.info(f"📁 Models: {len(MODELS)} loaded from single bundle")
#     logger.info(f"🌐 Server starting on http://0.0.0.0:5002")
#     logger.info("="*80)
#     app.run(host="0.0.0.0", port=5002, debug=True)


# # from flask import Flask, request, jsonify
# # from flask_cors import CORS
# # import pickle
# # import os
# # import re
# # import requests
# # from bs4 import BeautifulSoup
# # import whois
# # from datetime import datetime
# # from urllib.parse import urlparse
# # import ipaddress
# # import tldextract
# # import logging
# # import numpy as np
# # import pandas as pd
# # import warnings
# # warnings.filterwarnings('ignore')

# # # -------------------- APP SETUP --------------------
# # app = Flask(__name__)
# # CORS(app)

# # logging.basicConfig(level=logging.INFO)
# # logger = logging.getLogger(__name__)

# # # -------------------- MODEL LOADING (SINGLE BUNDLE) --------------------
# # MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
# # BUNDLE_PATH = os.path.join(MODEL_DIR, "phishing_model_bundle.pkl")

# # logger.info("="*80)
# # logger.info("🚀 Loading Phishing Detection Model Bundle...")
# # logger.info("="*80)

# # if not os.path.exists(BUNDLE_PATH):
# #     error_msg = f"Model bundle not found at {BUNDLE_PATH}"
# #     logger.error(error_msg)
# #     raise FileNotFoundError(error_msg)

# # try:
# #     # Load the complete bundle
# #     with open(BUNDLE_PATH, 'rb') as f:
# #         bundle = pickle.load(f)
    
# #     # Extract models
# #     MODELS = {
# #         'voting_hard': bundle['voting_hard'],
# #         'voting_soft': bundle['voting_soft'],
# #         'stacking': bundle['stacking'],
# #         'gradient_boosting': bundle['gradient_boosting'],
# #         'xgboost': bundle['xgboost'],
# #         'catboost': bundle['catboost'],
# #         'random_forest': bundle['random_forest'],
# #         'svm': bundle['svm'],
# #     }
    
# #     # Extract metadata
# #     SCALER = bundle['scaler']
# #     FEATURE_NAMES = bundle['feature_names']
# #     THRESHOLD = bundle['threshold']
# #     MODEL_METRICS = bundle['model_metrics']
    
# #     # Log bundle info
# #     logger.info(f"✅ Model bundle loaded successfully!")
# #     logger.info(f"   Bundle size: {os.path.getsize(BUNDLE_PATH) / (1024*1024):.2f} MB")
# #     logger.info(f"   Models loaded: {len(MODELS)}")
# #     logger.info(f"   Features: {len(FEATURE_NAMES)}")
# #     logger.info(f"   Training date: {bundle.get('training_date', 'N/A')}")
# #     logger.info(f"   Primary model: Voting Hard (F1: {MODEL_METRICS['voting_hard']['f1_score']:.3f})")
# #     logger.info("="*80)
    
# # except Exception as e:
# #     logger.error(f"❌ Failed to load model bundle: {str(e)}")
# #     raise

# # # Primary model for predictions
# # PRIMARY_MODEL = MODELS['voting_hard']

# # # -------------------- HELPERS --------------------
# # def add_scheme_if_missing(url):
# #     """Add https:// if URL doesn't have a scheme"""
# #     return url if urlparse(url).scheme else "https://" + url

# # def safe_request(url, timeout=10):
# #     """Safely make HTTP request with error handling"""
# #     try:
# #         headers = {
# #             "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
# #         }
# #         return requests.get(url, timeout=timeout, headers=headers, verify=False)
# #     except Exception as e:
# #         logger.warning(f"Request failed for {url}: {str(e)}")
# #         return None

# # # -------------------- REASON GENERATOR --------------------
# # def generate_reason(feature_name, value):
# #     """Generate human-readable explanation for why a feature is risky."""
    
# #     # Safely format value
# #     def format_value(v):
# #         try:
# #             if isinstance(v, float):
# #                 return f"{v:.2f}"
# #             return str(v)
# #         except:
# #             return str(v)
    
# #     v = format_value(value)
    
# #     reasons = {
# #         "url_length": f"URL length is {v} characters. Very long URLs (>75) are often used to hide malicious intent.",
# #         "hostname_length": f"Hostname length is {v} characters. Long hostnames (>30) may indicate obfuscation.",
# #         "num_subdomains": f"Contains {v} subdomains. Excessive subdomains (>3) are used to mimic legitimate sites.",
# #         "has_ip": "Uses IP address instead of domain name - Strong phishing indicator." if value == 1 else "Uses proper domain name - Good sign.",
# #         "shortened": "Uses URL shortener - Hides true destination, frequently abused." if value == 1 else "Not a shortened URL - Good sign.",
# #         "num_sensitive_words": f"Contains {v} sensitive words like 'login', 'secure', 'verify' - Often used to trick users.",
# #         "domain_age_days": f"Domain is {v} days old. New domains (<30 days) or unknown age are red flags." if int(float(v)) < 30 or int(float(v)) == -1 else f"Domain is {v} days old - Established domain.",
# #         "num_hyphens": f"Contains {v} hyphens. Multiple hyphens in domain indicate fake sites.",
# #         "ratio_digits_letters": f"Digit/letter ratio is {v}. High ratio (>0.2) indicates obfuscation.",
# #         "num_digits": f"Contains {v} digits. Excessive digits confuse users.",
# #         "has_https": "No HTTPS - Insecure connection ⚠️" if value == 0 else "Has HTTPS - Secure connection ✓",
# #         "num_special_chars": f"Contains {v} special characters. High count (>10) may indicate suspicious URL.",
# #         "path_length": f"Path length is {v} characters. Very long paths (>50) can hide malicious intent.",
# #         "query_length": f"Query length is {v} characters. Long query strings (>50) may contain encoded attacks.",
# #         "tld_length": f"TLD length is {v} characters.",
# #         "num_letters": f"Contains {v} letters in the URL.",
# #     }
    
# #     return reasons.get(feature_name, f"{feature_name.replace('_', ' ').title()}: {v}")

# # # -------------------- EXPLAIN PREDICTION --------------------
# # def explain_prediction(model, X_scaled, X_raw, feature_names, raw_features, top_k=6):
# #     """
# #     Returns top contributing features with explanations.
# #     Works with tree-based models and ensembles.
# #     """
# #     try:
# #         # Try to get feature importances
# #         if hasattr(model, 'feature_importances_'):
# #             importances = model.feature_importances_
# #         elif hasattr(model, 'estimators_'):
# #             # For ensemble models, average feature importances
# #             try:
# #                 importances = np.mean([
# #                     est.feature_importances_ if hasattr(est, 'feature_importances_') else np.zeros(len(feature_names))
# #                     for est in model.estimators_
# #                 ], axis=0)
# #             except:
# #                 logger.warning("Could not extract feature importances from ensemble")
# #                 return []
# #         else:
# #             logger.warning("Model doesn't support feature importance")
# #             return []

# #         # Weight by actual feature values
# #         weighted = importances * np.abs(X_raw.flatten())
# #         feature_scores = list(zip(feature_names, weighted, X_raw.flatten()))
# #         feature_scores.sort(key=lambda x: abs(x[1]), reverse=True)

# #         explanations = []
# #         for fname, score, raw_value in feature_scores[:top_k]:
# #             value = raw_features.get(fname, "N/A")
            
# #             # Determine if this feature increases risk
# #             risk_contribution = "🔴 High Risk" if score > np.mean(weighted) else "🟡 Moderate Risk"
            
# #             explanations.append({
# #                 "feature": fname.replace("_", " ").title(),
# #                 "value": value,
# #                 "importance_score": round(float(score), 4),
# #                 "risk_contribution": risk_contribution,
# #                 "reason": generate_reason(fname, value)
# #             })
        
# #         return explanations
    
# #     except Exception as e:
# #         logger.error(f"Error in explain_prediction: {str(e)}")
# #         return []

# # # -------------------- ENSEMBLE PREDICTION --------------------
# # def predict_with_ensemble(X_scaled, X_raw, readable_feats):
# #     """
# #     Get predictions from multiple models for robustness.
# #     Returns consensus and individual model predictions.
# #     """
# #     predictions = {}
# #     probabilities = {}
    
# #     for model_name, model in MODELS.items():
# #         try:
# #             # Get prediction
# #             pred = model.predict(X_scaled)[0]
            
# #             # Handle -1/1 vs 0/1 labels
# #             if pred == -1:
# #                 pred = 0
            
# #             predictions[model_name] = int(pred)
            
# #             # Get probability if available
# #             if hasattr(model, 'predict_proba'):
# #                 prob = model.predict_proba(X_scaled)[0]
# #                 probabilities[model_name] = float(prob[1] if len(prob) > 1 else prob[0])
# #             else:
# #                 probabilities[model_name] = float(pred)
        
# #         except Exception as e:
# #             logger.error(f"Error with {model_name}: {str(e)}")
# #             continue
    
# #     # Consensus prediction (majority vote)
# #     consensus = int(sum(predictions.values()) > len(predictions) / 2)
    
# #     # Average probability
# #     avg_probability = np.mean(list(probabilities.values()))
    
# #     # Get explanations from primary model
# #     explanations = explain_prediction(
# #         PRIMARY_MODEL, X_scaled, X_raw, FEATURE_NAMES, readable_feats, top_k=6
# #     )
    
# #     return {
# #         'consensus': consensus,
# #         'consensus_probability': float(avg_probability),
# #         'individual_predictions': predictions,
# #         'individual_probabilities': probabilities,
# #         'explanations': explanations
# #     }

# # # -------------------- FEATURE EXTRACTION --------------------
# # class PhishingFeatureExtractor:
# #     """Extract features from URL for phishing detection"""
    
# #     def __init__(self, url):
# #         self.url = url
# #         self.parsed = urlparse(url)
# #         self.domain = self.parsed.netloc.replace("www.", "").lower()
        
# #         # Get page content (optional, can be disabled for faster processing)
# #         # self.response = safe_request(url)
# #         # self.soup = BeautifulSoup(self.response.text, "html.parser") if self.response else None
# #         self.response = None
# #         self.soup = None
        
# #         # Get WHOIS data
# #         try:
# #             self.whois_response = whois.whois(self.domain)
# #         except Exception as e:
# #             logger.debug(f"WHOIS lookup failed: {str(e)}")
# #             self.whois_response = None

# #     def has_ip(self):
# #         """Check if URL uses IP address instead of domain"""
# #         try:
# #             ipaddress.ip_address(self.domain)
# #             return 1
# #         except:
# #             return 0

# #     def domain_age_days(self):
# #         """Get domain age in days"""
# #         try:
# #             if not self.whois_response:
# #                 return -1
            
# #             creation_date = self.whois_response.creation_date
# #             if isinstance(creation_date, list):
# #                 creation_date = creation_date[0]
            
# #             if creation_date:
# #                 age = (datetime.now() - creation_date).days
# #                 return max(0, age)
# #             return -1
# #         except Exception as e:
# #             logger.debug(f"Domain age extraction failed: {str(e)}")
# #             return -1

# #     def is_shortened(self):
# #         """Check if URL uses shortener service"""
# #         shorteners = [
# #             r"bit\.ly", r"goo\.gl", r"tinyurl", r"t\.co", r"short\.ly",
# #             r"ow\.ly", r"buff\.ly", r"adf\.ly", r"is\.gd", r"tiny\.cc"
# #         ]
# #         pattern = "|".join(shorteners)
# #         return int(bool(re.search(pattern, self.url, re.I)))

# #     def count_sensitive_words(self):
# #         """Count sensitive words that are often used in phishing"""
# #         sensitive_words = [
# #             "login", "secure", "bank", "verify", "update", "account",
# #             "password", "paypal", "amazon", "signin", "confirm",
# #             "suspend", "restrict", "urgent", "alert", "authenticate"
# #         ]
# #         url_lower = self.url.lower()
# #         return sum(1 for word in sensitive_words if word in url_lower)

# #     def extract(self):
# #         """Extract all features as a vector"""
        
# #         # Calculate all features
# #         url_length = len(self.url)
# #         hostname_length = len(self.domain)
# #         path_length = len(self.parsed.path)
# #         query_length = len(self.parsed.query or "")
# #         num_subdomains = self.domain.count(".")
# #         num_digits = sum(c.isdigit() for c in self.url)
# #         num_letters = sum(c.isalpha() for c in self.url)
# #         num_special_chars = len(re.findall(r"[^a-zA-Z0-9]", self.url))
# #         has_ip = self.has_ip()
# #         has_https = int(self.parsed.scheme == "https")
        
# #         try:
# #             tld = tldextract.extract(self.url).suffix
# #             tld_length = len(tld)
# #         except:
# #             tld_length = 0
        
# #         num_hyphens = self.domain.count("-")
# #         ratio_digits_letters = num_digits / max(1, num_letters)
# #         domain_age_days = self.domain_age_days()
# #         shortened = self.is_shortened()
# #         num_sensitive_words = self.count_sensitive_words()
        
# #         # Create feature dictionary
# #         features = {
# #             "url_length": url_length,
# #             "hostname_length": hostname_length,
# #             "path_length": path_length,
# #             "query_length": query_length,
# #             "num_subdomains": num_subdomains,
# #             "num_digits": num_digits,
# #             "num_letters": num_letters,
# #             "num_special_chars": num_special_chars,
# #             "has_ip": has_ip,
# #             "has_https": has_https,
# #             "tld_length": tld_length,
# #             "num_hyphens": num_hyphens,
# #             "ratio_digits_letters": round(ratio_digits_letters, 3),
# #             "domain_age_days": domain_age_days,
# #             "shortened": shortened,
# #             "num_sensitive_words": num_sensitive_words,
# #         }
        
# #         # Create vector in exact order of trained features
# #         vector = np.array([features.get(f, 0) for f in FEATURE_NAMES])
        
# #         return vector.reshape(1, -1), features

# # # -------------------- API ROUTES --------------------

# # @app.route("/", methods=["GET"])
# # def home():
# #     """Health check endpoint"""
# #     return jsonify({
# #         "status": "healthy",
# #         "service": "Phishing URL Detection API",
# #         "version": "2.0 (Single Bundle)",
# #         "primary_model": "Voting Classifier (Hard)",
# #         "performance": MODEL_METRICS['voting_hard'],
# #         "available_models": list(MODELS.keys()),
# #         "features": len(FEATURE_NAMES),
# #         "training_date": bundle.get('training_date', 'N/A')
# #     }), 200

# # @app.route("/health", methods=["GET"])
# # def health():
# #     """Detailed health check"""
# #     return jsonify({
# #         "status": "healthy",
# #         "models_loaded": len(MODELS),
# #         "models": list(MODELS.keys()),
# #         "primary_model": "voting_hard",
# #         "threshold": THRESHOLD,
# #         "bundle_location": BUNDLE_PATH
# #     }), 200

# # @app.route("/analyze", methods=["POST"])
# # def analyze_url():
# #     """
# #     Main endpoint to analyze URL for phishing.
    
# #     Request body:
# #     {
# #         "url": "https://example.com",
# #         "threshold": 0.5 (optional)
# #     }
# #     """
# #     try:
# #         # Get request data
# #         data = request.get_json()
# #         if not data or "url" not in data:
# #             return jsonify({"error": "URL missing in request body"}), 400

# #         url = add_scheme_if_missing(data["url"].strip())
# #         threshold = data.get("threshold", THRESHOLD)
        
# #         logger.info(f"Analyzing URL: {url}")

# #         # Extract features
# #         extractor = PhishingFeatureExtractor(url)
# #         X_raw, readable_features = extractor.extract()
        
# #         # Scale features
# #         X_scaled = SCALER.transform(X_raw)
        
# #         # Get ensemble predictions
# #         ensemble_results = predict_with_ensemble(X_scaled, X_raw, readable_features)
        
# #         # Get primary model prediction
# #         primary_prob = ensemble_results['individual_probabilities'].get('voting_hard', 
# #                                                                          ensemble_results['consensus_probability'])
# #         primary_pred = int(primary_prob >= threshold)
        
# #         # Determine risk level
# #         if primary_prob > 0.85:
# #             risk_level = "Critical"
# #             risk_color = "red"
# #             risk_emoji = "🔴"
# #         elif primary_prob > 0.70:
# #             risk_level = "High"
# #             risk_color = "orange"
# #             risk_emoji = "🟠"
# #         elif primary_prob > 0.50:
# #             risk_level = "Medium"
# #             risk_color = "yellow"
# #             risk_emoji = "🟡"
# #         else:
# #             risk_level = "Low"
# #             risk_color = "green"
# #             risk_emoji = "🟢"
        
# #         # Build response
# #         response = {
# #             "url": url,
# #             "domain": extractor.domain,
# #             "timestamp": datetime.now().isoformat(),
            
# #             # Primary prediction
# #             "prediction": "Phishing" if primary_pred else "Legitimate",
# #             "confidence": round(primary_prob * 100, 2),
# #             "probability": round(primary_prob, 4),
# #             "threshold_used": threshold,
            
# #             # Risk assessment
# #             "risk_level": risk_level,
# #             "risk_color": risk_color,
# #             "risk_emoji": risk_emoji,
# #             "safe_to_visit": primary_prob < 0.5,
            
# #             # Ensemble insights
# #             "ensemble": {
# #                 "consensus": "Phishing" if ensemble_results['consensus'] else "Legitimate",
# #                 "consensus_probability": round(ensemble_results['consensus_probability'], 4),
# #                 "individual_predictions": ensemble_results['individual_predictions'],
# #                 "individual_probabilities": {
# #                     k: round(v, 4) for k, v in ensemble_results['individual_probabilities'].items()
# #                 },
# #                 "agreement": f"{sum(ensemble_results['individual_predictions'].values())}/{len(ensemble_results['individual_predictions'])} models agree"
# #             },
            
# #             # Feature analysis
# #             "features": readable_features,
# #             "top_risk_factors": ensemble_results['explanations'],
            
# #             # Model performance
# #             "model_info": {
# #                 "primary_model": "Voting Classifier (Hard)",
# #                 "accuracy": MODEL_METRICS['voting_hard']['accuracy'],
# #                 "f1_score": MODEL_METRICS['voting_hard']['f1_score'],
# #                 "recall": MODEL_METRICS['voting_hard']['recall'],
# #                 "precision": MODEL_METRICS['voting_hard']['precision']
# #             },
            
# #             # Recommendations
# #             "recommendation": (
# #                 f"{risk_emoji} DO NOT VISIT - High probability of phishing attack" if primary_prob > 0.7 else
# #                 f"{risk_emoji} EXERCISE CAUTION - Moderate phishing indicators detected" if primary_prob > 0.5 else
# #                 f"{risk_emoji} Appears legitimate - Low phishing probability"
# #             )
# #         }

# #         logger.info(f"Analysis complete: {response['prediction']} ({response['confidence']}%)")
# #         return jsonify(response), 200

# #     except Exception as e:
# #         logger.error(f"Error analyzing URL: {str(e)}", exc_info=True)
# #         return jsonify({
# #             "error": "Internal server error",
# #             "message": str(e),
# #             "status": "failed"
# #         }), 500

# # @app.route("/analyze_url", methods=["POST"])
# # def analyze_url_legacy():
# #     """Legacy endpoint for backward compatibility"""
# #     return analyze_url()

# # @app.route("/batch_analyze", methods=["POST"])
# # def batch_analyze():
# #     """
# #     Analyze multiple URLs at once.
    
# #     Request body:
# #     {
# #         "urls": ["https://example1.com", "https://example2.com", ...]
# #     }
# #     """
# #     try:
# #         data = request.get_json()
# #         if not data or "urls" not in data:
# #             return jsonify({"error": "URLs list missing"}), 400
        
# #         urls = data["urls"]
# #         if not isinstance(urls, list):
# #             return jsonify({"error": "URLs must be a list"}), 400
        
# #         if len(urls) > 50:
# #             return jsonify({"error": "Maximum 50 URLs per batch"}), 400
        
# #         results = []
# #         for url in urls:
# #             try:
# #                 url = add_scheme_if_missing(url.strip())
# #                 extractor = PhishingFeatureExtractor(url)
# #                 X_raw, readable_features = extractor.extract()
# #                 X_scaled = SCALER.transform(X_raw)
                
# #                 prob = PRIMARY_MODEL.predict_proba(X_scaled)[0][1]
# #                 pred = int(prob >= THRESHOLD)
                
# #                 results.append({
# #                     "url": url,
# #                     "prediction": "Phishing" if pred else "Legitimate",
# #                     "confidence": round(prob * 100, 2),
# #                     "risk_level": "High" if prob > 0.7 else "Medium" if prob > 0.5 else "Low"
# #                 })
# #             except Exception as e:
# #                 results.append({
# #                     "url": url,
# #                     "error": str(e),
# #                     "prediction": "Error"
# #                 })
        
# #         return jsonify({
# #             "total": len(urls),
# #             "results": results,
# #             "timestamp": datetime.now().isoformat()
# #         }), 200
    
# #     except Exception as e:
# #         logger.error(f"Batch analysis error: {str(e)}")
# #         return jsonify({"error": str(e)}), 500

# # @app.route("/models", methods=["GET"])
# # def list_models():
# #     """List all available models and their performance"""
# #     models_info = []
# #     for name, metrics in MODEL_METRICS.items():
# #         models_info.append({
# #             "name": name,
# #             "metrics": metrics,
# #             "is_primary": name == "voting_hard"
# #         })
    
# #     return jsonify({
# #         "available_models": models_info,
# #         "total_models": len(models_info),
# #         "bundle_info": {
# #             "training_date": bundle.get('training_date', 'N/A'),
# #             "training_samples": bundle.get('training_samples', 'N/A'),
# #             "test_samples": bundle.get('test_samples', 'N/A')
# #         }
# #     }), 200

# # # -------------------- ERROR HANDLERS --------------------

# # @app.errorhandler(404)
# # def not_found(e):
# #     return jsonify({"error": "Endpoint not found"}), 404

# # @app.errorhandler(500)
# # def internal_error(e):
# #     return jsonify({"error": "Internal server error"}), 500

# # # -------------------- RUN --------------------
# # if __name__ == "__main__":
# #     logger.info("="*80)
# #     logger.info("🚀 PHISHING DETECTION API READY")
# #     logger.info(f"📊 Primary Model: Voting Hard - F1: {MODEL_METRICS['voting_hard']['f1_score']}")
# #     logger.info(f"🎯 Recall: {MODEL_METRICS['voting_hard']['recall']} (Catches 98.5% of phishing!)")
# #     logger.info(f"📁 Models: {len(MODELS)} loaded from single bundle")
# #     logger.info("="*80)
# #     app.run(host="0.0.0.0", port=5002, debug=True)
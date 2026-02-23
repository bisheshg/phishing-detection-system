"""
Test the trained phishing detection model with sample URLs
"""

import pickle
import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import warnings
warnings.filterwarnings('ignore')

# Load the trained model
print("="*80)
print("PHISHING DETECTION MODEL - URL TEST")
print("="*80)

MODEL_PATH = 'PhishNet-main/FlaskBack/models/phishing_model_bundle_no_leakage.pkl'

print(f"\nLoading model from: {MODEL_PATH}")
with open(MODEL_PATH, 'rb') as f:
    bundle = pickle.load(f)

model = bundle['gradient_boosting']  # Using LightGBM
scaler = bundle['scaler']
feature_names = bundle['feature_names']

print(f"✅ Model loaded successfully")
print(f"   Features: {len(feature_names)}")
print(f"   Model type: {type(model).__name__}")

# Feature extraction function (simplified - matches training features)
def extract_features_simple(url):
    """Extract basic features from URL without fetching page content"""
    features = {}

    parsed = urlparse(url)
    domain = parsed.netloc.replace("www.", "").lower()

    # Basic URL features
    features['URLLength'] = len(url)
    features['DomainLength'] = len(domain)
    features['IsDomainIP'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+', domain) else 0
    features['CharContinuationRate'] = 0.5  # Default
    features['TLDLegitimateProb'] = 0.8 if domain.endswith('.com') else 0.5
    features['URLCharProb'] = sum(c.isalnum() or c in '.-/:' for c in url) / max(len(url), 1)
    features['TLDLength'] = len(domain.split('.')[-1]) if '.' in domain else 0
    features['NoOfSubDomain'] = domain.count('.')
    features['HasObfuscation'] = 1 if '%' in url or '\\x' in url else 0
    features['NoOfObfuscatedChar'] = len(re.findall(r'%[0-9a-fA-F]{2}', url))
    features['ObfuscationRatio'] = features['NoOfObfuscatedChar'] / max(len(url), 1)
    features['LetterRatioInURL'] = sum(c.isalpha() for c in url) / max(len(url), 1)
    features['NoOfDegitsInURL'] = sum(c.isdigit() for c in url)
    features['DegitRatioInURL'] = features['NoOfDegitsInURL'] / max(len(url), 1)
    features['NoOfEqualsInURL'] = url.count('=')
    features['NoOfQMarkInURL'] = url.count('?')
    features['NoOfAmpersandInURL'] = url.count('&')
    features['NoOfOtherSpecialCharsInURL'] = len([c for c in url if not c.isalnum() and c not in '=?&.:/-@#'])
    features['SpacialCharRatioInURL'] = sum(not c.isalnum() for c in url) / max(len(url), 1)
    features['IsHTTPS'] = 1 if parsed.scheme == 'https' else 0

    # Page content features (defaults when not fetching)
    features['LineOfCode'] = 500  # Default
    features['LargestLineLength'] = 1000  # Default
    features['HasTitle'] = 1  # Default
    features['DomainTitleMatchScore'] = 50.0  # Default
    features['HasFavicon'] = 1  # Default
    features['Robots'] = 0  # Default
    features['IsResponsive'] = 1  # Default
    features['NoOfURLRedirect'] = 0  # Default
    features['NoOfSelfRedirect'] = 0  # Default
    features['HasDescription'] = 1  # Default
    features['NoOfPopup'] = 0  # Default
    features['NoOfiFrame'] = 0  # Default
    features['HasExternalFormSubmit'] = 0  # Default
    features['HasSocialNet'] = 1 if any(social in url.lower() for social in ['facebook', 'twitter', 'instagram', 'linkedin']) else 0
    features['HasSubmitButton'] = 1  # Default
    features['HasHiddenFields'] = 0  # Default
    features['HasPasswordField'] = 1 if 'login' in url.lower() or 'signin' in url.lower() else 0

    # Keyword features
    features['Bank'] = 1 if any(kw in url.lower() for kw in ['bank', 'banking', 'paypal', 'payment']) else 0
    features['Pay'] = 1 if any(kw in url.lower() for kw in ['pay', 'payment', 'billing', 'checkout']) else 0
    features['Crypto'] = 1 if any(kw in url.lower() for kw in ['crypto', 'bitcoin', 'wallet', 'blockchain']) else 0
    features['HasCopyrightInfo'] = 1  # Default

    # Content count features (defaults)
    features['NoOfImage'] = 10  # Default
    features['NoOfCSS'] = 5  # Default
    features['NoOfJS'] = 5  # Default
    features['NoOfSelfRef'] = 50  # Default
    features['NoOfEmptyRef'] = 1  # Default
    features['NoOfExternalRef'] = 20  # Default

    # Engineered features
    features['ObfuscationIPRisk'] = features['IsDomainIP'] * features['HasObfuscation']
    features['InsecurePasswordField'] = (1 - features['IsHTTPS']) * features['HasPasswordField']
    features['PageCompletenessRatio'] = features['NoOfSelfRef'] / (features['NoOfExternalRef'] + 1)
    features['LegitContentScore'] = (features['HasTitle'] + features['HasFavicon'] +
                                     features['HasDescription'] + features['HasCopyrightInfo'] +
                                     features['IsResponsive'])
    features['SuspiciousFinancialFlag'] = ((features['Bank'] + features['Pay'] + features['Crypto']) *
                                           (1 - features['HasCopyrightInfo']))
    features['TitleMatchCombined'] = np.sqrt(features['DomainTitleMatchScore'] * features['DomainTitleMatchScore'])

    # Log transforms
    for col in ['LineOfCode', 'LargestLineLength', 'NoOfExternalRef', 'NoOfSelfRef',
                'NoOfCSS', 'NoOfJS', 'NoOfImage', 'NoOfEmptyRef', 'URLLength', 'DomainLength']:
        if col in features:
            features[f'{col}_log'] = np.log1p(features[col])

    return features

def predict_url(url, model, scaler, feature_names):
    """Predict if a URL is phishing or legitimate"""
    print(f"\n{'='*80}")
    print(f"Testing URL: {url}")
    print(f"{'='*80}")

    # Extract features
    features = extract_features_simple(url)

    # Create feature vector in correct order
    feature_vector = []
    for fname in feature_names:
        feature_vector.append(features.get(fname, 0))

    # Convert to DataFrame for scaler
    X = pd.DataFrame([feature_vector], columns=feature_names)
    X_scaled = scaler.transform(X)

    # Predict
    prediction = model.predict(X_scaled)[0]
    probability = model.predict_proba(X_scaled)[0]

    # Display results
    label = "🚨 PHISHING" if prediction == 0 else "✅ LEGITIMATE"
    confidence = probability[prediction] * 100

    print(f"\n📊 PREDICTION: {label}")
    print(f"   Confidence: {confidence:.2f}%")
    print(f"   Phishing probability: {probability[0]*100:.2f}%")
    print(f"   Legitimate probability: {probability[1]*100:.2f}%")

    # Risk assessment
    if probability[0] > 0.8:
        risk = "🔴 VERY HIGH RISK - Block immediately"
    elif probability[0] > 0.5:
        risk = "🟠 HIGH RISK - Proceed with caution"
    elif probability[0] > 0.3:
        risk = "🟡 MEDIUM RISK - Verify before proceeding"
    elif probability[0] > 0.1:
        risk = "🟢 LOW RISK - Likely safe"
    else:
        risk = "✅ VERY LOW RISK - Safe"

    print(f"\n⚠️  RISK LEVEL: {risk}")

    # Show key features
    print(f"\n🔍 Key Features:")
    print(f"   URL Length: {features['URLLength']}")
    print(f"   Domain Length: {features['DomainLength']}")
    print(f"   HTTPS: {'Yes' if features['IsHTTPS'] else 'No'}")
    print(f"   Has IP in domain: {'Yes' if features['IsDomainIP'] else 'No'}")
    print(f"   Has obfuscation: {'Yes' if features['HasObfuscation'] else 'No'}")
    print(f"   Subdomains: {features['NoOfSubDomain']}")
    print(f"   Suspicious keywords: Bank={features['Bank']}, Pay={features['Pay']}, Crypto={features['Crypto']}")

    return prediction, probability

# Test URLs
print("\n" + "="*80)
print("TESTING SAMPLE URLs")
print("="*80)

test_urls = [
    # Legitimate URLs
    "https://www.google.com",
    "https://github.com/anthropics/claude-code",
    "https://www.wikipedia.org",
    "https://stackoverflow.com/questions",

    # Suspicious/Phishing-like URLs
    "http://paypal-secure-login.com",
    "https://192.168.1.1/admin",
    "http://secure-bank-verify-account-update.com",
    "https://amaz0n-customer-support.com",
    "http://bit.ly.phishing.xyz",
]

print("\n🟢 TESTING LEGITIMATE URLs:")
print("-" * 80)
for url in test_urls[:4]:
    predict_url(url, model, scaler, feature_names)

print("\n\n🔴 TESTING SUSPICIOUS URLs:")
print("-" * 80)
for url in test_urls[4:]:
    predict_url(url, model, scaler, feature_names)

print("\n" + "="*80)
print("TESTING COMPLETE!")
print("="*80)

# Interactive mode
print("\n💡 Want to test your own URL? Enter it below (or press Enter to skip):")
custom_url = input("URL: ").strip()

if custom_url:
    predict_url(custom_url, model, scaler, feature_names)

"""
Enhanced Phishing Detection with Real Page Content Fetching
Extracts actual features from live URLs for accurate predictions
"""

import pickle
import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import warnings
import tldextract
from datetime import datetime
warnings.filterwarnings('ignore')

# Load the trained model
print("="*80)
print("🔍 ENHANCED PHISHING DETECTION - WITH PAGE CONTENT ANALYSIS")
print("="*80)

MODEL_PATH = 'PhishNet-main/FlaskBack/models/phishing_model_bundle_no_leakage.pkl'

print(f"\nLoading model from: {MODEL_PATH}")
with open(MODEL_PATH, 'rb') as f:
    bundle = pickle.load(f)

model = bundle['gradient_boosting']
scaler = bundle['scaler']
feature_names = bundle['feature_names']

print(f"✅ Model loaded successfully")
print(f"   Model: {bundle.get('best_model', 'LightGBM')}")
print(f"   Version: {bundle.get('version', '2.1')}")
print(f"   Features: {len(feature_names)}")

class EnhancedFeatureExtractor:
    def __init__(self, url):
        self.url = url.strip()
        self.parsed = urlparse(self.url)
        self.domain = self.parsed.netloc.replace("www.", "").lower().strip()
        self.page_html = ""
        self.soup = None
        self.fetch_success = False

        # Fetch page content
        self._fetch_page()

    def _fetch_page(self):
        """Fetch actual page content"""
        try:
            print(f"   📡 Fetching page content...")
            response = requests.get(
                self.url,
                timeout=5,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                verify=False
            )
            self.page_html = response.text
            self.soup = BeautifulSoup(self.page_html, "html.parser")
            self.fetch_success = True
            print(f"   ✅ Page fetched successfully ({len(self.page_html)} bytes)")
        except requests.Timeout:
            print(f"   ⏱️  Timeout - using URL-only features")
        except requests.ConnectionError:
            print(f"   ❌ Connection failed - using URL-only features")
        except Exception as e:
            print(f"   ⚠️  Error: {str(e)[:50]} - using URL-only features")

    def extract_all_features(self):
        """Extract all features matching training data"""
        features = {}

        # === URL STRUCTURE FEATURES ===
        features['URLLength'] = len(self.url)
        features['DomainLength'] = len(self.domain)

        # Check if domain is IP address
        features['IsDomainIP'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+', self.domain) else 0

        # Character continuation rate
        if self.url:
            max_run = cur_run = 1
            for i in range(1, len(self.url)):
                if self.url[i].isalpha() == self.url[i-1].isalpha():
                    cur_run += 1
                    max_run = max(max_run, cur_run)
                else:
                    cur_run = 1
            features['CharContinuationRate'] = max_run / len(self.url)
        else:
            features['CharContinuationRate'] = 0.0

        # TLD features
        tld_info = tldextract.extract(self.url)
        tld = tld_info.suffix.lower()
        tld_probs = {"com": 0.95, "org": 0.85, "net": 0.80, "edu": 0.95,
                     "gov": 0.98, "co": 0.75, "io": 0.70, "uk": 0.80}
        features['TLDLegitimateProb'] = tld_probs.get(tld, 0.3)
        features['TLDLength'] = len(tld)

        # URL character probability
        features['URLCharProb'] = sum(c.isalnum() or c in '.-/:#@_' for c in self.url) / max(len(self.url), 1)

        # Subdomain count
        features['NoOfSubDomain'] = self.domain.count('.')

        # Obfuscation detection
        features['HasObfuscation'] = 1 if re.search(r'%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}', self.url) else 0
        features['NoOfObfuscatedChar'] = len(re.findall(r'%[0-9a-fA-F]{2}', self.url))
        features['ObfuscationRatio'] = features['NoOfObfuscatedChar'] / max(len(self.url), 1)

        # Character statistics
        features['LetterRatioInURL'] = sum(c.isalpha() for c in self.url) / max(len(self.url), 1)
        features['NoOfDegitsInURL'] = sum(c.isdigit() for c in self.url)
        features['DegitRatioInURL'] = features['NoOfDegitsInURL'] / max(len(self.url), 1)

        # Special characters
        features['NoOfEqualsInURL'] = self.url.count('=')
        features['NoOfQMarkInURL'] = self.url.count('?')
        features['NoOfAmpersandInURL'] = self.url.count('&')
        standard_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=?&.:/-@#")
        features['NoOfOtherSpecialCharsInURL'] = sum(1 for c in self.url if c not in standard_chars)
        features['SpacialCharRatioInURL'] = sum(not c.isalnum() for c in self.url) / max(len(self.url), 1)

        # HTTPS
        features['IsHTTPS'] = 1 if self.parsed.scheme == 'https' else 0

        # === PAGE CONTENT FEATURES ===
        if self.fetch_success and self.soup:
            # Line of code
            lines = self.page_html.splitlines()
            features['LineOfCode'] = min(len(lines), 50000)
            features['LargestLineLength'] = min(max((len(l) for l in lines), default=0), 500000)

            # Title
            title_tag = self.soup.find('title')
            features['HasTitle'] = 1 if title_tag and title_tag.get_text().strip() else 0

            # Title match scores
            if title_tag and title_tag.get_text().strip():
                title_text = title_tag.get_text().lower()
                domain_words = set(re.findall(r'\w+', self.domain.lower()))
                title_words = set(re.findall(r'\w+', title_text))

                if domain_words and title_words:
                    domain_match = len(domain_words & title_words) / len(domain_words) * 100
                    features['DomainTitleMatchScore'] = min(domain_match, 100.0)
                else:
                    features['DomainTitleMatchScore'] = 0.0
            else:
                features['DomainTitleMatchScore'] = 0.0

            # Favicon
            features['HasFavicon'] = 1 if self.soup.find('link', rel='icon') or self.soup.find('link', rel='shortcut icon') else 0

            # Meta tags
            features['Robots'] = 1 if self.soup.find('meta', attrs={'name': 'robots'}) else 0
            features['IsResponsive'] = 1 if self.soup.find('meta', attrs={'name': 'viewport'}) else 0
            features['HasDescription'] = 1 if self.soup.find('meta', attrs={'name': 'description'}) else 0

            # Redirects (approximate)
            features['NoOfURLRedirect'] = 0  # Would need to track actual redirects
            features['NoOfSelfRedirect'] = 0

            # Page elements
            features['NoOfPopup'] = len(self.soup.find_all('div', class_=re.compile('popup|modal', re.I)))
            features['NoOfiFrame'] = len(self.soup.find_all('iframe'))

            # Forms
            forms = self.soup.find_all('form')
            external_forms = [f for f in forms if f.get('action', '').startswith('http')
                            and self.domain not in f.get('action', '')]
            features['HasExternalFormSubmit'] = 1 if external_forms else 0

            # Social network links
            social_patterns = ['facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com', 'youtube.com']
            links = self.soup.find_all('a', href=True)
            features['HasSocialNet'] = 1 if any(any(social in link['href'] for social in social_patterns) for link in links) else 0

            # Form fields
            features['HasSubmitButton'] = 1 if self.soup.find('input', type='submit') or self.soup.find('button', type='submit') else 0
            features['HasHiddenFields'] = 1 if self.soup.find('input', type='hidden') else 0
            features['HasPasswordField'] = 1 if self.soup.find('input', type='password') else 0

            # Copyright
            page_text = self.soup.get_text().lower()
            features['HasCopyrightInfo'] = 1 if '©' in page_text or 'copyright' in page_text else 0

            # Resource counts
            features['NoOfImage'] = len(self.soup.find_all('img'))
            features['NoOfCSS'] = len(self.soup.find_all('link', rel='stylesheet')) + len(self.soup.find_all('style'))
            features['NoOfJS'] = len(self.soup.find_all('script'))

            # References
            all_links = self.soup.find_all(['a', 'link', 'script', 'img'], href=True) + self.soup.find_all(['a', 'link', 'script', 'img'], src=True)
            self_refs = sum(1 for tag in all_links if self.domain in tag.get('href', '') or self.domain in tag.get('src', ''))
            external_refs = sum(1 for tag in all_links if 'http' in tag.get('href', '') or 'http' in tag.get('src', ''))
            empty_refs = sum(1 for tag in all_links if tag.get('href', '#') == '#' or tag.get('src', '#') == '#')

            features['NoOfSelfRef'] = min(self_refs, 1000)
            features['NoOfExternalRef'] = min(external_refs, 1000)
            features['NoOfEmptyRef'] = min(empty_refs, 100)
        else:
            # Use defaults when page not fetched
            features['LineOfCode'] = 500
            features['LargestLineLength'] = 1000
            features['HasTitle'] = 0
            features['DomainTitleMatchScore'] = 0.0
            features['HasFavicon'] = 0
            features['Robots'] = 0
            features['IsResponsive'] = 0
            features['NoOfURLRedirect'] = 0
            features['NoOfSelfRedirect'] = 0
            features['HasDescription'] = 0
            features['NoOfPopup'] = 0
            features['NoOfiFrame'] = 0
            features['HasExternalFormSubmit'] = 0
            features['HasSocialNet'] = 0
            features['HasSubmitButton'] = 0
            features['HasHiddenFields'] = 0
            features['HasPasswordField'] = 0
            features['HasCopyrightInfo'] = 0
            features['NoOfImage'] = 0
            features['NoOfCSS'] = 0
            features['NoOfJS'] = 0
            features['NoOfSelfRef'] = 0
            features['NoOfExternalRef'] = 0
            features['NoOfEmptyRef'] = 0

        # === KEYWORD FEATURES ===
        url_lower = self.url.lower()
        features['Bank'] = 1 if any(kw in url_lower for kw in ['bank', 'banking']) else 0
        features['Pay'] = 1 if any(kw in url_lower for kw in ['paypal', 'pay', 'payment']) else 0
        features['Crypto'] = 1 if any(kw in url_lower for kw in ['crypto', 'bitcoin', 'wallet']) else 0

        # === ENGINEERED FEATURES ===
        features['ObfuscationIPRisk'] = features['IsDomainIP'] * features['HasObfuscation']
        features['InsecurePasswordField'] = (1 - features['IsHTTPS']) * features['HasPasswordField']
        features['PageCompletenessRatio'] = features['NoOfSelfRef'] / (features['NoOfExternalRef'] + 1)
        features['LegitContentScore'] = (features['HasTitle'] + features['HasFavicon'] +
                                         features['HasDescription'] + features['HasCopyrightInfo'] +
                                         features['IsResponsive'])
        features['SuspiciousFinancialFlag'] = ((features['Bank'] + features['Pay'] + features['Crypto']) *
                                               (1 - features['HasCopyrightInfo']))
        features['TitleMatchCombined'] = np.sqrt(features['DomainTitleMatchScore'] * features['DomainTitleMatchScore'])

        # === LOG TRANSFORMS ===
        for col in ['LineOfCode', 'LargestLineLength', 'NoOfExternalRef', 'NoOfSelfRef',
                    'NoOfCSS', 'NoOfJS', 'NoOfImage', 'NoOfEmptyRef', 'URLLength', 'DomainLength']:
            if col in features:
                features[f'{col}_log'] = np.log1p(features[col])

        return features

def predict_url_enhanced(url, model, scaler, feature_names):
    """Enhanced prediction with real page content"""
    print(f"\n{'='*80}")
    print(f"🔍 Analyzing: {url}")
    print(f"{'='*80}")

    # Extract features
    extractor = EnhancedFeatureExtractor(url)
    features = extractor.extract_all_features()

    # Create feature vector
    feature_vector = [features.get(fname, 0) for fname in feature_names]
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
    print(f"\n🔍 Key Security Indicators:")
    print(f"   ├─ URL Length: {features['URLLength']} chars")
    print(f"   ├─ Domain Length: {features['DomainLength']} chars")
    print(f"   ├─ HTTPS: {'✅ Yes' if features['IsHTTPS'] else '❌ No (MAJOR RED FLAG)'}")
    print(f"   ├─ IP in domain: {'⚠️  Yes' if features['IsDomainIP'] else '✅ No'}")
    print(f"   ├─ Obfuscation: {'⚠️  Yes' if features['HasObfuscation'] else '✅ No'}")
    print(f"   ├─ Subdomains: {features['NoOfSubDomain']}")
    print(f"   └─ Suspicious keywords: Bank={features['Bank']}, Pay={features['Pay']}, Crypto={features['Crypto']}")

    if extractor.fetch_success:
        print(f"\n📄 Page Content Analysis:")
        print(f"   ├─ Lines of code: {features['LineOfCode']}")
        print(f"   ├─ Has title: {'✅ Yes' if features['HasTitle'] else '❌ No'}")
        print(f"   ├─ Has favicon: {'✅ Yes' if features['HasFavicon'] else '❌ No'}")
        print(f"   ├─ Has copyright: {'✅ Yes' if features['HasCopyrightInfo'] else '❌ No'}")
        print(f"   ├─ Images: {features['NoOfImage']}")
        print(f"   ├─ CSS files: {features['NoOfCSS']}")
        print(f"   ├─ JS files: {features['NoOfJS']}")
        print(f"   ├─ Password field: {'⚠️  Yes' if features['HasPasswordField'] else 'No'}")
        print(f"   ├─ External form: {'⚠️  Yes' if features['HasExternalFormSubmit'] else '✅ No'}")
        print(f"   └─ Legitimacy score: {features['LegitContentScore']}/5")

    return prediction, probability, features

# Test URLs
print("\n" + "="*80)
print("TESTING SAMPLE URLs WITH PAGE CONTENT ANALYSIS")
print("="*80)

test_urls = [
    # Legitimate URLs
    ("https://www.google.com", "Google Search"),
    ("https://github.com", "GitHub"),
    ("https://www.wikipedia.org", "Wikipedia"),

    # Suspicious URLs
    ("http://paypal-secure-login.com", "Fake PayPal"),
    ("http://secure-bank-verify-account-update.com", "Fake Banking"),
]

print("\n🟢 LEGITIMATE URLs:")
print("-" * 80)
for url, desc in test_urls[:3]:
    print(f"\nTesting: {desc}")
    predict_url_enhanced(url, model, scaler, feature_names)

print("\n\n🔴 SUSPICIOUS URLs:")
print("-" * 80)
for url, desc in test_urls[3:]:
    print(f"\nTesting: {desc}")
    predict_url_enhanced(url, model, scaler, feature_names)

print("\n" + "="*80)
print("✅ TESTING COMPLETE!")
print("="*80)

# Interactive mode
print("\n💡 Test your own URL:")
custom_url = input("Enter URL (or press Enter to skip): ").strip()

if custom_url:
    if not custom_url.startswith(('http://', 'https://')):
        custom_url = 'http://' + custom_url
    predict_url_enhanced(custom_url, model, scaler, feature_names)

print("\n🎯 Model is ready for production use!")

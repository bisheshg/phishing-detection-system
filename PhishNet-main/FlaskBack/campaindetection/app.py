from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import os
import re
import subprocess
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from urllib.parse import urlparse
from dateutil import parser as dateutil_parser
import ipaddress
import tldextract
import logging
import numpy as np
import warnings
import concurrent.futures
import socket
import urllib3
warnings.filterwarnings('ignore')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import rule engine for hybrid detection
from rule_engine import RuleEngine
import shap
from adversarial_engine import AdversarialEngine

# -------------------- APP SETUP --------------------
app = Flask(__name__)
CORS(app, resources={
    r"/*": {
        "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------- MODEL LOADING --------------------
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

# Auto-detect: prefer new UCI WebsitePhishing bundle, fall back to REALISTIC_v3
UCI_BUNDLE_PATH      = os.path.join(MODEL_DIR, "phishing_model_bundle_websitephishing.pkl")
REALISTIC_BUNDLE_PATH = os.path.join(MODEL_DIR, "phishing_model_bundle_REALISTIC_v3.pkl")

logger.info("="*80)
logger.info("🚀 Loading Model Bundle...")

if os.path.exists(UCI_BUNDLE_PATH):
    BUNDLE_PATH = UCI_BUNDLE_PATH
    MODEL_TYPE  = 'uci'
    logger.info("✅ Using UCI WebsitePhishing bundle (16 features)")
elif os.path.exists(REALISTIC_BUNDLE_PATH):
    BUNDLE_PATH = REALISTIC_BUNDLE_PATH
    MODEL_TYPE  = 'realistic'
    logger.info("✅ Using REALISTIC_v3 bundle (63 features)")
else:
    raise FileNotFoundError(f"No model bundle found in {MODEL_DIR}")

with open(BUNDLE_PATH, 'rb') as f:
    bundle = pickle.load(f)

# Initialize Rule Engine
rule_engine = RuleEngine()
logger.info("✅ Rule Engine initialized")

# -------------------- WHOIS via subprocess (Python-3.14 safe) --------------------
class _WhoisInfo:
    """Minimal WHOIS result container — keeps .creation_date API compatible."""
    __slots__ = ('creation_date',)
    def __init__(self, creation_date):
        self.creation_date = creation_date

# Ordered patterns: most specific / reliable first.
# 'Creation Date:' is the ICANN-standard registrar field; 'created:' can be
# a Verisign registry server date (1985-01-01 placeholder) — try it last.
_WHOIS_DATE_PATTERNS = [
    re.compile(r'Creation Date\s*:\s*(.+)',              re.IGNORECASE),
    re.compile(r'Domain Registration Date\s*:\s*(.+)',   re.IGNORECASE),
    re.compile(r'Registration Date\s*:\s*(.+)',          re.IGNORECASE),
    re.compile(r'Registered On\s*:\s*(.+)',              re.IGNORECASE),
    re.compile(r'Registered\s*:\s*(.+)',                 re.IGNORECASE),
    re.compile(r'created\s*:\s*(.+)',                    re.IGNORECASE),
]

# strptime formats to try in order (most common first)
_WHOIS_DATE_FMTS = [
    '%Y-%m-%dT%H:%M:%SZ',
    '%Y-%m-%dT%H:%M:%S+0000',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%d',
    '%d-%b-%Y',
    '%d/%m/%Y',
    '%Y/%m/%d',
    '%d.%m.%Y',
    '%B %d, %Y',
    '%d %B %Y',
]

# Known Verisign placeholder — not a real creation date
_WHOIS_PLACEHOLDER_DATE = datetime(1985, 1, 1)

def _parse_whois_date(raw):
    """Try to parse a date string from WHOIS output. Returns datetime or None."""
    raw = raw.strip()[:40]
    for fmt in _WHOIS_DATE_FMTS:
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=None)
        except ValueError:
            pass
    try:
        return dateutil_parser.parse(raw, ignoretz=True)
    except Exception:
        pass
    return None

def safe_whois(domain, timeout_sec=8):
    """
    WHOIS lookup using the system 'whois' CLI + regex parsing.
    Returns a _WhoisInfo(creation_date=datetime) or None.
    Works on Python 3.14 where the 'whois' PyPI library is broken.
    """
    domain = domain.split(':')[0].strip().lstrip('.')
    if not domain:
        return None
    try:
        proc = subprocess.run(
            ['whois', domain],
            capture_output=True, text=True, timeout=timeout_sec
        )
        text = proc.stdout or ''
        # Try each pattern in priority order; skip placeholder dates
        for pat in _WHOIS_DATE_PATTERNS:
            for m in pat.finditer(text):
                dt = _parse_whois_date(m.group(1))
                if dt and dt != _WHOIS_PLACEHOLDER_DATE and dt.year > 1990:
                    logger.info(f"WHOIS {domain}: created {dt.date()} ({(datetime.now()-dt).days} days ago)")
                    return _WhoisInfo(dt)
        logger.debug(f"WHOIS: no valid creation date found for {domain}")
        return None
    except subprocess.TimeoutExpired:
        logger.warning(f"WHOIS timeout for {domain} (>{timeout_sec}s)")
        return None
    except FileNotFoundError:
        logger.warning("'whois' CLI not found — domain age unavailable")
        return None
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        return None

# Load models based on bundle type
if MODEL_TYPE == 'uci':
    # UCI bundle keys: lgb, xgb, catboost, rf (and optionally stacking/best_model)
    MODELS = {}
    for key in ['lgb', 'xgb', 'catboost', 'rf']:
        if key in bundle:
            MODELS[key] = bundle[key]
    if 'stacking' in bundle:
        MODELS['stacking'] = bundle['stacking']
    SCALER = None  # UCI features are categorical — no scaling needed
else:
    # REALISTIC bundle: gradient_boosting (LightGBM), xgboost, catboost, random_forest
    MODELS = {
        'gradient_boosting': bundle['gradient_boosting'],
        'xgboost':           bundle['xgboost'],
        'catboost':          bundle['catboost'],
        'random_forest':     bundle['random_forest'],
    }
    SCALER = bundle['scaler']

FEATURE_NAMES  = bundle['feature_names']
THRESHOLD      = bundle.get('optimal_threshold', 0.5)
MODEL_METRICS  = bundle.get('model_metrics', {})

# Trusted domains whitelist
TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'apple.com',
    'microsoft.com', 'github.com', 'stackoverflow.com', 'reddit.com',
    'twitter.com', 'x.com', 'linkedin.com', 'netflix.com', 'wikipedia.org',
    'yahoo.com', 'bing.com', 'instagram.com', 'tiktok.com', 'zoom.us',
    'dropbox.com', 'adobe.com', 'ebay.com', 'paypal.com', 'spotify.com',
    # Anthropic / AI platforms
    'claude.ai', 'anthropic.com',
    # Other common AI / tech platforms
    'openai.com', 'chatgpt.com', 'huggingface.co',
    'notion.so', 'figma.com', 'canva.com', 'slack.com', 'discord.com',
    'whatsapp.com', 'telegram.org', 'signal.org',
}

logger.info(f"✅ Model type: {MODEL_TYPE.upper()}")
logger.info(f"✅ Loaded {len(MODELS)} models")
logger.info(f"✅ Features: {len(FEATURE_NAMES)}")
logger.info(f"✅ Trusted domains: {len(TRUSTED_DOMAINS)}")

# -------------------- SHAP EXPLAINERS --------------------
SHAP_EXPLAINERS = {}
for _name, _model in MODELS.items():
    try:
        SHAP_EXPLAINERS[_name] = shap.TreeExplainer(_model)
        logger.info(f"✅ SHAP explainer ready: {_name}")
    except Exception as _e:
        logger.warning(f"⚠️  SHAP not available for {_name}: {_e}")

# Initialize Adversarial Engine
adversarial_engine = AdversarialEngine(MODELS, FEATURE_NAMES)
logger.info("✅ Adversarial Engine ready")

logger.info("="*80)

# -------------------- FEATURE EXTRACTION --------------------
class FeatureExtractor:
    def __init__(self, url):
        self.url = url.strip()
        self.parsed = urlparse(self.url)
        self.domain = self.parsed.netloc.replace("www.", "").lower().strip()
        self.whois_response = None
        self.page_html = ""
        self.soup = None

        # WHOIS only for suspicious domains — with a hard 5s timeout
        if self._is_suspicious():
            self.whois_response = safe_whois(self.domain)

        # Fetch page content for HTML-based features
        self._fetch_page()

    def _is_suspicious(self):
        return any([
            self.domain.count("-") > 2,
            len(self.domain) > 30,
            bool(re.search(r"login|secure|verify|update|account", self.url, re.I)),
            self._has_ip(),
        ])

    def _has_ip(self):
        try:
            ipaddress.ip_address(self.domain)
            return True
        except Exception:
            return False

    def _fetch_page(self):
        from hardened_fetcher import fetcher
        try:
            # Use the production-grade hardened fetcher
            self.page_html = fetcher.fetch(self.url) or ""
            if self.page_html:
                self.soup = BeautifulSoup(self.page_html, "html.parser")
            else:
                self.soup = None
        except Exception as e:
            logger.error(f"Fetch failed: {e}")
            self.page_html = ""
            self.soup = None

    def get_campaign_signature(self):
        """Extract markers for campaign correlation"""
        import hashlib
        import socket
        
        # 1. HTML similarity hash (content-based)
        html_hash = ""
        if self.page_html:
            # Normalize HTML by removing dynamic/variable parts
            normalized = re.sub(r'\s+', ' ', self.page_html) # collapse whitespace
            # Only hash first 10k chars to focus on main structure
            html_hash = hashlib.md5(normalized[:10000].encode()).hexdigest()
            
        # 2. Server IP (infrastructure-based)
        server_ip = ""
        try:
            server_ip = socket.gethostbyname(self.domain)
        except:
            pass
            
        return {
            "html_hash": html_hash,
            "server_ip": server_ip,
            "domain_name": self.domain
        }

    # ---- URL-structure features ----
    def _url_length(self): return len(self.url)
    def _domain_length(self): return len(self.domain)
    def _is_domain_ip(self): return 1 if self._has_ip() else 0
    def _tld_length(self): return len(tldextract.extract(self.url).suffix)
    def _no_of_subdomain(self): return self.domain.count(".")
    def _is_https(self): return 1 if self.parsed.scheme == "https" else 0

    def _letter_ratio(self):
        n = sum(c.isalpha() for c in self.url)
        return n / max(1, len(self.url))

    def _no_of_digits(self): return sum(c.isdigit() for c in self.url)
    def _digit_ratio(self): return self._no_of_digits() / max(1, len(self.url))
    def _no_of_equals(self): return self.url.count("=")
    def _no_of_qmark(self): return self.url.count("?")
    def _no_of_ampersand(self): return self.url.count("&")

    def _no_of_other_special(self):
        standard = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=?&.:/_-@#")
        return sum(1 for c in self.url if c not in standard)

    def _special_char_ratio(self):
        return sum(1 for c in self.url if not c.isalnum()) / max(1, len(self.url))

    def _has_obfuscation(self):
        return 1 if re.search(r"%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|&#\d+;", self.url) else 0

    def _no_of_obfuscated_chars(self):
        return len(re.findall(r"%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|&#\d+;", self.url))

    def _obfuscation_ratio(self):
        return self._no_of_obfuscated_chars() / max(1, len(self.url))

    def _url_similarity_index(self):
        n = sum(c.isalnum() or c in ".-/" for c in self.url)
        return n / max(1, len(self.url))

    def _char_continuation_rate(self):
        if not self.url:
            return 0.0
        max_run = cur_run = 1
        for i in range(1, len(self.url)):
            if self.url[i].isalpha() == self.url[i - 1].isalpha():
                cur_run += 1
                max_run = max(max_run, cur_run)
            else:
                cur_run = 1
        return max_run / max(1, len(self.url))

    def _tld_legit_prob(self):
        legit = {"com": 0.95, "org": 0.85, "net": 0.80, "edu": 0.95,
                 "gov": 0.98, "co": 0.75, "io": 0.70, "uk": 0.80}
        return legit.get(tldextract.extract(self.url).suffix.lower(), 0.3)

    def _url_char_prob(self):
        n = sum(1 for c in self.url if c.isalnum() or c in ".-/:#@_")
        return n / max(1, len(self.url))

    def _domain_age_days(self):
        base = ".".join(self.domain.split(".")[-2:])
        if base in TRUSTED_DOMAINS:
            return 7300
        try:
            if not self.whois_response:
                return -1
            cd = self.whois_response.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            return max(0, (datetime.now() - cd).days) if cd else -1
        except Exception:
            return -1

    # ---- Page-content features (require page fetch) ----
    def _lines(self):
        return self.page_html.splitlines() if self.page_html else []

    def _line_of_code(self): return min(len(self._lines()), 50000)
    def _largest_line_length(self):
        return min(max((len(l) for l in self._lines()), default=0), 500000)

    def _has_title(self):
        return 1 if (self.soup and self.soup.find("title")) else 0

    def _get_title_text(self):
        if not self.soup:
            return ""
        tag = self.soup.find("title")
        return tag.get_text(strip=True).lower() if tag else ""

    def _domain_title_match_score(self):
        title = self._get_title_text()
        if not title:
            return 0.0
        base = self.domain.split(".")[0].lower()
        if base in title:
            return 1.0
        return sum(1 for c in base if c in title) / max(1, len(base))

    def _url_title_match_score(self):
        """Calculate similarity between full URL and page title"""
        title = self._get_title_text()
        if not title:
            return 0.0
        url_lower = self.url.lower()
        # Check if any significant word from URL appears in title
        url_words = set([w for w in re.findall(r'[a-z]{3,}', url_lower)])
        title_words = set([w for w in re.findall(r'[a-z]{3,}', title)])
        if not url_words:
            return 0.0
        matches = url_words & title_words
        return len(matches) / len(url_words) if url_words else 0.0

    def _has_favicon(self):
        if not self.soup:
            return 0
        links = self.soup.find_all("link", rel=lambda r: r and "icon" in " ".join(r).lower())
        return 1 if links else 0

    def _robots(self):
        if not self.soup:
            return 0
        meta = self.soup.find("meta", attrs={"name": re.compile(r"robots", re.I)})
        if meta:
            content = meta.get("content", "").lower()
            return 0 if ("noindex" in content or "nofollow" in content) else 1
        return 1

    def _is_responsive(self):
        if not self.soup:
            return 0
        return 1 if self.soup.find("meta", attrs={"name": re.compile(r"viewport", re.I)}) else 0

    def _no_of_url_redirect(self):
        if not self.soup:
            return 0
        html = str(self.soup)
        return min(len(re.findall(r"redirect|location\.href", html, re.I)), 100)

    def _no_of_self_redirect(self):
        if not self.soup:
            return 0
        count = sum(
            1 for a in self.soup.find_all("a", href=True)
            if self.domain in a["href"] and "redirect" in a["href"].lower()
        )
        return min(count, 100)

    def _has_description(self):
        if not self.soup:
            return 0
        meta = self.soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
        return 1 if (meta and meta.get("content")) else 0

    def _no_of_popup(self):
        if not self.soup:
            return 0
        return min(len(re.findall(r"window\.open|alert\(|confirm\(|popup", str(self.soup), re.I)), 50)

    def _no_of_iframe(self):
        return min(len(self.soup.find_all("iframe")), 50) if self.soup else 0

    def _has_external_form_submit(self):
        if not self.soup:
            return 0
        for form in self.soup.find_all("form"):
            action = form.get("action", "")
            if action and self.domain not in action and action.startswith("http"):
                return 1
        return 0

    def _has_social_net(self):
        if not self.soup:
            return 0
        social = ["facebook.com", "twitter.com", "instagram.com", "linkedin.com",
                  "youtube.com", "t.co", "x.com"]
        html = str(self.soup).lower()
        return 1 if any(s in html for s in social) else 0

    def _has_submit_button(self):
        if not self.soup:
            return 0
        return 1 if (self.soup.find("input", type="submit") or
                     self.soup.find("button", type="submit")) else 0

    def _has_hidden_fields(self):
        return 1 if (self.soup and self.soup.find("input", type="hidden")) else 0

    def _has_password_field(self):
        return 1 if (self.soup and self.soup.find("input", type="password")) else 0

    def _bank(self):
        return 1 if any(w in self.url.lower() for w in ["bank", "banking", "finance", "financial"]) else 0

    def _pay(self):
        return 1 if any(w in self.url.lower() for w in ["pay", "payment", "checkout", "invoice"]) else 0

    def _crypto(self):
        return 1 if any(w in self.url.lower() for w in ["crypto", "bitcoin", "btc", "wallet", "ethereum"]) else 0

    def _has_copyright(self):
        if not self.soup:
            return 0
        html = str(self.soup).lower()
        return 1 if ("©" in html or "copyright" in html or "&copy;" in html) else 0

    def _no_of_image(self):
        return min(len(self.soup.find_all("img")), 1000) if self.soup else 0

    def _no_of_css(self):
        if not self.soup:
            return 0
        return min(len(self.soup.find_all("link", rel=lambda r: r and "stylesheet" in " ".join(r).lower())), 200)

    def _no_of_js(self):
        return min(len(self.soup.find_all("script")), 300) if self.soup else 0

    def _no_of_self_ref(self):
        if not self.soup:
            return 0
        return min(sum(
            1 for a in self.soup.find_all("a", href=True)
            if self.domain in a["href"] or a["href"].startswith("/")
        ), 1000)

    def _no_of_empty_ref(self):
        if not self.soup:
            return 0
        return min(sum(
            1 for a in self.soup.find_all("a", href=True)
            if not a["href"] or a["href"] in ["#", "javascript:void(0)", "javascript:;"]
        ), 500)

    def _no_of_external_ref(self):
        if not self.soup:
            return 0
        return min(sum(
            1 for a in self.soup.find_all("a", href=True)
            if a["href"].startswith("http") and self.domain not in a["href"]
        ), 1000)

    def extract(self):
        import math

        # Raw feature values
        url_len      = self._url_length()
        dom_len      = self._domain_length()
        is_ip        = self._is_domain_ip()
        url_sim      = self._url_similarity_index()
        char_cont    = self._char_continuation_rate()
        tld_legit    = self._tld_legit_prob()
        url_char     = self._url_char_prob()
        tld_len      = self._tld_length()
        n_sub        = self._no_of_subdomain()
        has_obf      = self._has_obfuscation()
        n_obf        = self._no_of_obfuscated_chars()
        obf_ratio    = self._obfuscation_ratio()
        letter_ratio = self._letter_ratio()
        n_digits     = self._no_of_digits()
        digit_ratio  = self._digit_ratio()
        n_equals     = self._no_of_equals()
        n_qmark      = self._no_of_qmark()
        n_amp        = self._no_of_ampersand()
        n_other_sp   = self._no_of_other_special()
        sp_ratio     = self._special_char_ratio()
        is_https     = self._is_https()
        loc          = self._line_of_code()
        largest_line = self._largest_line_length()
        h_title      = self._has_title()
        dom_title    = self._domain_title_match_score()
        url_title    = self._url_title_match_score()
        h_favicon    = self._has_favicon()
        robots_val   = self._robots()
        is_resp      = self._is_responsive()
        n_redirect   = self._no_of_url_redirect()
        n_self_redir = self._no_of_self_redirect()
        h_desc       = self._has_description()
        n_popup      = self._no_of_popup()
        n_iframe     = self._no_of_iframe()
        h_ext_form   = self._has_external_form_submit()
        h_social     = self._has_social_net()
        h_submit     = self._has_submit_button()
        h_hidden     = self._has_hidden_fields()
        h_password   = self._has_password_field()
        bank         = self._bank()
        pay          = self._pay()
        crypto       = self._crypto()
        h_copyright  = self._has_copyright()
        n_img        = self._no_of_image()
        n_css        = self._no_of_css()
        n_js         = self._no_of_js()
        n_self_ref   = self._no_of_self_ref()
        n_empty_ref  = self._no_of_empty_ref()
        n_ext_ref    = self._no_of_external_ref()

        # Engineered interaction features (match notebook cell 6)
        obf_ip_risk    = is_ip * has_obf
        insecure_pwd   = (1 - is_https) * h_password
        page_complete  = n_self_ref / (n_ext_ref + 1)
        legit_score    = h_title + h_favicon + h_desc + h_copyright + is_resp
        sus_fin        = (bank + pay + crypto) * (1 - h_copyright)
        # TitleMatchCombined uses geometric mean of both title match scores
        title_combined = float(np.sqrt(dom_title * url_title))

        # Log-transformed features (match notebook cell 7)
        features = {
            "URLLength":                    url_len,
            "DomainLength":                 dom_len,
            "IsDomainIP":                   is_ip,
            "URLSimilarityIndex":           url_sim,
            "CharContinuationRate":         char_cont,
            "TLDLegitimateProb":            tld_legit,
            "URLCharProb":                  url_char,
            "TLDLength":                    tld_len,
            "NoOfSubDomain":                n_sub,
            "HasObfuscation":               has_obf,
            "NoOfObfuscatedChar":           n_obf,
            "ObfuscationRatio":             obf_ratio,
            "LetterRatioInURL":             letter_ratio,
            "NoOfDegitsInURL":              n_digits,
            "DegitRatioInURL":              digit_ratio,
            "NoOfEqualsInURL":              n_equals,
            "NoOfQMarkInURL":               n_qmark,
            "NoOfAmpersandInURL":           n_amp,
            "NoOfOtherSpecialCharsInURL":   n_other_sp,
            "SpacialCharRatioInURL":        sp_ratio,
            "IsHTTPS":                      is_https,
            "LineOfCode":                   loc,
            "LargestLineLength":            largest_line,
            "HasTitle":                     h_title,
            "DomainTitleMatchScore":        dom_title,
            "URLTitleMatchScore":           url_title,
            "HasFavicon":                   h_favicon,
            "Robots":                       robots_val,
            "IsResponsive":                 is_resp,
            "NoOfURLRedirect":              n_redirect,
            "NoOfSelfRedirect":             n_self_redir,
            "HasDescription":               h_desc,
            "NoOfPopup":                    n_popup,
            "NoOfiFrame":                   n_iframe,
            "HasExternalFormSubmit":        h_ext_form,
            "HasSocialNet":                 h_social,
            "HasSubmitButton":              h_submit,
            "HasHiddenFields":              h_hidden,
            "HasPasswordField":             h_password,
            "Bank":                         bank,
            "Pay":                          pay,
            "Crypto":                       crypto,
            "HasCopyrightInfo":             h_copyright,
            "NoOfImage":                    n_img,
            "NoOfCSS":                      n_css,
            "NoOfJS":                       n_js,
            "NoOfSelfRef":                  n_self_ref,
            "NoOfEmptyRef":                 n_empty_ref,
            "NoOfExternalRef":              n_ext_ref,
            # Interaction features
            "ObfuscationIPRisk":            obf_ip_risk,
            "InsecurePasswordField":        insecure_pwd,
            "PageCompletenessRatio":        page_complete,
            "LegitContentScore":            legit_score,
            "SuspiciousFinancialFlag":      sus_fin,
            "TitleMatchCombined":           title_combined,
            # Log features
            "LineOfCode_log":               math.log1p(loc),
            "LargestLineLength_log":        math.log1p(largest_line),
            "NoOfExternalRef_log":          math.log1p(n_ext_ref),
            "NoOfSelfRef_log":              math.log1p(n_self_ref),
            "NoOfCSS_log":                  math.log1p(n_css),
            "NoOfJS_log":                   math.log1p(n_js),
            "NoOfImage_log":                math.log1p(n_img),
            "NoOfEmptyRef_log":             math.log1p(n_empty_ref),
            "URLLength_log":                math.log1p(url_len),
            "DomainLength_log":             math.log1p(dom_len),
            "NoOfPopup_log":                math.log1p(n_popup),
            "NoOfURLRedirect_log":          math.log1p(n_redirect),
            "NoOfiFrame_log":               math.log1p(n_iframe),
        }

        vector = np.array([features.get(f, 0) for f in FEATURE_NAMES])
        return vector.reshape(1, -1), features

# -------------------- UCI FEATURE EXTRACTOR --------------------
class UCIFeatureExtractor:
    """
    Extracts the 9 categorical UCI WebsitePhishing features (-1/0/1)
    plus 7 engineered interaction features = 16 total, matching
    PhishNet_WebsitePhishing_Analysis.ipynb.
    """
    UCI_FEATURE_COLS = [
        'SFH', 'popUpWidnow', 'SSLfinal_State', 'Request_URL',
        'URL_of_Anchor', 'web_traffic', 'URL_Length', 'age_of_domain',
        'having_IP_Address'
    ]

    def __init__(self, url):
        self.url = url.strip()
        self.parsed = urlparse(self.url)
        # Strip port and www from netloc for feature extraction
        self.domain = self.parsed.netloc.split(':')[0].replace("www.", "").lower().strip()
        # WHOIS must query the registrable domain (e.g. abc.com, not mail.abc.com or abc.com:8080)
        _ext = tldextract.extract(self.url)
        _whois_domain = (
            f"{_ext.domain}.{_ext.suffix}"
            if _ext.domain and _ext.suffix
            else self.domain
        )
        self.whois_response = safe_whois(_whois_domain)
        self.page_html = ""
        self.soup = None
        self._fetch_page()

    def _fetch_page(self):
        from hardened_fetcher import fetcher
        try:
            # Use the production-grade hardened fetcher
            self.page_html = fetcher.fetch(self.url) or ""
            if self.page_html:
                self.soup = BeautifulSoup(self.page_html, "html.parser")
            else:
                self.soup = None
        except Exception as e:
            logger.error(f"UCI Fetch failed: {e}")
            self.page_html = ""
            self.soup = None

    def get_campaign_signature(self):
        """Extract markers for campaign correlation"""
        import hashlib
        import socket
        
        # 1. HTML similarity hash (content-based)
        html_hash = ""
        if self.page_html:
            normalized = re.sub(r'\s+', ' ', self.page_html)
            html_hash = hashlib.md5(normalized[:10000].encode()).hexdigest()
            
        # 2. Server IP (infrastructure-based)
        server_ip = ""
        try:
            server_ip = socket.gethostbyname(self.domain)
        except:
            pass
            
        return {
            "html_hash": html_hash,
            "server_ip": server_ip,
            "domain_name": self.domain
        }

    def _has_ip(self):
        try:
            ipaddress.ip_address(self.domain)
            return True
        except Exception:
            return False

    def _having_ip_address(self):
        """1 = IP-based domain (phishing signal), 0 = domain name"""
        return 1 if self._has_ip() else 0

    def _ssl_final_state(self):
        """1 = HTTPS (legit), -1 = HTTP (phishing)"""
        return 1 if self.parsed.scheme == 'https' else -1

    def _url_length(self):
        """1 = short (<54 chars), 0 = medium (54-75), -1 = long (>75)"""
        n = len(self.url)
        if n < 54:
            return 1
        elif n <= 75:
            return 0
        return -1

    def _age_of_domain(self):
        """1 = domain >= 180 days old (legit), 0 = WHOIS unavailable/unknown, -1 = new domain (< 180 days)"""
        base = '.'.join(self.domain.split('.')[-2:])
        if base in TRUSTED_DOMAINS:
            return 1
        try:
            if not self.whois_response:
                return 0
            cd = self.whois_response.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            if cd:
                return 1 if (datetime.now() - cd).days >= 180 else -1
            return 0
        except Exception:
            return 0

    def _get_domain_age_days(self):
        """Returns domain age in days (int) or None if WHOIS unavailable."""
        try:
            if not self.whois_response:
                return None
            cd = self.whois_response.creation_date
            if isinstance(cd, list):
                cd = cd[0]
            if cd:
                return max(0, (datetime.now() - cd).days)
            return None
        except Exception:
            return None

    def _get_recent_content(self):
        """Detect recently published content via OG tags, <time> elements, JSON-LD.
        Returns (date_str, True) or (None, False)."""
        if not self.soup:
            return None, False
        # OG article:published_time
        og_time = self.soup.find("meta", property="article:published_time")
        if og_time and og_time.get("content"):
            return og_time["content"][:50], True
        # <time datetime="...">
        for time_el in self.soup.find_all("time", datetime=True):
            dt_val = time_el.get("datetime", "").strip()
            if dt_val:
                return dt_val[:50], True
        # JSON-LD datePublished
        for script in self.soup.find_all("script", type="application/ld+json"):
            text = script.get_text()
            if "datePublished" in text:
                m = re.search(r'"datePublished"\s*:\s*"([^"]+)"', text)
                if m:
                    return m.group(1)[:50], True
        return None, False

    def _get_subdomain_info(self):
        """Extract subdomain info using tldextract."""
        ext = tldextract.extract(self.url)
        subdomain = ext.subdomain or ''
        parts = [s for s in subdomain.split('.') if s] if subdomain else []
        return {
            'subdomain':    subdomain,
            'domain_name':  ext.domain or '',
            'tld':          ext.suffix or '',
            'subdomain_count': len(parts)
        }

    def _enumerate_subdomains(self):
        """
        Discover all known subdomains of the base domain via:
          1. Certificate Transparency logs (crt.sh) — finds subdomains with SSL certs
          2. DNS brute-force of 40 common subdomain names

        Returns a dict with 'found' list, 'count', 'base_domain', 'sources'.
        Total runtime is capped at ~10 s.
        """
        ext = tldextract.extract(self.url)
        if not ext.domain or not ext.suffix:
            return {'found': [], 'count': 0, 'base_domain': '', 'sources': []}

        base_domain = f"{ext.domain}.{ext.suffix}"
        discovered = set()
        sources = []

        # ── 1. Certificate Transparency via crt.sh ────────────────────
        try:
            ct_resp = requests.get(
                f"https://crt.sh/?q=%.{base_domain}&output=json",
                timeout=6,
                headers={"User-Agent": "Mozilla/5.0 PhishNet/1.0"}
            )
            if ct_resp.status_code == 200:
                for cert in ct_resp.json():
                    for name in cert.get('name_value', '').split('\n'):
                        name = name.strip().lower().lstrip('*.')
                        if name.endswith(f'.{base_domain}') and name != base_domain:
                            sub = name[:-len(f'.{base_domain}')]
                            if sub and '.' not in sub:   # only single-level subdomains
                                discovered.add(sub)
                if discovered:
                    sources.append('crt.sh')
                    logger.info(f"crt.sh found {len(discovered)} subdomains for {base_domain}")
        except Exception as e:
            logger.warning(f"crt.sh lookup failed for {base_domain}: {e}")

        # ── 2. DNS brute-force for common subdomain names ─────────────
        COMMON_SUBS = [
            'www', 'mail', 'webmail', 'smtp', 'pop', 'pop3', 'imap',
            'ftp', 'sftp', 'api', 'api2', 'v1', 'v2', 'v3',
            'admin', 'administrator', 'panel', 'cpanel', 'whm', 'dashboard',
            'login', 'secure', 'auth', 'sso', 'app', 'apps', 'mobile', 'm',
            'blog', 'shop', 'store', 'checkout', 'pay', 'payment',
            'dev', 'staging', 'stg', 'test', 'qa', 'sandbox',
            'cdn', 'static', 'assets', 'images', 'img', 'media',
            'vpn', 'remote', 'support', 'help', 'docs', 'portal',
            'ns1', 'ns2', 'mx', 'mx1', 'mx2',
        ]

        def _dns_resolve(sub):
            try:
                socket.getaddrinfo(f"{sub}.{base_domain}", None)
                return sub
            except Exception:
                return None

        dns_new = []
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=25)
        try:
            futures = {executor.submit(_dns_resolve, s): s for s in COMMON_SUBS}
            for future in concurrent.futures.as_completed(futures, timeout=8):
                result = future.result()
                if result:
                    dns_new.append(result)
                    discovered.add(result)
        except concurrent.futures.TimeoutError:
            pass
        finally:
            executor.shutdown(wait=False)

        if dns_new:
            sources.append('DNS')
            logger.info(f"DNS brute-force found {len(dns_new)} subdomains for {base_domain}")

        sorted_subs = sorted(discovered)[:60]
        return {
            'found':       sorted_subs,
            'count':       len(sorted_subs),
            'base_domain': base_domain,
            'sources':     sources,
        }

    def _sfh(self):
        """
        Server Form Handler:
        1 = same-domain/relative form action (legit)
        0 = no forms or empty action
        -1 = external domain form action (phishing)
        """
        if not self.soup:
            return 0
        for form in self.soup.find_all("form"):
            action = form.get("action", "").strip()
            if not action:
                continue
            if action.startswith("http") and self.domain not in action:
                return -1
            if action.startswith("/") or self.domain in action:
                return 1
        return 0

    def _popup_widnow(self):
        """
        1 = popup/window.open detected (phishing signal)
        -1 = no popups (legit signal)
        Note: 'widnow' matches the intentional typo in the UCI dataset.
        """
        if not self.soup:
            return -1
        popups = re.findall(r"window\.open|alert\(|confirm\(|popup", str(self.soup), re.I)
        return 1 if popups else -1

    def _request_url(self):
        """
        Ratio of external resources (img, script, stylesheet link):
        1 = < 22% external (legit), 0 = 22-61% (suspicious), -1 = > 61% external (phishing)
        """
        if not self.soup:
            return 0
        total = 0
        external = 0
        for tag in self.soup.find_all(["img", "script"]):
            src = tag.get("src", "")
            if src:
                total += 1
                if src.startswith("http") and self.domain not in src:
                    external += 1
        for tag in self.soup.find_all("link", rel=lambda r: r and "stylesheet" in " ".join(r).lower()):
            href = tag.get("href", "")
            if href:
                total += 1
                if href.startswith("http") and self.domain not in href:
                    external += 1
        if total == 0:
            return 0
        ratio = external / total
        if ratio < 0.22:
            return 1
        elif ratio < 0.61:
            return 0
        return -1

    def _url_of_anchor(self):
        """
        Ratio of external anchor links:
        1 = < 31% external (legit), 0 = 31-67% (suspicious), -1 = > 67% external (phishing)
        """
        if not self.soup:
            return 0
        total = 0
        external = 0
        for a in self.soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href in ["#", "javascript:void(0)", "javascript:;"]:
                continue
            total += 1
            if href.startswith("http") and self.domain not in href:
                external += 1
        if total == 0:
            return 1  # No anchors = not suspicious
        ratio = external / total
        if ratio < 0.31:
            return 1
        elif ratio < 0.67:
            return 0
        return -1

    def _web_traffic(self):
        """
        Proxy for Alexa traffic rank (no API available):
        1 = trusted/known domain (high traffic)
        0 = page has title or favicon (some presence)
        -1 = no title, no favicon (low/unknown traffic)
        """
        base = '.'.join(self.domain.split('.')[-2:])
        if base in TRUSTED_DOMAINS:
            return 1
        if self.soup:
            has_title   = bool(self.soup.find("title") and self.soup.find("title").get_text(strip=True))
            has_favicon = bool(self.soup.find_all("link", rel=lambda r: r and "icon" in " ".join(r).lower()))
            if has_title or has_favicon:
                return 0
        return -1

    def extract(self):
        # Raw UCI categorical features
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

        # Engineered interaction features (matching notebook Feature Engineering cell)
        phish_count = sum(1 for f in self.UCI_FEATURE_COLS if raw[f] == -1)
        legit_count = sum(1 for f in self.UCI_FEATURE_COLS if raw[f] == 1)
        net_score   = sum(raw[f] for f in self.UCI_FEATURE_COLS)

        features = {
            **raw,
            'PhishingSignalCount': phish_count,
            'LegitSignalCount':    legit_count,
            'NetScore':            net_score,
            'PhishingSignalRatio': phish_count / len(self.UCI_FEATURE_COLS),
            'NoSSL_HasIP':         int(raw['SSLfinal_State'] == -1 and raw['having_IP_Address'] == 1),
            'BadSFH_BadSSL':       int(raw['SFH'] == -1 and raw['SSLfinal_State'] == -1),
            'YoungDomain_NoSSL':   int(raw['age_of_domain'] == -1 and raw['SSLfinal_State'] == -1),
        }

        # Metadata for display (prefixed _ so they're never passed to the ML vector)
        age_days = self._get_domain_age_days()
        recent_date, is_active = self._get_recent_content()
        sub_info = self._get_subdomain_info()
        sub_enum = self._enumerate_subdomains()
        features['_domain_age_days']     = age_days
        features['_recent_content_date'] = recent_date
        features['_is_recently_active']  = is_active
        features['_subdomain']           = sub_info['subdomain']
        features['_domain_name']         = sub_info['domain_name']
        features['_tld']                 = sub_info['tld']
        features['_subdomain_count']     = sub_info['subdomain_count']
        features['_url_raw_length']      = len(self.url)
        features['_subdomain_enum']      = sub_enum

        vector = np.array([features.get(f, 0) for f in FEATURE_NAMES])
        return vector.reshape(1, -1), features

# -------------------- RISK CALCULATION --------------------
def is_trusted_domain(domain):
    """Check if domain is in trusted whitelist"""
    # Extract base domain (e.g., google.com from mail.google.com)
    base_domain = '.'.join(domain.split('.')[-2:])
    return base_domain in TRUSTED_DOMAINS

def calculate_phishing_score(features, model_probabilities):
    """
    Calculate final phishing score using new feature names from phishurl.csv.
    Verdict is based on ML probability + heuristic boosts.
    Trusted domain status is a weak negative signal only — it does NOT override ML.
    """
    base_score = float(np.mean(list(model_probabilities.values())))

    boost = 0.0
    reasons = []

    # Trusted domain: weak legitimacy signal (reduces probability slightly)
    domain = features.get("_domain", "")
    if is_trusted_domain(domain):
        boost -= 0.10
        reasons.append("Domain is in trusted whitelist (legitimacy signal)")
        logger.info(f"Trusted domain signal applied (not overriding ML): {domain}")

    # IP-based domain is a strong phishing signal
    if features.get("IsDomainIP", 0) == 1:
        boost += 0.35
        reasons.append("IP address used instead of domain name")

    # Obfuscation in URL
    if features.get("HasObfuscation", 0) == 1:
        boost += 0.20
        reasons.append(f"URL obfuscation detected ({features.get('NoOfObfuscatedChar', 0)} chars)")

    # No HTTPS + password field = credential theft
    if features.get("InsecurePasswordField", 0) == 1:
        boost += 0.30
        reasons.append("Password field on non-HTTPS page")

    # No HTTPS at all
    if features.get("IsHTTPS", 0) == 0:
        boost += 0.10
        reasons.append("No HTTPS encryption")

    # Long domain (obfuscation attempt)
    dom_len = features.get("DomainLength", 0)
    if dom_len > 40:
        boost += 0.20
        reasons.append(f"Very long domain ({dom_len} chars)")
    elif dom_len > 30:
        boost += 0.10
        reasons.append(f"Long domain ({dom_len} chars)")

    # Financial keywords with no copyright (phishing finance pages)
    if features.get("SuspiciousFinancialFlag", 0) > 0:
        boost += 0.15
        reasons.append("Financial keywords without legitimacy markers")

    # External form submission (data harvesting)
    if features.get("HasExternalFormSubmit", 0) == 1:
        boost += 0.20
        reasons.append("Form submits to external domain")

    # Very low legitimacy score (missing title, favicon, description, copyright)
    legit = features.get("LegitContentScore", 0)
    if legit == 0:
        boost += 0.15
        reasons.append("No legitimacy markers (title/favicon/description/copyright)")
    elif legit == 1:
        boost += 0.08
        reasons.append("Very few legitimacy markers")

    # Crypto keywords (common in phishing)
    if features.get("Crypto", 0) == 1:
        boost += 0.10
        reasons.append("Cryptocurrency keywords detected")

    final_score = max(0.01, min(base_score + boost, 0.99))
    return final_score, boost, reasons, base_score

def calculate_phishing_score_uci(features, model_probabilities):
    """
    Calculate final phishing score for the UCI 16-feature model.
    Uses categorical UCI feature values (-1/0/1) plus engineered signals.
    Verdict is based on ML probability + heuristic boosts.
    Trusted domain status is a weak negative signal only — it does NOT override ML.
    """
    base_score = float(np.mean(list(model_probabilities.values())))

    boost = 0.0
    reasons = []

    # Trusted domain: strong legitimacy signal
    # UCI model is trained on old HTML pages and cannot analyse modern SPAs/auth-protected sites.
    # Trusted status is an explicit human override that deserves real weight.
    domain = features.get("_domain", "")
    if is_trusted_domain(domain):
        boost -= 0.30
        reasons.append("Domain is in trusted whitelist (strong legitimacy signal)")
        logger.info(f"Trusted domain boost -0.30 applied: {domain}")

    # NetScore signal: reflects how many of the 9 UCI features vote legitimate vs phishing
    # Positive = more legit signals, Negative = more phishing signals
    net_score   = features.get("NetScore", 0)
    legit_count = features.get("LegitSignalCount", 0)

    if net_score >= 3:
        boost -= 0.15
        reasons.append(f"Strong legitimate feature profile (NetScore: {net_score})")
    elif net_score >= 1:
        boost -= 0.08
        reasons.append(f"Moderate legitimate feature profile (NetScore: {net_score})")
    elif net_score <= -3:
        boost += 0.15
        reasons.append(f"Strong phishing feature profile (NetScore: {net_score})")
    elif net_score <= -1:
        boost += 0.08
        reasons.append(f"Moderate phishing feature profile (NetScore: {net_score})")

    # High legitimate indicator count from UCI features
    if legit_count >= 4:
        boost -= 0.10
        reasons.append(f"Multiple legitimate indicators ({legit_count}/9 UCI features)")

    # IP-based domain is a strong phishing signal
    if features.get("having_IP_Address", 0) == 1:
        boost += 0.35
        reasons.append("IP address used instead of domain name")

    # No HTTPS
    if features.get("SSLfinal_State", 1) == -1:
        boost += 0.15
        reasons.append("No HTTPS encryption")

    # External form submission (credential harvesting)
    if features.get("SFH", 0) == -1:
        boost += 0.20
        reasons.append("Form submits to external domain")

    # Young/unknown domain age
    if features.get("age_of_domain", 1) == -1:
        boost += 0.10
        reasons.append("New or unknown domain age")

    # Popup windows
    if features.get("popUpWidnow", -1) == 1:
        boost += 0.05
        reasons.append("Popup windows detected")

    # Critical combination: IP + no SSL
    if features.get("NoSSL_HasIP", 0) == 1:
        boost += 0.20
        reasons.append("IP address without HTTPS (high-risk combination)")

    # Critical combination: external form + no SSL
    if features.get("BadSFH_BadSSL", 0) == 1:
        boost += 0.15
        reasons.append("External form submission + no HTTPS (credential theft risk)")

    # Multiple phishing signals
    phish_count = features.get("PhishingSignalCount", 0)
    if phish_count >= 5:
        boost += 0.20
        reasons.append(f"Many phishing signals detected ({phish_count}/9 features)")
    elif phish_count >= 3:
        boost += 0.10
        reasons.append(f"Multiple phishing signals detected ({phish_count}/9 features)")

    # No detectable web traffic
    if features.get("web_traffic", 0) == -1:
        boost += 0.08
        reasons.append("No detectable web traffic (obscure/new site)")

    # Most resources from external domains
    if features.get("Request_URL", 0) == -1:
        boost += 0.08
        reasons.append("Most page resources loaded from external domains")

    # Most anchor links are external
    if features.get("URL_of_Anchor", 0) == -1:
        boost += 0.05
        reasons.append("Most anchor links point to external domains")

    final_score = max(0.01, min(base_score + boost, 0.99))
    return final_score, boost, reasons, base_score

def compute_shap_explanation(X_input, feature_names):
    """
    Average SHAP values across all tree-based models, return top 10 by |shap_value|.
    Returns None if no SHAP explainer is available or all fail.
    Class encoding: 1 = phishing → positive SHAP = pushes toward phishing.
    """
    shap_arrays = []
    for name, explainer in SHAP_EXPLAINERS.items():
        try:
            sv = explainer.shap_values(X_input)
            # RF and CatBoost return list [class0_shap, class1_shap]; LGB/XGB return single array
            if isinstance(sv, list) and len(sv) == 2:
                sv_phishing = np.array(sv[1]).flatten()
            else:
                sv_phishing = np.array(sv).flatten()
            if len(sv_phishing) == len(feature_names):
                shap_arrays.append(sv_phishing)
        except Exception as e:
            logger.warning(f"SHAP computation failed for {name}: {e}")

    if not shap_arrays:
        return None

    avg_shap = np.mean(shap_arrays, axis=0)

    items = [
        {
            'feature':     feature_names[i],
            'shap_value':  float(avg_shap[i]),
            'direction':   'phishing' if avg_shap[i] > 0 else 'legitimate',
            'abs_value':   float(abs(avg_shap[i]))
        }
        for i in range(len(feature_names))
    ]
    items.sort(key=lambda x: x['abs_value'], reverse=True)
    top = items[:10]
    for item in top:
        del item['abs_value']

    return {
        'top_features':    top,
        'total_features':  len(feature_names),
        'models_averaged': len(shap_arrays)
    }


def convert_to_serializable(obj):
    """Convert numpy types to JSON-serializable"""
    if isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, (np.bool_, bool)):
        return bool(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, dict):
        return {k: convert_to_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [convert_to_serializable(item) for item in obj]
    return obj

# -------------------- ANALYSIS LOGIC --------------------
def analyze_url_logic(url):
    """Enhanced analysis with whitelist and better heuristics"""
    try:
        url = url.strip()
        if not url:
            return {"error": "URL required"}, 400

        # Reject non-http/https schemes (javascript:, file://, ftp://, etc.)
        scheme = urlparse(url).scheme.lower()
        if scheme and scheme not in ('http', 'https'):
            return {"error": f"Unsupported scheme '{scheme}'. Only http/https URLs are accepted."}, 400
        if not scheme:
            url = "https://" + url

        # Guard against excessively long URLs (DoS protection)
        if len(url) > 2000:
            return {"error": "URL too long (max 2000 characters)"}, 400

        logger.info(f"🔍 Analyzing: {url}")

        # LAYER 1: Rule-Based Detection (always runs — result feeds into hybrid fusion)
        rule_result = rule_engine.evaluate(url)

        if rule_result['is_phishing']:
            logger.info(f"⚠️  Rule engine: PHISHING signals ({rule_result['confidence']:.0%}) — continuing to ML for full verdict")
        else:
            logger.info(f"✅ Rule engine: no phishing signals — continuing to ML")

        # LAYER 2: ML Ensemble Detection (always runs — verdict = ML + rule fusion)
        if MODEL_TYPE == 'uci':
            extractor = UCIFeatureExtractor(url)
        else:
            extractor = FeatureExtractor(url)
        X_raw, features = extractor.extract()

        # Add domain for trusted-domain check (not part of ML features)
        features["_domain"] = extractor.domain

        # UCI features are categorical — no scaling needed
        X_for_prediction = X_raw if MODEL_TYPE == 'uci' else SCALER.transform(X_raw)
        
        # Get model predictions
        predictions = {}
        probabilities = {}
        
        for name, model in MODELS.items():
            try:
                pred = model.predict(X_for_prediction)[0]
                if pred == -1:
                    pred = 0
                predictions[name] = int(pred)

                if hasattr(model, 'predict_proba'):
                    prob = model.predict_proba(X_for_prediction)[0]
                    probabilities[name] = float(prob[1] if len(prob) > 1 else prob[0])
                else:
                    probabilities[name] = float(pred)
            except Exception as e:
                logger.error(f"Error with {name}: {e}")
        
        # All models failed — cannot produce a reliable verdict
        if not probabilities:
            logger.error("All ML models failed to produce predictions — aborting analysis")
            return {"error": "All ML models failed. Please try again."}, 500

        # Calculate final score with intelligent rules
        if MODEL_TYPE == 'uci':
            final_prob, boost, reasons, base_prob = calculate_phishing_score_uci(features, probabilities)
        else:
            final_prob, boost, reasons, base_prob = calculate_phishing_score(features, probabilities)

        if boost > 0:
            logger.info(f"📈 Risk boosted: {base_prob:.2%} → {final_prob:.2%}")
            for reason in reasons:
                logger.info(f"   {reason}")

        # LAYER 3: Hybrid Rule-ML Fusion
        # ML is blind to new/non-existent domains (all HTML features = 0).
        # When the rule engine has detected real signals, apply a score floor.
        if rule_result['confidence'] > 0.3:
            has_critical = any(r['severity'] == 'CRITICAL' for r in rule_result['rules'])
            has_high     = any(r['severity'] == 'HIGH'     for r in rule_result['rules'])
            if has_critical:
                # CRITICAL rule fired — trust rule engine heavily.
                # Multiplier 0.95 ensures a 0.55-confidence CRITICAL result (0.55×0.95=0.5225)
                # still crosses the 0.5 decision threshold.
                rule_floor = rule_result['confidence'] * 0.95
                if final_prob < rule_floor:
                    final_prob = rule_floor
                    boost = final_prob - base_prob
                    reasons.append(f"Rule engine override (CRITICAL signals, {rule_result['confidence']:.0%} confidence)")
                    logger.info(f"🚨 Hybrid override: ML={base_prob:.2%} → Rule floor={rule_floor:.2%}")
            elif has_high and rule_result['confidence'] > 0.45:
                # HIGH rule with moderate confidence — apply lighter floor
                rule_floor = rule_result['confidence'] * 0.70
                if final_prob < rule_floor:
                    final_prob = rule_floor
                    boost = final_prob - base_prob
                    reasons.append(f"Rule engine override (HIGH signals, {rule_result['confidence']:.0%} confidence)")
        # 🛡️ ADVERSARIAL TELEMETRY
        # Evaluate Certified Robustness & Generate Semantic Embedding
        robustness_data = adversarial_engine.evaluate_robustness(X_for_prediction, final_prob, THRESHOLD)
        semantic_embedding = adversarial_engine.get_learned_embedding(X_for_prediction)

        # Determine risk level
        if final_prob > 0.85:
            risk_level = "Critical"
            risk_emoji = "🔴"
            risk_color = "red"
        elif final_prob > 0.65:
            risk_level = "High"
            risk_emoji = "🟠"
            risk_color = "orange"
        elif final_prob > 0.45:
            risk_level = "Medium"
            risk_emoji = "🟡"
            risk_color = "yellow"
        elif final_prob > 0.20:
            risk_level = "Low"
            risk_emoji = "🟢"
            risk_color = "lightgreen"
        else:
            risk_level = "Safe"
            risk_emoji = "✅"
            risk_color = "green"

        # Calculate consensus for 4-model ensemble voting
        final_prediction = 1 if final_prob >= THRESHOLD else 0
        phishing_votes = sum(1 for pred in predictions.values() if pred == 1)
        legitimate_votes = sum(1 for pred in predictions.values() if pred == 0)
        total_models = len(predictions)

        # Determine consensus confidence level
        if max(phishing_votes, legitimate_votes) >= 3:
            consensus_confidence = "High"  # 3+/4 models agree
        elif max(phishing_votes, legitimate_votes) == 2:
            consensus_confidence = "Medium"  # 2/4 models agree (split)
        else:
            consensus_confidence = "Low"  # No clear agreement

        consensus_text = f"{phishing_votes} Phishing | {legitimate_votes} Legitimate"

        logger.info(f"🗳️ Ensemble Voting: {consensus_text} (Confidence: {consensus_confidence})")

        # Determine detection_source for the frontend
        rule_contributed = rule_result['is_phishing'] and rule_result['confidence'] > 0.3
        if rule_contributed and boost > 0:
            detection_source = "rule_engine_ml"   # Both rule engine and ML flagged it
        else:
            detection_source = "ml_ensemble"       # ML verdict (rules may have run but didn't contribute)

        # Compute SHAP explanation (best-effort — non-fatal if it fails)
        shap_explanation = None
        if SHAP_EXPLAINERS:
            try:
                shap_explanation = compute_shap_explanation(X_for_prediction, FEATURE_NAMES)
            except Exception as _shap_err:
                logger.warning(f"SHAP explanation skipped: {_shap_err}")

        # Build url_analysis display metadata (UCI extractor only)
        url_analysis = None
        if MODEL_TYPE == 'uci':
            _age_days    = features.pop('_domain_age_days', None)
            _recent_date = features.pop('_recent_content_date', None)
            _is_active   = features.pop('_is_recently_active', False)
            _subdomain   = features.pop('_subdomain', '')
            _domain_name = features.pop('_domain_name', '')
            _tld         = features.pop('_tld', '')
            _sub_count   = features.pop('_subdomain_count', 0)
            _url_len     = features.pop('_url_raw_length', len(url))
            _sub_enum    = features.pop('_subdomain_enum', {'found': [], 'count': 0, 'base_domain': '', 'sources': []})

            def _human_age(days):
                if days is None:
                    return "Unknown (WHOIS unavailable)"
                if days < 30:
                    return f"{days} day(s)"
                if days < 365:
                    return f"{days // 30} month(s)"
                yrs = days // 365
                mos = (days % 365) // 30
                return f"{yrs} yr{'s' if yrs != 1 else ''}{(', ' + str(mos) + ' mo') if mos > 0 else ''}"

            url_analysis = {
                'domain_age_days':     _age_days,
                'domain_age_human':    _human_age(_age_days),
                'subdomain':           _subdomain or None,
                'subdomain_count':     _sub_count,
                'domain_name':         _domain_name,
                'tld':                 _tld,
                'url_length':          _url_len,
                'is_https':            extractor.parsed.scheme == 'https',
                'has_www':             extractor.url.lower().startswith(('http://www.', 'https://www.')),
                'has_query_params':    bool(extractor.parsed.query),
                'recent_content_date': _recent_date,
                'is_recently_active':  bool(_is_active),
                'subdomain_enum':      _sub_enum,
            }

        # Remove internal domain key
        features.pop('_domain', None)

        response = {
            "url": str(url),
            "domain": str(extractor.domain),
            "prediction": "Phishing" if final_prob >= THRESHOLD else "Legitimate",
            "confidence": float(round(final_prob * 100, 2)),
            "probability": float(round(final_prob, 4)),
            "base_probability": float(round(base_prob, 4)),
            "risk_boost": float(round(boost, 4)),
            "boost_reasons": reasons,
            "safe_to_visit": bool(final_prob < THRESHOLD),
            "is_trusted": is_trusted_domain(extractor.domain),
            "detection_source": detection_source,
            "risk_level": str(risk_level),
            "risk_emoji": str(risk_emoji),
            "risk_color": str(risk_color),
            "threshold_used": float(THRESHOLD),
            "ensemble": {
                "base_probability": float(round(base_prob, 4)),
                "individual_predictions": convert_to_serializable(predictions),
                "individual_probabilities": convert_to_serializable({k: round(v, 4) for k, v in probabilities.items()}),
                "agreement": f"{int(sum(predictions.values()))}/{len(predictions)}",
                "voting": {
                    "phishing_votes": int(phishing_votes),
                    "legitimate_votes": int(legitimate_votes),
                    "total_models": int(total_models),
                    "consensus_text": str(consensus_text),
                    "consensus_confidence": str(consensus_confidence)
                }
            },
            "rule_analysis": {
                "is_phishing": rule_result['is_phishing'],
                "confidence": float(round(rule_result['confidence'], 4)),
                "rule_violations": rule_result['rules'],
                "rule_count": rule_result['rule_count'],
                "signals": rule_result['signals']
            },
            "features": convert_to_serializable(features),
            "campaign_signature": {
                **extractor.get_campaign_signature(),
                "semantic_embedding": semantic_embedding
            },
            "adversarial_robustness": robustness_data,
            "shap_explanation": shap_explanation,
            "url_analysis": url_analysis,
            "model_info": {
                "models_used": len(MODELS),
                "model_names": list(MODELS.keys()),
                "detection_method": f"Full Pipeline: Rule Engine (all rules) + {'UCI 16-Feature' if MODEL_TYPE == 'uci' else '4-Model'} ML Ensemble + Score Fusion",
                "rule_engine_enabled": True,
                "rules_checked": 14,
                "f1_score": MODEL_METRICS.get("gradient_boosting", {}).get("f1_score", 0.0),
            },
            "timestamp": str(datetime.now().isoformat())
        }
        
        logger.info(f"✅ {response['prediction']} ({response['confidence']}%)")
        return response, 200
        
    except Exception as e:
        logger.error(f"❌ Error: {str(e)}", exc_info=True)
        return {"error": str(e)}, 500

# -------------------- API ROUTES --------------------

@app.route("/", methods=["GET", "OPTIONS"])
def home():
    if request.method == "OPTIONS":
        return "", 200
    return jsonify({
        "status": "healthy",
        "service": "Phishing Detection API",
        "version": "5.0 - Fixed",
        "models": len(MODELS),
        "trusted_domains": len(TRUSTED_DOMAINS)
    }), 200

@app.route("/analyze", methods=["POST", "OPTIONS"])
@app.route("/analyze_url", methods=["POST", "OPTIONS"])
def analyze():
    if request.method == "OPTIONS":
        return "", 200

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON with a 'url' field"}), 400

    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400

    try:
        result, status = analyze_url_logic(url)
        return jsonify(result), status
    except Exception as e:
        logger.error(f"Unhandled exception in analyze route: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@app.before_request
def handle_preflight():
    if request.method == "OPTIONS":
        response = jsonify({"status": "ok"})
        response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
        response.headers.add("Access-Control-Allow-Headers", "Content-Type")
        response.headers.add("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        return response, 200

# -------------------- RUN --------------------
if __name__ == "__main__":
    logger.info("="*80)
    logger.info("🚀 PHISHING DETECTION API v5.0 - PRODUCTION")
    logger.info(f"✅ Detection: ML + Whitelist + Heuristics")
    logger.info(f"✅ Trusted domains: {len(TRUSTED_DOMAINS)}")
    logger.info("="*80)
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

# # ✅ FIX 1: Use ONLY Flask-CORS, remove manual CORS headers
# CORS(app, origins=["http://localhost:3000"])

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# # -------------------- MODEL LOADING WITH ERROR HANDLING --------------------
# MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
# BUNDLE_PATH = os.path.join(MODEL_DIR, "phishing_model_bundle.pkl")

# # Initialize with safe defaults
# MODELS = {}
# SCALER = None
# FEATURE_NAMES = []
# THRESHOLD = 0.5

# try:
#     if os.path.exists(BUNDLE_PATH):
#         logger.info(f"Loading model bundle from: {BUNDLE_PATH}")
#         with open(BUNDLE_PATH, "rb") as f:
#             bundle = pickle.load(f)
        
#         # Safely extract models (skip if missing)
#         model_names = [
#             "voting_hard", "voting_soft", "stacking", 
#             "gradient_boosting", "xgboost", "catboost",
#             "random_forest", "svm"
#         ]
        
#         for name in model_names:
#             if name in bundle and bundle[name] is not None:
#                 MODELS[name] = bundle[name]
#                 logger.info(f"  ✓ Loaded {name}")
        
#         # Get other components
#         SCALER = bundle.get("scaler")
#         FEATURE_NAMES = bundle.get("feature_names", [])
#         THRESHOLD = bundle.get("threshold", 0.5)
        
#         logger.info(f"✅ Models loaded: {len(MODELS)} | Features: {len(FEATURE_NAMES)}")
#     else:
#         logger.warning(f"⚠️ Model file not found: {BUNDLE_PATH}")
        
# except Exception as e:
#     logger.error(f"❌ Error loading models: {e}")
#     # Continue without models for now

# # -------------------- SIMPLE HELPERS --------------------
# def add_scheme_if_missing(url):
#     """Add https scheme if missing"""
#     url = url.strip()
#     if not urlparse(url).scheme:
#         return "https://" + url
#     return url

# def safe_request(url, timeout=3):
#     """Make HTTP request with error handling"""
#     try:
#         headers = {
#             "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#         }
#         return requests.get(url, timeout=timeout, headers=headers, verify=False, allow_redirects=True)
#     except Exception as e:
#         logger.debug(f"Request failed for {url}: {e}")
#         return None

# # -------------------- SAFE WHOIS HANDLING --------------------
# def safe_whois_lookup(domain):
#     """Safe WHOIS lookup that handles lists properly"""
#     try:
#         if not domain:
#             return None
        
#         whois_info = whois.whois(domain)
#         return whois_info
#     except Exception as e:
#         logger.debug(f"WHOIS lookup failed for {domain}: {e}")
#         return None

# def extract_whois_domain(whois_info):
#     """Safely extract domain name from WHOIS response"""
#     if not whois_info:
#         return ""
    
#     try:
#         domain_name = whois_info.get('domain_name', '')
        
#         # Handle cases where domain_name might be a list
#         if isinstance(domain_name, list):
#             if domain_name:
#                 # Take the first domain name in the list
#                 domain_name = domain_name[0]
#             else:
#                 domain_name = ''
        
#         # Convert to string and clean up
#         if domain_name:
#             return str(domain_name).lower().strip()
        
#         return ""
#     except Exception as e:
#         logger.debug(f"Error extracting WHOIS domain: {e}")
#         return ""

# # -------------------- SIMPLIFIED FEATURE EXTRACTOR --------------------
# class SimpleFeatureExtractor:
#     """Simplified feature extractor that avoids WHOIS list issues"""
    
#     def __init__(self, url):
#         self.url = url
#         self.parsed = urlparse(url)
#         self.netloc = self.parsed.netloc.lower() if self.parsed.netloc else ""
        
#         # Extract domain
#         extracted = tldextract.extract(url)
#         self.domain = f"{extracted.domain}.{extracted.suffix}" if extracted.domain and extracted.suffix else ""
        
#         # WHOIS - but only if domain exists
#         self.whois_info = None
#         if self.domain:
#             self.whois_info = safe_whois_lookup(self.domain)
        
#         # Try to fetch page (but don't fail if it doesn't work)
#         try:
#             self.response = safe_request(url)
#             self.soup = BeautifulSoup(self.response.text, 'html.parser') if self.response else None
#         except:
#             self.response = None
#             self.soup = None
    
#     def extract_features(self):
#         """Extract features safely without list errors"""
#         features = {}
        
#         # Initialize with neutral values for all expected features
#         for feature_name in FEATURE_NAMES:
#             features[feature_name] = 0
        
#         # Basic feature extraction
#         # 1. UsingIP
#         try:
#             hostname = self.netloc.split(':')[0]
#             ipaddress.ip_address(hostname)
#             features["UsingIP"] = -1
#         except:
#             features["UsingIP"] = 1
        
#         # 2. LongURL
#         url_len = len(self.url)
#         if url_len < 54:
#             features["LongURL"] = 1
#         elif url_len <= 75:
#             features["LongURL"] = 0
#         else:
#             features["LongURL"] = -1
        
#         # 3. ShortURL
#         shorteners = ["bit.ly", "goo.gl", "tinyurl.com", "t.co"]
#         url_lower = self.url.lower()
#         features["ShortURL"] = -1 if any(short in url_lower for short in shorteners) else 1
        
#         # 4. Symbol@
#         features["Symbol@"] = -1 if "@" in self.url else 1
        
#         # 5. Redirecting//
#         protocol_end = self.url.find("://")
#         if protocol_end != -1:
#             features["Redirecting//"] = -1 if "//" in self.url[protocol_end + 3:] else 1
#         else:
#             features["Redirecting//"] = 1
        
#         # 6. PrefixSuffix-
#         if self.domain:
#             domain_part = self.domain.split('.')[0]
#             features["PrefixSuffix-"] = -1 if "-" in domain_part else 1
#         else:
#             features["PrefixSuffix-"] = 1
        
#         # 7. SubDomains
#         extracted = tldextract.extract(self.url)
#         subdomain = extracted.subdomain
#         if not subdomain:
#             features["SubDomains"] = 1
#         else:
#             subdomain_count = len(subdomain.split('.'))
#             if subdomain_count == 1:
#                 features["SubDomains"] = 1
#             elif subdomain_count == 2:
#                 features["SubDomains"] = 0
#             else:
#                 features["SubDomains"] = -1
        
#         # 8. HTTPS
#         features["HTTPS"] = 1 if self.parsed.scheme == "https" else -1
        
#         # 9. DomainRegLen (assume legitimate for now)
#         features["DomainRegLen"] = 1
        
#         # 10. Favicon (assume legitimate)
#         features["Favicon"] = 1
        
#         # 11. NonStdPort
#         port = self.parsed.port
#         if not port:
#             port = 443 if self.parsed.scheme == "https" else 80
#         features["NonStdPort"] = -1 if port not in [80, 443] else 1
        
#         # 12. HTTPSDomainURL
#         features["HTTPSDomainURL"] = -1 if "https" in self.domain else 1
        
#         # 13. RequestURL (neutral)
#         features["RequestURL"] = 0
        
#         # 14. AnchorURL (neutral)
#         features["AnchorURL"] = 0
        
#         # 15. LinksInScriptTags (neutral)
#         features["LinksInScriptTags"] = 0
        
#         # 16. ServerFormHandler (assume legitimate)
#         features["ServerFormHandler"] = 1
        
#         # 17. InfoEmail (assume no mailto links)
#         features["InfoEmail"] = 1
        
#         # ✅ FIXED: 18. AbnormalURL - Handle WHOIS lists safely
#         try:
#             whois_domain_str = extract_whois_domain(self.whois_info)
#             if not whois_domain_str or not self.domain:
#                 features["AbnormalURL"] = -1
#             else:
#                 # Check if our domain is in the WHOIS domain string
#                 if self.domain.lower() in whois_domain_str:
#                     features["AbnormalURL"] = 1
#                 else:
#                     features["AbnormalURL"] = -1
#         except Exception as e:
#             logger.debug(f"Error in AbnormalURL feature: {e}")
#             features["AbnormalURL"] = -1
        
#         # 19. WebsiteForwarding (no redirects)
#         features["WebsiteForwarding"] = 0
        
#         # 20. StatusBarCust (no suspicious JS)
#         features["StatusBarCust"] = 1
        
#         # 21. DisableRightClick (no suspicious JS)
#         features["DisableRightClick"] = 1
        
#         # 22. UsingPopupWindow (no suspicious JS)
#         features["UsingPopupWindow"] = 1
        
#         # 23. IframeRedirection (no iframes)
#         features["IframeRedirection"] = 1
        
#         # 24. AgeofDomain (assume > 6 months)
#         features["AgeofDomain"] = 1
        
#         # 25. DNSRecording (has DNS record if WHOIS exists)
#         features["DNSRecording"] = -1 if not self.whois_info else 1
        
#         # 26-30. External metrics (neutral/default)
#         if "WebsiteTraffic" in FEATURE_NAMES:
#             features["WebsiteTraffic"] = 0
#         if "PageRank" in FEATURE_NAMES:
#             features["PageRank"] = 0
#         if "GoogleIndex" in FEATURE_NAMES:
#             features["GoogleIndex"] = 1
#         if "LinksPointingToPage" in FEATURE_NAMES:
#             features["LinksPointingToPage"] = 0
#         if "StatsReport" in FEATURE_NAMES:
#             features["StatsReport"] = 1
        
#         # Create feature vector in correct order
#         feature_vector = []
#         missing_features = []
        
#         for feature_name in FEATURE_NAMES:
#             if feature_name in features:
#                 feature_vector.append(features[feature_name])
#             else:
#                 feature_vector.append(0)  # Default neutral value
#                 missing_features.append(feature_name)
        
#         if missing_features:
#             logger.warning(f"Missing features: {missing_features}")
        
#         return np.array(feature_vector).reshape(1, -1), features

# # -------------------- PREDICTION FUNCTION --------------------
# def predict_with_ensemble(X_scaled, readable_features):
#     """Make predictions using available models"""
#     predictions = {}
#     probabilities = {}
    
#     for name, model in MODELS.items():
#         try:
#             pred = model.predict(X_scaled)[0]
#             predictions[name] = int(pred)
            
#             if hasattr(model, "predict_proba"):
#                 proba = model.predict_proba(X_scaled)[0]
#                 if len(proba) == 2:
#                     probabilities[name] = float(proba[1])
#                 else:
#                     probabilities[name] = float(proba[0])
#             else:
#                 probabilities[name] = float(pred)
#         except Exception as e:
#             logger.error(f"Model {name} failed: {e}")
#             predictions[name] = 0
#             probabilities[name] = 0.0
    
#     # If no models available, use fallback
#     if not predictions:
#         logger.warning("No models available, using fallback")
#         # Simple heuristic based on URL
#         url = readable_features.get('_url', '')
#         risk_score = 0.0
        
#         if len(url) > 75:
#             risk_score += 0.2
#         if "@" in url:
#             risk_score += 0.3
#         if not url.startswith("https://"):
#             risk_score += 0.2
        
#         avg_prob = min(max(risk_score, 0.0), 1.0)
#         predictions = {"fallback": 1 if avg_prob > 0.5 else 0}
#         probabilities = {"fallback": avg_prob}
#     else:
#         avg_prob = np.mean(list(probabilities.values())) if probabilities else 0.5
    
#     consensus = 1 if avg_prob >= THRESHOLD else 0
    
#     return {
#         "consensus": consensus,
#         "consensus_probability": float(avg_prob),
#         "individual_predictions": predictions,
#         "individual_probabilities": probabilities,
#         "readable_features": readable_features
#     }

# # -------------------- API ENDPOINTS --------------------
# @app.route("/health", methods=["GET"])
# def health():
#     """Health endpoint - GET only"""
#     return jsonify({
#         "status": "healthy",
#         "models_loaded": len(MODELS),
#         "features": len(FEATURE_NAMES),
#         "threshold": THRESHOLD,
#         "timestamp": datetime.now().isoformat()
#     })

# @app.route("/analyze", methods=["POST", "OPTIONS"])
# @app.route("/analyze_url", methods=["POST", "OPTIONS"])
# def analyze():
#     """Main analysis endpoint"""
#     try:
#         logger.info(f"📥 Received analysis request")
        
#         # Handle OPTIONS preflight
#         if request.method == "OPTIONS":
#             return jsonify({}), 200
        
#         # Get request data
#         if not request.is_json:
#             return jsonify({
#                 "error": "Content-Type must be application/json",
#                 "status": "error"
#             }), 400
        
#         data = request.get_json()
#         if not data or "url" not in data:
#             return jsonify({
#                 "error": "Missing 'url' parameter",
#                 "status": "error"
#             }), 400
        
#         url = data["url"].strip()
#         if not url:
#             return jsonify({
#                 "error": "URL cannot be empty",
#                 "status": "error"
#             }), 400
        
#         logger.info(f"🔗 Analyzing: {url}")
        
#         # Add scheme if missing
#         url_with_scheme = add_scheme_if_missing(url)
        
#         # Extract features
#         extractor = SimpleFeatureExtractor(url_with_scheme)
#         X_raw, readable_features = extractor.extract_features()
        
#         # Add URL to readable features for fallback
#         readable_features['_url'] = url_with_scheme
        
#         # Scale features if scaler exists
#         if SCALER is not None:
#             try:
#                 X_scaled = SCALER.transform(X_raw)
#                 logger.info("✅ Features scaled")
#             except Exception as e:
#                 logger.error(f"Scaling failed: {e}")
#                 X_scaled = X_raw
#         else:
#             X_scaled = X_raw
#             logger.warning("⚠️ No scaler available")
        
#         # Make predictions
#         ensemble_result = predict_with_ensemble(X_scaled, readable_features)
        
#         # Determine final result
#         primary_prob = ensemble_result["consensus_probability"]
#         is_phishing = primary_prob >= THRESHOLD
        
#         # Calculate risk level
#         if primary_prob < 0.3:
#             risk_level = "Low"
#         elif primary_prob < 0.7:
#             risk_level = "Medium"
#         else:
#             risk_level = "High"
        
#         # Generate recommendation
#         if is_phishing:
#             recommendation = f"This URL shows phishing indicators with {primary_prob*100:.1f}% confidence. Avoid entering personal information."
#         elif primary_prob > 0.8:
#             recommendation = f"This URL appears legitimate with {primary_prob*100:.1f}% confidence. It should be safe to use."
#         elif primary_prob > 0.5:
#             recommendation = f"This URL is likely safe ({primary_prob*100:.1f}% confidence), but exercise caution."
#         else:
#             recommendation = f"The verdict is uncertain ({primary_prob*100:.1f}% confidence). Proceed with caution."
        
#         # Prepare response
#         response = {
#             "url": url_with_scheme,
#             "domain": extractor.domain or urlparse(url_with_scheme).netloc or "unknown",
#             "prediction": "Phishing" if is_phishing else "Legitimate",
#             "probability": round(primary_prob, 4),
#             "confidence": round(primary_prob * 100, 2),
#             "risk_level": risk_level,
#             "recommendation": recommendation,
#             "safe_to_visit": not is_phishing,
#             "ensemble": {
#                 "consensus": ensemble_result["consensus"],
#                 "consensus_probability": round(ensemble_result["consensus_probability"], 4),
#                 "total_models": len(ensemble_result["individual_predictions"]),
#                 "agreement": f"{sum(ensemble_result['individual_predictions'].values())}/{len(ensemble_result['individual_predictions'])}",
#                 "individual_predictions": ensemble_result["individual_predictions"]
#             },
#             "timestamp": datetime.now().isoformat(),
#             "features_extracted": len(readable_features)
#         }
        
#         logger.info(f"✅ Analysis complete: {response['prediction']} ({response['confidence']}%)")
#         return jsonify(response), 200
        
#     except Exception as e:
#         logger.error(f"❌ Analysis error: {str(e)}", exc_info=True)
#         return jsonify({
#             "error": str(e),
#             "status": "error",
#             "message": "Failed to analyze URL",
#             "timestamp": datetime.now().isoformat()
#         }), 500

# # -------------------- ERROR HANDLERS --------------------
# @app.errorhandler(404)
# def not_found(e):
#     return jsonify({"error": "Endpoint not found", "status": "error"}), 404

# @app.errorhandler(405)
# def method_not_allowed(e):
#     return jsonify({"error": "Method not allowed", "status": "error"}), 405

# @app.errorhandler(500)
# def internal_error(e):
#     return jsonify({
#         "error": "Internal server error",
#         "status": "error",
#         "message": "Something went wrong on the server"
#     }), 500

# # -------------------- RUN APPLICATION --------------------
# if __name__ == "__main__":
#     import os
    
#     # Kill any existing process on port 5002
#     os.system("lsof -ti:5002 | xargs kill -9 2>/dev/null || true")
    
#     port = 5002
#     logger.info(f"🚀 Starting Flask Backend on port {port}")
#     logger.info(f"🌐 CORS enabled for: http://localhost:3000")
#     logger.info(f"🤖 Models available: {len(MODELS)}")
#     logger.info(f"📊 Features configured: {len(FEATURE_NAMES)}")
    
#     app.run(host="0.0.0.0", port=port, debug=False)
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

# # ✅ FIX 1: Explicit CORS (frontend @3000 → backend @5002)
# CORS(
#     app,
#     resources={r"/*": {"origins": "*"}},
#     supports_credentials=True
# )

# # ✅ FIX 1B: Handle OPTIONS preflight
# @app.before_request
# def handle_preflight():
#     if request.method == "OPTIONS":
#         response = app.make_response("")
#         response.headers["Access-Control-Allow-Origin"] = "*"
#         response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
#         response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
#         return response

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)

# # -------------------- MODEL LOADING (SINGLE BUNDLE) --------------------
# MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")
# BUNDLE_PATH = os.path.join(MODEL_DIR, "phishing_model_bundle.pkl")

# with open(BUNDLE_PATH, "rb") as f:
#     bundle = pickle.load(f)

# MODELS = {
#     "voting_hard": bundle["voting_hard"],
#     "voting_soft": bundle["voting_soft"],
#     "stacking": bundle["stacking"],
#     "gradient_boosting": bundle["gradient_boosting"],
#     "xgboost": bundle["xgboost"],
#     "catboost": bundle["catboost"],
#     "random_forest": bundle["random_forest"],
#     "svm": bundle["svm"],
# }

# SCALER = bundle["scaler"]
# FEATURE_NAMES = bundle["feature_names"]
# THRESHOLD = bundle["threshold"]
# MODEL_METRICS = bundle["model_metrics"]

# PRIMARY_MODEL = MODELS["voting_hard"]

# # -------------------- HELPERS --------------------
# def add_scheme_if_missing(url):
#     return url if urlparse(url).scheme else "https://" + url

# # -------------------- ENSEMBLE PREDICTION --------------------
# def predict_with_ensemble(X_scaled, X_raw, readable_feats):
#     predictions = {}
#     probabilities = {}

#     for name, model in MODELS.items():
#         try:
#             pred = model.predict(X_scaled)[0]
#             predictions[name] = int(pred if pred != -1 else 0)

#             if hasattr(model, "predict_proba"):
#                 probabilities[name] = float(model.predict_proba(X_scaled)[0][1])
#         except:
#             continue

#     consensus = int(sum(predictions.values()) > len(predictions) / 2)

#     avg_probability = (
#         np.mean(list(probabilities.values()))
#         if probabilities else float(consensus)
#     )

#     return {
#         "consensus": consensus,
#         "consensus_probability": float(avg_probability),
#         "individual_predictions": predictions,
#         "individual_probabilities": probabilities,
#         "explanations": []
#     }

# # -------------------- FEATURE EXTRACTION --------------------
# class PhishingFeatureExtractor:
#     def __init__(self, url):
#         self.url = url
#         self.parsed = urlparse(url)
#         self.domain = self.parsed.netloc.replace("www.", "").lower()
#         try:
#             self.whois_response = whois.whois(self.domain)
#         except:
#             self.whois_response = None

#     def has_ip(self):
#         try:
#             ipaddress.ip_address(self.domain)
#             return 1
#         except:
#             return 0

#     def domain_age_days(self):
#         try:
#             cd = self.whois_response.creation_date
#             if isinstance(cd, list):
#                 cd = cd[0]
#             return (datetime.now() - cd).days if cd else -1
#         except:
#             return -1

#     def extract(self):
#         features = {
#             "url_length": len(self.url),
#             "hostname_length": len(self.domain),
#             "path_length": len(self.parsed.path),
#             "query_length": len(self.parsed.query),
#             "num_subdomains": self.domain.count("."),
#             "num_digits": sum(c.isdigit() for c in self.url),
#             "num_letters": sum(c.isalpha() for c in self.url),
#             "num_special_chars": len(re.findall(r"[^a-zA-Z0-9]", self.url)),
#             "has_ip": self.has_ip(),
#             "has_https": int(self.parsed.scheme == "https"),
#             "tld_length": len(tldextract.extract(self.url).suffix),
#             "num_hyphens": self.domain.count("-"),
#             "ratio_digits_letters": 0,
#             "domain_age_days": self.domain_age_days(),
#             "shortened": 0,
#             "num_sensitive_words": 0,
#         }

#         vector = np.array([features.get(f, 0) for f in FEATURE_NAMES]).reshape(1, -1)
#         return vector, features
    
    

# # -------------------- API --------------------
# @app.route("/health", methods=["GET"])
# def health():
#     """Detailed health check"""
#     return jsonify({...})

# @app.route("/models", methods=["GET"])
# def list_models():
#     """List all available models and their performance"""
#     return jsonify({...})
# @app.route("/analyze", methods=["POST", "OPTIONS"])
# @app.route("/analyze_url", methods=["POST", "OPTIONS"])  # legacy
# def analyze():
#     data = request.get_json()
#     url = add_scheme_if_missing(data["url"])

#     extractor = PhishingFeatureExtractor(url)
#     X_raw, readable = extractor.extract()
#     X_scaled = SCALER.transform(X_raw)

#     ensemble = predict_with_ensemble(X_scaled, X_raw, readable)

#     # ✅ FIX 2: Proper probability source
#     primary_prob = (
#         ensemble["individual_probabilities"].get("voting_soft")
#         or ensemble["consensus_probability"]
#     )

#     pred = int(primary_prob >= THRESHOLD)

#     return jsonify({
#         "url": url,
#         "domain": extractor.domain,
#         "prediction": "Phishing" if pred else "Legitimate",
#         "probability": round(primary_prob, 4),
#         "confidence": round(primary_prob * 100, 2),
#         "ensemble": ensemble,
#         "safe_to_visit": primary_prob < 0.5,
#         "timestamp": datetime.now().isoformat()
#     }), 200

# # -------------------- RUN --------------------
# if __name__ == "__main__":
#     app.run(host="0.0.0.0", port=5002, debug=True)


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


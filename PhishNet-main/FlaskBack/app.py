import os
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

# -------------------- NEW DETECTION MODULES --------------------
from url_normalizer import URLNormalizer
_url_normalizer = URLNormalizer()

from domain_metadata_analyzer import DomainMetadataAnalyzer
_domain_analyzer = DomainMetadataAnalyzer()

from cloaking_detector import CloakingDetector
_cloaking_detector = CloakingDetector(enable_headless=True)

from intelligent_fusion import IntelligentFusion
_fusion_engine = IntelligentFusion()

from visual_similarity import VisualSimilarityAnalyzer
_visual_analyzer = VisualSimilarityAnalyzer(
    brand_db_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'brand_database')
)

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

# ==================== BUG FIX 1: DUPLICATE LOGS ====================
# Do NOT use basicConfig when Flask debug=True + reloader is active,
# as the module gets imported twice (master + reloader child process).
# Instead configure a single named logger with a handler-existence check.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
if not logger.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(message)s'))
    logger.addHandler(_handler)
    logger.propagate = False  # prevent double-logging via root logger
# ===================================================================

# -------------------- MODEL LOADING --------------------
MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

UCI_BUNDLE_PATH       = os.path.join(MODEL_DIR, "phishing_model_bundle_websitephishing.pkl")
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
    __slots__ = ('creation_date',)
    def __init__(self, creation_date):
        self.creation_date = creation_date

_WHOIS_DATE_PATTERNS = [
    re.compile(r'Creation Date\s*:\s*(.+)',              re.IGNORECASE),
    re.compile(r'Domain Registration Date\s*:\s*(.+)',   re.IGNORECASE),
    re.compile(r'Registration Date\s*:\s*(.+)',          re.IGNORECASE),
    re.compile(r'Registered On\s*:\s*(.+)',              re.IGNORECASE),
    re.compile(r'Registered\s*:\s*(.+)',                 re.IGNORECASE),
    re.compile(r'created\s*:\s*(.+)',                    re.IGNORECASE),
]

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

_WHOIS_PLACEHOLDER_DATE = datetime(1985, 1, 1)

def _parse_whois_date(raw):
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
    domain = domain.split(':')[0].strip().lstrip('.')
    if not domain:
        return None
    try:
        proc = subprocess.run(
            ['whois', domain],
            capture_output=True, text=True, timeout=timeout_sec
        )
        text = proc.stdout or ''
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
    MODELS = {}
    for key in ['lgb', 'xgb', 'catboost', 'rf']:
        if key in bundle:
            MODELS[key] = bundle[key]
    if 'stacking' in bundle:
        MODELS['stacking'] = bundle['stacking']
    SCALER = None
else:
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

TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'apple.com',
    'microsoft.com', 'github.com', 'stackoverflow.com', 'reddit.com',
    'twitter.com', 'x.com', 'linkedin.com', 'netflix.com', 'wikipedia.org',
    'yahoo.com', 'bing.com', 'instagram.com', 'tiktok.com', 'zoom.us',
    'dropbox.com', 'adobe.com', 'ebay.com', 'paypal.com', 'spotify.com',
    'claude.ai', 'anthropic.com',
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

        if self._is_suspicious():
            self.whois_response = safe_whois(self.domain)

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
        try:
            resp = requests.get(
                self.url, timeout=5, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
                verify=False
            )
            self.page_html = resp.text
            self.soup = BeautifulSoup(self.page_html, "html.parser")
        except Exception:
            self.page_html = ""
            self.soup = None

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
        title = self._get_title_text()
        if not title:
            return 0.0
        url_lower = self.url.lower()
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

        obf_ip_risk    = is_ip * has_obf
        insecure_pwd   = (1 - is_https) * h_password
        page_complete  = n_self_ref / (n_ext_ref + 1)
        legit_score    = h_title + h_favicon + h_desc + h_copyright + is_resp
        sus_fin        = (bank + pay + crypto) * (1 - h_copyright)
        title_combined = float(np.sqrt(dom_title * url_title))

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
            "ObfuscationIPRisk":            obf_ip_risk,
            "InsecurePasswordField":        insecure_pwd,
            "PageCompletenessRatio":        page_complete,
            "LegitContentScore":            legit_score,
            "SuspiciousFinancialFlag":      sus_fin,
            "TitleMatchCombined":           title_combined,
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
    UCI_FEATURE_COLS = [
        'SFH', 'popUpWidnow', 'SSLfinal_State', 'Request_URL',
        'URL_of_Anchor', 'web_traffic', 'URL_Length', 'age_of_domain',
        'having_IP_Address'
    ]

    def __init__(self, url):
        self.url = url.strip()
        self.parsed = urlparse(self.url)
        self.domain = self.parsed.netloc.split(':')[0].replace("www.", "").lower().strip()
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
        try:
            resp = requests.get(
                self.url, timeout=5, allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"},
                verify=False
            )
            self.page_html = resp.text
            self.soup = BeautifulSoup(self.page_html, "html.parser")
        except Exception:
            self.page_html = ""
            self.soup = None

    def _has_ip(self):
        try:
            ipaddress.ip_address(self.domain)
            return True
        except Exception:
            return False

    def _having_ip_address(self):
        return 1 if self._has_ip() else 0

    def _ssl_final_state(self):
        return 1 if self.parsed.scheme == 'https' else -1

    def _url_length(self):
        n = len(self.url)
        if n < 54:
            return 1
        elif n <= 75:
            return 0
        return -1

    def _age_of_domain(self):
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
        if not self.soup:
            return None, False
        og_time = self.soup.find("meta", property="article:published_time")
        if og_time and og_time.get("content"):
            return og_time["content"][:50], True
        for time_el in self.soup.find_all("time", datetime=True):
            dt_val = time_el.get("datetime", "").strip()
            if dt_val:
                return dt_val[:50], True
        for script in self.soup.find_all("script", type="application/ld+json"):
            text = script.get_text()
            if "datePublished" in text:
                m = re.search(r'"datePublished"\s*:\s*"([^"]+)"', text)
                if m:
                    return m.group(1)[:50], True
        return None, False

    def _get_subdomain_info(self):
        ext = tldextract.extract(self.url)
        subdomain = ext.subdomain or ''
        parts = [s for s in subdomain.split('.') if s] if subdomain else []
        return {
            'subdomain':       subdomain,
            'domain_name':     ext.domain or '',
            'tld':             ext.suffix or '',
            'subdomain_count': len(parts)
        }

    def _enumerate_subdomains(self):
        ext = tldextract.extract(self.url)
        if not ext.domain or not ext.suffix:
            return {'found': [], 'count': 0, 'base_domain': '', 'sources': []}

        base_domain = f"{ext.domain}.{ext.suffix}"
        discovered = set()
        sources = []

        try:
            # stream=True + read cap avoids blocking on huge CT logs (e.g. claude.ai has 100s of certs)
            ct_resp = requests.get(
                f"https://crt.sh/?q=%.{base_domain}&output=json",
                timeout=(4, 12),   # 4s connect, 12s read
                headers={"User-Agent": "Mozilla/5.0 PhishNet/1.0"},
                stream=True
            )
            if ct_resp.status_code == 200:
                import json as _json
                ct_content = ct_resp.raw.read(512 * 1024, decode_content=True)  # max 512 KB
                for cert in _json.loads(ct_content):
                    for name in cert.get('name_value', '').split('\n'):
                        name = name.strip().lower().lstrip('*.')
                        if name.endswith(f'.{base_domain}') and name != base_domain:
                            sub = name[:-len(f'.{base_domain}')]
                            if sub and '.' not in sub:
                                discovered.add(sub)
                if discovered:
                    sources.append('crt.sh')
                    logger.info(f"crt.sh found {len(discovered)} subdomains for {base_domain}")
        except Exception as e:
            logger.debug(f"crt.sh lookup failed for {base_domain}: {e}")

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
        if not self.soup:
            return -1
        popups = re.findall(r"window\.open|alert\(|confirm\(|popup", str(self.soup), re.I)
        return 1 if popups else -1

    def _request_url(self):
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
            return 1
        ratio = external / total
        if ratio < 0.31:
            return 1
        elif ratio < 0.67:
            return 0
        return -1

    def _web_traffic(self):
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
    base_domain = '.'.join(domain.split('.')[-2:])
    return base_domain in TRUSTED_DOMAINS

def calculate_phishing_score(features, model_probabilities):
    base_score = float(np.mean(list(model_probabilities.values())))
    boost = 0.0
    reasons = []

    domain = features.get("_domain", "")
    if is_trusted_domain(domain):
        boost -= 0.10
        reasons.append("Domain is in trusted whitelist (legitimacy signal)")

    if features.get("IsDomainIP", 0) == 1:
        boost += 0.35
        reasons.append("IP address used instead of domain name")

    if features.get("HasObfuscation", 0) == 1:
        boost += 0.20
        reasons.append(f"URL obfuscation detected ({features.get('NoOfObfuscatedChar', 0)} chars)")

    if features.get("InsecurePasswordField", 0) == 1:
        boost += 0.30
        reasons.append("Password field on non-HTTPS page")

    if features.get("IsHTTPS", 0) == 0:
        boost += 0.10
        reasons.append("No HTTPS encryption")

    dom_len = features.get("DomainLength", 0)
    if dom_len > 40:
        boost += 0.20
        reasons.append(f"Very long domain ({dom_len} chars)")
    elif dom_len > 30:
        boost += 0.10
        reasons.append(f"Long domain ({dom_len} chars)")

    if features.get("SuspiciousFinancialFlag", 0) > 0:
        boost += 0.15
        reasons.append("Financial keywords without legitimacy markers")

    if features.get("HasExternalFormSubmit", 0) == 1:
        boost += 0.20
        reasons.append("Form submits to external domain")

    legit = features.get("LegitContentScore", 0)
    if legit == 0:
        boost += 0.15
        reasons.append("No legitimacy markers (title/favicon/description/copyright)")
    elif legit == 1:
        boost += 0.08
        reasons.append("Very few legitimacy markers")

    if features.get("Crypto", 0) == 1:
        boost += 0.10
        reasons.append("Cryptocurrency keywords detected")

    final_score = max(0.01, min(base_score + boost, 0.99))
    return final_score, boost, reasons, base_score

def calculate_phishing_score_uci(features, model_probabilities):
    base_score = float(np.mean(list(model_probabilities.values())))
    boost = 0.0
    reasons = []

    domain = features.get("_domain", "")
    if is_trusted_domain(domain):
        boost -= 0.30
        reasons.append("Domain is in trusted whitelist (strong legitimacy signal)")
        
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

    if legit_count >= 4:
        boost -= 0.10
        reasons.append(f"Multiple legitimate indicators ({legit_count}/9 UCI features)")

    if features.get("having_IP_Address", 0) == 1:
        boost += 0.35
        reasons.append("IP address used instead of domain name")

    if features.get("SSLfinal_State", 1) == -1:
        boost += 0.15
        reasons.append("No HTTPS encryption")

    if features.get("SFH", 0) == -1:
        boost += 0.20
        reasons.append("Form submits to external domain")

    if features.get("age_of_domain", 1) == -1:
        boost += 0.10
        reasons.append("New or unknown domain age")

    if features.get("popUpWidnow", -1) == 1:
        boost += 0.05
        reasons.append("Popup windows detected")

    if features.get("NoSSL_HasIP", 0) == 1:
        boost += 0.20
        reasons.append("IP address without HTTPS (high-risk combination)")

    if features.get("BadSFH_BadSSL", 0) == 1:
        boost += 0.15
        reasons.append("External form submission + no HTTPS (credential theft risk)")

    phish_count = features.get("PhishingSignalCount", 0)
    if phish_count >= 5:
        boost += 0.20
        reasons.append(f"Many phishing signals detected ({phish_count}/9 features)")
    elif phish_count >= 3:
        boost += 0.10
        reasons.append(f"Multiple phishing signals detected ({phish_count}/9 features)")

    if features.get("web_traffic", 0) == -1:
        boost += 0.08
        reasons.append("No detectable web traffic (obscure/new site)")

    if features.get("Request_URL", 0) == -1:
        boost += 0.08
        reasons.append("Most page resources loaded from external domains")

    if features.get("URL_of_Anchor", 0) == -1:
        boost += 0.05
        reasons.append("Most anchor links point to external domains")

    final_score = max(0.01, min(base_score + boost, 0.99))
    return final_score, boost, reasons, base_score

def compute_shap_explanation(X_input, feature_names):
    shap_arrays = []
    for name, explainer in SHAP_EXPLAINERS.items():
        try:
            sv = explainer.shap_values(X_input)
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
            'feature':    feature_names[i],
            'shap_value': float(avg_shap[i]),
            'direction':  'phishing' if avg_shap[i] > 0 else 'legitimate',
            'abs_value':  float(abs(avg_shap[i]))
        }
        for i in range(len(feature_names))
    ]
    items.sort(key=lambda x: x['abs_value'], reverse=True)
    top = items[:10]
    for item in top:
        del item['abs_value']

    return {
        'top_features':   top,
        'total_features': len(feature_names),
        'models_averaged': len(shap_arrays)
    }


def convert_to_serializable(obj):
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


# -------------------- URL EXPANDER --------------------
_SHORTENER_DOMAINS = {
    'bit.ly', 'bitly.com', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'short.io', 'tiny.cc', 'rb.gy', 'cutt.ly',
    'shorturl.at', 'bl.ink', 'snip.ly', 'clck.ru', 'x.co',
    'lnkd.in', 'dlvr.it', 'ift.tt', 'fb.me', 'youtu.be',
    'adf.ly', 'bc.vc', 'sh.st', 'linktr.ee', 'go2l.ink',
    'rebrand.ly', 'qr.ae', 'ur1.ca', 'v.gd',
}

def expand_short_url(url: str, max_hops: int = 6, per_hop_timeout: int = 4) -> dict:
    parsed_initial = urlparse(url)
    domain = parsed_initial.netloc.lower().lstrip('www.')
    if domain not in _SHORTENER_DOMAINS:
        return {'original': url, 'expanded': url, 'was_shortened': False, 'hops': 0}

    logger.info(f"🔗 Shortener detected ({domain}) — following redirects…")
    current_url = url
    hops = 0
    dest_unreachable = False

    for _ in range(max_hops):
        try:
            resp = requests.head(
                current_url,
                allow_redirects=False,
                timeout=per_hop_timeout,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; PhishNet/1.0)'},
            )
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get('Location', '').strip()
                if not location:
                    break
                if location.startswith('//'):
                    location = urlparse(current_url).scheme + ':' + location
                elif location.startswith('/'):
                    p = urlparse(current_url)
                    location = f"{p.scheme}://{p.netloc}{location}"
                current_url = location
                hops += 1
            else:
                break
        except requests.exceptions.Timeout:
            dest_unreachable = True
            break
        except Exception as _ex:
            logger.warning(f"Hop failed ({current_url}): {_ex}")
            dest_unreachable = True
            break

    final_domain = urlparse(current_url).netloc.lower().lstrip('www.')

    if not final_domain or (final_domain in _SHORTENER_DOMAINS and current_url == url):
        return {
            'original': url, 'expanded': url, 'was_shortened': True, 'hops': hops,
            'error': 'Could not resolve final destination'
        }

    logger.info(f"🔗 Expanded: {url} → {current_url} ({hops} hop(s))"
                + (" [destination unreachable]" if dest_unreachable else ""))
    result = {'original': url, 'expanded': current_url, 'was_shortened': True, 'hops': hops}
    if dest_unreachable:
        result['destination_unreachable'] = True
    return result


# ==================== BUG FIX 2: PREDICTION LABEL HELPER ====================
def _prediction_label(prob: float, threshold: float) -> str:
    """
    Three-tier verdict so the WARN zone (fusion risk between 0.35 and threshold)
    is never incorrectly labelled 'Legitimate'.

    Phishing   : prob >= threshold
    Suspicious : prob >= 0.35  (previously shown as 'Legitimate' — the bug)
    Legitimate : prob <  0.35
    """
    if prob >= threshold:
        return "Phishing"
    elif prob >= 0.35:
        return "Suspicious"
    else:
        return "Legitimate"
# =============================================================================


# -------------------- ANALYSIS LOGIC --------------------
def analyze_url_logic(url):
    try:
        url = url.strip()
        if not url:
            return {"error": "URL required"}, 400

        scheme = urlparse(url).scheme.lower()
        if scheme and scheme not in ('http', 'https'):
            return {"error": f"Unsupported scheme '{scheme}'. Only http/https URLs are accepted."}, 400
        if not scheme:
            url = "https://" + url

        if len(url) > 2000:
            return {"error": "URL too long (max 2000 characters)"}, 400

        logger.info(f"🔍 Analyzing: {url}")

        # LAYER 0: URL Expansion
        expansion = expand_short_url(url)
        original_url = url
        if expansion['was_shortened'] and expansion['expanded'] != url:
            url = expansion['expanded']
            logger.info(f"🔗 Analyzing real destination: {url}")

        # LAYER 0.5: URL Normalization
        try:
            url_norm_result = _url_normalizer.normalize(url)
            norm_flags = url_norm_result.get('flags', [])
            if expansion.get('was_shortened') and 'URL_SHORTENER' not in norm_flags:
                norm_flags.append('URL_SHORTENER')
                url_norm_result['flags'] = norm_flags
            if norm_flags:
                logger.info(f"🔎 URL flags: {norm_flags}")
        except Exception as _un_err:
            logger.warning(f"URL normalizer failed: {_un_err}")
            url_norm_result = {'is_suspicious': False, 'flags': [], 'decoded_domain': '', 'details': {}}
            norm_flags = ['URL_SHORTENER'] if expansion.get('was_shortened') else []

        # LAYER 1: Rule-Based Detection
        rule_result = rule_engine.evaluate(url)

        if rule_result['is_phishing']:
            logger.info(f"⚠️  Rule engine: PHISHING signals ({rule_result['confidence']:.0%}) — continuing to ML for full verdict")
        else:
            logger.info(f"✅ Rule engine: no phishing signals — continuing to ML")

        # LAYER 2: ML Ensemble Detection
        if MODEL_TYPE == 'uci':
            extractor = UCIFeatureExtractor(url)
        else:
            extractor = FeatureExtractor(url)
        X_raw, features = extractor.extract()

        features["_domain"] = extractor.domain

        X_for_prediction = X_raw if MODEL_TYPE == 'uci' else SCALER.transform(X_raw)

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

        if not probabilities:
            logger.error("All ML models failed to produce predictions — aborting analysis")
            return {"error": "All ML models failed. Please try again."}, 500

        if MODEL_TYPE == 'uci':
            final_prob, boost, reasons, base_prob = calculate_phishing_score_uci(features, probabilities)
        else:
            final_prob, boost, reasons, base_prob = calculate_phishing_score(features, probabilities)

        if boost > 0:
            logger.info(f"📈 Risk boosted: {base_prob:.2%} → {final_prob:.2%}")
            for reason in reasons:
                logger.info(f"   {reason}")

        # LAYER 3: Hybrid Rule-ML Fusion
        if rule_result['confidence'] > 0.3:
            has_critical = any(r['severity'] == 'CRITICAL' for r in rule_result['rules'])
            has_high     = any(r['severity'] == 'HIGH'     for r in rule_result['rules'])
            if has_critical:
                rule_floor = rule_result['confidence'] * 0.95
                if final_prob < rule_floor:
                    final_prob = rule_floor
                    boost = final_prob - base_prob
                    reasons.append(f"Rule engine override (CRITICAL signals, {rule_result['confidence']:.0%} confidence)")
                    logger.info(f"🚨 Hybrid override: ML={base_prob:.2%} → Rule floor={rule_floor:.2%}")
            elif has_high and rule_result['confidence'] > 0.45:
                rule_floor = rule_result['confidence'] * 0.70
                if final_prob < rule_floor:
                    final_prob = rule_floor
                    boost = final_prob - base_prob
                    reasons.append(f"Rule engine override (HIGH signals, {rule_result['confidence']:.0%} confidence)")
                    logger.info(f"⚠️  Hybrid override: ML={base_prob:.2%} → Rule floor={rule_floor:.2%}")

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

        phishing_votes    = sum(1 for pred in predictions.values() if pred == 1)
        legitimate_votes  = sum(1 for pred in predictions.values() if pred == 0)
        total_models      = len(predictions)

        if max(phishing_votes, legitimate_votes) >= 3:
            consensus_confidence = "High"
        elif max(phishing_votes, legitimate_votes) == 2:
            consensus_confidence = "Medium"
        else:
            consensus_confidence = "Low"

        consensus_text = f"{phishing_votes} Phishing | {legitimate_votes} Legitimate"
        logger.info(f"🗳️ Ensemble Voting: {consensus_text} (Confidence: {consensus_confidence})")

        rule_contributed = rule_result['is_phishing'] and rule_result['confidence'] > 0.3
        if rule_contributed and boost > 0:
            detection_source = "rule_engine_ml"
        else:
            detection_source = "ml_ensemble"

        shap_explanation = None
        if SHAP_EXPLAINERS:
            try:
                shap_explanation = compute_shap_explanation(X_for_prediction, FEATURE_NAMES)
            except Exception as _shap_err:
                logger.warning(f"SHAP explanation skipped: {_shap_err}")

        # Build url_analysis display metadata
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

        features.pop('_domain', None)

        # LAYER 3: Domain Metadata Analysis
        domain_result = None
        if 'IP_ADDRESS' in norm_flags:
            logger.info("⏭️  Fast-path domain metadata (IP-address URL)")
            domain_result = {
                'risk_score': 0.6,
                'is_suspicious': True,
                'risk_factors': ['IP address used instead of domain name'],
                'metadata': {
                    'ip': {'ip': url_norm_result.get('decoded_domain', ''), 'is_private': False},
                    'ssl': {'has_ssl': False},
                    'whois': {'domain_age_days': None},
                    'dns': {'has_mx': False, 'has_spf': False, 'has_dmarc': False},
                    'asn': {}
                }
            }
        else:
            try:
                domain_result = _domain_analyzer.analyze(url)
                logger.info(f"🌐 Domain risk: {domain_result.get('risk_score', 0):.2f}")
            except Exception as _dm_err:
                logger.warning(f"Domain metadata analysis failed: {_dm_err}")
                domain_result = {'risk_score': 0.0, 'is_suspicious': False, 'risk_factors': [], 'metadata': {}}

        # LAYER 3b: Visual Similarity
        visual_result = None
        if 'IP_ADDRESS' not in norm_flags:
            try:
                visual_result = _visual_analyzer.analyze(url)
                if visual_result.get('matched_brand'):
                    logger.warning(
                        f"🚨 Brand impersonation detected: {visual_result['matched_brand']} "
                        f"({visual_result['max_similarity']:.0%} visual similarity)"
                    )
                elif not visual_result.get('skipped'):
                    logger.info(f"🖼️  Visual: no brand clone (max SSIM {visual_result.get('max_similarity', 0):.0%})")
            except Exception as _vs_err:
                logger.warning(f"Visual similarity failed: {_vs_err}")
                visual_result = None

        # ==================== BUG FIX 3: CLOAKING RISK FOR UNREACHABLE SITES ====================
        # Previously: DNS failure → cloaking risk defaults to 0.30 (neutral / "safe")
        # which dragged the fused score down, causing phishing sites to be labelled Legitimate.
        # Fix: unresolvable / unreachable = 0.65 (suspicious), not 0.30.
        _dest_unreachable = expansion.get('destination_unreachable', False)
        _expansion_error  = expansion.get('was_shortened') and expansion.get('error') is not None
        cloaking_result = None
        if 'IP_ADDRESS' in norm_flags:
            logger.info("⏭️  Skipping cloaking detection (IP-address URL — already flagged)")
            cloaking_result = {
                'overall_risk': 0.65,          # ← FIX: was 0.50 — IP with no DNS is high risk
                'cloaking_detected': False,
                'skipped': True,
                'evidence': ['IP-address URL skips cloaking scan']
            }
        elif _dest_unreachable or _expansion_error:
            reason = 'destination server unreachable' if _dest_unreachable else 'shortener redirect unresolved'
            logger.info(f"⏭️  Skipping cloaking detection ({reason})")
            cloaking_result = {
                'overall_risk': 0.65,          # ← FIX: was 0.30 — unreachable = suspicious
                'cloaking_detected': False,
                'skipped': True,
                'evidence': [f'Cloaking scan skipped: {reason}']
            }
        else:
            # TCP reachability — catches dead DNS AND sinkholed/parked domains
            _h       = urlparse(url).hostname or url
            _host_ok = _is_reachable(url)

            if not _host_ok:
                logger.warning(f"⏭️  Cloaking skipped — DNS unresolvable: {_h}")
                cloaking_result = {
                    'overall_risk': 0.65, 'cloaking_detected': False,
                    'skipped': True, 'evidence': [f'DNS unresolvable: {_h}']
                }
            else:
                try:
                    cloaking_result = _cloaking_detector.analyze(url, domain_result)
                    cloaking_result['skipped'] = False
                    if cloaking_result.get('cloaking_detected'):
                        logger.warning(f"🎭 Cloaking detected! Risk: {cloaking_result.get('overall_risk', 0):.2f}")
                    else:
                        logger.info(f"✅ No cloaking detected (risk: {cloaking_result.get('overall_risk', 0):.2f})")
                except Exception as _cd_err:
                    logger.warning(f"Cloaking detection failed: {_cd_err}")
                    cloaking_result = {
                        'overall_risk': 0.50, 'cloaking_detected': False,
                        'skipped': True, 'evidence': [f'Cloaking failed: {_cd_err}']
                    }
        # ========================================================================================

        # LAYER 5: Intelligent Multi-Modal Fusion
        fusion_result = None
        try:
            ml_result_for_fusion = {
                'probability': final_prob,
                'prediction': 'phishing' if final_prob >= THRESHOLD else 'legitimate',
                'confidence': final_prob
            }
            fusion_result = _fusion_engine.analyze(
                url=url,
                ml_result=ml_result_for_fusion,
                domain_result=domain_result,
                cloaking_result=cloaking_result,
                visual_result=visual_result,
            )
            fused_risk = fusion_result.get('final_risk', final_prob)
            logger.info(f"🧠 Fusion: {fusion_result.get('scenario')} → {fusion_result.get('verdict')} (risk {fused_risk:.2f})")
            final_prob = fused_risk
        except Exception as _fe:
            logger.warning(f"Intelligent fusion failed: {_fe}")

        # ==================== BUG FIX 2 (applied here) ====================
        # Use three-tier label: Phishing / Suspicious / Legitimate
        # Previously: anything below threshold (0.63) → "Legitimate",
        # even when fusion verdict was WARN (risk ~0.49).
        prediction_label = _prediction_label(final_prob, THRESHOLD)
        logger.info(f"✅ {prediction_label} ({round(final_prob * 100, 2)}%)")
        # ===================================================================

        response = {
            "url":           str(original_url),
            "analyzed_url":  str(url),
            "url_expanded":  expansion.get('was_shortened', False),
            "url_expansion": {
                "original":               expansion.get('original', original_url),
                "expanded":               expansion.get('expanded', url),
                "was_shortened":          expansion.get('was_shortened', False),
                "hops":                   expansion.get('hops', 0),
                "destination_unreachable": expansion.get('destination_unreachable', False),
                "error":                  expansion.get('error'),
            } if expansion.get('was_shortened') else None,
            "domain":            str(extractor.domain),
            "prediction":        prediction_label,          # ← FIX 2
            "confidence":        float(round(final_prob * 100, 2)),
            "probability":       float(round(final_prob, 4)),
            "base_probability":  float(round(base_prob, 4)),
            "risk_boost":        float(round(boost, 4)),
            "boost_reasons":     reasons,
            "safe_to_visit":     bool(prediction_label == "Legitimate"),
            "is_trusted":        is_trusted_domain(extractor.domain),
            "detection_source":  detection_source,
            "risk_level":        str(risk_level),
            "risk_emoji":        str(risk_emoji),
            "risk_color":        str(risk_color),
            "threshold_used":    float(THRESHOLD),
            "ensemble": {
                "base_probability":       float(round(base_prob, 4)),
                "individual_predictions": convert_to_serializable(predictions),
                "individual_probabilities": convert_to_serializable({k: round(v, 4) for k, v in probabilities.items()}),
                "agreement":              f"{int(sum(predictions.values()))}/{len(predictions)}",
                "voting": {
                    "phishing_votes":      int(phishing_votes),
                    "legitimate_votes":    int(legitimate_votes),
                    "total_models":        int(total_models),
                    "consensus_text":      str(consensus_text),
                    "consensus_confidence": str(consensus_confidence)
                }
            },
            "rule_analysis": {
                "is_phishing":    rule_result['is_phishing'],
                "confidence":     float(round(rule_result['confidence'], 4)),
                "rule_violations": rule_result['rules'],
                "rule_count":     rule_result['rule_count'],
                "signals":        rule_result['signals']
            },
            "features":          convert_to_serializable(features),
            "shap_explanation":  shap_explanation,
            "url_analysis":      url_analysis,
            "url_normalization": {
                "flags":          norm_flags,
                "is_suspicious":  bool(url_norm_result.get('is_suspicious', False)),
                "decoded_domain": str(url_norm_result.get('decoded_domain', '')),
                "details":        url_norm_result.get('details', {})
            },
            "domain_metadata": {
                "risk_score":   float(domain_result.get('risk_score', 0.0)),
                "is_suspicious": bool(domain_result.get('is_suspicious', False)),
                "risk_factors": domain_result.get('risk_factors', []),
                "metadata":     domain_result.get('metadata', {})
            } if domain_result else None,
            "cloaking": {
                "risk":     float(cloaking_result.get('overall_risk', 0.0)),
                "detected": bool(cloaking_result.get('cloaking_detected', False)),
                "evidence": cloaking_result.get('evidence', [])[:5]
            } if cloaking_result else None,
            "fusion_result": {
                "final_risk":    float(fusion_result.get('final_risk', 0.0)),
                "verdict":       str(fusion_result.get('verdict', '')),
                "scenario":      str(fusion_result.get('scenario', '')),
                "reasoning":     fusion_result.get('reasoning', []),
                "confidence":    float(fusion_result.get('confidence', 0.0)),
                "module_scores": fusion_result.get('module_scores', {})
            } if fusion_result else None,
            "visual_similarity": {
                "risk_score":     float(visual_result.get('risk_score', 0.0)),
                "max_similarity": float(visual_result.get('max_similarity', 0.0)),
                "matched_brand":  visual_result.get('matched_brand'),
                "skipped":        bool(visual_result.get('skipped', False)),
                "skip_reason":    visual_result.get('reason'),
            } if visual_result else None,
            "model_info": {
                "models_used":       len(MODELS),
                "model_names":       list(MODELS.keys()),
                "detection_method":  f"Full Pipeline: Rule Engine (all rules) + {'UCI 16-Feature' if MODEL_TYPE == 'uci' else '4-Model'} ML Ensemble + Score Fusion",
                "rule_engine_enabled": True,
                "rules_checked":     14,
                "f1_score":          MODEL_METRICS.get("gradient_boosting", {}).get("f1_score", 0.0),
            },
            "timestamp": str(datetime.now().isoformat())
        }

        return response, 200

    except Exception as e:
        logger.error(f"❌ Error: {str(e)}", exc_info=True)
        return {"error": str(e)}, 500


# -------------------- API ROUTES --------------------
from fusion_endpoint import fusion_bp
app.register_blueprint(fusion_bp)

@app.route("/", methods=["GET", "OPTIONS"])
def home():
    if request.method == "OPTIONS":
        return "", 200
    return jsonify({
        "status": "healthy",
        "service": "Phishing Detection API",
        "version": "5.1 - Triple Bug Fix",
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
    logger.info("🚀 PHISHING DETECTION API v5.1 - TRIPLE BUG FIX")
    logger.info("   Fix 1: Duplicate logs — use_reloader=False eliminates double imports")
    logger.info("   Fix 2: 3-tier labels: Phishing / Suspicious / Legitimate")
    logger.info("   Fix 3: Unreachable/DNS-fail cloaking risk = 0.65 (not 0.30)")
    logger.info(f"✅ Detection: ML + Whitelist + Heuristics")
    logger.info(f"✅ Trusted domains: {len(TRUSTED_DOMAINS)}")
    logger.info("="*80)
    # ==================== BUG FIX 1 ====================
    # use_reloader=False prevents Werkzeug from importing the module twice,
    # which was the root cause of every log line appearing twice.
    # If you need live-reload during development, use an external tool like
    # watchdog/hupper instead, or accept that debug=True will double-log.
    app.run(host="0.0.0.0", port=5002, debug=True, use_reloader=False)
    # ====================================================
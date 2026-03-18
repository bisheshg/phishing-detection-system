import os
import hashlib
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
        return _rdap_fallback(domain)
    except subprocess.TimeoutExpired:
        logger.warning(f"WHOIS timeout for {domain} (>{timeout_sec}s)")
        return _rdap_fallback(domain)
    except FileNotFoundError:
        logger.warning("'whois' CLI not found — domain age unavailable")
        return _rdap_fallback(domain)
    except Exception as e:
        logger.warning(f"WHOIS lookup failed for {domain}: {e}")
        return _rdap_fallback(domain)

def _rdap_fallback(domain):
    """RDAP fallback when WHOIS fails — modern HTTP-based registry lookup."""
    try:
        resp = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=5,
            headers={"Accept": "application/rdap+json"}
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        for event in data.get('events', []):
            if event.get('eventAction') == 'registration':
                dt_str = event.get('eventDate', '')[:25]
                dt = _parse_whois_date(dt_str)
                if dt and dt.year > 1990:
                    logger.info(f"RDAP {domain}: created {dt.date()} ({(datetime.now()-dt).days} days ago)")
                    return _WhoisInfo(dt)
    except Exception as e:
        logger.debug(f"RDAP fallback failed for {domain}: {e}")
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
THRESHOLD      = 0.63  # fixed detection threshold (do not read from bundle — bundle value is 0.425, too low)
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
    # Sports & News
    'espncricinfo.com', 'espn.com', 'bbc.com', 'bbc.co.uk', 'cnn.com',
    'nytimes.com', 'theguardian.com', 'reuters.com', 'apnews.com',
    'cricbuzz.com', 'icc-cricket.com', 'fifa.com', 'nfl.com', 'nba.com',
    # Nepal
    'onlinekhabar.com', 'ekantipur.com', 'kantipurtv.com', 'ratopati.com',
    'setopati.com', 'nagariknetwork.com',
    # Banking / Finance
    'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
    'hsbc.com', 'barclays.co.uk',
    # Tech / Cloud
    'aws.amazon.com', 'azure.com', 'cloud.google.com',
    'onedrive.live.com', 'office.com', 'live.com', 'outlook.com',
    'salesforce.com', 'shopify.com', 'wordpress.com', 'wix.com',
    # Domain registrars & web hosting (commonly block bots → false cloaking positives)
    'godaddy.com', 'namecheap.com', 'name.com', 'domain.com',
    'bluehost.com', 'hostgator.com', 'siteground.com', 'hostinger.com',
    'ionos.com', 'dreamhost.com', 'a2hosting.com', 'inmotionhosting.com',
    # CDN / Infrastructure (aggressive bot-protection)
    'cloudflare.com', 'fastly.com', 'akamai.com',
    # E-commerce / Travel / Business
    'etsy.com', 'aliexpress.com', 'alibaba.com', 'airbnb.com',
    'booking.com', 'expedia.com', 'tripadvisor.com', 'yelp.com',
    'craigslist.org', 'autotrader.com', 'zillow.com',
    # Social / Content platforms
    'twitch.tv', 'medium.com', 'substack.com', 'quora.com',
    'pinterest.com', 'tumblr.com', 'vimeo.com', 'dailymotion.com',
    # Website builders
    'squarespace.com', 'webflow.com', 'weebly.com', 'jimdo.com',
}

# Platforms where users can upload arbitrary web content — the ONLY domains
# where force visual scanning makes sense (to detect hosted phishing pages).
# Core service subdomains (scholar.google.com, maps.google.com, etc.) are NOT
# included because they ARE Google, not just hosted BY Google.
_CONTENT_HOSTING_DOMAINS = {
    'docs.google.com', 'drive.google.com', 'sites.google.com',
    'storage.googleapis.com', 'colab.research.google.com',
    'dropbox.com', 'www.dropbox.com',
    'onedrive.live.com', 'sharepoint.com',
    'github.io', 'raw.githubusercontent.com',
    'netlify.app', 'vercel.app', 'web.app', 'firebaseapp.com',
    's3.amazonaws.com', 'storage.amazonaws.com',
    'notion.site',
    # Website builders — users can publish arbitrary pages on user subdomains
    'webflow.io',       # beetmartloginn.webflow.io, auth-sso--log--capital-i.webflow.io
    'webwave.dev',      # nielzu.webwave.dev
    'framer.app',       # lime-tenets-056451.framer.app
    'weebly.com',       # officespanishlog.weebly.com
    'wixsite.com',      # *.wixsite.com
    'strikingly.com',   # *.strikingly.com
    'carrd.co',         # *.carrd.co
    'glitch.me',        # *.glitch.me
    # IPFS gateways — content addressed, anyone can pin arbitrary pages
    'dweb.link',        # bafkrei....ipfs.dweb.link  (IPFS gateway)
    'ipfs.io',          # *.ipfs.io
    'cloudflare-ipfs.com',
    # Additional cloud/app platforms
    'appspot.com',      # Google App Engine user apps
    'azurewebsites.net',# Azure App Service
    'azurestaticapps.net',
    'pages.dev',        # Cloudflare Pages
    'surge.sh',         # surge.sh CLI deployments
    'render.com',       # render.com web services
    # Cloudflare Workers — serverless compute, arbitrary user code
    'workers.dev',      # lodfdf-sd87.randolfa20.workers.dev
    # Object storage (any URL can be served)
    'backblazeb2.com',  # aumentinhoultravioletamais.s3.us-east-005.backblazeb2.com
    'r2.dev',           # Cloudflare R2 public buckets
    'digitaloceanspaces.com',
    # Landing page / form builders
    'convertflowpages.com',
    'unbounce.com', 'lp.unbounce.com',
    'webnode.com', 'webnode.page',
    'webcindario.com',  # free web hosting
    '000webhostapp.com',
    'infinityfreeapp.com',
    'square.site',      # csu-student-office365-verification.square.site
    'sites.google.com', # already in docs.google.com subset but explicit
}

def is_content_hosting_domain(domain):
    """True only for platforms where users can upload arbitrary web content."""
    return any(domain == d or domain.endswith('.' + d) for d in _CONTENT_HOSTING_DOMAINS)

# Phishing action keywords that appear in subdomain/path of hosted phishing pages.
# e.g. beetmartloginn.webflow.io  →  subdomain contains 'login'
#      auth-sso--log--capital-i.webflow.io → 'auth', 'sso', 'log'
#      mail-ovhcloud.web.app → 'mail'
_HOSTING_PHISH_KEYWORDS = {
    'login', 'logon', 'signin', 'sign-in', 'sign_in',
    'verify', 'verification', 'validated', 'validation',
    'secure', 'security', 'update', 'updates',
    'auth', 'authenticate', 'authentication', 'sso',
    'account', 'accounts', 'myaccount',
    'confirm', 'confirmation', 'suspend', 'suspended',
    'recover', 'recovery', 'reset', 'password',
    'credential', 'credentials', 'wallet',
    'invoice', 'billing', 'payment', 'checkout',
    'bank', 'banking', 'mail', 'webmail', 'support',
    'helpdesk', 'service', 'portal', 'dashboard',
}

# Brand names whose presence in subdomain/path of a hosting platform
# strongly indicates impersonation (separate from visual_similarity brands).
_HOSTING_BRAND_KEYWORDS = {
    'amazon', 'paypal', 'netflix', 'apple', 'microsoft', 'google',
    'facebook', 'instagram', 'linkedin', 'chase', 'twitter', 'roblox',
    'wells', 'citi', 'hsbc', 'barclays', 'nationwide', 'halifax',
    'rogers', 'telus', 'bell', 'verizon', 'att', 'tmobile',
    'ovh', 'godaddy', 'namecheap', 'cpanel', 'wordpress',
    'dropbox', 'onedrive', 'icloud', 'office365', 'outlook',
    'coinbase', 'binance', 'metamask', 'crypto', 'kucoin', 'kraken', 'bybit',
    'dhl', 'fedex', 'ups', 'usps', 'royal-mail',
    'esewa', 'khalti', 'fonepay', 'imepay',
}

def _hosting_phish_keyword_in_url(url: str, domain: str) -> bool:
    """
    Returns True when a URL on a content-hosting platform has phishing
    action keywords or known brand names in its subdomain or path segment.

    Catches patterns like:
      beetmartloginn.webflow.io        → subdomain has 'login'
      auth-sso--log--capital-i.webflow.io → subdomain has 'auth','sso','log'
      ddeepakgoutam2005.github.io/Netflix_Clone/ → path has 'netflix'
      mail-ovhcloud.web.app/           → subdomain has 'mail', 'ovhcloud' (brand)
      rogerlicentree.github.io/Rogers  → path has 'rogers' (brand)
    """
    if not is_content_hosting_domain(domain):
        return False

    parsed = urlparse(url.lower())
    hostname = (parsed.hostname or '').lower()
    path     = (parsed.path or '').lower()

    # Extract the user-controlled subdomain portion by stripping the hosting suffix.
    subdomain = ''
    for hd in _CONTENT_HOSTING_DOMAINS:
        if hostname == hd:
            break                      # no subdomain (root hosting domain)
        if hostname.endswith('.' + hd):
            subdomain = hostname[: -(len(hd) + 1)]
            break

    # Use substring matching: 'login' is inside 'beetmartloginn', 'netflix'
    # is inside 'netflix_clone'. We don't need whole-word boundaries here —
    # any embedding of a phishing keyword in the subdomain/path is suspicious.
    combined = subdomain + ' ' + path

    for kw in _HOSTING_PHISH_KEYWORDS:
        if kw in combined:
            return True

    for brand in _HOSTING_BRAND_KEYWORDS:
        if brand in combined:
            return True

    return False

logger.info(f"✅ Model type: {MODEL_TYPE.upper()}")
logger.info(f"✅ Loaded {len(MODELS)} models")
logger.info(f"✅ Features: {len(FEATURE_NAMES)}")
logger.info(f"✅ Trusted domains: {len(TRUSTED_DOMAINS)}")

# ── FIX 2: Nepal brand keyword → official domain mapping ────────────────────
# When a brand keyword appears in the URL but the official domain does NOT,
# it signals brand impersonation. Adds +0.30 boost to final_prob.
NEPAL_BRAND_MAP = {
    # Digital payments
    'esewa':       'esewa.com.np',
    'khalti':      'khalti.com',
    'connectips':  'connectips.com',
    'imepay':      'imepay.com.np',
    # Banks
    'nicasia':     'nicasiabank.com',
    'globalime':   'globalimebank.com',
    'nabil':       'nabilbank.com',
    'himalayan':   'himalayanbank.com',
    'siddhartha':  'siddharthabank.com',
    'everest':     'everestbankltd.com',
    'kumari':      'kumaribank.com',
    'machhapuchhre': 'machbank.com',
    'sanima':      'sanimabank.com',
    'citizens':    'citizensbank.com.np',
    'laxmi':       'laxmibank.com',
    'prabhu':      'prabhubank.com',
    # Telecom
    'ntc':         'ntc.net.np',
    'ncell':       'ncell.com.np',
    'subisu':      'subisu.net.np',
    'dishhome':    'dishhome.com.np',
    # Global brands (reinforce — rule engine may miss these)
    'paypal':      'paypal.com',
    'amazon':      'amazon.com',
    'google':      'google.com',
    'microsoft':   'microsoft.com',
    'apple':       'apple.com',
    'facebook':    'facebook.com',
    'instagram':   'instagram.com',
    'coinbase':    'coinbase.com',
    'binance':     'binance.com',
}

# Generic financial/auth phishing keywords — these are NOT specific brand names
# but appear almost exclusively in phishing URLs pretending to be banking portals.
# Combined with a dead DNS signal they are near-certain phishing.
# Used separately from NEPAL_BRAND_MAP — smaller boost (0.20) and only fires
# when DNS is also dead (cloaking_dns_failed), preventing false positives on
# legitimate banking sites that happen to contain these words.
GENERIC_PHISHING_KEYWORDS = {
    # Banking / auth patterns
    'banking-portal', 'bank-portal', 'banking-login', 'bank-login',
    'banking-secure', 'secure-banking', 'banking-verify', 'bank-verify',
    'account-verify', 'account-verification', 'account-update', 'account-secure',
    'login-secure', 'secure-login', 'verify-account', 'verification-service',
    'payment-confirm', 'payment-verification', 'payment-secure',
    'wallet-verify', 'wallet-update', 'wallet-secure',
    'kyc-update', 'kyc-verify', 'update-kyc',
    # Gaming / trading platform clones (CS:GO skins, Steam trading)
    'skins-trade', 'skin-trade', 'csgo-trade', 'steam-trade',
    'item-trade', 'trade-skins', 'trade-items',
    # Crypto / NFT drainers
    'wallet-connect', 'wallet-sync', 'wallet-recover', 'nft-claim',
    'crypto-claim', 'token-claim', 'airdrop-claim',
    # Delivery / parcel scams
    'parcel-tracking', 'tracking-fee', 'delivery-fee', 'package-fee',
    'parcel-fee', 'customs-fee', 'delivery-update',
    # Account suspension / appeal scams
    'account-suspended', 'account-appeal', 'suspended-appeal',
    'appeal-verify', 'account-disabled',
}

# ── FIX 4: Free hosting platform detection ──────────────────────────────────
# These platforms host user content at subdomains. Phishing pages built on
# ghost.io, blogspot.com etc. benefit from the platform's clean domain_risk
# (e.g. ghost.io = 5278 days old, domain_risk=0.10), which pulls fusion scores
# down even when all ML models voted phishing. We neutralise this by treating
# such subdomains as fresh unknown sites (domain_risk=0.50) and flagging them.
FREE_HOSTING_PLATFORMS = {
    'ghost.io', 'blogspot.com', 'wordpress.com', 'weebly.com',
    'wix.com', 'squarespace.com', 'webflow.io',
    'github.io', 'gitlab.io', 'netlify.app', 'vercel.app',
    'pages.dev', 'web.app', 'firebaseapp.com',
    'sites.google.com', 'glitch.me', 'replit.app',
    '000webhostapp.com', 'byethost.com', 'infinityfreeapp.com',
}


def check_nepal_brand_impersonation(url: str) -> dict:
    """
    FIX 2: Detect Nepal/global brand impersonation by keyword matching.

    Two tiers:
      Tier 1 — specific brand keyword (esewa, nabil, nicasia …)
               → boost +0.30, fires always (brand name in URL but wrong domain)
      Tier 2 — generic phishing pattern (banking-portal, kyc-update …)
               → boost +0.20, only fires when combined with other risk signals
                 (caller checks cloaking_dns_failed before applying)

    Returns boost amount and reason string, or zero boost if no match.
    """
    url_lower = url.lower()
    parsed    = urlparse(url_lower)
    full_host = parsed.netloc

    # Tier 1: specific brand name
    for brand_kw, official_domain in NEPAL_BRAND_MAP.items():
        if brand_kw in url_lower and official_domain not in full_host:
            return {
                'is_impersonation': True,
                'tier': 1,
                'brand':            brand_kw,
                'official_domain':  official_domain,
                'boost':            0.30,
                'reason': f"Brand keyword '{brand_kw}' in URL but not on official domain ({official_domain})"
            }

    # Tier 2: generic phishing keyword pattern (hyphenated compound words)
    for kw in GENERIC_PHISHING_KEYWORDS:
        if kw in url_lower:
            return {
                'is_impersonation': True,
                'tier': 2,
                'brand':            kw,
                'official_domain':  None,
                'boost':            0.20,
                'reason': f"Generic phishing pattern '{kw}' detected in URL (banking/auth impersonation)"
            }

    return {'is_impersonation': False, 'tier': 0, 'brand': None, 'boost': 0.0}


def is_free_hosting_subdomain(url: str) -> bool:
    """
    FIX 4: Return True if URL is a subdomain of a known free hosting platform.
    e.g. globalpage-intro.ghost.io → True
         ghost.io itself → False (it's the platform page, not user content)
    """
    ext = tldextract.extract(url)
    registered = f"{ext.domain}.{ext.suffix}"
    has_subdomain = bool(ext.subdomain)
    return registered in FREE_HOSTING_PLATFORMS and has_subdomain

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
            return 0  # neutral — page inaccessible/dynamic, don't penalize
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

    _CONTENT_BRAND_TITLE_MAP = {
        'microsoft': 'microsoft.com', 'apple': 'apple.com',
        'google': 'google.com',       'amazon': 'amazon.com',
        'paypal': 'paypal.com',       'facebook': 'facebook.com',
        'netflix': 'netflix.com',     'instagram': 'instagram.com',
        'linkedin': 'linkedin.com',   'chase': 'chase.com',
        'dropbox': 'dropbox.com',     'twitter': 'twitter.com',
        'roblox': 'roblox.com',       'coinbase': 'coinbase.com',
        'esewa': 'esewa.com.np',      'khalti': 'khalti.com',
    }

    def _has_password_field(self):
        """True if page has any <input type="password"> element."""
        if not self.soup:
            return False
        return bool(self.soup.find('input', {'type': 'password'}))

    def _has_login_form(self):
        """True if page has a form with both a password field and an email/username field."""
        if not self.soup:
            return False
        for form in self.soup.find_all('form'):
            has_pwd = bool(form.find('input', {'type': 'password'}))
            has_email = bool(form.find('input', {'type': lambda t: t and t.lower() in ('email', 'text')}))
            if has_pwd and has_email:
                return True
        return False

    def _page_title_brand_mismatch(self):
        """True if <title> contains a known brand name but the URL domain doesn't match that brand."""
        if not self.soup:
            return False
        title_tag = self.soup.find('title')
        if not title_tag:
            return False
        title = (title_tag.get_text(strip=True) or '').lower()
        url_base = '.'.join(self.domain.split('.')[-2:])
        for brand_kw, official_domain in self._CONTENT_BRAND_TITLE_MAP.items():
            if brand_kw in title:
                official_base = '.'.join(official_domain.split('.')[-2:])
                if url_base != official_base:
                    return True
        return False

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
        features['_url_raw_length']         = len(self.url)
        features['_subdomain_enum']         = sub_enum
        features['_has_password_field']     = self._has_password_field()
        features['_has_login_form']         = self._has_login_form()
        features['_page_title_brand_mismatch'] = self._page_title_brand_mismatch()

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
        boost -= 0.45
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

    # High-confidence ML cap: when the raw ML ensemble is already very confident
    # (base_score > 0.80, i.e. 5/5 models at ~89%), applying a -0.25 legitimacy
    # boost based on feature counts overrides a near-certain phishing vote.
    # The models have ALREADY seen NetScore and LegitSignalCount as features —
    # applying the same info again as a manual boost is double-counting.
    # Cap: allow at most -0.10 negative boost when base_score > 0.80.
    if base_score > 0.80 and boost < -0.10:
        boost = -0.10

    final_score = max(0.01, min(base_score + boost, 0.99))

    # Hard cap: established trusted domains should never show > 35% phishing probability
    domain_age_days = features.get('_domain_age_days', 0) or 0
    if is_trusted_domain(domain) and domain_age_days > 365:
        final_score = min(final_score, 0.35)

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
    # Additional shorteners missing from original list
    'bit.do', 't.ly', 'su.pr', 'po.st', 'fur.ly', 'ow.ly',
    'mcaf.ee', 'ff.im', 'twitthis.com', 'u.to', 'j.mp',
    # QR code shorteners — generate short links for QR codes,
    # commonly abused to bypass visual/email phishing filters
    'qrco.de',          # qrco.de/bfkA9N — QR code campaigns
    'qr.io', 'qr.net',
    'bitly.ws',         # Bitly QR variant
    's.id',             # s.id short links
    'lk.to',
    'dub.sh', 'dub.co',
    # Redirect/tracking services used as phishing proxy
    'appopener.com',    # appopener.com/web/... redirects to destination
    'go.microsoft.com', # Sometimes abused, but also legit (handle carefully)
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


# ==================== SHORTENER SLUG ANALYSER ====================
# Keywords that, when found in a shortener slug, indicate phishing intent.
# Using the same vocabulary as RuleEngine.FINANCIAL_KEYWORDS + KNOWN_BRANDS so
# both layers stay in sync.
_SLUG_PHISHING_KEYWORDS = frozenset([
    # Actions / credential harvesting
    'login', 'signin', 'sign-in', 'account', 'verify', 'secure', 'update',
    'confirm', 'billing', 'payment', 'wallet', 'password', 'credential',
    'suspended', 'unlock', 'restore', 'validate', 'recover', 'activate',
    # Prize / reward scams
    'claim', 'prize', 'winner', 'reward', 'bonus', 'free', 'gift', 'giveaway',
    'sweepstake', 'congratulations', 'promo',
    # Financial / crypto
    'bank', 'paypal', 'crypto', 'airdrop', 'nft', 'token',
    # Nepal-specific payments and telecoms
    'esewa', 'khalti', 'connectips', 'ncell', 'ntc', 'imepay',
    'recharge', 'topup', 'kyc',
    # Global brands
    'google', 'facebook', 'amazon', 'apple', 'microsoft', 'netflix',
    'instagram', 'twitter', 'linkedin', 'ebay', 'chase', 'wellsfargo',
    'coinbase', 'binance', 'metamask',
    # Delivery / parcel scams
    'tracking', 'delivery', 'parcel', 'customs', 'shipment',
])


def analyze_slug_risk(original_url: str) -> dict:
    """
    Analyse the path/slug of a shortener URL for phishing keyword hints.
    Called BEFORE expansion so intent in the original slug is never lost.

    Returns:
        { 'slug': str, 'matched_keywords': list[str], 'risk': float 0–1 }
    Risk scoring: 0.35 per unique keyword match, capped at 1.0.
    Threshold guidance: ≥ 0.35 → at least one signal; ≥ 0.70 → two or more.
    """
    try:
        from urllib.parse import urlparse as _urlparse
        slug = _urlparse(original_url).path.lstrip('/').lower()
        if not slug:
            return {'slug': '', 'matched_keywords': [], 'risk': 0.0}

        # Split on hyphens, underscores, slashes, dots to get individual tokens
        tokens = set(re.split(r'[-_/.]', slug))
        matched = tokens & _SLUG_PHISHING_KEYWORDS

        # Substring scan catches compound words: "freeprize" contains "prize"
        for kw in _SLUG_PHISHING_KEYWORDS:
            if len(kw) >= 4 and kw in slug:
                matched.add(kw)

        risk = min(1.0, len(matched) * 0.35)
        return {'slug': slug, 'matched_keywords': sorted(matched), 'risk': risk}
    except Exception:
        return {'slug': '', 'matched_keywords': [], 'risk': 0.0}


# ==================== CAMPAIGN SIGNATURE HELPER ====================
def generate_campaign_signature(html_content, resolved_ip, model_probabilities=None):
    """Generate a multi-factor signature for campaign correlation."""
    html_hash = hashlib.sha256(
        (html_content or "").encode('utf-8', errors='ignore')
    ).hexdigest()[:32]

    server_ip = (resolved_ip or "unknown").strip()

    # Semantic embedding: normalized probability vector from ML models
    embedding = []
    if model_probabilities:
        try:
            embedding = [float(round(v, 4)) for v in model_probabilities.values()]
        except Exception:
            pass

    return {
        "html_hash": html_hash,
        "server_ip": server_ip,
        "semantic_embedding": embedding
    }


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


def _is_reachable(url: str) -> bool:
    """Return True if the URL's hostname resolves in DNS (fast pre-check for cloaking)."""
    try:
        host = urlparse(url).hostname or url
        socket.getaddrinfo(host, None)
        return True
    except Exception:
        return False


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
        expansion = expand_short_url(url, max_hops=3)
        original_url = url

        # Slug analysis runs on the ORIGINAL shortener URL before expansion so
        # phishing keywords in the slug (e.g. "esewa-login", "freeprize-claim")
        # are never lost even if the expanded destination looks legitimate.
        _slug_analysis = {}
        _slug_risk = 0.0
        if expansion.get('was_shortened'):
            _slug_analysis = analyze_slug_risk(url)
            _slug_risk = _slug_analysis.get('risk', 0.0)
            if _slug_analysis.get('matched_keywords'):
                logger.info(
                    f"🎯 Slug keywords in '{_slug_analysis['slug']}': "
                    f"{_slug_analysis['matched_keywords']} (risk: {_slug_risk:.2f})"
                )

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

        # ── Homoglyph / character-substitution boost ───────────────────────────
        # The URL normalizer already detected homoglyph chars (e.g. buff163-trade.com:
        # '1'→'l', '3'→'e' → spoofing buff163.com Steam market).
        # This signal is NOT in the 16 UCI features — the ML never sees it.
        # Apply +0.25 boost so the fusion engine gets the correct risk level.
        # Only fires when HOMOGLYPH_DETECTED is in norm_flags and domain is not trusted.
        if 'HOMOGLYPH_DETECTED' in norm_flags and not is_trusted_domain(extractor.domain):
            _hg_boost = 0.25
            final_prob = min(final_prob + _hg_boost, 0.99)
            boost += _hg_boost
            reasons.append("Homoglyph/character-substitution attack detected in domain")
            logger.info(f"🔤 Homoglyph boost: +{_hg_boost:.2f} (new prob={final_prob:.2%})")
        # ─────────────────────────────────────────────────────────────────────

        # ── FIX 2: Nepal / global brand impersonation boost ─────────────────
        # Computed here (before cloaking) — dns_failed flag applied AFTER cloaking.
        # cloaking_result is not yet assigned at this point; we store the brand
        # check result and apply the boost further down after cloaking runs.
        _brand_check = check_nepal_brand_impersonation(url)
        # (boost applied after cloaking block — see _apply_brand_boost below)
        # ─────────────────────────────────────────────────────────────────────

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
        # For trusted domains with high raw ML score (potential hosted-content phishing),
        # force a screenshot comparison against ALL brands even without brand keywords in
        # the URL — the phishing form is inside the page body, not the URL path.
        # Threshold: base_prob >= 0.88 (raw ensemble, before trusted-domain boost).
        # Only force visual scan on content-hosting platforms (Drive, Dropbox, etc.)
        # NOT on all trusted domains — scholar.google.com IS Google, not a hosting service.
        _force_visual = (
            is_content_hosting_domain(extractor.domain)
            and base_prob >= 0.88
        )
        visual_result = None
        if 'IP_ADDRESS' not in norm_flags:
            try:
                visual_result = _visual_analyzer.analyze(url, force=_force_visual)
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
                'dns_failed': False,           # IP URL — not a DNS failure, separate signal
                'skipped': True,
                'evidence': ['IP-address URL skips cloaking scan']
            }
        elif _dest_unreachable or _expansion_error:
            reason = 'destination server unreachable' if _dest_unreachable else 'shortener redirect unresolved'
            logger.info(f"⏭️  Skipping cloaking detection ({reason})")
            cloaking_result = {
                'overall_risk': 0.65,          # ← FIX: was 0.30 — unreachable = suspicious
                'cloaking_detected': False,
                'dns_failed': True,            # FIX 1: signal dns_failed to fusion engine
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
                    'dns_failed': True,    # FIX 1: signal dns_failed to fusion engine
                    'skipped': True, 'evidence': [f'DNS unresolvable: {_h}']
                }
            else:
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as _cloak_ex:
                        _cloak_fut = _cloak_ex.submit(_cloaking_detector.analyze, url, domain_result)
                        try:
                            cloaking_result = _cloak_fut.result(timeout=20)
                        except concurrent.futures.TimeoutError:
                            logger.warning("⏱️  Cloaking analysis timed out (20s) — using neutral risk")
                            cloaking_result = {
                                'overall_risk': 0.30, 'cloaking_detected': False,
                                'skipped': True, 'error': 'timeout',
                                'evidence': ['Cloaking analysis exceeded 20s budget']
                            }
                    cloaking_result['skipped'] = cloaking_result.get('skipped', False)
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

        # ── FIX 2 (apply): Nepal brand boost — now cloaking_result is assigned ──────────────
        # Tier 1 (specific brand: nabil, esewa, nicasia …) fires always.
        # Tier 2 (generic pattern: banking-portal, kyc-update …) only fires when
        # DNS is dead, preventing false positives on legitimate banking sites.
        _cloaking_dns_failed = (cloaking_result or {}).get('dns_failed', False)
        _apply_brand_boost = (
            _brand_check['is_impersonation']
            and not is_trusted_domain(extractor.domain)
            and (_brand_check['tier'] == 1 or _cloaking_dns_failed)
        )
        if _apply_brand_boost:
            _brand_boost = _brand_check['boost']
            final_prob   = min(final_prob + _brand_boost, 0.99)
            boost        += _brand_boost
            reasons.append(_brand_check['reason'])
            logger.info(f"🏷️  Brand impersonation (Tier {_brand_check['tier']}): "
                        f"'{_brand_check['brand']}' → +{_brand_boost:.2f} "
                        f"(new prob={final_prob:.2%})")
        # ─────────────────────────────────────────────────────────────────────────────────────

        # LAYER 5: Intelligent Multi-Modal Fusion
        fusion_result = None
        try:
            # ── FIX 3: compute unanimous vote flag ───────────────────────────
            # True when every single ML model voted phishing (e.g. 5/5).
            # Passed into fusion so _handle_standard_ensemble can apply the
            # +0.08 boost for near-miss scores (0.50–0.65 range).
            _ml_unanimous = (phishing_votes == total_models and total_models > 0)

            # ── FIX 4: detect free hosting platform subdomains ───────────────
            # ghost.io/blogspot.com etc. have clean WHOIS (domain_risk≈0.10)
            # even when a phishing page is hosted at a subdomain.
            # Neutralise domain_risk to 0.50 so it doesn't pull the score down.
            # keyword_match: True when brand/generic phishing keyword was found in URL.
            # Passed to fusion so it can route keyword+dns_failed → fresh_phishing_setup
            # even when the ML base_prob is very low (model regression after retraining).
            _keyword_match = _brand_check.get('is_impersonation', False)

            _on_free_host = is_free_hosting_subdomain(url)
            _domain_result_for_fusion = domain_result

            if _on_free_host:
                import copy
                _domain_result_for_fusion = copy.deepcopy(domain_result) if domain_result else {}
                _domain_result_for_fusion['risk_score'] = 0.50
                _domain_result_for_fusion.setdefault('metadata', {}) \
                                         .setdefault('whois', {}) \
                                         ['domain_age_days'] = 0
                logger.info(f"🏠 Free-hosting subdomain — domain_risk neutralised to 0.50: {url}")
                if _ml_unanimous and _keyword_match:
                    # Escalate only when a brand/phishing keyword is in the URL.
                    final_prob = max(final_prob, 0.72)
                    reasons.append("Phishing page on free hosting platform (unanimous ML + free host)")
                    logger.warning(f"🏠 Free hosting + unanimous ML → escalated: {url}")
                elif not _keyword_match:
                    # No keyword match → likely a portfolio/demo site. The UCI models
                    # have a known false-positive rate on Vercel/Netlify/GitHub Pages
                    # because those sites share structural features with phishing pages
                    # (no MX, no web traffic rank, popup windows, etc.).
                    # Clamp final_prob so it can only cross the HIGH threshold (0.82)
                    # if the raw ML evidence is extremely strong.
                    _free_host_cap = 0.62   # just under THRESHOLD — forces Legitimate
                    if final_prob > _free_host_cap:
                        logger.info(
                            f"🏠 Free-host + no keyword → capping ML score "
                            f"{final_prob:.3f} → {_free_host_cap} to suppress false positive"
                        )
                        final_prob = _free_host_cap

            ml_result_for_fusion = {
                'probability':           final_prob,
                'prediction':            'phishing' if final_prob >= THRESHOLD else 'legitimate',
                'confidence':            final_prob,
                'unanimous':             _ml_unanimous,            # FIX 3
                'free_hosting_subdomain': _on_free_host,           # FIX 4
                'keyword_match':          _keyword_match,          # keyword+dns_failed routing
                'slug_risk':             _slug_risk,               # shortener slug keywords
                'was_shortened':         expansion.get('was_shortened', False),
                'trusted_domain':        is_trusted_domain(extractor.domain),  # hosted-content impersonation
                'is_content_hosting':    is_content_hosting_domain(extractor.domain),  # only content-hosting platforms
                'url_base_domain':       '.'.join(extractor.domain.split('.')[-2:]),  # for self-brand exclusion
            }

            # Domain age fallback: domain_metadata_analyzer WHOIS sometimes fails
            # (e.g. whois library API mismatch) but url_analysis has the correct age
            # from the subprocess whois call. Patch domain_result so fusion gets the
            # right age instead of treating every WHOIS-fail domain as brand new.
            # NOTE: if _on_free_host already set _domain_result_for_fusion above,
            # we apply the age fallback ON TOP of that — don't reset to domain_result.
            _whois_age = ((_domain_result_for_fusion or domain_result or {})
                          .get('metadata', {})
                          .get('whois', {})
                          .get('domain_age_days'))
            _fallback_age = (url_analysis or {}).get('domain_age_days')
            if _whois_age is None and _fallback_age is not None:
                import copy
                if _domain_result_for_fusion is domain_result:
                    # Not already deep-copied by free-hosting fix — copy now
                    _domain_result_for_fusion = copy.deepcopy(domain_result)
                _domain_result_for_fusion.setdefault('metadata', {}) \
                                         .setdefault('whois', {}) \
                                         ['domain_age_days'] = _fallback_age
                logger.info(f"🔧 Domain age fallback: using url_analysis age {_fallback_age}d (WHOIS library failed)")

            # Cloudflare CDN cloaking false-positive suppression.
            # Cloudflare injects geo-check / UA-check / timing JS on ALL proxied sites —
            # these look like cloaking patterns but are normal bot protection.
            # HOWEVER: if the cloaking detector found 2+ distinct patterns beyond the
            # single Cloudflare UA check, the site is using deliberate evasion on top of CF.
            # buff163-trade.com: UA check + timing delay + geo check + referrer check = 4 patterns
            # → genuine cloaking, not just Cloudflare defaults → do NOT cap.
            # Rule: cap to 0.35 only if suspicious_patterns_found <= 1.
            _cloaking_result_for_fusion = cloaking_result
            _asn_desc = (domain_result.get('metadata', {})
                                      .get('asn', {})
                                      .get('asn_description', ''))
            if 'CLOUDFLARE' in _asn_desc.upper() and cloaking_result:
                _cf_patterns = (cloaking_result.get('tier1', {})
                                               .get('suspicious_patterns_found', 0)
                                or len(cloaking_result.get('evidence', [])))
                _cf_should_cap = (_cf_patterns <= 1)
                if _cf_should_cap:
                    _cf_risk = min(cloaking_result.get('overall_risk', 0), 0.35)
                    if _cf_risk < cloaking_result.get('overall_risk', 0):
                        _cloaking_result_for_fusion = {**cloaking_result, 'overall_risk': _cf_risk}
                        logger.info(f"☁️  Cloudflare CDN: cloaking risk capped {cloaking_result.get('overall_risk', 0):.2f} → {_cf_risk:.2f} (patterns={_cf_patterns})")
                else:
                    logger.info(f"☁️  Cloudflare CDN: cap skipped — {_cf_patterns} cloaking patterns detected (genuine evasion)")

            # Trusted domain cloaking cap:
            # Major legitimate sites (ESPN, BBC, etc.) often block automated requests,
            # causing cloaking detector to return 0.65 "unreachable" — this is not cloaking.
            if is_trusted_domain(extractor.domain) and cloaking_result:
                _td_risk = min(_cloaking_result_for_fusion.get('overall_risk', 0), 0.30)
                if _td_risk < _cloaking_result_for_fusion.get('overall_risk', 0):
                    _cloaking_result_for_fusion = {**_cloaking_result_for_fusion, 'overall_risk': _td_risk}
                    logger.info(f"🛡️  Trusted domain: cloaking risk capped at {_td_risk:.2f}")

            # Build URL features dict for fusion engine.
            # Previously this was always None because url_features was never constructed.
            # The fusion engine has url_features support but was never fed real data.
            _orig_netloc = urlparse(expansion.get('original', url)).netloc.lower().lstrip('www.')
            _exp_netloc  = urlparse(expansion.get('expanded',  url)).netloc.lower().lstrip('www.')
            _is_dead_link = (
                expansion.get('was_shortened', False)
                and bool(_orig_netloc)
                and _orig_netloc == _exp_netloc   # shortener expanded to its own domain
            )
            # Detect phishing keywords in subdomain/path of content-hosting platforms.
            # e.g. beetmartloginn.webflow.io, github.io/Netflix_Clone
            # Passed as a signal to the fusion engine → Scenario 2.6.
            _hosting_phish_kw = _hosting_phish_keyword_in_url(url, extractor.domain)
            if _hosting_phish_kw:
                logger.info(f"🎯 Hosting phish keyword detected in subdomain/path: {url}")

            _url_features_for_fusion = {
                'is_suspicious':           url_norm_result.get('is_suspicious', False),
                'norm_flags':              norm_flags,
                'suspicious_tld':          'SUSPICIOUS_TLD'      in norm_flags,
                'has_homoglyph':           'HOMOGLYPH_DETECTED'  in norm_flags,
                'has_punycode':            'PUNYCODE_DETECTED'   in norm_flags,
                'is_shortener':            expansion.get('was_shortened', False),
                'destination_unreachable': expansion.get('destination_unreachable', False),
                'is_dead_link':            _is_dead_link,
                'hops':                    expansion.get('hops', 0),
                # NEW: phishing keyword in subdomain/path of content-hosting platform
                'hosting_phish_keyword':   _hosting_phish_kw,
                # NEW: content-based signals from page HTML
                'has_password_field':       features.get('_has_password_field', False),
                'has_login_form':           features.get('_has_login_form', False),
                'page_title_brand_mismatch': features.get('_page_title_brand_mismatch', False),
            }
            if _is_dead_link:
                logger.info(f"🔗 Dead short link detected ({_orig_netloc} → {_exp_netloc}/error) — routing as dead_link")

            fusion_result = _fusion_engine.analyze(
                url=url,
                ml_result=ml_result_for_fusion,
                domain_result=_domain_result_for_fusion,
                cloaking_result=_cloaking_result_for_fusion,
                visual_result=visual_result,
                url_features=_url_features_for_fusion,
            )
            fused_risk = fusion_result.get('final_risk', final_prob)
            logger.info(f"🧠 Fusion: {fusion_result.get('scenario')} → {fusion_result.get('verdict')} (risk {fused_risk:.2f})")

            # Trusted-domain + clean-rule-engine override:
            # If a domain is explicitly in TRUSTED_DOMAINS and the rule engine
            # found zero phishing signals, a flawed ML vote must NOT produce a
            # BLOCK or WARN verdict. Force ALLOW so the prediction label is Legitimate.
            # Covers both BLOCK and WARN — e.g. namecheap.com getting 'Suspicious'
            # from established_domain handler when ML is mildly elevated.
            #
            # EXCEPTION: content-hosting platforms (webflow.io, github.io, weebly.com)
            # are in _CONTENT_HOSTING_DOMAINS. When Scenario 2.6 detected a phishing
            # keyword in the subdomain/path AND routed to fresh_phishing_setup→BLOCK,
            # the override must NOT override that BLOCK back to ALLOW.
            # e.g. terminationaccountnotice.weebly.com: weebly.com IS in TRUSTED_DOMAINS,
            # but this is a phishing kit subdomain — keep BLOCK.
            _td_verdict = fusion_result.get('verdict')
            _is_hosting_phish = _hosting_phish_kw  # True = Scenario 2.6 fired
            if (_td_verdict in ('BLOCK', 'WARN')
                    and is_trusted_domain(extractor.domain)
                    and not rule_result.get('is_phishing', False)
                    and not _is_hosting_phish):       # ← don't override hosting phish detections
                fusion_result = {**fusion_result, 'verdict': 'ALLOW', 'final_risk': 0.20}
                fused_risk = 0.20
                logger.info(f"🛡️  Trusted+clean-rules override: {_td_verdict} → ALLOW (ML false-positive suppressed)")

            final_prob = fused_risk
        except Exception as _fe:
            logger.warning(f"Intelligent fusion failed: {_fe}")

        # ==================== BUG FIX 2 (applied here) ====================
        # Derive label from fusion verdict when available.
        # fusion ALLOW  → "Legitimate"  (even if final_prob is ~0.39)
        # fusion WARN   → "Suspicious"
        # fusion BLOCK  → "Phishing"
        # No fusion     → fall back to probability threshold
        _fusion_verdict = fusion_result.get('verdict') if fusion_result else None
        if _fusion_verdict == 'BLOCK':
            prediction_label = 'Phishing'
        elif _fusion_verdict == 'WARN':
            prediction_label = 'Suspicious'
        elif _fusion_verdict == 'ALLOW':
            prediction_label = 'Legitimate'
        else:
            prediction_label = _prediction_label(final_prob, THRESHOLD)
        logger.info(f"✅ {prediction_label} ({round(final_prob * 100, 2)}%) [fusion={_fusion_verdict}]")
        # ===================================================================

        # SHAP override notice: when a trusted domain's ML signals are overridden
        # by domain trust evidence, flag it so the frontend can show a clear notice
        # instead of misleading "phishing direction" SHAP arrows.
        if (shap_explanation
                and is_trusted_domain(extractor.domain)
                and _fusion_verdict == 'ALLOW'
                and base_prob > 0.6):
            shap_explanation['overridden'] = True
            shap_explanation['override_reason'] = (
                "ML feature signals were overridden by domain trust evidence "
                "(established domain age + trusted whitelist). "
                "The SHAP values below reflect URL structure analysis only — "
                "they do not determine the final verdict for trusted domains."
            )

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
                "slug_analysis":          _slug_analysis if _slug_analysis else None,
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

        # ── Campaign signature for correlation engine ──────────────────────
        try:
            _html_content = getattr(extractor, 'page_html', '') or ''
            _server_ip = domain_result.get('metadata', {}).get('ip_address', '') if domain_result else ''
            if not _server_ip:
                # Fallback: resolve IP from domain name
                try:
                    _server_ip = socket.gethostbyname(extractor.domain)
                except Exception:
                    _server_ip = 'unknown'

            # Free hosting platforms (Vercel, Netlify, GitHub Pages, etc.) use shared
            # CDN infrastructure — all sites on vercel.app resolve to the same IP pool.
            # Using that IP for campaign correlation would group thousands of unrelated
            # legitimate sites into one "campaign". Mark as 'shared_cdn' so Phase A
            # in the Express controller skips the server_ip match entirely.
            if is_free_hosting_subdomain(url):
                _server_ip = 'shared_cdn'

            response["campaign_signature"] = generate_campaign_signature(
                _html_content, _server_ip, probabilities
            )
        except Exception as _sig_err:
            logger.warning(f"Campaign signature generation failed (non-fatal): {_sig_err}")
            response["campaign_signature"] = {"html_hash": "", "server_ip": "unknown", "semantic_embedding": []}
        # ──────────────────────────────────────────────────────────────────

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
        "version": "6.0 - Four-Fix Update",
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
        # Hard 70s cap — ensures Flask always responds before Express's 90s timeout
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as _route_ex:
            _route_fut = _route_ex.submit(analyze_url_logic, url)
            try:
                result, status = _route_fut.result(timeout=70)
            except concurrent.futures.TimeoutError:
                logger.error(f"⏱️  analyze_url_logic timed out (70s) for: {url}")
                return jsonify({"error": "Analysis timed out — please try again"}), 503
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
    logger.info("🚀 PHISHING DETECTION API v6.0 - FOUR-FIX UPDATE")
    logger.info("   Fix 1: DNS-dead domains → fresh_phishing_setup via dns_failed flag")
    logger.info("   Fix 2: Nepal brand impersonation boost (+0.30 for known brands)")
    logger.info("   Fix 3: Unanimous ML vote boost (+0.08 in 0.50-0.65 near-miss zone)")
    logger.info("   Fix 4: Free-hosting subdomain detection (ghost.io, blogspot etc.)")
    logger.info("   (Prev) Fix A: Duplicate logs — use_reloader=False")
    logger.info("   (Prev) Fix B: 3-tier labels: Phishing / Suspicious / Legitimate")
    logger.info("   (Prev) Fix C: Unreachable/DNS-fail cloaking risk = 0.65 (not 0.30)")
    logger.info(f"✅ Detection: ML + Whitelist + Heuristics + Brand Check")
    logger.info(f"✅ Trusted domains: {len(TRUSTED_DOMAINS)}")
    logger.info(f"✅ Nepal brand map: {len(NEPAL_BRAND_MAP)} brands")
    logger.info(f"✅ Free hosting platforms: {len(FREE_HOSTING_PLATFORMS)}")
    logger.info("="*80)
    # ==================== BUG FIX 1 ====================
    # use_reloader=False prevents Werkzeug from importing the module twice,
    # which was the root cause of every log line appearing twice.
    # If you need live-reload during development, use an external tool like
    # watchdog/hupper instead, or accept that debug=True will double-log.
    app.run(host="0.0.0.0", port=5002, debug=True, use_reloader=False)
    # ====================================================


# import os
# from flask import Flask, request, jsonify
# from flask_cors import CORS
# import pickle
# import os
# import re
# import subprocess
# import requests
# from bs4 import BeautifulSoup
# from datetime import datetime
# from urllib.parse import urlparse
# from dateutil import parser as dateutil_parser
# import ipaddress
# import tldextract
# import logging
# import numpy as np
# import warnings
# import concurrent.futures
# import socket
# import urllib3
# warnings.filterwarnings('ignore')
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# # Import rule engine for hybrid detection
# from rule_engine import RuleEngine
# import shap

# # -------------------- NEW DETECTION MODULES --------------------
# from url_normalizer import URLNormalizer
# _url_normalizer = URLNormalizer()

# from domain_metadata_analyzer import DomainMetadataAnalyzer
# _domain_analyzer = DomainMetadataAnalyzer()

# from cloaking_detector import CloakingDetector
# _cloaking_detector = CloakingDetector(enable_headless=True)

# from intelligent_fusion import IntelligentFusion
# _fusion_engine = IntelligentFusion()

# from visual_similarity import VisualSimilarityAnalyzer
# _visual_analyzer = VisualSimilarityAnalyzer(
#     brand_db_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'brand_database')
# )

# # -------------------- APP SETUP --------------------
# app = Flask(__name__)
# CORS(app, resources={
#     r"/*": {
#         "origins": ["http://localhost:3000", "http://127.0.0.1:3000"],
#         "methods": ["GET", "POST", "OPTIONS"],
#         "allow_headers": ["Content-Type", "Authorization"],
#         "supports_credentials": True
#     }
# })

# # ==================== BUG FIX 1: DUPLICATE LOGS ====================
# # Do NOT use basicConfig when Flask debug=True + reloader is active,
# # as the module gets imported twice (master + reloader child process).
# # Instead configure a single named logger with a handler-existence check.
# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger(__name__)
# if not logger.handlers:
#     _handler = logging.StreamHandler()
#     _handler.setFormatter(logging.Formatter('%(levelname)s:%(name)s:%(message)s'))
#     logger.addHandler(_handler)
#     logger.propagate = False  # prevent double-logging via root logger
# # ===================================================================

# # -------------------- MODEL LOADING --------------------
# MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")

# UCI_BUNDLE_PATH       = os.path.join(MODEL_DIR, "phishing_model_bundle_websitephishing.pkl")
# REALISTIC_BUNDLE_PATH = os.path.join(MODEL_DIR, "phishing_model_bundle_REALISTIC_v3.pkl")

# logger.info("="*80)
# logger.info("🚀 Loading Model Bundle...")

# if os.path.exists(UCI_BUNDLE_PATH):
#     BUNDLE_PATH = UCI_BUNDLE_PATH
#     MODEL_TYPE  = 'uci'
#     logger.info("✅ Using UCI WebsitePhishing bundle (16 features)")
# elif os.path.exists(REALISTIC_BUNDLE_PATH):
#     BUNDLE_PATH = REALISTIC_BUNDLE_PATH
#     MODEL_TYPE  = 'realistic'
#     logger.info("✅ Using REALISTIC_v3 bundle (63 features)")
# else:
#     raise FileNotFoundError(f"No model bundle found in {MODEL_DIR}")

# with open(BUNDLE_PATH, 'rb') as f:
#     bundle = pickle.load(f)

# # Initialize Rule Engine
# rule_engine = RuleEngine()
# logger.info("✅ Rule Engine initialized")

# # -------------------- WHOIS via subprocess (Python-3.14 safe) --------------------
# class _WhoisInfo:
#     __slots__ = ('creation_date',)
#     def __init__(self, creation_date):
#         self.creation_date = creation_date

# _WHOIS_DATE_PATTERNS = [
#     re.compile(r'Creation Date\s*:\s*(.+)',              re.IGNORECASE),
#     re.compile(r'Domain Registration Date\s*:\s*(.+)',   re.IGNORECASE),
#     re.compile(r'Registration Date\s*:\s*(.+)',          re.IGNORECASE),
#     re.compile(r'Registered On\s*:\s*(.+)',              re.IGNORECASE),
#     re.compile(r'Registered\s*:\s*(.+)',                 re.IGNORECASE),
#     re.compile(r'created\s*:\s*(.+)',                    re.IGNORECASE),
# ]

# _WHOIS_DATE_FMTS = [
#     '%Y-%m-%dT%H:%M:%SZ',
#     '%Y-%m-%dT%H:%M:%S+0000',
#     '%Y-%m-%dT%H:%M:%S',
#     '%Y-%m-%d',
#     '%d-%b-%Y',
#     '%d/%m/%Y',
#     '%Y/%m/%d',
#     '%d.%m.%Y',
#     '%B %d, %Y',
#     '%d %B %Y',
# ]

# _WHOIS_PLACEHOLDER_DATE = datetime(1985, 1, 1)

# def _parse_whois_date(raw):
#     raw = raw.strip()[:40]
#     for fmt in _WHOIS_DATE_FMTS:
#         try:
#             return datetime.strptime(raw, fmt).replace(tzinfo=None)
#         except ValueError:
#             pass
#     try:
#         return dateutil_parser.parse(raw, ignoretz=True)
#     except Exception:
#         pass
#     return None

# def safe_whois(domain, timeout_sec=8):
#     domain = domain.split(':')[0].strip().lstrip('.')
#     if not domain:
#         return None
#     try:
#         proc = subprocess.run(
#             ['whois', domain],
#             capture_output=True, text=True, timeout=timeout_sec
#         )
#         text = proc.stdout or ''
#         for pat in _WHOIS_DATE_PATTERNS:
#             for m in pat.finditer(text):
#                 dt = _parse_whois_date(m.group(1))
#                 if dt and dt != _WHOIS_PLACEHOLDER_DATE and dt.year > 1990:
#                     logger.info(f"WHOIS {domain}: created {dt.date()} ({(datetime.now()-dt).days} days ago)")
#                     return _WhoisInfo(dt)
#         logger.debug(f"WHOIS: no valid creation date found for {domain}")
#         return None
#     except subprocess.TimeoutExpired:
#         logger.warning(f"WHOIS timeout for {domain} (>{timeout_sec}s)")
#         return None
#     except FileNotFoundError:
#         logger.warning("'whois' CLI not found — domain age unavailable")
#         return None
#     except Exception as e:
#         logger.warning(f"WHOIS lookup failed for {domain}: {e}")
#         return None

# # Load models based on bundle type
# if MODEL_TYPE == 'uci':
#     MODELS = {}
#     for key in ['lgb', 'xgb', 'catboost', 'rf']:
#         if key in bundle:
#             MODELS[key] = bundle[key]
#     if 'stacking' in bundle:
#         MODELS['stacking'] = bundle['stacking']
#     SCALER = None
# else:
#     MODELS = {
#         'gradient_boosting': bundle['gradient_boosting'],
#         'xgboost':           bundle['xgboost'],
#         'catboost':          bundle['catboost'],
#         'random_forest':     bundle['random_forest'],
#     }
#     SCALER = bundle['scaler']

# FEATURE_NAMES  = bundle['feature_names']
# THRESHOLD      = bundle.get('optimal_threshold', 0.5)
# MODEL_METRICS  = bundle.get('model_metrics', {})

# TRUSTED_DOMAINS = {
#     'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'apple.com',
#     'microsoft.com', 'github.com', 'stackoverflow.com', 'reddit.com',
#     'twitter.com', 'x.com', 'linkedin.com', 'netflix.com', 'wikipedia.org',
#     'yahoo.com', 'bing.com', 'instagram.com', 'tiktok.com', 'zoom.us',
#     'dropbox.com', 'adobe.com', 'ebay.com', 'paypal.com', 'spotify.com',
#     'claude.ai', 'anthropic.com',
#     'openai.com', 'chatgpt.com', 'huggingface.co',
#     'notion.so', 'figma.com', 'canva.com', 'slack.com', 'discord.com',
#     'whatsapp.com', 'telegram.org', 'signal.org',
#     # Sports & News
#     'espncricinfo.com', 'espn.com', 'bbc.com', 'bbc.co.uk', 'cnn.com',
#     'nytimes.com', 'theguardian.com', 'reuters.com', 'apnews.com',
#     'cricbuzz.com', 'icc-cricket.com', 'fifa.com', 'nfl.com', 'nba.com',
#     # Nepal
#     'onlinekhabar.com', 'ekantipur.com', 'kantipurtv.com', 'ratopati.com',
#     'setopati.com', 'nagariknetwork.com',
#     # Banking / Finance
#     'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com',
#     'hsbc.com', 'barclays.co.uk',
#     # Tech / Cloud
#     'aws.amazon.com', 'azure.com', 'cloud.google.com',
#     'onedrive.live.com', 'office.com', 'live.com', 'outlook.com',
#     'salesforce.com', 'shopify.com', 'wordpress.com', 'wix.com',
# }

# logger.info(f"✅ Model type: {MODEL_TYPE.upper()}")
# logger.info(f"✅ Loaded {len(MODELS)} models")
# logger.info(f"✅ Features: {len(FEATURE_NAMES)}")
# logger.info(f"✅ Trusted domains: {len(TRUSTED_DOMAINS)}")

# # -------------------- SHAP EXPLAINERS --------------------
# SHAP_EXPLAINERS = {}
# for _name, _model in MODELS.items():
#     try:
#         SHAP_EXPLAINERS[_name] = shap.TreeExplainer(_model)
#         logger.info(f"✅ SHAP explainer ready: {_name}")
#     except Exception as _e:
#         logger.warning(f"⚠️  SHAP not available for {_name}: {_e}")

# logger.info("="*80)

# # -------------------- FEATURE EXTRACTION --------------------
# class FeatureExtractor:
#     def __init__(self, url):
#         self.url = url.strip()
#         self.parsed = urlparse(self.url)
#         self.domain = self.parsed.netloc.replace("www.", "").lower().strip()
#         self.whois_response = None
#         self.page_html = ""
#         self.soup = None

#         if self._is_suspicious():
#             self.whois_response = safe_whois(self.domain)

#         self._fetch_page()

#     def _is_suspicious(self):
#         return any([
#             self.domain.count("-") > 2,
#             len(self.domain) > 30,
#             bool(re.search(r"login|secure|verify|update|account", self.url, re.I)),
#             self._has_ip(),
#         ])

#     def _has_ip(self):
#         try:
#             ipaddress.ip_address(self.domain)
#             return True
#         except Exception:
#             return False

#     def _fetch_page(self):
#         try:
#             resp = requests.get(
#                 self.url, timeout=5, allow_redirects=True,
#                 headers={"User-Agent": "Mozilla/5.0"},
#                 verify=False
#             )
#             self.page_html = resp.text
#             self.soup = BeautifulSoup(self.page_html, "html.parser")
#         except Exception:
#             self.page_html = ""
#             self.soup = None

#     def _url_length(self): return len(self.url)
#     def _domain_length(self): return len(self.domain)
#     def _is_domain_ip(self): return 1 if self._has_ip() else 0
#     def _tld_length(self): return len(tldextract.extract(self.url).suffix)
#     def _no_of_subdomain(self): return self.domain.count(".")
#     def _is_https(self): return 1 if self.parsed.scheme == "https" else 0

#     def _letter_ratio(self):
#         n = sum(c.isalpha() for c in self.url)
#         return n / max(1, len(self.url))

#     def _no_of_digits(self): return sum(c.isdigit() for c in self.url)
#     def _digit_ratio(self): return self._no_of_digits() / max(1, len(self.url))
#     def _no_of_equals(self): return self.url.count("=")
#     def _no_of_qmark(self): return self.url.count("?")
#     def _no_of_ampersand(self): return self.url.count("&")

#     def _no_of_other_special(self):
#         standard = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=?&.:/_-@#")
#         return sum(1 for c in self.url if c not in standard)

#     def _special_char_ratio(self):
#         return sum(1 for c in self.url if not c.isalnum()) / max(1, len(self.url))

#     def _has_obfuscation(self):
#         return 1 if re.search(r"%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|&#\d+;", self.url) else 0

#     def _no_of_obfuscated_chars(self):
#         return len(re.findall(r"%[0-9a-fA-F]{2}|\\x[0-9a-fA-F]{2}|&#\d+;", self.url))

#     def _obfuscation_ratio(self):
#         return self._no_of_obfuscated_chars() / max(1, len(self.url))

#     def _url_similarity_index(self):
#         n = sum(c.isalnum() or c in ".-/" for c in self.url)
#         return n / max(1, len(self.url))

#     def _char_continuation_rate(self):
#         if not self.url:
#             return 0.0
#         max_run = cur_run = 1
#         for i in range(1, len(self.url)):
#             if self.url[i].isalpha() == self.url[i - 1].isalpha():
#                 cur_run += 1
#                 max_run = max(max_run, cur_run)
#             else:
#                 cur_run = 1
#         return max_run / max(1, len(self.url))

#     def _tld_legit_prob(self):
#         legit = {"com": 0.95, "org": 0.85, "net": 0.80, "edu": 0.95,
#                  "gov": 0.98, "co": 0.75, "io": 0.70, "uk": 0.80}
#         return legit.get(tldextract.extract(self.url).suffix.lower(), 0.3)

#     def _url_char_prob(self):
#         n = sum(1 for c in self.url if c.isalnum() or c in ".-/:#@_")
#         return n / max(1, len(self.url))

#     def _domain_age_days(self):
#         base = ".".join(self.domain.split(".")[-2:])
#         if base in TRUSTED_DOMAINS:
#             return 7300
#         try:
#             if not self.whois_response:
#                 return -1
#             cd = self.whois_response.creation_date
#             if isinstance(cd, list):
#                 cd = cd[0]
#             return max(0, (datetime.now() - cd).days) if cd else -1
#         except Exception:
#             return -1

#     def _lines(self):
#         return self.page_html.splitlines() if self.page_html else []

#     def _line_of_code(self): return min(len(self._lines()), 50000)
#     def _largest_line_length(self):
#         return min(max((len(l) for l in self._lines()), default=0), 500000)

#     def _has_title(self):
#         return 1 if (self.soup and self.soup.find("title")) else 0

#     def _get_title_text(self):
#         if not self.soup:
#             return ""
#         tag = self.soup.find("title")
#         return tag.get_text(strip=True).lower() if tag else ""

#     def _domain_title_match_score(self):
#         title = self._get_title_text()
#         if not title:
#             return 0.0
#         base = self.domain.split(".")[0].lower()
#         if base in title:
#             return 1.0
#         return sum(1 for c in base if c in title) / max(1, len(base))

#     def _url_title_match_score(self):
#         title = self._get_title_text()
#         if not title:
#             return 0.0
#         url_lower = self.url.lower()
#         url_words = set([w for w in re.findall(r'[a-z]{3,}', url_lower)])
#         title_words = set([w for w in re.findall(r'[a-z]{3,}', title)])
#         if not url_words:
#             return 0.0
#         matches = url_words & title_words
#         return len(matches) / len(url_words) if url_words else 0.0

#     def _has_favicon(self):
#         if not self.soup:
#             return 0
#         links = self.soup.find_all("link", rel=lambda r: r and "icon" in " ".join(r).lower())
#         return 1 if links else 0

#     def _robots(self):
#         if not self.soup:
#             return 0
#         meta = self.soup.find("meta", attrs={"name": re.compile(r"robots", re.I)})
#         if meta:
#             content = meta.get("content", "").lower()
#             return 0 if ("noindex" in content or "nofollow" in content) else 1
#         return 1

#     def _is_responsive(self):
#         if not self.soup:
#             return 0
#         return 1 if self.soup.find("meta", attrs={"name": re.compile(r"viewport", re.I)}) else 0

#     def _no_of_url_redirect(self):
#         if not self.soup:
#             return 0
#         html = str(self.soup)
#         return min(len(re.findall(r"redirect|location\.href", html, re.I)), 100)

#     def _no_of_self_redirect(self):
#         if not self.soup:
#             return 0
#         count = sum(
#             1 for a in self.soup.find_all("a", href=True)
#             if self.domain in a["href"] and "redirect" in a["href"].lower()
#         )
#         return min(count, 100)

#     def _has_description(self):
#         if not self.soup:
#             return 0
#         meta = self.soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
#         return 1 if (meta and meta.get("content")) else 0

#     def _no_of_popup(self):
#         if not self.soup:
#             return 0
#         return min(len(re.findall(r"window\.open|alert\(|confirm\(|popup", str(self.soup), re.I)), 50)

#     def _no_of_iframe(self):
#         return min(len(self.soup.find_all("iframe")), 50) if self.soup else 0

#     def _has_external_form_submit(self):
#         if not self.soup:
#             return 0
#         for form in self.soup.find_all("form"):
#             action = form.get("action", "")
#             if action and self.domain not in action and action.startswith("http"):
#                 return 1
#         return 0

#     def _has_social_net(self):
#         if not self.soup:
#             return 0
#         social = ["facebook.com", "twitter.com", "instagram.com", "linkedin.com",
#                   "youtube.com", "t.co", "x.com"]
#         html = str(self.soup).lower()
#         return 1 if any(s in html for s in social) else 0

#     def _has_submit_button(self):
#         if not self.soup:
#             return 0
#         return 1 if (self.soup.find("input", type="submit") or
#                      self.soup.find("button", type="submit")) else 0

#     def _has_hidden_fields(self):
#         return 1 if (self.soup and self.soup.find("input", type="hidden")) else 0

#     def _has_password_field(self):
#         return 1 if (self.soup and self.soup.find("input", type="password")) else 0

#     def _bank(self):
#         return 1 if any(w in self.url.lower() for w in ["bank", "banking", "finance", "financial"]) else 0

#     def _pay(self):
#         return 1 if any(w in self.url.lower() for w in ["pay", "payment", "checkout", "invoice"]) else 0

#     def _crypto(self):
#         return 1 if any(w in self.url.lower() for w in ["crypto", "bitcoin", "btc", "wallet", "ethereum"]) else 0

#     def _has_copyright(self):
#         if not self.soup:
#             return 0
#         html = str(self.soup).lower()
#         return 1 if ("©" in html or "copyright" in html or "&copy;" in html) else 0

#     def _no_of_image(self):
#         return min(len(self.soup.find_all("img")), 1000) if self.soup else 0

#     def _no_of_css(self):
#         if not self.soup:
#             return 0
#         return min(len(self.soup.find_all("link", rel=lambda r: r and "stylesheet" in " ".join(r).lower())), 200)

#     def _no_of_js(self):
#         return min(len(self.soup.find_all("script")), 300) if self.soup else 0

#     def _no_of_self_ref(self):
#         if not self.soup:
#             return 0
#         return min(sum(
#             1 for a in self.soup.find_all("a", href=True)
#             if self.domain in a["href"] or a["href"].startswith("/")
#         ), 1000)

#     def _no_of_empty_ref(self):
#         if not self.soup:
#             return 0
#         return min(sum(
#             1 for a in self.soup.find_all("a", href=True)
#             if not a["href"] or a["href"] in ["#", "javascript:void(0)", "javascript:;"]
#         ), 500)

#     def _no_of_external_ref(self):
#         if not self.soup:
#             return 0
#         return min(sum(
#             1 for a in self.soup.find_all("a", href=True)
#             if a["href"].startswith("http") and self.domain not in a["href"]
#         ), 1000)

#     def extract(self):
#         import math

#         url_len      = self._url_length()
#         dom_len      = self._domain_length()
#         is_ip        = self._is_domain_ip()
#         url_sim      = self._url_similarity_index()
#         char_cont    = self._char_continuation_rate()
#         tld_legit    = self._tld_legit_prob()
#         url_char     = self._url_char_prob()
#         tld_len      = self._tld_length()
#         n_sub        = self._no_of_subdomain()
#         has_obf      = self._has_obfuscation()
#         n_obf        = self._no_of_obfuscated_chars()
#         obf_ratio    = self._obfuscation_ratio()
#         letter_ratio = self._letter_ratio()
#         n_digits     = self._no_of_digits()
#         digit_ratio  = self._digit_ratio()
#         n_equals     = self._no_of_equals()
#         n_qmark      = self._no_of_qmark()
#         n_amp        = self._no_of_ampersand()
#         n_other_sp   = self._no_of_other_special()
#         sp_ratio     = self._special_char_ratio()
#         is_https     = self._is_https()
#         loc          = self._line_of_code()
#         largest_line = self._largest_line_length()
#         h_title      = self._has_title()
#         dom_title    = self._domain_title_match_score()
#         url_title    = self._url_title_match_score()
#         h_favicon    = self._has_favicon()
#         robots_val   = self._robots()
#         is_resp      = self._is_responsive()
#         n_redirect   = self._no_of_url_redirect()
#         n_self_redir = self._no_of_self_redirect()
#         h_desc       = self._has_description()
#         n_popup      = self._no_of_popup()
#         n_iframe     = self._no_of_iframe()
#         h_ext_form   = self._has_external_form_submit()
#         h_social     = self._has_social_net()
#         h_submit     = self._has_submit_button()
#         h_hidden     = self._has_hidden_fields()
#         h_password   = self._has_password_field()
#         bank         = self._bank()
#         pay          = self._pay()
#         crypto       = self._crypto()
#         h_copyright  = self._has_copyright()
#         n_img        = self._no_of_image()
#         n_css        = self._no_of_css()
#         n_js         = self._no_of_js()
#         n_self_ref   = self._no_of_self_ref()
#         n_empty_ref  = self._no_of_empty_ref()
#         n_ext_ref    = self._no_of_external_ref()

#         obf_ip_risk    = is_ip * has_obf
#         insecure_pwd   = (1 - is_https) * h_password
#         page_complete  = n_self_ref / (n_ext_ref + 1)
#         legit_score    = h_title + h_favicon + h_desc + h_copyright + is_resp
#         sus_fin        = (bank + pay + crypto) * (1 - h_copyright)
#         title_combined = float(np.sqrt(dom_title * url_title))

#         features = {
#             "URLLength":                    url_len,
#             "DomainLength":                 dom_len,
#             "IsDomainIP":                   is_ip,
#             "URLSimilarityIndex":           url_sim,
#             "CharContinuationRate":         char_cont,
#             "TLDLegitimateProb":            tld_legit,
#             "URLCharProb":                  url_char,
#             "TLDLength":                    tld_len,
#             "NoOfSubDomain":                n_sub,
#             "HasObfuscation":               has_obf,
#             "NoOfObfuscatedChar":           n_obf,
#             "ObfuscationRatio":             obf_ratio,
#             "LetterRatioInURL":             letter_ratio,
#             "NoOfDegitsInURL":              n_digits,
#             "DegitRatioInURL":              digit_ratio,
#             "NoOfEqualsInURL":              n_equals,
#             "NoOfQMarkInURL":               n_qmark,
#             "NoOfAmpersandInURL":           n_amp,
#             "NoOfOtherSpecialCharsInURL":   n_other_sp,
#             "SpacialCharRatioInURL":        sp_ratio,
#             "IsHTTPS":                      is_https,
#             "LineOfCode":                   loc,
#             "LargestLineLength":            largest_line,
#             "HasTitle":                     h_title,
#             "DomainTitleMatchScore":        dom_title,
#             "URLTitleMatchScore":           url_title,
#             "HasFavicon":                   h_favicon,
#             "Robots":                       robots_val,
#             "IsResponsive":                 is_resp,
#             "NoOfURLRedirect":              n_redirect,
#             "NoOfSelfRedirect":             n_self_redir,
#             "HasDescription":               h_desc,
#             "NoOfPopup":                    n_popup,
#             "NoOfiFrame":                   n_iframe,
#             "HasExternalFormSubmit":        h_ext_form,
#             "HasSocialNet":                 h_social,
#             "HasSubmitButton":              h_submit,
#             "HasHiddenFields":              h_hidden,
#             "HasPasswordField":             h_password,
#             "Bank":                         bank,
#             "Pay":                          pay,
#             "Crypto":                       crypto,
#             "HasCopyrightInfo":             h_copyright,
#             "NoOfImage":                    n_img,
#             "NoOfCSS":                      n_css,
#             "NoOfJS":                       n_js,
#             "NoOfSelfRef":                  n_self_ref,
#             "NoOfEmptyRef":                 n_empty_ref,
#             "NoOfExternalRef":              n_ext_ref,
#             "ObfuscationIPRisk":            obf_ip_risk,
#             "InsecurePasswordField":        insecure_pwd,
#             "PageCompletenessRatio":        page_complete,
#             "LegitContentScore":            legit_score,
#             "SuspiciousFinancialFlag":      sus_fin,
#             "TitleMatchCombined":           title_combined,
#             "LineOfCode_log":               math.log1p(loc),
#             "LargestLineLength_log":        math.log1p(largest_line),
#             "NoOfExternalRef_log":          math.log1p(n_ext_ref),
#             "NoOfSelfRef_log":              math.log1p(n_self_ref),
#             "NoOfCSS_log":                  math.log1p(n_css),
#             "NoOfJS_log":                   math.log1p(n_js),
#             "NoOfImage_log":                math.log1p(n_img),
#             "NoOfEmptyRef_log":             math.log1p(n_empty_ref),
#             "URLLength_log":                math.log1p(url_len),
#             "DomainLength_log":             math.log1p(dom_len),
#             "NoOfPopup_log":                math.log1p(n_popup),
#             "NoOfURLRedirect_log":          math.log1p(n_redirect),
#             "NoOfiFrame_log":               math.log1p(n_iframe),
#         }

#         vector = np.array([features.get(f, 0) for f in FEATURE_NAMES])
#         return vector.reshape(1, -1), features


# # -------------------- UCI FEATURE EXTRACTOR --------------------
# class UCIFeatureExtractor:
#     UCI_FEATURE_COLS = [
#         'SFH', 'popUpWidnow', 'SSLfinal_State', 'Request_URL',
#         'URL_of_Anchor', 'web_traffic', 'URL_Length', 'age_of_domain',
#         'having_IP_Address'
#     ]

#     def __init__(self, url):
#         self.url = url.strip()
#         self.parsed = urlparse(self.url)
#         self.domain = self.parsed.netloc.split(':')[0].replace("www.", "").lower().strip()
#         _ext = tldextract.extract(self.url)
#         _whois_domain = (
#             f"{_ext.domain}.{_ext.suffix}"
#             if _ext.domain and _ext.suffix
#             else self.domain
#         )
#         self.whois_response = safe_whois(_whois_domain)
#         self.page_html = ""
#         self.soup = None
#         self._fetch_page()

#     def _fetch_page(self):
#         try:
#             resp = requests.get(
#                 self.url, timeout=5, allow_redirects=True,
#                 headers={"User-Agent": "Mozilla/5.0"},
#                 verify=False
#             )
#             self.page_html = resp.text
#             self.soup = BeautifulSoup(self.page_html, "html.parser")
#         except Exception:
#             self.page_html = ""
#             self.soup = None

#     def _has_ip(self):
#         try:
#             ipaddress.ip_address(self.domain)
#             return True
#         except Exception:
#             return False

#     def _having_ip_address(self):
#         return 1 if self._has_ip() else 0

#     def _ssl_final_state(self):
#         return 1 if self.parsed.scheme == 'https' else -1

#     def _url_length(self):
#         n = len(self.url)
#         if n < 54:
#             return 1
#         elif n <= 75:
#             return 0
#         return -1

#     def _age_of_domain(self):
#         base = '.'.join(self.domain.split('.')[-2:])
#         if base in TRUSTED_DOMAINS:
#             return 1
#         try:
#             if not self.whois_response:
#                 return 0
#             cd = self.whois_response.creation_date
#             if isinstance(cd, list):
#                 cd = cd[0]
#             if cd:
#                 return 1 if (datetime.now() - cd).days >= 180 else -1
#             return 0
#         except Exception:
#             return 0

#     def _get_domain_age_days(self):
#         try:
#             if not self.whois_response:
#                 return None
#             cd = self.whois_response.creation_date
#             if isinstance(cd, list):
#                 cd = cd[0]
#             if cd:
#                 return max(0, (datetime.now() - cd).days)
#             return None
#         except Exception:
#             return None

#     def _get_recent_content(self):
#         if not self.soup:
#             return None, False
#         og_time = self.soup.find("meta", property="article:published_time")
#         if og_time and og_time.get("content"):
#             return og_time["content"][:50], True
#         for time_el in self.soup.find_all("time", datetime=True):
#             dt_val = time_el.get("datetime", "").strip()
#             if dt_val:
#                 return dt_val[:50], True
#         for script in self.soup.find_all("script", type="application/ld+json"):
#             text = script.get_text()
#             if "datePublished" in text:
#                 m = re.search(r'"datePublished"\s*:\s*"([^"]+)"', text)
#                 if m:
#                     return m.group(1)[:50], True
#         return None, False

#     def _get_subdomain_info(self):
#         ext = tldextract.extract(self.url)
#         subdomain = ext.subdomain or ''
#         parts = [s for s in subdomain.split('.') if s] if subdomain else []
#         return {
#             'subdomain':       subdomain,
#             'domain_name':     ext.domain or '',
#             'tld':             ext.suffix or '',
#             'subdomain_count': len(parts)
#         }

#     def _enumerate_subdomains(self):
#         ext = tldextract.extract(self.url)
#         if not ext.domain or not ext.suffix:
#             return {'found': [], 'count': 0, 'base_domain': '', 'sources': []}

#         base_domain = f"{ext.domain}.{ext.suffix}"
#         discovered = set()
#         sources = []

#         try:
#             # stream=True + read cap avoids blocking on huge CT logs (e.g. claude.ai has 100s of certs)
#             ct_resp = requests.get(
#                 f"https://crt.sh/?q=%.{base_domain}&output=json",
#                 timeout=(4, 12),   # 4s connect, 12s read
#                 headers={"User-Agent": "Mozilla/5.0 PhishNet/1.0"},
#                 stream=True
#             )
#             if ct_resp.status_code == 200:
#                 import json as _json
#                 ct_content = ct_resp.raw.read(512 * 1024, decode_content=True)  # max 512 KB
#                 for cert in _json.loads(ct_content):
#                     for name in cert.get('name_value', '').split('\n'):
#                         name = name.strip().lower().lstrip('*.')
#                         if name.endswith(f'.{base_domain}') and name != base_domain:
#                             sub = name[:-len(f'.{base_domain}')]
#                             if sub and '.' not in sub:
#                                 discovered.add(sub)
#                 if discovered:
#                     sources.append('crt.sh')
#                     logger.info(f"crt.sh found {len(discovered)} subdomains for {base_domain}")
#         except Exception as e:
#             logger.debug(f"crt.sh lookup failed for {base_domain}: {e}")

#         COMMON_SUBS = [
#             'www', 'mail', 'webmail', 'smtp', 'pop', 'pop3', 'imap',
#             'ftp', 'sftp', 'api', 'api2', 'v1', 'v2', 'v3',
#             'admin', 'administrator', 'panel', 'cpanel', 'whm', 'dashboard',
#             'login', 'secure', 'auth', 'sso', 'app', 'apps', 'mobile', 'm',
#             'blog', 'shop', 'store', 'checkout', 'pay', 'payment',
#             'dev', 'staging', 'stg', 'test', 'qa', 'sandbox',
#             'cdn', 'static', 'assets', 'images', 'img', 'media',
#             'vpn', 'remote', 'support', 'help', 'docs', 'portal',
#             'ns1', 'ns2', 'mx', 'mx1', 'mx2',
#         ]

#         def _dns_resolve(sub):
#             try:
#                 socket.getaddrinfo(f"{sub}.{base_domain}", None)
#                 return sub
#             except Exception:
#                 return None

#         dns_new = []
#         executor = concurrent.futures.ThreadPoolExecutor(max_workers=25)
#         try:
#             futures = {executor.submit(_dns_resolve, s): s for s in COMMON_SUBS}
#             for future in concurrent.futures.as_completed(futures, timeout=8):
#                 result = future.result()
#                 if result:
#                     dns_new.append(result)
#                     discovered.add(result)
#         except concurrent.futures.TimeoutError:
#             pass
#         finally:
#             executor.shutdown(wait=False)

#         if dns_new:
#             sources.append('DNS')
#             logger.info(f"DNS brute-force found {len(dns_new)} subdomains for {base_domain}")

#         sorted_subs = sorted(discovered)[:60]
#         return {
#             'found':       sorted_subs,
#             'count':       len(sorted_subs),
#             'base_domain': base_domain,
#             'sources':     sources,
#         }

#     def _sfh(self):
#         if not self.soup:
#             return 0
#         for form in self.soup.find_all("form"):
#             action = form.get("action", "").strip()
#             if not action:
#                 continue
#             if action.startswith("http") and self.domain not in action:
#                 return -1
#             if action.startswith("/") or self.domain in action:
#                 return 1
#         return 0

#     def _popup_widnow(self):
#         if not self.soup:
#             return -1
#         popups = re.findall(r"window\.open|alert\(|confirm\(|popup", str(self.soup), re.I)
#         return 1 if popups else -1

#     def _request_url(self):
#         if not self.soup:
#             return 0
#         total = 0
#         external = 0
#         for tag in self.soup.find_all(["img", "script"]):
#             src = tag.get("src", "")
#             if src:
#                 total += 1
#                 if src.startswith("http") and self.domain not in src:
#                     external += 1
#         for tag in self.soup.find_all("link", rel=lambda r: r and "stylesheet" in " ".join(r).lower()):
#             href = tag.get("href", "")
#             if href:
#                 total += 1
#                 if href.startswith("http") and self.domain not in href:
#                     external += 1
#         if total == 0:
#             return 0
#         ratio = external / total
#         if ratio < 0.22:
#             return 1
#         elif ratio < 0.61:
#             return 0
#         return -1

#     def _url_of_anchor(self):
#         if not self.soup:
#             return 0
#         total = 0
#         external = 0
#         for a in self.soup.find_all("a", href=True):
#             href = a["href"].strip()
#             if not href or href in ["#", "javascript:void(0)", "javascript:;"]:
#                 continue
#             total += 1
#             if href.startswith("http") and self.domain not in href:
#                 external += 1
#         if total == 0:
#             return 1
#         ratio = external / total
#         if ratio < 0.31:
#             return 1
#         elif ratio < 0.67:
#             return 0
#         return -1

#     def _web_traffic(self):
#         base = '.'.join(self.domain.split('.')[-2:])
#         if base in TRUSTED_DOMAINS:
#             return 1
#         if self.soup:
#             has_title   = bool(self.soup.find("title") and self.soup.find("title").get_text(strip=True))
#             has_favicon = bool(self.soup.find_all("link", rel=lambda r: r and "icon" in " ".join(r).lower()))
#             if has_title or has_favicon:
#                 return 0
#         return -1

#     def extract(self):
#         raw = {
#             'SFH':               self._sfh(),
#             'popUpWidnow':       self._popup_widnow(),
#             'SSLfinal_State':    self._ssl_final_state(),
#             'Request_URL':       self._request_url(),
#             'URL_of_Anchor':     self._url_of_anchor(),
#             'web_traffic':       self._web_traffic(),
#             'URL_Length':        self._url_length(),
#             'age_of_domain':     self._age_of_domain(),
#             'having_IP_Address': self._having_ip_address(),
#         }

#         phish_count = sum(1 for f in self.UCI_FEATURE_COLS if raw[f] == -1)
#         legit_count = sum(1 for f in self.UCI_FEATURE_COLS if raw[f] == 1)
#         net_score   = sum(raw[f] for f in self.UCI_FEATURE_COLS)

#         features = {
#             **raw,
#             'PhishingSignalCount': phish_count,
#             'LegitSignalCount':    legit_count,
#             'NetScore':            net_score,
#             'PhishingSignalRatio': phish_count / len(self.UCI_FEATURE_COLS),
#             'NoSSL_HasIP':         int(raw['SSLfinal_State'] == -1 and raw['having_IP_Address'] == 1),
#             'BadSFH_BadSSL':       int(raw['SFH'] == -1 and raw['SSLfinal_State'] == -1),
#             'YoungDomain_NoSSL':   int(raw['age_of_domain'] == -1 and raw['SSLfinal_State'] == -1),
#         }

#         age_days = self._get_domain_age_days()
#         recent_date, is_active = self._get_recent_content()
#         sub_info = self._get_subdomain_info()
#         sub_enum = self._enumerate_subdomains()
#         features['_domain_age_days']     = age_days
#         features['_recent_content_date'] = recent_date
#         features['_is_recently_active']  = is_active
#         features['_subdomain']           = sub_info['subdomain']
#         features['_domain_name']         = sub_info['domain_name']
#         features['_tld']                 = sub_info['tld']
#         features['_subdomain_count']     = sub_info['subdomain_count']
#         features['_url_raw_length']      = len(self.url)
#         features['_subdomain_enum']      = sub_enum

#         vector = np.array([features.get(f, 0) for f in FEATURE_NAMES])
#         return vector.reshape(1, -1), features


# # -------------------- RISK CALCULATION --------------------
# def is_trusted_domain(domain):
#     base_domain = '.'.join(domain.split('.')[-2:])
#     return base_domain in TRUSTED_DOMAINS

# def calculate_phishing_score(features, model_probabilities):
#     base_score = float(np.mean(list(model_probabilities.values())))
#     boost = 0.0
#     reasons = []

#     domain = features.get("_domain", "")
#     if is_trusted_domain(domain):
#         boost -= 0.10
#         reasons.append("Domain is in trusted whitelist (legitimacy signal)")

#     if features.get("IsDomainIP", 0) == 1:
#         boost += 0.35
#         reasons.append("IP address used instead of domain name")

#     if features.get("HasObfuscation", 0) == 1:
#         boost += 0.20
#         reasons.append(f"URL obfuscation detected ({features.get('NoOfObfuscatedChar', 0)} chars)")

#     if features.get("InsecurePasswordField", 0) == 1:
#         boost += 0.30
#         reasons.append("Password field on non-HTTPS page")

#     if features.get("IsHTTPS", 0) == 0:
#         boost += 0.10
#         reasons.append("No HTTPS encryption")

#     dom_len = features.get("DomainLength", 0)
#     if dom_len > 40:
#         boost += 0.20
#         reasons.append(f"Very long domain ({dom_len} chars)")
#     elif dom_len > 30:
#         boost += 0.10
#         reasons.append(f"Long domain ({dom_len} chars)")

#     if features.get("SuspiciousFinancialFlag", 0) > 0:
#         boost += 0.15
#         reasons.append("Financial keywords without legitimacy markers")

#     if features.get("HasExternalFormSubmit", 0) == 1:
#         boost += 0.20
#         reasons.append("Form submits to external domain")

#     legit = features.get("LegitContentScore", 0)
#     if legit == 0:
#         boost += 0.15
#         reasons.append("No legitimacy markers (title/favicon/description/copyright)")
#     elif legit == 1:
#         boost += 0.08
#         reasons.append("Very few legitimacy markers")

#     if features.get("Crypto", 0) == 1:
#         boost += 0.10
#         reasons.append("Cryptocurrency keywords detected")

#     final_score = max(0.01, min(base_score + boost, 0.99))
#     return final_score, boost, reasons, base_score

# def calculate_phishing_score_uci(features, model_probabilities):
#     base_score = float(np.mean(list(model_probabilities.values())))
#     boost = 0.0
#     reasons = []

#     domain = features.get("_domain", "")
#     if is_trusted_domain(domain):
#         boost -= 0.30
#         reasons.append("Domain is in trusted whitelist (strong legitimacy signal)")
        
#     net_score   = features.get("NetScore", 0)
#     legit_count = features.get("LegitSignalCount", 0)

#     if net_score >= 3:
#         boost -= 0.15
#         reasons.append(f"Strong legitimate feature profile (NetScore: {net_score})")
#     elif net_score >= 1:
#         boost -= 0.08
#         reasons.append(f"Moderate legitimate feature profile (NetScore: {net_score})")
#     elif net_score <= -3:
#         boost += 0.15
#         reasons.append(f"Strong phishing feature profile (NetScore: {net_score})")
#     elif net_score <= -1:
#         boost += 0.08
#         reasons.append(f"Moderate phishing feature profile (NetScore: {net_score})")

#     if legit_count >= 4:
#         boost -= 0.10
#         reasons.append(f"Multiple legitimate indicators ({legit_count}/9 UCI features)")

#     if features.get("having_IP_Address", 0) == 1:
#         boost += 0.35
#         reasons.append("IP address used instead of domain name")

#     if features.get("SSLfinal_State", 1) == -1:
#         boost += 0.15
#         reasons.append("No HTTPS encryption")

#     if features.get("SFH", 0) == -1:
#         boost += 0.20
#         reasons.append("Form submits to external domain")

#     if features.get("age_of_domain", 1) == -1:
#         boost += 0.10
#         reasons.append("New or unknown domain age")

#     if features.get("popUpWidnow", -1) == 1:
#         boost += 0.05
#         reasons.append("Popup windows detected")

#     if features.get("NoSSL_HasIP", 0) == 1:
#         boost += 0.20
#         reasons.append("IP address without HTTPS (high-risk combination)")

#     if features.get("BadSFH_BadSSL", 0) == 1:
#         boost += 0.15
#         reasons.append("External form submission + no HTTPS (credential theft risk)")

#     phish_count = features.get("PhishingSignalCount", 0)
#     if phish_count >= 5:
#         boost += 0.20
#         reasons.append(f"Many phishing signals detected ({phish_count}/9 features)")
#     elif phish_count >= 3:
#         boost += 0.10
#         reasons.append(f"Multiple phishing signals detected ({phish_count}/9 features)")

#     if features.get("web_traffic", 0) == -1:
#         boost += 0.08
#         reasons.append("No detectable web traffic (obscure/new site)")

#     if features.get("Request_URL", 0) == -1:
#         boost += 0.08
#         reasons.append("Most page resources loaded from external domains")

#     if features.get("URL_of_Anchor", 0) == -1:
#         boost += 0.05
#         reasons.append("Most anchor links point to external domains")

#     final_score = max(0.01, min(base_score + boost, 0.99))
#     return final_score, boost, reasons, base_score

# def compute_shap_explanation(X_input, feature_names):
#     shap_arrays = []
#     for name, explainer in SHAP_EXPLAINERS.items():
#         try:
#             sv = explainer.shap_values(X_input)
#             if isinstance(sv, list) and len(sv) == 2:
#                 sv_phishing = np.array(sv[1]).flatten()
#             else:
#                 sv_phishing = np.array(sv).flatten()
#             if len(sv_phishing) == len(feature_names):
#                 shap_arrays.append(sv_phishing)
#         except Exception as e:
#             logger.warning(f"SHAP computation failed for {name}: {e}")

#     if not shap_arrays:
#         return None

#     avg_shap = np.mean(shap_arrays, axis=0)
#     items = [
#         {
#             'feature':    feature_names[i],
#             'shap_value': float(avg_shap[i]),
#             'direction':  'phishing' if avg_shap[i] > 0 else 'legitimate',
#             'abs_value':  float(abs(avg_shap[i]))
#         }
#         for i in range(len(feature_names))
#     ]
#     items.sort(key=lambda x: x['abs_value'], reverse=True)
#     top = items[:10]
#     for item in top:
#         del item['abs_value']

#     return {
#         'top_features':   top,
#         'total_features': len(feature_names),
#         'models_averaged': len(shap_arrays)
#     }


# def convert_to_serializable(obj):
#     if isinstance(obj, (np.integer, np.int64, np.int32)):
#         return int(obj)
#     elif isinstance(obj, (np.floating, np.float64, np.float32)):
#         return float(obj)
#     elif isinstance(obj, (np.bool_, bool)):
#         return bool(obj)
#     elif isinstance(obj, np.ndarray):
#         return obj.tolist()
#     elif isinstance(obj, dict):
#         return {k: convert_to_serializable(v) for k, v in obj.items()}
#     elif isinstance(obj, (list, tuple)):
#         return [convert_to_serializable(item) for item in obj]
#     return obj


# # -------------------- URL EXPANDER --------------------
# _SHORTENER_DOMAINS = {
#     'bit.ly', 'bitly.com', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
#     'is.gd', 'buff.ly', 'short.io', 'tiny.cc', 'rb.gy', 'cutt.ly',
#     'shorturl.at', 'bl.ink', 'snip.ly', 'clck.ru', 'x.co',
#     'lnkd.in', 'dlvr.it', 'ift.tt', 'fb.me', 'youtu.be',
#     'adf.ly', 'bc.vc', 'sh.st', 'linktr.ee', 'go2l.ink',
#     'rebrand.ly', 'qr.ae', 'ur1.ca', 'v.gd',
# }

# def expand_short_url(url: str, max_hops: int = 6, per_hop_timeout: int = 4) -> dict:
#     parsed_initial = urlparse(url)
#     domain = parsed_initial.netloc.lower().lstrip('www.')
#     if domain not in _SHORTENER_DOMAINS:
#         return {'original': url, 'expanded': url, 'was_shortened': False, 'hops': 0}

#     logger.info(f"🔗 Shortener detected ({domain}) — following redirects…")
#     current_url = url
#     hops = 0
#     dest_unreachable = False

#     for _ in range(max_hops):
#         try:
#             resp = requests.head(
#                 current_url,
#                 allow_redirects=False,
#                 timeout=per_hop_timeout,
#                 headers={'User-Agent': 'Mozilla/5.0 (compatible; PhishNet/1.0)'},
#             )
#             if resp.status_code in (301, 302, 303, 307, 308):
#                 location = resp.headers.get('Location', '').strip()
#                 if not location:
#                     break
#                 if location.startswith('//'):
#                     location = urlparse(current_url).scheme + ':' + location
#                 elif location.startswith('/'):
#                     p = urlparse(current_url)
#                     location = f"{p.scheme}://{p.netloc}{location}"
#                 current_url = location
#                 hops += 1
#             else:
#                 break
#         except requests.exceptions.Timeout:
#             dest_unreachable = True
#             break
#         except Exception as _ex:
#             logger.warning(f"Hop failed ({current_url}): {_ex}")
#             dest_unreachable = True
#             break

#     final_domain = urlparse(current_url).netloc.lower().lstrip('www.')

#     if not final_domain or (final_domain in _SHORTENER_DOMAINS and current_url == url):
#         return {
#             'original': url, 'expanded': url, 'was_shortened': True, 'hops': hops,
#             'error': 'Could not resolve final destination'
#         }

#     logger.info(f"🔗 Expanded: {url} → {current_url} ({hops} hop(s))"
#                 + (" [destination unreachable]" if dest_unreachable else ""))
#     result = {'original': url, 'expanded': current_url, 'was_shortened': True, 'hops': hops}
#     if dest_unreachable:
#         result['destination_unreachable'] = True
#     return result


# # ==================== BUG FIX 2: PREDICTION LABEL HELPER ====================
# def _prediction_label(prob: float, threshold: float) -> str:
#     """
#     Three-tier verdict so the WARN zone (fusion risk between 0.35 and threshold)
#     is never incorrectly labelled 'Legitimate'.

#     Phishing   : prob >= threshold
#     Suspicious : prob >= 0.35  (previously shown as 'Legitimate' — the bug)
#     Legitimate : prob <  0.35
#     """
#     if prob >= threshold:
#         return "Phishing"
#     elif prob >= 0.35:
#         return "Suspicious"
#     else:
#         return "Legitimate"
# # =============================================================================


# def _is_reachable(url: str) -> bool:
#     """Return True if the URL's hostname resolves in DNS (fast pre-check for cloaking)."""
#     try:
#         host = urlparse(url).hostname or url
#         socket.getaddrinfo(host, None)
#         return True
#     except Exception:
#         return False


# # -------------------- ANALYSIS LOGIC --------------------
# def analyze_url_logic(url):
#     try:
#         url = url.strip()
#         if not url:
#             return {"error": "URL required"}, 400

#         scheme = urlparse(url).scheme.lower()
#         if scheme and scheme not in ('http', 'https'):
#             return {"error": f"Unsupported scheme '{scheme}'. Only http/https URLs are accepted."}, 400
#         if not scheme:
#             url = "https://" + url

#         if len(url) > 2000:
#             return {"error": "URL too long (max 2000 characters)"}, 400

#         logger.info(f"🔍 Analyzing: {url}")

#         # LAYER 0: URL Expansion
#         expansion = expand_short_url(url, max_hops=3)
#         original_url = url
#         if expansion['was_shortened'] and expansion['expanded'] != url:
#             url = expansion['expanded']
#             logger.info(f"🔗 Analyzing real destination: {url}")

#         # LAYER 0.5: URL Normalization
#         try:
#             url_norm_result = _url_normalizer.normalize(url)
#             norm_flags = url_norm_result.get('flags', [])
#             if expansion.get('was_shortened') and 'URL_SHORTENER' not in norm_flags:
#                 norm_flags.append('URL_SHORTENER')
#                 url_norm_result['flags'] = norm_flags
#             if norm_flags:
#                 logger.info(f"🔎 URL flags: {norm_flags}")
#         except Exception as _un_err:
#             logger.warning(f"URL normalizer failed: {_un_err}")
#             url_norm_result = {'is_suspicious': False, 'flags': [], 'decoded_domain': '', 'details': {}}
#             norm_flags = ['URL_SHORTENER'] if expansion.get('was_shortened') else []

#         # LAYER 1: Rule-Based Detection
#         rule_result = rule_engine.evaluate(url)

#         if rule_result['is_phishing']:
#             logger.info(f"⚠️  Rule engine: PHISHING signals ({rule_result['confidence']:.0%}) — continuing to ML for full verdict")
#         else:
#             logger.info(f"✅ Rule engine: no phishing signals — continuing to ML")

#         # LAYER 2: ML Ensemble Detection
#         if MODEL_TYPE == 'uci':
#             extractor = UCIFeatureExtractor(url)
#         else:
#             extractor = FeatureExtractor(url)
#         X_raw, features = extractor.extract()

#         features["_domain"] = extractor.domain

#         X_for_prediction = X_raw if MODEL_TYPE == 'uci' else SCALER.transform(X_raw)

#         predictions = {}
#         probabilities = {}

#         for name, model in MODELS.items():
#             try:
#                 pred = model.predict(X_for_prediction)[0]
#                 if pred == -1:
#                     pred = 0
#                 predictions[name] = int(pred)

#                 if hasattr(model, 'predict_proba'):
#                     prob = model.predict_proba(X_for_prediction)[0]
#                     probabilities[name] = float(prob[1] if len(prob) > 1 else prob[0])
#                 else:
#                     probabilities[name] = float(pred)
#             except Exception as e:
#                 logger.error(f"Error with {name}: {e}")

#         if not probabilities:
#             logger.error("All ML models failed to produce predictions — aborting analysis")
#             return {"error": "All ML models failed. Please try again."}, 500

#         if MODEL_TYPE == 'uci':
#             final_prob, boost, reasons, base_prob = calculate_phishing_score_uci(features, probabilities)
#         else:
#             final_prob, boost, reasons, base_prob = calculate_phishing_score(features, probabilities)

#         if boost > 0:
#             logger.info(f"📈 Risk boosted: {base_prob:.2%} → {final_prob:.2%}")
#             for reason in reasons:
#                 logger.info(f"   {reason}")

#         # LAYER 3: Hybrid Rule-ML Fusion
#         if rule_result['confidence'] > 0.3:
#             has_critical = any(r['severity'] == 'CRITICAL' for r in rule_result['rules'])
#             has_high     = any(r['severity'] == 'HIGH'     for r in rule_result['rules'])
#             if has_critical:
#                 rule_floor = rule_result['confidence'] * 0.95
#                 if final_prob < rule_floor:
#                     final_prob = rule_floor
#                     boost = final_prob - base_prob
#                     reasons.append(f"Rule engine override (CRITICAL signals, {rule_result['confidence']:.0%} confidence)")
#                     logger.info(f"🚨 Hybrid override: ML={base_prob:.2%} → Rule floor={rule_floor:.2%}")
#             elif has_high and rule_result['confidence'] > 0.45:
#                 rule_floor = rule_result['confidence'] * 0.70
#                 if final_prob < rule_floor:
#                     final_prob = rule_floor
#                     boost = final_prob - base_prob
#                     reasons.append(f"Rule engine override (HIGH signals, {rule_result['confidence']:.0%} confidence)")
#                     logger.info(f"⚠️  Hybrid override: ML={base_prob:.2%} → Rule floor={rule_floor:.2%}")

#         # Determine risk level
#         if final_prob > 0.85:
#             risk_level = "Critical"
#             risk_emoji = "🔴"
#             risk_color = "red"
#         elif final_prob > 0.65:
#             risk_level = "High"
#             risk_emoji = "🟠"
#             risk_color = "orange"
#         elif final_prob > 0.45:
#             risk_level = "Medium"
#             risk_emoji = "🟡"
#             risk_color = "yellow"
#         elif final_prob > 0.20:
#             risk_level = "Low"
#             risk_emoji = "🟢"
#             risk_color = "lightgreen"
#         else:
#             risk_level = "Safe"
#             risk_emoji = "✅"
#             risk_color = "green"

#         phishing_votes    = sum(1 for pred in predictions.values() if pred == 1)
#         legitimate_votes  = sum(1 for pred in predictions.values() if pred == 0)
#         total_models      = len(predictions)

#         if max(phishing_votes, legitimate_votes) >= 3:
#             consensus_confidence = "High"
#         elif max(phishing_votes, legitimate_votes) == 2:
#             consensus_confidence = "Medium"
#         else:
#             consensus_confidence = "Low"

#         consensus_text = f"{phishing_votes} Phishing | {legitimate_votes} Legitimate"
#         logger.info(f"🗳️ Ensemble Voting: {consensus_text} (Confidence: {consensus_confidence})")

#         rule_contributed = rule_result['is_phishing'] and rule_result['confidence'] > 0.3
#         if rule_contributed and boost > 0:
#             detection_source = "rule_engine_ml"
#         else:
#             detection_source = "ml_ensemble"

#         shap_explanation = None
#         if SHAP_EXPLAINERS:
#             try:
#                 shap_explanation = compute_shap_explanation(X_for_prediction, FEATURE_NAMES)
#             except Exception as _shap_err:
#                 logger.warning(f"SHAP explanation skipped: {_shap_err}")

#         # Build url_analysis display metadata
#         url_analysis = None
#         if MODEL_TYPE == 'uci':
#             _age_days    = features.pop('_domain_age_days', None)
#             _recent_date = features.pop('_recent_content_date', None)
#             _is_active   = features.pop('_is_recently_active', False)
#             _subdomain   = features.pop('_subdomain', '')
#             _domain_name = features.pop('_domain_name', '')
#             _tld         = features.pop('_tld', '')
#             _sub_count   = features.pop('_subdomain_count', 0)
#             _url_len     = features.pop('_url_raw_length', len(url))
#             _sub_enum    = features.pop('_subdomain_enum', {'found': [], 'count': 0, 'base_domain': '', 'sources': []})

#             def _human_age(days):
#                 if days is None:
#                     return "Unknown (WHOIS unavailable)"
#                 if days < 30:
#                     return f"{days} day(s)"
#                 if days < 365:
#                     return f"{days // 30} month(s)"
#                 yrs = days // 365
#                 mos = (days % 365) // 30
#                 return f"{yrs} yr{'s' if yrs != 1 else ''}{(', ' + str(mos) + ' mo') if mos > 0 else ''}"

#             url_analysis = {
#                 'domain_age_days':     _age_days,
#                 'domain_age_human':    _human_age(_age_days),
#                 'subdomain':           _subdomain or None,
#                 'subdomain_count':     _sub_count,
#                 'domain_name':         _domain_name,
#                 'tld':                 _tld,
#                 'url_length':          _url_len,
#                 'is_https':            extractor.parsed.scheme == 'https',
#                 'has_www':             extractor.url.lower().startswith(('http://www.', 'https://www.')),
#                 'has_query_params':    bool(extractor.parsed.query),
#                 'recent_content_date': _recent_date,
#                 'is_recently_active':  bool(_is_active),
#                 'subdomain_enum':      _sub_enum,
#             }

#         features.pop('_domain', None)

#         # LAYER 3: Domain Metadata Analysis
#         domain_result = None
#         if 'IP_ADDRESS' in norm_flags:
#             logger.info("⏭️  Fast-path domain metadata (IP-address URL)")
#             domain_result = {
#                 'risk_score': 0.6,
#                 'is_suspicious': True,
#                 'risk_factors': ['IP address used instead of domain name'],
#                 'metadata': {
#                     'ip': {'ip': url_norm_result.get('decoded_domain', ''), 'is_private': False},
#                     'ssl': {'has_ssl': False},
#                     'whois': {'domain_age_days': None},
#                     'dns': {'has_mx': False, 'has_spf': False, 'has_dmarc': False},
#                     'asn': {}
#                 }
#             }
#         else:
#             try:
#                 domain_result = _domain_analyzer.analyze(url)
#                 logger.info(f"🌐 Domain risk: {domain_result.get('risk_score', 0):.2f}")
#             except Exception as _dm_err:
#                 logger.warning(f"Domain metadata analysis failed: {_dm_err}")
#                 domain_result = {'risk_score': 0.0, 'is_suspicious': False, 'risk_factors': [], 'metadata': {}}

#         # LAYER 3b: Visual Similarity
#         visual_result = None
#         if 'IP_ADDRESS' not in norm_flags:
#             try:
#                 visual_result = _visual_analyzer.analyze(url)
#                 if visual_result.get('matched_brand'):
#                     logger.warning(
#                         f"🚨 Brand impersonation detected: {visual_result['matched_brand']} "
#                         f"({visual_result['max_similarity']:.0%} visual similarity)"
#                     )
#                 elif not visual_result.get('skipped'):
#                     logger.info(f"🖼️  Visual: no brand clone (max SSIM {visual_result.get('max_similarity', 0):.0%})")
#             except Exception as _vs_err:
#                 logger.warning(f"Visual similarity failed: {_vs_err}")
#                 visual_result = None

#         # ==================== BUG FIX 3: CLOAKING RISK FOR UNREACHABLE SITES ====================
#         # Previously: DNS failure → cloaking risk defaults to 0.30 (neutral / "safe")
#         # which dragged the fused score down, causing phishing sites to be labelled Legitimate.
#         # Fix: unresolvable / unreachable = 0.65 (suspicious), not 0.30.
#         _dest_unreachable = expansion.get('destination_unreachable', False)
#         _expansion_error  = expansion.get('was_shortened') and expansion.get('error') is not None
#         cloaking_result = None
#         if 'IP_ADDRESS' in norm_flags:
#             logger.info("⏭️  Skipping cloaking detection (IP-address URL — already flagged)")
#             cloaking_result = {
#                 'overall_risk': 0.65,          # ← FIX: was 0.50 — IP with no DNS is high risk
#                 'cloaking_detected': False,
#                 'skipped': True,
#                 'evidence': ['IP-address URL skips cloaking scan']
#             }
#         elif _dest_unreachable or _expansion_error:
#             reason = 'destination server unreachable' if _dest_unreachable else 'shortener redirect unresolved'
#             logger.info(f"⏭️  Skipping cloaking detection ({reason})")
#             cloaking_result = {
#                 'overall_risk': 0.65,          # ← FIX: was 0.30 — unreachable = suspicious
#                 'cloaking_detected': False,
#                 'skipped': True,
#                 'evidence': [f'Cloaking scan skipped: {reason}']
#             }
#         else:
#             # TCP reachability — catches dead DNS AND sinkholed/parked domains
#             _h       = urlparse(url).hostname or url
#             _host_ok = _is_reachable(url)

#             if not _host_ok:
#                 logger.warning(f"⏭️  Cloaking skipped — DNS unresolvable: {_h}")
#                 cloaking_result = {
#                     'overall_risk': 0.65, 'cloaking_detected': False,
#                     'skipped': True, 'evidence': [f'DNS unresolvable: {_h}']
#                 }
#             else:
#                 try:
#                     with concurrent.futures.ThreadPoolExecutor(max_workers=1) as _cloak_ex:
#                         _cloak_fut = _cloak_ex.submit(_cloaking_detector.analyze, url, domain_result)
#                         try:
#                             cloaking_result = _cloak_fut.result(timeout=20)
#                         except concurrent.futures.TimeoutError:
#                             logger.warning("⏱️  Cloaking analysis timed out (20s) — using neutral risk")
#                             cloaking_result = {
#                                 'overall_risk': 0.30, 'cloaking_detected': False,
#                                 'skipped': True, 'error': 'timeout',
#                                 'evidence': ['Cloaking analysis exceeded 20s budget']
#                             }
#                     cloaking_result['skipped'] = cloaking_result.get('skipped', False)
#                     if cloaking_result.get('cloaking_detected'):
#                         logger.warning(f"🎭 Cloaking detected! Risk: {cloaking_result.get('overall_risk', 0):.2f}")
#                     else:
#                         logger.info(f"✅ No cloaking detected (risk: {cloaking_result.get('overall_risk', 0):.2f})")
#                 except Exception as _cd_err:
#                     logger.warning(f"Cloaking detection failed: {_cd_err}")
#                     cloaking_result = {
#                         'overall_risk': 0.50, 'cloaking_detected': False,
#                         'skipped': True, 'evidence': [f'Cloaking failed: {_cd_err}']
#                     }
#         # ========================================================================================

#         # LAYER 5: Intelligent Multi-Modal Fusion
#         fusion_result = None
#         try:
#             ml_result_for_fusion = {
#                 'probability': final_prob,
#                 'prediction': 'phishing' if final_prob >= THRESHOLD else 'legitimate',
#                 'confidence': final_prob
#             }

#             # Domain age fallback: domain_metadata_analyzer WHOIS sometimes fails
#             # (e.g. whois library API mismatch) but url_analysis has the correct age
#             # from the subprocess whois call. Patch domain_result so fusion gets the
#             # right age instead of treating every WHOIS-fail domain as brand new.
#             _domain_result_for_fusion = domain_result
#             _whois_age = (domain_result.get('metadata', {})
#                                        .get('whois', {})
#                                        .get('domain_age_days'))
#             _fallback_age = url_analysis.get('domain_age_days')
#             if _whois_age is None and _fallback_age is not None:
#                 import copy
#                 _domain_result_for_fusion = copy.deepcopy(domain_result)
#                 _domain_result_for_fusion.setdefault('metadata', {}) \
#                                          .setdefault('whois', {}) \
#                                          ['domain_age_days'] = _fallback_age
#                 logger.info(f"🔧 Domain age fallback: using url_analysis age {_fallback_age}d (WHOIS library failed)")

#             # Cloudflare CDN cloaking false-positive suppression:
#             # Cloudflare injects geo-check / UA-check / timing JS on all proxied sites.
#             # These look like cloaking to Tier 1 but are not actually malicious.
#             # If ASN is Cloudflare, cap cloaking risk at 0.35 (uncertain, not suspicious).
#             _cloaking_result_for_fusion = cloaking_result
#             _asn_desc = (domain_result.get('metadata', {})
#                                       .get('asn', {})
#                                       .get('asn_description', ''))
#             if 'CLOUDFLARE' in _asn_desc.upper() and cloaking_result:
#                 _cf_risk = min(cloaking_result.get('overall_risk', 0), 0.35)
#                 if _cf_risk < cloaking_result.get('overall_risk', 0):
#                     _cloaking_result_for_fusion = {**cloaking_result, 'overall_risk': _cf_risk}
#                     logger.info(f"☁️  Cloudflare CDN: cloaking risk capped {cloaking_result.get('overall_risk', 0):.2f} → {_cf_risk:.2f}")

#             # Trusted domain cloaking cap:
#             # Major legitimate sites (ESPN, BBC, etc.) often block automated requests,
#             # causing cloaking detector to return 0.65 "unreachable" — this is not cloaking.
#             if is_trusted_domain(extractor.domain) and cloaking_result:
#                 _td_risk = min(_cloaking_result_for_fusion.get('overall_risk', 0), 0.30)
#                 if _td_risk < _cloaking_result_for_fusion.get('overall_risk', 0):
#                     _cloaking_result_for_fusion = {**_cloaking_result_for_fusion, 'overall_risk': _td_risk}
#                     logger.info(f"🛡️  Trusted domain: cloaking risk capped at {_td_risk:.2f}")

#             fusion_result = _fusion_engine.analyze(
#                 url=url,
#                 ml_result=ml_result_for_fusion,
#                 domain_result=_domain_result_for_fusion,
#                 cloaking_result=_cloaking_result_for_fusion,
#                 visual_result=visual_result,
#             )
#             fused_risk = fusion_result.get('final_risk', final_prob)
#             logger.info(f"🧠 Fusion: {fusion_result.get('scenario')} → {fusion_result.get('verdict')} (risk {fused_risk:.2f})")

#             # Trusted-domain + clean-rule-engine override:
#             # If a domain is explicitly in TRUSTED_DOMAINS and the rule engine
#             # found zero phishing signals, a flawed ML vote must NOT produce a
#             # BLOCK verdict. Force ALLOW so the prediction label is Legitimate.
#             if (fusion_result.get('verdict') == 'BLOCK'
#                     and is_trusted_domain(extractor.domain)
#                     and not rule_result.get('is_phishing', False)):
#                 fusion_result = {**fusion_result, 'verdict': 'ALLOW', 'final_risk': 0.20}
#                 fused_risk = 0.20
#                 logger.info(f"🛡️  Trusted+clean-rules override: BLOCK → ALLOW (ML false-positive suppressed)")

#             final_prob = fused_risk
#         except Exception as _fe:
#             logger.warning(f"Intelligent fusion failed: {_fe}")

#         # ==================== BUG FIX 2 (applied here) ====================
#         # Derive label from fusion verdict when available.
#         # fusion ALLOW  → "Legitimate"  (even if final_prob is ~0.39)
#         # fusion WARN   → "Suspicious"
#         # fusion BLOCK  → "Phishing"
#         # No fusion     → fall back to probability threshold
#         _fusion_verdict = fusion_result.get('verdict') if fusion_result else None
#         if _fusion_verdict == 'BLOCK':
#             prediction_label = 'Phishing'
#         elif _fusion_verdict == 'WARN':
#             prediction_label = 'Suspicious'
#         elif _fusion_verdict == 'ALLOW':
#             prediction_label = 'Legitimate'
#         else:
#             prediction_label = _prediction_label(final_prob, THRESHOLD)
#         logger.info(f"✅ {prediction_label} ({round(final_prob * 100, 2)}%) [fusion={_fusion_verdict}]")
#         # ===================================================================

#         response = {
#             "url":           str(original_url),
#             "analyzed_url":  str(url),
#             "url_expanded":  expansion.get('was_shortened', False),
#             "url_expansion": {
#                 "original":               expansion.get('original', original_url),
#                 "expanded":               expansion.get('expanded', url),
#                 "was_shortened":          expansion.get('was_shortened', False),
#                 "hops":                   expansion.get('hops', 0),
#                 "destination_unreachable": expansion.get('destination_unreachable', False),
#                 "error":                  expansion.get('error'),
#             } if expansion.get('was_shortened') else None,
#             "domain":            str(extractor.domain),
#             "prediction":        prediction_label,          # ← FIX 2
#             "confidence":        float(round(final_prob * 100, 2)),
#             "probability":       float(round(final_prob, 4)),
#             "base_probability":  float(round(base_prob, 4)),
#             "risk_boost":        float(round(boost, 4)),
#             "boost_reasons":     reasons,
#             "safe_to_visit":     bool(prediction_label == "Legitimate"),
#             "is_trusted":        is_trusted_domain(extractor.domain),
#             "detection_source":  detection_source,
#             "risk_level":        str(risk_level),
#             "risk_emoji":        str(risk_emoji),
#             "risk_color":        str(risk_color),
#             "threshold_used":    float(THRESHOLD),
#             "ensemble": {
#                 "base_probability":       float(round(base_prob, 4)),
#                 "individual_predictions": convert_to_serializable(predictions),
#                 "individual_probabilities": convert_to_serializable({k: round(v, 4) for k, v in probabilities.items()}),
#                 "agreement":              f"{int(sum(predictions.values()))}/{len(predictions)}",
#                 "voting": {
#                     "phishing_votes":      int(phishing_votes),
#                     "legitimate_votes":    int(legitimate_votes),
#                     "total_models":        int(total_models),
#                     "consensus_text":      str(consensus_text),
#                     "consensus_confidence": str(consensus_confidence)
#                 }
#             },
#             "rule_analysis": {
#                 "is_phishing":    rule_result['is_phishing'],
#                 "confidence":     float(round(rule_result['confidence'], 4)),
#                 "rule_violations": rule_result['rules'],
#                 "rule_count":     rule_result['rule_count'],
#                 "signals":        rule_result['signals']
#             },
#             "features":          convert_to_serializable(features),
#             "shap_explanation":  shap_explanation,
#             "url_analysis":      url_analysis,
#             "url_normalization": {
#                 "flags":          norm_flags,
#                 "is_suspicious":  bool(url_norm_result.get('is_suspicious', False)),
#                 "decoded_domain": str(url_norm_result.get('decoded_domain', '')),
#                 "details":        url_norm_result.get('details', {})
#             },
#             "domain_metadata": {
#                 "risk_score":   float(domain_result.get('risk_score', 0.0)),
#                 "is_suspicious": bool(domain_result.get('is_suspicious', False)),
#                 "risk_factors": domain_result.get('risk_factors', []),
#                 "metadata":     domain_result.get('metadata', {})
#             } if domain_result else None,
#             "cloaking": {
#                 "risk":     float(cloaking_result.get('overall_risk', 0.0)),
#                 "detected": bool(cloaking_result.get('cloaking_detected', False)),
#                 "evidence": cloaking_result.get('evidence', [])[:5]
#             } if cloaking_result else None,
#             "fusion_result": {
#                 "final_risk":    float(fusion_result.get('final_risk', 0.0)),
#                 "verdict":       str(fusion_result.get('verdict', '')),
#                 "scenario":      str(fusion_result.get('scenario', '')),
#                 "reasoning":     fusion_result.get('reasoning', []),
#                 "confidence":    float(fusion_result.get('confidence', 0.0)),
#                 "module_scores": fusion_result.get('module_scores', {})
#             } if fusion_result else None,
#             "visual_similarity": {
#                 "risk_score":     float(visual_result.get('risk_score', 0.0)),
#                 "max_similarity": float(visual_result.get('max_similarity', 0.0)),
#                 "matched_brand":  visual_result.get('matched_brand'),
#                 "skipped":        bool(visual_result.get('skipped', False)),
#                 "skip_reason":    visual_result.get('reason'),
#             } if visual_result else None,
#             "model_info": {
#                 "models_used":       len(MODELS),
#                 "model_names":       list(MODELS.keys()),
#                 "detection_method":  f"Full Pipeline: Rule Engine (all rules) + {'UCI 16-Feature' if MODEL_TYPE == 'uci' else '4-Model'} ML Ensemble + Score Fusion",
#                 "rule_engine_enabled": True,
#                 "rules_checked":     14,
#                 "f1_score":          MODEL_METRICS.get("gradient_boosting", {}).get("f1_score", 0.0),
#             },
#             "timestamp": str(datetime.now().isoformat())
#         }

#         return response, 200

#     except Exception as e:
#         logger.error(f"❌ Error: {str(e)}", exc_info=True)
#         return {"error": str(e)}, 500


# # -------------------- API ROUTES --------------------
# from fusion_endpoint import fusion_bp
# app.register_blueprint(fusion_bp)

# @app.route("/", methods=["GET", "OPTIONS"])
# def home():
#     if request.method == "OPTIONS":
#         return "", 200
#     return jsonify({
#         "status": "healthy",
#         "service": "Phishing Detection API",
#         "version": "5.1 - Triple Bug Fix",
#         "models": len(MODELS),
#         "trusted_domains": len(TRUSTED_DOMAINS)
#     }), 200

# @app.route("/analyze", methods=["POST", "OPTIONS"])
# @app.route("/analyze_url", methods=["POST", "OPTIONS"])
# def analyze():
#     if request.method == "OPTIONS":
#         return "", 200

#     data = request.get_json(silent=True)
#     if not data:
#         return jsonify({"error": "Request body must be JSON with a 'url' field"}), 400

#     url = data.get("url", "").strip()
#     if not url:
#         return jsonify({"error": "URL is required"}), 400

#     try:
#         # Hard 70s cap — ensures Flask always responds before Express's 90s timeout
#         with concurrent.futures.ThreadPoolExecutor(max_workers=1) as _route_ex:
#             _route_fut = _route_ex.submit(analyze_url_logic, url)
#             try:
#                 result, status = _route_fut.result(timeout=70)
#             except concurrent.futures.TimeoutError:
#                 logger.error(f"⏱️  analyze_url_logic timed out (70s) for: {url}")
#                 return jsonify({"error": "Analysis timed out — please try again"}), 503
#         return jsonify(result), status
#     except Exception as e:
#         logger.error(f"Unhandled exception in analyze route: {e}", exc_info=True)
#         return jsonify({"error": "Internal server error"}), 500

# @app.before_request
# def handle_preflight():
#     if request.method == "OPTIONS":
#         response = jsonify({"status": "ok"})
#         response.headers.add("Access-Control-Allow-Origin", "http://localhost:3000")
#         response.headers.add("Access-Control-Allow-Headers", "Content-Type")
#         response.headers.add("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
#         return response, 200


# # -------------------- RUN --------------------
# if __name__ == "__main__":
#     logger.info("="*80)
#     logger.info("🚀 PHISHING DETECTION API v5.1 - TRIPLE BUG FIX")
#     logger.info("   Fix 1: Duplicate logs — use_reloader=False eliminates double imports")
#     logger.info("   Fix 2: 3-tier labels: Phishing / Suspicious / Legitimate")
#     logger.info("   Fix 3: Unreachable/DNS-fail cloaking risk = 0.65 (not 0.30)")
#     logger.info(f"✅ Detection: ML + Whitelist + Heuristics")
#     logger.info(f"✅ Trusted domains: {len(TRUSTED_DOMAINS)}")
#     logger.info("="*80)
#     # ==================== BUG FIX 1 ====================
#     # use_reloader=False prevents Werkzeug from importing the module twice,
#     # which was the root cause of every log line appearing twice.
#     # If you need live-reload during development, use an external tool like
#     # watchdog/hupper instead, or accept that debug=True will double-log.
#     app.run(host="0.0.0.0", port=5002, debug=True, use_reloader=False)
#     # ====================================================
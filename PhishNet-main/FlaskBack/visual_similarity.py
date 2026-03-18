"""
Visual Similarity Analyzer — Phase 4 Integration
Wraps ScreenshotEngine + SSIMAnalyzer into the 3-field dict expected by IntelligentFusion.

Author: Phase 4 Integration
Date: March 2026
"""

import os
import json
import logging
import sys
import socket
import ipaddress
import time
from urllib.parse import urlparse
from PIL import Image
from screenshot_engine import ScreenshotEngine
from ssim_analyzer import SSIMAnalyzer

logger = logging.getLogger(__name__)

# Chromium-compatible browser binary auto-detection (in priority order)
_BROWSER_CANDIDATES = [
    # Brave (macOS)
    '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
    # Brave (Linux)
    '/usr/bin/brave-browser',
    '/usr/bin/brave',
    # Chromium (macOS)
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    # Chromium (Linux)
    '/usr/bin/chromium-browser',
    '/usr/bin/chromium',
    # Google Chrome (macOS)
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    # Google Chrome (Linux)
    '/usr/bin/google-chrome',
]


def _is_reachable(url: str, timeout: float = 3.0) -> bool:
    """
    TCP connect on port 80/443 — catches both dead DNS and sinkholed domains.
    DNS-only checks miss sinkholed domains (resolve in DNS, no server listening).
    """
    try:
        p    = urlparse(url)
        host = p.hostname
        port = 443 if p.scheme == 'https' else 80
        if not host:
            return False
        try:
            ipaddress.ip_address(host)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
            return True
        except ValueError:
            pass
        addrs = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        if not addrs:
            return False
        af, socktype, proto, _, addr = addrs[0]
        with socket.socket(af, socktype, proto) as s:
            s.settimeout(timeout)
            s.connect(addr)
        return True
    except (socket.gaierror, socket.timeout, OSError, ConnectionRefusedError):
        return False

def _find_browser_binary() -> str | None:
    """Return the first available Chromium-based browser binary, or None."""
    for path in _BROWSER_CANDIDATES:
        if os.path.exists(path):
            logger.info(f"🖼️  Browser binary: {path}")
            return path
    return None

_CHROME_BINARY = _find_browser_binary()

# Brand keyword → official domain mapping.
# A URL is worth screenshotting only if it contains a brand keyword
# but NOT the brand's official domain (classic impersonation pattern).
_BRAND_DOMAINS = {
    # Global brands
    'paypal':      'paypal.com',
    'google':      'google.com',
    'facebook':    'facebook.com',
    'microsoft':   'microsoft.com',
    'amazon':      'amazon.com',
    'apple':       'apple.com',
    'instagram':   'instagram.com',
    'linkedin':    'linkedin.com',
    'netflix':     'netflix.com',
    'chase':       'chase.com',
    'coinbase':    'coinbase.com',
    'binance':     'binance.com',
    'metamask':    'metamask.io',
    # Nepal brands
    'esewa':       'esewa.com.np',
    'khalti':      'khalti.com',
    'connectips':  'connectips.com',
    'nicasia':     'nicasiabank.com',
    'globalime':   'globalimebank.com',
    'nabil':       'nabilbank.com',
    'ncell':       'ncell.com.np',
}


class VisualSimilarityAnalyzer:
    """
    Detects brand impersonation by comparing a suspect page's screenshot
    against a pre-built database of legitimate brand screenshots.

    Expected output format (matches IntelligentFusion._extract_signals):
        {
            'risk_score':     float  0-1,
            'max_similarity': float  0-1  (SSIM score vs best-matching brand),
            'matched_brand':  str or None (brand name if clone detected),
            'skipped':        bool  (True when scan was intentionally skipped),
            'reason':         str or None (why skipped, if skipped=True),
        }
    """

    # In-memory cache for official brand screenshots — avoids re-capturing on every scan.
    # Key: lowercase brand name  Value: {'image': PIL.Image, 'captured_at': float (unix ts)}
    _CACHE_TTL = 86400  # 24 hours

    def __init__(self, brand_db_path: str = 'brand_database', ssim_threshold: float = 0.85):
        self.db_path = brand_db_path
        self.ssim = SSIMAnalyzer(threshold=ssim_threshold)
        self.brands = self._load_brands()
        self._official_cache: dict = {}   # populated lazily at scan time
        if self.brands:
            logger.info(f"🖼️  Visual similarity: loaded {len(self.brands)} brand references")
        else:
            logger.warning("🖼️  Visual similarity: no brand database found — run brand_database_builder.py to enable")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_brands(self) -> list:
        """Load brand metadata from brand_database/metadata.json."""
        meta_path = os.path.join(self.db_path, 'metadata.json')
        if not os.path.exists(meta_path):
            return []
        try:
            with open(meta_path) as f:
                all_brands = json.load(f)
            return [b for b in all_brands if b.get('success')]
        except Exception as e:
            logger.warning(f"Failed to load brand metadata: {e}")
            return []

    def _should_screen(self, url: str) -> tuple:
        """
        Quick pre-filter: only screenshot URLs that contain a known brand
        keyword but NOT that brand's official domain.

        Returns: (should_screen: bool, hint_brand: str | None)
        """
        url_lower = url.lower()
        for brand, official_domain in _BRAND_DOMAINS.items():
            if brand in url_lower and official_domain not in url_lower:
                return True, brand.title()
        return False, None

    def _get_official_screenshot(self, brand: str, official_url: str):
        """
        Return a PIL Image of the OFFICIAL brand website — captured live with 24h caching.

        Priority:
          1. In-memory cache (< 24h) — fastest, no browser launch needed
          2. Fresh live capture of official_url — always up-to-date
          3. Stored static PNG fallback — used when live capture fails

        This makes comparisons dynamic: the suspect page is always compared against the
        CURRENT design of the real brand site, not a potentially stale stored screenshot.
        """
        brand_key = brand.lower()
        now = time.time()

        # 1. Cache hit
        cached = self._official_cache.get(brand_key)
        if cached and (now - cached['captured_at']) < self._CACHE_TTL:
            logger.info(f"🖼️  Official screenshot cache hit: {brand} (age {int(now - cached['captured_at'])}s)")
            return cached['image']

        # 2. Live capture of official site
        if _CHROME_BINARY is not None:
            try:
                with ScreenshotEngine(headless=True, timeout=15, chrome_binary=_CHROME_BINARY) as eng:
                    img = eng.capture_screenshot(official_url, output_path=None)
                if img is not None:
                    self._official_cache[brand_key] = {'image': img, 'captured_at': now}
                    logger.info(f"🖼️  Official brand screenshot refreshed: {brand} ({official_url})")
                    return img
            except Exception as e:
                logger.warning(f"🖼️  Live capture failed for {brand} ({official_url}): {e}")

        # 3. Fallback: stored static PNG
        for entry in self.brands:
            if entry.get('brand_name', '').lower() == brand_key:
                stored = os.path.join(self.db_path, 'screenshots', entry['screenshot_file'])
                if os.path.exists(stored):
                    logger.info(f"🖼️  Using stored fallback screenshot for {brand}")
                    return Image.open(stored)
                break

        logger.warning(f"🖼️  No official reference available for {brand}")
        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, url: str, force: bool = False) -> dict:
        """
        Analyze a URL for visual brand impersonation.

        Fast path (no Chrome started):
          - No brand database → skipped: no_brand_database
          - URL has no brand keywords → skipped: no_brand_keywords (unless force=True)

        Slow path (Chrome launched, ~4-15s):
          - Screenshot captured, compared against all brand references
          - Returns match details

        Args:
            url:   URL to analyze
            force: If True, skip the brand-keyword fast path and always screenshot.
                   Used for trusted domains with high ML scores (hosted-content phishing).
        """
        # Fast path 1: no brand database
        if not self.brands:
            return {
                'risk_score': 0.0, 'max_similarity': 0.0, 'matched_brand': None,
                'skipped': True, 'reason': 'no_brand_database',
            }

        # Fast path 2: URL doesn't mention any known brand
        # Skipped when force=True — trusted domains hosting phishing content won't
        # have brand keywords in the URL (the phishing form is inside the page body).
        should, hint_brand = self._should_screen(url)
        if not should and not force:
            return {
                'risk_score': 0.0, 'max_similarity': 0.0, 'matched_brand': None,
                'skipped': True, 'reason': 'no_brand_keywords',
            }
        if not should and force:
            hint_brand = None  # no URL hint — compare against all brands
         # Fast path 3: host not reachable — catches dead DNS and sinkholed domains.
        # IMPORTANT: a dead domain that contains a brand keyword IS suspicious —
        # return an elevated risk score instead of neutral 0.0 so the fusion engine
        # can use this signal rather than treating it as "visual module abstained".
        if not _is_reachable(url):
            _h = urlparse(url).hostname or url
            logger.warning(
                f"🖼️  Skipping screenshot — host unreachable: {_h} "
                f"(DNS failure or sinkholed — elevated risk 0.55 returned)"
            )
            return {
                'risk_score': 0.55,      # dead brand-keyword domain = suspicious
                'max_similarity': 0.0,
                'matched_brand': None,
                'skipped': True,
                'reason': 'host_unreachable',
                'hint_brand': hint_brand,
                'dns_failed': True,      # flag consumed by intelligent_fusion.py
            }
        # # Fast path 3: host not reachable — catches dead DNS and sinkholed domains
        # if not _is_reachable(url):
        #     _h = urlparse(url).hostname or url
        #     logger.warning(
        #         f"🖼️  Skipping screenshot — host unreachable: {_h} "
        #         f"(DNS failure or sinkholed domain)"
        #     )
        #     return {
        #         'risk_score': 0.0, 'max_similarity': 0.0, 'matched_brand': None,
        #         'skipped': True, 'reason': 'host_unreachable', 'hint_brand': hint_brand,
        #     }

        if force:
            logger.info(f"🖼️  Visual scan FORCED (trusted domain + high ML score — checking all brands): {url}")
        else:
            logger.info(f"🖼️  Visual scan triggered (possible {hint_brand} impersonation): {url}")

        # Slow path: capture + compare
        if _CHROME_BINARY is None:
            logger.warning("🖼️  No Chromium-based browser found — install Brave or Chrome to enable visual scanning")
            return {
                'risk_score': 0.0, 'max_similarity': 0.0, 'matched_brand': None,
                'skipped': True, 'reason': 'no_browser_binary',
            }

        try:
            with ScreenshotEngine(headless=True, timeout=15, chrome_binary=_CHROME_BINARY) as engine:
                screenshot = engine.capture_screenshot(url)

            if screenshot is None:
                logger.warning(f"🖼️  Screenshot failed for {url}")
                return {
                    'risk_score': 0.0, 'max_similarity': 0.0, 'matched_brand': None,
                    'skipped': True, 'reason': 'screenshot_failed',
                }

            max_score = 0.0
            matched_brand = None

            if hint_brand:
                # ── Dynamic path: compare against LIVE official brand screenshot ──
                # hint_brand is the brand identified from the URL (e.g. 'Paypal').
                # Fetch the current official site screenshot (cached 24h), so the
                # comparison is always against the brand's current design.
                official_url = 'https://www.' + _BRAND_DOMAINS.get(hint_brand.lower(), '')
                official_img = self._get_official_screenshot(hint_brand, official_url)
                if official_img is not None:
                    try:
                        result = self.ssim.calculate_ssim(screenshot, official_img)
                        max_score = result['ssim_score']
                        if result['is_clone']:
                            matched_brand = hint_brand
                    except Exception as _cmp_err:
                        logger.warning(f"SSIM comparison failed for {hint_brand}: {_cmp_err}")
                else:
                    # Official screenshot unavailable — fall through to static loop below
                    hint_brand = None

            if not hint_brand:
                # ── Static path: compare against all stored brand PNGs ──
                # Used when: force=True (no URL hint) OR official capture failed.
                # Self-brand exclusion: skip brands whose official domain matches
                # the URL's base domain — e.g. don't flag scholar.google.com as
                # impersonating "Google" (it IS Google).
                url_base = '.'.join((urlparse(url).hostname or '').split('.')[-2:])
                for brand in self.brands:
                    # Extract official domain from the brand's URL field
                    brand_url = brand.get('url', '')
                    brand_official = '.'.join(urlparse(brand_url).hostname.lstrip('www.').split('.')[-2:]) if brand_url else ''
                    if brand_official and url_base == brand_official:
                        continue  # URL is the brand's own site — skip comparison

                    ref_path = os.path.join(self.db_path, 'screenshots', brand['screenshot_file'])
                    if not os.path.exists(ref_path):
                        continue
                    try:
                        result = self.ssim.calculate_ssim(screenshot, ref_path)
                        score = result['ssim_score']
                        if score > max_score:
                            max_score = score
                            if result['is_clone']:
                                matched_brand = brand['brand_name']
                    except Exception as _cmp_err:
                        logger.warning(f"SSIM comparison failed for {brand['brand_name']}: {_cmp_err}")

            # risk_score: full SSIM when there's a clone, 30% of SSIM otherwise
            risk_score = max_score if matched_brand else max_score * 0.3

            if matched_brand:
                logger.warning(f"🚨 Brand impersonation: {matched_brand} ({max_score:.0%} SSIM)")
            else:
                logger.info(f"🖼️  Visual: no clone (max SSIM {max_score:.0%})")

            return {
                'risk_score':     float(risk_score),
                'max_similarity': float(max_score),
                'matched_brand':  matched_brand,
                'skipped':        False,
                'reason':         None,
            }

        except Exception as e:
            logger.warning(f"Visual similarity analysis failed: {e}")
            return {
                'risk_score': 0.0, 'max_similarity': 0.0, 'matched_brand': None,
                'skipped': True, 'reason': 'exception', 'error': str(e),
            }

    def reload_database(self):
        """Reload brand database from disk (useful after running brand_database_builder.py)."""
        self.brands = self._load_brands()
        logger.info(f"🖼️  Visual similarity: reloaded {len(self.brands)} brand references")

# """
# Visual Similarity Analyzer — Phase 4 Integration
# Wraps ScreenshotEngine + SSIMAnalyzer into the 3-field dict expected by IntelligentFusion.

# Author: Phase 4 Integration
# Date: March 2026
# """

# import os
# import json
# import logging
# import sys
# from screenshot_engine import ScreenshotEngine
# from ssim_analyzer import SSIMAnalyzer

# logger = logging.getLogger(__name__)

# # Chromium-compatible browser binary auto-detection (in priority order)
# _BROWSER_CANDIDATES = [
#     # Brave (macOS)
#     '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
#     # Brave (Linux)
#     '/usr/bin/brave-browser',
#     '/usr/bin/brave',
#     # Chromium (macOS)
#     '/Applications/Chromium.app/Contents/MacOS/Chromium',
#     # Chromium (Linux)
#     '/usr/bin/chromium-browser',
#     '/usr/bin/chromium',
#     # Google Chrome (macOS)
#     '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
#     # Google Chrome (Linux)
#     '/usr/bin/google-chrome',
# ]

# def _find_browser_binary() -> str | None:
#     """Return the first available Chromium-based browser binary, or None."""
#     for path in _BROWSER_CANDIDATES:
#         if os.path.exists(path):
#             logger.info(f"🖼️  Browser binary: {path}")
#             return path
#     return None

# _CHROME_BINARY = _find_browser_binary()

# # Brand keyword → official domain mapping.
# # A URL is worth screenshotting only if it contains a brand keyword
# # but NOT the brand's official domain (classic impersonation pattern).
# _BRAND_DOMAINS = {
#     'paypal':     'paypal.com',
#     'google':     'google.com',
#     'facebook':   'facebook.com',
#     'microsoft':  'microsoft.com',
#     'amazon':     'amazon.com',
#     'apple':      'apple.com',
#     'instagram':  'instagram.com',
#     'linkedin':   'linkedin.com',
#     'netflix':    'netflix.com',
#     'chase':      'chase.com',
# }



# class VisualSimilarityAnalyzer:
#     """
#     Detects brand impersonation by comparing a suspect page's screenshot
#     against a pre-built database of legitimate brand screenshots.

#     Expected output format (matches IntelligentFusion._extract_signals):
#         {
#             'risk_score':     float  0-1,
#             'max_similarity': float  0-1  (SSIM score vs best-matching brand),
#             'matched_brand':  str or None (brand name if clone detected),
#             'skipped':        bool  (True when scan was intentionally skipped),
#             'reason':         str or None (why skipped, if skipped=True),
#         }
#     """

#     def __init__(self, brand_db_path: str = 'brand_database', ssim_threshold: float = 0.85):
#         self.db_path = brand_db_path
#         self.ssim = SSIMAnalyzer(threshold=ssim_threshold)
#         self.brands = self._load_brands()
#         if self.brands:
#             logger.info(f"🖼️  Visual similarity: loaded {len(self.brands)} brand references")
#         else:
#             logger.warning("🖼️  Visual similarity: no brand database found — run brand_database_builder.py to enable")

#     # ------------------------------------------------------------------
#     # Internal helpers
#     # ------------------------------------------------------------------

#     def _load_brands(self) -> list:
#         """Load brand metadata from brand_database/metadata.json."""
#         meta_path = os.path.join(self.db_path, 'metadata.json')
#         if not os.path.exists(meta_path):
#             return []
#         try:
#             with open(meta_path) as f:
#                 all_brands = json.load(f)
#             return [b for b in all_brands if b.get('success')]
#         except Exception as e:
#             logger.warning(f"Failed to load brand metadata: {e}")
#             return []

#     def _should_screen(self, url: str) -> tuple:
#         """
#         Quick pre-filter: only screenshot URLs that contain a known brand
#         keyword but NOT that brand's official domain.

#         Returns: (should_screen: bool, hint_brand: str | None)
#         """
#         url_lower = url.lower()
#         for brand, official_domain in _BRAND_DOMAINS.items():
#             if brand in url_lower and official_domain not in url_lower:
#                 return True, brand.title()
#         return False, None

#     # ------------------------------------------------------------------
#     # Public API
#     # ------------------------------------------------------------------

#     def analyze(self, url: str) -> dict:
#         """
#         Analyze a URL for visual brand impersonation.

#         Fast path (no Chrome started):
#           - No brand database → skipped: no_brand_database
#           - URL has no brand keywords → skipped: no_brand_keywords

#         Slow path (Chrome launched, ~4-15s):
#           - Screenshot captured, compared against all brand references
#           - Returns match details
#         """
#         # Fast path 1: no brand database
#         if not self.brands:
#             return {
#                 'risk_score': 0.0, 'max_similarity': 0.0, 'matched_brand': None,
#                 'skipped': True, 'reason': 'no_brand_database',
#             }

#         # Fast path 2: URL doesn't mention any known brand
#         should, hint_brand = self._should_screen(url)
#         if not should:
#             return {
#                 'risk_score': 0.0, 'max_similarity': 0.0, 'matched_brand': None,
#                 'skipped': True, 'reason': 'no_brand_keywords',
#             }

#         logger.info(f"🖼️  Visual scan triggered (possible {hint_brand} impersonation): {url}")

#         # Slow path: capture + compare
#         if _CHROME_BINARY is None:
#             logger.warning("🖼️  No Chromium-based browser found — install Brave or Chrome to enable visual scanning")
#             return {
#                 'risk_score': 0.0, 'max_similarity': 0.0, 'matched_brand': None,
#                 'skipped': True, 'reason': 'no_browser_binary',
#             }

#         try:
#             with ScreenshotEngine(headless=True, timeout=15, chrome_binary=_CHROME_BINARY) as engine:
#                 screenshot = engine.capture_screenshot(url)

#             if screenshot is None:
#                 logger.warning(f"🖼️  Screenshot failed for {url}")
#                 return {
#                     'risk_score': 0.0, 'max_similarity': 0.0, 'matched_brand': None,
#                     'skipped': True, 'reason': 'screenshot_failed',
#                 }

#             max_score = 0.0
#             matched_brand = None

#             for brand in self.brands:
#                 ref_path = os.path.join(self.db_path, 'screenshots', brand['screenshot_file'])
#                 if not os.path.exists(ref_path):
#                     continue
#                 try:
#                     result = self.ssim.calculate_ssim(screenshot, ref_path)
#                     score = result['ssim_score']
#                     if score > max_score:
#                         max_score = score
#                         if result['is_clone']:
#                             matched_brand = brand['brand_name']
#                 except Exception as _cmp_err:
#                     logger.warning(f"SSIM comparison failed for {brand['brand_name']}: {_cmp_err}")

#             # risk_score: full SSIM when there's a clone, 30% of SSIM otherwise
#             risk_score = max_score if matched_brand else max_score * 0.3

#             if matched_brand:
#                 logger.warning(f"🚨 Brand impersonation: {matched_brand} ({max_score:.0%} SSIM)")
#             else:
#                 logger.info(f"🖼️  Visual: no clone (max SSIM {max_score:.0%})")

#             return {
#                 'risk_score':     float(risk_score),
#                 'max_similarity': float(max_score),
#                 'matched_brand':  matched_brand,
#                 'skipped':        False,
#                 'reason':         None,
#             }

#         except Exception as e:
#             logger.warning(f"Visual similarity analysis failed: {e}")
#             return {
#                 'risk_score': 0.0, 'max_similarity': 0.0, 'matched_brand': None,
#                 'skipped': True, 'reason': 'exception', 'error': str(e),
#             }

#     def reload_database(self):
#         """Reload brand database from disk (useful after running brand_database_builder.py)."""
#         self.brands = self._load_brands()
#         logger.info(f"🖼️  Visual similarity: reloaded {len(self.brands)} brand references")
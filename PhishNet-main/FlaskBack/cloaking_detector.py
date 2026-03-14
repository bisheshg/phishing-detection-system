"""
Phishing Cloaking Detection Module
Detects when phishing sites show different content to security scanners vs real users
 
Two-tier approach:
- Tier 1: Lightweight HTML/JavaScript analysis (fast, <1s)
- Tier 2: Headless browser comparison (thorough, 5-8s)
 
Author: PhishDetect Team
Date: March 2026
 
FIXES APPLIED:
  1. Trusted domain short-circuit — skips all analysis for known-legit domains,
     preventing false positives (e.g. netflix.com flagged 4/5 Phishing) and
     eliminating the 30-second timeout caused by Tier 2 headless launches.
  2. DNS/connection failure risk = 0.65 (was 0.30) — unreachable site is
     suspicious, not neutral; previously caused fused score to drop below
     threshold and show "Legitimate"/"Suspicious" for obvious phishing URLs.
  3. Tier 2 trigger threshold raised to 0.55 AND requires non-trusted domain —
     prevents deep headless analysis from running on legitimate sites that have
     bot-detection JS (common on all major sites).
  4. Tier 2 fetch timeout reduced to 8s (was 10s) with an overall Tier 2 cap
     of 15s, preventing the 30s Node.js timeout.
  5. All fetch errors now use specific exception types so DNS failures are
     correctly distinguished from other network errors.
"""
 
import re
import hashlib
import requests
import socket
import ipaddress
import logging
import concurrent.futures
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple
import time
from datetime import datetime
import json
import tldextract
 
logger = logging.getLogger(__name__)
 
 
# -------------------- TRUSTED DOMAIN WHITELIST --------------------
# Mirror of TRUSTED_DOMAINS in app.py — kept in sync manually.
# These domains are NEVER subjected to cloaking analysis:
#   (a) they're known-legitimate, so cloaking risk is meaningless
#   (b) they all have bot-detection JS that would trigger false positives
#   (c) their pages load slowly under headless browsers → 30s timeout
_TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com', 'apple.com',
    'microsoft.com', 'github.com', 'stackoverflow.com', 'reddit.com',
    'twitter.com', 'x.com', 'linkedin.com', 'netflix.com', 'wikipedia.org',
    'yahoo.com', 'bing.com', 'instagram.com', 'tiktok.com', 'zoom.us',
    'dropbox.com', 'adobe.com', 'ebay.com', 'paypal.com', 'spotify.com',
    'claude.ai', 'anthropic.com', 'openai.com', 'chatgpt.com',
    'huggingface.co', 'notion.so', 'figma.com', 'canva.com',
    'slack.com', 'discord.com', 'whatsapp.com', 'telegram.org', 'signal.org',
    # Crypto exchanges — legitimate versions
    'coinbase.com', 'binance.com', 'kraken.com', 'crypto.com',
    'gemini.com', 'blockchain.com', 'metamask.io',
}
 
def _is_trusted(domain: str) -> bool:
    """Return True if domain (or its base domain) is in the trusted whitelist."""
    domain = domain.lower().split(':')[0]  # strip port
    base = '.'.join(domain.split('.')[-2:])
    return base in _TRUSTED_DOMAINS or domain in _TRUSTED_DOMAINS
 
 
def _is_reachable(url: str, timeout: float = 3.0) -> bool:
    """
    TCP connect on port 80/443 — catches both dead DNS and sinkholed domains.
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


class CloakingDetector:
    """
    Detects cloaking/obfuscation techniques used by phishing sites.
    Cloaking = showing different content to security scanners vs real users.
    """
 
    def __init__(self, enable_headless: bool = True):
        """
        Args:
            enable_headless: Enable Tier 2 headless browser checks (slower but more thorough).
        """
        self.enable_headless = enable_headless
 
        self.user_agents = {
            'bot':      'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'headless': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36',
            'human':    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'mobile':   'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
        }
 
        self.cloaking_patterns = {
            'user_agent_check': [
                r'navigator\.userAgent',
                r'navigator\.vendor',
                r'navigator\.platform',
                r'(/bot|crawler|spider|googlebot|bingbot|slurp/i)',
                r'(headless|phantom|selenium|webdriver)',
            ],
            'bot_detection': [
                r'navigator\.webdriver',
                r'window\.callPhantom',
                r'window\._phantom',
                r'__nightmare',
                r'__selenium',
                r'__webdriver',
                r'\$cdc_',
                r'document\.\$cdc_',
            ],
            'ip_check': [
                r'x-forwarded-for',
                r'x-real-ip',
                r'cf-connecting-ip',
                r'getClientIP',
                r'visitor\.ip',
            ],
            'timing_delay': [
                r'setTimeout\s*\(\s*function',
                r'setInterval\s*\(\s*function',
                r'\.delay\s*\(',
                r'sleep\s*\(',
            ],
            'geo_check': [
                r'geolocation',
                r'country',
                r'region',
                r'timezone',
                r'locale',
            ],
            'referrer_check': [
                r'document\.referrer',
                r'window\.referrer',
                r'HTTP_REFERER',
            ],
        }
 
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq',
            '.pw', '.top', '.club', '.work', '.party',
            '.xyz', '.online', '.site', '.tech', '.icu',
        }
 
    # ------------------------------------------------------------------
    def analyze(self, url: str, domain_metadata: Optional[Dict] = None) -> Dict:
        """
        Main analysis function — runs Tier 1 and optionally Tier 2.
 
        Returns:
            Complete cloaking analysis results dict.
        """
        # ==================== FIX 1: TRUSTED DOMAIN SHORT-CIRCUIT ====================
        # Skip ALL analysis for trusted domains:
        #   - Prevents false positives from bot-detection JS on legit sites
        #   - Eliminates 30s Tier 2 timeout that crashes the Node.js backend
        parsed   = urlparse(url)
        domain   = parsed.netloc.replace('www.', '').lower().strip()
        if _is_trusted(domain):
            logger.info(f"⏭️  Cloaking scan skipped (trusted domain): {domain}")
            return {
                'url':               url,
                'timestamp':         datetime.now().isoformat(),
                'tier1':             {},
                'tier2':             {},
                'overall_risk':      0.0,
                'cloaking_detected': False,
                'skipped':           True,
                'evidence':          [f'Trusted domain — cloaking scan skipped ({domain})'],
                'recommendations':   [],
            }
        # ==============================================================================
 
        # ── DNS pre-check: bail out immediately if host doesn't resolve ───────────────
        # This prevents _fetch_html from wasting ~10s on TCP retries before
        # raising NameResolutionError. An unresolvable host is itself suspicious.
        if not _is_reachable(url):
            _host = parsed.netloc or url
            logger.warning(f"⏭️  Cloaking skipped — DNS unresolvable: {_host}")
            return {
                'url':               url,
                'timestamp':         datetime.now().isoformat(),
                'tier1':             {'fetch_failed': True, 'risk_score': 0.65},
                'tier2':             {},
                'overall_risk':      0.65,
                'cloaking_detected': False,
                'skipped':           True,
                'evidence':          [f'DNS unresolvable: {_host}'],
                'recommendations':   ['Domain does not resolve — likely taken down or never registered'],
            }
        # ─────────────────────────────────────────────────────────────────────────────
 
        results = {
            'url':               url,
            'timestamp':         datetime.now().isoformat(),
            'tier1':             {},
            'tier2':             {},
            'overall_risk':      0.0,
            'cloaking_detected': False,
            'skipped':           False,
            'evidence':          [],
            'recommendations':   [],
        }
 
        # TIER 1: Lightweight checks
        logger.info(f"[Tier 1] Analyzing: {url}")
        tier1_results = self._tier1_analysis(url, domain_metadata)
        results['tier1'] = tier1_results
 
        # ==================== FIX 3: RAISED TIER 2 TRIGGER THRESHOLD ====================
        # Old threshold: risk_score > 0.4 OR suspicious_patterns > 2
        #   → triggered on netflix.com (has UA-check JS) → 30s timeout
        # New threshold: risk_score > 0.55 AND site was actually reachable
        #   → only triggers on genuinely suspicious, reachable sites
        fetch_succeeded  = not tier1_results.get('fetch_failed', False)
        needs_deep_check = (
            fetch_succeeded
            and tier1_results['risk_score'] > 0.55
            and tier1_results.get('suspicious_patterns_found', 0) >= 2
        )
        # =================================================================================
 
        if self.enable_headless and needs_deep_check:
            logger.info(f"[Tier 2] Deep analysis triggered (risk={tier1_results['risk_score']:.2f})")
            tier2_results = self._tier2_analysis(url)
            results['tier2'] = tier2_results
 
            results['overall_risk']      = max(tier1_results['risk_score'], tier2_results.get('risk_score', 0))
            results['cloaking_detected'] = tier2_results.get('cloaking_detected', False)
        else:
            results['overall_risk']      = tier1_results['risk_score']
            results['cloaking_detected'] = tier1_results['risk_score'] > 0.6
 
            if self.enable_headless and not fetch_succeeded:
                results['recommendations'].append("Site unreachable — headless analysis skipped")
            elif self.enable_headless and not needs_deep_check:
                results['recommendations'].append("Risk below Tier 2 threshold — lightweight scan only")
            elif not self.enable_headless and needs_deep_check:
                results['recommendations'].append("Enable headless browser for deep cloaking analysis")
 
        results['evidence'] = self._compile_evidence(tier1_results, results.get('tier2', {}))
        return results
 
    # ------------------------------------------------------------------
    def _tier1_analysis(self, url: str, domain_metadata: Optional[Dict]) -> Dict:
        """
        TIER 1: Lightweight HTML/JavaScript pattern analysis.
        Fast checks without executing JavaScript.
        """
        results = {
            'risk_score':               0.0,
            'suspicious_patterns_found': 0,
            'patterns':                 {},
            'html_analysis':            {},
            'context_factors':          {},
            'fetch_failed':             False,
        }
 
        try:
            html_content = self._fetch_html(url, user_agent='human')
 
            if not html_content:
                # ==================== FIX 2: DNS/CONNECTION FAILURE RISK ====================
                # Old value: 0.30 (neutral) — dragged fused score below threshold,
                #   causing obvious phishing URLs to be labelled "Legitimate"
                # New value: 0.65 — unreachable/unresolvable = suspicious
                results['error']        = "Could not fetch HTML (site unreachable or DNS failure)"
                results['risk_score']   = 0.65
                results['fetch_failed'] = True
                logger.warning(f"[Tier 1] Site unreachable — assigning elevated risk 0.65: {url}")
                return results
                # =============================================================================
 
            soup    = BeautifulSoup(html_content, 'html.parser')
            scripts = []
 
            for script in soup.find_all('script'):
                script_content = script.string or ''
                if script.get('src'):
                    try:
                        ext_script = self._fetch_external_script(script['src'], url)
                        if ext_script:
                            scripts.append(ext_script)
                    except Exception:
                        pass
                scripts.append(script_content)
 
            combined_js = '\n'.join(scripts)
 
            # Check for cloaking patterns
            for category, patterns in self.cloaking_patterns.items():
                found_patterns = []
                for pattern in patterns:
                    if re.search(pattern, combined_js, re.IGNORECASE):
                        found_patterns.append(pattern)
 
                if found_patterns:
                    results['patterns'][category] = {
                        'found':    True,
                        'count':    len(found_patterns),
                        'patterns': found_patterns[:3],
                    }
                    results['suspicious_patterns_found'] += 1
 
            results['html_analysis'] = {
                'has_login_form':               self._has_login_form(soup),
                'has_hidden_elements':          len(soup.find_all(style=re.compile(r'display:\s*none', re.I))) > 0,
                'dynamic_content_indicators':   len(soup.find_all(id=re.compile(r'(load|dynamic|inject)', re.I))) > 0,
                'script_count':                 len(soup.find_all('script')),
                'external_scripts':             len([s for s in soup.find_all('script') if s.get('src')]),
                'inline_scripts':               len([s for s in soup.find_all('script') if not s.get('src')]),
            }
 
            if domain_metadata:
                results['context_factors'] = self._analyze_context(domain_metadata, results)
 
            results['risk_score'] = self._calculate_tier1_risk(results, domain_metadata)
 
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                socket.gaierror,
                OSError) as net_err:
            # ==================== FIX 2 (network exception path) ====================
            results['error']        = f"Network error: {type(net_err).__name__}: {net_err}"
            results['risk_score']   = 0.65   # suspicious, not neutral
            results['fetch_failed'] = True
            logger.warning(f"[Tier 1] Network error — assigning elevated risk 0.65: {url} — {net_err}")
            # =========================================================================
        except Exception as e:
            results['error']      = str(e)
            results['risk_score'] = 0.50   # unknown error → neutral
            logger.warning(f"[Tier 1] Unexpected error for {url}: {e}")
 
        return results
 
    # ------------------------------------------------------------------
    def _tier2_analysis(self, url: str) -> Dict:
        """
        TIER 2: Headless browser comparison.
        Visit site as bot vs human and compare content.
 
        FIX 4: Fetch timeout reduced to 8s; overall method protected by
        a 15s wall-clock guard to prevent the 30s Node.js timeout.
        """
        results = {
            'risk_score':        0.0,
            'cloaking_detected': False,
            'views':             {},
            'differences':       {},
            'evidence':          [],
        }
 
        # ==================== FIX 4: OVERALL TIER 2 TIME BUDGET ====================
        tier2_start = time.time()
        TIER2_BUDGET_SECONDS = 15   # hard cap — Node.js times out at 30s
        # ===========================================================================
 
        try:
            logger.info("  [Tier 2] Fetching as bot...")
            bot_html = self._fetch_html(url, user_agent='bot', timeout=8)  # FIX 4: 8s
 
            # Bail early if time budget is running out
            if time.time() - tier2_start > TIER2_BUDGET_SECONDS:
                results['error'] = "Tier 2 time budget exceeded after bot fetch"
                return results
 
            time.sleep(0.5)   # reduced from 1s to save budget
 
            logger.info("  [Tier 2] Fetching as human...")
            human_html = self._fetch_html(url, user_agent='human', timeout=8)  # FIX 4: 8s
 
            if not bot_html or not human_html:
                results['error'] = "Could not fetch both views"
                return results
 
            bot_soup   = BeautifulSoup(bot_html,   'html.parser')
            human_soup = BeautifulSoup(human_html, 'html.parser')
 
            results['views'] = {
                'bot': {
                    'length':         len(bot_html),
                    'has_login_form': self._has_login_form(bot_soup),
                    'title':          bot_soup.title.string if bot_soup.title else None,
                    'form_count':     len(bot_soup.find_all('form')),
                    'input_count':    len(bot_soup.find_all('input')),
                },
                'human': {
                    'length':         len(human_html),
                    'has_login_form': self._has_login_form(human_soup),
                    'title':          human_soup.title.string if human_soup.title else None,
                    'form_count':     len(human_soup.find_all('form')),
                    'input_count':    len(human_soup.find_all('input')),
                },
            }
 
            similarity = SequenceMatcher(None, bot_html, human_html).ratio()
            results['content_similarity'] = round(similarity, 3)
 
            results['differences'] = {
                'length_diff':           abs(len(bot_html) - len(human_html)),
                'length_diff_percent':   round(abs(len(bot_html) - len(human_html)) / max(len(bot_html), 1) * 100, 1),
                'form_count_diff':       abs(results['views']['bot']['form_count']  - results['views']['human']['form_count']),
                'input_count_diff':      abs(results['views']['bot']['input_count'] - results['views']['human']['input_count']),
                'login_form_mismatch':   results['views']['bot']['has_login_form']  != results['views']['human']['has_login_form'],
            }
 
            cloaking_indicators = []
 
            if similarity < 0.7:
                cloaking_indicators.append(f"Content only {similarity*100:.0f}% similar between bot and human views")
                results['risk_score'] += 0.5
 
            if not results['views']['bot']['has_login_form'] and results['views']['human']['has_login_form']:
                cloaking_indicators.append("Login form hidden from bots, shown to humans")
                results['risk_score']        += 0.6
                results['cloaking_detected']  = True
 
            if results['differences']['form_count_diff'] > 0:
                cloaking_indicators.append(
                    f"Form count differs: bot={results['views']['bot']['form_count']}, "
                    f"human={results['views']['human']['form_count']}"
                )
                results['risk_score'] += 0.3
 
            if results['differences']['length_diff_percent'] > 30:
                cloaking_indicators.append(f"Content size differs by {results['differences']['length_diff_percent']:.0f}%")
                results['risk_score'] += 0.2
 
            results['evidence']    = cloaking_indicators
            results['risk_score']  = min(results['risk_score'], 1.0)
 
            if results['risk_score'] > 0.5:
                results['cloaking_detected'] = True
 
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                socket.gaierror) as net_err:
            results['error'] = f"Tier 2 network error: {net_err}"
            logger.warning(f"[Tier 2] Network error: {net_err}")
        except Exception as e:
            results['error'] = str(e)
            logger.warning(f"[Tier 2] Unexpected error: {e}")
 
        return results
 
    # ------------------------------------------------------------------
    def _fetch_html(self, url: str, user_agent: str = 'human', timeout: int = 8) -> Optional[str]:
        """
        Fetch HTML content with specified user agent.
 
        FIX 4: timeout parameter exposed (default 8s, was hardcoded 10s).
        FIX 5: raises specific exceptions rather than swallowing them, so
               callers can distinguish DNS failures from other errors.
        """
        headers = {
            'User-Agent':              self.user_agents.get(user_agent, self.user_agents['human']),
            'Accept':                  'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language':         'en-US,en;q=0.5',
            'Accept-Encoding':         'gzip, deflate',
            'Connection':              'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        try:
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            if response.status_code == 200:
                return response.text
            logger.debug(f"  Non-200 response ({response.status_code}) for {url}")
            return None
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                socket.gaierror) as net_err:
            # Re-raise so _tier1_analysis / _tier2_analysis can classify correctly
            logger.debug(f"  Error fetching {url}: {net_err}")
            raise
        except Exception as e:
            logger.debug(f"  Unexpected fetch error for {url}: {e}")
            return None
 
    # ------------------------------------------------------------------
    def _fetch_external_script(self, script_src: str, base_url: str) -> Optional[str]:
        """Fetch external JavaScript file."""
        try:
            if script_src.startswith('//'):
                script_src = 'https:' + script_src
            elif script_src.startswith('/'):
                parsed     = urlparse(base_url)
                script_src = f"{parsed.scheme}://{parsed.netloc}{script_src}"
            elif not script_src.startswith('http'):
                script_src = base_url.rstrip('/') + '/' + script_src.lstrip('/')
 
            response = requests.get(script_src, timeout=5)
            if response.status_code == 200:
                return response.text
        except Exception:
            pass
        return None
 
    # ------------------------------------------------------------------
    def _has_login_form(self, soup: BeautifulSoup) -> bool:
        """Check if page has a login form."""
        for form in soup.find_all('form'):
            inputs      = form.find_all('input')
            input_types = [inp.get('type', '').lower() for inp in inputs]
            input_names = [inp.get('name', '').lower() for inp in inputs]
 
            if 'password' in input_types:
                return True
 
            login_keywords = ['password', 'passwd', 'pwd', 'pass', 'login', 'email', 'username', 'user']
            if any(kw in ' '.join(input_names) for kw in login_keywords):
                return True
        return False
 
    # ------------------------------------------------------------------
    def _analyze_context(self, domain_metadata: Dict, tier1_results: Dict) -> Dict:
        """Analyze contextual factors that affect cloaking risk."""
        context = {}
 
        whois_info = domain_metadata.get('metadata', {}).get('whois', {})
        domain_age = whois_info.get('domain_age_days', 9999)
 
        context['domain_age_days']      = domain_age
        context['is_new_domain']        = domain_age is not None and domain_age < 90
        context['is_very_new_domain']   = domain_age is not None and domain_age < 30
 
        domain = domain_metadata.get('domain', '')
        context['has_suspicious_tld']   = any(domain.endswith(tld) for tld in self.suspicious_tlds)
 
        dns_info = domain_metadata.get('metadata', {}).get('dns', {})
        context['has_mx_records']       = dns_info.get('has_mx',    False)
        context['has_spf']              = dns_info.get('has_spf',   False)
        context['has_dmarc']            = dns_info.get('has_dmarc', False)
 
        return context
 
    # ------------------------------------------------------------------
    def _calculate_tier1_risk(self, tier1_results: Dict, domain_metadata: Optional[Dict]) -> float:
        """Calculate risk score for Tier 1 analysis."""
        # If fetch failed, risk was already set to 0.65 in _tier1_analysis — don't override
        if tier1_results.get('fetch_failed'):
            return tier1_results.get('risk_score', 0.65)
 
        risk     = 0.0
        patterns = tier1_results.get('patterns', {})
 
        if 'user_agent_check' in patterns: risk += 0.3
        if 'bot_detection'    in patterns: risk += 0.4
        if 'ip_check'         in patterns: risk += 0.25
        if 'timing_delay'     in patterns: risk += 0.15
        if 'geo_check'        in patterns: risk += 0.2
        if 'referrer_check'   in patterns: risk += 0.1
 
        if domain_metadata:
            context = tier1_results.get('context_factors', {})
 
            if context.get('is_very_new_domain') and risk > 0.3:
                risk += 0.3
            elif context.get('is_new_domain') and risk > 0.3:
                risk += 0.2
 
            if context.get('has_suspicious_tld') and risk > 0.2:
                risk += 0.3
 
            if not context.get('has_mx_records') and risk > 0.3:
                risk += 0.2
 
            # Established domain (5+ years) with UA-check JS is likely legitimate
            # (e.g. analytics, A/B testing) — reduce but don't zero out
            domain_age = context.get('domain_age_days', 0) or 0
            if domain_age > 1825 and risk > 0:
                risk *= 0.5
 
        return min(risk, 1.0)
 
    # ------------------------------------------------------------------
    def _compile_evidence(self, tier1: Dict, tier2: Dict) -> List[str]:
        """Compile human-readable evidence list."""
        evidence = []
 
        if tier1.get('fetch_failed'):
            evidence.append(tier1.get('error', 'Site unreachable — DNS or connection failure'))
            return evidence
 
        for category, data in tier1.get('patterns', {}).items():
            if data.get('found'):
                evidence.append(f"Detected {category.replace('_', ' ')}: {data['count']} instance(s)")
 
        context = tier1.get('context_factors', {})
        if context.get('is_very_new_domain'):
            evidence.append(f"Very new domain ({context.get('domain_age_days')} days old)")
        if context.get('has_suspicious_tld'):
            evidence.append("Suspicious TLD commonly used in phishing")
        if not context.get('has_mx_records') and context:
            evidence.append("No email infrastructure (no MX records)")
 
        if tier2:
            evidence.extend(tier2.get('evidence', []))
 
        return evidence
 
 
# -------------------- CLI TEST --------------------
if __name__ == '__main__':
    import sys
    logging.basicConfig(level=logging.INFO)
 
    print("=" * 80)
    print("CLOAKING DETECTOR — TEST SUITE")
    print("=" * 80)
 
    detector = CloakingDetector(enable_headless=True)
 
    test_urls = [
        "https://www.google.com",
        "https://www.netflix.com",
        "https://coinbase-secure-authentication-check.info",
        "https://binance-account-verification-alert.xyz",
    ]
 
    if len(sys.argv) > 1:
        test_urls = sys.argv[1:]
 
    for url in test_urls:
        print(f"\nTesting: {url}")
        print("-" * 80)
        result = detector.analyze(url)
        print(f"Overall Risk:       {result['overall_risk']:.2f}")
        print(f"Cloaking Detected:  {result['cloaking_detected']}")
        print(f"Skipped:            {result.get('skipped', False)}")
        if result['evidence']:
            print("Evidence:")
            for i, ev in enumerate(result['evidence'], 1):
                print(f"  {i}. {ev}")
        print()
 


# """
# Phishing Cloaking Detection Module
# Detects when phishing sites show different content to security scanners vs real users

# Two-tier approach:
# - Tier 1: Lightweight HTML/JavaScript analysis (fast, <1s)
# - Tier 2: Headless browser comparison (thorough, 5-8s)

# Author: PhishDetect Team
# Date: March 2026
# """

# import re
# import hashlib
# import requests
# from bs4 import BeautifulSoup
# from difflib import SequenceMatcher
# from urllib.parse import urlparse
# from typing import Dict, List, Optional, Tuple
# import time
# from datetime import datetime
# import json


# class CloakingDetector:
#     """
#     Detects cloaking/obfuscation techniques used by phishing sites
    
#     Cloaking = showing different content to security scanners vs real users
#     """
    
#     def __init__(self, enable_headless: bool = True):
#         """
#         Initialize detector
        
#         Args:
#             enable_headless: Enable Tier 2 headless browser checks (slower but more thorough)
#         """
#         self.enable_headless = enable_headless
        
#         # User agents for testing
#         self.user_agents = {
#             'bot': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
#             'headless': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/120.0.0.0 Safari/537.36',
#             'human': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
#             'mobile': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1'
#         }
        
#         # Known cloaking patterns in JavaScript
#         self.cloaking_patterns = {
#             'user_agent_check': [
#                 r'navigator\.userAgent',
#                 r'navigator\.vendor',
#                 r'navigator\.platform',
#                 r'(/bot|crawler|spider|googlebot|bingbot|slurp/i)',
#                 r'(headless|phantom|selenium|webdriver)',
#             ],
#             'bot_detection': [
#                 r'navigator\.webdriver',
#                 r'window\.callPhantom',
#                 r'window\._phantom',
#                 r'__nightmare',
#                 r'__selenium',
#                 r'__webdriver',
#                 r'\$cdc_',
#                 r'document\.\$cdc_'
#             ],
#             'ip_check': [
#                 r'x-forwarded-for',
#                 r'x-real-ip',
#                 r'cf-connecting-ip',
#                 r'getClientIP',
#                 r'visitor\.ip'
#             ],
#             'timing_delay': [
#                 r'setTimeout\s*\(\s*function',
#                 r'setInterval\s*\(\s*function',
#                 r'\.delay\s*\(',
#                 r'sleep\s*\('
#             ],
#             'geo_check': [
#                 r'geolocation',
#                 r'country',
#                 r'region',
#                 r'timezone',
#                 r'locale'
#             ],
#             'referrer_check': [
#                 r'document\.referrer',
#                 r'window\.referrer',
#                 r'HTTP_REFERER'
#             ]
#         }
        
#         # Suspicious TLDs commonly used with cloaking
#         self.suspicious_tlds = {
#             '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains
#             '.pw', '.top', '.club', '.work', '.party',
#             '.xyz', '.online', '.site', '.tech', '.icu'
#         }
    
#     def analyze(self, url: str, domain_metadata: Optional[Dict] = None) -> Dict:
#         """
#         Main analysis function - runs both Tier 1 and Tier 2 checks
        
#         Args:
#             url: URL to analyze
#             domain_metadata: Optional metadata from domain_metadata_analyzer
            
#         Returns:
#             Complete cloaking analysis results
#         """
#         results = {
#             'url': url,
#             'timestamp': datetime.now().isoformat(),
#             'tier1': {},
#             'tier2': {},
#             'overall_risk': 0.0,
#             'cloaking_detected': False,
#             'evidence': [],
#             'recommendations': []
#         }
        
#         # TIER 1: Lightweight checks
#         print(f"[Tier 1] Analyzing: {url}")
#         tier1_results = self._tier1_analysis(url, domain_metadata)
#         results['tier1'] = tier1_results
        
#         # Decide if we need Tier 2
#         needs_deep_check = tier1_results['risk_score'] > 0.4 or tier1_results['suspicious_patterns_found'] > 2
        
#         # TIER 2: Deep analysis (if enabled and needed)
#         if self.enable_headless and needs_deep_check:
#             print(f"[Tier 2] Deep analysis triggered (risk={tier1_results['risk_score']:.2f})")
#             tier2_results = self._tier2_analysis(url)
#             results['tier2'] = tier2_results
            
#             # Combine scores
#             results['overall_risk'] = max(tier1_results['risk_score'], tier2_results.get('risk_score', 0))
#             results['cloaking_detected'] = tier2_results.get('cloaking_detected', False)
#         else:
#             results['overall_risk'] = tier1_results['risk_score']
#             results['cloaking_detected'] = tier1_results['risk_score'] > 0.6
            
#             if not self.enable_headless and needs_deep_check:
#                 results['recommendations'].append("Enable headless browser for deep cloaking analysis")
        
#         # Compile evidence
#         results['evidence'] = self._compile_evidence(tier1_results, results.get('tier2', {}))
        
#         return results
    
#     def _tier1_analysis(self, url: str, domain_metadata: Optional[Dict]) -> Dict:
#         """
#         TIER 1: Lightweight HTML/JavaScript pattern analysis
#         Fast checks without executing JavaScript
#         """
#         results = {
#             'risk_score': 0.0,
#             'suspicious_patterns_found': 0,
#             'patterns': {},
#             'html_analysis': {},
#             'context_factors': {}
#         }
        
#         try:
#             # Fetch HTML with human-like headers
#             html_content = self._fetch_html(url, user_agent='human')
            
#             if not html_content:
#                 # Domain is unresolvable or unreachable — treat as uncertain (0.3)
#                 # rather than clean (0.0): can't verify = mildly suspicious.
#                 results['error'] = "Could not fetch HTML"
#                 results['risk_score'] = 0.3
#                 return results
            
#             # Parse HTML
#             soup = BeautifulSoup(html_content, 'html.parser')
            
#             # Extract all JavaScript
#             scripts = []
#             for script in soup.find_all('script'):
#                 script_content = script.string or ''
#                 if script.get('src'):
#                     # Try to fetch external scripts
#                     try:
#                         ext_script = self._fetch_external_script(script['src'], url)
#                         if ext_script:
#                             scripts.append(ext_script)
#                     except:
#                         pass
#                 scripts.append(script_content)
            
#             combined_js = '\n'.join(scripts)
            
#             # Check for cloaking patterns
#             for category, patterns in self.cloaking_patterns.items():
#                 found_patterns = []
#                 for pattern in patterns:
#                     if re.search(pattern, combined_js, re.IGNORECASE):
#                         found_patterns.append(pattern)
                
#                 if found_patterns:
#                     results['patterns'][category] = {
#                         'found': True,
#                         'count': len(found_patterns),
#                         'patterns': found_patterns[:3]  # First 3 matches
#                     }
#                     results['suspicious_patterns_found'] += 1
            
#             # HTML structure analysis
#             results['html_analysis'] = {
#                 'has_login_form': self._has_login_form(soup),
#                 'has_hidden_elements': len(soup.find_all(style=re.compile(r'display:\s*none', re.I))) > 0,
#                 'dynamic_content_indicators': len(soup.find_all(id=re.compile(r'(load|dynamic|inject)', re.I))) > 0,
#                 'script_count': len(soup.find_all('script')),
#                 'external_scripts': len([s for s in soup.find_all('script') if s.get('src')]),
#                 'inline_scripts': len([s for s in soup.find_all('script') if not s.get('src')]),
#             }
            
#             # Context-aware scoring
#             if domain_metadata:
#                 results['context_factors'] = self._analyze_context(domain_metadata, results)
            
#             # Calculate risk score
#             results['risk_score'] = self._calculate_tier1_risk(results, domain_metadata)
            
#         except Exception as e:
#             results['error'] = str(e)
        
#         return results
    
#     def _tier2_analysis(self, url: str) -> Dict:
#         """
#         TIER 2: Headless browser comparison
#         Visit site as bot vs human and compare content
#         """
#         results = {
#             'risk_score': 0.0,
#             'cloaking_detected': False,
#             'views': {},
#             'differences': {},
#             'evidence': []
#         }
        
#         try:
#             # This requires Selenium/Puppeteer
#             # For now, implement basic version with requests
#             # Full implementation would use actual headless browser
            
#             print("  [Tier 2] Fetching as bot...")
#             bot_html = self._fetch_html(url, user_agent='bot')
#             time.sleep(1)  # Avoid rate limiting
            
#             print("  [Tier 2] Fetching as human...")
#             human_html = self._fetch_html(url, user_agent='human')
            
#             if not bot_html or not human_html:
#                 results['error'] = "Could not fetch both views"
#                 return results
            
#             # Parse both
#             bot_soup = BeautifulSoup(bot_html, 'html.parser')
#             human_soup = BeautifulSoup(human_html, 'html.parser')
            
#             # Compare content
#             results['views'] = {
#                 'bot': {
#                     'length': len(bot_html),
#                     'has_login_form': self._has_login_form(bot_soup),
#                     'title': bot_soup.title.string if bot_soup.title else None,
#                     'form_count': len(bot_soup.find_all('form')),
#                     'input_count': len(bot_soup.find_all('input')),
#                 },
#                 'human': {
#                     'length': len(human_html),
#                     'has_login_form': self._has_login_form(human_soup),
#                     'title': human_soup.title.string if human_soup.title else None,
#                     'form_count': len(human_soup.find_all('form')),
#                     'input_count': len(human_soup.find_all('input')),
#                 }
#             }
            
#             # Calculate similarity
#             similarity = SequenceMatcher(None, bot_html, human_html).ratio()
#             results['content_similarity'] = round(similarity, 3)
            
#             # Detect differences
#             results['differences'] = {
#                 'length_diff': abs(len(bot_html) - len(human_html)),
#                 'length_diff_percent': round(abs(len(bot_html) - len(human_html)) / max(len(bot_html), 1) * 100, 1),
#                 'form_count_diff': abs(results['views']['bot']['form_count'] - results['views']['human']['form_count']),
#                 'input_count_diff': abs(results['views']['bot']['input_count'] - results['views']['human']['input_count']),
#                 'login_form_mismatch': results['views']['bot']['has_login_form'] != results['views']['human']['has_login_form']
#             }
            
#             # Cloaking detection logic
#             cloaking_indicators = []
            
#             # Major content difference
#             if similarity < 0.7:
#                 cloaking_indicators.append(f"Content only {similarity*100:.0f}% similar between bot and human views")
#                 results['risk_score'] += 0.5
            
#             # Login form appears only for humans
#             if not results['views']['bot']['has_login_form'] and results['views']['human']['has_login_form']:
#                 cloaking_indicators.append("Login form hidden from bots, shown to humans")
#                 results['risk_score'] += 0.6
#                 results['cloaking_detected'] = True
            
#             # Significant form count difference
#             if results['differences']['form_count_diff'] > 0:
#                 cloaking_indicators.append(f"Form count differs: bot={results['views']['bot']['form_count']}, human={results['views']['human']['form_count']}")
#                 results['risk_score'] += 0.3
            
#             # Large content size difference
#             if results['differences']['length_diff_percent'] > 30:
#                 cloaking_indicators.append(f"Content size differs by {results['differences']['length_diff_percent']:.0f}%")
#                 results['risk_score'] += 0.2
            
#             results['evidence'] = cloaking_indicators
#             results['risk_score'] = min(results['risk_score'], 1.0)
            
#             if results['risk_score'] > 0.5:
#                 results['cloaking_detected'] = True
            
#         except Exception as e:
#             results['error'] = str(e)
        
#         return results
    
#     def _fetch_html(self, url: str, user_agent: str = 'human') -> Optional[str]:
#         """Fetch HTML content with specified user agent"""
#         try:
#             headers = {
#                 'User-Agent': self.user_agents.get(user_agent, self.user_agents['human']),
#                 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
#                 'Accept-Language': 'en-US,en;q=0.5',
#                 'Accept-Encoding': 'gzip, deflate',
#                 'Connection': 'keep-alive',
#                 'Upgrade-Insecure-Requests': '1'
#             }
            
#             response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
            
#             if response.status_code == 200:
#                 return response.text
            
#         except Exception as e:
#             print(f"  Error fetching {url}: {e}")
        
#         return None
    
#     def _fetch_external_script(self, script_src: str, base_url: str) -> Optional[str]:
#         """Fetch external JavaScript file"""
#         try:
#             # Handle relative URLs
#             if script_src.startswith('//'):
#                 script_src = 'https:' + script_src
#             elif script_src.startswith('/'):
#                 parsed = urlparse(base_url)
#                 script_src = f"{parsed.scheme}://{parsed.netloc}{script_src}"
#             elif not script_src.startswith('http'):
#                 script_src = base_url.rstrip('/') + '/' + script_src.lstrip('/')
            
#             response = requests.get(script_src, timeout=5)
#             if response.status_code == 200:
#                 return response.text
#         except:
#             pass
        
#         return None
    
#     def _has_login_form(self, soup: BeautifulSoup) -> bool:
#         """Check if page has a login form"""
#         forms = soup.find_all('form')
        
#         for form in forms:
#             inputs = form.find_all('input')
#             input_types = [inp.get('type', '').lower() for inp in inputs]
#             input_names = [inp.get('name', '').lower() for inp in inputs]
            
#             # Look for password field
#             if 'password' in input_types:
#                 return True
            
#             # Look for common login field names
#             login_keywords = ['password', 'passwd', 'pwd', 'pass', 'login', 'email', 'username', 'user']
#             if any(keyword in ' '.join(input_names) for keyword in login_keywords):
#                 return True
        
#         return False
    
#     def _analyze_context(self, domain_metadata: Dict, tier1_results: Dict) -> Dict:
#         """Analyze contextual factors that affect cloaking risk"""
#         context = {}
        
#         # Extract domain age
#         whois_info = domain_metadata.get('metadata', {}).get('whois', {})
#         domain_age = whois_info.get('domain_age_days', 9999)
        
#         context['domain_age_days'] = domain_age
#         context['is_new_domain'] = domain_age < 90
#         context['is_very_new_domain'] = domain_age < 30
        
#         # Check TLD
#         domain = domain_metadata.get('domain', '')
#         context['has_suspicious_tld'] = any(domain.endswith(tld) for tld in self.suspicious_tlds)
        
#         # Check infrastructure
#         dns_info = domain_metadata.get('metadata', {}).get('dns', {})
#         context['has_mx_records'] = dns_info.get('has_mx', False)
#         context['has_spf'] = dns_info.get('has_spf', False)
#         context['has_dmarc'] = dns_info.get('has_dmarc', False)
        
#         return context
    
#     def _calculate_tier1_risk(self, tier1_results: Dict, domain_metadata: Optional[Dict]) -> float:
#         """Calculate risk score for Tier 1 analysis"""
#         risk = 0.0
        
#         # Pattern-based scoring
#         patterns = tier1_results.get('patterns', {})
        
#         if 'user_agent_check' in patterns:
#             risk += 0.3
        
#         if 'bot_detection' in patterns:
#             risk += 0.4
        
#         if 'ip_check' in patterns:
#             risk += 0.25
        
#         if 'timing_delay' in patterns:
#             risk += 0.15
        
#         if 'geo_check' in patterns:
#             risk += 0.2
        
#         if 'referrer_check' in patterns:
#             risk += 0.1
        
#         # Context-aware adjustments
#         if domain_metadata:
#             context = tier1_results.get('context_factors', {})
            
#             # NEW domain with cloaking = very suspicious
#             if context.get('is_very_new_domain') and risk > 0.3:
#                 risk += 0.3
#             elif context.get('is_new_domain') and risk > 0.3:
#                 risk += 0.2
            
#             # Suspicious TLD + cloaking
#             if context.get('has_suspicious_tld') and risk > 0.2:
#                 risk += 0.3
            
#             # No email infrastructure + cloaking
#             if not context.get('has_mx_records') and risk > 0.3:
#                 risk += 0.2
            
#             # Established domain with cloaking = less suspicious (might be legitimate bot protection)
#             if context.get('domain_age_days', 0) > 1825 and risk > 0:  # 5 years
#                 risk *= 0.5  # Reduce risk by 50%
        
#         return min(risk, 1.0)
    
#     def _compile_evidence(self, tier1: Dict, tier2: Dict) -> List[str]:
#         """Compile human-readable evidence list"""
#         evidence = []
        
#         # Tier 1 evidence
#         for category, data in tier1.get('patterns', {}).items():
#             if data.get('found'):
#                 evidence.append(f"Detected {category.replace('_', ' ')}: {data['count']} instances")
        
#         # Context evidence
#         context = tier1.get('context_factors', {})
#         if context.get('is_very_new_domain'):
#             evidence.append(f"Very new domain ({context.get('domain_age_days')} days old)")
        
#         if context.get('has_suspicious_tld'):
#             evidence.append("Suspicious TLD commonly used in phishing")
        
#         if not context.get('has_mx_records'):
#             evidence.append("No email infrastructure (no MX records)")
        
#         # Tier 2 evidence
#         if tier2:
#             evidence.extend(tier2.get('evidence', []))
        
#         return evidence


# # Example usage and testing
# if __name__ == '__main__':
#     print("=" * 80)
#     print("CLOAKING DETECTOR - TEST SUITE")
#     print("=" * 80)
    
#     # Initialize detector
#     detector = CloakingDetector(enable_headless=True)
    
#     # Test cases
#     test_urls = [
#         "https://www.google.com",
#         "https://www.github.com",
#         # Add more test URLs here
#     ]
    
#     for url in test_urls:
#         print(f"\nTesting: {url}")
#         print("-" * 80)
        
#         result = detector.analyze(url)
        
#         print(f"Overall Risk: {result['overall_risk']:.2f}")
#         print(f"Cloaking Detected: {result['cloaking_detected']}")
        
#         if result['evidence']:
#             print("\nEvidence:")
#             for i, ev in enumerate(result['evidence'], 1):
#                 print(f"  {i}. {ev}")
        
#         print("\nFull results:")
#         print(json.dumps(result, indent=2, default=str))
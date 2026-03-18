#!/usr/bin/env python3
"""
Enhanced Rule Engine for Phishing Detection
Fast rule-based detection for obvious phishing patterns
"""

import re
import ipaddress
import tldextract
from urllib.parse import urlparse
from Levenshtein import distance

class RuleEngine:
    """
    Fast rule-based detection for obvious phishing patterns
    """

    SUSPICIOUS_TLDS = [
        'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs (high phishing rate)
        'pw', 'cc', 'top', 'xyz', 'work', 'date', 'download',
        'racing', 'review', 'faith', 'science', 'party'
    ]

    LEGITIMATE_TLDS = [
        'com', 'org', 'net', 'edu', 'gov',
        'mil', 'int', 'co.uk', 'ac.uk', 'gov.uk'
    ]

    FINANCIAL_KEYWORDS = [
        # Global financial keywords
        'bank', 'paypal', 'amazon', 'login', 'signin',
        'account', 'verify', 'secure', 'update', 'confirm',
        'billing', 'payment', 'wallet', 'crypto', 'ebay',
        'password', 'credential', 'suspended', 'limited',
        'unlock', 'restore', 'validate',
        # Nepal-specific keywords
        'esewa', 'khalti', 'connectips', 'ncell', 'ntc',
        'recharge', 'topup', 'kyc', 'nabil', 'nicasia',
        # Modern phishing patterns
        'claim', 'prize', 'winner', 'alert', 'notice',
        'tracking', 'delivery', 'parcel', 'customs',
    ]

    KNOWN_BRANDS = [
        # Global brands
        'google', 'facebook', 'amazon', 'paypal', 'apple',
        'microsoft', 'netflix', 'instagram', 'twitter', 'linkedin',
        'ebay', 'yahoo', 'chase', 'wellsfargo', 'bankofamerica',
        # Apple product aliases
        'appleid', 'icloud', 'itunes',
        # Crypto exchanges
        'coinbase', 'binance', 'metamask', 'kraken', 'blockchain',
        # Nepal digital payments
        'esewa', 'khalti', 'connectips', 'imepay',
        # Nepal banks
        'nicasia', 'globalime', 'nabil', 'himalayan', 'siddhartha',
        'everest', 'kumari', 'sanima', 'prabhu', 'laxmi',
        # Nepal telecom
        'ncell', 'subisu', 'dishhome',
    ]

    # Lookalike character substitutions used in homograph attacks
    # e.g. paypaI (capital I) → paypal, g00gle (zeros) → google
    HOMOGLYPH_MAP = str.maketrans({
        ord('I'): 'l',   # capital I → lowercase l  (paypaI → paypal)
        ord('1'): 'l',   # digit 1 → lowercase l    (paypa1 → paypal)
        ord('0'): 'o',   # digit 0 → lowercase o    (g00gle → google)
        ord('3'): 'e',   # digit 3 → lowercase e
        ord('4'): 'a',   # digit 4 → lowercase a
        ord('5'): 's',   # digit 5 → lowercase s
    })

    # TLD words that attackers embed as subdomain or domain prefix
    # to make URLs look like "brand.com/..." to a human reader
    COMMON_TLDS_WORDS = {'com', 'net', 'org', 'co', 'io', 'gov', 'edu', 'uk'}

    def __init__(self):
        self.rules_triggered = []
        self.total_score = 0.0

    def evaluate(self, url):
        """
        Apply rule-based checks and return results
        """
        self.rules_triggered = []
        self.total_score = 0.0

        try:
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            domain = extracted.domain
            tld = extracted.suffix

            # Rule 1: IP address instead of domain
            if self._is_ip_address(parsed.netloc):
                self._add_rule(
                    'IP_ADDRESS_DOMAIN',
                    'HIGH',
                    'Using IP address instead of domain name',
                    0.3
                )

            # Rule 2: Suspicious TLD
            if tld.lower() in self.SUSPICIOUS_TLDS:
                self._add_rule(
                    'SUSPICIOUS_TLD',
                    'MEDIUM',
                    f'TLD ".{tld}" commonly used in phishing (73% phishing rate)',
                    0.15
                )

            # Rule 3: Punycode (IDN homograph attack)
            if 'xn--' in url:
                self._add_rule(
                    'PUNYCODE_DETECTED',
                    'HIGH',
                    'Punycode domain detected (possible homograph attack)',
                    0.35
                )

            # Rule 4: Excessive subdomains
            subdomain_count = parsed.netloc.count('.')
            if subdomain_count > 3:
                self._add_rule(
                    'EXCESSIVE_SUBDOMAINS',
                    'MEDIUM',
                    f'{subdomain_count} subdomains detected (obfuscation tactic)',
                    0.2
                )

            # Rule 5: Financial keyword + suspicious domain
            has_financial_keyword = any(kw in url.lower() for kw in self.FINANCIAL_KEYWORDS)
            if has_financial_keyword:
                if tld.lower() in self.SUSPICIOUS_TLDS or self._is_ip_address(parsed.netloc):
                    self._add_rule(
                        'FINANCIAL_KEYWORD_SUSPICIOUS',
                        'CRITICAL',
                        'Financial keyword detected with suspicious domain',
                        0.4
                    )

            # Rule 6: URL length > 75 characters
            if len(url) > 75:
                self._add_rule(
                    'EXCESSIVE_URL_LENGTH',
                    'LOW',
                    f'URL length: {len(url)} chars (phishing often uses long URLs)',
                    0.1
                )

            # Rule 7: @ symbol in URL (credential injection)
            if '@' in parsed.netloc:
                self._add_rule(
                    'AT_SYMBOL_IN_URL',
                    'HIGH',
                    'URL contains @ symbol (credential injection attack)',
                    0.35
                )

            # Rule 8: Port number other than 80/443
            if parsed.port and parsed.port not in [80, 443]:
                self._add_rule(
                    'NON_STANDARD_PORT',
                    'MEDIUM',
                    f'Non-standard port: {parsed.port}',
                    0.15
                )

            # Rule 9: Typosquatting — check EVERY hostname part, not just registered domain.
            # e.g. "paypaI.com-security-check.com": tldextract gives domain="com-security-check"
            # but the subdomain "paypaI" is the impersonation attempt.
            # Also normalises homoglyphs (I→l, 0→o, 1→l) before comparison.
            all_hostname_parts = [
                p for p in parsed.netloc.lower().replace('www.', '').split('.')
                if len(p) >= 4
            ]
            _typosquat_found = False
            for _part in all_hostname_parts:
                _normalized = _part.translate(self.HOMOGLYPH_MAP)
                for _variant in {_part, _normalized}:
                    _tq = self._check_typosquatting(_variant)
                    if _tq['is_typosquat']:
                        _label = _part if _part == _variant else f'{_part} (normalised: {_normalized})'
                        self._add_rule(
                            'TYPOSQUATTING',
                            'CRITICAL',
                            f'Hostname part "{_label}" resembles "{_tq["brand"]}" (typosquatting/homograph)',
                            0.45
                        )
                        _typosquat_found = True
                        break
                if _typosquat_found:
                    break

            # Rule 10: Multiple hyphens (common in phishing)
            hyphen_count = domain.count('-')
            if hyphen_count >= 3:
                self._add_rule(
                    'EXCESSIVE_HYPHENS',
                    'MEDIUM',
                    f'{hyphen_count} hyphens in domain (obfuscation)',
                    0.15
                )

            # Rule 11: Suspicious patterns (combining keywords)
            if self._has_suspicious_pattern(url):
                self._add_rule(
                    'SUSPICIOUS_PATTERN',
                    'HIGH',
                    'Suspicious keyword combination detected',
                    0.25
                )

            # Rule 12: Multiple suspicious keywords stacked in domain name
            # e.g. secure-update-bank-login.com — classic phishing construction
            domain_parts = domain.lower().split('-')
            # Use substring match so "ebanking" catches "bank", "elogin" catches "login", etc.
            kw_lower = [k.lower() for k in self.FINANCIAL_KEYWORDS]
            keyword_hits = [p for p in domain_parts if any(kw in p for kw in kw_lower)]
            keyword_count = len(keyword_hits)
            if keyword_count >= 3:
                self._add_rule(
                    'KEYWORD_STACKING',
                    'CRITICAL',
                    f'{keyword_count} phishing keywords stacked in domain: {", ".join(keyword_hits)}',
                    0.55
                )
            elif keyword_count == 2:
                self._add_rule(
                    'KEYWORD_STACKING',
                    'HIGH',
                    f'2 suspicious keywords stacked in domain: {", ".join(keyword_hits)}',
                    0.30
                )

            # Rule 13: TLD-as-domain-prefix
            # e.g. "paypaI.com-security-check.com" — registered domain is "com-security-check"
            # which starts with "com-", making the URL visually read as "paypaI.com/security-check"
            # Classic trick to spoof brand.com by registering brand.com-something.xyz
            domain_hyphen_first = domain.lower().split('-')[0]
            if domain_hyphen_first in self.COMMON_TLDS_WORDS:
                self._add_rule(
                    'TLD_AS_DOMAIN_PREFIX',
                    'CRITICAL',
                    f'Domain starts with TLD word "{domain_hyphen_first}-" — disguises true domain as "brand.{domain_hyphen_first}/..." (e.g. paypal.com-phishing.xyz)',
                    0.50
                )

            # Rule 14: Brand name embedded as a complete word in any hostname part
            # This is DIFFERENT from typosquatting (which catches misspellings at distance 1-2).
            # Here the brand name is used EXACTLY but inside a longer domain to impersonate it.
            #
            # Examples caught:
            #   accounts-google-security.com  → 'google' in 'accounts-google-security'
            #   paypal-secure-update.com      → 'paypal' in 'paypal-secure-update'
            #   amazon-delivery-alert.xyz     → 'amazon' in 'amazon-delivery-alert'
            #
            # Guard: skip if the REGISTERED domain IS exactly the brand (mail.google.com is
            # legitimate — tldextract gives domain='google', which == brand → skip).
            if domain.lower() not in self.KNOWN_BRANDS:
                _brand_found = False
                for _hpart in all_hostname_parts:
                    for _brand in self.KNOWN_BRANDS:
                        # Only match brand as a complete word bounded by hyphen or string edge
                        if re.search(rf'(^|-)({re.escape(_brand)})([-]|$)', _hpart.lower()):
                            self._add_rule(
                                'BRAND_IN_DOMAIN',
                                'CRITICAL',
                                f'Known brand "{_brand}" directly impersonated in hostname part "{_hpart}"',
                                0.65
                            )
                            _brand_found = True
                            break
                    if _brand_found:
                        break

            # Normalize score (max 1.0)
            self.total_score = min(self.total_score, 1.0)

            return {
                'is_phishing': self.total_score > 0.5,
                'confidence': self.total_score,
                'score': self.total_score,
                'rules': self.rules_triggered,
                'rule_count': len(self.rules_triggered),
                'signals': {
                    'tld': tld,
                    'is_ip': self._is_ip_address(parsed.netloc),
                    'subdomain_count': subdomain_count,
                    'url_length': len(url),
                    'has_financial_keywords': has_financial_keyword,
                    'has_punycode': 'xn--' in url
                }
            }

        except Exception as e:
            print(f"Rule engine error: {e}")
            return {
                'is_phishing': False,
                'confidence': 0.0,
                'score': 0.0,
                'rules': [],
                'rule_count': 0,
                'signals': {},
                'error': str(e)
            }

    def _add_rule(self, rule_name, severity, description, weight):
        """Add triggered rule to list"""
        self.rules_triggered.append({
            'rule': rule_name,
            'severity': severity,
            'description': description,
            'weight': weight
        })
        self.total_score += weight

    def _is_ip_address(self, netloc):
        """Check if netloc is an IP address"""
        try:
            # Remove port if present
            host = netloc.split(':')[0]
            ipaddress.ip_address(host)
            return True
        except:
            return False

    def _check_typosquatting(self, domain):
        """
        Check if domain is similar to known brands using Levenshtein distance
        """
        domain_lower = domain.lower()

        for brand in self.KNOWN_BRANDS:
            # Calculate edit distance
            dist = distance(domain_lower, brand)

            # If 1-2 character difference, likely typosquatting
            if 1 <= dist <= 2 and len(domain) >= 4:
                return {'is_typosquat': True, 'brand': brand, 'distance': dist}

        return {'is_typosquat': False, 'brand': None, 'distance': None}

    def _has_suspicious_pattern(self, url):
        """
        Check for suspicious patterns in URL
        """
        url_lower = url.lower()

        suspicious_patterns = [
            r'verify.*account',
            r'suspend.*account',
            r'update.*billing',
            r'confirm.*identity',
            r'secure.*login',
            r'unlock.*account',
            r'unusual.*activity',
            r'click.*here',
            r'limited.*time'
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, url_lower):
                return True

        return False


# Example usage
if __name__ == "__main__":
    rule_engine = RuleEngine()

    # Test URLs
    test_urls = [
        "https://google.com",
        "http://192.168.1.1/login",
        "http://paypa1-secure.tk/verify",
        "https://secure-bank-login-verify.xyz/account",
        "http://apple-support@malicious.com/unlock"
    ]

    print("="*70)
    print("RULE ENGINE TEST")
    print("="*70)

    for url in test_urls:
        print(f"\n🔍 Testing: {url}")
        result = rule_engine.evaluate(url)

        print(f"   Verdict: {'🔴 PHISHING' if result['is_phishing'] else '✅ SAFE'}")
        print(f"   Confidence: {result['confidence']:.2%}")
        print(f"   Rules triggered: {result['rule_count']}")

        if result['rules']:
            for rule in result['rules']:
                print(f"      • [{rule['severity']}] {rule['rule']}: {rule['description']}")

# #!/usr/bin/env python3
# """
# Enhanced Rule Engine for Phishing Detection
# Fast rule-based detection for obvious phishing patterns
# """

# import re
# import ipaddress
# import tldextract
# from urllib.parse import urlparse
# from Levenshtein import distance

# class RuleEngine:
#     """
#     Fast rule-based detection for obvious phishing patterns
#     """

#     SUSPICIOUS_TLDS = [
#         'tk', 'ml', 'ga', 'cf', 'gq',  # Free TLDs (high phishing rate)
#         'pw', 'cc', 'top', 'xyz', 'work', 'date', 'download',
#         'racing', 'review', 'faith', 'science', 'party'
#     ]

#     LEGITIMATE_TLDS = [
#         'com', 'org', 'net', 'edu', 'gov',
#         'mil', 'int', 'co.uk', 'ac.uk', 'gov.uk'
#     ]

#     FINANCIAL_KEYWORDS = [
#         'bank', 'paypal', 'amazon', 'login', 'signin',
#         'account', 'verify', 'secure', 'update', 'confirm',
#         'billing', 'payment', 'wallet', 'crypto', 'ebay',
#         'password', 'credential', 'suspended', 'limited',
#         'unlock', 'restore', 'validate'
#     ]

#     KNOWN_BRANDS = [
#         'google', 'facebook', 'amazon', 'paypal', 'apple',
#         'microsoft', 'netflix', 'instagram', 'twitter', 'linkedin',
#         'ebay', 'yahoo', 'chase', 'wellsfargo', 'bankofamerica',
#         # Apple product aliases — attackers use "appleid", "icloud", "itunes"
#         # as standalone labels (appleid-login.xyz) so they don't match bare "apple"
#         'appleid', 'icloud', 'itunes',
#     ]

#     # Lookalike character substitutions used in homograph attacks
#     # e.g. paypaI (capital I) → paypal, g00gle (zeros) → google
#     HOMOGLYPH_MAP = str.maketrans({
#         ord('I'): 'l',   # capital I → lowercase l  (paypaI → paypal)
#         ord('1'): 'l',   # digit 1 → lowercase l    (paypa1 → paypal)
#         ord('0'): 'o',   # digit 0 → lowercase o    (g00gle → google)
#         ord('3'): 'e',   # digit 3 → lowercase e
#         ord('4'): 'a',   # digit 4 → lowercase a
#         ord('5'): 's',   # digit 5 → lowercase s
#     })

#     # TLD words that attackers embed as subdomain or domain prefix
#     # to make URLs look like "brand.com/..." to a human reader
#     COMMON_TLDS_WORDS = {'com', 'net', 'org', 'co', 'io', 'gov', 'edu', 'uk'}

#     def __init__(self):
#         self.rules_triggered = []
#         self.total_score = 0.0

#     def evaluate(self, url):
#         """
#         Apply rule-based checks and return results
#         """
#         self.rules_triggered = []
#         self.total_score = 0.0

#         try:
#             parsed = urlparse(url)
#             extracted = tldextract.extract(url)
#             domain = extracted.domain
#             tld = extracted.suffix

#             # Rule 1: IP address instead of domain
#             if self._is_ip_address(parsed.netloc):
#                 self._add_rule(
#                     'IP_ADDRESS_DOMAIN',
#                     'HIGH',
#                     'Using IP address instead of domain name',
#                     0.3
#                 )

#             # Rule 2: Suspicious TLD
#             if tld.lower() in self.SUSPICIOUS_TLDS:
#                 self._add_rule(
#                     'SUSPICIOUS_TLD',
#                     'MEDIUM',
#                     f'TLD ".{tld}" commonly used in phishing (73% phishing rate)',
#                     0.15
#                 )

#             # Rule 3: Punycode (IDN homograph attack)
#             if 'xn--' in url:
#                 self._add_rule(
#                     'PUNYCODE_DETECTED',
#                     'HIGH',
#                     'Punycode domain detected (possible homograph attack)',
#                     0.35
#                 )

#             # Rule 4: Excessive subdomains
#             subdomain_count = parsed.netloc.count('.')
#             if subdomain_count > 3:
#                 self._add_rule(
#                     'EXCESSIVE_SUBDOMAINS',
#                     'MEDIUM',
#                     f'{subdomain_count} subdomains detected (obfuscation tactic)',
#                     0.2
#                 )

#             # Rule 5: Financial keyword + suspicious domain
#             has_financial_keyword = any(kw in url.lower() for kw in self.FINANCIAL_KEYWORDS)
#             if has_financial_keyword:
#                 if tld.lower() in self.SUSPICIOUS_TLDS or self._is_ip_address(parsed.netloc):
#                     self._add_rule(
#                         'FINANCIAL_KEYWORD_SUSPICIOUS',
#                         'CRITICAL',
#                         'Financial keyword detected with suspicious domain',
#                         0.4
#                     )

#             # Rule 6: URL length > 75 characters
#             if len(url) > 75:
#                 self._add_rule(
#                     'EXCESSIVE_URL_LENGTH',
#                     'LOW',
#                     f'URL length: {len(url)} chars (phishing often uses long URLs)',
#                     0.1
#                 )

#             # Rule 7: @ symbol in URL (credential injection)
#             if '@' in parsed.netloc:
#                 self._add_rule(
#                     'AT_SYMBOL_IN_URL',
#                     'HIGH',
#                     'URL contains @ symbol (credential injection attack)',
#                     0.35
#                 )

#             # Rule 8: Port number other than 80/443
#             if parsed.port and parsed.port not in [80, 443]:
#                 self._add_rule(
#                     'NON_STANDARD_PORT',
#                     'MEDIUM',
#                     f'Non-standard port: {parsed.port}',
#                     0.15
#                 )

#             # Rule 9: Typosquatting — check EVERY hostname part, not just registered domain.
#             # e.g. "paypaI.com-security-check.com": tldextract gives domain="com-security-check"
#             # but the subdomain "paypaI" is the impersonation attempt.
#             # Also normalises homoglyphs (I→l, 0→o, 1→l) before comparison.
#             all_hostname_parts = [
#                 p for p in parsed.netloc.lower().replace('www.', '').split('.')
#                 if len(p) >= 4
#             ]
#             _typosquat_found = False
#             for _part in all_hostname_parts:
#                 _normalized = _part.translate(self.HOMOGLYPH_MAP)
#                 for _variant in {_part, _normalized}:
#                     _tq = self._check_typosquatting(_variant)
#                     if _tq['is_typosquat']:
#                         _label = _part if _part == _variant else f'{_part} (normalised: {_normalized})'
#                         self._add_rule(
#                             'TYPOSQUATTING',
#                             'CRITICAL',
#                             f'Hostname part "{_label}" resembles "{_tq["brand"]}" (typosquatting/homograph)',
#                             0.45
#                         )
#                         _typosquat_found = True
#                         break
#                 if _typosquat_found:
#                     break

#             # Rule 10: Multiple hyphens (common in phishing)
#             hyphen_count = domain.count('-')
#             if hyphen_count >= 3:
#                 self._add_rule(
#                     'EXCESSIVE_HYPHENS',
#                     'MEDIUM',
#                     f'{hyphen_count} hyphens in domain (obfuscation)',
#                     0.15
#                 )

#             # Rule 11: Suspicious patterns (combining keywords)
#             if self._has_suspicious_pattern(url):
#                 self._add_rule(
#                     'SUSPICIOUS_PATTERN',
#                     'HIGH',
#                     'Suspicious keyword combination detected',
#                     0.25
#                 )

#             # Rule 12: Multiple suspicious keywords stacked in domain name
#             # e.g. secure-update-bank-login.com — classic phishing construction
#             domain_parts = domain.lower().split('-')
#             # Use substring match so "ebanking" catches "bank", "elogin" catches "login", etc.
#             kw_lower = [k.lower() for k in self.FINANCIAL_KEYWORDS]
#             keyword_hits = [p for p in domain_parts if any(kw in p for kw in kw_lower)]
#             keyword_count = len(keyword_hits)
#             if keyword_count >= 3:
#                 self._add_rule(
#                     'KEYWORD_STACKING',
#                     'CRITICAL',
#                     f'{keyword_count} phishing keywords stacked in domain: {", ".join(keyword_hits)}',
#                     0.55
#                 )
#             elif keyword_count == 2:
#                 self._add_rule(
#                     'KEYWORD_STACKING',
#                     'HIGH',
#                     f'2 suspicious keywords stacked in domain: {", ".join(keyword_hits)}',
#                     0.30
#                 )

#             # Rule 13: TLD-as-domain-prefix
#             # e.g. "paypaI.com-security-check.com" — registered domain is "com-security-check"
#             # which starts with "com-", making the URL visually read as "paypaI.com/security-check"
#             # Classic trick to spoof brand.com by registering brand.com-something.xyz
#             domain_hyphen_first = domain.lower().split('-')[0]
#             if domain_hyphen_first in self.COMMON_TLDS_WORDS:
#                 self._add_rule(
#                     'TLD_AS_DOMAIN_PREFIX',
#                     'CRITICAL',
#                     f'Domain starts with TLD word "{domain_hyphen_first}-" — disguises true domain as "brand.{domain_hyphen_first}/..." (e.g. paypal.com-phishing.xyz)',
#                     0.50
#                 )

#             # Rule 14: Brand name embedded as a complete word in any hostname part
#             # This is DIFFERENT from typosquatting (which catches misspellings at distance 1-2).
#             # Here the brand name is used EXACTLY but inside a longer domain to impersonate it.
#             #
#             # Examples caught:
#             #   accounts-google-security.com  → 'google' in 'accounts-google-security'
#             #   paypal-secure-update.com      → 'paypal' in 'paypal-secure-update'
#             #   amazon-delivery-alert.xyz     → 'amazon' in 'amazon-delivery-alert'
#             #
#             # Guard: skip if the REGISTERED domain IS exactly the brand (mail.google.com is
#             # legitimate — tldextract gives domain='google', which == brand → skip).
#             if domain.lower() not in self.KNOWN_BRANDS:
#                 _brand_found = False
#                 for _hpart in all_hostname_parts:
#                     for _brand in self.KNOWN_BRANDS:
#                         # Only match brand as a complete word bounded by hyphen or string edge
#                         if re.search(rf'(^|-)({re.escape(_brand)})([-]|$)', _hpart.lower()):
#                             self._add_rule(
#                                 'BRAND_IN_DOMAIN',
#                                 'CRITICAL',
#                                 f'Known brand "{_brand}" directly impersonated in hostname part "{_hpart}"',
#                                 0.65
#                             )
#                             _brand_found = True
#                             break
#                     if _brand_found:
#                         break

#             # Normalize score (max 1.0)
#             self.total_score = min(self.total_score, 1.0)

#             return {
#                 'is_phishing': self.total_score > 0.5,
#                 'confidence': self.total_score,
#                 'score': self.total_score,
#                 'rules': self.rules_triggered,
#                 'rule_count': len(self.rules_triggered),
#                 'signals': {
#                     'tld': tld,
#                     'is_ip': self._is_ip_address(parsed.netloc),
#                     'subdomain_count': subdomain_count,
#                     'url_length': len(url),
#                     'has_financial_keywords': has_financial_keyword,
#                     'has_punycode': 'xn--' in url
#                 }
#             }

#         except Exception as e:
#             print(f"Rule engine error: {e}")
#             return {
#                 'is_phishing': False,
#                 'confidence': 0.0,
#                 'score': 0.0,
#                 'rules': [],
#                 'rule_count': 0,
#                 'signals': {},
#                 'error': str(e)
#             }

#     def _add_rule(self, rule_name, severity, description, weight):
#         """Add triggered rule to list"""
#         self.rules_triggered.append({
#             'rule': rule_name,
#             'severity': severity,
#             'description': description,
#             'weight': weight
#         })
#         self.total_score += weight

#     def _is_ip_address(self, netloc):
#         """Check if netloc is an IP address"""
#         try:
#             # Remove port if present
#             host = netloc.split(':')[0]
#             ipaddress.ip_address(host)
#             return True
#         except:
#             return False

#     def _check_typosquatting(self, domain):
#         """
#         Check if domain is similar to known brands using Levenshtein distance
#         """
#         domain_lower = domain.lower()

#         for brand in self.KNOWN_BRANDS:
#             # Calculate edit distance
#             dist = distance(domain_lower, brand)

#             # If 1-2 character difference, likely typosquatting
#             if 1 <= dist <= 2 and len(domain) >= 4:
#                 return {'is_typosquat': True, 'brand': brand, 'distance': dist}

#         return {'is_typosquat': False, 'brand': None, 'distance': None}

#     def _has_suspicious_pattern(self, url):
#         """
#         Check for suspicious patterns in URL
#         """
#         url_lower = url.lower()

#         suspicious_patterns = [
#             r'verify.*account',
#             r'suspend.*account',
#             r'update.*billing',
#             r'confirm.*identity',
#             r'secure.*login',
#             r'unlock.*account',
#             r'unusual.*activity',
#             r'click.*here',
#             r'limited.*time'
#         ]

#         for pattern in suspicious_patterns:
#             if re.search(pattern, url_lower):
#                 return True

#         return False


# # Example usage
# if __name__ == "__main__":
#     rule_engine = RuleEngine()

#     # Test URLs
#     test_urls = [
#         "https://google.com",
#         "http://192.168.1.1/login",
#         "http://paypa1-secure.tk/verify",
#         "https://secure-bank-login-verify.xyz/account",
#         "http://apple-support@malicious.com/unlock"
#     ]

#     print("="*70)
#     print("RULE ENGINE TEST")
#     print("="*70)

#     for url in test_urls:
#         print(f"\n🔍 Testing: {url}")
#         result = rule_engine.evaluate(url)

#         print(f"   Verdict: {'🔴 PHISHING' if result['is_phishing'] else '✅ SAFE'}")
#         print(f"   Confidence: {result['confidence']:.2%}")
#         print(f"   Rules triggered: {result['rule_count']}")

#         if result['rules']:
#             for rule in result['rules']:
#                 print(f"      • [{rule['severity']}] {rule['rule']}: {rule['description']}")

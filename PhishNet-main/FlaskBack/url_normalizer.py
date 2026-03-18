"""
URL Normalizer Module - Day 2: Advanced Detection
Author: Bhanu Bista
Features: Punycode, Homoglyphs, IP, Shorteners, Suspicious TLDs, Obfuscation
"""

import urllib.parse
import re
import idna


class URLNormalizer:
    """Normalizes URLs and detects suspicious patterns"""
    
    # Common homoglyphs (visually similar characters)
    HOMOGLYPHS = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',  # Cyrillic
        'ı': 'i', 'ο': 'o', 'ν': 'v',  # Greek/Turkish
        '0': 'o', '1': 'l', '3': 'e',  # Numbers that look like letters
    }
    
    # Known URL shorteners
    SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'short.io'
    ]
    
    # Suspicious TLDs (free domains, often abused)
    SUSPICIOUS_TLDS = [
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains from Freenom
        '.xyz', '.top', '.work', '.click', '.link',  # Cheap domains
        '.zip', '.review', '.country', '.stream', '.download',
        # Additional high-phishing-rate TLDs (added from PhishTank analysis)
        '.online', '.site', '.icu', '.shop', '.store',
        '.live', '.club', '.fun', '.space', '.tech',
        '.info', '.pw', '.cc', '.biz',
    ]
    
    def __init__(self):
        self.stats = {
            'total_checked': 0,
            'suspicious_found': 0,
            'punycode_detected': 0,
            'homoglyphs_detected': 0,
            'ip_detected': 0,
            'shorteners_detected': 0,
            'suspicious_tld_detected': 0,
            'obfuscation_detected': 0
        }
        print("URLNormalizer initialized")
    
    def normalize(self, url: str) -> dict:
        """
        Takes a URL and returns normalized version with detection flags
        """
        self.stats['total_checked'] += 1
        
        # Step 1: Clean the URL
        url = url.strip().lower()
        
        # Step 2: Add http:// if missing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Step 3: Parse the URL
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc
        except Exception as e:
            return {
                'original_url': url,
                'error': str(e),
                'is_suspicious': True,
                'flags': ['MALFORMED_URL']
            }
        
        # Step 4: Check if domain is IP address FIRST
        is_ip = self._is_ip_address(domain)
        
        # Step 5: Check for Punycode (skip if IP)
        if not is_ip:
            decoded_domain, is_punycode = self._decode_punycode(domain)
        else:
            decoded_domain, is_punycode = domain, False
        
        # Step 6: Check for Homoglyphs (skip if IP)
        if not is_ip:
            homoglyph_count, suspicious_chars = self._detect_homoglyphs(decoded_domain)
        else:
            homoglyph_count, suspicious_chars = 0, []
        
        # Step 7: Check for URL shorteners
        is_shortener = self._is_shortener(domain)
        
        # Step 8: Check for suspicious TLD (NEW!)
        has_suspicious_tld = self._has_suspicious_tld(domain)
        
        # Step 9: Detect obfuscation techniques (NEW!)
        obfuscation_flags = self._detect_obfuscation(url, parsed)
        
        result = {
            'original_url': url,
            'domain': domain,
            'decoded_domain': decoded_domain,
            'is_suspicious': False,
            'flags': [],
            'details': {}
        }
        
        # Mark as suspicious if Punycode detected
        if is_punycode:
            result['flags'].append('PUNYCODE_DETECTED')
            result['is_suspicious'] = True
            self.stats['punycode_detected'] += 1
        
        # Mark as suspicious if homoglyphs detected
        if homoglyph_count > 0:
            result['flags'].append('HOMOGLYPH_DETECTED')
            result['details']['suspicious_chars'] = suspicious_chars
            result['is_suspicious'] = True
            self.stats['homoglyphs_detected'] += 1
        
        # Mark as suspicious if IP address
        if is_ip:
            result['flags'].append('IP_ADDRESS')
            result['is_suspicious'] = True
            self.stats['ip_detected'] += 1
        
        # Mark for URL shorteners (not always malicious, just flagged)
        if is_shortener:
            result['flags'].append('URL_SHORTENER')
            self.stats['shorteners_detected'] += 1
        
        # Mark as suspicious if using suspicious TLD (NEW!)
        if has_suspicious_tld:
            result['flags'].append('SUSPICIOUS_TLD')
            result['is_suspicious'] = True
            self.stats['suspicious_tld_detected'] += 1
        
        # Add obfuscation flags (NEW!)
        if obfuscation_flags:
            result['flags'].extend(obfuscation_flags)
            result['details']['obfuscation'] = obfuscation_flags
            result['is_suspicious'] = True
            self.stats['obfuscation_detected'] += 1
        
        if result['is_suspicious']:
            self.stats['suspicious_found'] += 1
        
        return result
    
    def _decode_punycode(self, domain: str) -> tuple:
        """
        Decode Punycode domains (xn-- prefix)
        Returns: (decoded_domain, is_punycode_flag)
        """
        if 'xn--' not in domain:
            return domain, False
        
        try:
            decoded = idna.decode(domain)
            print(f"  [Punycode] {domain} → {decoded}")
            return decoded, True
        except Exception as e:
            return domain, False
    
    def _detect_homoglyphs(self, text: str) -> tuple:
        """
        Detect visually similar characters (homoglyphs)
        Returns: (count, list_of_suspicious_chars)
        """
        suspicious = []
        
        for char in text:
            if char in self.HOMOGLYPHS:
                replacement = self.HOMOGLYPHS[char]
                suspicious.append(f"'{char}' (should be '{replacement}')")
        
        if suspicious:
            print(f"  [Homoglyph] Found: {', '.join(suspicious)}")
        
        return len(suspicious), suspicious
    
    def _is_ip_address(self, domain: str) -> bool:
        """
        Check if domain is an IP address (IPv4)
        Returns: True if IP address, False otherwise
        """
        # Remove port if present (e.g., 192.168.1.1:8080)
        domain = domain.split(':')[0]
        
        # IPv4 pattern: xxx.xxx.xxx.xxx
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if re.match(ipv4_pattern, domain):
            print(f"  [IP Address] Detected: {domain}")
            return True
        
        return False
    
    def _is_shortener(self, domain: str) -> bool:
        """
        Check if domain is a known URL shortener
        Returns: True if shortener, False otherwise
        """
        for shortener in self.SHORTENERS:
            # Exact match or subdomain — NOT substring.
            # "shortener in domain" wrongly matches t.co inside managment.com
            if domain == shortener or domain.endswith('.' + shortener):
                print(f"  [URL Shortener] Detected: {shortener}")
                return True
        return False
    
    def _has_suspicious_tld(self, domain: str) -> bool:
        """
        Check if domain uses a suspicious top-level domain
        Returns: True if suspicious TLD found
        """
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                print(f"  [Suspicious TLD] Detected: {tld}")
                return True
        return False
    
    def _detect_obfuscation(self, url: str, parsed) -> list:
        """
        Detect common URL obfuscation techniques
        Returns: list of obfuscation flags
        """
        flags = []
        
        # Check for excessive subdomains
        subdomain_count = parsed.netloc.count('.') - 1
        if subdomain_count > 3:
            flags.append('EXCESSIVE_SUBDOMAINS')
            print(f"  [Obfuscation] {subdomain_count} subdomains detected")
        
        # Check for @ symbol (can hide real domain)
        if '@' in url:
            flags.append('AT_SYMBOL_OBFUSCATION')
            print(f"  [Obfuscation] @ symbol detected (hides real domain)")
        
        # Check for excessive hyphens/underscores
        if parsed.netloc.count('-') > 3:
            flags.append('EXCESSIVE_HYPHENS')
            print(f"  [Obfuscation] Excessive hyphens in domain")
        
        # Check for hex encoding in URL
        hex_matches = re.findall(r'%[0-9a-f]{2}', url, re.IGNORECASE)
        if len(hex_matches) > 5:
            flags.append('EXCESSIVE_HEX_ENCODING')
            print(f"  [Obfuscation] {len(hex_matches)} hex-encoded characters")
        
        # Check for unusually long domain
        if len(parsed.netloc) > 50:
            flags.append('UNUSUALLY_LONG_DOMAIN')
            print(f"  [Obfuscation] Domain length: {len(parsed.netloc)} chars")
        
        return flags
    
    def get_stats(self) -> dict:
        """Return detection statistics"""
        return self.stats.copy()


# Test it
if __name__ == "__main__":
    normalizer = URLNormalizer()
    
    print("\n" + "="*60)
    print("Testing URL Normalizer - Day 2: All Features")
    print("="*60)
    
    # Test 1: Normal domain
    print("\nTest 1: Legitimate domain")
    result = normalizer.normalize("paypal.com")
    print(f"Domain: {result['domain']}")
    print(f"Suspicious: {result['is_suspicious']}")
    print(f"Flags: {result['flags']}")
    
    # Test 2: Suspicious TLD
    print("\nTest 2: Suspicious TLD (.tk free domain)")
    result = normalizer.normalize("secure-paypal-login.tk")
    print(f"Domain: {result['domain']}")
    print(f"Suspicious: {result['is_suspicious']}")
    print(f"Flags: {result['flags']}")
    
    # Test 3: Excessive subdomains
    print("\nTest 3: Obfuscation - Excessive subdomains")
    result = normalizer.normalize("login.secure.account.verify.paypal.com.phishing.tk")
    print(f"Domain: {result['domain']}")
    print(f"Suspicious: {result['is_suspicious']}")
    print(f"Flags: {result['flags']}")
    
    # Test 4: @ symbol obfuscation
    print("\nTest 4: Obfuscation - @ symbol trick")
    result = normalizer.normalize("http://paypal.com@malicious.com/login")
    print(f"Domain: {result['domain']}")
    print(f"Suspicious: {result['is_suspicious']}")
    print(f"Flags: {result['flags']}")
    
    # Test 5: Hex encoding obfuscation
    print("\nTest 5: Obfuscation - Excessive hex encoding")
    result = normalizer.normalize("http://example.com/%70%61%79%70%61%6c%2e%63%6f%6d")
    print(f"Domain: {result['domain']}")
    print(f"Suspicious: {result['is_suspicious']}")
    print(f"Flags: {result['flags']}")
    
    # Test 6: Combined attack (multiple techniques)
    print("\nTest 6: Combined attack")
    result = normalizer.normalize("xn--pypal-4ve.tk")
    print(f"Domain: {result['domain']}")
    print(f"Suspicious: {result['is_suspicious']}")
    print(f"Flags: {result['flags']}")
    
    # Show statistics
    print("\n" + "="*60)
    print("DETECTION STATISTICS:")
    print("="*60)
    stats = normalizer.get_stats()
    for key, value in stats.items():
        print(f"{key}: {value}")
    
    print("\n" + "="*60)

# """
# URL Normalizer Module - Day 2: Advanced Detection
# Author: Bhanu Bista
# Features: Punycode, Homoglyphs, IP, Shorteners, Suspicious TLDs, Obfuscation
# """

# import urllib.parse
# import re
# import idna


# class URLNormalizer:
#     """Normalizes URLs and detects suspicious patterns"""
    
#     # Common homoglyphs (visually similar characters)
#     HOMOGLYPHS = {
#         'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',  # Cyrillic
#         'ı': 'i', 'ο': 'o', 'ν': 'v',  # Greek/Turkish
#         '0': 'o', '1': 'l', '3': 'e',  # Numbers that look like letters
#     }
    
#     # Known URL shorteners
#     SHORTENERS = [
#         'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
#         'is.gd', 'buff.ly', 'short.io'
#     ]
    
#     # Suspicious TLDs (free domains, often abused)
#     SUSPICIOUS_TLDS = [
#         '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains from Freenom
#         '.xyz', '.top', '.work', '.click', '.link',  # Cheap domains
#         '.zip', '.review', '.country', '.stream', '.download'
#     ]
    
#     def __init__(self):
#         self.stats = {
#             'total_checked': 0,
#             'suspicious_found': 0,
#             'punycode_detected': 0,
#             'homoglyphs_detected': 0,
#             'ip_detected': 0,
#             'shorteners_detected': 0,
#             'suspicious_tld_detected': 0,
#             'obfuscation_detected': 0
#         }
#         print("URLNormalizer initialized")
    
#     def normalize(self, url: str) -> dict:
#         """
#         Takes a URL and returns normalized version with detection flags
#         """
#         self.stats['total_checked'] += 1
        
#         # Step 1: Clean the URL
#         url = url.strip().lower()
        
#         # Step 2: Add http:// if missing
#         if not url.startswith(('http://', 'https://')):
#             url = 'http://' + url
        
#         # Step 3: Parse the URL
#         try:
#             parsed = urllib.parse.urlparse(url)
#             domain = parsed.netloc
#         except Exception as e:
#             return {
#                 'original_url': url,
#                 'error': str(e),
#                 'is_suspicious': True,
#                 'flags': ['MALFORMED_URL']
#             }
        
#         # Step 4: Check if domain is IP address FIRST
#         is_ip = self._is_ip_address(domain)
        
#         # Step 5: Check for Punycode (skip if IP)
#         if not is_ip:
#             decoded_domain, is_punycode = self._decode_punycode(domain)
#         else:
#             decoded_domain, is_punycode = domain, False
        
#         # Step 6: Check for Homoglyphs (skip if IP)
#         if not is_ip:
#             homoglyph_count, suspicious_chars = self._detect_homoglyphs(decoded_domain)
#         else:
#             homoglyph_count, suspicious_chars = 0, []
        
#         # Step 7: Check for URL shorteners
#         is_shortener = self._is_shortener(domain)
        
#         # Step 8: Check for suspicious TLD (NEW!)
#         has_suspicious_tld = self._has_suspicious_tld(domain)
        
#         # Step 9: Detect obfuscation techniques (NEW!)
#         obfuscation_flags = self._detect_obfuscation(url, parsed)
        
#         result = {
#             'original_url': url,
#             'domain': domain,
#             'decoded_domain': decoded_domain,
#             'is_suspicious': False,
#             'flags': [],
#             'details': {}
#         }
        
#         # Mark as suspicious if Punycode detected
#         if is_punycode:
#             result['flags'].append('PUNYCODE_DETECTED')
#             result['is_suspicious'] = True
#             self.stats['punycode_detected'] += 1
        
#         # Mark as suspicious if homoglyphs detected
#         if homoglyph_count > 0:
#             result['flags'].append('HOMOGLYPH_DETECTED')
#             result['details']['suspicious_chars'] = suspicious_chars
#             result['is_suspicious'] = True
#             self.stats['homoglyphs_detected'] += 1
        
#         # Mark as suspicious if IP address
#         if is_ip:
#             result['flags'].append('IP_ADDRESS')
#             result['is_suspicious'] = True
#             self.stats['ip_detected'] += 1
        
#         # Mark for URL shorteners (not always malicious, just flagged)
#         if is_shortener:
#             result['flags'].append('URL_SHORTENER')
#             self.stats['shorteners_detected'] += 1
        
#         # Mark as suspicious if using suspicious TLD (NEW!)
#         if has_suspicious_tld:
#             result['flags'].append('SUSPICIOUS_TLD')
#             result['is_suspicious'] = True
#             self.stats['suspicious_tld_detected'] += 1
        
#         # Add obfuscation flags (NEW!)
#         if obfuscation_flags:
#             result['flags'].extend(obfuscation_flags)
#             result['details']['obfuscation'] = obfuscation_flags
#             result['is_suspicious'] = True
#             self.stats['obfuscation_detected'] += 1
        
#         if result['is_suspicious']:
#             self.stats['suspicious_found'] += 1
        
#         return result
    
#     def _decode_punycode(self, domain: str) -> tuple:
#         """
#         Decode Punycode domains (xn-- prefix)
#         Returns: (decoded_domain, is_punycode_flag)
#         """
#         if 'xn--' not in domain:
#             return domain, False
        
#         try:
#             decoded = idna.decode(domain)
#             print(f"  [Punycode] {domain} → {decoded}")
#             return decoded, True
#         except Exception as e:
#             return domain, False
    
#     def _detect_homoglyphs(self, text: str) -> tuple:
#         """
#         Detect visually similar characters (homoglyphs)
#         Returns: (count, list_of_suspicious_chars)
#         """
#         suspicious = []
        
#         for char in text:
#             if char in self.HOMOGLYPHS:
#                 replacement = self.HOMOGLYPHS[char]
#                 suspicious.append(f"'{char}' (should be '{replacement}')")
        
#         if suspicious:
#             print(f"  [Homoglyph] Found: {', '.join(suspicious)}")
        
#         return len(suspicious), suspicious
    
#     def _is_ip_address(self, domain: str) -> bool:
#         """
#         Check if domain is an IP address (IPv4)
#         Returns: True if IP address, False otherwise
#         """
#         # Remove port if present (e.g., 192.168.1.1:8080)
#         domain = domain.split(':')[0]
        
#         # IPv4 pattern: xxx.xxx.xxx.xxx
#         ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
#         if re.match(ipv4_pattern, domain):
#             print(f"  [IP Address] Detected: {domain}")
#             return True
        
#         return False
    
#     def _is_shortener(self, domain: str) -> bool:
#         """
#         Check if domain is a known URL shortener
#         Returns: True if shortener, False otherwise
#         """
#         for shortener in self.SHORTENERS:
#             # Exact match or subdomain — NOT substring.
#             # "shortener in domain" wrongly matches t.co inside managment.com
#             if domain == shortener or domain.endswith('.' + shortener):
#                 print(f"  [URL Shortener] Detected: {shortener}")
#                 return True
#         return False
    
#     def _has_suspicious_tld(self, domain: str) -> bool:
#         """
#         Check if domain uses a suspicious top-level domain
#         Returns: True if suspicious TLD found
#         """
#         for tld in self.SUSPICIOUS_TLDS:
#             if domain.endswith(tld):
#                 print(f"  [Suspicious TLD] Detected: {tld}")
#                 return True
#         return False
    
#     def _detect_obfuscation(self, url: str, parsed) -> list:
#         """
#         Detect common URL obfuscation techniques
#         Returns: list of obfuscation flags
#         """
#         flags = []
        
#         # Check for excessive subdomains
#         subdomain_count = parsed.netloc.count('.') - 1
#         if subdomain_count > 3:
#             flags.append('EXCESSIVE_SUBDOMAINS')
#             print(f"  [Obfuscation] {subdomain_count} subdomains detected")
        
#         # Check for @ symbol (can hide real domain)
#         if '@' in url:
#             flags.append('AT_SYMBOL_OBFUSCATION')
#             print(f"  [Obfuscation] @ symbol detected (hides real domain)")
        
#         # Check for excessive hyphens/underscores
#         if parsed.netloc.count('-') > 3:
#             flags.append('EXCESSIVE_HYPHENS')
#             print(f"  [Obfuscation] Excessive hyphens in domain")
        
#         # Check for hex encoding in URL
#         hex_matches = re.findall(r'%[0-9a-f]{2}', url, re.IGNORECASE)
#         if len(hex_matches) > 5:
#             flags.append('EXCESSIVE_HEX_ENCODING')
#             print(f"  [Obfuscation] {len(hex_matches)} hex-encoded characters")
        
#         # Check for unusually long domain
#         if len(parsed.netloc) > 50:
#             flags.append('UNUSUALLY_LONG_DOMAIN')
#             print(f"  [Obfuscation] Domain length: {len(parsed.netloc)} chars")
        
#         return flags
    
#     def get_stats(self) -> dict:
#         """Return detection statistics"""
#         return self.stats.copy()


# # Test it
# if __name__ == "__main__":
#     normalizer = URLNormalizer()
    
#     print("\n" + "="*60)
#     print("Testing URL Normalizer - Day 2: All Features")
#     print("="*60)
    
#     # Test 1: Normal domain
#     print("\nTest 1: Legitimate domain")
#     result = normalizer.normalize("paypal.com")
#     print(f"Domain: {result['domain']}")
#     print(f"Suspicious: {result['is_suspicious']}")
#     print(f"Flags: {result['flags']}")
    
#     # Test 2: Suspicious TLD
#     print("\nTest 2: Suspicious TLD (.tk free domain)")
#     result = normalizer.normalize("secure-paypal-login.tk")
#     print(f"Domain: {result['domain']}")
#     print(f"Suspicious: {result['is_suspicious']}")
#     print(f"Flags: {result['flags']}")
    
#     # Test 3: Excessive subdomains
#     print("\nTest 3: Obfuscation - Excessive subdomains")
#     result = normalizer.normalize("login.secure.account.verify.paypal.com.phishing.tk")
#     print(f"Domain: {result['domain']}")
#     print(f"Suspicious: {result['is_suspicious']}")
#     print(f"Flags: {result['flags']}")
    
#     # Test 4: @ symbol obfuscation
#     print("\nTest 4: Obfuscation - @ symbol trick")
#     result = normalizer.normalize("http://paypal.com@malicious.com/login")
#     print(f"Domain: {result['domain']}")
#     print(f"Suspicious: {result['is_suspicious']}")
#     print(f"Flags: {result['flags']}")
    
#     # Test 5: Hex encoding obfuscation
#     print("\nTest 5: Obfuscation - Excessive hex encoding")
#     result = normalizer.normalize("http://example.com/%70%61%79%70%61%6c%2e%63%6f%6d")
#     print(f"Domain: {result['domain']}")
#     print(f"Suspicious: {result['is_suspicious']}")
#     print(f"Flags: {result['flags']}")
    
#     # Test 6: Combined attack (multiple techniques)
#     print("\nTest 6: Combined attack")
#     result = normalizer.normalize("xn--pypal-4ve.tk")
#     print(f"Domain: {result['domain']}")
#     print(f"Suspicious: {result['is_suspicious']}")
#     print(f"Flags: {result['flags']}")
    
#     # Show statistics
#     print("\n" + "="*60)
#     print("DETECTION STATISTICS:")
#     print("="*60)
#     stats = normalizer.get_stats()
#     for key, value in stats.items():
#         print(f"{key}: {value}")
    
#     print("\n" + "="*60)
"""
Domain/Hosting Metadata Analysis Module
Analyzes network-level indicators for phishing detection
"""

import socket
import ssl
import whois
import dns.resolver
import ipaddress
import requests
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
import re
from ipwhois import IPWhois
import tldextract
import json   # ← Added this line (fixes the NameError)

class DomainMetadataAnalyzer:
    """
    Analyzes domain metadata including:
    - IP address and geolocation
    - SSL certificates
    - WHOIS information
    - DNS records
    - ASN (Autonomous System Number)
    """
    
    def __init__(self):
        self.suspicious_asns = set([
            16276,  # OVH (frequently abused)
            24940,  # Hetzner (frequently abused)
            # Add more as discovered
        ])
        
        self.suspicious_tlds = {
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains
            '.pw', '.top', '.club', '.work', '.party'
        }
        
        self.free_ssl_issuers = {
            "Let's Encrypt",
            "cPanel, Inc.",
            "ZeroSSL"
        }
    
    def analyze(self, url: str) -> Dict:
        """
        Main analysis function - returns comprehensive metadata
        """
        domain = self._extract_domain(url)
        
        results = {
            'domain': domain,
            'url': url,
            'risk_score': 0.0,
            'risk_factors': [],
            'metadata': {}
        }
        
        # IP Analysis
        ip_info = self._analyze_ip(domain)
        results['metadata']['ip'] = ip_info
        
        # SSL Certificate Analysis
        ssl_info = self._analyze_ssl(domain)
        results['metadata']['ssl'] = ssl_info
        
        # WHOIS Analysis
        whois_info = self._analyze_whois(domain)
        results['metadata']['whois'] = whois_info
        
        # DNS Analysis
        dns_info = self._analyze_dns(domain)
        results['metadata']['dns'] = dns_info
        
        # ASN Analysis
        asn_info = self._analyze_asn(ip_info.get('ip'))
        results['metadata']['asn'] = asn_info
        
        # Calculate risk score
        results = self._calculate_risk(results)
        
        return results
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        extracted = tldextract.extract(url)
        return f"{extracted.domain}.{extracted.suffix}"
    
    def _analyze_ip(self, domain: str) -> Dict:
        """Analyze IP address"""
        try:
            ip = socket.gethostbyname(domain)
            
            # Check if IP is private/local
            ip_obj = ipaddress.ip_address(ip)
            is_private = ip_obj.is_private
            
            # Get reverse DNS
            try:
                reverse_dns = socket.gethostbyaddr(ip)[0]
            except:
                reverse_dns = None
            
            # Check for shared hosting (multiple domains on same IP)
            shared_domains = self._get_reverse_ip_domains(ip)
            
            return {
                'ip': ip,
                'is_private': is_private,
                'reverse_dns': reverse_dns,
                'shared_hosting': len(shared_domains) > 1,
                'domain_count_on_ip': len(shared_domains),
                'other_domains': shared_domains[:10]  # First 10
            }
        except Exception as e:
            return {
                'error': str(e),
                'ip': None
            }
    
    def _get_reverse_ip_domains(self, ip: str) -> List[str]:
        """
        Get other domains hosted on same IP
        (In production, use ViewDNS API, SecurityTrails API, or similar)
        """
        # Placeholder - in real implementation, use API like:
        # - https://viewdns.info/reverseip/
        # - https://securitytrails.com/
        # - https://hackertarget.com/reverse-ip-lookup/
        
        # For demo, return mock data
        return [ip]  # Would return list of domains
    
    def _analyze_ssl(self, domain: str) -> Dict:
        """Analyze SSL certificate"""
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            
            # Extract certificate info
            issuer = dict(x[0] for x in cert['issuer'])
            subject = dict(x[0] for x in cert['subject'])
            
            # Parse dates
            not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
            not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
            
            cert_age_days = (datetime.now() - not_before).days
            cert_validity_days = (not_after - not_before).days
            
            # Check issuer
            issuer_org = issuer.get('organizationName', 'Unknown')
            is_free_cert = any(free in issuer_org for free in self.free_ssl_issuers)
            
            # Check domain mismatch
            cert_domain = subject.get('commonName', '')
            domain_mismatch = cert_domain != domain and not cert_domain.startswith('*.')
            
            return {
                'has_ssl': True,
                'issuer': issuer_org,
                'is_free_cert': is_free_cert,
                'cert_age_days': cert_age_days,
                'cert_validity_days': cert_validity_days,
                'not_before': not_before.isoformat(),
                'not_after': not_after.isoformat(),
                'cert_domain': cert_domain,
                'domain_mismatch': domain_mismatch,
                'is_wildcard': cert_domain.startswith('*.'),
                'is_self_signed': issuer == subject
            }
            
        except ssl.SSLError as e:
            return {
                'has_ssl': False,
                'error': 'SSL Error',
                'details': str(e)
            }
        except Exception as e:
            return {
                'has_ssl': False,
                'error': str(e)
            }
    
    def _analyze_whois(self, domain: str) -> Dict:
        """Analyze WHOIS information - FIXED VERSION"""
        try:
            w = whois.whois(domain)
            
            # Parse creation date
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            # FIXED: Handle timezone-aware and timezone-naive datetimes
            if creation_date:
                try:
                    # If datetime is timezone-aware
                    if creation_date.tzinfo is not None:
                        domain_age_days = (datetime.now(timezone.utc) - creation_date).days
                    else:
                        # If datetime is timezone-naive
                        domain_age_days = (datetime.now() - creation_date).days
                except Exception as e:
                    print(f"Warning: Could not calculate domain age: {e}")
                    domain_age_days = None
            else:
                domain_age_days = None
            
            # Parse expiration date
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            # Check for WHOIS privacy
            registrant = w.get('registrant', '') or ''
            has_privacy = 'privacy' in str(registrant).lower() or 'redacted' in str(registrant).lower()
            
            return {
                'domain_age_days': domain_age_days,
                'creation_date': creation_date.isoformat() if creation_date else None,
                'expiration_date': expiration_date.isoformat() if expiration_date else None,
                'registrar': w.registrar,
                'has_privacy_protection': has_privacy,
                'name_servers': w.name_servers if w.name_servers else [],
                'status': w.status if w.status else []
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'domain_age_days': None
            }
    
    def _analyze_dns(self, domain: str) -> Dict:
        """Analyze DNS records"""
        try:
            dns_info = {
                'a_records': [],
                'mx_records': [],
                'txt_records': [],
                'ns_records': []
            }
            
            # A records
            try:
                answers = dns.resolver.resolve(domain, 'A')
                dns_info['a_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # MX records
            try:
                answers = dns.resolver.resolve(domain, 'MX')
                dns_info['mx_records'] = [str(rdata.exchange) for rdata in answers]
            except:
                pass
            
            # TXT records
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                dns_info['txt_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # NS records
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                dns_info['ns_records'] = [str(rdata) for rdata in answers]
            except:
                pass
            
            # Check for SPF/DMARC (anti-spoofing)
            has_spf = any('spf' in txt.lower() for txt in dns_info['txt_records'])
            has_dmarc = any('dmarc' in txt.lower() for txt in dns_info['txt_records'])
            
            dns_info['has_spf'] = has_spf
            dns_info['has_dmarc'] = has_dmarc
            dns_info['has_mx'] = len(dns_info['mx_records']) > 0
            
            return dns_info
            
        except Exception as e:
            return {'error': str(e)}
    
    def _analyze_asn(self, ip: str) -> Dict:
        """Analyze ASN (Autonomous System Number)"""
        if not ip:
            return {'error': 'No IP provided'}
        
        try:
            obj = IPWhois(ip)
            results = obj.lookup_rdap()
            
            asn = results.get('asn', 'Unknown')
            asn_description = results.get('asn_description', 'Unknown')
            asn_country = results.get('asn_country_code', 'Unknown')
            
            # Check if ASN is suspicious
            try:
                asn_number = int(asn.replace('AS', '')) if asn.startswith('AS') else int(asn)
                is_suspicious_asn = asn_number in self.suspicious_asns
            except:
                is_suspicious_asn = False
            
            return {
                'asn': asn,
                'asn_description': asn_description,
                'asn_country': asn_country,
                'is_suspicious_asn': is_suspicious_asn,
                'network': results.get('network', {})
            }
            
        except Exception as e:
            return {'error': str(e)}
    
    def _calculate_risk(self, results: Dict) -> Dict:
        """Calculate overall risk score based on metadata"""
        risk_score = 0.0
        risk_factors = []
        
        metadata = results['metadata']
        
        # IP Analysis
        ip_info = metadata.get('ip', {})
        if ip_info.get('is_private'):
            risk_score += 0.3
            risk_factors.append("Private IP address")
        
        if ip_info.get('shared_hosting') and ip_info.get('domain_count_on_ip', 0) > 50:
            risk_score += 0.2
            risk_factors.append(f"Shared hosting with {ip_info.get('domain_count_on_ip')} domains")
        
        # SSL Analysis
        ssl_info = metadata.get('ssl', {})
        if not ssl_info.get('has_ssl'):
            risk_score += 0.4
            risk_factors.append("No SSL certificate")
        elif ssl_info.get('is_self_signed'):
            risk_score += 0.5
            risk_factors.append("Self-signed SSL certificate")
        elif ssl_info.get('domain_mismatch'):
            risk_score += 0.6
            risk_factors.append("SSL certificate domain mismatch")
        elif ssl_info.get('cert_age_days', 999) < 7:
            risk_score += 0.3
            risk_factors.append(f"Very new SSL certificate ({ssl_info.get('cert_age_days')} days)")
        
        if ssl_info.get('is_free_cert'):
            risk_score += 0.1
            risk_factors.append("Free SSL certificate (Let's Encrypt)")
        
        # WHOIS Analysis
        whois_info = metadata.get('whois', {})
        domain_age = whois_info.get('domain_age_days')
        
        if domain_age is not None:
            if domain_age < 7:
                risk_score += 0.5
                risk_factors.append(f"Very new domain ({domain_age} days old)")
            elif domain_age < 30:
                risk_score += 0.3
                risk_factors.append(f"New domain ({domain_age} days old)")
        
        if whois_info.get('has_privacy_protection'):
            risk_score += 0.1
            risk_factors.append("WHOIS privacy protection enabled")
        
        # DNS Analysis
        dns_info = metadata.get('dns', {})
        if not dns_info.get('has_mx'):
            risk_score += 0.1
            risk_factors.append("No MX records (no email)")
        
        if not dns_info.get('has_spf'):
            risk_score += 0.05
            risk_factors.append("No SPF record")
        
        # ASN Analysis
        asn_info = metadata.get('asn', {})
        if asn_info.get('is_suspicious_asn'):
            risk_score += 0.4
            risk_factors.append(f"Suspicious ASN: {asn_info.get('asn_description')}")
        
        # TLD Check
        domain = results.get('domain', '')
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            risk_score += 0.3
            risk_factors.append("Suspicious TLD (free/commonly abused)")
        
        # Normalize risk score to 0-1
        risk_score = min(risk_score, 1.0)
        
        results['risk_score'] = round(risk_score, 3)
        results['risk_factors'] = risk_factors
        results['is_suspicious'] = risk_score >= 0.5
        
        return results


# Example usage
if __name__ == '__main__':
    analyzer = DomainMetadataAnalyzer()
    
    # Test on legitimate site
    print("="*70)
    print("Testing: Google.com (Legitimate)")
    print("="*70)
    result = analyzer.analyze('https://www.google.com')
    
    print(f"Domain: {result['domain']}")
    print(f"Risk Score: {result['risk_score']}")
    print(f"Is Suspicious: {result['is_suspicious']}")
    print(f"\nRisk Factors:")
    if result['risk_factors']:
        for factor in result['risk_factors']:
            print(f"  - {factor}")
    else:
        print("  (none)")
    
    print(f"\nMetadata Summary:")
    
    # IP
    ip_info = result['metadata']['ip']
    print(f"  IP: {ip_info.get('ip', 'Unknown')}")
    
    # SSL
    ssl_info = result['metadata']['ssl']
    if ssl_info.get('has_ssl'):
        print(f"  SSL Issuer: {ssl_info.get('issuer')}")
        print(f"  Cert Age: {ssl_info.get('cert_age_days')} days")
    
    # Domain Age
    whois_info = result['metadata']['whois']
    if whois_info.get('domain_age_days'):
        print(f"  Domain Age: {whois_info['domain_age_days']} days")
    
    # ASN
    asn_info = result['metadata']['asn']
    print(f"  ASN: {asn_info.get('asn')} - {asn_info.get('asn_description')}")
    
    print("\nFull metadata (JSON):")
    print(json.dumps(result['metadata'], indent=2, default=str))
    
    print("\n" + "="*70)
    print("✅ Test Complete!")
    print("="*70)
"""
Comprehensive Test Suite for Domain Metadata Analyzer
Demonstrates detection capabilities across different risk levels

Updated with fixes:
- Proper import of DomainMetadataAnalyzer
- Defensive .get() usage in calculate_risk
- Safe registrar handling
- Reduced aggressive penalties
- Sequential fallback + better error reporting
"""

# ────────────────────────────────────────────────
#  IMPORTS - must be at the top
# ────────────────────────────────────────────────

from domain_metadata_analyzer import DomainMetadataAnalyzer   # ← This must be here

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import traceback
import sys

# ────────────────────────────────────────────────
#  CONFIGURABLE LISTS
# ────────────────────────────────────────────────

suspicious_tlds = [
    '.xin', '.bond', '.help', '.win', '.cfd',
    '.top', '.xyz', '.shop', '.online', '.cc', '.ru',
    '.site', '.click', '.info', '.cn', '.fun', '.icu', '.cyou', '.sbs', '.asia', '.qpon'
]

suspicious_registrars = [
    'NICENIC', 'Sav.com', 'MainReg', 'Dominet', 'Aceville', 'Webnic', 'OwnRegistrar', 'REGRU'
]

known_legit_whitelist = [
    'github.com', 'wikipedia.org', 'abc.xyz', 'mirror.xyz', 'block.xyz',
    'google.com', 'amazon.com', 'microsoft.com', 'paypal.com'
]

# ────────────────────────────────────────────────
#  PRINTING HELPERS
# ────────────────────────────────────────────────

def print_separator(char="=", length=80):
    print(char * length)

def print_analysis(result, title, expected_risk="Unknown"):
    print_separator()
    print(f"{title}")
    print(f"Expected Risk Level: {expected_risk}")
    print_separator()

    domain = result.get('domain', 'N/A')
    risk_score = result.get('risk_score', 0.0)
    is_suspicious = result.get('is_suspicious', False)

    if risk_score < 0.3:
        risk_emoji = "✅ LOW RISK"
    elif risk_score < 0.5:
        risk_emoji = "⚠️  MEDIUM RISK"
    else:
        risk_emoji = "🚨 HIGH RISK"

    print(f"\nDomain: {domain}")
    print(f"Risk Score: {risk_score} {risk_emoji}")
    print(f"Suspicious: {'YES' if is_suspicious else 'NO'}")

    print(f"\n📋 Risk Factors ({len(result.get('risk_factors', []))}):")
    for i, factor in enumerate(result.get('risk_factors', []), 1):
        print(f"  {i}. {factor}")
    if not result.get('risk_factors'):
        print("  ✓ None detected")

    print(f"\n🔍 Key Metadata:")
    metadata = result.get('metadata', {})
    print(json.dumps(metadata, indent=2, default=str))

    print()

# ────────────────────────────────────────────────
#  RISK CALCULATION (with defensive .get() calls)
# ────────────────────────────────────────────────

def calculate_risk(results: dict) -> dict:
    risk_score = 0.0
    risk_factors = []

    metadata = results.get('metadata', {}) or {}
    domain = results.get('domain', '').lower().rstrip('.')

    is_whitelisted = any(wl in domain for wl in known_legit_whitelist)
    if is_whitelisted:
        risk_factors.append("Known legitimate domain (whitelisted) - reduced penalties")

    ip_info = metadata.get('ip', {}) or {}
    if ip_info.get('is_private'):
        risk_score += 0.3
        risk_factors.append("Private IP address")

    if ip_info.get('shared_hosting') and ip_info.get('domain_count_on_ip', 0) > 50:
        penalty = 0.05 if is_whitelisted else 0.2
        risk_score += penalty
        risk_factors.append(f"Shared hosting with {ip_info.get('domain_count_on_ip')} domains")

    # Very light rDNS check
    r_dns = ip_info.get('reverse_dns')
    if r_dns and r_dns != domain and domain:
        if not is_whitelisted:
            risk_score += 0.05
            risk_factors.append("Reverse DNS mismatch - possible compromise")

    whois_info = metadata.get('whois', {}) or {}
    domain_age = whois_info.get('domain_age_days')

    if domain_age is None:
        risk_score += 0.3
        risk_factors.append("Unknown domain age - treated as suspicious")
        domain_age = 0

    ssl_info = metadata.get('ssl', {}) or {}
    if not ssl_info.get('has_ssl'):
        risk_score += 0.4
        risk_factors.append("No SSL certificate")
    elif ssl_info.get('is_self_signed'):
        risk_score += 0.5
        risk_factors.append("Self-signed SSL certificate")
    elif ssl_info.get('domain_mismatch'):
        risk_score += 0.6
        risk_factors.append("SSL certificate domain mismatch")
    else:
        cert_age = ssl_info.get('cert_age_days', 999)
        if cert_age < 7:
            if domain_age > 365:
                risk_score += 0.05
                risk_factors.append(f"Recently renewed SSL ({cert_age} days)")
            elif domain_age < 30:
                risk_score += 0.5
                risk_factors.append(f"Very new SSL ({cert_age}d) on very new domain")
            elif domain_age < 365:
                risk_score += 0.3
                risk_factors.append(f"New SSL ({cert_age}d) on new domain")
            else:
                risk_score += 0.15
                risk_factors.append(f"Very new SSL ({cert_age}d), age unknown")

    if ssl_info.get('is_free_cert'):
        if domain_age > 1825:
            risk_score += 0.02
            risk_factors.append("Free SSL on established domain")
        elif domain_age < 90:
            penalty = 0.05 if is_whitelisted else 0.2
            risk_score += penalty
            risk_factors.append("Free SSL on new domain")
        else:
            risk_score += 0.1
            risk_factors.append("Free SSL certificate")

    if domain_age is not None and domain_age > 0:
        if domain_age < 7:
            risk_score += 0.6
            risk_factors.append(f"Very new domain ({domain_age} days)")
        elif domain_age < 30:
            risk_score += 0.4
            risk_factors.append(f"New domain ({domain_age} days)")
        elif domain_age < 90:
            risk_score += 0.2
            risk_factors.append(f"Recently registered ({domain_age} days)")

    if whois_info.get('has_privacy_protection'):
        if domain_age < 180 and not is_whitelisted:
            risk_score += 0.1
            risk_factors.append("WHOIS privacy on new domain")

    registrar = str(whois_info.get('registrar') or '').upper()
    if any(sreg.upper() in registrar for sreg in suspicious_registrars):
        risk_score += 0.4
        risk_factors.append(f"Suspicious registrar: {registrar}")

    dns_info = metadata.get('dns', {}) or {}
    if not dns_info.get('has_mx'):
        risk_score += 0.1
        risk_factors.append("No MX records (no email)")

    if not dns_info.get('has_spf'):
        risk_score += 0.05
        risk_factors.append("No SPF record")

    if not dns_info.get('has_dmarc'):
        risk_score += 0.05
        risk_factors.append("No DMARC - potential spoofing risk")

    asn_info = metadata.get('asn', {}) or {}
    if asn_info.get('is_suspicious_asn'):
        risk_score += 0.4
        risk_factors.append(f"Suspicious ASN: {asn_info.get('asn_description')}")

    if any(domain.endswith(tld) for tld in suspicious_tlds):
        if is_whitelisted or domain_age > 1825:
            risk_score += 0.1
            risk_factors.append("Suspicious TLD - established/whitelisted")
        elif domain_age < 90:
            risk_score += 0.5
            risk_factors.append("Suspicious TLD on new domain")
        else:
            risk_score += 0.3
            risk_factors.append("Suspicious TLD (commonly abused)")

    risk_score = min(risk_score, 1.0)
    results['risk_score'] = round(risk_score, 3)
    results['risk_factors'] = risk_factors
    results['is_suspicious'] = risk_score >= 0.5

    return results

# ────────────────────────────────────────────────
#  MAIN EXECUTION
# ────────────────────────────────────────────────

def main():
    print("\n" + "🔬 DOMAIN METADATA ANALYZER TEST SUITE".center(80))
    print("=" * 80)

    try:
        analyzer = DomainMetadataAnalyzer()
        print("Analyzer initialized successfully")
    except Exception as e:
        print(f"Failed to initialize analyzer: {type(e).__name__}: {e}")
        traceback.print_exc()
        return

    socket.setdefaulttimeout(12)

    # Example test cases - add your full groups here
    test_cases = [
        ("https://www.google.com",        "Google",          "VERY LOW"),
        ("https://www.github.com",        "GitHub",          "VERY LOW"),
        ("https://www.amazon.com",        "Amazon",          "VERY LOW"),
        ("https://www.microsoft.com",     "Microsoft",       "VERY LOW"),
        ("https://www.paypal.com",        "PayPal",          "VERY LOW"),
        ("https://abc.xyz",               "Alphabet .xyz",   "LOW"),
        ("http://example.ru",             "example.ru",      "HIGH"),
        ("http://neverssl.com",           "NeverSSL",        "MEDIUM-HIGH"),
    ]

    print("\nRunning test cases...\n")

    for url, desc, expected in test_cases:
        try:
            raw_result = analyzer.analyze(url)
            final_result = calculate_risk(raw_result)
            print_analysis(final_result, f"TEST: {desc}", expected)
        except Exception as e:
            print(f"Error analyzing {url}: {type(e).__name__}: {e}")
            traceback.print_exc()
            print("-" * 40)

    print("=" * 80)
    print("TEST SUITE COMPLETE")
    print("=" * 80)


if __name__ == '__main__':
    main()
from cloaking_detector import CloakingDetector
from domain_metadata_analyzer import DomainMetadataAnalyzer

print('=' * 70)
print('INTEGRATION TEST: Cloaking + Domain Metadata')
print('=' * 70)

# Initialize both analyzers
print('\nInitializing analyzers...')
metadata_analyzer = DomainMetadataAnalyzer()
cloaking_detector = CloakingDetector(enable_headless=True)

# Test 1: GitHub
print('\n[TEST 1] GitHub.com')
print('-' * 70)
print('Getting domain metadata...')
domain_data1 = metadata_analyzer.analyze('https://www.github.com')
print(f'  Domain age: {domain_data1["metadata"]["whois"].get("domain_age_days", "Unknown")} days')
print(f'  Domain risk: {domain_data1["risk_score"]:.2f}')

print('Checking for cloaking...')
cloaking_data1 = cloaking_detector.analyze('https://www.github.com', domain_data1)
print(f'  Cloaking risk: {cloaking_data1["overall_risk"]:.2f}')
print(f'  Cloaking detected: {cloaking_data1["cloaking_detected"]}')

final_risk1 = max(domain_data1['risk_score'], cloaking_data1['overall_risk'])
print(f'  FINAL RISK: {final_risk1:.2f}')

# Test 2: Google
print('\n[TEST 2] Google.com')
print('-' * 70)
print('Getting domain metadata...')
domain_data2 = metadata_analyzer.analyze('https://www.google.com')
print(f'  Domain age: {domain_data2["metadata"]["whois"].get("domain_age_days", "Unknown")} days')
print(f'  Domain risk: {domain_data2["risk_score"]:.2f}')

print('Checking for cloaking...')
cloaking_data2 = cloaking_detector.analyze('https://www.google.com', domain_data2)
print(f'  Cloaking risk: {cloaking_data2["overall_risk"]:.2f}')
print(f'  Cloaking detected: {cloaking_data2["cloaking_detected"]}')

final_risk2 = max(domain_data2['risk_score'], cloaking_data2['overall_risk'])
print(f'  FINAL RISK: {final_risk2:.2f}')

# Test 3: Amazon
print('\n[TEST 3] Amazon.com')
print('-' * 70)
print('Getting domain metadata...')
domain_data3 = metadata_analyzer.analyze('https://www.amazon.com')
print(f'  Domain age: {domain_data3["metadata"]["whois"].get("domain_age_days", "Unknown")} days')
print(f'  Domain risk: {domain_data3["risk_score"]:.2f}')

print('Checking for cloaking...')
cloaking_data3 = cloaking_detector.analyze('https://www.amazon.com', domain_data3)
print(f'  Cloaking risk: {cloaking_data3["overall_risk"]:.2f}')
print(f'  Cloaking detected: {cloaking_data3["cloaking_detected"]}')

final_risk3 = max(domain_data3['risk_score'], cloaking_data3['overall_risk'])
print(f'  FINAL RISK: {final_risk3:.2f}')

# Summary
print('\n' + '=' * 70)
print('SUMMARY - WITH DOMAIN METADATA CONTEXT')
print('=' * 70)
print(f'\nGitHub  - Final Risk: {final_risk1:.2f}')
print(f'Google  - Final Risk: {final_risk2:.2f}')
print(f'Amazon  - Final Risk: {final_risk3:.2f}')

print('\n' + '=' * 70)
print('INTEGRATION TEST COMPLETE')
print('=' * 70)
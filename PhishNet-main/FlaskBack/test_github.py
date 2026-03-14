from cloaking_detector import CloakingDetector

print("Testing on GitHub...")
detector = CloakingDetector(enable_headless=True)
result = detector.analyze("https://www.github.com")

print(f"Risk: {result['overall_risk']:.2f}")
print(f"Cloaking: {result['cloaking_detected']}")
if result['evidence']:
    for ev in result['evidence'][:5]:
        print(f"  - {ev}")

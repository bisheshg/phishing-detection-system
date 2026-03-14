from cloaking_detector import CloakingDetector

print("=" * 60)
print("Testing Cloaking Detector on Google.com")
print("=" * 60)

detector = CloakingDetector(enable_headless=True)
result = detector.analyze("https://www.google.com")

print(f"\nURL: {result['url']}")
print(f"Overall Risk: {result['overall_risk']:.2f}")
print(f"Cloaking Detected: {result['cloaking_detected']}")

if result['evidence']:
    print(f"\nEvidence Found:")
    for i, ev in enumerate(result['evidence'], 1):
        print(f"  {i}. {ev}")
else:
    print(f"\nNo suspicious evidence found")

print("\n" + "=" * 60)
print("Test Complete!")
print("=" * 60)

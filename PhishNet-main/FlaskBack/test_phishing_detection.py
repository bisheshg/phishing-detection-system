"""
Test Visual Similarity with Real Phishing Examples
"""

from screenshot_engine import ScreenshotEngine
from ssim_analyzer import SSIMAnalyzer
import json
import os

# Create results directory
os.makedirs('test_results', exist_ok=True)

# Phishing-like test URLs (safe examples for testing)
TEST_CASES = [
    {
        "url": "https://www.paypal.com",  # Legitimate (control test)
        "expected_brand": "PayPal",
        "should_match": True
    },
    {
        "url": "https://www.google.com/search?q=paypal",  # Different site
        "expected_brand": "PayPal", 
        "should_match": False
    }
]

def find_brand_screenshot(brand_name, db_path='brand_database'):
    """Find brand screenshot from database"""
    metadata_file = os.path.join(db_path, 'metadata.json')
    
    with open(metadata_file, 'r') as f:
        brands = json.load(f)
    
    for brand in brands:
        if brand['brand_name'].lower() == brand_name.lower():
            screenshot_path = os.path.join(db_path, 'screenshots', brand['screenshot_file'])
            if os.path.exists(screenshot_path):
                return screenshot_path
    
    return None

def test_detection():
    """Run phishing detection tests"""
    
    print("="*60)
    print("PHISHING DETECTION TEST")
    print("="*60)
    
    analyzer = SSIMAnalyzer(threshold=0.85)
    
    with ScreenshotEngine(headless=True) as engine:
        for i, test in enumerate(TEST_CASES, 1):
            print(f"\n[TEST {i}] {test['url']}")
            print(f"Expected: {test['expected_brand']}, Should Match: {test['should_match']}")
            
            # Capture test URL
            test_img = engine.capture_screenshot(test['url'])
            if not test_img:
                print("  FAILED: Could not capture screenshot")
                continue
            
            # Find brand reference
            brand_path = find_brand_screenshot(test['expected_brand'])
            if not brand_path:
                print(f"  FAILED: Brand '{test['expected_brand']}' not in database")
                continue
            
            # Compare
            result = analyzer.calculate_ssim(test_img, brand_path)
            
            # Report
            print(f"  SSIM Score: {result['ssim_score']:.4f}")
            print(f"  Is Clone?: {result['is_clone']}")
            print(f"  Expected Clone?: {test['should_match']}")
            
            if result['is_clone'] == test['should_match']:
                print("  ✅ PASS - Correct detection")
            else:
                print("  ❌ FAIL - Incorrect detection")
            
            # Generate report with full path
            report_name = os.path.join('test_results', f"test_case_{i}_report.png")
            analyzer.generate_comparison_report(
                test_img, brand_path,
                test['url'][:50], f"Legitimate {test['expected_brand']}",
                report_name
            )
    
    print(f"\n{'='*60}")
    print("TESTS COMPLETE - Check test_results/ folder")

if __name__ == "__main__":
    test_detection()
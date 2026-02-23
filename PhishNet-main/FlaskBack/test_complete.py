import requests
import json

API_URL = "http://localhost:5002"

def test_url(url, description):
    """Test a URL and display results"""
    print("\n" + "="*80)
    print(f"🔍 {description}")
    print(f"URL: {url}")
    print("="*80)
    
    try:
        response = requests.post(
            f"{API_URL}/analyze",
            json={"url": url},
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            
            print(f"\n📊 PREDICTION: {result['prediction']}")
            print(f"   Confidence: {result['confidence']}%")
            print(f"   Risk Level: {result['risk_emoji']} {result['risk_level']}")
            print(f"   Safe to visit: {'✅ Yes' if result['safe_to_visit'] else '❌ No'}")
            
            print(f"\n🤖 ENSEMBLE:")
            print(f"   Agreement: {result['ensemble']['agreement']}")
            print(f"   Consensus: {result['ensemble']['consensus']}")
            
            if result['top_risk_factors']:
                print(f"\n⚠️ TOP RISK FACTORS:")
                for i, factor in enumerate(result['top_risk_factors'][:3], 1):
                    print(f"\n   {i}. {factor['feature']}")
                    print(f"      Value: {factor['value']}")
                    print(f"      {factor['risk_contribution']}")
                    print(f"      {factor['reason']}")
            else:
                print(f"\n✅ No significant risk factors detected")
            
            print(f"\n💡 RECOMMENDATION:")
            print(f"   {result['recommendation']}")
            
        else:
            print(f"❌ Error: {response.status_code}")
            print(response.text)
    
    except Exception as e:
        print(f"❌ Exception: {str(e)}")

if __name__ == "__main__":
    print("\n" + "="*80)
    print("🛡️  PHISHING URL DETECTION - COMPREHENSIVE TEST")
    print("="*80)
    
    # Test legitimate URLs
    print("\n\n" + "🟢 TESTING LEGITIMATE URLs ".center(80, "="))
    test_url("https://google.com", "Google - Major Search Engine")
    test_url("https://github.com", "GitHub - Developer Platform")
    test_url("https://amazon.com", "Amazon - E-commerce")
    test_url("https://wikipedia.org", "Wikipedia - Encyclopedia")
    
    # Test suspicious URLs
    print("\n\n" + "🔴 TESTING SUSPICIOUS URLs ".center(80, "="))
    test_url("¸", 
             "Fake PayPal - Multiple sensitive words")
    test_url("https://amaz0n-secure-login.com", 
             "Fake Amazon - Digit substitution")
    test_url("https://192.168.1.1/login", 
             "IP Address URL - Common phishing technique")
    test_url("https://secure-bank-login-verify-update-account.com", 
             "Generic Bank Phishing - Many hyphens and sensitive words")
    test_url("https://bit.ly/3xYz123", 
             "URL Shortener - Hides destination")
    
    
    print("✅ TESTING COMPLETE")
    
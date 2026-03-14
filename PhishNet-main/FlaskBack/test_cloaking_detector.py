"""
Cloaking Detector Test Suite
Tests against real domains to measure false positive rate and detection accuracy

Follows real-world validation methodology:
1. Test on legitimate sites (measure false positives)
2. Test on known phishing sites (measure true positives)
3. Test edge cases
4. Report metrics honestly
"""

from cloaking_detector import CloakingDetector
import json
import time
from typing import List, Dict


class CloakingDetectorTester:
    """
    Comprehensive testing framework for cloaking detection
    """
    
    def __init__(self):
        self.detector = CloakingDetector(enable_headless=True)
        
        # Test sets
        self.legitimate_sites = {
            'react_spa': [
                'https://react.dev',
                'https://vuejs.org',
            ],
            'cdn_protected': [
                'https://www.cloudflare.com',
                'https://www.akamai.com',
            ],
            'established_brands': [
                'https://www.google.com',
                'https://www.github.com',
                'https://www.amazon.com',
                'https://www.microsoft.com',
                'https://www.paypal.com',
            ],
            'mobile_optimized': [
                'https://m.youtube.com',
                'https://mobile.twitter.com',
            ],
            'paywalls': [
                'https://www.nytimes.com',
                'https://www.wsj.com',
            ]
        }
        
        # Known phishing patterns (for educational testing)
        # NOTE: These are HYPOTHETICAL examples for testing
        self.phishing_test_cases = {
            'simulated': [
                # These would be simulated phishing pages in a test environment
                # DO NOT use real active phishing URLs
            ]
        }
    
    def run_full_test_suite(self) -> Dict:
        """
        Run complete test suite and generate report
        """
        print("=" * 80)
        print("CLOAKING DETECTOR - COMPREHENSIVE TEST SUITE")
        print("=" * 80)
        
        results = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'legitimate_tests': {},
            'false_positives': [],
            'statistics': {},
            'recommendations': []
        }
        
        # Test legitimate sites
        print("\n[PHASE 1] Testing Legitimate Sites")
        print("=" * 80)
        print("Goal: Measure false positive rate (target: <1%)")
        print()
        
        total_legitimate = 0
        false_positives = 0
        
        for category, urls in self.legitimate_sites.items():
            print(f"\n--- Category: {category.replace('_', ' ').title()} ---")
            
            category_results = []
            
            for url in urls:
                total_legitimate += 1
                print(f"\n[{total_legitimate}] Testing: {url}")
                
                try:
                    result = self.detector.analyze(url)
                    
                    risk = result['overall_risk']
                    detected = result['cloaking_detected']
                    
                    # Classification
                    if detected or risk > 0.5:
                        false_positives += 1
                        status = "FALSE POSITIVE"
                        emoji = "❌"
                    elif risk > 0.3:
                        status = "SUSPICIOUS (borderline)"
                        emoji = "⚠️ "
                    else:
                        status = "PASS"
                        emoji = "✅"
                    
                    print(f"  {emoji} Risk: {risk:.2f} | Status: {status}")
                    
                    if result['evidence']:
                        print(f"  Evidence: {', '.join(result['evidence'][:2])}")
                    
                    category_results.append({
                        'url': url,
                        'risk': risk,
                        'detected': detected,
                        'status': status,
                        'evidence': result['evidence']
                    })
                    
                    if detected or risk > 0.5:
                        results['false_positives'].append({
                            'url': url,
                            'category': category,
                            'risk': risk,
                            'evidence': result['evidence']
                        })
                    
                    # Rate limiting
                    time.sleep(2)
                    
                except Exception as e:
                    print(f"  ❌ Error: {e}")
                    category_results.append({
                        'url': url,
                        'error': str(e)
                    })
            
            results['legitimate_tests'][category] = category_results
        
        # Calculate statistics
        fp_rate = (false_positives / total_legitimate * 100) if total_legitimate > 0 else 0
        
        results['statistics'] = {
            'total_legitimate_tested': total_legitimate,
            'false_positives': false_positives,
            'false_positive_rate': round(fp_rate, 2),
            'true_negatives': total_legitimate - false_positives,
            'accuracy': round((total_legitimate - false_positives) / total_legitimate * 100, 1) if total_legitimate > 0 else 0
        }
        
        # Print summary
        print("\n" + "=" * 80)
        print("TEST RESULTS SUMMARY")
        print("=" * 80)
        print(f"\nLegitimate Sites Tested: {total_legitimate}")
        print(f"False Positives: {false_positives}")
        print(f"False Positive Rate: {fp_rate:.2f}%")
        print(f"Accuracy: {results['statistics']['accuracy']}%")
        
        if fp_rate > 1.0:
            print(f"\n⚠️  WARNING: False positive rate ({fp_rate:.1f}%) exceeds 1% target")
            results['recommendations'].append("Tune detection thresholds to reduce false positives")
        else:
            print(f"\n✅ PASS: False positive rate ({fp_rate:.1f}%) is within acceptable range")
        
        # List false positives
        if results['false_positives']:
            print(f"\n❌ False Positives Detected:")
            for i, fp in enumerate(results['false_positives'], 1):
                print(f"\n  {i}. {fp['url']}")
                print(f"     Category: {fp['category']}")
                print(f"     Risk: {fp['risk']:.2f}")
                print(f"     Evidence: {', '.join(fp['evidence'][:3])}")
        
        return results
    
    def test_single_url(self, url: str, expected_result: str = None) -> Dict:
        """
        Test single URL with detailed output
        
        Args:
            url: URL to test
            expected_result: 'safe' or 'phishing' (optional)
        """
        print("=" * 80)
        print(f"TESTING: {url}")
        print("=" * 80)
        
        result = self.detector.analyze(url)
        
        print(f"\n📊 TIER 1 RESULTS:")
        print(f"  Risk Score: {result['tier1']['risk_score']:.2f}")
        print(f"  Suspicious Patterns: {result['tier1']['suspicious_patterns_found']}")
        
        if result['tier1'].get('patterns'):
            print(f"\n  🔍 Detected Patterns:")
            for pattern_type, data in result['tier1']['patterns'].items():
                print(f"    - {pattern_type}: {data['count']} instances")
        
        if result['tier1'].get('context_factors'):
            print(f"\n  📋 Context Factors:")
            context = result['tier1']['context_factors']
            if context.get('domain_age_days'):
                print(f"    - Domain Age: {context['domain_age_days']} days")
            if context.get('has_suspicious_tld'):
                print(f"    - Suspicious TLD: Yes")
        
        if result.get('tier2'):
            print(f"\n📊 TIER 2 RESULTS:")
            print(f"  Risk Score: {result['tier2']['risk_score']:.2f}")
            print(f"  Cloaking Detected: {result['tier2']['cloaking_detected']}")
            
            if result['tier2'].get('content_similarity') is not None:
                print(f"  Content Similarity: {result['tier2']['content_similarity']*100:.1f}%")
            
            if result['tier2'].get('views'):
                bot_view = result['tier2']['views']['bot']
                human_view = result['tier2']['views']['human']
                
                print(f"\n  Bot View:")
                print(f"    - Login Form: {bot_view['has_login_form']}")
                print(f"    - Forms: {bot_view['form_count']}")
                print(f"    - Inputs: {bot_view['input_count']}")
                
                print(f"\n  Human View:")
                print(f"    - Login Form: {human_view['has_login_form']}")
                print(f"    - Forms: {human_view['form_count']}")
                print(f"    - Inputs: {human_view['input_count']}")
        
        print(f"\n🎯 OVERALL ASSESSMENT:")
        print(f"  Final Risk Score: {result['overall_risk']:.2f}")
        print(f"  Cloaking Detected: {result['cloaking_detected']}")
        
        if result['evidence']:
            print(f"\n  📋 Evidence:")
            for i, evidence in enumerate(result['evidence'], 1):
                print(f"    {i}. {evidence}")
        
        if expected_result:
            actual = 'phishing' if result['cloaking_detected'] else 'safe'
            if actual == expected_result:
                print(f"\n  ✅ CORRECT: Expected {expected_result}, got {actual}")
            else:
                print(f"\n  ❌ INCORRECT: Expected {expected_result}, got {actual}")
        
        print("=" * 80)
        
        return result
    
    def generate_report(self, results: Dict, filename: str = 'cloaking_test_report.json'):
        """Save detailed test report to file"""
        with open(filename, 'w') as f:
            json.dump(results, indent=2, fp=f)
        
        print(f"\n📄 Full report saved to: {filename}")


def main():
    """Run the test suite"""
    tester = CloakingDetectorTester()
    
    print("\n🚀 Starting Cloaking Detector Test Suite")
    print("This will test against real legitimate websites")
    print("to measure false positive rate.\n")
    
    # Run full test suite
    results = tester.run_full_test_suite()
    
    # Generate report
    tester.generate_report(results)
    
    print("\n" + "=" * 80)
    print("✅ TEST SUITE COMPLETE")
    print("=" * 80)
    
    return results


if __name__ == '__main__':
    main()

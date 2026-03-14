"""
Test Suite for Intelligent Fusion Module
Tests all 7 scenarios with mock data

Author: Bhanu
Date: March 2026
"""

from intelligent_fusion import IntelligentFusion
import json


class FusionTester:
    """Comprehensive test suite for fusion module"""
    
    def __init__(self):
        self.fusion = IntelligentFusion()
        self.tests_passed = 0
        self.tests_failed = 0
    
    def print_header(self, title):
        """Print test section header"""
        print("\n" + "="*70)
        print(f"  {title}")
        print("="*70)
    
    def print_result(self, result):
        """Print test result in readable format"""
        print(f"\n🎯 URL: {result['url']}")
        print(f"📊 Final Risk: {result['final_risk']:.3f}")
        print(f"⚠️  Risk Level: {result['risk_level'].upper()}")
        print(f"✅ Verdict: {result['verdict']}")
        print(f"🎲 Confidence: {result['confidence']:.0%}")
        print(f"🔍 Scenario: {result['scenario']}")
        print(f"\n📋 Module Scores:")
        for module, score in result['module_scores'].items():
            if score is not None:
                print(f"   {module}: {score:.3f}")
        print(f"\n💭 Reasoning:")
        for i, reason in enumerate(result['reasoning'], 1):
            print(f"   {i}. {reason}")
    
    def verify_expectation(self, result, expected_scenario, expected_verdict, test_name):
        """Verify test result matches expectations"""
        passed = True
        
        if result['scenario'] != expected_scenario:
            print(f"\n❌ FAILED: Expected scenario '{expected_scenario}', got '{result['scenario']}'")
            passed = False
        
        if result['verdict'] != expected_verdict:
            print(f"\n❌ FAILED: Expected verdict '{expected_verdict}', got '{result['verdict']}'")
            passed = False
        
        if passed:
            print(f"\n✅ PASSED: {test_name}")
            self.tests_passed += 1
        else:
            self.tests_failed += 1
        
        return passed
    
    # ========================================================================
    # TEST 1: BRAND IMPERSONATION (Fake PayPal)
    # ========================================================================
    
    def test_brand_impersonation(self):
        """Test Scenario 1: Brand Impersonation"""
        self.print_header("TEST 1: BRAND IMPERSONATION (Fake PayPal)")
        
        # Mock data for a fake PayPal site
        ml_result = {
            'prediction': 0.85,
            'confidence': 0.9
        }
        
        domain_result = {
            'risk_score': 0.7,
            'metadata': {
                'whois': {'domain_age_days': 5},  # Very new
                'dns': {'has_mx': False, 'has_dmarc': False},
                'ssl': {'has_ssl': True}
            }
        }
        
        cloaking_result = {
            'overall_risk': 0.6,
            'cloaking_detected': True,
            'tier1': {'suspicious_patterns_found': 3}
        }
        
        visual_result = {
            'risk_score': 0.95,
            'max_similarity': 0.92,
            'matched_brand': 'PayPal'
        }
        
        result = self.fusion.analyze(
            url='https://paypal-secure-login.xyz',
            ml_result=ml_result,
            domain_result=domain_result,
            cloaking_result=cloaking_result,
            visual_result=visual_result
        )
        
        self.print_result(result)
        self.verify_expectation(result, 'brand_impersonation', 'BLOCK', 
                               'Brand Impersonation Detection')
    
    # ========================================================================
    # TEST 2: FRESH PHISHING SETUP
    # ========================================================================
    
    def test_fresh_phishing(self):
        """Test Scenario 2: Fresh Phishing Setup"""
        self.print_header("TEST 2: FRESH PHISHING SETUP")
        
        ml_result = {
            'prediction': 0.75,
            'confidence': 0.8
        }
        
        domain_result = {
            'risk_score': 0.8,
            'metadata': {
                'whois': {'domain_age_days': 3},  # 3 days old
                'dns': {'has_mx': False, 'has_dmarc': False},
                'ssl': {'has_ssl': False}
            }
        }
        
        cloaking_result = {
            'overall_risk': 0.85,
            'cloaking_detected': True,
            'tier1': {'suspicious_patterns_found': 5}
        }
        
        visual_result = {
            'risk_score': 0.2,
            'max_similarity': 0.3,
            'matched_brand': None
        }
        
        result = self.fusion.analyze(
            url='https://secure-bank-verify.tk',
            ml_result=ml_result,
            domain_result=domain_result,
            cloaking_result=cloaking_result,
            visual_result=visual_result
        )
        
        self.print_result(result)
        self.verify_expectation(result, 'fresh_phishing_setup', 'BLOCK',
                               'Fresh Phishing Setup Detection')
    
    # ========================================================================
    # TEST 3: ESTABLISHED DOMAIN (GitHub)
    # ========================================================================
    
    def test_established_domain(self):
        """Test Scenario 3: Established Domain"""
        self.print_header("TEST 3: ESTABLISHED DOMAIN (GitHub)")
        
        ml_result = {
            'prediction': 0.8,  # High ML score (false positive)
            'confidence': 0.75
        }
        
        domain_result = {
            'risk_score': 0.3,
            'metadata': {
                'whois': {'domain_age_days': 6724},  # 18 years
                'dns': {'has_mx': True, 'has_dmarc': True},
                'ssl': {'has_ssl': True}
            }
        }
        
        cloaking_result = {
            'overall_risk': 0.58,
            'cloaking_detected': False,
            'tier1': {'suspicious_patterns_found': 5}
        }
        
        visual_result = {
            'risk_score': 0.0,
            'max_similarity': 0.1,
            'matched_brand': None
        }
        
        result = self.fusion.analyze(
            url='https://github.com',
            ml_result=ml_result,
            domain_result=domain_result,
            cloaking_result=cloaking_result,
            visual_result=visual_result
        )
        
        self.print_result(result)
        self.verify_expectation(result, 'established_domain', 'ALLOW',
                               'Established Domain False Positive Reduction')
    
    # ========================================================================
    # TEST 4: CONFLICTING SIGNALS
    # ========================================================================
    
    def test_conflicting_signals(self):
        """Test Scenario 4: Conflicting Signals"""
        self.print_header("TEST 4: CONFLICTING SIGNALS")
        
        ml_result = {
            'prediction': 0.75,  # High ML
            'confidence': 0.7
        }
        
        domain_result = {
            'risk_score': 0.25,  # Low domain risk
            'metadata': {
                'whois': {'domain_age_days': 1200},  # 3+ years
                'dns': {'has_mx': True, 'has_dmarc': False},
                'ssl': {'has_ssl': True}
            }
        }
        
        cloaking_result = {
            'overall_risk': 0.4,
            'cloaking_detected': False,
            'tier1': {'suspicious_patterns_found': 2}
        }
        
        visual_result = {
            'risk_score': 0.0,
            'max_similarity': 0.0,
            'matched_brand': None
        }
        
        result = self.fusion.analyze(
            url='https://some-site.com',
            ml_result=ml_result,
            domain_result=domain_result,
            cloaking_result=cloaking_result,
            visual_result=visual_result
        )
        
        self.print_result(result)
        self.verify_expectation(result, 'conflicting_signals', 'WARN',
                               'Conflicting Signals Resolution')
    
    # ========================================================================
    # TEST 5: COMPROMISED OLD DOMAIN
    # ========================================================================
    
    def test_compromised_domain(self):
        """Test Scenario 5: Compromised Old Domain"""
        self.print_header("TEST 5: COMPROMISED OLD DOMAIN")
        
        ml_result = {
            'prediction': 0.7,
            'confidence': 0.75
        }
        
        domain_result = {
            'risk_score': 0.4,
            'metadata': {
                'whois': {'domain_age_days': 2500},  # 6+ years
                'dns': {'has_mx': True, 'has_dmarc': True},
                'ssl': {'has_ssl': True}
            }
        }
        
        cloaking_result = {
            'overall_risk': 0.8,  # High cloaking (unusual for old domain)
            'cloaking_detected': True,
            'tier1': {'suspicious_patterns_found': 6}
        }
        
        visual_result = {
            'risk_score': 0.0,
            'max_similarity': 0.0,
            'matched_brand': None
        }
        
        result = self.fusion.analyze(
            url='https://old-forum.com/phishing-page',
            ml_result=ml_result,
            domain_result=domain_result,
            cloaking_result=cloaking_result,
            visual_result=visual_result
        )
        
        self.print_result(result)
        self.verify_expectation(result, 'compromised_domain', 'BLOCK',
                               'Compromised Domain Detection')
    
    # ========================================================================
    # TEST 6: LOW RISK CONSENSUS (Amazon)
    # ========================================================================
    
    def test_low_risk_consensus(self):
        """Test Scenario 6: Low Risk Consensus"""
        self.print_header("TEST 6: LOW RISK CONSENSUS (Amazon)")
        
        ml_result = {
            'prediction': 0.1,
            'confidence': 0.9
        }
        
        domain_result = {
            'risk_score': 0.0,
            'metadata': {
                'whois': {'domain_age_days': 11449},  # 31+ years
                'dns': {'has_mx': True, 'has_dmarc': True},
                'ssl': {'has_ssl': True}
            }
        }
        
        cloaking_result = {
            'overall_risk': 0.0,
            'cloaking_detected': False,
            'tier1': {'suspicious_patterns_found': 0}
        }
        
        visual_result = {
            'risk_score': 0.0,
            'max_similarity': 0.0,
            'matched_brand': None
        }
        
        result = self.fusion.analyze(
            url='https://www.amazon.com',
            ml_result=ml_result,
            domain_result=domain_result,
            cloaking_result=cloaking_result,
            visual_result=visual_result
        )
        
        self.print_result(result)
        self.verify_expectation(result, 'low_risk_consensus', 'ALLOW',
                               'Low Risk Consensus Detection')
    
    # ========================================================================
    # TEST 7: STANDARD ENSEMBLE
    # ========================================================================
    
    def test_standard_ensemble(self):
        """Test Scenario 7: Standard Ensemble"""
        self.print_header("TEST 7: STANDARD ENSEMBLE")
        
        ml_result = {
            'prediction': 0.55,
            'confidence': 0.65
        }
        
        domain_result = {
            'risk_score': 0.45,
            'metadata': {
                'whois': {'domain_age_days': 800},  # 2+ years
                'dns': {'has_mx': True, 'has_dmarc': False},
                'ssl': {'has_ssl': True}
            }
        }
        
        cloaking_result = {
            'overall_risk': 0.5,
            'cloaking_detected': False,
            'tier1': {'suspicious_patterns_found': 2}
        }
        
        visual_result = {
            'risk_score': 0.1,
            'max_similarity': 0.2,
            'matched_brand': None
        }
        
        result = self.fusion.analyze(
            url='https://medium-risk-site.com',
            ml_result=ml_result,
            domain_result=domain_result,
            cloaking_result=cloaking_result,
            visual_result=visual_result
        )
        
        self.print_result(result)
        self.verify_expectation(result, 'standard_ensemble', 'WARN',
                               'Standard Ensemble Calculation')
    
    # ========================================================================
    # TEST 8: MISSING MODULE DATA (Robustness)
    # ========================================================================
    
    def test_missing_modules(self):
        """Test handling of missing module data"""
        self.print_header("TEST 8: ROBUSTNESS - MISSING MODULE DATA")
        
        # Only ML result provided, all others missing
        ml_result = {
            'prediction': 0.6,
            'confidence': 0.7
        }
        
        result = self.fusion.analyze(
            url='https://example-with-missing-data.com',
            ml_result=ml_result,
            domain_result=None,  # Missing
            cloaking_result=None,  # Missing
            visual_result=None  # Missing
        )
        
        self.print_result(result)
        
        # Should still work with defaults
        if result['final_risk'] is not None:
            print("\n✅ PASSED: Handles missing module data gracefully")
            self.tests_passed += 1
        else:
            print("\n❌ FAILED: Crashed on missing data")
            self.tests_failed += 1
    
    # ========================================================================
    # RUN ALL TESTS
    # ========================================================================
    
    def run_all_tests(self):
        """Run complete test suite"""
        print("\n" + "="*70)
        print("  INTELLIGENT FUSION - COMPREHENSIVE TEST SUITE")
        print("  Testing all 7 scenarios + robustness")
        print("="*70)
        
        # Run all tests
        self.test_brand_impersonation()
        self.test_fresh_phishing()
        self.test_established_domain()
        self.test_conflicting_signals()
        self.test_compromised_domain()
        self.test_low_risk_consensus()
        self.test_standard_ensemble()
        self.test_missing_modules()
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print test summary"""
        total = self.tests_passed + self.tests_failed
        
        print("\n" + "="*70)
        print("  TEST SUMMARY")
        print("="*70)
        print(f"✅ Tests Passed: {self.tests_passed}/{total}")
        print(f"❌ Tests Failed: {self.tests_failed}/{total}")
        
        if self.tests_failed == 0:
            print("\n🎉 ALL TESTS PASSED! Fusion module is working correctly!")
        else:
            print(f"\n⚠️  {self.tests_failed} test(s) failed. Review output above.")
        
        print("="*70 + "\n")


# ============================================================================
# MAIN EXECUTION
# ============================================================================

if __name__ == '__main__':
    tester = FusionTester()
    tester.run_all_tests()
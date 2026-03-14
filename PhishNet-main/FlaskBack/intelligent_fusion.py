"""
Intelligent Fusion Module
System-level ensemble that combines all detection signals with context-aware logic

Author: Bhanu (Integration Lead)
Date: March 2026
Version: 1.1 (Fixed scenario priority and thresholds)
"""

from typing import Dict, List, Optional
from enum import Enum


class RiskLevel(Enum):
    """Risk level categories"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IntelligentFusion:
    """
    Smart multi-modal fusion for phishing detection
    
    Combines signals from:
    1. ML model predictions (Bishesh's models)
    2. Domain metadata analysis (Task 9)
    3. Cloaking detection (Task 8)
    4. Visual similarity (Task 3)
    5. URL normalization (Task 2)
    
    Uses context-aware rules instead of simple averaging
    """
    
    def __init__(self):
        # Thresholds for risk categorization
        self.thresholds = {
            'safe': 0.2,
            'low': 0.4,
            'medium': 0.6,
            'high': 0.8
        }
        
        # Known brands for impersonation detection
        self.known_brands = [
            'paypal', 'amazon', 'google', 'microsoft', 'apple',
            'facebook', 'instagram', 'netflix', 'linkedin', 'chase',
            'bank of america', 'wells fargo', 'citibank', 'github'
        ]
    
    def analyze(self, 
                url: str,
                ml_result: Optional[Dict] = None,
                domain_result: Optional[Dict] = None,
                cloaking_result: Optional[Dict] = None,
                visual_result: Optional[Dict] = None,
                url_features: Optional[Dict] = None) -> Dict:
        """
        Main fusion analysis
        
        Args:
            url: The URL being analyzed
            ml_result: ML model prediction
            domain_result: Domain metadata analysis
            cloaking_result: Cloaking detection results
            visual_result: Visual similarity results
            url_features: URL normalization features
            
        Returns:
            Complete decision with reasoning
        """
        
        # Extract signals from each module
        signals = self._extract_signals(
            ml_result, domain_result, cloaking_result, 
            visual_result, url_features
        )
        
        # Detect scenario
        scenario = self._detect_scenario(url, signals)
        
        # Apply scenario-specific logic
        decision = self._apply_fusion_logic(scenario, signals)
        
        # Generate reasoning
        reasoning = self._generate_reasoning(scenario, signals, decision)
        
        return {
            'url': url,
            'final_risk': round(decision['risk'], 3),
            'risk_level': decision['level'].value,
            'verdict': decision['verdict'],
            'confidence': round(decision['confidence'], 2),
            'reasoning': reasoning,
            'scenario': scenario,
            'module_scores': {
                'ml': signals.get('ml_score'),
                'domain': signals.get('domain_risk'),
                'cloaking': signals.get('cloaking_risk'),
                'visual': signals.get('visual_risk')
            }
        }
    
    def _extract_signals(self, ml_result, domain_result, 
                         cloaking_result, visual_result, url_features) -> Dict:
        """Extract risk scores and metadata from all modules"""
        
        signals = {}
        
        # ML Model signals
        if ml_result:
            # 'probability' is the numeric score; 'prediction' may be a string label
            raw_ml = ml_result.get('probability', ml_result.get('prediction', 0.5))
            signals['ml_score'] = float(raw_ml) if isinstance(raw_ml, (int, float)) else 0.5
            signals['ml_confidence'] = float(ml_result.get('confidence', 0.5))
        else:
            signals['ml_score'] = 0.5  # Default if not available
            signals['ml_confidence'] = 0.3
        
        # Domain metadata signals
        if domain_result:
            signals['domain_risk'] = domain_result.get('risk_score', 0.5)
            whois_data = domain_result.get('metadata', {}).get('whois', {})
            signals['domain_age'] = whois_data.get('domain_age_days') or 0  # None → 0
            
            dns_data = domain_result.get('metadata', {}).get('dns', {})
            signals['has_mx'] = dns_data.get('has_mx', False)
            signals['has_dmarc'] = dns_data.get('has_dmarc', False)
            
            ssl_data = domain_result.get('metadata', {}).get('ssl', {})
            signals['has_ssl'] = ssl_data.get('has_ssl', False)
        else:
            signals['domain_risk'] = 0.5
            signals['domain_age'] = 0
            signals['has_mx'] = False
            signals['has_dmarc'] = False
            signals['has_ssl'] = True  # Assume SSL by default
        
        # Cloaking detection signals
        if cloaking_result:
            signals['cloaking_risk'] = cloaking_result.get('overall_risk', 0.5)
            signals['cloaking_detected'] = cloaking_result.get('cloaking_detected', False)
            tier1 = cloaking_result.get('tier1', {})
            signals['cloaking_patterns'] = tier1.get('suspicious_patterns_found', 0)
        else:
            signals['cloaking_risk'] = 0.5
            signals['cloaking_detected'] = False
            signals['cloaking_patterns'] = 0
        
        # Visual similarity signals
        if visual_result:
            signals['visual_risk'] = visual_result.get('risk_score', 0.0)
            signals['visual_similarity'] = visual_result.get('max_similarity', 0.0)
            signals['brand_matched'] = visual_result.get('matched_brand')
            # dns_failed=True means: the domain contained a brand keyword but had no DNS.
            # This is a strong phishing signal — surface it so _detect_scenario can use it.
            signals['visual_dns_failed'] = visual_result.get('dns_failed', False)
            signals['visual_hint_brand'] = visual_result.get('hint_brand')
        else:
            signals['visual_risk'] = 0.0
            signals['visual_similarity'] = 0.0
            signals['brand_matched'] = None
            signals['visual_dns_failed'] = False
            signals['visual_hint_brand'] = None
        # # Visual similarity signals
        # if visual_result:
        #     signals['visual_risk'] = visual_result.get('risk_score', 0.0)
        #     signals['visual_similarity'] = visual_result.get('max_similarity', 0.0)
        #     signals['brand_matched'] = visual_result.get('matched_brand')
        # else:
        #     signals['visual_risk'] = 0.0
        #     signals['visual_similarity'] = 0.0
        #     signals['brand_matched'] = None
        
        # URL features
        if url_features:
            signals['has_ip'] = url_features.get('has_ip', False)
            signals['url_length'] = url_features.get('url_length', 0)
            signals['suspicious_tld'] = url_features.get('suspicious_tld', False)
        
        return signals
    
    def _detect_scenario(self, url: str, signals: Dict) -> str:
        """
        Detect which scenario this URL falls into
        
        FIXED: Proper priority ordering to avoid false scenario detection
        Priority order:
        1. Brand Impersonation (most critical)
        2. Fresh Phishing Setup (high priority)
        3. Low Risk Consensus (check before established domain)
        4. Compromised Old Domain (check before established domain)
        5. Established Domain (reduces false positives)
        6. Conflicting Signals (needs careful handling)
        7. Standard Ensemble (default)
        """
        
        domain_age = signals.get('domain_age', 0)
        ml_score = signals.get('ml_score', 0.5)
        domain_risk = signals.get('domain_risk', 0.5)
        cloaking_risk = signals.get('cloaking_risk', 0.5)
        cloaking_detected = signals.get('cloaking_detected', False)
        visual_similarity = signals.get('visual_similarity', 0.0)
        brand_matched = signals.get('brand_matched')
        
        # Scenario 1: Brand Impersonation (HIGHEST PRIORITY)
        # Requires a live screenshot match — only fires when the page was reachable.
        if visual_similarity > 0.85 and brand_matched:
            return 'brand_impersonation'
 
        # Scenario 1.5: Dead Brand-Keyword Domain
        # The visual module couldn't screenshot because DNS failed, but the URL
        # contained a known brand keyword (e.g. amazon-account-update.site).
        # A dead domain impersonating a brand is a near-certain phishing setup.
        if signals.get('visual_dns_failed') and ml_score > 0.5:
            return 'fresh_phishing_setup'
 
        # Scenario 2: Fresh Phishing Setup (High Priority)
        # FIXED: original required BOTH domain_age < 30 AND cloaking_detected.
        # This missed cases where:
        #   (a) WHOIS returns stale/wrong registration dates (common)
        #   (b) Domain is newly stood up on an old registrar account
        # New logic: cloaking alone is enough when ML confidence is very high,
        # OR use the original young-domain check as a secondary path.
        if cloaking_detected and (domain_age < 30 or ml_score > 0.85):
            return 'fresh_phishing_setup'
        if domain_age < 30 and cloaking_detected:
            return 'fresh_phishing_setup'
        # # Scenario 1: Brand Impersonation (HIGHEST PRIORITY)
        # if visual_similarity > 0.85 and brand_matched:
        #     return 'brand_impersonation'
        
        # # Scenario 2: Fresh Phishing Setup (High Priority)
        # if domain_age < 30 and cloaking_detected:
        #     return 'fresh_phishing_setup'
        
        # Scenario 3: Low Risk Consensus (Check BEFORE established domain)
        # This prevents Amazon/Google from being labeled "established_domain"
        if (ml_score < 0.3 and domain_risk < 0.3 and cloaking_risk < 0.3):
            return 'low_risk_consensus'
        
        # Scenario 4: Compromised Old Domain (Check BEFORE established domain)
        # Old domain + cloaking is MORE suspicious than just old domain
        if domain_age > 365 and cloaking_detected and ml_score > 0.6:
            return 'compromised_domain'
        
        # Scenario 5: Established Domain (Reduce FP)
        # Now checked AFTER compromised and low-risk scenarios
        if domain_age > 1825:  # 5 years
            if signals.get('has_mx') and signals.get('has_dmarc'):
                return 'established_domain'
        
        # Scenario 6: High ML + Low Domain Risk (Conflict)
        if ml_score > 0.7 and domain_risk < 0.3:
            return 'conflicting_signals'
        
        # Default: Standard weighted ensemble
        return 'standard_ensemble'
    
    def _apply_fusion_logic(self, scenario: str, signals: Dict) -> Dict:
        """Apply scenario-specific fusion logic"""
        
        handlers = {
            'brand_impersonation': self._handle_brand_impersonation,
            'fresh_phishing_setup': self._handle_fresh_phishing,
            'established_domain': self._handle_established_domain,
            'conflicting_signals': self._handle_conflicting_signals,
            'compromised_domain': self._handle_compromised_domain,
            'low_risk_consensus': self._handle_low_risk,
            'standard_ensemble': self._handle_standard_ensemble
        }
        
        handler = handlers.get(scenario, self._handle_standard_ensemble)
        return handler(signals)
    
    def _handle_brand_impersonation(self, signals: Dict) -> Dict:
        """Brand impersonation detected - VERY HIGH RISK"""
        visual_sim = signals.get('visual_similarity', 0.0)
        ml_score = signals.get('ml_score', 0.5)
        
        risk = max(0.9, visual_sim, ml_score)
        
        return {
            'risk': min(risk, 1.0),
            'level': RiskLevel.CRITICAL,
            'verdict': 'BLOCK',
            'confidence': 0.95
        }
    
    def _handle_fresh_phishing(self, signals: Dict) -> Dict:
        """New domain with cloaking - VERY HIGH RISK"""
        ml_score = signals.get('ml_score', 0.5)
        cloaking_risk = signals.get('cloaking_risk', 0.5)
        
        risk = max(ml_score, cloaking_risk, 0.85)
        
        return {
            'risk': min(risk, 1.0),
            'level': RiskLevel.CRITICAL,
            'verdict': 'BLOCK',
            'confidence': 0.9
        }
    
    def _handle_established_domain(self, signals: Dict) -> Dict:
        """Old domain with good infrastructure - REDUCE FALSE POSITIVES"""
        ml_score = signals.get('ml_score', 0.5)
        domain_risk = signals.get('domain_risk', 0.5)
        cloaking_risk = signals.get('cloaking_risk', 0.5)
        
        # Reduce ML score impact for established domains
        adjusted_ml = ml_score * 0.5
        
        # Weighted combination with reduced ML weight
        risk = (adjusted_ml * 0.3 + 
                domain_risk * 0.3 + 
                cloaking_risk * 0.4)
        
        risk_level = self._categorize_risk(risk)
        verdict = 'BLOCK' if risk >= 0.7 else ('WARN' if risk >= 0.5 else 'ALLOW')
        
        return {
            'risk': risk,
            'level': risk_level,
            'verdict': verdict,
            'confidence': 0.75
        }
    
    def _handle_conflicting_signals(self, signals: Dict) -> Dict:
        """High ML but low domain risk - Need careful analysis"""
        ml_score = signals.get('ml_score', 0.5)
        domain_risk = signals.get('domain_risk', 0.5)
        cloaking_risk = signals.get('cloaking_risk', 0.5)
        domain_age = signals.get('domain_age', 0)
        
        # If domain is very old (10+ years), trust domain metadata more
        if domain_age > 3650:
            risk = (ml_score * 0.3 + 
                    domain_risk * 0.4 + 
                    cloaking_risk * 0.3)
            confidence = 0.7
        else:
            # Newer domain, trust ML more
            risk = (ml_score * 0.5 + 
                    domain_risk * 0.2 + 
                    cloaking_risk * 0.3)
            confidence = 0.6
        
        risk_level = self._categorize_risk(risk)
        verdict = 'BLOCK' if risk >= 0.7 else ('WARN' if risk >= 0.5 else 'ALLOW')
        
        return {
            'risk': risk,
            'level': risk_level,
            'verdict': verdict,
            'confidence': confidence
        }
    
    def _handle_compromised_domain(self, signals: Dict) -> Dict:
        """Old domain but showing phishing behavior - Likely compromised"""
        ml_score = signals.get('ml_score', 0.5)
        cloaking_risk = signals.get('cloaking_risk', 0.5)
        
        # Cloaking on old domain is very suspicious
        risk = max(ml_score, cloaking_risk * 1.2, 0.8)
        
        return {
            'risk': min(risk, 1.0),
            'level': RiskLevel.HIGH,
            'verdict': 'BLOCK',
            'confidence': 0.85
        }
    
    def _handle_low_risk(self, signals: Dict) -> Dict:
        """All modules agree - low risk"""
        ml_score = signals.get('ml_score', 0.5)
        domain_risk = signals.get('domain_risk', 0.5)
        cloaking_risk = signals.get('cloaking_risk', 0.5)
        
        # Simple average when all low
        risk = (ml_score + domain_risk + cloaking_risk) / 3
        
        return {
            'risk': min(risk, 0.3),
            'level': RiskLevel.SAFE,
            'verdict': 'ALLOW',
            'confidence': 0.9
        }
    
    def _handle_standard_ensemble(self, signals: Dict) -> Dict:
        """
        Standard weighted ensemble for normal cases
        
        FIXED: Adjusted WARN threshold from 0.5 to 0.45
        to catch medium-risk cases (like 0.468)
        """
        ml_score = signals.get('ml_score', 0.5)
        domain_risk = signals.get('domain_risk', 0.5)
        cloaking_risk = signals.get('cloaking_risk', 0.5)
        visual_risk = signals.get('visual_risk', 0.0)
        
        # Weighted combination (ML has highest weight as it's trained)
        risk = (ml_score * 0.4 + 
                domain_risk * 0.25 + 
                cloaking_risk * 0.25 +
                visual_risk * 0.1)
        
        risk_level = self._categorize_risk(risk)
        
        # FIXED: Changed threshold from 0.5 to 0.45
        verdict = 'BLOCK' if risk >= 0.7 else ('WARN' if risk >= 0.45 else 'ALLOW')
        
        return {
            'risk': risk,
            'level': risk_level,
            'verdict': verdict,
            'confidence': 0.7
        }
    
    def _categorize_risk(self, risk: float) -> RiskLevel:
        """Convert numerical risk to category"""
        if risk < self.thresholds['safe']:
            return RiskLevel.SAFE
        elif risk < self.thresholds['low']:
            return RiskLevel.LOW
        elif risk < self.thresholds['medium']:
            return RiskLevel.MEDIUM
        elif risk < self.thresholds['high']:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    def _generate_reasoning(self, scenario: str, signals: Dict, 
                           decision: Dict) -> List[str]:
        """Generate human-readable reasoning for the decision"""
        reasoning = []
        
        # Scenario explanation
        scenario_explanations = {
            'brand_impersonation': f"ALERT: Visual match to {signals.get('brand_matched')} ({signals.get('visual_similarity', 0)*100:.0f}% similarity)",
            'fresh_phishing_setup': f"Suspicious: New domain ({signals.get('domain_age', 0)} days) with cloaking techniques",
            'established_domain': f"Note: Established domain ({signals.get('domain_age', 0)} days old) with infrastructure",
            'conflicting_signals': "Mixed signals detected from different modules",
            'compromised_domain': f"WARNING: Old domain ({signals.get('domain_age', 0)} days) showing malicious behavior",
            'low_risk_consensus': "All detection modules indicate low risk",
            'standard_ensemble': "Multi-modal analysis applied"
        }
        
        reasoning.append(scenario_explanations.get(scenario, "Standard analysis"))
        
        # Add key findings
        if signals.get('ml_score', 0) > 0.7:
            reasoning.append(f"ML model: High phishing probability ({signals['ml_score']:.2f})")
        
        if signals.get('cloaking_detected'):
            reasoning.append(f"Cloaking: {signals.get('cloaking_patterns', 0)} suspicious patterns detected")
        
        if signals.get('domain_age', 0) < 30:
            reasoning.append("Domain: Very recently registered (high risk)")
        elif signals.get('domain_age', 0) > 1825:
            reasoning.append("Domain: Well-established (reduces false positive risk)")
        
        if not signals.get('has_mx'):
            reasoning.append("Infrastructure: No email (suspicious)")
        
        if not signals.get('has_ssl'):
            reasoning.append("Security: No SSL certificate")
        
        # Final verdict
        reasoning.append(f"VERDICT: {decision['verdict']} (Risk: {decision['risk']:.2f}, Confidence: {decision['confidence']:.0%})")
        
        return reasoning


# Simple usage example
if __name__ == '__main__':
    fusion = IntelligentFusion()
    
    # Test with mock data
    result = fusion.analyze(
        url='https://example.com',
        ml_result={'prediction': 0.7},
        domain_result={'risk_score': 0.3},
        cloaking_result={'overall_risk': 0.5}
    )
    
    print("Test Result:")
    print(f"Risk: {result['final_risk']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Scenario: {result['scenario']}")
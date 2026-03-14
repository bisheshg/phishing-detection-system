"""
Flask Endpoint for Intelligent Fusion Module
Standalone endpoint that can be imported into app.py

Author: Bhanu
Date: March 2026
"""

from flask import Blueprint, request, jsonify
from intelligent_fusion import IntelligentFusion
import traceback

# Create Blueprint (can be imported into app.py)
fusion_bp = Blueprint('fusion', __name__)

# Initialize fusion module
fusion = IntelligentFusion()


@fusion_bp.route('/api/check-url-fusion', methods=['POST', 'OPTIONS'])
def check_url_fusion():
    """
    Intelligent Fusion Endpoint - Multi-modal phishing detection
    
    REQUEST:
    POST /api/check-url-fusion
    {
        "url": "https://example.com",
        "use_mock": true  // Optional: use mock data for testing
    }
    
    RESPONSE:
    {
        "success": true,
        "url": "https://example.com",
        "final_risk": 0.468,
        "risk_level": "medium",
        "verdict": "WARN",
        "confidence": 0.70,
        "scenario": "standard_ensemble",
        "reasoning": [...],
        "module_scores": {...},
        "mock_data_used": true
    }
    """
    
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        return _build_cors_response()
    
    try:
        # Get request data
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400
        
        url = data.get('url')
        use_mock = data.get('use_mock', True)  # Default to mock for now
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL parameter is required'
            }), 400
        
        # For now, use mock data (Phase 3 will integrate real modules)
        if use_mock:
            result = _analyze_with_mock_data(url)
        else:
            # Phase 3: Integrate real modules here
            result = _analyze_with_real_modules(url)
        
        # Add CORS headers and return
        response = jsonify(result)
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        
        return response
    
    except Exception as e:
        error_trace = traceback.format_exc()
        print(f"Error in fusion endpoint: {error_trace}")
        
        return jsonify({
            'success': False,
            'error': str(e),
            'trace': error_trace
        }), 500


def _analyze_with_mock_data(url: str) -> dict:
    """
    Analyze URL with mock data (for testing)
    Simulates realistic module responses
    """
    
    # Determine mock data based on URL patterns
    mock_ml = None
    mock_domain = None
    mock_cloaking = None
    mock_visual = None
    
    url_lower = url.lower()
    
    # Pattern 1: Obvious phishing (paypal, bank, etc. in suspicious domain)
    if any(brand in url_lower for brand in ['paypal', 'banking', 'secure-login', 'verify-account']):
        if not any(legit in url_lower for legit in ['paypal.com', 'chase.com', 'bankofamerica.com']):
            mock_ml = {'prediction': 0.85, 'confidence': 0.9}
            mock_domain = {
                'risk_score': 0.7,
                'metadata': {
                    'whois': {'domain_age_days': 5},
                    'dns': {'has_mx': False, 'has_dmarc': False},
                    'ssl': {'has_ssl': True}
                }
            }
            mock_cloaking = {
                'overall_risk': 0.6,
                'cloaking_detected': True,
                'tier1': {'suspicious_patterns_found': 3}
            }
            mock_visual = {
                'risk_score': 0.9,
                'max_similarity': 0.88,
                'matched_brand': 'PayPal' if 'paypal' in url_lower else 'Banking'
            }
    
    # Pattern 2: Known legitimate sites
    elif any(legit in url_lower for legit in ['github.com', 'google.com', 'amazon.com', 'microsoft.com']):
        mock_ml = {'prediction': 0.2, 'confidence': 0.8}
        mock_domain = {
            'risk_score': 0.1,
            'metadata': {
                'whois': {'domain_age_days': 6000},
                'dns': {'has_mx': True, 'has_dmarc': True},
                'ssl': {'has_ssl': True}
            }
        }
        mock_cloaking = {
            'overall_risk': 0.1,
            'cloaking_detected': False,
            'tier1': {'suspicious_patterns_found': 0}
        }
        mock_visual = {
            'risk_score': 0.0,
            'max_similarity': 0.0,
            'matched_brand': None
        }
    
    # Pattern 3: Default medium risk
    else:
        mock_ml = {'prediction': 0.55, 'confidence': 0.65}
        mock_domain = {
            'risk_score': 0.45,
            'metadata': {
                'whois': {'domain_age_days': 800},
                'dns': {'has_mx': True, 'has_dmarc': False},
                'ssl': {'has_ssl': True}
            }
        }
        mock_cloaking = {
            'overall_risk': 0.5,
            'cloaking_detected': False,
            'tier1': {'suspicious_patterns_found': 2}
        }
        mock_visual = {
            'risk_score': 0.1,
            'max_similarity': 0.2,
            'matched_brand': None
        }
    
    # Run fusion analysis
    fusion_result = fusion.analyze(
        url=url,
        ml_result=mock_ml,
        domain_result=mock_domain,
        cloaking_result=mock_cloaking,
        visual_result=mock_visual
    )
    
    # Add metadata
    fusion_result['success'] = True
    fusion_result['mock_data_used'] = True
    fusion_result['note'] = 'Using simulated module data for testing. Real integration in Phase 3.'
    
    return fusion_result


def _analyze_with_real_modules(url: str) -> dict:
    """
    Analyze URL with real modules (Phase 3).
    Delegates to the full analyze_url_logic pipeline in app.py.
    Lazy import prevents circular import at module load time.
    """
    try:
        from app import analyze_url_logic
        result, status_code = analyze_url_logic(url)
        if status_code != 200:
            return {'success': False, 'error': result.get('error', 'Analysis failed')}
        # Surface the fusion fields at the top level for consistency
        fusion = result.get('fusion_result') or {}
        return {
            'success': True,
            'url': result.get('url', url),
            'final_risk': fusion.get('final_risk', result.get('probability', 0.0)),
            'risk_level': result.get('risk_level', ''),
            'verdict': fusion.get('verdict', 'BLOCK' if result.get('probability', 0) >= 0.5 else 'ALLOW'),
            'confidence': fusion.get('confidence', result.get('probability', 0.0)),
            'scenario': fusion.get('scenario', 'standard_ensemble'),
            'reasoning': fusion.get('reasoning', []),
            'module_scores': fusion.get('module_scores', {}),
            'mock_data_used': False,
            'prediction': result.get('prediction'),
            'url_normalization': result.get('url_normalization'),
            'domain_metadata': result.get('domain_metadata'),
            'cloaking': result.get('cloaking'),
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'note': 'Real module analysis failed. Set "use_mock": true to test with mock data.'
        }


def _build_cors_response():
    """Build CORS preflight response"""
    response = jsonify({'status': 'ok'})
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
    return response


# Standalone Flask app for testing (optional)
if __name__ == '__main__':
    from flask import Flask
    
    app = Flask(__name__)
    app.register_blueprint(fusion_bp)
    
    print("\n" + "="*70)
    print("  INTELLIGENT FUSION - STANDALONE TEST SERVER")
    print("="*70)
    print("\nServer running at: http://localhost:5001")
    print("\nTest with curl:")
    print('curl -X POST http://localhost:5001/api/check-url-fusion \\')
    print('  -H "Content-Type: application/json" \\')
    print('  -d \'{"url": "https://paypal-secure.xyz", "use_mock": true}\'')
    print("\n" + "="*70 + "\n")
    
    app.run(debug=True, port=5001)
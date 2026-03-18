"""
Intelligent Fusion Module
System-level ensemble that combines all detection signals with context-aware logic

Author: Bhanu (Integration Lead)
Date: March 2026
Version: 1.1 (Fixed scenario priority and thresholds)
"""

from typing import Dict, List, Optional
from enum import Enum

# Maps brand names (lowercase) to their official base domains.
# Used to prevent self-brand false positives: if the URL's base domain matches
# the brand we detected visually, it's the real brand — not an impersonator.
_BRAND_OFFICIAL_DOMAINS = {
    'amazon':    'amazon.com',
    'google':    'google.com',
    'facebook':  'facebook.com',
    'microsoft': 'microsoft.com',
    'apple':     'apple.com',
    'paypal':    'paypal.com',
    'netflix':   'netflix.com',
    'instagram': 'instagram.com',
    'linkedin':  'linkedin.com',
    'chase':     'chase.com',
    'zoom':      'zoom.us',
    'esewa':     'esewa.com.np',
    'twitter':   'twitter.com',
    'dropbox':   'dropbox.com',
    'adobe':     'adobe.com',
}


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
            # FIX 3: unanimous vote flag — True when every model voted phishing.
            # Passed from app.py via ml_result_for_fusion['unanimous'].
            signals['ml_unanimous'] = bool(ml_result.get('unanimous', False))
            # FIX 4: free hosting subdomain flag — True for ghost.io, blogspot.com etc.
            # Passed from app.py so we can override domain_risk weighting.
            signals['free_hosting_subdomain'] = bool(ml_result.get('free_hosting_subdomain', False))
            # keyword_match: brand or generic phishing keyword found in URL.
            # When True + dns_failed=True → route to fresh_phishing_setup regardless
            # of ml_score. Compensates for model regression after retraining.
            signals['keyword_match'] = bool(ml_result.get('keyword_match', False))
            # slug_risk: phishing keywords found in the shortener slug BEFORE expansion.
            # 0.35 per matched keyword, capped at 1.0. Preserved even when the expanded
            # destination looks legitimate (e.g. dead ow.ly link to Hootsuite 404).
            signals['slug_risk'] = float(ml_result.get('slug_risk', 0.0))
            signals['was_shortened'] = bool(ml_result.get('was_shortened', False))
            # trusted_domain: True for well-known platforms (Google, Microsoft, etc.)
            # Used to detect hosted-content phishing where the domain is legit but
            # the page content impersonates another brand (e.g. Google Docs phishing).
            signals['trusted_domain']    = bool(ml_result.get('trusted_domain', False))
            signals['is_content_hosting'] = bool(ml_result.get('is_content_hosting', False))
        else:
            signals['ml_score'] = 0.5  # Default if not available
            signals['ml_confidence'] = 0.3
            signals['ml_unanimous'] = False
            signals['free_hosting_subdomain'] = False
            signals['keyword_match'] = False
            signals['slug_risk'] = 0.0
            signals['was_shortened'] = False
            signals['trusted_domain']    = False
            signals['is_content_hosting'] = False

        # Domain metadata signals
        if domain_result:
            signals['domain_risk'] = domain_result.get('risk_score', 0.5)
            whois_data = domain_result.get('metadata', {}).get('whois', {})
            signals['domain_age'] = whois_data.get('domain_age_days') or 0  # None → 0
            
            dns_data = domain_result.get('metadata', {}).get('dns', {})
            signals['has_mx']    = dns_data.get('has_mx', False)
            signals['has_dmarc'] = dns_data.get('has_dmarc', False)
            signals['has_spf']   = dns_data.get('has_spf', False)

            ssl_data = domain_result.get('metadata', {}).get('ssl', {})
            signals['has_ssl']       = ssl_data.get('has_ssl', False)
            # cert_age_days: days since the SSL cert was issued.
            # A 1-day cert on an "old" domain = just spun up = hijacked domain signal.
            signals['cert_age_days'] = ssl_data.get('cert_age_days', 999)
            signals['is_free_cert']  = ssl_data.get('is_free_cert', False)
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
            # FIX 1: carry dns_failed flag so _detect_scenario can use it even when
            # cloaking_detected=False (cloaking was skipped due to DNS failure, not measured)
            signals['cloaking_dns_failed'] = cloaking_result.get('dns_failed', False)
        else:
            signals['cloaking_risk'] = 0.5
            signals['cloaking_detected'] = False
            signals['cloaking_patterns'] = 0
            signals['cloaking_dns_failed'] = False
        
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
        
        # URL normalization features — previously this block was never reached because
        # app.py never passed url_features to analyze(). Now fully wired up.
        if url_features:
            signals['has_ip']                  = url_features.get('has_ip', False)
            signals['url_length']              = url_features.get('url_length', 0)
            signals['suspicious_tld']          = url_features.get('suspicious_tld', False)
            signals['has_homoglyph']           = url_features.get('has_homoglyph', False)
            signals['has_punycode']            = url_features.get('has_punycode', False)
            signals['is_shortener']            = url_features.get('is_shortener', False)
            signals['destination_unreachable'] = url_features.get('destination_unreachable', False)
            # Dead link: shortened URL resolved back to the shortener's own error page.
            # The original short link is expired — no phishing content at this URL.
            signals['is_dead_link']            = url_features.get('is_dead_link', False)
            signals['norm_flags']              = url_features.get('norm_flags', [])
            # Phishing action/brand keyword in subdomain or path of a content-hosting domain.
            # e.g. beetmartloginn.webflow.io (login), github.io/Netflix_Clone (netflix)
            signals['hosting_phish_keyword']   = url_features.get('hosting_phish_keyword', False)
            signals['has_password_field']      = url_features.get('has_password_field', False)
            signals['has_login_form']          = url_features.get('has_login_form', False)
            signals['page_title_brand_mismatch'] = url_features.get('page_title_brand_mismatch', False)
        else:
            signals['has_ip']                  = False
            signals['url_length']              = 0
            signals['suspicious_tld']          = False
            signals['has_homoglyph']           = False
            signals['has_punycode']            = False
            signals['is_shortener']            = False
            signals['destination_unreachable'] = False
            signals['is_dead_link']            = False
            signals['norm_flags']              = []
            signals['hosting_phish_keyword']   = False
            signals['has_password_field']      = False
            signals['has_login_form']          = False
            signals['page_title_brand_mismatch'] = False

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
        
        domain_age        = signals.get('domain_age', 0)
        ml_score          = signals.get('ml_score', 0.5)
        domain_risk       = signals.get('domain_risk', 0.5)
        cloaking_risk     = signals.get('cloaking_risk', 0.5)
        cloaking_detected = signals.get('cloaking_detected', False)
        visual_similarity = signals.get('visual_similarity', 0.0)
        brand_matched     = signals.get('brand_matched')
        ml_unanimous      = signals.get('ml_unanimous', False)

        # ── Scenario 0: Dead short link ──────────────────────────────────────
        # A URL shortener that expanded back to its own domain (e.g.
        # shorturl.at/Pl6ZN → shorturl.at/error.php). The original short link
        # is expired — no phishing content exists at this URL anymore.
        # Route immediately to low_risk so ML noise on the error page doesn't
        # produce a false phishing verdict.
        if signals.get('is_dead_link', False):
            return 'low_risk_consensus'

        # Self-brand exclusion: if the URL's base domain IS the matched brand's
        # official domain, the visual match is the real site — not an impersonator.
        # e.g. scholar.google.com matching "Google" → is_own_brand=True → skip.
        url_base_domain = signals.get('url_base_domain', '')
        brand_official  = _BRAND_OFFICIAL_DOMAINS.get((brand_matched or '').lower(), '')
        is_own_brand    = bool(brand_official and url_base_domain == brand_official)

        # Scenario 1: Brand Impersonation (HIGHEST PRIORITY)
        # Requires a live screenshot match — only fires when the page was reachable
        # AND the URL is not the brand's own official domain.
        if visual_similarity > 0.85 and brand_matched and not is_own_brand:
            return 'brand_impersonation'

        # Scenario 1.1: Hosted-Content Impersonation (trusted platform abuse)
        # A content-hosting platform (docs.google.com, drive.google.com) hosts a page
        # that visually resembles another brand at moderate similarity (0.60–0.85).
        is_trusted_domain_signal = signals.get('trusted_domain', False)
        if is_trusted_domain_signal and brand_matched and visual_similarity > 0.60 and not is_own_brand:
            return 'fresh_phishing_setup'

        # Scenario 1.5: DNS-Dead Phishing Domain
        # When DNS fails cloaking is skipped, so Scenario 2 never fires.
        # dns_failed=True is a strong phishing signal, but needs a secondary
        # guard to avoid false positives on legitimate unreachable sites.
        #
        # TWO routing paths:
        #
        # Path A — keyword + dns_failed (fires regardless of ml_score):
        #   When a brand/generic phishing keyword is in the URL AND DNS is dead,
        #   the domain name alone is sufficient evidence. The ML abstention (low
        #   base_prob after retraining) should NOT override this clear signal.
        #   Examples: dhl-parcel-tracking-fee.com (tracking-fee keyword)
        #             csgo-skins-trade.com (skins-trade keyword)
        #             nepal-banking-portal.com (banking-portal keyword)
        #
        # Path B — high ML + dns_failed + young domain (no keyword required):
        #   For phishing pages without obvious keywords, require ML confidence > 0.55
        #   AND domain age < 730 days to avoid blocking old legitimate sites.
        #   Guard: municipality-sewa.com.np (age=11373d) and hamro-gaming.com.np
        #   both have old domains → dns_young=False → stay in standard_ensemble.
        _dns_failed = (signals.get('cloaking_dns_failed', False) or
                       signals.get('visual_dns_failed', False))
        _domain_age = signals.get('domain_age', 0)
        _dns_young = (_domain_age < 730)   # < 2 years old
        _keyword_match = signals.get('keyword_match', False)

        if _dns_failed:
            # Path A: keyword match is definitive evidence — ml_score irrelevant
            if _keyword_match:
                return 'fresh_phishing_setup'
            # Path B: no keyword — need high ML + young domain
            if ml_score > 0.55 and _dns_young:
                return 'fresh_phishing_setup'

        # Scenario 1.6: Free Hosting Platform Subdomain (FIX 4)
        # A phishing page hosted on ghost.io / blogspot.com etc. gets the host
        # platform's clean domain_risk (0.10 for ghost.io), which pulls the
        # fusion score down despite 5/5 ML votes. Route to fresh_phishing_setup
        # so the max() handler fires instead of a weighted average.
        #
        # GUARD: require keyword_match to avoid false positives on legitimate
        # developer portfolio/demo sites (vercel.app, netlify.app etc.).
        # A personal portfolio like portfolitpiyush.vercel.app has no brand
        # keywords and should not be escalated on ML score alone.
        if signals.get('free_hosting_subdomain', False) and ml_score > 0.65:
            if signals.get('keyword_match', False):
                return 'fresh_phishing_setup'

        # Scenario 2.6: Content-Hosting Platform with Phishing Keyword
        # When a URL is on a user-content platform (webflow.io, github.io,
        # firebaseapp.com, web.app, etc.) AND the subdomain or path contains
        # phishing action keywords (login, verify, auth, secure…) or a known
        # brand name (netflix, paypal, rogers…), the page is almost certainly
        # a phishing kit hosted on free infrastructure.
        #
        # Root cause this fixes: ML scores are suppressed for trusted/hosting
        # domains (big negative boost from UCI feature extractor), so the raw
        # probability never reaches the 0.88 threshold for force_visual. The
        # content-hosting subdomain/path keyword is a structural signal that
        # doesn't depend on ML confidence.
        #
        # Examples caught:
        #   beetmartloginn.webflow.io      → subdomain has 'login'
        #   auth-sso--log--capital-i.webflow.io → 'auth','sso','log'
        #   ddeepakgoutam2005.github.io/Netflix_Clone/ → path has 'netflix'
        #   mail-ovhcloud.web.app/         → 'mail' (action) + 'ovhcloud' (brand)
        #   wstgbvtcvhujpr0vngwr.firebaseapp.com → no keyword, skip (random)
        #
        # GUARDS:
        #   - ml_score > 0.25: require at least minimal ML agreement; prevents
        #     flagging developer tooling pages that legitimately mention login/auth
        #     in their documentation (e.g. auth0.github.io/docs).
        #   - NOT trusted_domain: content-hosting domains are not in TRUSTED_DOMAINS,
        #     so this check is redundant but explicit for clarity.
        # Scenario 2.6 guard: require ml_score > 0.10 (not 0.25).
        # Content-hosting platforms (webflow.io, github.io) are in TRUSTED_DOMAINS
        # indirectly, so the UCI boost suppresses ML to 0.10–0.20 even for real
        # phishing kits. The keyword signal alone is sufficient evidence when the
        # hosting platform is confirmed. Only exclude URLs where ALL 5 models are
        # near-certain legitimate (< 10%) — these are likely developer tooling pages
        # (auth0 SDK docs on github.io) rather than phishing pages.
        if signals.get('hosting_phish_keyword', False) and ml_score > 0.10:
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
        
        # Scenario 2.5: Ultra-Fresh Domain with Suspicious Infrastructure
        # Modern PhaaS kits use clean URLs (short, SSL, no typos) to fool ML models,
        # but the domain is only days old and has elevated infrastructure risk.
        # A domain ≤7 days old with domain_risk ≥ 0.45 is almost always set up
        # for phishing — legitimate services rarely launch within 7 days AND score
        # suspicious on multiple infrastructure checks simultaneously.
        # Guard: domain_risk ≥ 0.45 avoids flagging brand-new legitimate domains
        # that have clean DNS, valid SSL, and no suspicious infrastructure patterns.
        # domain_age=0 means WHOIS timed out / unknown — treat as unresolved,
        # not as a zero-day domain. Only fire when age is positively confirmed young.
        if 0 < domain_age <= 7 and domain_risk >= 0.45:
            return 'fresh_phishing_setup'

        # Scenario 2.7: Suspicious Shortener Slug
        # A shortener URL whose slug contains clear phishing keywords is treated as
        # a direct phishing signal regardless of what the expanded destination looks
        # like (the destination may be dead or a redirect error page).
        #
        # Two tiers:
        #   ≥ 0.70 (2+ keywords): e.g. "esewa-login", "freeprize-claim" → BLOCK
        #   ≥ 0.35 (1 keyword) + high ML: e.g. "amazon-deal" + ML > 0.55 → BLOCK
        #
        # Guard: only fires when the URL was actually shortened (was_shortened=True)
        # to avoid false positives on legitimate URLs that happen to contain a keyword.
        if signals.get('was_shortened', False):
            _slug_risk = signals.get('slug_risk', 0.0)
            if _slug_risk >= 0.70:
                return 'fresh_phishing_setup'
            if _slug_risk >= 0.35 and ml_score > 0.55:
                return 'fresh_phishing_setup'

        # Scenario 2.75: Suspicious TLD + unanimous ML phishing
        # TLDs like .tk, .ml, .ga, .xyz, .top are free/very cheap and heavily
        # abused for phishing. When ML is unanimous at 60%+ AND the URL normalizer
        # flagged a suspicious TLD, route to fresh_phishing_setup.
        # Guard: ml_unanimous required to avoid false positives on legitimate .xyz/.top sites.
        if signals.get('suspicious_tld', False) and ml_unanimous and ml_score > 0.60:
            return 'fresh_phishing_setup'

        # Scenario 2.8: Hijacked Old Domain
        # Pattern: phisher re-registers/buys an expired old domain (WHOIS age looks old),
        # sets up a fresh SSL cert (1–7 days), and runs a phishing site with no email
        # infrastructure (phishing sites don't need email).
        # The old WHOIS age fools age-based checks, but the fresh cert + no email combo
        # is a strong fingerprint. ML must be unanimous (5/5) to avoid false positives.
        #
        # Examples: trj-mars.pro (domain age 23 yrs, SSL cert 1 day, no MX/DMARC/SPF)
        #
        # GUARDS:
        #   - ml_unanimous: all 5 models must agree (reduces false positive risk)
        #   - cert_age_days ≤ 7: cert installed within a week (clear fresh-setup signal)
        #   - not has_email: no MX AND no DMARC (legitimate sites always have email)
        #   - domain_age > 180: only triggers for "old" domains (new domains are caught
        #     by Scenario 2 fresh_phishing_setup with young domain age)
        _cert_age  = signals.get('cert_age_days', 999)
        _has_email = signals.get('has_mx', False) or signals.get('has_dmarc', False)
        if (ml_unanimous
                and ml_score > 0.60
                and _cert_age <= 7
                and not _has_email
                and domain_age > 180):
            return 'fresh_phishing_setup'

        # Scenario 2.9: Credential-harvesting page on trusted/hosting platform
        # Fires when page has a login form or password field AND either:
        #   (a) page title impersonates a brand the URL doesn't belong to, OR
        #   (b) URL is on a trusted/content-hosting domain but ML score > 0.05
        # This catches Google Docs / Adobe Express phishing pages where all
        # UCI structural features look legitimate (HTTPS, old domain, trusted domain)
        # but the page content is a credential-harvesting form.
        _has_creds          = (signals.get('has_login_form', False) or
                               signals.get('has_password_field', False))
        _title_mismatch     = signals.get('page_title_brand_mismatch', False)
        _is_content_hosting = signals.get('is_content_hosting', False)
        # Only fire on content-hosting platforms (Google Drive, Dropbox, Netlify…)
        # NOT on general trusted domains (namecheap.com, espn.com, bankofamerica.com…)
        # which all have legitimate login forms and would generate false positives.
        if _has_creds and (_title_mismatch or (_is_content_hosting and ml_score > 0.15)):
            return 'fresh_phishing_setup'

        # Scenario 3: Low Risk Consensus (Check BEFORE established domain)
        # This prevents Amazon/Google from being labeled "established_domain"
        if (ml_score < 0.3 and domain_risk < 0.3 and cloaking_risk < 0.3):
            return 'low_risk_consensus'

        # Fast-path: very old domain (10+ years) with clean infrastructure → established.
        # Fires BEFORE compromised_domain to prevent 27-year-old legitimate domains
        # (godaddy.com, cloudflare.com, etc.) from being mis-routed when the cloaking
        # detector returns cloaking_detected=True due to bot-protection (not real cloaking).
        _clean_infra = (
            signals.get('domain_risk', 1.0) <= 0.10
            and (signals.get('has_mx') or signals.get('has_dmarc'))
        )
        if domain_age > 3650 and _clean_infra:   # 10 years + clean DNS
            return 'established_domain'

        # Scenario 4: Compromised Old Domain (Check BEFORE established domain)
        # Old domain + cloaking is MORE suspicious than just old domain.
        # GUARD: cloaking_risk must be actually elevated (> 0.50) — prevents bot-protection
        # capping (risk=0.35 for CDN-fronted sites) from triggering this scenario.
        if domain_age > 365 and cloaking_detected and cloaking_risk > 0.50 and ml_score > 0.6:
            return 'compromised_domain'
        
        # Scenario 5: Established Domain (Reduce FP)
        # Now checked AFTER compromised and low-risk scenarios
        # Relaxed: MX OR DMARC (not both) — many legitimate old domains lack DMARC
        if domain_age > 1825:  # 5 years
            if signals.get('has_mx') or signals.get('has_dmarc'):
                return 'established_domain'
        
        # Scenario 6: ML-Domain Conflict
        # Fires when ML is moderately-to-strongly phishing BUT domain signals
        # don't confirm it. Lowered thresholds (was: ml>0.7 AND domain<0.3):
        #   - ml_score > 0.60  → covers unanimous 5/5 phishing after UCI boost
        #   - domain_risk < 0.40 → covers clean-DNS e-commerce sites (risk~0.30)
        # This prevents standard_ensemble from outputting ALLOW/Legitimate when
        # every model votes phishing. conflicting_signals routes to a handler that
        # returns at minimum WARN (Suspicious).
        if ml_score > 0.60 and domain_risk < 0.40:
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
        is_trusted = signals.get('trusted_domain', False)

        # For trusted domains (in whitelist), ML is largely irrelevant — trust the domain
        # For established but not explicitly trusted, still reduce but less aggressively
        ml_factor = 0.15 if is_trusted else 0.5
        adjusted_ml = ml_score * ml_factor

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
        """
        ML says phishing but domain signals are clean — genuine conflict.

        Three sub-cases based on domain age:
          1. Very old (10+ years): domain metadata is authoritative → weight domain 40%
          2. WHOIS timeout (age=0): unknown age → balanced weights, treat neutrally
          3. Known newer domain: trust ML more → weight ML 50%

        IMPORTANT: When ML is unanimous (5/5) and ml_score is still above 0.55
        after all boosts, we NEVER return ALLOW/Legitimate — minimum is WARN/Suspicious.
        This prevents e-commerce sites with external resources from being classified
        as 'Legitimate' when every model votes phishing.
        """
        ml_score    = signals.get('ml_score', 0.5)
        domain_risk = signals.get('domain_risk', 0.5)
        cloaking_risk = signals.get('cloaking_risk', 0.5)
        domain_age  = signals.get('domain_age', 0)
        ml_unanimous = signals.get('ml_unanimous', False)

        if domain_age > 3650:
            # Very old domain (10+ years) → trust domain metadata more
            risk = (ml_score * 0.3 +
                    domain_risk * 0.4 +
                    cloaking_risk * 0.3)
            confidence = 0.70
        elif domain_age == 0:
            # WHOIS timeout — domain age unknown (not necessarily young).
            # Use balanced weights: don't over-penalise for WHOIS failure.
            risk = (ml_score    * 0.40 +
                    domain_risk * 0.35 +
                    cloaking_risk * 0.25)
            confidence = 0.60
        else:
            # Known younger domain → trust ML more
            risk = (ml_score    * 0.50 +
                    domain_risk * 0.20 +
                    cloaking_risk * 0.30)
            confidence = 0.60

        risk_level = self._categorize_risk(risk)
        # FIXED: WARN threshold lowered from 0.5 → 0.45 (consistent with standard_ensemble)
        verdict = 'BLOCK' if risk >= 0.7 else ('WARN' if risk >= 0.45 else 'ALLOW')

        # Unanimous ML floor: if every model voted phishing AND ml_score is still
        # elevated after boosts, never return ALLOW — minimum is WARN (Suspicious).
        # A 5/5 unanimous vote cannot be overridden to 'Legitimate' by domain alone.
        if ml_unanimous and ml_score > 0.55 and verdict == 'ALLOW':
            verdict = 'WARN'
            risk    = max(risk, 0.46)

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
        Standard weighted ensemble for normal cases.

        FIXED v1.1: Adjusted WARN threshold from 0.5 to 0.45
        FIXED v1.2: Unanimous ML vote boost — when all models agree on phishing and
                    the score is in the near-miss zone (0.50–0.65), apply a +0.08 boost
                    so scores like 0.607 / 0.623 cross the 0.63 Phishing threshold.
                    Only fires when every single model voted phishing (ml_unanimous=True).
                    Fixes: account-protection-verification.online (0.607→0.687),
                           nicasia-account-verify-login.secure-banking.xyz (0.623→0.703),
                           ncell-winner-prize-claim-2026.info (0.696→beyond WARN).
        """
        ml_score      = signals.get('ml_score', 0.5)
        domain_risk   = signals.get('domain_risk', 0.5)
        cloaking_risk = signals.get('cloaking_risk', 0.5)
        visual_risk   = signals.get('visual_risk', 0.0)
        ml_unanimous  = signals.get('ml_unanimous', False)

        # Weighted combination (ML has highest weight as it's trained)
        risk = (ml_score    * 0.40 +
                domain_risk * 0.25 +
                cloaking_risk * 0.25 +
                visual_risk * 0.10)

        # ── FIX 3: Unanimous vote boost ────────────────────────────────────
        # When every model agrees the URL is phishing AND the fused score is
        # already in the suspicious-to-phishing boundary zone, add a small boost.
        # Conservative: only fires when ml_unanimous=True AND 0.50 ≤ risk < 0.65.
        if ml_unanimous and 0.50 <= risk < 0.65:
            risk = min(risk + 0.08, 0.99)
        # ───────────────────────────────────────────────────────────────────

        risk_level = self._categorize_risk(risk)

        # FIXED: Changed WARN threshold from 0.5 to 0.45
        verdict = 'BLOCK' if risk >= 0.7 else ('WARN' if risk >= 0.45 else 'ALLOW')

        # ── Unanimous ML safety net ─────────────────────────────────────────
        # If every model voted phishing AND ml_score is still high after all boosts,
        # never return ALLOW/Legitimate — minimum output is WARN/Suspicious.
        # (Most unanimous-phishing cases are caught by conflicting_signals first;
        #  this safety net covers the remaining edge cases.)
        if ml_unanimous and ml_score > 0.55 and verdict == 'ALLOW':
            verdict = 'WARN'
            risk    = max(risk, 0.46)
        # ────────────────────────────────────────────────────────────────────

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
            'fresh_phishing_setup': (
                f"DNS-dead domain with brand keywords — near-certain phishing setup"
                if signals.get('cloaking_dns_failed') or signals.get('visual_dns_failed')
                else f"Free-hosting platform subdomain with high ML confidence"
                if signals.get('free_hosting_subdomain')
                else f"Suspicious: domain ({signals.get('domain_age', 0)} days) with cloaking techniques"
            ),
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


# """
# Intelligent Fusion Module
# System-level ensemble that combines all detection signals with context-aware logic

# Author: Bhanu (Integration Lead)
# Date: March 2026
# Version: 1.1 (Fixed scenario priority and thresholds)
# """

# from typing import Dict, List, Optional
# from enum import Enum


# class RiskLevel(Enum):
#     """Risk level categories"""
#     SAFE = "safe"
#     LOW = "low"
#     MEDIUM = "medium"
#     HIGH = "high"
#     CRITICAL = "critical"


# class IntelligentFusion:
#     """
#     Smart multi-modal fusion for phishing detection
    
#     Combines signals from:
#     1. ML model predictions (Bishesh's models)
#     2. Domain metadata analysis (Task 9)
#     3. Cloaking detection (Task 8)
#     4. Visual similarity (Task 3)
#     5. URL normalization (Task 2)
    
#     Uses context-aware rules instead of simple averaging
#     """
    
#     def __init__(self):
#         # Thresholds for risk categorization
#         self.thresholds = {
#             'safe': 0.2,
#             'low': 0.4,
#             'medium': 0.6,
#             'high': 0.8
#         }
        
#         # Known brands for impersonation detection
#         self.known_brands = [
#             'paypal', 'amazon', 'google', 'microsoft', 'apple',
#             'facebook', 'instagram', 'netflix', 'linkedin', 'chase',
#             'bank of america', 'wells fargo', 'citibank', 'github'
#         ]
    
#     def analyze(self, 
#                 url: str,
#                 ml_result: Optional[Dict] = None,
#                 domain_result: Optional[Dict] = None,
#                 cloaking_result: Optional[Dict] = None,
#                 visual_result: Optional[Dict] = None,
#                 url_features: Optional[Dict] = None) -> Dict:
#         """
#         Main fusion analysis
        
#         Args:
#             url: The URL being analyzed
#             ml_result: ML model prediction
#             domain_result: Domain metadata analysis
#             cloaking_result: Cloaking detection results
#             visual_result: Visual similarity results
#             url_features: URL normalization features
            
#         Returns:
#             Complete decision with reasoning
#         """
        
#         # Extract signals from each module
#         signals = self._extract_signals(
#             ml_result, domain_result, cloaking_result, 
#             visual_result, url_features
#         )
        
#         # Detect scenario
#         scenario = self._detect_scenario(url, signals)
        
#         # Apply scenario-specific logic
#         decision = self._apply_fusion_logic(scenario, signals)
        
#         # Generate reasoning
#         reasoning = self._generate_reasoning(scenario, signals, decision)
        
#         return {
#             'url': url,
#             'final_risk': round(decision['risk'], 3),
#             'risk_level': decision['level'].value,
#             'verdict': decision['verdict'],
#             'confidence': round(decision['confidence'], 2),
#             'reasoning': reasoning,
#             'scenario': scenario,
#             'module_scores': {
#                 'ml': signals.get('ml_score'),
#                 'domain': signals.get('domain_risk'),
#                 'cloaking': signals.get('cloaking_risk'),
#                 'visual': signals.get('visual_risk')
#             }
#         }
    
#     def _extract_signals(self, ml_result, domain_result, 
#                          cloaking_result, visual_result, url_features) -> Dict:
#         """Extract risk scores and metadata from all modules"""
        
#         signals = {}
        
#         # ML Model signals
#         if ml_result:
#             # 'probability' is the numeric score; 'prediction' may be a string label
#             raw_ml = ml_result.get('probability', ml_result.get('prediction', 0.5))
#             signals['ml_score'] = float(raw_ml) if isinstance(raw_ml, (int, float)) else 0.5
#             signals['ml_confidence'] = float(ml_result.get('confidence', 0.5))
#         else:
#             signals['ml_score'] = 0.5  # Default if not available
#             signals['ml_confidence'] = 0.3
        
#         # Domain metadata signals
#         if domain_result:
#             signals['domain_risk'] = domain_result.get('risk_score', 0.5)
#             whois_data = domain_result.get('metadata', {}).get('whois', {})
#             signals['domain_age'] = whois_data.get('domain_age_days') or 0  # None → 0
            
#             dns_data = domain_result.get('metadata', {}).get('dns', {})
#             signals['has_mx'] = dns_data.get('has_mx', False)
#             signals['has_dmarc'] = dns_data.get('has_dmarc', False)
            
#             ssl_data = domain_result.get('metadata', {}).get('ssl', {})
#             signals['has_ssl'] = ssl_data.get('has_ssl', False)
#         else:
#             signals['domain_risk'] = 0.5
#             signals['domain_age'] = 0
#             signals['has_mx'] = False
#             signals['has_dmarc'] = False
#             signals['has_ssl'] = True  # Assume SSL by default
        
#         # Cloaking detection signals
#         if cloaking_result:
#             signals['cloaking_risk'] = cloaking_result.get('overall_risk', 0.5)
#             signals['cloaking_detected'] = cloaking_result.get('cloaking_detected', False)
#             tier1 = cloaking_result.get('tier1', {})
#             signals['cloaking_patterns'] = tier1.get('suspicious_patterns_found', 0)
#         else:
#             signals['cloaking_risk'] = 0.5
#             signals['cloaking_detected'] = False
#             signals['cloaking_patterns'] = 0
        
#         # Visual similarity signals
#         if visual_result:
#             signals['visual_risk'] = visual_result.get('risk_score', 0.0)
#             signals['visual_similarity'] = visual_result.get('max_similarity', 0.0)
#             signals['brand_matched'] = visual_result.get('matched_brand')
#             # dns_failed=True means: the domain contained a brand keyword but had no DNS.
#             # This is a strong phishing signal — surface it so _detect_scenario can use it.
#             signals['visual_dns_failed'] = visual_result.get('dns_failed', False)
#             signals['visual_hint_brand'] = visual_result.get('hint_brand')
#         else:
#             signals['visual_risk'] = 0.0
#             signals['visual_similarity'] = 0.0
#             signals['brand_matched'] = None
#             signals['visual_dns_failed'] = False
#             signals['visual_hint_brand'] = None
#         # # Visual similarity signals
#         # if visual_result:
#         #     signals['visual_risk'] = visual_result.get('risk_score', 0.0)
#         #     signals['visual_similarity'] = visual_result.get('max_similarity', 0.0)
#         #     signals['brand_matched'] = visual_result.get('matched_brand')
#         # else:
#         #     signals['visual_risk'] = 0.0
#         #     signals['visual_similarity'] = 0.0
#         #     signals['brand_matched'] = None
        
#         # URL features
#         if url_features:
#             signals['has_ip'] = url_features.get('has_ip', False)
#             signals['url_length'] = url_features.get('url_length', 0)
#             signals['suspicious_tld'] = url_features.get('suspicious_tld', False)
        
#         return signals
    
#     def _detect_scenario(self, url: str, signals: Dict) -> str:
#         """
#         Detect which scenario this URL falls into
        
#         FIXED: Proper priority ordering to avoid false scenario detection
#         Priority order:
#         1. Brand Impersonation (most critical)
#         2. Fresh Phishing Setup (high priority)
#         3. Low Risk Consensus (check before established domain)
#         4. Compromised Old Domain (check before established domain)
#         5. Established Domain (reduces false positives)
#         6. Conflicting Signals (needs careful handling)
#         7. Standard Ensemble (default)
#         """
        
#         domain_age = signals.get('domain_age', 0)
#         ml_score = signals.get('ml_score', 0.5)
#         domain_risk = signals.get('domain_risk', 0.5)
#         cloaking_risk = signals.get('cloaking_risk', 0.5)
#         cloaking_detected = signals.get('cloaking_detected', False)
#         visual_similarity = signals.get('visual_similarity', 0.0)
#         brand_matched = signals.get('brand_matched')
        
#         # Scenario 1: Brand Impersonation (HIGHEST PRIORITY)
#         # Requires a live screenshot match — only fires when the page was reachable.
#         if visual_similarity > 0.85 and brand_matched:
#             return 'brand_impersonation'
 
#         # Scenario 1.5: Dead Brand-Keyword Domain
#         # The visual module couldn't screenshot because DNS failed, but the URL
#         # contained a known brand keyword (e.g. amazon-account-update.site).
#         # A dead domain impersonating a brand is a near-certain phishing setup.
#         if signals.get('visual_dns_failed') and ml_score > 0.5:
#             return 'fresh_phishing_setup'
 
#         # Scenario 2: Fresh Phishing Setup (High Priority)
#         # FIXED: original required BOTH domain_age < 30 AND cloaking_detected.
#         # This missed cases where:
#         #   (a) WHOIS returns stale/wrong registration dates (common)
#         #   (b) Domain is newly stood up on an old registrar account
#         # New logic: cloaking alone is enough when ML confidence is very high,
#         # OR use the original young-domain check as a secondary path.
#         if cloaking_detected and (domain_age < 30 or ml_score > 0.85):
#             return 'fresh_phishing_setup'
#         if domain_age < 30 and cloaking_detected:
#             return 'fresh_phishing_setup'
#         # # Scenario 1: Brand Impersonation (HIGHEST PRIORITY)
#         # if visual_similarity > 0.85 and brand_matched:
#         #     return 'brand_impersonation'
        
#         # # Scenario 2: Fresh Phishing Setup (High Priority)
#         # if domain_age < 30 and cloaking_detected:
#         #     return 'fresh_phishing_setup'
        
#         # Scenario 3: Low Risk Consensus (Check BEFORE established domain)
#         # This prevents Amazon/Google from being labeled "established_domain"
#         if (ml_score < 0.3 and domain_risk < 0.3 and cloaking_risk < 0.3):
#             return 'low_risk_consensus'
        
#         # Scenario 4: Compromised Old Domain (Check BEFORE established domain)
#         # Old domain + cloaking is MORE suspicious than just old domain
#         if domain_age > 365 and cloaking_detected and ml_score > 0.6:
#             return 'compromised_domain'
        
#         # Scenario 5: Established Domain (Reduce FP)
#         # Now checked AFTER compromised and low-risk scenarios
#         if domain_age > 1825:  # 5 years
#             if signals.get('has_mx') and signals.get('has_dmarc'):
#                 return 'established_domain'
        
#         # Scenario 6: High ML + Low Domain Risk (Conflict)
#         if ml_score > 0.7 and domain_risk < 0.3:
#             return 'conflicting_signals'
        
#         # Default: Standard weighted ensemble
#         return 'standard_ensemble'
    
#     def _apply_fusion_logic(self, scenario: str, signals: Dict) -> Dict:
#         """Apply scenario-specific fusion logic"""
        
#         handlers = {
#             'brand_impersonation': self._handle_brand_impersonation,
#             'fresh_phishing_setup': self._handle_fresh_phishing,
#             'established_domain': self._handle_established_domain,
#             'conflicting_signals': self._handle_conflicting_signals,
#             'compromised_domain': self._handle_compromised_domain,
#             'low_risk_consensus': self._handle_low_risk,
#             'standard_ensemble': self._handle_standard_ensemble
#         }
        
#         handler = handlers.get(scenario, self._handle_standard_ensemble)
#         return handler(signals)
    
#     def _handle_brand_impersonation(self, signals: Dict) -> Dict:
#         """Brand impersonation detected - VERY HIGH RISK"""
#         visual_sim = signals.get('visual_similarity', 0.0)
#         ml_score = signals.get('ml_score', 0.5)
        
#         risk = max(0.9, visual_sim, ml_score)
        
#         return {
#             'risk': min(risk, 1.0),
#             'level': RiskLevel.CRITICAL,
#             'verdict': 'BLOCK',
#             'confidence': 0.95
#         }
    
#     def _handle_fresh_phishing(self, signals: Dict) -> Dict:
#         """New domain with cloaking - VERY HIGH RISK"""
#         ml_score = signals.get('ml_score', 0.5)
#         cloaking_risk = signals.get('cloaking_risk', 0.5)
        
#         risk = max(ml_score, cloaking_risk, 0.85)
        
#         return {
#             'risk': min(risk, 1.0),
#             'level': RiskLevel.CRITICAL,
#             'verdict': 'BLOCK',
#             'confidence': 0.9
#         }
    
#     def _handle_established_domain(self, signals: Dict) -> Dict:
#         """Old domain with good infrastructure - REDUCE FALSE POSITIVES"""
#         ml_score = signals.get('ml_score', 0.5)
#         domain_risk = signals.get('domain_risk', 0.5)
#         cloaking_risk = signals.get('cloaking_risk', 0.5)
        
#         # Reduce ML score impact for established domains
#         adjusted_ml = ml_score * 0.5
        
#         # Weighted combination with reduced ML weight
#         risk = (adjusted_ml * 0.3 + 
#                 domain_risk * 0.3 + 
#                 cloaking_risk * 0.4)
        
#         risk_level = self._categorize_risk(risk)
#         verdict = 'BLOCK' if risk >= 0.7 else ('WARN' if risk >= 0.5 else 'ALLOW')
        
#         return {
#             'risk': risk,
#             'level': risk_level,
#             'verdict': verdict,
#             'confidence': 0.75
#         }
    
#     def _handle_conflicting_signals(self, signals: Dict) -> Dict:
#         """High ML but low domain risk - Need careful analysis"""
#         ml_score = signals.get('ml_score', 0.5)
#         domain_risk = signals.get('domain_risk', 0.5)
#         cloaking_risk = signals.get('cloaking_risk', 0.5)
#         domain_age = signals.get('domain_age', 0)
        
#         # If domain is very old (10+ years), trust domain metadata more
#         if domain_age > 3650:
#             risk = (ml_score * 0.3 + 
#                     domain_risk * 0.4 + 
#                     cloaking_risk * 0.3)
#             confidence = 0.7
#         else:
#             # Newer domain, trust ML more
#             risk = (ml_score * 0.5 + 
#                     domain_risk * 0.2 + 
#                     cloaking_risk * 0.3)
#             confidence = 0.6
        
#         risk_level = self._categorize_risk(risk)
#         verdict = 'BLOCK' if risk >= 0.7 else ('WARN' if risk >= 0.5 else 'ALLOW')
        
#         return {
#             'risk': risk,
#             'level': risk_level,
#             'verdict': verdict,
#             'confidence': confidence
#         }
    
#     def _handle_compromised_domain(self, signals: Dict) -> Dict:
#         """Old domain but showing phishing behavior - Likely compromised"""
#         ml_score = signals.get('ml_score', 0.5)
#         cloaking_risk = signals.get('cloaking_risk', 0.5)
        
#         # Cloaking on old domain is very suspicious
#         risk = max(ml_score, cloaking_risk * 1.2, 0.8)
        
#         return {
#             'risk': min(risk, 1.0),
#             'level': RiskLevel.HIGH,
#             'verdict': 'BLOCK',
#             'confidence': 0.85
#         }
    
#     def _handle_low_risk(self, signals: Dict) -> Dict:
#         """All modules agree - low risk"""
#         ml_score = signals.get('ml_score', 0.5)
#         domain_risk = signals.get('domain_risk', 0.5)
#         cloaking_risk = signals.get('cloaking_risk', 0.5)
        
#         # Simple average when all low
#         risk = (ml_score + domain_risk + cloaking_risk) / 3
        
#         return {
#             'risk': min(risk, 0.3),
#             'level': RiskLevel.SAFE,
#             'verdict': 'ALLOW',
#             'confidence': 0.9
#         }
    
#     def _handle_standard_ensemble(self, signals: Dict) -> Dict:
#         """
#         Standard weighted ensemble for normal cases
        
#         FIXED: Adjusted WARN threshold from 0.5 to 0.45
#         to catch medium-risk cases (like 0.468)
#         """
#         ml_score = signals.get('ml_score', 0.5)
#         domain_risk = signals.get('domain_risk', 0.5)
#         cloaking_risk = signals.get('cloaking_risk', 0.5)
#         visual_risk = signals.get('visual_risk', 0.0)
        
#         # Weighted combination (ML has highest weight as it's trained)
#         risk = (ml_score * 0.4 + 
#                 domain_risk * 0.25 + 
#                 cloaking_risk * 0.25 +
#                 visual_risk * 0.1)
        
#         risk_level = self._categorize_risk(risk)
        
#         # FIXED: Changed threshold from 0.5 to 0.45
#         verdict = 'BLOCK' if risk >= 0.7 else ('WARN' if risk >= 0.45 else 'ALLOW')
        
#         return {
#             'risk': risk,
#             'level': risk_level,
#             'verdict': verdict,
#             'confidence': 0.7
#         }
    
#     def _categorize_risk(self, risk: float) -> RiskLevel:
#         """Convert numerical risk to category"""
#         if risk < self.thresholds['safe']:
#             return RiskLevel.SAFE
#         elif risk < self.thresholds['low']:
#             return RiskLevel.LOW
#         elif risk < self.thresholds['medium']:
#             return RiskLevel.MEDIUM
#         elif risk < self.thresholds['high']:
#             return RiskLevel.HIGH
#         else:
#             return RiskLevel.CRITICAL
    
#     def _generate_reasoning(self, scenario: str, signals: Dict, 
#                            decision: Dict) -> List[str]:
#         """Generate human-readable reasoning for the decision"""
#         reasoning = []
        
#         # Scenario explanation
#         scenario_explanations = {
#             'brand_impersonation': f"ALERT: Visual match to {signals.get('brand_matched')} ({signals.get('visual_similarity', 0)*100:.0f}% similarity)",
#             'fresh_phishing_setup': f"Suspicious: New domain ({signals.get('domain_age', 0)} days) with cloaking techniques",
#             'established_domain': f"Note: Established domain ({signals.get('domain_age', 0)} days old) with infrastructure",
#             'conflicting_signals': "Mixed signals detected from different modules",
#             'compromised_domain': f"WARNING: Old domain ({signals.get('domain_age', 0)} days) showing malicious behavior",
#             'low_risk_consensus': "All detection modules indicate low risk",
#             'standard_ensemble': "Multi-modal analysis applied"
#         }
        
#         reasoning.append(scenario_explanations.get(scenario, "Standard analysis"))
        
#         # Add key findings
#         if signals.get('ml_score', 0) > 0.7:
#             reasoning.append(f"ML model: High phishing probability ({signals['ml_score']:.2f})")
        
#         if signals.get('cloaking_detected'):
#             reasoning.append(f"Cloaking: {signals.get('cloaking_patterns', 0)} suspicious patterns detected")
        
#         if signals.get('domain_age', 0) < 30:
#             reasoning.append("Domain: Very recently registered (high risk)")
#         elif signals.get('domain_age', 0) > 1825:
#             reasoning.append("Domain: Well-established (reduces false positive risk)")
        
#         if not signals.get('has_mx'):
#             reasoning.append("Infrastructure: No email (suspicious)")
        
#         if not signals.get('has_ssl'):
#             reasoning.append("Security: No SSL certificate")
        
#         # Final verdict
#         reasoning.append(f"VERDICT: {decision['verdict']} (Risk: {decision['risk']:.2f}, Confidence: {decision['confidence']:.0%})")
        
#         return reasoning


# # Simple usage example
# if __name__ == '__main__':
#     fusion = IntelligentFusion()
    
#     # Test with mock data
#     result = fusion.analyze(
#         url='https://example.com',
#         ml_result={'prediction': 0.7},
#         domain_result={'risk_score': 0.3},
#         cloaking_result={'overall_risk': 0.5}
#     )
    
#     print("Test Result:")
#     print(f"Risk: {result['final_risk']}")
#     print(f"Verdict: {result['verdict']}")
#     print(f"Scenario: {result['scenario']}")
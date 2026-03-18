// import { useLocation } from 'react-router-dom';
// import React, { useEffect, useState } from 'react';
// import axios from 'axios';
// import API_URLS from '../../apiConfig';
// import './Result.css';

// const Result = () => {
//     const location = useLocation();
//     const { inputUrl } = location.state || {};

//     const [analysisResult, setAnalysisResult] = useState(null);
//     const [loading, setLoading] = useState(true);
//     const [error, setError] = useState(null);

//     useEffect(() => {
//         const fetchAnalysis = async () => {
//             if (!inputUrl) {
//                 setError("No URL was provided for analysis.");
//                 setLoading(false);
//                 return;
//             }

//             try {
//                 setLoading(true);
//                 const response = await axios.post(
//                     `${API_URLS.flaskBackend}/analyze_url`,
//                     { url: inputUrl.trim() }
//                 );
//                 setAnalysisResult(response.data);
//                 setError(null);
//             } catch (err) {
//                 console.error('Analysis failed:', err);
//                 const msg = err.response?.data?.error || err.message || "Unknown error";
//                 setError(`Failed to analyze URL: ${msg}`);
//             } finally {
//                 setLoading(false);
//             }
//         };

//         fetchAnalysis();
//     }, [inputUrl]);

//     if (loading) {
//         return (
//             <div style={containerStyle}>
//                 <h2>Analyzing URL...</h2>
//                 <p>Please wait while we scan for phishing indicators.</p>
//             </div>
//         );
//     }

//     if (error) {
//         return (
//             <div style={containerStyle}>
//                 <h2 style={{ color: '#c62828' }}>Analysis Error</h2>
//                 <p>{error}</p>
//             </div>
//         );
//     }

//     if (!analysisResult) {
//         return (
//             <div style={containerStyle}>
//                 <h2>No Results</h2>
//             </div>
//         );
//     }

//     // ------------------ CLASSIFICATION LOGIC ------------------
//     const isSafe = analysisResult.prediction === "Legitimate";
//     const confidencePercent = analysisResult.ensemble
//   ? (analysisResult.ensemble.consensus_probability * 100).toFixed(1)
//   : (analysisResult.confidence || 0).toFixed(1);


//     const riskColor =
//         analysisResult.risk_level === "Low" ? "#2e7d32" :
//         analysisResult.risk_level === "Medium" ? "#ff8f00" :
//         "#c62828";

//     return (
//         <div style={containerStyle}>
//             {/* ================= SUMMARY CARDS ================= */}
//             <div className="card-container">
//                 <div className="card">
//                     <h2>Verdict</h2>
//                     <div style={isSafe ? cardStyle_S : cardStyle_F}>
//                         <h2 style={{ color: isSafe ? '#2e7d32' : '#c62828' }}>
//                             {analysisResult.prediction}
//                         </h2>
//                         <p>
//                             {isSafe
//                                 ? "This website appears safe."
//                                 : "This website shows phishing indicators."}
//                         </p>
//                     </div>
//                 </div>

//                 <div className="card">
//                     <h2>Model Confidence</h2>
//                     <h1 style={{ color: isSafe ? '#2e7d32' : '#c62828' }}>
//                         {confidencePercent}%
//                     </h1>
//                     <p>AI certainty level</p>
//                 </div>

//                 <div className="card">
//                     <h2>Risk Level</h2>
//                     <h1 style={{ color: riskColor }}>
//                         {analysisResult.risk_level}
//                     </h1>
//                     <p>Estimated threat severity</p>
//                 </div>
//             </div>

//             {/* ================= VERDICT REASON (NEW) ================= */}
//             <div
//                 style={{
//                     maxWidth: '900px',
//                     margin: '3rem auto',
//                     background: isSafe ? '#e8f5e8' : '#ffebee',
//                     padding: '2.5rem',
//                     borderRadius: '20px',
//                     borderLeft: `6px solid ${isSafe ? '#2e7d32' : '#c62828'}`,
//                     textAlign: 'left'
//                 }}
//             >
//                 <h2 style={{ color: isSafe ? '#2e7d32' : '#c62828' }}>
//                     🧠 Verdict Reason
//                 </h2>

//                 <p style={{ fontSize: '1.1rem', marginTop: '1rem' }}>
//                     <strong>System Recommendation:</strong><br />
//                     {analysisResult.recommendation}
//                 </p>

//                 {analysisResult.ensemble && (
//                     <p style={{ marginTop: '1.2rem' }}>
//                         <strong>Model Consensus:</strong><br />
//                         {analysisResult.ensemble.agreement} →{" "}
//                         <strong>{analysisResult.ensemble.consensus}</strong>
//                         {" "}({(analysisResult.ensemble.consensus_probability * 100).toFixed(1)}%)
//                     </p>
//                 )}

//                 {analysisResult.top_risk_factors?.length > 0 ? (
//                     <>
//                         <p style={{ marginTop: '1.5rem', fontWeight: 600 }}>
//                             Key factors influencing this decision:
//                         </p>
//                         <ul style={{ paddingLeft: '1.5rem' }}>
//                             {analysisResult.top_risk_factors.map((factor, idx) => (
//                                 <li key={idx} style={{ marginBottom: '0.7rem' }}>
//                                     <strong>{factor.feature}:</strong> {factor.reason}
//                                 </li>
//                             ))}
//                         </ul>
//                     </>
//                 ) : (
//                     <p style={{ marginTop: '1.5rem', fontStyle: 'italic' }}>
//                         No significant phishing indicators were detected for this URL.
//                     </p>
//                 )}
//             </div>

//             {/* ================= URL INFO ================= */}
//             <div style={statusStyle}>
//                 <p style={urlTextStyle}>
//                     <strong>Scanned URL:</strong> {analysisResult.url}
//                 </p>
//                 <p>
//                     <strong>Domain:</strong> {analysisResult.domain}
//                 </p>
//             </div>

//             {/* ================= FOOTER ================= */}
//             <p style={{ marginTop: '3rem', color: '#555' }}>
//                 PhishNet uses an ensemble ML model with explainable AI to detect phishing attempts.
//             </p>
//         </div>
//     );
// };

// /* ================= STYLES ================= */
// const containerStyle = { textAlign: 'center', padding: '2rem', backgroundColor: '#f5f7fa', minHeight: '100vh' };
// const statusStyle = { margin: '2rem 0' };
// const urlTextStyle = { fontSize: '1.2rem', background: '#fff', padding: '1rem', borderRadius: '12px' };
// const cardStyle_S = { background: '#e8f5e8', padding: '1.5rem', borderRadius: '16px' };
// const cardStyle_F = { background: '#ffebee', padding: '1.5rem', borderRadius: '16px' };

// export default Result;
import { useLocation, useNavigate } from 'react-router-dom';
import { useEffect, useState, useContext, useRef } from 'react';
import axios from 'axios';
import { UserContext } from '../../context/UserContext';
import './Result.css';

const Result = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const { inputUrl } = location.state || {};
    const { fetchScanStatistics } = useContext(UserContext);

    const [analysisResult, setAnalysisResult] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const hasFetched = useRef(false);

    useEffect(() => {
        if (hasFetched.current) return;  // StrictMode guard — only run once per mount
        hasFetched.current = true;

        const fetchAnalysis = async () => {
            if (!inputUrl) {
                setError("No URL was provided for analysis.");
                setLoading(false);
                return;
            }

            try {
                setLoading(true);
                setError(null);

                // ✅ NEW: Use Express backend with authentication
                const response = await axios.post(
                    'http://localhost:8800/api/phishing/analyze',
                    { url: inputUrl.trim() },
                    {
                        headers: { 'Content-Type': 'application/json' },
                        withCredentials: true,  // Include JWT cookie
                        timeout: 120000
                    }
                );

                if (response.data.success) {
                    setAnalysisResult(response.data.data);
                    await fetchScanStatistics();
                } else {
                    throw new Error(response.data.message || 'Analysis failed');
                }

            } catch (err) {
                console.error('Analysis failed:', err);

                // ✅ Handle rate limit error (429)
                if (err.response?.status === 429) {
                    setError(
                        <div>
                            <p>{err.response.data.message}</p>
                            {!err.response.data.isPremium && (
                                <p style={{ marginTop: '1rem' }}>
                                    <a href="/getpremium" style={{ color: '#667eea', textDecoration: 'underline' }}>
                                        Upgrade to Premium for 1000 scans/day →
                                    </a>
                                </p>
                            )}
                        </div>
                    );
                } else if (err.response?.status === 401 || err.response?.status === 403) {
                    setError('Please login to scan URLs');
                    setTimeout(() => navigate('/login'), 2000);
                } else if (err.response?.status === 503) {
                    setError('Phishing detection service is temporarily unavailable. Please try again later.');
                } else {
                    setError(err.response?.data?.message || err.message || 'Analysis failed');
                }
            } finally {
                setLoading(false);
            }
        };

        fetchAnalysis();
    }, [inputUrl]);

    // Loading State
    if (loading) {
        return (
            <div className="result-container">
                <div className="loading-card">
                    <div className="loading-spinner"></div>
                    <h2>Analyzing URL...</h2>
                    <p className="url-text">{inputUrl}</p>
                    <p className="loading-subtext">This may take a few seconds</p>
                </div>
            </div>
        );
    }

    // Error State
    if (error) {
        return (
            <div className="result-container">
                <div className="error-card">
                    <div className="error-icon">⚠️</div>
                    <h2>Analysis Failed</h2>
                    <p className="error-message">{error}</p>
                    <div className="button-group">
                        <button onClick={() => navigate('/')} className="btn-primary">
                            ← Back to Home
                        </button>
                        <button onClick={() => window.location.reload()} className="btn-secondary">
                            🔄 Try Again
                        </button>
                    </div>
                </div>
            </div>
        );
    }

    if (!analysisResult) {
        return (
            <div className="result-container">
                <div className="error-card">
                    <h2>No Results Available</h2>
                    <button onClick={() => navigate('/')} className="btn-primary">
                        Go Back
                    </button>
                </div>
            </div>
        );
    }

    // Main Results Display
    const isPhishing = analysisResult.prediction === "Phishing";
    const isTrusted = analysisResult.is_trusted;
    const detectionSource = analysisResult.detection_source;

    // Hosted-content risk: only when backend explicitly flagged it (content-hosting platforms
    // like Google Docs/Drive/Dropbox with unanimous ML + 90%+ probability).
    // Do NOT derive this on the frontend — trusted domains like facebook.com, namecheap.com
    // all have high raw ML scores and would false-positive here.
    const isHostedContentRisk = analysisResult.hosted_content_risk === true;
    // ML always runs now — ensemble data is present for ml_ensemble and rule_engine_ml
    const hasMLData = ['ml', 'ml_ensemble', 'rule_engine_ml'].includes(detectionSource) || (!detectionSource && analysisResult.ensemble);
    const autoBlacklisted = analysisResult.auto_blacklisted === true;

    const handleRemoveFromBlacklist = async () => {
        if (!window.confirm(
            `Remove "${analysisResult.url}" from the blacklist?\n\nOnly do this if you are sure this is a legitimate site that was incorrectly flagged.`
        )) return;
        try {
            const response = await axios.delete(
                'http://localhost:8800/api/phishing/blacklist/remove',
                { data: { url: analysisResult.url }, withCredentials: true }
            );
            // alert(response.data.message + '\n\nThe page will reload to show the updated result.');
            // window.location.reload();
        } catch (err) {
            alert(err.response?.data?.message || 'Failed to remove from blacklist. Please try again.');
        }
    };

    const handleReport = async () => {
        try {
            const response = await axios.post(
                'http://localhost:8800/api/phishing/report',
                { url: analysisResult.url },
                { withCredentials: true }
            );
            alert(response.data.message);
        } catch (err) {
            alert(err.response?.data?.message || 'Failed to submit report. Please try again.');
        }
    };

    const detectionSourceMeta = {
        blacklist:            { label: 'Known Threat — Blacklisted Domain',     icon: '⚫',    cls: 'source-blacklist'  },
        rules:                { label: 'Detected by Rule Engine',               icon: '🔍',    cls: 'source-rules'      },
        rule_engine_ml:       { label: 'Rule Engine + ML Ensemble (combined)',  icon: '🔍🤖',  cls: 'source-rules-ml'   },
        ml:                   { label: 'Detected by ML Ensemble',               icon: '🤖',    cls: 'source-ml'         },
        ml_ensemble:          { label: 'Detected by ML Ensemble',               icon: '🤖',    cls: 'source-ml'         },
        campaign_correlation: { label: 'Campaign Correlation Match',            icon: '🌐',    cls: 'source-campaign'   },
    };
    const sourceMeta = detectionSourceMeta[detectionSource] || null;

    // ── Derived helpers used in new layout ──────────────────────
    const scenarioLabels = {
        brand_impersonation:  'Brand Impersonation',
        fresh_phishing_setup: 'Fresh Phishing Setup',
        low_risk_consensus:   'Low Risk Consensus',
        compromised_domain:   'Compromised Domain',
        established_domain:   'Established Domain',
        conflicting_signals:  'Conflicting Signals',
        standard_ensemble:    'Standard Ensemble',
    };
    const fusionModuleLabels = { ml: 'ML Ensemble', domain: 'Domain', cloaking: 'Cloaking', visual: 'Visual' };
    const flagMeta = {
        PUNYCODE_DETECTED:       { label: 'Punycode Domain',       cls: 'flag-danger' },
        HOMOGLYPH_DETECTED:      { label: 'Lookalike Characters',  cls: 'flag-danger' },
        IP_ADDRESS:              { label: 'IP Address Domain',     cls: 'flag-danger' },
        URL_SHORTENER:           { label: 'URL Shortener',         cls: 'flag-warn'   },
        SUSPICIOUS_TLD:          { label: 'Suspicious TLD',        cls: 'flag-warn'   },
        EXCESSIVE_SUBDOMAINS:    { label: 'Excessive Subdomains',  cls: 'flag-warn'   },
        AT_SYMBOL_OBFUSCATION:   { label: '@ Symbol Trick',        cls: 'flag-danger' },
        EXCESSIVE_HYPHENS:       { label: 'Excessive Hyphens',     cls: 'flag-warn'   },
        EXCESSIVE_HEX_ENCODING:  { label: 'Hex Obfuscation',       cls: 'flag-danger' },
        UNUSUALLY_LONG_DOMAIN:   { label: 'Unusually Long Domain', cls: 'flag-warn'   },
    };

    const urlFlags     = analysisResult.url_normalization?.flags || [];
    const ruleViolations = analysisResult.rule_analysis?.rule_violations || [];
    const allReasons   = analysisResult.boost_reasons || [];
    // Split boost_reasons into actual threat signals vs legitimacy indicators
    const _LEGIT_KEYWORDS = ['legitimate', 'legitimacy', 'trusted whitelist'];
    const threatReasons = allReasons.filter(r => !_LEGIT_KEYWORDS.some(kw => r.toLowerCase().includes(kw)));
    const legitReasons  = allReasons.filter(r =>  _LEGIT_KEYWORDS.some(kw => r.toLowerCase().includes(kw)));
    const hasThreats    = urlFlags.length > 0 || ruleViolations.length > 0 || threatReasons.length > 0 || legitReasons.length > 0;
    const hasDomainData = analysisResult.domain_metadata || analysisResult.cloaking || analysisResult.url_analysis;

    return (
        <div className="result-container">
            {/* Header */}
            <div className="result-header">
                <button onClick={() => navigate('/')} className="back-button">← Back</button>
                <h1>Analysis Results</h1>
            </div>


            {/* ── CARD 1: Main Verdict ───────────────────────────────── */}
            <div className={`main-result-card ${isHostedContentRisk ? 'suspicious' : isPhishing ? 'phishing' : 'legitimate'}`}>
                <div className="result-icon">
                    {isHostedContentRisk ? '⚠️' : (analysisResult.risk_emoji || (isPhishing ? '🔴' : '✅'))}
                </div>
                <h2 className="result-prediction">
                    {isHostedContentRisk ? 'Suspicious' : analysisResult.prediction}
                </h2>
                <div className={`safety-verdict ${isHostedContentRisk ? 'warn' : analysisResult.safe_to_visit ? 'safe' : 'unsafe'}`}>
                    {isHostedContentRisk
                        ? <span>Proceed with Caution</span>
                        : analysisResult.safe_to_visit
                            ? <span>Safe to Visit</span>
                            : <span>Do Not Visit</span>}
                </div>

                {/* Risk bar */}
                <div className="risk-bar-container" style={{ margin: '12px 0 8px' }}>
                    <div className="risk-bar-fill" style={{
                        width: isHostedContentRisk ? `${Math.round(analysisResult.base_probability * 100)}%` : `${analysisResult.confidence}%`,
                        background: isHostedContentRisk ? '#ffa500' : getRiskColor(analysisResult.confidence)
                    }} />
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', color: '#666', marginBottom: '12px' }}>
                    <span>{isHostedContentRisk ? 'High Risk (Hosted Content)' : `${analysisResult.risk_level} Risk`}</span>
                    <span>{isHostedContentRisk ? `${Math.round(analysisResult.base_probability * 100)}%` : `${analysisResult.confidence}%`}</span>
                </div>

                <p className="url-analyzed" style={{ wordBreak: 'break-all', fontSize: '0.85rem' }}>
                    <strong>URL:</strong> {analysisResult.url}
                </p>

                {/* Inline badges */}
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginTop: '10px', justifyContent: 'center' }}>
                    {isHostedContentRisk && (
                        <span className="detection-source-badge source-hosted-risk" style={{ display: 'inline-flex' }}>
                            Phishing Content on Trusted Platform
                        </span>
                    )}
                    {!isHostedContentRisk && sourceMeta && (
                        <span className={`detection-source-badge ${sourceMeta.cls}`} style={{ display: 'inline-flex' }}>
                            {sourceMeta.label}
                        </span>
                    )}
                    {isTrusted && <span className="inline-badge badge-trusted">Trusted Domain</span>}
                    {autoBlacklisted && <span className="inline-badge badge-blacklisted">Auto-blacklisted</span>}
                </div>
            </div>

            {/* Blacklist Info Card */}
            {detectionSource === 'blacklist' && analysisResult.blacklist_info && (
                <div className="blacklist-info-card">
                    <h3>Confirmed Blacklisted Domain</h3>
                    <p className="blacklist-desc">
                        This domain is in our threat database and has been confirmed malicious.
                        No further analysis was needed.
                    </p>
                    <div className="blacklist-details-grid">
                        <div className="blacklist-detail-item">
                            <span className="bl-label">Category</span>
                            <span className={`bl-value category-badge ${analysisResult.blacklist_info.category}`}>
                                {analysisResult.blacklist_info.category}
                            </span>
                        </div>
                        <div className="blacklist-detail-item">
                            <span className="bl-label">Reports</span>
                            <span className="bl-value">{analysisResult.blacklist_info.reports_count} user report(s)</span>
                        </div>
                        {analysisResult.blacklist_info.target_brand && (
                            <div className="blacklist-detail-item">
                                <span className="bl-label">Impersonating</span>
                                <span className="bl-value">{analysisResult.blacklist_info.target_brand}</span>
                            </div>
                        )}
                        <div className="blacklist-detail-item">
                            <span className="bl-label">Detection</span>
                            <span className="bl-value">{analysisResult.blacklist_info.detection_method}</span>
                        </div>
                    </div>
                    <div className="blacklist-false-positive">
                        <p className="fp-hint">Think this is a mistake? You can flag it as a false positive to remove it from the blacklist.</p>
                        <button className="btn-false-positive" onClick={handleRemoveFromBlacklist}>
                            ✕ Remove from Blacklist (False Positive)
                        </button>
                    </div>
                </div>
            )}

            {/* ── Hosted-Content Phishing Warning ─────────────────── */}
            {/* Only fires when backend explicitly flagged hosted_content_risk  */}
            {analysisResult.hosted_content_risk === true && (
                <div className="hosted-content-warning">
                    <div className="hcw-header">
                        <div>
                            <h3>Legitimate Platform — Suspicious Content</h3>
                            <p className="hcw-subtitle">
                                This URL belongs to a trusted domain, but the ML models detected strong phishing signals in the page content.
                            </p>
                        </div>
                        <span className="hcw-badge">CONTENT RISK</span>
                    </div>
                    <p className="hcw-desc">
                        Attackers sometimes host phishing pages on legitimate platforms (Google Docs, Google Drawings, OneDrive, Dropbox) to bypass domain-based filters.
                        The domain <strong>{analysisResult.domain}</strong> is genuine, but the content at this specific URL may be a credential-harvesting page.
                    </p>
                    <div className="hcw-stat-row">
                        <div className="hcw-stat">
                            <span className="hcw-stat-label">ML Phishing Score</span>
                            <span className="hcw-stat-value hcw-danger">{(analysisResult.base_probability * 100).toFixed(1)}%</span>
                        </div>
                        <div className="hcw-stat">
                            <span className="hcw-stat-label">Domain Trust</span>
                            <span className="hcw-stat-value hcw-safe">Verified</span>
                        </div>
                        <div className="hcw-stat">
                            <span className="hcw-stat-label">Recommendation</span>
                            <span className="hcw-stat-value hcw-warn">Inspect carefully</span>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Campaign Match Card ─────────────────────────────── */}
            {analysisResult.campaign_match && (
                <div className="campaign-match-card">
                    <h3>Campaign Correlation Match</h3>
                    <p className="campaign-match-desc">
                        This URL's infrastructure fingerprint matches a known active phishing campaign.
                        The verdict has been elevated to <strong>Phishing</strong> based on collective intelligence.
                    </p>
                    <div className="campaign-match-grid">
                        <div className="cm-item">
                            <span className="cm-label">Campaign</span>
                            <span className="cm-value">{analysisResult.campaign_match.name}</span>
                        </div>
                        <div className="cm-item">
                            <span className="cm-label">Total Hits</span>
                            <span className="cm-value cm-hits">{analysisResult.campaign_match.totalHits} URLs</span>
                        </div>
                        <div className="cm-item">
                            <span className="cm-label">Threat Level</span>
                            <span className="cm-value">{analysisResult.campaign_match.threatLevel}</span>
                        </div>
                        <div className="cm-item">
                            <span className="cm-label">First Seen</span>
                            <span className="cm-value">{new Date(analysisResult.campaign_match.firstSeen).toLocaleDateString()}</span>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Campaign Intelligence Card (Phase B) ─────────────── */}
            {/* Shows when this scan contributed to the campaign database  */}
            {/* but the verdict itself came from ML/rules (not Phase A).   */}
            {analysisResult.campaign_info && !analysisResult.campaign_match && (
                <div className="campaign-intel-card">
                    <div className="ci-header">
                        <div>
                            <h3>Campaign Intelligence</h3>
                            <p className="ci-subtitle">
                                {analysisResult.campaign_info.isNew
                                    ? 'This URL seeded a new phishing campaign in the intelligence database.'
                                    : 'This URL was linked to an existing active phishing campaign.'}
                            </p>
                        </div>
                        <span className={`ci-badge ${analysisResult.campaign_info.isNew ? 'ci-badge-new' : 'ci-badge-known'}`}>
                            {analysisResult.campaign_info.isNew ? 'NEW CAMPAIGN' : 'KNOWN CAMPAIGN'}
                        </span>
                    </div>
                    <p className="ci-desc">
                        PhishNet's collective intelligence engine has recorded this infrastructure fingerprint.
                        Future URLs sharing the same server IP or HTML signature will be <strong>automatically flagged as Phishing</strong> — even if their ML score appears legitimate.
                    </p>
                    <div className="campaign-match-grid">
                        <div className="cm-item">
                            <span className="cm-label">Campaign ID</span>
                            <span className="cm-value ci-mono">{analysisResult.campaign_info.name}</span>
                        </div>
                        <div className="cm-item">
                            <span className="cm-label">Total Hits</span>
                            <span className="cm-value cm-hits">{analysisResult.campaign_info.totalHits} URL{analysisResult.campaign_info.totalHits !== 1 ? 's' : ''}</span>
                        </div>
                        <div className="cm-item">
                            <span className="cm-label">Threat Level</span>
                            <span className="cm-value">{analysisResult.campaign_info.threatLevel}</span>
                        </div>
                        <div className="cm-item">
                            <span className="cm-label">First Seen</span>
                            <span className="cm-value">{new Date(analysisResult.campaign_info.firstSeen).toLocaleDateString()}</span>
                        </div>
                    </div>
                </div>
            )}

            {/* ── Hosted-Content Risk Warning ─────────────────────── */}
            {analysisResult.hosted_content_risk && (
                <div className="hosted-content-warning">
                    <div className="hcw-header">
                        <div>
                            <h3>Potential Hosted Phishing Content</h3>
                            <p className="hcw-subtitle">
                                This URL is on a trusted platform, but our ML models flagged it with very high confidence.
                                Attackers sometimes host phishing pages inside Google Docs, Forms, or Drawings.
                            </p>
                        </div>
                    </div>
                    <p className="hcw-note">
                        The domain itself is legitimate. If you did not expect this link, do not enter any personal information on the page it leads to.
                    </p>
                </div>
            )}

            {/* ── CARD 2: Why This Verdict (Fusion) ──────────────── */}
            {analysisResult.fusion_result && (
                <div className="fusion-card">
                    <div className="fusion-header-row">
                        <div>
                            <h3 style={{ margin: 0 }}>Why This Verdict?</h3>
                            <span className="fusion-scenario-tag">
                                {scenarioLabels[analysisResult.fusion_result.scenario] || analysisResult.fusion_result.scenario}
                            </span>
                        </div>
                        <span className={`fusion-verdict-badge fusion-verdict-${analysisResult.fusion_result.verdict?.toLowerCase()}`}>
                            {analysisResult.fusion_result.verdict === 'ALLOW' ? 'ALLOW' :
                             analysisResult.fusion_result.verdict === 'WARN'  ? 'WARN'  : 'BLOCK'}
                        </span>
                    </div>

                    {/* Module score bars */}
                    {analysisResult.fusion_result.module_scores && Object.keys(analysisResult.fusion_result.module_scores).length > 0 && (
                        <div className="fusion-module-scores">
                            {Object.entries(analysisResult.fusion_result.module_scores).map(([mod, score]) => {
                                const pct = Math.round((score || 0) * 100);
                                const cls = pct >= 60 ? 'high' : pct >= 35 ? 'medium' : 'low';
                                return (
                                    <div key={mod} className="fusion-score-row">
                                        <span className="fusion-score-label">{fusionModuleLabels[mod] || mod}</span>
                                        <div className="fusion-score-bar-wrap">
                                            <div className={`fusion-score-bar fusion-bar-${cls}`} style={{ width: `${pct}%` }} />
                                        </div>
                                        <span className={`fusion-score-val fusion-bar-${cls}`}>{pct}%</span>
                                    </div>
                                );
                            })}
                        </div>
                    )}

                    {/* Reasoning */}
                    {analysisResult.fusion_result.reasoning?.length > 0 && (
                        <ul className="fusion-reasoning-list">
                            {analysisResult.fusion_result.reasoning.map((r, i) => <li key={i}>{r}</li>)}
                        </ul>
                    )}
                </div>
            )}

            {/* ── CARD 3: Threat Signals (Rule Violations + Risk Factors + URL Flags) ── */}
            {hasThreats && (
                <div className="threat-signals-card">
                    <h3>{threatReasons.length > 0 || ruleViolations.length > 0 || urlFlags.length > 0 ? 'Threat Signals Detected' : 'Detection Signals'}</h3>

                    {/* URL pattern flags */}
                    {urlFlags.length > 0 && (
                        <div className="threat-section">
                            <h4>URL Patterns</h4>
                            <div className="url-norm-flags">
                                {urlFlags.map((flag, i) => {
                                    const meta = flagMeta[flag] || { label: flag.replace(/_/g, ' '), cls: 'flag-warn' };
                                    return <span key={i} className={`url-norm-flag ${meta.cls}`}>{meta.label}</span>;
                                })}
                            </div>
                        </div>
                    )}

                    {/* Rule violations */}
                    {ruleViolations.length > 0 && (
                        <div className="threat-section">
                            <h4>Rule Violations ({ruleViolations.length}) — {(analysisResult.rule_analysis.confidence * 100).toFixed(0)}% confidence</h4>
                            <div className="violations-list">
                                {ruleViolations.map((rule, idx) => (
                                    <div key={idx} className={`violation-item sev-${rule.severity.toLowerCase()}`}>
                                        <span className={`severity-badge sev-badge-${rule.severity.toLowerCase()}`}>{rule.severity}</span>
                                        <span className="rule-name">{rule.rule.replace(/_/g, ' ')}</span>
                                        <p className="violation-desc">{rule.description}</p>
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Risk boost reasons — actual threat signals only */}
                    {threatReasons.length > 0 && (
                        <div className="threat-section">
                            <h4>Risk Factors</h4>
                            <ul className="risk-factors-simple">
                                {threatReasons.map((r, i) => <li key={i}>{r}</li>)}
                            </ul>
                        </div>
                    )}

                    {/* Legitimacy indicators — signals that reduce risk */}
                    {legitReasons.length > 0 && (
                        <div className="threat-section">
                            <h4 style={{ color: '#4caf50' }}>Legitimacy Indicators</h4>
                            <ul className="risk-factors-simple" style={{ color: '#81c784' }}>
                                {legitReasons.map((r, i) => <li key={i}>{r}</li>)}
                            </ul>
                        </div>
                    )}
                </div>
            )}

            {/* ── CARD 4: Site Intelligence (Domain + Cloaking + URL Details) ── */}
            {hasDomainData && (
                <div className="site-intel-card">
                    <h3>Site Intelligence</h3>
                    <div className="site-intel-grid">

                        {/* Domain age */}
                        {(analysisResult.domain_metadata?.metadata?.whois?.domain_age_days !== undefined ||
                          analysisResult.url_analysis?.domain_age_days !== undefined) && (
                            <div className="intel-item">
                                <span className="intel-label">Domain Age</span>
                                {(() => {
                                    const days = analysisResult.domain_metadata?.metadata?.whois?.domain_age_days
                                              ?? analysisResult.url_analysis?.domain_age_days;
                                    const cls = days === null ? 'meta-neutral' : days < 30 ? 'meta-danger' : days < 180 ? 'meta-warn' : 'meta-good';
                                    const txt = days === null || days === undefined ? 'Unknown'
                                              : days < 30 ? `${days} day(s) (new)`
                                              : days < 365 ? `${Math.round(days/30)} month(s)`
                                              : `${(days/365).toFixed(1)} yr(s)`;
                                    return <span className={`intel-value ${cls}`}>{txt}</span>;
                                })()}
                            </div>
                        )}

                        {/* SSL */}
                        {(analysisResult.domain_metadata?.metadata?.ssl ||
                          analysisResult.url_analysis?.is_https !== undefined) && (
                            <div className="intel-item">
                                <span className="intel-label">SSL / HTTPS</span>
                                {(() => {
                                    const ssl = analysisResult.domain_metadata?.metadata?.ssl;
                                    if (ssl) {
                                        const ok = ssl.has_ssl && !ssl.is_self_signed && !ssl.domain_mismatch;
                                        return <span className={`intel-value ${ok ? 'meta-good' : 'meta-danger'}`}>
                                            {ssl.has_ssl ? (ssl.is_self_signed ? 'Self-signed' : 'Valid') : 'None'}
                                            {ssl.is_free_cert && ' (Free CA)'}
                                        </span>;
                                    }
                                    const isHttps = analysisResult.url_analysis?.is_https;
                                    return <span className={`intel-value ${isHttps ? 'meta-good' : 'meta-danger'}`}>{isHttps ? 'HTTPS' : 'HTTP'}</span>;
                                })()}
                            </div>
                        )}

                        {/* MX records */}
                        {analysisResult.domain_metadata?.metadata?.dns?.has_mx !== undefined && (
                            <div className="intel-item">
                                <span className="intel-label">Email (MX)</span>
                                <span className={`intel-value ${analysisResult.domain_metadata.metadata.dns.has_mx ? 'meta-good' : 'meta-warn'}`}>
                                    {analysisResult.domain_metadata.metadata.dns.has_mx ? 'Yes' : 'No MX'}
                                </span>
                            </div>
                        )}

                        {/* DMARC */}
                        {analysisResult.domain_metadata?.metadata?.dns?.has_dmarc !== undefined && (
                            <div className="intel-item">
                                <span className="intel-label">DMARC</span>
                                <span className={`intel-value ${analysisResult.domain_metadata.metadata.dns.has_dmarc ? 'meta-good' : 'meta-warn'}`}>
                                    {analysisResult.domain_metadata.metadata.dns.has_dmarc ? 'Protected' : 'None'}
                                </span>
                            </div>
                        )}

                        {/* Registrar */}
                        {analysisResult.domain_metadata?.metadata?.whois?.registrar && (
                            <div className="intel-item">
                                <span className="intel-label">Registrar</span>
                                <span className="intel-value meta-neutral">{analysisResult.domain_metadata.metadata.whois.registrar}</span>
                            </div>
                        )}

                        {/* Cloaking */}
                        {analysisResult.cloaking && (
                            <div className="intel-item">
                                <span className="intel-label">Cloaking</span>
                                <span className={`intel-value ${analysisResult.cloaking.detected ? 'meta-danger' : 'meta-good'}`}>
                                    {analysisResult.cloaking.detected
                                        ? `Detected (${Math.round(analysisResult.cloaking.risk * 100)}% risk)`
                                        : 'None detected'}
                                </span>
                            </div>
                        )}

                        {/* Domain risk score from metadata */}
                        {analysisResult.domain_metadata?.risk_score !== undefined && (
                            <div className="intel-item">
                                <span className="intel-label">Domain Risk</span>
                                {(() => {
                                    const pct = Math.round(analysisResult.domain_metadata.risk_score * 100);
                                    const cls = pct >= 60 ? 'meta-danger' : pct >= 35 ? 'meta-warn' : 'meta-good';
                                    return <span className={`intel-value ${cls}`}>{pct}%</span>;
                                })()}
                            </div>
                        )}
                    </div>

                    {/* Domain risk factors (if suspicious) */}
                    {analysisResult.domain_metadata?.risk_factors?.length > 0 && analysisResult.domain_metadata.is_suspicious && (
                        <details className="intel-details">
                            <summary>Domain Risk Factors ({analysisResult.domain_metadata.risk_factors.length})</summary>
                            <ul className="risk-factors-simple">
                                {analysisResult.domain_metadata.risk_factors.map((f, i) => <li key={i}>{f}</li>)}
                            </ul>
                        </details>
                    )}

                    {/* Cloaking evidence */}
                    {analysisResult.cloaking?.detected && analysisResult.cloaking.evidence?.length > 0 && (
                        <details className="intel-details">
                            <summary>Cloaking Evidence</summary>
                            <ul className="risk-factors-simple" style={{ color: '#ef9a9a' }}>
                                {analysisResult.cloaking.evidence.map((e, i) => <li key={i}>{e}</li>)}
                            </ul>
                        </details>
                    )}
                </div>
            )}

            {/* ── Technical Details (Collapsible) ────────────────── */}
            <details className="technical-details">
                <summary>Technical Details</summary>
                <div className="technical-content">
                    {/* Basic model info */}
                    <div className="detail-row"><span className="detail-label">Analyzed:</span><span className="detail-value">{new Date(analysisResult.timestamp).toLocaleString()}</span></div>
                    <div className="detail-row"><span className="detail-label">Models:</span><span className="detail-value">{analysisResult.model_info?.models_used} ({analysisResult.model_info?.model_names?.join(', ')})</span></div>
                    <div className="detail-row"><span className="detail-label">F1-Score:</span><span className="detail-value">{(analysisResult.model_info?.f1_score * 100).toFixed(1)}%</span></div>
                    <div className="detail-row"><span className="detail-label">Threshold:</span><span className="detail-value">{analysisResult.threshold_used}</span></div>

                    {/* Model voting */}
                    {hasMLData && analysisResult.ensemble?.individual_probabilities && (
                        <div style={{ marginTop: '1rem' }}>
                            <p style={{ fontWeight: 600, marginBottom: '8px', color: '#aaa', fontSize: '0.82rem', textTransform: 'uppercase' }}>Model Votes</p>
                            <div className="model-grid">
                                {Object.entries(analysisResult.ensemble.individual_probabilities).map(([model, prob]) => {
                                    const prediction = analysisResult.ensemble?.individual_predictions?.[model];
                                    return (
                                        <div key={model} className="model-item">
                                            <div className="model-name">{formatModelName(model)}</div>
                                            <div className="model-prediction">
                                                <div className="model-bar">
                                                    <div className="model-bar-fill" style={{ width: `${prob * 100}%`, background: prob >= 0.5 ? '#ef5350' : '#66bb6a' }} />
                                                </div>
                                                <span className={`model-verdict ${prediction === 1 ? 'phishing' : 'legitimate'}`}>{(prob * 100).toFixed(1)}%</span>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    )}

                    {/* SHAP feature importance */}
                    {hasMLData && analysisResult.shap_explanation?.top_features?.length > 0 && (
                        <div style={{ marginTop: '1rem' }}>
                            {analysisResult.shap_explanation.overridden && (
                                <div style={{
                                    background: 'rgba(99, 102, 241, 0.12)',
                                    border: '1px solid rgba(99, 102, 241, 0.35)',
                                    borderRadius: '6px',
                                    padding: '0.6rem 0.9rem',
                                    marginBottom: '0.75rem',
                                    fontSize: '0.82rem',
                                    color: '#a5b4fc',
                                    lineHeight: 1.5,
                                }}>
                                    <strong style={{ color: '#c7d2fe' }}>Note:</strong>{' '}
                                    {analysisResult.shap_explanation.override_reason}
                                </div>
                            )}
                            <p style={{ fontWeight: 600, marginBottom: '8px', color: '#aaa', fontSize: '0.82rem', textTransform: 'uppercase' }}>
                                Top AI Features ({analysisResult.shap_explanation.models_averaged} models averaged)
                            </p>
                            <div className="shap-chart">
                                {(() => {
                                    const maxAbs = Math.max(...analysisResult.shap_explanation.top_features.map(f => Math.abs(f.shap_value)));
                                    return analysisResult.shap_explanation.top_features.slice(0, 7).map((item, idx) => {
                                        const pct = maxAbs > 0 ? (Math.abs(item.shap_value) / maxAbs * 100).toFixed(1) : 0;
                                        return (
                                            <div key={idx} className="shap-row">
                                                <span className="shap-feature-name">{formatFeatureName(item.feature)}</span>
                                                <div className="shap-bar-wrap"><div className={`shap-bar shap-${item.direction}`} style={{ width: `${pct}%` }} /></div>
                                                <span className={`shap-val shap-${item.direction}`}>{item.shap_value > 0 ? '+' : ''}{item.shap_value.toFixed(3)}</span>
                                            </div>
                                        );
                                    });
                                })()}
                            </div>
                            <div className="shap-legend">
                                <span className="shap-legend-phishing">■</span> Phishing &nbsp;
                                <span className="shap-legend-legit">■</span> Legitimate
                            </div>
                        </div>
                    )}
                </div>
            </details>

            {/* Action Buttons */}
            <div className="action-buttons">
                <button onClick={() => navigate('/')} className="btn-primary-large">
                    Analyze Another URL
                </button>
                <button
                    onClick={() => {
                        const resultText = `
Phishing Analysis Report
========================
URL: ${analysisResult.url}
Prediction: ${analysisResult.prediction}
Confidence: ${analysisResult.confidence}%
Risk Level: ${analysisResult.risk_level}
Safe to Visit: ${analysisResult.safe_to_visit ? 'Yes' : 'No'}

Risk Factors:
${analysisResult.boost_reasons?.join('\n') || 'None detected'}

Generated: ${new Date().toLocaleString()}
                        `.trim();

                        navigator.clipboard.writeText(resultText);
                        alert('Results copied to clipboard!');
                    }}
                    className="btn-secondary-large"
                >
                    Copy Report
                </button>
                {!isPhishing && (
                    <button onClick={handleReport} className="btn-report-large">
                        Report as Phishing
                    </button>
                )}
            </div>
        </div>
    );
};

// Helper Functions
const getRiskColor = (confidence) => {
    if (confidence > 85) return '#c62828';
    if (confidence > 65) return '#f57c00';
    if (confidence > 45) return '#fbc02d';
    if (confidence > 20) return '#7cb342';
    return '#43a047';
};

const formatModelName = (model) => {
    return model
        .split('_')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
};

const formatFeatureName = (name) => {
    const map = {
        // UCI WebsitePhishing features (9 raw)
        SFH:               'Server Form Handler',
        popUpWidnow:       'Popup Windows',
        SSLfinal_State:    'HTTPS / SSL Certificate',
        Request_URL:       'External Resource URLs',
        URL_of_Anchor:     'Anchor Link Ratio',
        web_traffic:       'Web Traffic Rank',
        URL_Length:        'URL Length',
        age_of_domain:     'Domain Age',
        having_IP_Address: 'IP Address in Domain',
        // UCI engineered features (7)
        PhishingSignalCount: 'Phishing Signal Count',
        LegitSignalCount:    'Legitimate Signal Count',
        NetScore:            'Net Signal Score',
        PhishingSignalRatio: 'Phishing Signal Ratio',
        NoSSL_HasIP:         'No SSL + IP Address',
        BadSFH_BadSSL:       'Bad Form + No SSL',
        YoungDomain_NoSSL:   'New Domain + No SSL',
        // Realistic model features
        IsHTTPS:                  'HTTPS Enabled',
        IsDomainIP:               'IP-based Domain',
        HasObfuscation:           'URL Obfuscation',
        DomainLength:             'Domain Length',
        URLLength:                'URL Length',
        HasExternalFormSubmit:    'External Form Submit',
        HasPasswordField:         'Password Field',
        HasTitle:                 'Page Title Present',
        HasFavicon:               'Favicon Present',
        LegitContentScore:        'Legit Content Score',
        SuspiciousFinancialFlag:  'Suspicious Financial Keywords',
        InsecurePasswordField:    'Insecure Password Field',
    };
    return map[name] || name.replace(/_/g, ' ');
};

const renderFeature = (label, value, unit = '') => {
    const displayValue = value !== undefined && value !== null ? `${value}${unit ? ' ' + unit : ''}` : 'N/A';
    
    return (
        <div className="feature-item">
            <span className="feature-label">{label}</span>
            <span className="feature-value">{displayValue}</span>
        </div>
    );
};

export default Result;
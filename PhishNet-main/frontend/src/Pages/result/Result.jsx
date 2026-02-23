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
import React, { useEffect, useState, useContext } from 'react';
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
    const [userInfo, setUserInfo] = useState(null);

    useEffect(() => {
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
                        timeout: 30000
                    }
                );

                if (response.data.success) {
                    setAnalysisResult(response.data.data);
                    setUserInfo(response.data.userInfo);

                    // ✅ Update scan statistics
                    await fetchScanStatistics();

                    // ✅ Warn if approaching limit
                    if (response.data.userInfo.remainingScans <= 5 && !response.data.userInfo.isPremium) {
                        console.warn(`⚠️ Only ${response.data.userInfo.remainingScans} scans remaining today!`);
                    }
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

    return (
        <div className="result-container">
            {/* Header Section */}
            <div className="result-header">
                <button onClick={() => navigate('/')} className="back-button">
                    ← Back
                </button>
                <h1>Analysis Results</h1>
            </div>

            {/* Scan Info Banner */}
            {userInfo && (
                <div className="scan-info-banner">
                    <div className="scan-info-content">
                        <span className="scan-info-text">
                            ✅ Scan successful! {userInfo.remainingScans} of {userInfo.isPremium ? 1000 : 50} scans remaining today
                        </span>
                        {!userInfo.isPremium && userInfo.remainingScans <= 10 && (
                            <a href="/getpremium" className="upgrade-link-inline">
                                Upgrade to Premium →
                            </a>
                        )}
                    </div>
                </div>
            )}

            {/* Main Result Card */}
            <div className={`main-result-card ${isPhishing ? 'phishing' : 'legitimate'}`}>
                <div className="result-icon">
                    {analysisResult.risk_emoji || (isPhishing ? '🔴' : '✅')}
                </div>
                <h2 className="result-prediction">{analysisResult.prediction}</h2>
                <div className="confidence-badge" style={{ 
                    background: isPhishing ? '#ffebee' : '#e8f5e9',
                    color: isPhishing ? '#c62828' : '#2e7d32'
                }}>
                    {analysisResult.confidence}% Confidence
                </div>
                <p className="url-analyzed">
                    <strong>URL:</strong> {analysisResult.url}
                </p>
                <p className="domain-analyzed">
                    <strong>Domain:</strong> {analysisResult.domain}
                </p>
            </div>

            {/* Risk Level Card */}
            <div className="risk-level-card">
                <h3>Risk Assessment</h3>
                <div className="risk-indicator">
                    <div className="risk-bar-container">
                        <div 
                            className="risk-bar-fill" 
                            style={{ 
                                width: `${analysisResult.confidence}%`,
                                background: getRiskColor(analysisResult.confidence)
                            }}
                        ></div>
                    </div>
                    <div className="risk-details">
                        <span className="risk-level">
                            {analysisResult.risk_emoji} {analysisResult.risk_level} Risk
                        </span>
                        <span className="risk-percentage">
                            {analysisResult.confidence}%
                        </span>
                    </div>
                </div>
                <div className={`safety-verdict ${analysisResult.safe_to_visit ? 'safe' : 'unsafe'}`}>
                    {analysisResult.safe_to_visit ? (
                        <>
                            <span className="verdict-icon">✅</span>
                            <span>Safe to Visit</span>
                        </>
                    ) : (
                        <>
                            <span className="verdict-icon">⛔</span>
                            <span>Do Not Visit</span>
                        </>
                    )}
                </div>
            </div>

            {/* Trusted Domain Badge */}
            {isTrusted && (
                <div className="trusted-badge-card">
                    <span className="shield-icon">🛡️</span>
                    <div>
                        <h4>Trusted Domain</h4>
                        <p>This domain is in our verified whitelist</p>
                    </div>
                </div>
            )}

            {/* Risk Factors Card */}
            {analysisResult.boost_reasons && analysisResult.boost_reasons.length > 0 && (
                <div className="risk-factors-card">
                    <h3>⚠️ Risk Factors Detected</h3>
                    <div className="risk-factors-list">
                        {analysisResult.boost_reasons.map((reason, index) => (
                            <div key={index} className="risk-factor-item">
                                <span className="factor-bullet">•</span>
                                <span className="factor-text">{reason}</span>
                            </div>
                        ))}
                    </div>
                    {analysisResult.risk_boost > 0 && (
                        <div className="boost-info">
                            <p>Risk score boosted by <strong>{(analysisResult.risk_boost * 100).toFixed(1)}%</strong> due to these factors</p>
                        </div>
                    )}
                </div>
            )}

            {/* Model Consensus */}
            <div className="model-consensus-card">
                <h3>AI Model Analysis</h3>
                <div className="consensus-summary">
                    <div className="consensus-item">
                        <span className="consensus-label">Models Agreement:</span>
                        <span className="consensus-value">{analysisResult.ensemble?.agreement}</span>
                    </div>
                    <div className="consensus-item">
                        <span className="consensus-label">Base Probability:</span>
                        <span className="consensus-value">{(analysisResult.base_probability * 100).toFixed(2)}%</span>
                    </div>
                </div>
                
                {/* Individual Model Results */}
                <div className="model-results">
                    <h4>Individual Model Predictions</h4>
                    <div className="model-grid">
                        {Object.entries(analysisResult.ensemble?.individual_probabilities || {}).map(([model, prob]) => {
                            const prediction = analysisResult.ensemble?.individual_predictions?.[model];
                            return (
                                <div key={model} className="model-item">
                                    <div className="model-name">{formatModelName(model)}</div>
                                    <div className="model-prediction">
                                        <div className="model-bar">
                                            <div 
                                                className="model-bar-fill"
                                                style={{ 
                                                    width: `${prob * 100}%`,
                                                    background: prob >= 0.5 ? '#ef5350' : '#66bb6a'
                                                }}
                                            ></div>
                                        </div>
                                        <span className={`model-verdict ${prediction === 1 ? 'phishing' : 'legitimate'}`}>
                                            {(prob * 100).toFixed(1)}%
                                        </span>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>
            </div>

            {/* Analysis Summary - WHY it's phishing or legitimate */}
            <div className="analysis-summary-card">
                <h3>📋 Analysis Summary</h3>
                <div className="summary-content">
                    <p className="summary-verdict">
                        {isPhishing ? (
                            <>
                                <strong>⚠️ This URL exhibits phishing characteristics.</strong> Our AI models detected
                                suspicious patterns commonly used in phishing attacks.
                            </>
                        ) : (
                            <>
                                <strong>✅ This URL appears legitimate.</strong> Our analysis found typical characteristics
                                of a safe website with no significant red flags.
                            </>
                        )}
                    </p>

                    {/* Key Factors */}
                    <div className="key-factors">
                        <h4>🔍 Key Factors in This Decision:</h4>
                        <div className="factors-grid">
                            {/* Security Indicators */}
                            <div className="factor-category">
                                <h5>🔒 Security</h5>
                                <ul>
                                    <li className={analysisResult.features?.IsHTTPS ? 'positive' : 'negative'}>
                                        {analysisResult.features?.IsHTTPS ? '✅' : '❌'}
                                        {analysisResult.features?.IsHTTPS ? ' Secure HTTPS connection' : ' No HTTPS encryption'}
                                    </li>
                                    <li className={!analysisResult.features?.IsDomainIP ? 'positive' : 'negative'}>
                                        {!analysisResult.features?.IsDomainIP ? '✅' : '⚠️'}
                                        {!analysisResult.features?.IsDomainIP ? ' Domain name (not IP)' : ' Uses IP address instead of domain'}
                                    </li>
                                    <li className={!analysisResult.features?.HasObfuscation ? 'positive' : 'negative'}>
                                        {!analysisResult.features?.HasObfuscation ? '✅' : '⚠️'}
                                        {!analysisResult.features?.HasObfuscation ? ' No URL obfuscation' : ` URL obfuscation detected (${analysisResult.features?.NoOfObfuscatedChar} chars)`}
                                    </li>
                                </ul>
                            </div>

                            {/* Content Quality */}
                            <div className="factor-category">
                                <h5>📄 Content Quality</h5>
                                <ul>
                                    <li className={analysisResult.features?.HasTitle ? 'positive' : 'neutral'}>
                                        {analysisResult.features?.HasTitle ? '✅' : '➖'}
                                        {analysisResult.features?.HasTitle ? ' Page has title' : ' No page title'}
                                    </li>
                                    <li className={analysisResult.features?.HasCopyrightInfo ? 'positive' : 'neutral'}>
                                        {analysisResult.features?.HasCopyrightInfo ? '✅' : '➖'}
                                        {analysisResult.features?.HasCopyrightInfo ? ' Copyright information present' : ' No copyright info'}
                                    </li>
                                    <li className={analysisResult.features?.HasFavicon ? 'positive' : 'neutral'}>
                                        {analysisResult.features?.HasFavicon ? '✅' : '➖'}
                                        {analysisResult.features?.HasFavicon ? ' Has favicon' : ' No favicon'}
                                    </li>
                                    <li className="info">
                                        📊 Legitimacy Score: {analysisResult.features?.LegitContentScore || 0}/5
                                    </li>
                                </ul>
                            </div>

                            {/* Risk Indicators */}
                            <div className="factor-category">
                                <h5>⚠️ Risk Indicators</h5>
                                <ul>
                                    <li className={!analysisResult.features?.HasExternalFormSubmit ? 'positive' : 'negative'}>
                                        {!analysisResult.features?.HasExternalFormSubmit ? '✅' : '⚠️'}
                                        {!analysisResult.features?.HasExternalFormSubmit ? ' No external form submission' : ' Form submits to external domain'}
                                    </li>
                                    <li className={!analysisResult.features?.InsecurePasswordField ? 'positive' : 'negative'}>
                                        {!analysisResult.features?.InsecurePasswordField ? '✅' : '🔴'}
                                        {!analysisResult.features?.InsecurePasswordField ? ' No insecure password fields' : ' Password field on non-HTTPS page!'}
                                    </li>
                                    <li className={analysisResult.features?.NoOfPopup === 0 ? 'positive' : 'neutral'}>
                                        {analysisResult.features?.NoOfPopup === 0 ? '✅' : '⚠️'}
                                        {analysisResult.features?.NoOfPopup === 0 ? ' No popups detected' : ` ${analysisResult.features?.NoOfPopup} popup(s) detected`}
                                    </li>
                                    <li className={analysisResult.features?.SuspiciousFinancialFlag === 0 ? 'positive' : 'negative'}>
                                        {analysisResult.features?.SuspiciousFinancialFlag === 0 ? '✅' : '🔴'}
                                        {analysisResult.features?.SuspiciousFinancialFlag === 0 ? ' No suspicious financial keywords' : ' Financial keywords without legitimacy markers'}
                                    </li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* URL Characteristics */}
            <div className="features-card">
                <h3>🔗 URL Characteristics</h3>
                <div className="features-grid">
                    {renderFeature('URL Length', analysisResult.features?.URLLength, 'chars')}
                    {renderFeature('Domain Length', analysisResult.features?.DomainLength, 'chars')}
                    {renderFeature('Subdomains', analysisResult.features?.NoOfSubDomain)}
                    {renderFeature('TLD', analysisResult.features?.TLDLength + ' chars')}
                    {renderFeature('Letter Ratio', (analysisResult.features?.LetterRatioInURL * 100)?.toFixed(0) + '%')}
                    {renderFeature('Digit Ratio', (analysisResult.features?.DegitRatioInURL * 100)?.toFixed(0) + '%')}
                    {renderFeature('Special Chars', analysisResult.features?.NoOfOtherSpecialCharsInURL)}
                    {renderFeature('HTTPS', analysisResult.features?.IsHTTPS ? '✅ Yes' : '❌ No')}
                    {renderFeature('IP Address', analysisResult.features?.IsDomainIP ? '⚠️ Yes' : '✅ No')}
                </div>
            </div>

            {/* Page Content Features */}
            <div className="features-card">
                <h3>📄 Page Content Analysis</h3>
                <div className="features-grid">
                    {renderFeature('Lines of Code', analysisResult.features?.LineOfCode)}
                    {renderFeature('Images', analysisResult.features?.NoOfImage)}
                    {renderFeature('CSS Files', analysisResult.features?.NoOfCSS)}
                    {renderFeature('JavaScript Files', analysisResult.features?.NoOfJS)}
                    {renderFeature('External References', analysisResult.features?.NoOfExternalRef)}
                    {renderFeature('Self References', analysisResult.features?.NoOfSelfRef)}
                    {renderFeature('Redirects', analysisResult.features?.NoOfURLRedirect)}
                    {renderFeature('iFrames', analysisResult.features?.NoOfiFrame)}
                    {renderFeature('Popups', analysisResult.features?.NoOfPopup)}
                </div>
            </div>

            {/* Technical Details (Collapsible) */}
            <details className="technical-details">
                <summary>🔧 Technical Details</summary>
                <div className="technical-content">
                    <div className="detail-row">
                        <span className="detail-label">Detection Method:</span>
                        <span className="detail-value">{analysisResult.model_info?.detection_method}</span>
                    </div>
                    <div className="detail-row">
                        <span className="detail-label">Models Used:</span>
                        <span className="detail-value">{analysisResult.model_info?.models_used}</span>
                    </div>
                    <div className="detail-row">
                        <span className="detail-label">Model F1-Score:</span>
                        <span className="detail-value">{(analysisResult.model_info?.f1_score * 100).toFixed(1)}%</span>
                    </div>
                    <div className="detail-row">
                        <span className="detail-label">Threshold:</span>
                        <span className="detail-value">{analysisResult.threshold_used}</span>
                    </div>
                    <div className="detail-row">
                        <span className="detail-label">Analyzed:</span>
                        <span className="detail-value">{new Date(analysisResult.timestamp).toLocaleString()}</span>
                    </div>
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
                    📋 Copy Report
                </button>
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
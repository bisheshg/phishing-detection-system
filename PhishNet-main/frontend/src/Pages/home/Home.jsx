import React, { useState, useContext } from 'react';
import male from './male.png';
import { useNavigate, Link } from 'react-router-dom';
import { UserContext } from '../../context/UserContext';
import './App.css';

const GRADIENT_COLORS = ['#67E0DD', '#A6D8DF', '#C5E8E2', '#94BBDF', '#DBDAE0', '#FAE8E1'];
const SCAN_STEPS = ['Initiating scan...', 'Analyzing domain...', 'Finalizing results...'];
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const App = () => {
  const [inputUrl, setInputUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanMessages, setScanMessages] = useState([]);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');

  const navigate = useNavigate();
  const { isLoggedIn, scanStats } = useContext(UserContext);

  const handleScan = async () => {
    const trimmed = inputUrl.trim();
    if (!trimmed) { setError('Please enter a URL to scan.'); return; }
    if (!trimmed.includes('.')) { setError('Please enter a valid URL (e.g. example.com).'); return; }
    if (isLoggedIn && scanStats.remainingScans === 0) {
      setError(`Daily scan limit reached (${scanStats.dailyLimit}/day). ${!scanStats.isPremium ? 'Upgrade to Premium for 1000 scans/day.' : 'Try again tomorrow.'}`);
      return;
    }
    setError('');
    setScanning(true);
    setScanMessages([]);
    setProgress(0);
    for (let i = 0; i < SCAN_STEPS.length; i++) {
      await delay(700);
      setScanMessages((prev) => [...prev, SCAN_STEPS[i]]);
      setProgress(((i + 1) / SCAN_STEPS.length) * 100);
    }
    await delay(400);
    setScanning(false);
    navigate('/results', { state: { inputUrl: trimmed } });
  };

  const handleKeyDown = (e) => { if (e.key === 'Enter' && !scanning) handleScan(); };

  const usedToday = scanStats.dailyLimit - scanStats.remainingScans;
  const usedPct = scanStats.dailyLimit > 0 ? (usedToday / scanStats.dailyLimit) * 100 : 0;

  return (
    <div className="app-gradient" style={{ background: `linear-gradient(to right, ${GRADIENT_COLORS.join(',')})` }}>
      <div className="bg-overlay" />
      <div className="scan-card animate-fade-in" aria-busy={scanning}>
        <h2 className="scan-title">SECURE YOUR BROWSING</h2>
        <p className="scan-subtitle">PhishNet — Your Shield Against Phishing Threats in Real-Time.</p>

        {isLoggedIn && (
          <div className="quota-bar-wrap">
            <div className="quota-bar-label">
              <span>Daily Scans Used</span>
              <span>{usedToday} / {scanStats.dailyLimit}</span>
            </div>
            <div className="quota-bar-bg">
              <div className="quota-bar-fill" style={{
                width: `${usedPct}%`,
                background: usedPct >= 100 ? '#ef4444' : usedPct > 80 ? '#f59e0b' : '#6366f1',
              }} />
            </div>
            {!scanStats.isPremium && scanStats.remainingScans < 10 && (
              <p className="quota-warning">
                Only {scanStats.remainingScans} scan{scanStats.remainingScans !== 1 ? 's' : ''} left today.{' '}
                <Link to="/getpremium" className="upgrade-link">Upgrade to Premium →</Link>
              </p>
            )}
          </div>
        )}

        {error && <div className="scan-error animate-fade-in">⚠ {error}</div>}

        <div className="scan-input-container">
          <input
            type="text"
            placeholder="Enter URL to scan (e.g. https://example.com)"
            className={`scan-input${error ? ' input-error' : ''}`}
            value={inputUrl}
            onChange={(e) => { setInputUrl(e.target.value); if (error) setError(''); }}
            onKeyDown={handleKeyDown}
            disabled={scanning}
            aria-label="URL to scan"
          />
          <button onClick={handleScan} className={`scan-btn${scanning ? ' scanning' : ''}`} disabled={scanning}>
            {scanning ? 'Scanning...' : 'Scan'}
          </button>
        </div>

        {scanning && (
          <div className="scan-messages">
            {scanMessages.map((msg, i) => (
              <div key={i} className="scan-message animate-fade-in">✓ {msg}</div>
            ))}
          </div>
        )}

        <div className="progress-bar-container">
          <div className="progress-bar" style={{ width: `${progress}%` }} />
        </div>

        {!isLoggedIn && (
          <p className="login-prompt">
            <Link to="/login" className="upgrade-link">Sign in</Link> to track history and get 50 free scans/day.
          </p>
        )}

        <div className="scan-image-container">
          <img src={male} alt="Cyber Guard" className="scan-image" />
        </div>
      </div>
    </div>
  );
};

export default App;

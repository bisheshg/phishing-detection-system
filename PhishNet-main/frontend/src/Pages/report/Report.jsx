import React, { useState, useContext } from 'react';
import './Report.css';
import axios from 'axios';
import { UserContext } from '../../context/UserContext';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faExclamationTriangle,
  faCheckCircle,
  faSpinner,
  faShieldAlt,
} from '@fortawesome/free-solid-svg-icons';

const GRADIENT_COLORS = ['#67E0DD', '#A6D8DF', '#C5E8E2', '#94BBDF', '#DBDAE0', '#FAE8E1'];

const Report = () => {
  const { userr } = useContext(UserContext);

  const [url, setUrl] = useState('');
  const [evidence, setEvidence] = useState('');
  const [targetBrand, setTargetBrand] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(null);
  const [error, setError] = useState(null);
  const [showConfirm, setShowConfirm] = useState(false);

  const gradientStyle = {
    background: `linear-gradient(to right, ${GRADIENT_COLORS.join(',')})`,
    minHeight: '80vh',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    padding: '2rem',
  };

  const validate = () => {
    if (!url.trim()) { setError('Please enter the suspected phishing URL.'); return false; }
    if (!url.includes('.')) { setError('Please enter a valid URL.'); return false; }
    if (!evidence.trim()) { setError('Please describe why this URL is suspicious.'); return false; }
    return true;
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    if (!validate()) return;
    setShowConfirm(true);
  };

  const handleConfirm = async () => {
    setShowConfirm(false);
    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const res = await axios.post(
        'http://localhost:8800/api/phishing/report',
        {
          url: url.trim(),
          evidence: evidence.trim(),
          ...(targetBrand.trim() && { targetBrand: targetBrand.trim() }),
        },
        { withCredentials: true }
      );

      if (res.data.success) {
        setSuccess(res.data.message || 'Report submitted! Thank you for helping keep the web safe.');
        setUrl('');
        setEvidence('');
        setTargetBrand('');
      } else {
        setError(res.data.message || 'Failed to submit report. Please try again.');
      }
    } catch (err) {
      setError(err.response?.data?.message || err.response?.data?.error || 'Network error. Please check your connection.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={gradientStyle}>
      <div className="report-container">
        <h2>
          <FontAwesomeIcon icon={faShieldAlt} style={{ marginRight: 8, color: '#6366f1' }} />
          Report a Phishing URL
        </h2>
        <p style={{ color: '#555', marginBottom: '1.5rem', fontSize: '0.9rem' }}>
          Help protect the community by reporting suspicious URLs you've encountered.
        </p>

        {success && (
          <div className="feedback success-feedback">
            <FontAwesomeIcon icon={faCheckCircle} style={{ marginRight: 8 }} />
            {success}
          </div>
        )}

        {error && (
          <div className="feedback error-feedback">
            <FontAwesomeIcon icon={faExclamationTriangle} style={{ marginRight: 8 }} />
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="input-container">
            <label htmlFor="urlInput">Suspected Phishing URL *</label>
            <input
              type="text"
              id="urlInput"
              value={url}
              onChange={(e) => { setUrl(e.target.value); if (error) setError(null); }}
              placeholder="https://fake-bank-login.com/verify"
              disabled={loading}
            />
          </div>

          <div className="input-container">
            <label htmlFor="evidenceInput">Why is this suspicious? *</label>
            <textarea
              id="evidenceInput"
              value={evidence}
              onChange={(e) => setEvidence(e.target.value)}
              placeholder="Describe the suspicious behaviour (e.g., fake login page mimicking PayPal, asks for credit card details...)"
              rows={4}
              disabled={loading}
            />
          </div>

          <div className="input-container">
            <label htmlFor="brandInput">Target Brand (optional)</label>
            <input
              type="text"
              id="brandInput"
              value={targetBrand}
              onChange={(e) => setTargetBrand(e.target.value)}
              placeholder="e.g., PayPal, Netflix, HDFC Bank"
              disabled={loading}
            />
          </div>

          <button className="submit-button" type="submit" disabled={loading}>
            {loading
              ? <><FontAwesomeIcon icon={faSpinner} spin style={{ marginRight: 8 }} />Submitting...</>
              : 'Submit Report'}
          </button>
        </form>

        {showConfirm && (
          <div className="confirmation-dialog">
            <p>Report <strong style={{ wordBreak: 'break-all' }}>{url}</strong> as phishing?</p>
            <button className="confirm-button" onClick={handleConfirm}>Yes, Report It</button>
            <button className="cancel-button" onClick={() => setShowConfirm(false)}>Cancel</button>
          </div>
        )}
      </div>
    </div>
  );
};

export default Report;

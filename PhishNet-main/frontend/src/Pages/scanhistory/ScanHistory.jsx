import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faSearch, faTrash, faExclamationTriangle,
  faCheckCircle, faArrowLeft, faInbox,
} from '@fortawesome/free-solid-svg-icons';
import './ScanHistory.css';

const API = 'http://localhost:8800/api';

const RISK_CLASS = {
  Critical: 'risk-critical', High: 'risk-high',
  Medium: 'risk-medium', Low: 'risk-low', Safe: 'risk-safe',
};

const ScanHistory = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(null); // scan._id to confirm

  useEffect(() => { fetchHistory(); }, [page]);

  const fetchHistory = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await axios.get(
        `${API}/phishing/history?page=${page}&limit=20`,
        { withCredentials: true }
      );
      if (res.data.success) {
        setScans(res.data.data);
        setTotalPages(res.data.pagination.pages);
        setTotal(res.data.pagination.total);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load scan history.');
      if (err.response?.status === 401) navigate('/login');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteConfirmed = async () => {
    const id = confirmDelete;
    setConfirmDelete(null);
    try {
      await axios.delete(`${API}/phishing/${id}`, { withCredentials: true });
      setScans((prev) => prev.filter((s) => s._id !== id));
      setTotal((t) => t - 1);
    } catch {
      setError('Failed to delete scan. Please try again.');
    }
  };

  const filtered = search
    ? scans.filter(
        (s) =>
          (s.url || '').toLowerCase().includes(search.toLowerCase()) ||
          (s.domain || '').toLowerCase().includes(search.toLowerCase())
      )
    : scans;

  return (
    <div className="scan-history-container">
      {/* Header */}
      <div className="history-header">
        <div>
          <h1>📜 Scan History</h1>
          {total > 0 && (
            <p style={{ margin: 0, color: '#6b7280', fontSize: '0.9rem' }}>
              {total} total scan{total !== 1 ? 's' : ''}
            </p>
          )}
        </div>
        <button onClick={() => navigate('/')} className="back-home-btn">
          <FontAwesomeIcon icon={faArrowLeft} /> Back to Home
        </button>
      </div>

      {/* Search */}
      {scans.length > 0 && (
        <div className="history-search-wrap">
          <FontAwesomeIcon icon={faSearch} className="history-search-icon" />
          <input
            type="text"
            className="history-search-input"
            placeholder="Filter by URL or domain..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button className="history-search-clear" onClick={() => setSearch('')}>✕</button>
          )}
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="loading">Loading scan history...</div>
      )}

      {/* Error */}
      {!loading && error && (
        <div className="error-message">{error}</div>
      )}

      {/* Empty */}
      {!loading && !error && filtered.length === 0 && (
        <div className="empty-state">
          <div className="empty-icon">
            <FontAwesomeIcon icon={faInbox} style={{ fontSize: '3rem', color: '#d1d5db' }} />
          </div>
          <h2>{scans.length === 0 ? 'No Scan History' : 'No matches found'}</h2>
          <p>
            {scans.length === 0
              ? 'Start scanning URLs to see your history here.'
              : 'Try a different search term.'}
          </p>
          {scans.length === 0 && (
            <button onClick={() => navigate('/')} className="scan-now-btn">
              Scan Your First URL
            </button>
          )}
        </div>
      )}

      {/* Table */}
      {!loading && !error && filtered.length > 0 && (
        <>
          <div className="scan-history-table">
            <table>
              <thead>
                <tr>
                  <th>Date & Time</th>
                  <th>URL</th>
                  <th>Domain</th>
                  <th>Result</th>
                  <th>Confidence</th>
                  <th>Risk Level</th>
                  <th>Delete</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((scan) => (
                  <tr key={scan._id}>
                    <td className="date-cell">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                    <td className="url-cell" title={scan.url}>
                      {scan.url.length > 50 ? scan.url.slice(0, 50) + '…' : scan.url}
                    </td>
                    <td className="domain-cell">{scan.domain}</td>
                    <td>
                      <span className={`badge ${scan.prediction === 'Phishing' ? 'phishing' : 'legitimate'}`}>
                        <FontAwesomeIcon
                          icon={scan.prediction === 'Phishing' ? faExclamationTriangle : faCheckCircle}
                          style={{ marginRight: 4 }}
                        />
                        {scan.prediction}
                      </span>
                    </td>
                    <td className="confidence-cell">{scan.confidence}%</td>
                    <td>
                      <span className={`risk-badge ${RISK_CLASS[scan.riskLevel] || ''}`}>
                        {scan.riskLevel}
                      </span>
                    </td>
                    <td>
                      {confirmDelete === scan._id ? (
                        <span className="confirm-delete-inline">
                          <button className="confirm-yes-btn" onClick={handleDeleteConfirmed}>Yes</button>
                          <button className="confirm-no-btn" onClick={() => setConfirmDelete(null)}>No</button>
                        </span>
                      ) : (
                        <button
                          onClick={() => setConfirmDelete(scan._id)}
                          className="delete-btn"
                          title="Delete scan"
                        >
                          <FontAwesomeIcon icon={faTrash} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="pagination">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="pagination-btn"
              >
                ← Previous
              </button>
              <span className="page-info">Page {page} of {totalPages}</span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="pagination-btn"
              >
                Next →
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default ScanHistory;

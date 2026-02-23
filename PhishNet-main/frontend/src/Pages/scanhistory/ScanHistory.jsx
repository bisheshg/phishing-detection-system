import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import './ScanHistory.css';

const ScanHistory = () => {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchScanHistory();
  }, [page]);

  const fetchScanHistory = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await axios.get(
        `http://localhost:8800/api/phishing/history?page=${page}&limit=20`,
        { withCredentials: true }
      );

      if (response.data.success) {
        setScans(response.data.data);
        setTotalPages(response.data.pagination.pages);
      }
    } catch (error) {
      console.error('Error fetching scan history:', error);
      setError(error.response?.data?.message || 'Failed to load scan history');

      if (error.response?.status === 401) {
        navigate('/login');
      }
    } finally {
      setLoading(false);
    }
  };

  const deleteScan = async (scanId) => {
    if (!window.confirm('Delete this scan from history?')) return;

    try {
      await axios.delete(
        `http://localhost:8800/api/phishing/${scanId}`,
        { withCredentials: true }
      );

      // Refresh list
      fetchScanHistory();
    } catch (error) {
      console.error('Error deleting scan:', error);
      alert('Failed to delete scan');
    }
  };

  if (loading) {
    return (
      <div className="scan-history-container">
        <div className="loading">Loading scan history...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="scan-history-container">
        <div className="error-message">{error}</div>
      </div>
    );
  }

  return (
    <div className="scan-history-container">
      <div className="history-header">
        <h1>📜 Scan History</h1>
        <button onClick={() => navigate('/')} className="back-home-btn">
          ← Back to Home
        </button>
      </div>

      {scans.length === 0 ? (
        <div className="empty-state">
          <div className="empty-icon">🔍</div>
          <h2>No Scan History</h2>
          <p>Start scanning URLs to see your history here</p>
          <button onClick={() => navigate('/')} className="scan-now-btn">
            Scan Your First URL
          </button>
        </div>
      ) : (
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
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr key={scan._id}>
                    <td className="date-cell">
                      {new Date(scan.createdAt).toLocaleString()}
                    </td>
                    <td className="url-cell" title={scan.url}>
                      {scan.url.length > 50 ? scan.url.substring(0, 50) + '...' : scan.url}
                    </td>
                    <td className="domain-cell">{scan.domain}</td>
                    <td>
                      <span className={`badge ${scan.prediction === 'Phishing' ? 'phishing' : 'legitimate'}`}>
                        {scan.prediction}
                      </span>
                    </td>
                    <td className="confidence-cell">{scan.confidence}%</td>
                    <td>
                      <span className={`risk-badge risk-${scan.riskLevel.toLowerCase()}`}>
                        {scan.riskLevel}
                      </span>
                    </td>
                    <td>
                      <button
                        onClick={() => deleteScan(scan._id)}
                        className="delete-btn"
                        title="Delete scan"
                      >
                        🗑️
                      </button>
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
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1}
                className="pagination-btn"
              >
                ← Previous
              </button>
              <span className="page-info">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
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

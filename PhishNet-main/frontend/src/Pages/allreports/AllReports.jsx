import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faExclamationTriangle,
  faCheckCircle,
  faSearch,
  faShieldAlt,
  faSyncAlt,
  faFilter,
  faInbox,
} from '@fortawesome/free-solid-svg-icons';
import './AllReports.css';

const API = 'http://localhost:8800/api';

const timeAgo = (d) => {
  const diff = Date.now() - new Date(d).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

const RISK_CLASS = {
  Critical: 'risk-critical',
  High: 'risk-high',
  Medium: 'risk-medium',
  Low: 'risk-low',
  Safe: 'risk-safe',
};

const AllReports = () => {
  const [scans, setScans] = useState([]);
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);

  useEffect(() => { fetchScans(); }, [page]);

  const fetchScans = async () => {
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
      setError('Failed to load reports. Make sure you are logged in and the backend is running.');
    } finally {
      setLoading(false);
    }
  };

  const filtered = scans.filter((s) => {
    const matchFilter =
      filter === 'all' || s.prediction.toLowerCase() === filter;
    const q = search.toLowerCase();
    const matchSearch =
      !q ||
      (s.url || '').toLowerCase().includes(q) ||
      (s.domain || '').toLowerCase().includes(q);
    return matchFilter && matchSearch;
  });

  const phishingCount = scans.filter((s) => s.prediction === 'Phishing').length;
  const legitCount = scans.filter((s) => s.prediction === 'Legitimate').length;

  return (
    <div className="allreports-container">
      {/* Header */}
      <div className="allreports-header">
        <div>
          <h1>
            <FontAwesomeIcon icon={faShieldAlt} className="header-icon" />
            Scan Reports
          </h1>
          <p className="header-sub">
            {total > 0 ? `${total} total scans across all pages` : 'Your URL analysis history'}
          </p>
        </div>
        <button onClick={fetchScans} className="refresh-btn" disabled={loading}>
          <FontAwesomeIcon icon={faSyncAlt} spin={loading} /> Refresh
        </button>
      </div>

      {/* Filter chips */}
      <div className="filter-row">
        <FontAwesomeIcon icon={faFilter} className="filter-icon" />
        <button
          className={`chip${filter === 'all' ? ' chip-active' : ''}`}
          onClick={() => { setFilter('all'); setPage(1); }}
        >
          All ({scans.length})
        </button>
        <button
          className={`chip chip-phishing${filter === 'phishing' ? ' chip-active' : ''}`}
          onClick={() => { setFilter('phishing'); setPage(1); }}
        >
          <FontAwesomeIcon icon={faExclamationTriangle} /> Phishing ({phishingCount})
        </button>
        <button
          className={`chip chip-legit${filter === 'legitimate' ? ' chip-active' : ''}`}
          onClick={() => { setFilter('legitimate'); setPage(1); }}
        >
          <FontAwesomeIcon icon={faCheckCircle} /> Legitimate ({legitCount})
        </button>
      </div>

      {/* Search */}
      <div className="search-wrap">
        <FontAwesomeIcon icon={faSearch} className="search-icon" />
        <input
          type="text"
          className="search-input"
          placeholder="Search by URL or domain..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        {search && (
          <button className="search-clear" onClick={() => setSearch('')}>✕</button>
        )}
      </div>

      {/* States */}
      {loading && (
        <div className="state-box">
          <div className="spinner-ring" />
          <span>Loading reports…</span>
        </div>
      )}

      {!loading && error && (
        <div className="state-box error-state">
          <FontAwesomeIcon icon={faExclamationTriangle} className="state-icon" />
          <p>{error}</p>
        </div>
      )}

      {!loading && !error && filtered.length === 0 && (
        <div className="state-box empty-state">
          <FontAwesomeIcon icon={faInbox} className="state-icon" />
          <h3>{scans.length === 0 ? 'No scans yet' : 'No matches found'}</h3>
          <p>
            {scans.length === 0
              ? 'Start scanning URLs to build your history.'
              : 'Try adjusting your filter or search term.'}
          </p>
          {scans.length === 0 && (
            <Link to="/" className="scan-link">Scan your first URL →</Link>
          )}
        </div>
      )}

      {/* Table */}
      {!loading && !error && filtered.length > 0 && (
        <div className="table-wrap">
          <table className="reports-table">
            <thead>
              <tr>
                <th>URL / Domain</th>
                <th>Result</th>
                <th>Confidence</th>
                <th>Risk</th>
                <th>Scanned</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((scan) => (
                <tr key={scan._id}>
                  <td className="url-td">
                    <div className="url-primary" title={scan.url}>
                      {scan.url.length > 60 ? scan.url.slice(0, 60) + '…' : scan.url}
                    </div>
                    {scan.domain && <div className="url-domain">{scan.domain}</div>}
                  </td>
                  <td>
                    <span className={`result-badge ${scan.prediction === 'Phishing' ? 'badge-phishing' : 'badge-legit'}`}>
                      <FontAwesomeIcon
                        icon={scan.prediction === 'Phishing' ? faExclamationTriangle : faCheckCircle}
                      />{' '}
                      {scan.prediction}
                    </span>
                  </td>
                  <td className="conf-td">{scan.confidence}%</td>
                  <td>
                    <span className={`risk-badge ${RISK_CLASS[scan.riskLevel] || ''}`}>
                      {scan.riskLevel || '—'}
                    </span>
                  </td>
                  <td className="time-td">{timeAgo(scan.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && !loading && (
        <div className="pagination">
          <button
            className="page-btn"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
          >
            ← Prev
          </button>
          <span className="page-info">Page {page} of {totalPages}</span>
          <button
            className="page-btn"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
};

export default AllReports;

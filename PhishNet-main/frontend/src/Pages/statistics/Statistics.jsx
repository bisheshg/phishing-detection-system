import React, { useState, useEffect, useContext } from 'react';
import { Link } from 'react-router-dom';
import { UserContext } from '../../context/UserContext';
import axios from 'axios';
import './Statistics.css';

const Statistics = () => {
  const { scanStats } = useContext(UserContext);
  const [detailedStats, setDetailedStats] = useState(null);
  const [recentPhishing, setRecentPhishing] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDetailedStatistics();
    fetchRecentPhishing();
  }, []);

  const fetchDetailedStatistics = async () => {
    try {
      const response = await axios.get(
        'http://localhost:8800/api/phishing/statistics',
        { withCredentials: true }
      );

      if (response.data.success) {
        setDetailedStats(response.data.data);
      }
    } catch (error) {
      console.error('Error fetching statistics:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchRecentPhishing = async () => {
    try {
      const response = await axios.get(
        'http://localhost:8800/api/phishing/detections?limit=10',
        { withCredentials: true }
      );

      if (response.data.success) {
        setRecentPhishing(response.data.data);
      }
    } catch (error) {
      console.error('Error fetching phishing detections:', error);
    }
  };

  if (loading) {
    return (
      <div className="statistics-container">
        <div className="loading">Loading statistics...</div>
      </div>
    );
  }

  if (!detailedStats) {
    return (
      <div className="statistics-container">
        <div className="error-message">Unable to load statistics</div>
      </div>
    );
  }

  return (
    <div className="statistics-container">
      <h1>📊 Your Scan Statistics</h1>

      {/* Summary Cards */}
      <div className="stats-cards">
        <div className="stat-card">
          <div className="stat-icon">🔍</div>
          <div className="stat-value">{detailedStats.totalScans}</div>
          <div className="stat-label">Total Scans</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">📅</div>
          <div className="stat-value">{detailedStats.todaysScans}</div>
          <div className="stat-label">Today's Scans</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">🚨</div>
          <div className="stat-value">{detailedStats.phishingCount}</div>
          <div className="stat-label">Phishing Detected</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">✅</div>
          <div className="stat-value">{detailedStats.legitimateCount}</div>
          <div className="stat-label">Legitimate Sites</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">📊</div>
          <div className="stat-value">{detailedStats.phishingRate}%</div>
          <div className="stat-label">Phishing Rate</div>
        </div>

        <div className="stat-card">
          <div className="stat-icon">⏳</div>
          <div className="stat-value">{detailedStats.remainingScans}</div>
          <div className="stat-label">Scans Remaining</div>
        </div>
      </div>

      {/* Risk Distribution */}
      {detailedStats.riskDistribution && Object.keys(detailedStats.riskDistribution).length > 0 && (
        <div className="risk-distribution">
          <h2>Risk Level Distribution</h2>
          <div className="risk-bars">
            {Object.entries(detailedStats.riskDistribution).map(([level, count]) => (
              <div key={level} className="risk-bar-item">
                <span className="risk-label">{level}</span>
                <div className="risk-bar-bg">
                  <div
                    className={`risk-bar-fill risk-${level.toLowerCase()}`}
                    style={{ width: `${(count / detailedStats.totalScans) * 100}%` }}
                  />
                </div>
                <span className="risk-count">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent Phishing Detections */}
      {recentPhishing.length > 0 && (
        <div className="recent-phishing">
          <h2>🚨 Recent Phishing Detections</h2>
          <ul>
            {recentPhishing.map((scan) => (
              <li key={scan._id}>
                <div className="phishing-item">
                  <span className="phishing-domain">{scan.domain}</span>
                  <span className="phishing-confidence">{scan.confidence}% confidence</span>
                  <span className={`phishing-risk risk-${scan.riskLevel.toLowerCase()}`}>
                    {scan.riskLevel}
                  </span>
                  <span className="phishing-date">
                    {new Date(scan.createdAt).toLocaleDateString()}
                  </span>
                </div>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Premium Upgrade Banner */}
      {!detailedStats.isPremium && (
        <div className="upgrade-banner">
          <h3>⭐ Upgrade to Premium</h3>
          <p>Get 1000 scans/day and advanced features!</p>
          <Link to="/getpremium" className="upgrade-button">
            Upgrade Now →
          </Link>
        </div>
      )}
    </div>
  );
};

export default Statistics;

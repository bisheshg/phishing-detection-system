# Frontend Integration Guide

## ✅ UserContext Updates

Your `UserContext` has been enhanced with scan tracking! It now provides:

```javascript
const {
  isLoggedIn,        // Boolean - user login status
  userr,             // Object - user details
  checkUserLoggedIn, // Function - verify authentication
  handleLogout,      // Function - logout user
  scanStats,         // Object - scan statistics
  fetchScanStatistics // Function - refresh scan stats
} = useContext(UserContext);
```

### New `scanStats` Object:
```javascript
{
  totalScans: 0,      // Lifetime scan count
  todaysScans: 0,     // Scans performed today
  remainingScans: 50, // Scans left for today
  dailyLimit: 50,     // Daily limit (50 or 1000)
  isPremium: false    // Premium status
}
```

---

## 🔄 Update Result.jsx to Use New Backend API

### Current Code (Direct Flask Call):
```javascript
// OLD - Don't use this anymore
const response = await axios.post(
  'http://localhost:5002/analyze_url',
  { url: inputUrl.trim() },
  {
    headers: { 'Content-Type': 'application/json' },
    timeout: 30000
  }
);
```

### New Code (Express Backend with Auth):
```javascript
// NEW - Use this instead
import { useContext } from 'react';
import { UserContext } from '../../context/UserContext';

const Result = () => {
  const { fetchScanStatistics } = useContext(UserContext);

  // ... inside fetchAnalysis function:

  try {
    const response = await axios.post(
      'http://localhost:8800/api/phishing/analyze',  // ✅ New endpoint
      { url: inputUrl.trim() },
      {
        headers: { 'Content-Type': 'application/json' },
        withCredentials: true,  // ✅ Include JWT cookie
        timeout: 30000
      }
    );

    if (response.data.success) {
      setAnalysisResult(response.data.data);

      // ✅ Update scan statistics after successful scan
      await fetchScanStatistics();

      // ✅ Check if approaching limit
      if (response.data.userInfo.remainingScans <= 5) {
        alert(`Warning: Only ${response.data.userInfo.remainingScans} scans remaining today!`);
      }
    }
  } catch (error) {
    // ✅ Handle rate limit error
    if (error.response?.status === 429) {
      setError(error.response.data.message);
      // Show upgrade prompt for free users
      if (!error.response.data.isPremium) {
        // Redirect to premium page or show modal
      }
    } else {
      setError(error.response?.data?.message || 'Analysis failed');
    }
  }
}
```

---

## 📊 Add Scan Limit Banner to Pages

### 1. Import the Component
```javascript
import ScanLimitBanner from '../../Components/ScanLimitBanner/ScanLimitBanner';
```

### 2. Add to Your Page (Home, Dashboard, etc.)
```javascript
const Home = () => {
  const { isLoggedIn } = useContext(UserContext);

  return (
    <div className="home-container">
      {/* Show scan limit banner only for logged-in users */}
      {isLoggedIn && <ScanLimitBanner />}

      {/* Rest of your page */}
      <div className="scan-input">
        {/* ... */}
      </div>
    </div>
  );
};
```

---

## 🎨 Create Scan History Page

Create a new page to display scan history:

**File**: `src/Pages/history/ScanHistory.jsx`

```javascript
import React, { useState, useEffect, useContext } from 'react';
import { UserContext } from '../../context/UserContext';
import axios from 'axios';
import './ScanHistory.css';

const ScanHistory = () => {
  const { isLoggedIn } = useContext(UserContext);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);

  useEffect(() => {
    if (isLoggedIn) {
      fetchScanHistory();
    }
  }, [isLoggedIn, page]);

  const fetchScanHistory = async () => {
    try {
      setLoading(true);
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
    }
  };

  if (loading) {
    return <div className="loading">Loading scan history...</div>;
  }

  return (
    <div className="scan-history-container">
      <h1>Scan History</h1>

      <div className="scan-history-table">
        <table>
          <thead>
            <tr>
              <th>Date</th>
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
                <td>{new Date(scan.createdAt).toLocaleString()}</td>
                <td className="url-cell" title={scan.url}>
                  {scan.url.length > 50 ? scan.url.substring(0, 50) + '...' : scan.url}
                </td>
                <td>{scan.domain}</td>
                <td>
                  <span className={`badge ${scan.prediction === 'Phishing' ? 'phishing' : 'legitimate'}`}>
                    {scan.prediction}
                  </span>
                </td>
                <td>{scan.confidence}%</td>
                <td>
                  <span className={`risk-badge risk-${scan.riskLevel.toLowerCase()}`}>
                    {scan.riskLevel}
                  </span>
                </td>
                <td>
                  <button onClick={() => deleteScan(scan._id)} className="delete-btn">
                    🗑️ Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="pagination">
        <button
          onClick={() => setPage(p => Math.max(1, p - 1))}
          disabled={page === 1}
        >
          Previous
        </button>
        <span>Page {page} of {totalPages}</span>
        <button
          onClick={() => setPage(p => Math.min(totalPages, p + 1))}
          disabled={page === totalPages}
        >
          Next
        </button>
      </div>
    </div>
  );
};

export default ScanHistory;
```

**File**: `src/Pages/history/ScanHistory.css`

```css
.scan-history-container {
  padding: 2rem;
  max-width: 1400px;
  margin: 0 auto;
}

.scan-history-table {
  overflow-x: auto;
  margin: 2rem 0;
}

table {
  width: 100%;
  border-collapse: collapse;
  background: white;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
  border-radius: 8px;
  overflow: hidden;
}

thead {
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
}

th, td {
  padding: 1rem;
  text-align: left;
}

tbody tr:hover {
  background: #f5f5f5;
}

.url-cell {
  max-width: 300px;
  word-break: break-all;
}

.badge {
  padding: 0.25rem 0.75rem;
  border-radius: 20px;
  font-size: 0.9rem;
  font-weight: 600;
}

.badge.phishing {
  background: #ffebee;
  color: #c62828;
}

.badge.legitimate {
  background: #e8f5e9;
  color: #2e7d32;
}

.risk-badge {
  padding: 0.25rem 0.75rem;
  border-radius: 20px;
  font-size: 0.85rem;
  font-weight: 600;
}

.risk-safe { background: #e8f5e9; color: #2e7d32; }
.risk-low { background: #f1f8e9; color: #558b2f; }
.risk-medium { background: #fff9c4; color: #f57f17; }
.risk-high { background: #ffe0b2; color: #e65100; }
.risk-critical { background: #ffebee; color: #c62828; }

.delete-btn {
  background: #f44336;
  color: white;
  border: none;
  padding: 0.5rem 1rem;
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.3s;
}

.delete-btn:hover {
  background: #d32f2f;
}

.pagination {
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 1rem;
  margin-top: 2rem;
}

.pagination button {
  padding: 0.5rem 1rem;
  background: #667eea;
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
}

.pagination button:disabled {
  background: #ccc;
  cursor: not-allowed;
}
```

---

## 📈 Add Statistics Dashboard

**File**: `src/Pages/statistics/Statistics.jsx`

```javascript
import React, { useState, useEffect, useContext } from 'react';
import { UserContext } from '../../context/UserContext';
import axios from 'axios';
import './Statistics.css';

const Statistics = () => {
  const { scanStats } = useContext(UserContext);
  const [detailedStats, setDetailedStats] = useState(null);
  const [recentPhishing, setRecentPhishing] = useState([]);

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

  if (!detailedStats) {
    return <div className="loading">Loading statistics...</div>;
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
      <div className="risk-distribution">
        <h2>Risk Level Distribution</h2>
        <div className="risk-bars">
          {Object.entries(detailedStats.riskDistribution || {}).map(([level, count]) => (
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

      {/* Recent Phishing Detections */}
      {recentPhishing.length > 0 && (
        <div className="recent-phishing">
          <h2>🚨 Recent Phishing Detections</h2>
          <ul>
            {recentPhishing.map((scan) => (
              <li key={scan._id}>
                <div className="phishing-item">
                  <span className="phishing-domain">{scan.domain}</span>
                  <span className="phishing-confidence">{scan.confidence}%</span>
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
    </div>
  );
};

export default Statistics;
```

---

## 🔀 Update App.js Routes

Add the new pages to your routes:

```javascript
import ScanHistory from "./Pages/history/ScanHistory";
import Statistics from "./Pages/statistics/Statistics";

// Inside Routes component:
<Route
  path="/scan-history"
  element={
    <ProtectedRoute>
      <ScanHistory />
    </ProtectedRoute>
  }
/>
<Route
  path="/statistics"
  element={
    <ProtectedRoute>
      <Statistics />
    </ProtectedRoute>
  }
/>
```

---

## 🎯 Quick Implementation Checklist

- [x] ✅ UserContext enhanced with scan statistics
- [x] ✅ ScanLimitBanner component created
- [ ] Update Result.jsx to use new backend API
- [ ] Add ScanLimitBanner to Home page
- [ ] Create ScanHistory page
- [ ] Create Statistics page
- [ ] Add routes to App.js
- [ ] Update Navbar with new links
- [ ] Test all functionality

---

## 🧪 Testing Steps

1. **Login** - Verify scanStats are loaded
2. **Scan a URL** - Check if stats update
3. **View History** - See all past scans
4. **Check Statistics** - View dashboard
5. **Test Limit** - Perform 50+ scans (free user)
6. **Premium Test** - Set user as premium and test 1000 limit

---

## 🎨 Navbar Update Suggestion

Add new navigation items:

```javascript
const navItems = [
  { path: '/', label: 'Home' },
  { path: '/scan-history', label: 'History' },
  { path: '/statistics', label: 'Statistics' },
  { path: '/dashboard', label: 'Dashboard' },
  { path: '/getpremium', label: '⭐ Premium' },
];
```

---

Your frontend is now ready to leverage all the new backend features! 🎉

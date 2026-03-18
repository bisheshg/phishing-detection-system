import React, { useState, useEffect, useRef } from 'react';
import io from 'socket.io-client';
import axios from 'axios';
import './Intelligence.css';
import {
  FaSatellite,
  FaShieldAlt,
  FaGlobeAmericas,
  FaSkullCrossbones,
  FaChartLine,
  FaCrosshairs
} from 'react-icons/fa';

const BACKEND_URL = "http://localhost:8800";

const IntelligenceDashboard = () => {
  const [detections, setDetections] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [stats, setStats] = useState({
    totalScans: 0,
    phishingRatio: 0,
    activeCampaigns: 0,
    criticalThreats: 0
  });
  const [connected, setConnected] = useState(false);
  const socketRef = useRef();

  useEffect(() => {
    // 1. Initial Data Fetch
    const fetchInitialData = async () => {
      try {
        const campaignRes = await axios.get(`${BACKEND_URL}/api/phishing/campaigns`, { withCredentials: true });
        setCampaigns(campaignRes.data.campaigns || []);
        setStats(prev => ({ ...prev, activeCampaigns: campaignRes.data.campaigns?.length || 0 }));
      } catch (err) {
        console.error("Failed to fetch initial intelligence data", err);
      }
    };

    fetchInitialData();

    // 2. Setup Socket.io
    socketRef.current = io(BACKEND_URL, {
      withCredentials: true,
      transports: ["websocket", "polling"]
    });

    socketRef.current.on('connect', () => {
      setConnected(true);
      console.log('Connected to PhishNet Intelligence Stream');
    });

    socketRef.current.on('disconnect', () => {
      setConnected(false);
    });

    socketRef.current.on('new_detection', (data) => {
      // Add new detection to the top of the list
      setDetections(prev => [data, ...prev].slice(0, 50));

      // Update global stats locally for real-time feel
      if (data.prediction === 'Phishing') {
        setStats(prev => ({
          ...prev,
          totalScans: prev.totalScans + 1,
          criticalThreats: data.riskLevel === 'Critical' ? prev.criticalThreats + 1 : prev.criticalThreats
        }));
      }

      // Refresh campaign list when a new campaign is created
      if (data.campaignId) {
        fetchInitialData();
      }
    });

    return () => {
      if (socketRef.current) socketRef.current.disconnect();
    };
  }, []);

  return (
    <div className="intelligence-container">
      <header className="dashboard-header">
        <div className="header-title">
          <h1>Live Intelligence Feed</h1>
          <p>Real-time global phishing surveillance &amp; campaign correlation</p>
        </div>
        <div className="header-status">
          <div className={`status-indicator ${connected ? 'active' : 'inactive'}`}></div>
          <span>{connected ? 'STREAMS ACTIVE' : 'RECONNECTING...'}</span>
        </div>
      </header>

      <div className="stats-header-grid">
        <div className="stat-box animate-in" style={{ animationDelay: '0.1s' }}>
          <FaShieldAlt className="stat-icon" />
          <span className="stat-value">{stats.totalScans || 0}</span>
          <span className="stat-label">Total Surveillance Events</span>
        </div>
        <div className="stat-box animate-in" style={{ animationDelay: '0.2s' }}>
          <FaSkullCrossbones className="stat-icon" style={{ color: '#ff4b2b' }} />
          <span className="stat-value">{stats.criticalThreats || 0}</span>
          <span className="stat-label">Critical Threat Clusters</span>
        </div>
        <div className="stat-box animate-in" style={{ animationDelay: '0.3s' }}>
          <FaCrosshairs className="stat-icon" style={{ color: '#a445b2' }} />
          <span className="stat-value">{campaigns.length || 0}</span>
          <span className="stat-label">Coordinated Campaigns</span>
        </div>
        <div className="stat-box animate-in" style={{ animationDelay: '0.4s' }}>
          <FaGlobeAmericas className="stat-icon" style={{ color: '#00ff87' }} />
          <span className="stat-value">Alpha-1</span>
          <span className="stat-label">Surveillance Node</span>
        </div>
      </div>

      <div className="dashboard-grid">
        <section className="card live-detections">
          <div className="card-header">
            <h2>Real-time Stream</h2>
            <div className="live-tag">LIVE</div>
          </div>
          <div className="live-feed-list">
            {detections.length === 0 ? (
              <div className="empty-state">Waiting for incoming threat signals...</div>
            ) : (
              detections.map((item, idx) => (
                <div key={idx} className={`detection-item ${item.prediction?.toLowerCase()} animate-in`}>
                  <div className={`item-badge badge-${item.prediction?.toLowerCase()}`}>
                    {item.prediction}
                  </div>
                  <div className="item-url">{item.url}</div>
                  <div className="item-time">
                    {new Date(item.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              ))
            )}
          </div>
        </section>

        <section className="dashboard-sidebar">
          <div className="card active-campaigns">
            <div className="card-header">
              <h2>Top Threat Campaigns</h2>
              <FaChartLine />
            </div>
            <div className="campaign-list">
              {campaigns.length === 0 ? (
                <div className="empty-state">No coordinated campaigns detected.</div>
              ) : (
                campaigns.map((c, idx) => (
                  <div key={idx} className="campaign-item">
                    <span className="campaign-name">{c.name || `Campaign-${String(c._id).substr(-6)}`}</span>
                    <span className="campaign-hits">{c.totalHits} Hits</span>
                  </div>
                ))
              )}
            </div>
          </div>

          <div className="card network-nodes" style={{ marginTop: '2rem' }}>
            <div className="card-header">
              <h2>Infrastructure Signature</h2>
              <FaSatellite />
            </div>
            <div className="infra-stats">
              <p style={{ color: '#94a3b8', fontSize: '0.8rem' }}>
                System is correlating detections using deep content hashing and single-resolution DNS infrastructure fingerprints.
              </p>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};

export default IntelligenceDashboard;

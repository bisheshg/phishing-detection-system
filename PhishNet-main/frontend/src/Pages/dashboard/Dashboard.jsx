import React, { useEffect, useState, useContext } from "react";
import axios from "axios";
import { Link } from "react-router-dom";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faShieldAlt,
  faExclamationTriangle,
  faCheckCircle,
  faSearch,
  faClock,
  faCalendarDay,
  faFire,
  faChartPie,
  faHistory,
  faStar,
  faArrowRight,
} from "@fortawesome/free-solid-svg-icons";
import { UserContext } from "../../context/UserContext";
import "./Dashboard.css";

const API = "http://localhost:8800/api";

// ── helpers ──────────────────────────────────────────────────────────────────
const timeAgo = (dateStr) => {
  const diff = Date.now() - new Date(dateStr).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

const truncate = (str, max = 48) =>
  str && str.length > max ? str.slice(0, max) + "…" : str;

const RISK_COLORS = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#f59e0b",
  Low: "#22c55e",
  Safe: "#10b981",
};

// ── sub-components ────────────────────────────────────────────────────────────
const Spinner = () => (
  <div className="loading-indicator">
    <div className="spinner" />
    Loading…
  </div>
);

const StatCard = ({ icon, label, value, sub, color }) => (
  <div className="stat-card card" style={{ borderTop: `4px solid ${color}` }}>
    <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
      <div
        style={{
          width: 44,
          height: 44,
          borderRadius: "0.6rem",
          background: color + "22",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color,
          fontSize: "1.25rem",
          flexShrink: 0,
        }}
      >
        <FontAwesomeIcon icon={icon} />
      </div>
      <div>
        <div className="stat-label">{label}</div>
        <div className="stat-value">{value}</div>
        {sub && <div className="stat-subtitle">{sub}</div>}
      </div>
    </div>
  </div>
);

const RiskBar = ({ label, count, total, color }) => {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return (
    <div style={{ marginBottom: "0.6rem" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          fontSize: "0.8rem",
          marginBottom: "0.25rem",
          color: "#374151",
        }}
      >
        <span>{label}</span>
        <span style={{ fontWeight: 600 }}>
          {count} <span style={{ color: "#9ca3af" }}>({pct}%)</span>
        </span>
      </div>
      <div
        style={{
          height: 8,
          background: "#f3f4f6",
          borderRadius: 4,
          overflow: "hidden",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${pct}%`,
            background: color,
            borderRadius: 4,
            transition: "width 0.6s ease",
          }}
        />
      </div>
    </div>
  );
};

const ScanRow = ({ scan }) => {
  const isPhishing = scan.prediction === "Phishing";
  return (
    <div className="activity-item">
      <div className="activity-content">
        <div className="activity-domain">{truncate(scan.url)}</div>
        <div className="activity-time">
          <span>
            <FontAwesomeIcon icon={faClock} style={{ marginRight: 4 }} />
            {timeAgo(scan.createdAt)}
          </span>
          {scan.domain && <span>{scan.domain}</span>}
        </div>
      </div>
      <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "0.25rem" }}>
        <span
          className={`tag ${isPhishing ? "tag-danger" : "tag-success"}`}
          style={{ fontSize: "0.78rem" }}
        >
          {isPhishing ? (
            <FontAwesomeIcon icon={faExclamationTriangle} style={{ marginRight: 4 }} />
          ) : (
            <FontAwesomeIcon icon={faCheckCircle} style={{ marginRight: 4 }} />
          )}
          {scan.prediction}
        </span>
        <span style={{ fontSize: "0.75rem", color: "#9ca3af" }}>
          {scan.confidence}% confidence
        </span>
      </div>
    </div>
  );
};

// ── Dashboard ─────────────────────────────────────────────────────────────────
const Dashboard = () => {
  const { userr } = useContext(UserContext);

  const [stats, setStats] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [statsRes, historyRes] = await Promise.all([
          axios.get(`${API}/phishing/statistics`, { withCredentials: true }),
          axios.get(`${API}/phishing/history?limit=5`, { withCredentials: true }),
        ]);

        if (statsRes.data.success) setStats(statsRes.data.data);
        if (historyRes.data.success) setRecentScans(historyRes.data.data);
      } catch (err) {
        console.error("Dashboard fetch error:", err);
        setError("Could not load dashboard data. Make sure the backend is running.");
      } finally {
        setLoading(false);
      }
    };
    fetchAll();
  }, []);

  const firstName = userr?.name ? userr.name.split(" ")[0] : "there";
  const today = new Date().toLocaleDateString("en-US", {
    weekday: "long",
    month: "long",
    day: "numeric",
  });

  if (loading) {
    return (
      <div style={{ padding: "3rem" }}>
        <Spinner />
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: "3rem", textAlign: "center", color: "#ef4444" }}>
        <FontAwesomeIcon icon={faExclamationTriangle} style={{ fontSize: "2rem", marginBottom: "1rem" }} />
        <p>{error}</p>
      </div>
    );
  }

  const totalScans = stats?.totalScans ?? 0;
  const phishingCount = stats?.phishingCount ?? 0;
  const legitimateCount = stats?.legitimateCount ?? 0;
  const todaysScans = stats?.todaysScans ?? 0;
  const remainingScans = stats?.remainingScans ?? 0;
  const dailyLimit = stats?.dailyLimit ?? 50;
  const phishingRate = stats?.phishingRate ?? 0;
  const isPremium = stats?.isPremium ?? false;
  const riskDist = stats?.riskDistribution ?? {};
  const usedToday = dailyLimit - remainingScans;
  const usedPct = dailyLimit > 0 ? Math.round((usedToday / dailyLimit) * 100) : 0;

  return (
    <div style={{ padding: "2rem", maxWidth: 1100, margin: "0 auto" }}>
      {/* ── Welcome header ─────────────────────────────────── */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          marginBottom: "2rem",
          flexWrap: "wrap",
          gap: "0.75rem",
        }}
      >
        <div>
          <h1
            style={{
              margin: 0,
              fontSize: "1.75rem",
              fontWeight: 700,
              color: "#111827",
            }}
          >
            <FontAwesomeIcon icon={faShieldAlt} style={{ marginRight: 10, color: "#6366f1" }} />
            Welcome back, {firstName}!
          </h1>
          <p style={{ margin: "0.25rem 0 0", color: "#6b7280", fontSize: "0.9rem" }}>
            <FontAwesomeIcon icon={faCalendarDay} style={{ marginRight: 6 }} />
            {today}
            {isPremium && (
              <span
                style={{
                  marginLeft: 12,
                  padding: "2px 8px",
                  background: "linear-gradient(135deg,#f59e0b,#d97706)",
                  color: "white",
                  borderRadius: 4,
                  fontSize: "0.75rem",
                  fontWeight: 600,
                }}
              >
                <FontAwesomeIcon icon={faStar} style={{ marginRight: 4 }} />
                Premium
              </span>
            )}
          </p>
        </div>
        <Link
          to="/report"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "0.5rem",
            padding: "0.625rem 1.25rem",
            background: "#6366f1",
            color: "white",
            borderRadius: "0.5rem",
            textDecoration: "none",
            fontWeight: 600,
            fontSize: "0.9rem",
          }}
        >
          <FontAwesomeIcon icon={faSearch} />
          Scan a URL
        </Link>
      </div>

      {/* ── Stat cards ─────────────────────────────────────── */}
      <div className="cards-row" style={{ marginBottom: "1.5rem" }}>
        <StatCard
          icon={faSearch}
          label="Total Scans"
          value={totalScans.toLocaleString()}
          sub="all time"
          color="#6366f1"
        />
        <StatCard
          icon={faCalendarDay}
          label="Today's Scans"
          value={todaysScans}
          sub={`${remainingScans} remaining`}
          color="#3b82f6"
        />
        <StatCard
          icon={faExclamationTriangle}
          label="Phishing Detected"
          value={phishingCount.toLocaleString()}
          sub={`${phishingRate}% of total`}
          color="#ef4444"
        />
        <StatCard
          icon={faCheckCircle}
          label="Safe URLs"
          value={legitimateCount.toLocaleString()}
          sub="verified legitimate"
          color="#10b981"
        />
      </div>

      {/* ── Middle row: Daily usage + Risk distribution ───── */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: "1.5rem",
          marginBottom: "1.5rem",
        }}
      >
        {/* Daily usage */}
        <div className="card">
          <h3 className="card-title">
            <FontAwesomeIcon icon={faFire} style={{ marginRight: 8, color: "#f59e0b" }} />
            Daily Usage
          </h3>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              fontSize: "0.85rem",
              color: "#6b7280",
              marginBottom: "0.5rem",
            }}
          >
            <span>{usedToday} used</span>
            <span>{dailyLimit} daily limit</span>
          </div>
          <div
            style={{
              height: 12,
              background: "#f3f4f6",
              borderRadius: 6,
              overflow: "hidden",
              marginBottom: "0.75rem",
            }}
          >
            <div
              style={{
                height: "100%",
                width: `${usedPct}%`,
                background:
                  usedPct > 80
                    ? "#ef4444"
                    : usedPct > 50
                    ? "#f59e0b"
                    : "#6366f1",
                borderRadius: 6,
                transition: "width 0.6s ease",
              }}
            />
          </div>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span
              style={{
                fontSize: "0.8rem",
                color: usedPct > 80 ? "#ef4444" : "#6b7280",
              }}
            >
              {usedPct}% used today
            </span>
            {!isPremium && (
              <Link
                to="/getpremium"
                style={{
                  fontSize: "0.8rem",
                  color: "#f59e0b",
                  textDecoration: "none",
                  fontWeight: 600,
                }}
              >
                Upgrade for 1000/day →
              </Link>
            )}
          </div>
        </div>

        {/* Risk distribution */}
        <div className="card">
          <h3 className="card-title">
            <FontAwesomeIcon icon={faChartPie} style={{ marginRight: 8, color: "#6366f1" }} />
            Risk Distribution
          </h3>
          {totalScans === 0 ? (
            <p style={{ color: "#9ca3af", fontSize: "0.875rem" }}>
              No scans yet. Start scanning URLs to see your risk distribution.
            </p>
          ) : (
            <>
              {["Critical", "High", "Medium", "Low", "Safe"].map((level) => (
                <RiskBar
                  key={level}
                  label={level}
                  count={riskDist[level] ?? 0}
                  total={totalScans}
                  color={RISK_COLORS[level]}
                />
              ))}
            </>
          )}
        </div>
      </div>

      {/* ── Recent scans ───────────────────────────────────── */}
      <div className="card">
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: "1rem",
          }}
        >
          <h3 className="card-title" style={{ margin: 0 }}>
            <FontAwesomeIcon icon={faHistory} style={{ marginRight: 8, color: "#6366f1" }} />
            Recent Scans
          </h3>
          <Link
            to="/scan-history"
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "0.4rem",
              fontSize: "0.875rem",
              color: "#6366f1",
              textDecoration: "none",
              fontWeight: 500,
            }}
          >
            View all
            <FontAwesomeIcon icon={faArrowRight} />
          </Link>
        </div>

        {recentScans.length === 0 ? (
          <div className="empty-scan-history">
            <div className="empty-icon">
              <FontAwesomeIcon icon={faSearch} style={{ fontSize: "2rem", color: "#d1d5db" }} />
            </div>
            <h4>No scans yet</h4>
            <p style={{ color: "#9ca3af", fontSize: "0.875rem" }}>
              Start by scanning a URL to see your history here.
            </p>
            <Link to="/report" className="link-button" style={{ display: "inline-block", width: "auto" }}>
              Scan your first URL →
            </Link>
          </div>
        ) : (
          <div className="recent-activity">
            {recentScans.map((scan) => (
              <ScanRow key={scan._id} scan={scan} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;

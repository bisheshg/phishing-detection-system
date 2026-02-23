import React, { useEffect, useState } from "react";
import axios from "axios";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import {
  faShieldAlt,
  faChartLine,
  faExclamationTriangle,
  faArrowTrendUp,
  faCheckCircle,
  faClock,
  faTrophy,
  faSearch,
} from "@fortawesome/free-solid-svg-icons";

import "./Dashboard.css";

/* =======================
   Reusable Stat Card
======================= */
const StatCard = ({ icon, label, value, change, gradient }) => {
  return (
    <div className="stat-card" style={{ background: gradient }}>
      <div className="stat-icon">
        <FontAwesomeIcon icon={icon} />
      </div>

      <div className="stat-info">
        <h4>{label}</h4>
        <h2>{value}</h2>

        {change !== undefined && (
          <p className={change >= 0 ? "positive" : "negative"}>
            {change >= 0 ? "+" : ""}
            {change}%
          </p>
        )}
      </div>
    </div>
  );
};

/* =======================
   Dashboard Component
======================= */
const Dashboard = () => {
  const [stats, setStats] = useState({
    totalScans: 0,
    phishingDetected: 0,
    safeUrls: 0,
    accuracy: 0,
  });

  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const res = await axios.get(
          "http://localhost:4000/api/dashboard/stats"
        );

        setStats({
          totalScans: res.data.totalScans || 0,
          phishingDetected: res.data.phishingDetected || 0,
          safeUrls: res.data.safeUrls || 0,
          accuracy: res.data.accuracy || 0,
        });
      } catch (err) {
        console.error("Dashboard API error:", err);

        // fallback demo data
        setStats({
          totalScans: 1240,
          phishingDetected: 312,
          safeUrls: 928,
          accuracy: 96.4,
        });
      } finally {
        setLoading(false);
      }
    };

    fetchStats();
  }, []);

  if (loading) {
    return <div className="dashboard-loading">Loading dashboard...</div>;
  }

  return (
    <div className="dashboard-container">
      <h1>
        <FontAwesomeIcon icon={faShieldAlt} /> PhishNet Dashboard
      </h1>

      <div className="stats-grid">
        <StatCard
          icon={faSearch}
          label="Total Scans"
          value={stats.totalScans}
          gradient="linear-gradient(135deg, #6366f1, #4f46e5)"
        />

        <StatCard
          icon={faExclamationTriangle}
          label="Phishing Detected"
          value={stats.phishingDetected}
          gradient="linear-gradient(135deg, #ef4444, #b91c1c)"
        />

        <StatCard
          icon={faCheckCircle}
          label="Safe URLs"
          value={stats.safeUrls}
          gradient="linear-gradient(135deg, #10b981, #059669)"
        />

        {/* Accuracy card */}
        <StatCard
          icon={faArrowTrendUp}
          label="Accuracy Rate"
          value={`${stats.accuracy}%`}
          change={2}
          gradient="linear-gradient(135deg, #22c55e, #16a34a)"
        />
      </div>

      <section className="dashboard-section">
        <h2>
          <FontAwesomeIcon icon={faChartLine} /> Recent Activity
        </h2>
        <ul>
          <li>
            <FontAwesomeIcon icon={faClock} /> Scan completed successfully
          </li>
          <li>
            <FontAwesomeIcon icon={faExclamationTriangle} /> Phishing URL blocked
          </li>
          <li>
            <FontAwesomeIcon icon={faTrophy} /> Accuracy milestone achieved
          </li>
        </ul>
      </section>
    </div>
  );
};

export default Dashboard;




// import React, { useState, useContext } from 'react';
// import './Dashboard.css';
// import Header from './Header';
// import DashboardNavbar from './DashboardNavbar';
// import Footer from '../../Components/Footer/Footer';
// import Home from './Home';
// import ScanHistory from './ScanHistory';
// import PhishingReportCard from './PhishingReportCard';
// import LeaderboardCard from './LeaderboardCard';
// import SecurityRecommendationsCard from './SecurityRecommendationsCard';
// import UserSettingsCard from './UserSettingsCard';
// import { UserContext } from '../../context/UserContext';

// const Dashboard = () => {
//   const [sidebarOpen, setSidebarOpen] = useState(false);
//   const [activeComponent, setActiveComponent] = useState('Home');
//   const { userr } = useContext(UserContext);

//   const toggleSidebar = () => setSidebarOpen(prev => !prev);

//   const handleNavigation = (component) => {
//     setActiveComponent(component);
//     // auto-close sidebar on small screens
//     if (window.innerWidth <= 992) setSidebarOpen(false);
//   };

//   const reports = [
//     { date: '2023-10-01', status: 'Pending', outcome: 'In review' },
//     { date: '2023-09-25', status: 'Closed', outcome: 'No threat detected' },
//     { date: '2023-09-20', status: 'Open', outcome: 'Under investigation' },
//   ];
//   const leaderboard = [
//     { name: 'John Doe', submitted: 15 },
//     { name: 'Alice Smith', submitted: 12 },
//     { name: 'Bob Johnson', submitted: 10 },
//   ];
//   const recommendations = [
//     'Enable two-factor authentication',
//     'Rotate passwords every 3 months',
//     'Install reputable endpoint protection',
//   ];
//   const settings = {
//     name: userr?.name || 'Your Name',
//     email: userr?.email || 'you@example.com',
//     isPremium: userr?.isPremium || false,
//   };

//   const components = {
//     Home: <Home />,
//     ScanHistory: <ScanHistory />,
//     PhishingReports: <PhishingReportCard reports={reports} />,
//     Leaderboard: <LeaderboardCard leaderboard={leaderboard} />,
//     Recommendations: <SecurityRecommendationsCard recommendations={recommendations} />,
//     Settings: <UserSettingsCard settings={settings} />,
//   };

//   return (
//     <div className={`dashboard-layout ${sidebarOpen ? 'sidebar-open' : ''}`}>
//       <Header toggleSidebar={toggleSidebar} user={userr} />
//       <DashboardNavbar
//         open={sidebarOpen}
//         onClose={() => setSidebarOpen(false)}
//         onNavigate={handleNavigation}
//         activeItem={activeComponent}
//       />

//       <div className="dashboard-main">
//         <div className="page-inner">
//           {/* Page title + breadcrumbs area */}
//           <div className="page-header">
//             <h1 className="page-title">{activeComponent === 'Home' ? 'Overview' : activeComponent}</h1>
//             <div className="page-actions">
//               {/* small quick actions can go here */}
//               <button className="btn btn-primary">New Report</button>
//             </div>
//           </div>

//           {/* Main content */}
//           <section className="content-grid">
//             {/* Left/primary column */}
//             <div className="content-main">
//               {components[activeComponent] || <div className="placeholder">Select a section</div>}
//             </div>

//             {/* Right / aside column */}
//             <aside className="content-aside">
//               <div className="card small-card">
//                 <h3 className="card-title">Profile</h3>
//                 <div className="profile">
//                   <div className="avatar">{(settings.name || 'U').slice(0,1)}</div>
//                   <div>
//                     <div className="profile-name">{settings.name}</div>
//                     <div className="profile-email">{settings.email}</div>
//                   </div>
//                 </div>
//               </div>

//               <div className="card small-card">
//                 <h3 className="card-title">Leaderboard</h3>
//                 <ul className="mini-list">
//                   {leaderboard.map((l, i) => (
//                     <li key={i}><strong>{l.name}</strong> <span className="muted">({l.submitted})</span></li>
//                   ))}
//                 </ul>
//               </div>

//               <div className="card small-card">
//                 <h3 className="card-title">Recommendations</h3>
//                 <ul className="mini-list">
//                   {recommendations.slice(0,3).map((r,i) => <li key={i}>{r}</li>)}
//                 </ul>
//               </div>
//             </aside>
//           </section>
//         </div>

//         <Footer />
//       </div>
//     </div>
//   );
// };

// export default Dashboard;

// import { useState } from 'react'
// import './Dashboard.css'
// import Header from './Header'
// import Sidebar from './SideBar';
// import Home from './Home'

// function App() {
//   const [openSidebarToggle, setOpenSidebarToggle] = useState(false)

//   const OpenSidebar = () => {
//     setOpenSidebarToggle(!openSidebarToggle)
//   }

//   return (
//     <div className='grid-container'>
//       {/* <Header /> */}
//       {/* <Sidebar openSidebarToggle={openSidebarToggle} OpenSidebar={OpenSidebar}/> */}
//       <Home />
//     </div>
//   )
// }

// export default App


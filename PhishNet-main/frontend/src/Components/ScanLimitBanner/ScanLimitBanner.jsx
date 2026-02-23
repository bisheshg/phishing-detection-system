import React, { useContext } from 'react';
import { UserContext } from '../../context/UserContext';
import './ScanLimitBanner.css';

const ScanLimitBanner = () => {
  const { scanStats } = useContext(UserContext);

  // Calculate percentage for progress bar
  const percentageUsed = (scanStats.todaysScans / scanStats.dailyLimit) * 100;

  // Determine warning level
  const isWarning = percentageUsed >= 70;
  const isCritical = percentageUsed >= 90;

  return (
    <div className={`scan-limit-banner ${isCritical ? 'critical' : isWarning ? 'warning' : ''}`}>
      <div className="scan-limit-content">
        <div className="scan-limit-text">
          <span className="scans-remaining">
            {scanStats.remainingScans} scans remaining today
          </span>
          {scanStats.isPremium ? (
            <span className="premium-badge">⭐ Premium</span>
          ) : (
            <span className="upgrade-link">
              <a href="/getpremium">Upgrade to Premium for 1000 scans/day</a>
            </span>
          )}
        </div>

        <div className="scan-limit-stats">
          <span>{scanStats.todaysScans} / {scanStats.dailyLimit} used</span>
          {!scanStats.isPremium && percentageUsed >= 80 && (
            <span className="upgrade-prompt">
              Running low! <a href="/getpremium">Upgrade now</a>
            </span>
          )}
        </div>

        <div className="progress-bar-container">
          <div
            className="progress-bar-fill"
            style={{
              width: `${percentageUsed}%`,
              backgroundColor: isCritical ? '#f44336' : isWarning ? '#ff9800' : '#4caf50'
            }}
          />
        </div>
      </div>
    </div>
  );
};

export default ScanLimitBanner;

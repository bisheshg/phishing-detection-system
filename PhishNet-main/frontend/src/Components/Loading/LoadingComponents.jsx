import React from 'react';
import './LoadingComponents.css';

// Loading Skeleton Component
export const LoadingSkeleton = ({ width = '100%', height = '20px', borderRadius = '8px', className = '' }) => (
  <div 
    className={`loading-skeleton ${className}`}
    style={{ 
      width, 
      height, 
      borderRadius,
      background: 'linear-gradient(90deg, #f0f0f0 25%, #e0e0e0 50%, #f0f0f0 75%)',
      backgroundSize: '200% 100%',
      animation: 'loading-skeleton 1.5s infinite'
    }}
  />
);

// Card Loading Skeleton
export const CardLoadingSkeleton = ({ className = '' }) => (
  <div className={`card loading-card ${className}`}>
    <LoadingSkeleton width="60%" height="24px" className="mb-3" />
    <LoadingSkeleton width="100%" height="16px" className="mb-2" />
    <LoadingSkeleton width="80%" height="16px" className="mb-2" />
    <LoadingSkeleton width="90%" height="16px" />
  </div>
);

// Dashboard Stats Loading Skeleton
export const StatsLoadingSkeleton = ({ className = '' }) => (
  <div className={`cards-row ${className}`}>
    {[1, 2, 3].map(i => (
      <div key={i} className="card stat-card">
        <LoadingSkeleton width="40%" height="14px" className="mb-2" />
        <LoadingSkeleton width="60%" height="32px" className="mb-2" />
      </div>
    ))}
  </div>
);

// List Loading Skeleton
export const ListLoadingSkeleton = ({ items = 3, className = '' }) => (
  <div className={`card ${className}`}>
    <LoadingSkeleton width="50%" height="20px" className="mb-3" />
    <div className="list">
      {Array.from({ length: items }).map((_, i) => (
        <div key={i} className="list-item">
          <LoadingSkeleton width="40%" height="16px" />
          <LoadingSkeleton width="20%" height="16px" />
          <LoadingSkeleton width="30%" height="16px" />
        </div>
      ))}
    </div>
  </div>
);

// Spinner Component
export const LoadingSpinner = ({ size = 'medium', color = 'var(--primary)', text = 'Loading...' }) => {
  const sizeClasses = {
    small: 'spinner-small',
    medium: 'spinner-medium',
    large: 'spinner-large'
  };

  return (
    <div className="loading-spinner-container">
      <div className={`loading-spinner ${sizeClasses[size]}`} style={{ borderColor: `${color}33`, borderTopColor: color }}>
      </div>
      {text && <p className="loading-text">{text}</p>}
    </div>
  );
};

// Full Page Loading
export const FullPageLoading = ({ text = 'Loading dashboard...' }) => (
  <div className="full-page-loading">
    <LoadingSpinner size="large" text={text} />
  </div>
);

// Loading States for Specific Components
export const DashboardLoadingStates = {
  Home: () => (
    <div>
      <StatsLoadingSkeleton />
      <ListLoadingSkeleton items={2} className="mt-4" />
    </div>
  ),
  
  ScanHistory: () => (
    <ListLoadingSkeleton items={5} />
  ),
  
  PhishingReports: () => (
    <ListLoadingSkeleton items={4} />
  ),
  
  Leaderboard: () => (
    <ListLoadingSkeleton items={5} className="mini-list" />
  ),
  
  Recommendations: () => (
    <ListLoadingSkeleton items={4} className="mini-list" />
  ),
  
  Settings: () => (
    <div className="card">
      <LoadingSkeleton width="40%" height="24px" className="mb-4" />
      <div className="settings-info">
        <LoadingSkeleton width="30%" height="16px" className="mb-2" />
        <LoadingSkeleton width="50%" height="16px" className="mb-2" />
        <LoadingSkeleton width="25%" height="16px" className="mb-2" />
        <LoadingSkeleton width="40%" height="16px" />
      </div>
    </div>
  )
};

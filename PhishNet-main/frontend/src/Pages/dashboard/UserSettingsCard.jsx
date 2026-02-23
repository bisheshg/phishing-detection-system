import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faUser, faEnvelope, faCrown, faShieldAlt } from '@fortawesome/free-solid-svg-icons';
import './Dashboard.css';

const UserSettingsCard = ({ settings = {} }) => {
  const {
    name = 'Guest User',
    email = 'guest@example.com',
    isPremium = false,
    coins = 0,
    memberSince
  } = settings;

  const formatDate = (dateString) => {
    if (!dateString) return 'Recently';
    try {
      return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long'
      });
    } catch {
      return 'Recently';
    }
  };

  return (
    <div className="card user-settings-card">
      <h3 className="card-title">Account Overview</h3>
      
      <div className="settings-list">
        <div className="setting-row">
          <div className="setting-icon">
            <FontAwesomeIcon icon={faUser} />
          </div>
          <div className="setting-content">
            <div className="setting-label">Name</div>
            <div className="setting-value">{name}</div>
          </div>
        </div>

        <div className="setting-row">
          <div className="setting-icon">
            <FontAwesomeIcon icon={faEnvelope} />
          </div>
          <div className="setting-content">
            <div className="setting-label">Email</div>
            <div className="setting-value">{email}</div>
          </div>
        </div>

        <div className="setting-row">
          <div className="setting-icon">
            <FontAwesomeIcon icon={faShieldAlt} />
          </div>
          <div className="setting-content">
            <div className="setting-label">Account Type</div>
            <div className="setting-value">
              {isPremium ? (
                <span className="premium-badge-inline">
                  <FontAwesomeIcon icon={faCrown} className="mr-1" />
                  Premium
                </span>
              ) : (
                <span>Free</span>
              )}
            </div>
          </div>
        </div>

        {coins !== undefined && coins !== null && (
          <div className="setting-row">
            <div className="setting-icon">💰</div>
            <div className="setting-content">
              <div className="setting-label">Coins Earned</div>
              <div className="setting-value">{coins.toLocaleString()}</div>
            </div>
          </div>
        )}

        {memberSince && (
          <div className="setting-row">
            <div className="setting-icon">📅</div>
            <div className="setting-content">
              <div className="setting-label">Member Since</div>
              <div className="setting-value">{formatDate(memberSince)}</div>
            </div>
          </div>
        )}
      </div>

      {!isPremium && (
        <div className="upgrade-prompt">
          <p className="upgrade-text">
            Upgrade to Premium for advanced features and priority support
          </p>
          <button className="upgrade-btn">
            <FontAwesomeIcon icon={faCrown} className="mr-1" />
            Upgrade Now
          </button>
        </div>
      )}
    </div>
  );
};

export default UserSettingsCard;


// import React from 'react';

// const UserSettingsCard = ({ settings }) => {
//   return (
//     <div>
//       <h2>User Settings</h2>
//       <p>Name: {settings.name}</p>
//       <p>Email: {settings.email}</p>
//       <p>Premium Account: {settings.isPremium ? 'Yes' : 'No'}</p>
//       {/* Add more settings based on your data */}
//     </div>
//   );
// };

// export default UserSettingsCard;


import React, { useState, useEffect, useContext } from "react";
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faUser, faEnvelope, faCalendar, faCoins, faShieldAlt, faSave, faEdit } from '@fortawesome/free-solid-svg-icons';
import { DashboardLoadingStates } from "../../Components/Loading/LoadingComponents";
//import { ErrorDisplay, NetworkError } from "../../Components/Error/ErrorHandling";
import { UserContext } from "../../context/UserContext";
import dashboardApi from "../../services/dashboardApi";
import "./UserSettings.css";

export default function UserSettings() {
  const { userr, isLoggedIn } = useContext(UserContext);
  const [userProfile, setUserProfile] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isEditing, setIsEditing] = useState(false);
  const [editForm, setEditForm] = useState({
    name: '',
    email: '',
    preferences: {
      emailNotifications: true,
      pushNotifications: false,
      weeklyReports: true
    }
  });
  const [saving, setSaving] = useState(false);

  const fetchUserProfile = async () => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await dashboardApi.getUserProfile();
      if (response.success) {
        const profile = response.data;
        setUserProfile(profile);
        setEditForm({
          name: profile.name || '',
          email: profile.email || '',
          preferences: profile.preferences || {
            emailNotifications: true,
            pushNotifications: false,
            weeklyReports: true
          }
        });
      } else {
        setError(response.error);
      }
    } catch (err) {
      setError(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isLoggedIn) {
      fetchUserProfile();
    }
  }, [isLoggedIn]);

  const handleRetry = () => {
    fetchUserProfile();
  };

  const handleEdit = () => {
    setIsEditing(true);
  };

  const handleCancel = () => {
    setIsEditing(false);
    if (userProfile) {
      setEditForm({
        name: userProfile.name || '',
        email: userProfile.email || '',
        preferences: userProfile.preferences || {
          emailNotifications: true,
          pushNotifications: false,
          weeklyReports: true
        }
      });
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const response = await dashboardApi.updateUserSettings(editForm);
      if (response.success) {
        setUserProfile(response.data);
        setIsEditing(false);
      } else {
        setError(response.error);
      }
    } catch (err) {
      setError(err);
    } finally {
      setSaving(false);
    }
  };

  const handleInputChange = (field, value) => {
    setEditForm(prev => ({
      ...prev,
      [field]: value
    }));
  };

  const handlePreferenceChange = (preference, value) => {
    setEditForm(prev => ({
      ...prev,
      preferences: {
        ...prev.preferences,
        [preference]: value
      }
    }));
  };

  const formatDate = (dateString) => {
    try {
      return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      });
    } catch {
      return 'Unknown';
    }
  };

  // Loading state
  if (loading) {
    return <DashboardLoadingStates.Settings />;
  }

  // Authentication check
  if (!isLoggedIn) {
    return (
      <div className="settings-card">
        <div className="auth-required">
          <FontAwesomeIcon icon={faShieldAlt} className="auth-icon" />
          <h2>Authentication Required</h2>
          <p>Please log in to view your account settings.</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error && !userProfile) {
    return (
      <div>
        <NetworkError onRetry={handleRetry} />
      </div>
    );
  }

  // Fallback user data
  const user = userProfile || userr || {
    name: 'User',
    email: 'user@example.com',
    plan: 'Free',
    createdAt: new Date().toISOString(),
    preferences: {
      emailNotifications: true,
      pushNotifications: false,
      weeklyReports: true
    }
  };

  return (
    <div className="settings-container">
      <div className="settings-card">
        <div className="settings-header">
          <h2>Account Settings</h2>
          <div className="settings-actions">
            {!isEditing ? (
              <button onClick={handleEdit} className="edit-btn">
                <FontAwesomeIcon icon={faEdit} className="mr-2" />
                Edit Profile
              </button>
            ) : (
              <div className="edit-actions">
                <button onClick={handleCancel} className="cancel-btn" disabled={saving}>
                  Cancel
                </button>
                <button onClick={handleSave} className="save-btn" disabled={saving}>
                  <FontAwesomeIcon icon={faSave} className="mr-2" />
                  {saving ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            )}
          </div>
        </div>

        <div className="settings-content">
          {/* Basic Information */}
          <div className="settings-section">
            <h3 className="section-title">
              <FontAwesomeIcon icon={faUser} className="section-icon" />
              Basic Information
            </h3>
            
            <div className="settings-grid">
              <div className="setting-item">
                <label className="setting-label">Full Name</label>
                {isEditing ? (
                  <input
                    type="text"
                    value={editForm.name}
                    onChange={(e) => handleInputChange('name', e.target.value)}
                    className="setting-input"
                    placeholder="Enter your full name"
                  />
                ) : (
                  <div className="setting-value">
                    <FontAwesomeIcon icon={faUser} className="value-icon" />
                    {user.name || 'Not provided'}
                  </div>
                )}
              </div>

              <div className="setting-item">
                <label className="setting-label">Email Address</label>
                {isEditing ? (
                  <input
                    type="email"
                    value={editForm.email}
                    onChange={(e) => handleInputChange('email', e.target.value)}
                    className="setting-input"
                    placeholder="Enter your email"
                  />
                ) : (
                  <div className="setting-value">
                    <FontAwesomeIcon icon={faEnvelope} className="value-icon" />
                    {user.email || 'Not provided'}
                  </div>
                )}
              </div>

              <div className="setting-item">
                <label className="setting-label">Account Type</label>
                <div className="setting-value">
                  <FontAwesomeIcon icon={faShieldAlt} className="value-icon" />
                  <span className={`plan-badge ${user.plan?.toLowerCase() || 'free'}`}>
                    {user.plan || 'Free'} Plan
                  </span>
                </div>
              </div>

              <div className="setting-item">
                <label className="setting-label">Member Since</label>
                <div className="setting-value">
                  <FontAwesomeIcon icon={faCalendar} className="value-icon" />
                  {formatDate(user.createdAt)}
                </div>
              </div>
            </div>
          </div>

          {/* Preferences */}
          <div className="settings-section">
            <h3 className="section-title">
              <FontAwesomeIcon icon={faShieldAlt} className="section-icon" />
              Preferences
            </h3>
            
            <div className="preferences-list">
              <div className="preference-item">
                <div className="preference-info">
                  <label className="preference-label">Email Notifications</label>
                  <p className="preference-description">
                    Receive email updates about security alerts and system notifications
                  </p>
                </div>
                <div className="preference-control">
                  {isEditing ? (
                    <label className="toggle-switch">
                      <input
                        type="checkbox"
                        checked={editForm.preferences.emailNotifications}
                        onChange={(e) => handlePreferenceChange('emailNotifications', e.target.checked)}
                      />
                      <span className="toggle-slider"></span>
                    </label>
                  ) : (
                    <span className={`toggle-state ${user.preferences?.emailNotifications ? 'active' : 'inactive'}`}>
                      {user.preferences?.emailNotifications ? 'Enabled' : 'Disabled'}
                    </span>
                  )}
                </div>
              </div>

              <div className="preference-item">
                <div className="preference-info">
                  <label className="preference-label">Push Notifications</label>
                  <p className="preference-description">
                    Get instant notifications in your browser for urgent security matters
                  </p>
                </div>
                <div className="preference-control">
                  {isEditing ? (
                    <label className="toggle-switch">
                      <input
                        type="checkbox"
                        checked={editForm.preferences.pushNotifications}
                        onChange={(e) => handlePreferenceChange('pushNotifications', e.target.checked)}
                      />
                      <span className="toggle-slider"></span>
                    </label>
                  ) : (
                    <span className={`toggle-state ${user.preferences?.pushNotifications ? 'active' : 'inactive'}`}>
                      {user.preferences?.pushNotifications ? 'Enabled' : 'Disabled'}
                    </span>
                  )}
                </div>
              </div>

              <div className="preference-item">
                <div className="preference-info">
                  <label className="preference-label">Weekly Reports</label>
                  <p className="preference-description">
                    Receive weekly summaries of your security activity and threat detection
                  </p>
                </div>
                <div className="preference-control">
                  {isEditing ? (
                    <label className="toggle-switch">
                      <input
                        type="checkbox"
                        checked={editForm.preferences.weeklyReports}
                        onChange={(e) => handlePreferenceChange('weeklyReports', e.target.checked)}
                      />
                      <span className="toggle-slider"></span>
                    </label>
                  ) : (
                    <span className={`toggle-state ${user.preferences?.weeklyReports ? 'active' : 'inactive'}`}>
                      {user.preferences?.weeklyReports ? 'Enabled' : 'Disabled'}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {/* Account Statistics */}
          {user.stats && (
            <div className="settings-section">
              <h3 className="section-title">
                <FontAwesomeIcon icon={faCoins} className="section-icon" />
                Account Statistics
              </h3>
              
              <div className="stats-grid">
                <div className="stat-item">
                  <div className="stat-value">{user.stats.totalScans || 0}</div>
                  <div className="stat-label">Total Scans</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{user.stats.threatsDetected || 0}</div>
                  <div className="stat-label">Threats Detected</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{user.stats.reportsSubmitted || 0}</div>
                  <div className="stat-label">Reports Submitted</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{user.stats.coinsEarned || 0}</div>
                  <div className="stat-label">Coins Earned</div>
                </div>
              </div>
            </div>
          )}
        </div>

        {error && isEditing && (
          <div className="settings-error">
            <ErrorDisplay
              error={error}
              showRetry={false}
              showDismiss={true}
              onDismiss={() => setError(null)}
            />
          </div>
        )}
      </div>
    </div>
  );
}


// import React, { useContext } from "react";
// import { UserContext } from "../../context/UserContext";
// import "./UserSettings.css";

// export default function Settings() {
//     const { userr, isLoggedIn } = useContext(UserContext);

//     if (!isLoggedIn) {
//         return (
//             <div className="settings-card">
//                 <h2>Please log in to view your account settings.</h2>
//             </div>
//         );
//     }

//     return (
//         <div className="settings-container">
//             <div className="settings-card">
//                 <h2>Account Information</h2>
//                 <div className="settings-info">
//                     <p><strong>Name:</strong> {userr.name}</p>
//                     <p><strong>Email:</strong> {userr.email}</p>
//                     <p><strong>Plan:</strong> {userr.plan || "Free"}</p>
//                     <p><strong>Joined:</strong> {new Date(userr.createdAt).toLocaleDateString()}</p>
//                 </div>
//             </div>
//         </div>
//     );
// }




// import React from 'react';
// import './Dashboard.css';

// const UserSettingsCard = ({ settings = {} }) => (
//   <div className="card">
//     <h3 className="card-title">User Settings</h3>
//     <div className="form-row">
//       <label>Name</label>
//       <div>{settings.name}</div>
//     </div>
//     <div className="form-row">
//       <label>Email</label>
//       <div>{settings.email}</div>
//     </div>
//     <div className="form-row">
//       <label>Premium</label>
//       <div>{settings.isPremium ? 'Yes' : 'No'}</div>
//     </div>
//   </div>
// );

// export default UserSettingsCard;

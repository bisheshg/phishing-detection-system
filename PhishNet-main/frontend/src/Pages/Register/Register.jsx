import React, { useState, useEffect, useContext } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { UserContext } from '../../context/UserContext';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faUser,
  faEnvelope,
  faPhone,
  faLock,
  faEye,
  faEyeSlash,
  faExclamationTriangle,
  faCheckCircle,
  faSpinner,
} from '@fortawesome/free-solid-svg-icons';
import '../Login/Login.css';

const Register = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    phone: '',
    password: '',
    confirmPassword: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  const navigate = useNavigate();
  const { checkUserLoggedIn } = useContext(UserContext);

  // Redirect if already logged in
  useEffect(() => {
    const checkAuth = async () => {
      const isLoggedIn = await checkUserLoggedIn();
      if (isLoggedIn) navigate('/dashboard');
    };
    checkAuth();
  }, [checkUserLoggedIn, navigate]);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    if (error) setError(null);
  };

  const validateForm = () => {
    if (!formData.name.trim()) {
      setError('Please enter your name');
      return false;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(formData.email)) {
      setError('Please enter a valid email address');
      return false;
    }
    if (!formData.phone.trim()) {
      setError('Please enter your phone number');
      return false;
    }
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    if (!passwordRegex.test(formData.password)) {
      setError('Password must be at least 8 characters and include uppercase, lowercase, and a number');
      return false;
    }
    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return false;
    }
    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validateForm()) return;

    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await fetch('http://localhost:8800/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formData.name.trim(),
          email: formData.email.toLowerCase().trim(),
          phone: formData.phone.trim(),
          password: formData.password,
        }),
      });

      const data = await response.text();

      if (!response.ok) {
        let errMsg = 'Registration failed. Please try again.';
        try {
          const json = JSON.parse(data);
          errMsg = json.error || errMsg;
        } catch (_) {}
        setError(errMsg);
        return;
      }

      setSuccess('Account created! Redirecting to sign in...');
      setTimeout(() => navigate('/login'), 1500);
    } catch (err) {
      console.error('Register error:', err);
      setError('Network error. Please check your connection and try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <h1 className="login-title">Create Account</h1>
          <p className="login-subtitle">Sign up to start detecting phishing URLs</p>
        </div>

        {error && (
          <div className="alert alert-error">
            <FontAwesomeIcon icon={faExclamationTriangle} className="alert-icon" />
            <div className="alert-content">
              <p>{error}</p>
            </div>
          </div>
        )}

        {success && (
          <div className="alert alert-success">
            <FontAwesomeIcon icon={faCheckCircle} className="alert-icon" />
            <div className="alert-content">
              <p>{success}</p>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="login-form">
          {/* Name */}
          <div className="form-group">
            <label htmlFor="name" className="form-label">Full Name</label>
            <div className="input-wrapper">
              <FontAwesomeIcon icon={faUser} className="input-icon" />
              <input
                type="text"
                id="name"
                name="name"
                value={formData.name}
                onChange={handleChange}
                className="form-input"
                placeholder="Enter your full name"
                disabled={loading}
                autoComplete="name"
                required
              />
            </div>
          </div>

          {/* Email */}
          <div className="form-group">
            <label htmlFor="email" className="form-label">Email Address</label>
            <div className="input-wrapper">
              <FontAwesomeIcon icon={faEnvelope} className="input-icon" />
              <input
                type="email"
                id="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                className="form-input"
                placeholder="Enter your email"
                disabled={loading}
                autoComplete="email"
                required
              />
            </div>
          </div>

          {/* Phone */}
          <div className="form-group">
            <label htmlFor="phone" className="form-label">Phone Number</label>
            <div className="input-wrapper">
              <FontAwesomeIcon icon={faPhone} className="input-icon" />
              <input
                type="tel"
                id="phone"
                name="phone"
                value={formData.phone}
                onChange={handleChange}
                className="form-input"
                placeholder="Enter your phone number"
                disabled={loading}
                autoComplete="tel"
                required
              />
            </div>
          </div>

          {/* Password */}
          <div className="form-group">
            <label htmlFor="password" className="form-label">Password</label>
            <div className="input-wrapper">
              <FontAwesomeIcon icon={faLock} className="input-icon" />
              <input
                type={showPassword ? 'text' : 'password'}
                id="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                className="form-input"
                placeholder="Min 8 chars, upper, lower & number"
                disabled={loading}
                autoComplete="new-password"
                required
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
                disabled={loading}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                <FontAwesomeIcon icon={showPassword ? faEyeSlash : faEye} />
              </button>
            </div>
          </div>

          {/* Confirm Password */}
          <div className="form-group">
            <label htmlFor="confirmPassword" className="form-label">Confirm Password</label>
            <div className="input-wrapper">
              <FontAwesomeIcon icon={faLock} className="input-icon" />
              <input
                type={showConfirm ? 'text' : 'password'}
                id="confirmPassword"
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleChange}
                className="form-input"
                placeholder="Re-enter your password"
                disabled={loading}
                autoComplete="new-password"
                required
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowConfirm(!showConfirm)}
                disabled={loading}
                aria-label={showConfirm ? 'Hide password' : 'Show password'}
              >
                <FontAwesomeIcon icon={showConfirm ? faEyeSlash : faEye} />
              </button>
            </div>
          </div>

          <button type="submit" className="submit-button" disabled={loading}>
            {loading ? (
              <>
                <FontAwesomeIcon icon={faSpinner} spin className="button-icon" />
                Creating Account...
              </>
            ) : (
              'Create Account'
            )}
          </button>
        </form>

        <div className="login-footer">
          <p>
            Already have an account?{' '}
            <Link to="/login" className="signup-link">
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Register;

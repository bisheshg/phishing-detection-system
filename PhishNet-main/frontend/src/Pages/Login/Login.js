import React, { useState, useEffect, useContext } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { UserContext } from '../../context/UserContext';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { 
  faEnvelope, 
  faLock, 
  faEye, 
  faEyeSlash,
  faExclamationTriangle,
  faCheckCircle,
  faSpinner,
  faClock
} from '@fortawesome/free-solid-svg-icons';
import './Login.css';

const Login = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);
  const [remainingAttempts, setRemainingAttempts] = useState(null);
  const [lockoutInfo, setLockoutInfo] = useState(null);
  const [lockoutTimer, setLockoutTimer] = useState(null);

  const navigate = useNavigate();
  const { checkUserLoggedIn } = useContext(UserContext);

  // Check if already logged in
  useEffect(() => {
    const checkAuth = async () => {
      const isLoggedIn = await checkUserLoggedIn();
      if (isLoggedIn) {
        navigate('/dashboard');
      }
    };
    checkAuth();
  }, [checkUserLoggedIn, navigate]);

  // Countdown timer for lockout
  useEffect(() => {
    if (lockoutInfo && lockoutInfo.remainingMinutes > 0) {
      const interval = setInterval(() => {
        setLockoutInfo(prev => {
          if (!prev || prev.remainingMinutes <= 0) {
            clearInterval(interval);
            setLockoutTimer(null);
            return null;
          }
          
          const newRemaining = prev.remainingMinutes - (1/60); // Decrease by 1 second
          if (newRemaining <= 0) {
            clearInterval(interval);
            setLockoutTimer(null);
            return null;
          }
          
          return {
            ...prev,
            remainingMinutes: newRemaining
          };
        });
      }, 1000);
      
      setLockoutTimer(interval);
      
      return () => clearInterval(interval);
    }
  }, [lockoutInfo]);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
    // Clear errors when user starts typing
    if (error) setError(null);
  };

  const validateForm = () => {
    if (!formData.email || !formData.password) {
      setError('Please fill in all fields');
      return false;
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(formData.email)) {
      setError('Please enter a valid email address');
      return false;
    }

    return true;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;
    
    if (lockoutInfo) {
      setError(`Account is locked. Please wait ${Math.ceil(lockoutInfo.remainingMinutes)} more minutes.`);
      return;
    }

    setLoading(true);
    setError(null);
    setSuccess(null);

    try {
      const response = await fetch('http://localhost:8800/api/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          email: formData.email.toLowerCase(),
          password: formData.password
        })
      });

      const data = await response.json();

      if (!response.ok) {
        // Handle different error codes
        if (data.code === 'AUTH_RATE_LIMIT_EXCEEDED') {
          setLockoutInfo({
            remainingMinutes: data.remainingMinutes || 15
          });
          setError(data.error || 'Too many failed attempts. Please try again later.');
        } else if (data.code === 'INVALID_CREDENTIALS') {
          setRemainingAttempts(data.remainingAttempts);
          setError(data.error || 'Invalid email or password');
        } else {
          setError(data.error || 'Login failed. Please try again.');
        }
        return;
      }

      // Success
      setSuccess('Login successful! Redirecting...');
      setRemainingAttempts(null);
      setLockoutInfo(null);
      
      // Wait a moment before redirecting
      setTimeout(async () => {
        await checkUserLoggedIn();
        navigate('/dashboard');
      }, 1000);

    } catch (err) {
      console.error('Login error:', err);
      setError('Network error. Please check your connection and try again.');
    } finally {
      setLoading(false);
    }
  };

  const formatLockoutTime = (minutes) => {
    if (minutes >= 1) {
      return `${Math.ceil(minutes)} minute${Math.ceil(minutes) !== 1 ? 's' : ''}`;
    }
    const seconds = Math.ceil(minutes * 60);
    return `${seconds} second${seconds !== 1 ? 's' : ''}`;
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <h1 className="login-title">Welcome Back</h1>
          <p className="login-subtitle">Sign in to access your account</p>
        </div>

        {/* Lockout Warning */}
        {lockoutInfo && (
          <div className="alert alert-warning">
            <FontAwesomeIcon icon={faClock} className="alert-icon" />
            <div className="alert-content">
              <strong>Account Temporarily Locked</strong>
              <p>Too many failed login attempts. Please try again in {formatLockoutTime(lockoutInfo.remainingMinutes)}.</p>
            </div>
          </div>
        )}

        {/* Error Message */}
        {error && !lockoutInfo && (
          <div className="alert alert-error">
            <FontAwesomeIcon icon={faExclamationTriangle} className="alert-icon" />
            <div className="alert-content">
              <p>{error}</p>
              {remainingAttempts !== null && remainingAttempts > 0 && (
                <small className="attempts-warning">
                  {remainingAttempts} attempt{remainingAttempts !== 1 ? 's' : ''} remaining before lockout
                </small>
              )}
            </div>
          </div>
        )}

        {/* Success Message */}
        {success && (
          <div className="alert alert-success">
            <FontAwesomeIcon icon={faCheckCircle} className="alert-icon" />
            <div className="alert-content">
              <p>{success}</p>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit} className="login-form">
          {/* Email Field */}
          <div className="form-group">
            <label htmlFor="email" className="form-label">
              Email Address
            </label>
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
                disabled={loading || lockoutInfo}
                autoComplete="email"
                required
              />
            </div>
          </div>

          {/* Password Field */}
          <div className="form-group">
            <label htmlFor="password" className="form-label">
              Password
            </label>
            <div className="input-wrapper">
              <FontAwesomeIcon icon={faLock} className="input-icon" />
              <input
                type={showPassword ? 'text' : 'password'}
                id="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                className="form-input"
                placeholder="Enter your password"
                disabled={loading || lockoutInfo}
                autoComplete="current-password"
                required
              />
              <button
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
                disabled={loading || lockoutInfo}
                aria-label={showPassword ? 'Hide password' : 'Show password'}
              >
                <FontAwesomeIcon icon={showPassword ? faEyeSlash : faEye} />
              </button>
            </div>
          </div>

          {/* Remember Me & Forgot Password */}
          <div className="form-options">
            <label className="checkbox-label">
              <input type="checkbox" className="checkbox-input" />
              <span>Remember me</span>
            </label>
            <Link to="/forgot-password" className="forgot-password-link">
              Forgot password?
            </Link>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            className="submit-button"
            disabled={loading || lockoutInfo}
          >
            {loading ? (
              <>
                <FontAwesomeIcon icon={faSpinner} spin className="button-icon" />
                Signing In...
              </>
            ) : lockoutInfo ? (
              <>
                <FontAwesomeIcon icon={faClock} className="button-icon" />
                Locked - Wait {formatLockoutTime(lockoutInfo.remainingMinutes)}
              </>
            ) : (
              'Sign In'
            )}
          </button>
        </form>

        {/* Sign Up Link */}
        <div className="login-footer">
          <p>
            Don't have an account?{' '}
            <Link to="/register" className="signup-link">
              Sign up now
            </Link>
          </p>
        </div>

        {/* Security Notice */}
        <div className="security-notice">
          <FontAwesomeIcon icon={faExclamationTriangle} className="notice-icon" />
          <small>
            For security reasons, accounts are temporarily locked after 5 failed login attempts.
          </small>
        </div>
      </div>
    </div>
  );
};

export default Login;



// import React, { useEffect, useState } from 'react';
// import { useNavigate } from "react-router-dom";
// import './Login.css';

// import { UserContext } from '../../context/UserContext';
// import { useContext } from 'react';

// import axios from 'axios';

// const Login = () => {
//     const { isLoggedIn, userr, checkUserLoggedIn, handleLogout } = useContext(UserContext);

//     const navigate = useNavigate();
//     const [email, setEmail] = useState("");
//     const [password, setPassword] = useState("");

//     const [email1, setEmail1] = useState("");
//     const [password1, setPassword1] = useState("");
//     const [phone1, setPhone1] = useState("");
//     const [name1, setName1] = useState("");

//     // Register action
//     const handleClick1 = async (e) => {
//         e.preventDefault();
//         if (!validateEmail(email1)) {
//             alert('Invalid email address');
//             return;
//         }
//         if (!validatePassword(password1)) {
//             alert('Password too weak. Try again.');
//             return;
//         }
//         if (!name1 || !phone1) {
//             alert('Please fill all the fields first.');
//             return;
//         }

//         const formData = {
//             email: email1,
//             name: name1,
//             phone: phone1,
//             password: password1
//         }
//         console.log(formData)

//         try {
//             const response = await axios.post('http://localhost:8800/api/auth/register', formData);
//             console.log(response.data);
//             console.log("Register succesful")
//             navigate("/");
//         } catch (error) {
//             console.error(error.response);
//         }
//     };

//     const validatePassword = (password) => {
//         const passwordPattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
//         return passwordPattern.test(password);
//     };

//     const validateEmail = (email) => {
//         const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//         return emailPattern.test(email);
//     };

//     // Login action
//     const handleClick = async (e) => {
//         e.preventDefault();
//         if (!email || !password) {
//             alert('Please fill all the fields first.');
//             return;
//         }
//         const formData = {
//             email: email,
//             password: password
//         }

//         try {
//             const response = await axios.post('http://localhost:8800/api/auth/login', formData, {
//                 withCredentials: true,
//                 credentials: "include",
//             });
//             checkUserLoggedIn();
//             console.log("Login succesful");
//             navigate("/");
//         } catch (error) {
//             console.error(error.response);
//         }
//     };

//     const [containerClass, setContainerClass] = useState('');

//     const handleRegisterClick = () => {
//         setContainerClass('active');
//     };

//     const handleLoginClick = () => {
//         setContainerClass('close');
//     };


//     return (
//         <>
//             <div id="LoginReg" className={containerClass}>
//                 <div className="Login">
//                     <div className="content">
//                         <h1>Log In</h1>
//                         <label className="inp" htmlFor="usernameInput">
//                             <input placeholder="Enter your email" id="usernameInput" type="text" value={email} onChange={(e) => setEmail(e.target.value)} />
//                             <span className="label">Email</span>
//                             <span className="focus-bg"></span>
//                         </label>
//                         <label className="inp" htmlFor="passwordInput">
//                             <input placeholder="Enter your password" id="passwordInput" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
//                             <span className="label">Password</span>
//                             <span className="focus-bg"></span>
//                         </label>
//                         <input className="LoginBtn" type="button" onClick={handleClick} value="Sign In" />
//                     </div>
//                 </div>

//                 <div className="page front">
//                     <div className="content">
//                         <svg
//                             xmlns="http://www.w3.org/2000/svg"
//                             width="96"
//                             height="96"
//                             viewBox="0 0 24 24"
//                             fill="none"
//                             stroke="currentColor"
//                             strokeWidth="2"
//                             strokeLinecap="round"
//                             strokeLinejoin="round"
//                             className="feather feather-user-plus"
//                         >
//                             <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
//                             <circle cx="8.5" cy="7" r="4" />
//                             <line x1="20" y1="8" x2="20" y2="14" />
//                             <line x1="23" y1="11" x2="17" y2="11" />
//                         </svg>
//                         <h1>Welcome Back!</h1>
//                         <p>To stay connected with us, please log in with your personal info</p>
//                         <button type="button" id="register" onClick={handleRegisterClick}>
//                             Login
//                         </button>
//                     </div>
//                 </div>

//                 <div className="page back">
//                     <div className="content">
//                         <svg
//                             xmlns="http://www.w3.org/2000/svg"
//                             width="96"
//                             height="96"
//                             viewBox="0 0 24 24"
//                             fill="none"
//                             stroke="currentColor"
//                             strokeWidth="2"
//                             strokeLinecap="round"
//                             strokeLinejoin="round"
//                             className="feather feather-log-in"
//                         >
//                             <path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" />
//                             <polyline points="10 17 15 12 10 7" />
//                             <line x1="15" y1="12" x2="3" y2="12" />
//                         </svg>
//                         <h1>Hello !</h1>
//                         <p>Enter your personal details and start the journey with us.</p>
//                         <button type="button" id="login" onClick={handleLoginClick}>
//                             Register
//                         </button>
//                     </div>
//                 </div>

//                 <div className="Register">
//                     <div className="content">
//                         <h1>Sign Up</h1>
//                         <label className="inp" htmlFor="emailInput">
//                             <input placeholder="Enter your email" id="emailInput" type="email" value={email1} onChange={(e) => setEmail1(e.target.value)} />
//                             {/* <span className="label">Email</span> */}
//                             <span className="focus-bg"></span>
//                         </label>
//                         <label className="inp" htmlFor="nameInput">
//                             <input placeholder="Enter your name" id="nameInput" type="text" value={name1} onChange={(e) => setName1(e.target.value)} />
//                             {/* <span className="label">Name</span> */}
//                             <span className="focus-bg"></span>
//                         </label>
//                         <label className="inp" htmlFor="phoneInput">
//                             <input placeholder="Enter your phone number" id="phoneInput" type="text" value={phone1} onChange={(e) => setPhone1(e.target.value)} />
//                             {/* <span className="label">Phone Number</span> */}
//                             <span className="focus-bg"></span>
//                         </label>
//                         <label className="inp" htmlFor="passwordInput">
//                             <input placeholder="Enter your password" id="passwordInput" type="password" value={password1} onChange={(e) => setPassword1(e.target.value)} />
//                             {/* <span className="label">Password</span> */}
//                             <span className="focus-bg"></span>
//                         </label>
//                         <input className="LoginBtn" type="button" onClick={handleClick1} value="Sign Up" />
//                     </div>
//                 </div>
//             </div>
//         </>
//     );
// };

// export default Login;
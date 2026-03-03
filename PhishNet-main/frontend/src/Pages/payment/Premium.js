import React, { useState, useContext } from "react";
import { Link } from "react-router-dom";
import { UserContext } from '../../context/UserContext';
import "./Premium.css";
import axios from "axios";

const API = 'http://localhost:8800/api';

export default function Premium() {
  const { isLoggedIn, userr, checkUserLoggedIn } = useContext(UserContext);
  const [paymentStatus, setPaymentStatus] = useState(null); // 'success' | 'error' | null
  const [paymentMsg, setPaymentMsg] = useState('');

  const gradientColors = ["#67E0DD", "#A6D8DF", "#C5E8E2", "#94BBDF", "#DBDAE0", "#FAE8E1"];
  const gradientStyle = {
    background: `linear-gradient(to right, ${gradientColors.join(",")})`,
    minHeight: "80vh",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
  };

  const handlePayment = async () => {
    if (!isLoggedIn) {
      setPaymentStatus('error');
      setPaymentMsg('Please sign in to purchase Premium.');
      return;
    }
    if (userr.isPremium) {
      setPaymentStatus('error');
      setPaymentMsg('You already have an active Premium subscription!');
      return;
    }

    try {
      const { data } = await axios.post(
        `${API}/pay/orders`,
        { amount: 350 },
        { withCredentials: true }
      );
      initPayment(data.data);
    } catch (error) {
      setPaymentStatus('error');
      setPaymentMsg('Could not initiate payment. Please try again.');
    }
  };

  const initPayment = (data) => {
    const options = {
      key: "rzp_test_Uf8e5ZC0BrgIFH",
      amount: data.amount,
      currency: data.currency,
      description: "PhishNet Premium Subscription",
      order_id: data.id,
      handler: async (response) => {
        try {
          const { data: verifyData } = await axios.post(
            `${API}/pay/verify`,
            { ...response, userId: userr._id },
            { withCredentials: true }
          );
          if (verifyData.status) {
            setPaymentStatus('success');
            setPaymentMsg('Premium activated! Enjoy 1000 scans/day.');
            // Refresh user context so isPremium updates everywhere
            await checkUserLoggedIn();
          } else {
            setPaymentStatus('error');
            setPaymentMsg('Payment verification failed. Contact support.');
          }
        } catch {
          setPaymentStatus('error');
          setPaymentMsg('Verification error. Please contact support.');
        }
      },
      theme: { color: "#6366f1" },
    };
    const rzp = new window.Razorpay(options);
    rzp.open();
  };

  return (
    <div style={gradientStyle}>
      <div className="premium_page">
        <div className="pre_heading">
          <h1>We scale with your needs</h1>
          <h4>Protect yourself with the plan that fits you best.</h4>
          {userr?.isPremium && (
            <div className="premium-active-badge">⭐ Premium Active</div>
          )}
        </div>

        {/* Inline payment status */}
        {paymentStatus && (
          <div className={`payment-notice ${paymentStatus === 'success' ? 'notice-success' : 'notice-error'}`}>
            {paymentMsg}
          </div>
        )}

        <div className="premium_flex">
          {/* Free tier */}
          <div className="pre_flex1">
            <div className="pre_head_flex">Essentials</div>
            <div className="pre_body">
              <h3>Always Free</h3>
              <ul className="feature-list">
                <li>✓ 50 scans per day</li>
                <li>✓ Full ML analysis</li>
                <li>✓ Scan history</li>
                <li>✓ SHAP explainability</li>
              </ul>
              {isLoggedIn
                ? <span className="current-plan-badge">Your current plan</span>
                : <Link to="/register" className="pre_b1_link"><button className="pre_b1">Get Started Free</button></Link>
              }
            </div>
          </div>

          {/* Premium tier */}
          <div className="pre_flex1 pre_featured">
            <div className="pre_head_flex">Premium</div>
            <div className="pre_body">
              <h3>₹350 / Month</h3>
              <ul className="feature-list">
                <li>✓ 1,000 scans per day</li>
                <li>✓ Priority analysis</li>
                <li>✓ Advanced statistics</li>
                <li>✓ All free features</li>
              </ul>
              {userr?.isPremium
                ? <span className="current-plan-badge">Active ✓</span>
                : <button onClick={handlePayment} className="pre_b2">
                    {!isLoggedIn ? 'Sign In to Purchase' : 'Purchase Now'}
                  </button>
              }
            </div>
          </div>

          {/* Chrome Extension */}
          <div className="pre_flex1">
            <div className="pre_head_flex">Chrome Extension</div>
            <div className="pre_body">
              <h3>Surf Safely!</h3>
              <ul className="feature-list">
                <li>✓ Real-time URL checking</li>
                <li>✓ Instant warnings</li>
                <li>✓ Works with Premium</li>
                <li>✓ Lightweight & fast</li>
              </ul>
              <button className="pre_b3">Coming Soon</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

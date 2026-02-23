// import React, { useContext, useState, useEffect } from 'react';
// import { Link, useLocation, useNavigate } from 'react-router-dom';
// import { UserContext } from '../../context/UserContext';
// import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
// import { 
//   faHome, 
//   faFileAlt, 
//   faChartBar, 
//   faFolderOpen,
//   faBars,
//   faTimes,
//   faSignInAlt,
//   faSignOutAlt,
//   faUser
// } from '@fortawesome/free-solid-svg-icons';
// import logo from './logo.svg';
// import './Navbar.css';

// const Navbar = () => {
//   const { isLoggedIn, handleLogout, userr } = useContext(UserContext);
//   const location = useLocation();
//   const navigate = useNavigate();
//   const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
//   const [scrolled, setScrolled] = useState(false);

//   const navbarList = [
//     {
//       title: "Home",
//       url: "/",
//       icon: faHome,
//       public: true
//     },
//     {
//       title: "Report",
//       url: "/report",
//       icon: faFileAlt,
//       public: false
//     },
//     {
//       title: "Dashboard",
//       url: "/dashboard",
//       icon: faChartBar,
//       public: false
//     },
//     {
//       title: "Reports",
//       url: "/allreports",
//       icon: faFolderOpen,
//       public: false
//     },
//   ];

//   // Handle scroll effect
//   useEffect(() => {
//     const handleScroll = () => {
//       setScrolled(window.scrollY > 20);
//     };

//     window.addEventListener('scroll', handleScroll);
//     return () => window.removeEventListener('scroll', handleScroll);
//   }, []);

//   // Close mobile menu on route change
//   useEffect(() => {
//     setMobileMenuOpen(false);
//   }, [location.pathname]);

//   // Prevent body scroll when mobile menu is open
//   useEffect(() => {
//     if (mobileMenuOpen) {
//       document.body.style.overflow = 'hidden';
//     } else {
//       document.body.style.overflow = '';
//     }
//     return () => {
//       document.body.style.overflow = '';
//     };
//   }, [mobileMenuOpen]);

//   const toggleMobileMenu = () => {
//     setMobileMenuOpen(!mobileMenuOpen);
//   };

//   const handleLogoutClick = () => {
//     handleLogout();
//     navigate('/');
//     setMobileMenuOpen(false);
//   };

//   const isLoginPage = location.pathname === '/login';

//   return (
//     <nav className={`navbar ${scrolled ? 'navbar-scrolled' : ''}`}>
//       <div className="navbar-container">
//         {/* Logo */}
//         <Link to="/" className="navbar-logo" onClick={() => setMobileMenuOpen(false)}>
//           <img src={logo} alt="PhishNet Logo" className="logo-image" />
//           <span className="logo-text">PhishNet</span>
//         </Link>

//         {/* Desktop Navigation */}
//         <ul className="navbar-menu">
//           {navbarList.map((item, index) => {
//             // Show all items if logged in, only public items if not
//             if (!item.public && !isLoggedIn) return null;
            
//             const isActive = location.pathname === item.url;
            
//             return (
//               <li key={index} className={`nav-item ${isActive ? 'active' : ''}`}>
//                 <Link to={item.url} className="nav-link">
//                   <FontAwesomeIcon icon={item.icon} className="nav-icon" />
//                   <span className="nav-text">{item.title}</span>
//                 </Link>
//               </li>
//             );
//           })}
//         </ul>

//         {/* Auth Buttons */}
//         <div className="navbar-actions">
//           {isLoggedIn ? (
//             <>
//               {userr?.name && (
//                 <div className="user-greeting">
//                   <FontAwesomeIcon icon={faUser} className="user-icon" />
//                   <span className="user-name">Hi, {userr.name.split(' ')[0]}</span>
//                 </div>
//               )}
//               <button onClick={handleLogoutClick} className="nav-button logout-button">
//                 <FontAwesomeIcon icon={faSignOutAlt} className="button-icon" />
//                 <span>Sign Out</span>
//               </button>
//             </>
//           ) : (
//             !isLoginPage && (
//               <Link to="/login" className="nav-button login-button">
//                 <FontAwesomeIcon icon={faSignInAlt} className="button-icon" />
//                 <span>Sign In</span>
//               </Link>
//             )
//           )}
//         </div>

//         {/* Mobile Menu Toggle */}
//         <button 
//           className="mobile-menu-toggle"
//           onClick={toggleMobileMenu}
//           aria-label="Toggle menu"
//           aria-expanded={mobileMenuOpen}
//         >
//           <FontAwesomeIcon icon={mobileMenuOpen ? faTimes : faBars} />
//         </button>
//       </div>

//       {/* Mobile Menu */}
//       <div className={`mobile-menu ${mobileMenuOpen ? 'mobile-menu-open' : ''}`}>
//         <div className="mobile-menu-header">
//           <div className="mobile-menu-brand">
//             <img src={logo} alt="PhishNet Logo" className="mobile-logo" />
//             <span>PhishNet</span>
//           </div>
//         </div>

//         <ul className="mobile-nav-list">
//           {navbarList.map((item, index) => {
//             if (!item.public && !isLoggedIn) return null;
            
//             const isActive = location.pathname === item.url;
            
//             return (
//               <li key={index} className={`mobile-nav-item ${isActive ? 'active' : ''}`}>
//                 <Link 
//                   to={item.url} 
//                   className="mobile-nav-link"
//                   onClick={() => setMobileMenuOpen(false)}
//                 >
//                   <FontAwesomeIcon icon={item.icon} className="mobile-nav-icon" />
//                   <span>{item.title}</span>
//                 </Link>
//               </li>
//             );
//           })}
//         </ul>

//         <div className="mobile-menu-footer">
//           {isLoggedIn ? (
//             <button onClick={handleLogoutClick} className="mobile-auth-button logout">
//               <FontAwesomeIcon icon={faSignOutAlt} className="mobile-button-icon" />
//               <span>Sign Out</span>
//             </button>
//           ) : (
//             !isLoginPage && (
//               <Link 
//                 to="/login" 
//                 className="mobile-auth-button login"
//                 onClick={() => setMobileMenuOpen(false)}
//               >
//                 <FontAwesomeIcon icon={faSignInAlt} className="mobile-button-icon" />
//                 <span>Sign In</span>
//               </Link>
//             )
//           )}
//         </div>
//       </div>

//       {/* Mobile Menu Overlay */}
//       {mobileMenuOpen && (
//         <div 
//           className="mobile-menu-overlay" 
//           onClick={() => setMobileMenuOpen(false)}
//           aria-hidden="true"
//         />
//       )}
//     </nav>
//   );
// };

// export default Navbar;



import React, { useContext } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { UserContext } from '../../context/UserContext';
import Navbarlist from './Navbarlist';
import logo from './logo.svg'
import './Navbar.css'

const Navbar = () => {
  const { isLoggedIn, checkUserLoggedIn, handleLogout } = useContext(UserContext);
  const location = useLocation();
  const isLoginPage = location.pathname === '/login';

  const renderAuthButton = () => {
    if (isLoggedIn) {
      return (
        <div className="ml-auto">
          {isLoginPage ? null : (
            <button onClick={handleLogout} className="login-button">
              <Link to="/">Sign out</Link>
            </button>
          )}
        </div>
      );
    } else {
      return (
        <div className="ml-auto">
          {isLoginPage ? null : (
            <div className="login-button">
              <Link to="/login">Sign In</Link>
            </div>
          )}
        </div>
      );
    }
  };

  const gradientColors =['#67E0DD', '#A6D8DF', '#C5E8E2', '#94BBDF', '#DBDAE0', '#FAE8E1'];

  const gradientStyle = {
    background: `linear-gradient(to right, ${gradientColors.join(',')})`,
    backgroundColor:'white'
  };

  return (
    <nav className="navbar" style={gradientStyle}>
      <div className="logo-links">
        <h2>
          <Link to="/" style={{ textDecoration: 'none', color: 'indigo' }}>
            <img src={logo} alt="" srcset="" />
          </Link>
        </h2>
        <ul className="navitems">
          <Navbarlist />
          {/* <li>
            <a href="http://localhost:8000" target="_blank" style={{ textDecoration: 'none', color: 'black' }}>
              Chatbot
            </a>
          </li> */}
        </ul>
      </div>
      <div id="google_translate_element"></div>
      {/* <button className="login-button">
        <Link to="/lawyer">For Advocates</Link>
      </button> */}
      {renderAuthButton()}
    </nav>
  );
};

export default Navbar;

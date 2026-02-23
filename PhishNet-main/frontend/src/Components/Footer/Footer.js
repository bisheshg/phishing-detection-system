

import React from 'react';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faGithub, faTwitter, faLinkedin } from '@fortawesome/free-brands-svg-icons';
import './Footer.css';

const Footer = () => {
  return (
    <footer className="footer">
      <p className="footer-text">
        Major project on Phishing Site Detection by SEC students
      </p>
      <div className="footer-social">
        <a href="https://github.com" target="_blank" rel="noopener noreferrer">
          <FontAwesomeIcon icon={faGithub} />
        </a>
        <a href="https://twitter.com" target="_blank" rel="noopener noreferrer">
          <FontAwesomeIcon icon={faTwitter} />
        </a>
        <a href="https://linkedin.com" target="_blank" rel="noopener noreferrer">
          <FontAwesomeIcon icon={faLinkedin} />
        </a>
      </div>
    </footer>
  );
};

export default Footer;

// import React from "react";
// import { BsHeartFill } from "react-icons/bs";
// import "./Footer.css";

// const Footer = () => {
//     return (
//         <footer style={footerStyle}>
//             <p>
//                 Major project on Phishing Site detetion by SEC students.
                
                
//             </p>
//         </footer>
//     );
// };

// const footerStyle = {
//     textAlign: "center",
//     padding: "1rem",
//     background: "#005a7b",
// };

// export default Footer;
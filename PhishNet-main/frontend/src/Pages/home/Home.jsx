import React, { useState } from 'react';
import male from './male.png';
import { useNavigate } from 'react-router-dom';
import './App.css';

// Constants
const GRADIENT_COLORS = [
  "#67E0DD",
  '#A6D8DF',
  '#C5E8E2',
  '#94BBDF',
  '#DBDAE0',
  '#FAE8E1',
];

const SCAN_STEPS = [
  'Initiating scan...',
  'Analyzing domain...',
  'Finalizing results...',
];

// Helper function for delays
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Scan Messages Component
const ScanMessages = ({ messages }) => (
  <div className="scan-messages">
    {messages.map((msg, index) => (
      <div key={index} className="scan-message animate-fade-in">
        {msg}
      </div>
    ))}
  </div>
);

// Scan Input Component
const ScanInput = ({ inputUrl, setInputUrl, handleScan, scanning }) => (
  <div className="scan-input-container">
    <input
      type="text"
      placeholder="Enter URL to scan..."
      className="scan-input"
      value={inputUrl}
      onChange={(e) => setInputUrl(e.target.value)}
      disabled={scanning}
      aria-label="URL to scan"
    />
    <button
      onClick={handleScan}
      className={`scan-btn ${scanning ? 'scanning' : ''}`}
      disabled={scanning}
    >
      {scanning ? 'Scanning...' : 'Scan'}
    </button>
  </div>
);

const App = () => {
  const [inputUrl, setInputUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanMessages, setScanMessages] = useState([]);
  const [progress, setProgress] = useState(0);
  const navigate = useNavigate();

  const handleScan = async () => {
    if (!inputUrl.trim()) {
      alert("Please enter a URL to scan.");
      return;
    }

    setScanning(true);
    setScanMessages([]);
    setProgress(0);

    for (let i = 0; i < SCAN_STEPS.length; i++) {
      await delay(700);
      setScanMessages((prev) => [...prev, SCAN_STEPS[i]]);
      setProgress(((i + 1) / SCAN_STEPS.length) * 100);
    }

    await delay(500);
    setScanning(false);
    setProgress(100);
    navigate('/results', { state: { inputUrl } });
  };

  return (
    <div
      className="app-gradient"
      style={{ background: `linear-gradient(to right, ${GRADIENT_COLORS.join(',')})` }}
    >
      <div className="bg-overlay"></div>
      <div className="scan-card animate-fade-in" aria-busy={scanning}>
        <h2 className="scan-title">SECURE YOUR BROWSING</h2>
        <p className="scan-subtitle">
          phishDetect - Your Shield Against Phishing Threats in Real-Time.
        </p>

        <ScanInput
          inputUrl={inputUrl}
          setInputUrl={setInputUrl}
          handleScan={handleScan}
          scanning={scanning}
        />

        {scanning && <ScanMessages messages={scanMessages} />}

        {/* Progress Bar */}
        <div className="progress-bar-container">
          <div
            className="progress-bar"
            style={{ width: `${progress}%` }}
          ></div>
        </div>

        <div className="scan-image-container">
          <img src={male} alt="Cyber Guard" className="scan-image" />
        </div>
      </div>
    </div>
  );
};

export default App;



// import React, { useState } from 'react';
// import male from './male.png';
// import { useNavigate } from 'react-router-dom';
// import './App.css';

// const App = () => {
//   const gradientColors = [
//     "#67E0DD",
//     '#A6D8DF',
//     '#C5E8E2',
//     '#94BBDF',
//     '#DBDAE0',
//     '#FAE8E1',
//   ];

//   const [inputUrl, setInputUrl] = useState('');
//   const navigate = useNavigate();
//   const [scanning, setScanning] = useState(false);
//   const [scanMessages, setScanMessages] = useState([]);

//   const handleScan = async () => {
//     if (!inputUrl) {
//       alert("Please enter a URL to scan.");
//       return;
//     }
//     setScanning(true);
//     setScanMessages([]);

//     const scanSteps = [
//       'Initiating scan...',
//       'Analyzing domain...',
//       'Finalizing results...',
//     ];

//     const scanPromises = scanSteps.map((step, index) => {
//       return new Promise((resolve) => {
//         setTimeout(() => {
//           setScanMessages((prevMessages) => [...prevMessages, step]);
//           resolve();
//         }, index * 750); // Faster animation
//       });
//     });

//     Promise.all(scanPromises).then(() => {
//       setTimeout(() => {
//         setScanning(false);
//         navigate('/results', { state: { inputUrl } });
//       }, 500);
//     });
//   };

//   return (
//     <div
//       className="app-gradient"
//       style={{ background: `linear-gradient(to right, ${gradientColors.join(',')})` }}
//     >
//       <div className="bg-overlay"></div>
//       <div className="scan-card animate-fade-in">
//         <h2 className="scan-title">SECURE YOUR BROWSING</h2>
//         <p className="scan-subtitle">phishDetect - Your Shield Against Phishing Threats in Real-Time.</p>

//         <div className="scan-input-container">
//           <input
//             type="text"
//             placeholder="Enter URL to scan..."
//             className="scan-input"
//             value={inputUrl}
//             onChange={(e) => setInputUrl(e.target.value)}
//             disabled={scanning}
//           />
//           <button
//             onClick={handleScan}
//             className="scan-btn"
//             disabled={scanning}
//           >
//             {scanning ? 'Scanning...' : 'Scan'}
//           </button>
//         </div>

//         {scanning && (
//           <div className="scan-messages">
//             {scanMessages.map((msg, index) => (
//               <div key={index}>{msg}</div>
//             ))}
//           </div>
//         )}

//         <div className="scan-image-container">
//           <img src={male} alt="Cyber Guard" className="scan-image" />
//         </div>
//       </div>
//     </div>
//   );
// };

// export default App;


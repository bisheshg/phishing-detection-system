// Layout.jsx
import React from 'react';
import Navbar from './Navbar/Navbar';
import Footer from './Footer/Footer';
import './Layout.css';

const Layout = ({ children, className = '', showFooter = true, showNavbar = true }) => {
  return (
    <div className={`layout-wrapper ${className}`}>
      {showNavbar && <Navbar />}
      <main className="layout-main">{children}</main>
      {showFooter && <Footer />}
    </div>
  );
};

export default Layout;

/* ==================== Layout.css ==================== */
/*
.layout-wrapper {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  background: #f5f7fa;
}

.layout-main {
  flex: 1;
  display: flex;
  flex-direction: column;
}

/* Page Container for Consistent Spacing */
/*
.page-container {
  max-width: 1400px;
  margin: 0 auto;
  padding: 2rem;
  width: 100%;
}

.page-container-narrow {
  max-width: 1200px;
}

.page-container-wide {
  max-width: 1600px;
}

/* Content Sections */
/*
.content-section {
  margin-bottom: 3rem;
}

.section-header {
  margin-bottom: 2rem;
}

.section-title {
  font-size: 2rem;
  font-weight: 700;
  color: #111827;
  margin: 0 0 0.5rem 0;
}

.section-subtitle {
  font-size: 1.125rem;
  color: #6b7280;
  margin: 0;
}

/* Layout Grid Utilities */
/*
.grid-2 {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 2rem;
}

.grid-3 {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 2rem;
}

.grid-4 {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 2rem;
}

/* Responsive Grid */
/*
@media (max-width: 1200px) {
  .grid-4 {
    grid-template-columns: repeat(3, 1fr);
  }
}

@media (max-width: 992px) {
  .grid-3,
  .grid-4 {
    grid-template-columns: repeat(2, 1fr);
  }
}

@media (max-width: 768px) {
  .page-container {
    padding: 1.5rem;
  }

  .grid-2,
  .grid-3,
  .grid-4 {
    grid-template-columns: 1fr;
    gap: 1.5rem;
  }

  .section-title {
    font-size: 1.5rem;
  }

  .section-subtitle {
    font-size: 1rem;
  }
}

@media (max-width: 480px) {
  .page-container {
    padding: 1rem;
  }

  .content-section {
    margin-bottom: 2rem;
  }
}

/* Spacing Utilities */
/*
.mt-1 { margin-top: 0.5rem; }
.mt-2 { margin-top: 1rem; }
.mt-3 { margin-top: 1.5rem; }
.mt-4 { margin-top: 2rem; }
.mt-5 { margin-top: 3rem; }

.mb-1 { margin-bottom: 0.5rem; }
.mb-2 { margin-bottom: 1rem; }
.mb-3 { margin-bottom: 1.5rem; }
.mb-4 { margin-bottom: 2rem; }
.mb-5 { margin-bottom: 3rem; }

.pt-1 { padding-top: 0.5rem; }
.pt-2 { padding-top: 1rem; }
.pt-3 { padding-top: 1.5rem; }
.pt-4 { padding-top: 2rem; }
.pt-5 { padding-top: 3rem; }

.pb-1 { padding-bottom: 0.5rem; }
.pb-2 { padding-bottom: 1rem; }
.pb-3 { padding-bottom: 1.5rem; }
.pb-4 { padding-bottom: 2rem; }
.pb-5 { padding-bottom: 3rem; }

/* Text Utilities */
/*
.text-center { text-align: center; }
.text-left { text-align: left; }
.text-right { text-align: right; }

.text-sm { font-size: 0.875rem; }
.text-base { font-size: 1rem; }
.text-lg { font-size: 1.125rem; }
.text-xl { font-size: 1.25rem; }
.text-2xl { font-size: 1.5rem; }

.font-normal { font-weight: 400; }
.font-medium { font-weight: 500; }
.font-semibold { font-weight: 600; }
.font-bold { font-weight: 700; }

/* Color Utilities */
/*
.text-primary { color: #667eea; }
.text-secondary { color: #6b7280; }
.text-success { color: #10b981; }
.text-danger { color: #ef4444; }
.text-warning { color: #f59e0b; }

/* Flex Utilities */
/*
.flex { display: flex; }
.flex-col { flex-direction: column; }
.flex-row { flex-direction: row; }
.items-center { align-items: center; }
.items-start { align-items: flex-start; }
.items-end { align-items: flex-end; }
.justify-center { justify-content: center; }
.justify-between { justify-content: space-between; }
.justify-around { justify-content: space-around; }
.justify-end { justify-content: flex-end; }
.gap-1 { gap: 0.5rem; }
.gap-2 { gap: 1rem; }
.gap-3 { gap: 1.5rem; }
.gap-4 { gap: 2rem; }

/* Print Styles */
/*
@media print {
  .layout-wrapper {
    background: white;
  }

  .page-container {
    max-width: 100%;
    padding: 0;
  }
}
*/


// import React from 'react';
// import Navbar from './Navbar/Navbar';
// import Footer from './Footer/Footer';
// import './Layout.css'; // Optional: Add custom styling if needed

// const Layout = ({ children }) => {
//   return (
//     <div className="layout-container">
//       <Navbar />
//       <main>{children}</main>
//       <Footer />
//     </div>
//   );
// };

// export default Layout;
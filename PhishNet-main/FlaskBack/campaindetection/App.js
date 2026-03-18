import "./App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { lazy, Suspense, useContext } from "react";
import { UserProvider, UserContext } from "./context/UserContext";

import Navbar from "./Components/Navbar/Navbar";
import Footer from "./Components/Footer/Footer";

// Lazy load pages for better performance
const Home = lazy(() => import("./Pages/home/Home"));
const Login = lazy(() => import("./Pages/Login/Login"));
const Report = lazy(() => import("./Pages/report/Report"));
const Premium = lazy(() => import("./Pages/payment/Premium"));
const Dashboard = lazy(() => import("./Pages/dashboard/Dashboard"));
const Result = lazy(() => import("./Pages/result/Result"));
const AllReports = lazy(() => import("./Pages/allreports/AllReports"));
const Statistics = lazy(() => import("./Pages/statistics/Statistics"));
const ScanHistory = lazy(() => import("./Pages/scanhistory/ScanHistory"));
const Register = lazy(() => import("./Pages/Register/Register"));
const IntelligenceDashboard = lazy(() => import("./Pages/intelligence/Intelligence"));

// Loading component
const Loading = () => (
  <div style={{ 
    display: 'flex', 
    justifyContent: 'center', 
    alignItems: 'center', 
    minHeight: '60vh' 
  }}>
    <div>Loading...</div>
  </div>
);

// 404 Not Found component
const NotFound = () => (
  <div style={{ 
    display: 'flex', 
    flexDirection: 'column',
    justifyContent: 'center', 
    alignItems: 'center', 
    minHeight: '60vh' 
  }}>
    <h1>404 - Page Not Found</h1>
    <p>The page you're looking for doesn't exist.</p>
    <a href="/">Go back home</a>
  </div>
);

// Layout component
const Layout = ({ children }) => (
  <>
    <Navbar />
    <main>{children}</main>
    <Footer />
  </>
);

// Protected Route component
const ProtectedRoute = ({ children }) => {
  const { isLoggedIn, authLoading } = useContext(UserContext);

  if (authLoading) {
    return <Loading />;
  }

  if (!isLoggedIn) {
    return <Navigate to="/login" replace />;
  }

  return children;
};

// App Routes component (needs to be inside UserProvider to use useUser)
const AppRoutes = () => {
  return (
    <BrowserRouter>
      <Layout>
        <Suspense fallback={<Loading />}>
          <Routes>
            {/* Public routes */}
            <Route path="/" element={<Home />} />
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />
            <Route path="/forgot-password" element={<Login />} />
            
            {/* Protected routes */}
            <Route 
              path="/report" 
              element={
                <ProtectedRoute>
                  <Report />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/dashboard" 
              element={
                <ProtectedRoute>
                  <Dashboard />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/results" 
              element={
                <ProtectedRoute>
                  <Result />
                </ProtectedRoute>
              } 
            />
            <Route
              path="/allreports"
              element={
                <ProtectedRoute>
                  <AllReports />
                </ProtectedRoute>
              }
            />
            <Route
              path="/statistics"
              element={
                <ProtectedRoute>
                  <Statistics />
                </ProtectedRoute>
              }
            />
            <Route
              path="/scan-history"
              element={
                <ProtectedRoute>
                  <ScanHistory />
                </ProtectedRoute>
              }
            />
            <Route
              path="/intelligence"
              element={
                <ProtectedRoute>
                  <IntelligenceDashboard />
                </ProtectedRoute>
              }
            />

            {/* Premium route - you can decide if this should be protected */}
            <Route path="/getpremium" element={<Premium />} />
            
            {/* 404 catch-all route */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Suspense>
      </Layout>
    </BrowserRouter>
  );
};

function App() {
  return (
    <UserProvider>
      <AppRoutes />
    </UserProvider>
  );
}

export default App;


// import "./App.css";
// import { BrowserRouter, Routes, Route } from "react-router-dom";
// import { UserProvider } from "./context/UserContext";

// import Navbar from "./Components/Navbar/Navbar";
// import Footer from "./Components/Footer/Footer";

// import Home from "./Pages/home/Home";
// import Login from "./Pages/Login/Login";
// import Report from "./Pages/report/Report";
// import Premium from "./Pages/payment/Premium";
// import Dashboard from "./Pages/dashboard/Dashboard";
// import Result from "./Pages/result/Result";
// import AllReports from "./Pages/allreports/AllReports";

// function App() {
//   return (
//     <UserProvider>
//       <BrowserRouter>
//         <Navbar />
//         <main>
//           <Routes>
//             <Route path="/login" element={<Login />} />
//             <Route path="/" element={<Home />} />
//             <Route path="/report" element={<Report />} />
//             <Route path="/dashboard" element={<Dashboard />} />
//             <Route path="/getpremium" element={<Premium />} />
//             <Route path="/results" element={<Result />} />
//             <Route path="/allreports" element={<AllReports />} />
//           </Routes>
//         </main>
//         <Footer />
//       </BrowserRouter>
//     </UserProvider>
//   );
// }

// export default App;



// import "./App.css";
// import Login from "./Pages/Login/Login.js";
// import Navbar from "./Components/Navbar/Navbar";
// import Footer from "./Components/Footer/Footer.js";
// import { BrowserRouter, Routes, Route } from "react-router-dom";
// import { UserProvider } from "./context/UserContext";
// import Home from "./Pages/home/Home";
// import Report from "../src/Pages/report/Report";
// import Premium from "./Pages/payment/Premium";
// import Dashboard from "./Pages/dashboard/Dashboard";
// import Result from "./Pages/result/Result";
// import AllReports from "./Pages/allreports/AllReports";

// function App() {
//     return (
//         <UserProvider>
//             <BrowserRouter>
//                 <Navbar />
//                 <main>
//                     <Routes>
//                         <Route path="/login" element={<Login />} />
//                         <Route path="/" element={<Home />} />
//                         <Route path="/report" element={<Report />} />
//                         <Route path="/dashboard" element={<Dashboard />} />
//                         <Route path="/getpremium" element={<Premium />} />
//                         <Route path="/results" element={<Result />} />
//                         <Route path="/allreports" element={<AllReports />} />
//                     </Routes>
//                 </main>
//                 <Footer />
//             </BrowserRouter>
//         </UserProvider>
//     );
// }

// export default App;




// import "./App.css";
// import Login from "./Pages/Login/Login.js";
// import Navbar from "./Components/Navbar/Navbar";
// import Footer from "./Components/Footer/Footer.js";
// import { BrowserRouter, Routes, Route } from "react-router-dom";
// import { UserProvider } from "./context/UserContext";
// import Home from "./Pages/home/Home";
// import Report from "../src/Pages/report/Report";
// import Premium from "./Pages/payment/Premium";
// import Dashboard from "./Pages/dashboard/Dashboard";
// import Result from "./Pages/result/Result";
// import AllReports from "./Pages/allreports/AllReports";

// function App() {
//     return (
//         <UserProvider>
//             <>
//                 <BrowserRouter>
//                     <Navbar />
//                     <Routes>
//                         <Route path="/login" element={<Login />} />
//                         <Route path="/" element={<Home />} />
//                         <Route path="/report" element={<Report />} />
//                         <Route path="/dashboard" element={<Dashboard />} />
//                         <Route path="/getpremium" element={<Premium />} />{" "}
//                         <Route path="/results" element={<Result />} />
//                         <Route path="/allreports" element={<AllReports />} />
//                     </Routes>
//                     <Footer />
//                 </BrowserRouter>
//             </>
//         </UserProvider>
//     );
// }

// export default App;

import React, { createContext, useState, useEffect } from 'react';
import axios from 'axios';

export const UserContext = createContext();

export const UserProvider = ({ children }) => {

   const [isLoggedIn, setIsLoggedIn] = useState(false);
   const [authLoading, setAuthLoading] = useState(true);
   const [userr, setUserr] = useState({});
   const [scanStats, setScanStats] = useState({
      totalScans: 0,
      todaysScans: 0,
      remainingScans: 50,
      dailyLimit: 50,
      isPremium: false
   });

   const checkUserLoggedIn = async () => {
      try {
         const response = await axios.get('http://localhost:8800/api/auth/user', {
            withCredentials: true,
            credentials: "include",
         });

         if (response.data.status) {
            setIsLoggedIn(true);
            setUserr(response.data.user);
            await fetchScanStatistics();
            return true;
         } else {
            setIsLoggedIn(false);
            setUserr({});
            resetScanStats();
            return false;
         }
      } catch (error) {
         console.error('Error checking user login status:', error);
         setIsLoggedIn(false);
         return false;
      } finally {
         setAuthLoading(false);
      }
   };

   const fetchScanStatistics = async () => {
      try {
         const response = await axios.get('http://localhost:8800/api/phishing/statistics', {
            withCredentials: true,
            credentials: "include",
         });

         if (response.data.success) {
            setScanStats({
               totalScans: response.data.data.totalScans,
               todaysScans: response.data.data.todaysScans,
               remainingScans: response.data.data.remainingScans,
               dailyLimit: response.data.data.dailyLimit,
               isPremium: response.data.data.isPremium
            });
         }
      } catch (error) {
         console.error('Error fetching scan statistics:', error);
      }
   };

   const resetScanStats = () => {
      setScanStats({
         totalScans: 0,
         todaysScans: 0,
         remainingScans: 50,
         dailyLimit: 50,
         isPremium: false
      });
   };


   const handleLogout = async () => {
      try {
         const response = await axios.get('http://localhost:8800/api/auth/logout', {
            withCredentials: true,
            credentials: "include",
         });
         console.log(response.data);
         setIsLoggedIn(false);
         setUserr({});
         resetScanStats();

         console.log(userr, "user deleted");

      } catch (error) {
         console.error('Error during logout:', error);
      }
   };


   useEffect(() => {
      checkUserLoggedIn();
   }, []);

   return (
      <UserContext.Provider value={{
         isLoggedIn,
         authLoading,
         userr,
         setUserr,
         checkUserLoggedIn,
         handleLogout,
         scanStats,
         fetchScanStatistics
      }}>
         {children}
      </UserContext.Provider>
   );
};

// import React, { createContext, useState, useEffect } from 'react';
// import axios from 'axios';
// import API_URLS from '../apiConfig';

// export const UserContext = createContext();

// export const UserProvider = ({ children }) => {

//    const [isLoggedIn, setIsLoggedIn] = useState(false);
//    const [userr, setUserr] = useState({});

//    // Function to set user details directly after login
//    const setUserDetails = (userObject) => {
//       setIsLoggedIn(true);
//       setUserr(userObject);
//    };

//    const checkUserLoggedIn = async () => {
//       try {
//          // This includes cookies in the request
//          const response = await axios.get(`${API_URLS.nodeBackend}/auth/user`, {
//             withCredentials: true,
//             credentials: "include",
//          });
//          if (response.data.status) {
//             setIsLoggedIn(true);
//             setUserr(response.data.user);

//          }
//          else {
//             setIsLoggedIn(false);
//             setUserr({});

//          }
//       } catch (error) {
//          console.error('Error checking user login status:', error);
//          setIsLoggedIn(false);
//          setUserr({});
//       }
//    };


//    const handleLogout = async () => {
//       try {
//          const response = await axios.get(`${API_URLS.nodeBackend}/auth/logout`, {
//             withCredentials: true,
//             credentials: "include",
//          });
//          setIsLoggedIn(false);
//          setUserr({});

//       } catch (error) {
//          console.error('Error during logout:', error);
//       }
//    };


//    useEffect(() => {
//       checkUserLoggedIn();
//    }, []);

//    return (
//       <UserContext.Provider value={{ isLoggedIn, userr, setUserr, checkUserLoggedIn, handleLogout, setUserDetails }}>
//          {children}
//       </UserContext.Provider>
//    );
// };

import {
  faHome,
  faFileAlt,
  faChartBar,
  faFolderOpen,
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { Link, useLocation } from "react-router-dom";
import './Navbar.css'

const Navbarlist = () => {
  const location = useLocation();

  const navbarList = [
    {
      title: "Home",
      url: "/",
      cName: "nav-link",
      icon: faHome,
    },
    {
      title: "Report",
      url: "/report",
      cName: "nav-link",
      icon: faFileAlt,
    },
    {
      title: "Dashboard",
      url: "/dashboard",
      cName: "nav-link",
      icon: faChartBar,
    },
    {
      title: "Reports",
      url: "/allreports",
      cName: "nav-link",
      icon: faFolderOpen,
    },
  ];

  return (
    <>
      {navbarList.map((item, index) => {
        const isActive = location.pathname === item.url;
        return (
          <li key={index} className={`nav-item ${isActive ? 'active' : ''}`}>
            <Link to={item.url} className={`${item.cName}`}>
              <FontAwesomeIcon icon={item.icon} className="nav-icon" />
              <span>{item.title}</span>
            </Link>
          </li>
        );
      })}
    </>
  );
};

export default Navbarlist;


// import {
//   faBalanceScale,
//   faFileAlt,
//   faHome,
//   faInfoCircle,
//   faQuestionCircle,
//   faVideo
// } from "@fortawesome/free-solid-svg-icons";
// import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
// import { Link, useLocation } from "react-router-dom";
// import './Navbar.css'
// const Navbarlist = () => {
//   const location = useLocation();

//   const navbarList = [
//     {
//       title: "Home",
//       url: "/",
//       cName: "Navlinks",
//       // icon: faInfoCircle,
//     },
//     {
//       title: "Report",
//       url: "/report",
//       cName: "Navlinks",
//       // icon: faVideo,
//     },
//     {
//       title: "Dashboard",
//       url: "/dashboard",
//       cName: "Navlinks",
//     },
//     // {
//     //   title : "Premium",
//     //   url:"/getPremium",
//     //   cName :"Navlinks",
//     //   // icon: faBalanceScale,
//     // },
//      {
//       title : "Reports",
//       url:"/allreports",
//       cName :"Navlinks",
//       // icon: faBalanceScale,
//     },
//     // {
//     //   title: "Typo Squatting",
//     //   url: "http://127.0.0.1:7005",
//     //   cName: "Navlinks",
//     //   // icon: faHome,
//     // },

//   ];

//   return (
//     <>
//       {navbarList.map((item, index) => {
//         const isActive = location.pathname === item.url;
//         const iconClass = isActive ? "" : "";
//         const linkClass = isActive ? "active" : "";
//         return (
//           <div>
//             <li key={index} className={linkClass}>
//               <Link to={item.url} className={`${item.cName} Navlinks`}>
//                 <FontAwesomeIcon icon={item.icon} className={iconClass} />
//                 {item.title}
//               </Link>
//             </li>
//           </div>
//         );
//       })}
//     </>
//   );
// };

// export default Navbarlist;

import { Link, useLocation } from 'react-router-dom';

export default function Navbar() {
  const location = useLocation();
  
  const isActive = (path) => {
    return location.pathname === path ? 'active' : '';
  };

  return (
    <nav className="navbar">
      <div className="navbar-brand">
        <div className="logo-dot"></div>
        <span className="logo-text">SIEM-lite</span>
      </div>
      <div className="navbar-links">
        <Link to="/" className={`nav-link ${isActive('/')}`}>Overview</Link>
        <Link to="/anomalies" className={`nav-link ${isActive('/anomalies')}`}>Anomalies</Link>
        <Link to="/logs" className={`nav-link ${isActive('/logs')}`}>System Logs</Link>
      </div>
    </nav>
  );
}

import { Link, useLocation, useNavigate } from 'react-router-dom';

export default function Navbar({ onLogout }) {
  const location = useLocation();
  const navigate = useNavigate();

  const isActive = (path) => {
    return location.pathname === path ? 'active' : '';
  };

  const handleLogout = () => {
    onLogout();
    navigate('/login');
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
        <button type="button" className="nav-link nav-logout" onClick={handleLogout}>
          Logout
        </button>
      </div>
    </nav>
  );
}
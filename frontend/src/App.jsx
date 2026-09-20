import { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import api from './api';
import Navbar from './components/Navbar';
import Overview from './pages/Overview';
import Anomalies from './pages/Anomalies';
import Logs from './pages/Logs';
import Login from './pages/Login';
import './App.css';

function App() {
  const [stats, setStats] = useState(null);
  const [anomalies, setAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  // Consider the user authenticated if a token is present. It might still
  // be expired — the first API call will 401, and api.js's interceptor
  // will clear it and redirect to /login automatically.
const [isAuthenticated, setIsAuthenticated] = useState(false);
const [checkingAuth, setCheckingAuth] = useState(true);

useEffect(() => {
  api.get('/auth/me')
    .then(() => setIsAuthenticated(true))
    .catch(() => setIsAuthenticated(false))
    .finally(() => setCheckingAuth(false));
}, []);

const handleLogout = () => {
  api.post('/auth/logout').finally(() => setIsAuthenticated(false));
};

  useEffect(() => {
    // Only fetch data if authenticated
    if (!isAuthenticated) {
      setLoading(false);
      return;
    }

    setLoading(true);
    Promise.all([
      api.get('/logs/stats'),
      api.get('/anomalies')
    ])

      .then(([statsRes, anomaliesRes]) => {
        setStats(statsRes.data);
        setAnomalies(anomaliesRes.data);
        setError(null);
      })
      .catch((err) => {
        setError('Failed to fetch dashboard data. Is the backend running?');
        console.error(err);
      })
      .finally(() => setLoading(false));
  }, [isAuthenticated]);

  if (checkingAuth || (loading && !stats && isAuthenticated))  {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
        <p>Initializing Security Dashboard...</p>
      </div>
    );
  }

  return (
    <Router>
      <div className="dashboard-container">
        {isAuthenticated && <Navbar onLogout={handleLogout} />}
        
        {error && isAuthenticated && (
          <div className="error-banner">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            {error}
          </div>
        )}

        <div className={isAuthenticated ? "page-wrapper" : ""}>
          <Routes>
            <Route 
              path="/login" 
              element={
                isAuthenticated ? <Navigate to="/" /> : <Login onLogin={() => setIsAuthenticated(true)} />
              } 
            />
            <Route 
              path="/" 
              element={isAuthenticated ? <Overview stats={stats} /> : <Navigate to="/login" />} 
            />
            <Route 
              path="/anomalies" 
              element={isAuthenticated ? <Anomalies anomalies={anomalies} /> : <Navigate to="/login" />} 
            />
            <Route 
              path="/logs" 
              element={isAuthenticated ? <Logs /> : <Navigate to="/login" />} 
            />
          </Routes>
        </div>
      </div>
    </Router>
  );
}

export default App;
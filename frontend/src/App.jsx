import { useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import axios from 'axios';
import Navbar from './components/Navbar';
import Overview from './pages/Overview';
import Anomalies from './pages/Anomalies';
import Logs from './pages/Logs';
import './App.css';

const API_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

function App() {
  const [stats, setStats] = useState(null);
  const [anomalies, setAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      axios.get(`${API_URL}/logs/stats`),
      axios.get(`${API_URL}/anomalies`)
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
  }, []);

  if (loading && !stats) {
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
        <Navbar />
        
        {error && (
          <div className="error-banner">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            {error}
          </div>
        )}

        <div className="page-wrapper">
          <Routes>
            <Route path="/" element={<Overview stats={stats} />} />
            <Route path="/anomalies" element={<Anomalies anomalies={anomalies} />} />
            <Route path="/logs" element={<Logs />} />
          </Routes>
        </div>
      </div>
    </Router>
  );
}

export default App;
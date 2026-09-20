import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api';
import './Login.css';

const Login = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSubmitting(true);

    // FastAPI's OAuth2PasswordRequestForm expects form-urlencoded data,
    // not JSON — same format we tested with curl.
    const body = new URLSearchParams();
    body.append('username', username);
    body.append('password', password);

    try {
      const res = await api.post('/auth/login', body, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });
      
      onLogin();

            navigate('/');
    } catch (err) {
      if (err.response && err.response.status === 401) {
        setError('Incorrect username or password.');
      } else if (err.response && err.response.status === 429) {
        setError('Too many login attempts. Please wait a minute and try again.');
      } else {
        setError('Unable to reach the server. Is the backend running?');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <div className="shield-icon-container">
            <svg className="shield-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
              <path d="M12 8v4"></path>
              <path d="M12 16h.01"></path>
            </svg>
          </div>
          
          <h2 className="auth-title">System Access</h2>
          <div className="status-badge">
            <span className="status-dot"></span>
            Secure Connection
          </div>
        </div>

        {error && (
          <div className="login-error" role="alert">
            {error}
          </div>
        )}
        
        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <div className="input-wrapper">
              <input 
                type="text" 
                id="username" 
                placeholder="admin" 
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required 
                autoComplete="off"
                spellCheck="false"
              />
            </div>
          </div>
          
          <div className="form-group">
            <label htmlFor="password">Password</label>
            <div className="input-wrapper">
              <input 
                type="password" 
                id="password" 
                placeholder="••••••••" 
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required 
              />
            </div>
          </div>
          
          <button type="submit" className="login-button" disabled={submitting}>
            <span>{submitting ? 'Signing In...' : 'Sign In'}</span>
          </button>
        </form>
      </div>
    </div>
  );
};

export default Login;

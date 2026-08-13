import { useState, useEffect } from 'react';
import api from '../api';

export default function Logs() {
  const [logs, setLogs] = useState([]);
  const [severity, setSeverity] = useState('');
  const [eventType, setEventType] = useState('');
  const [search, setSearch] = useState('');
  const [error, setError] = useState(null);

  useEffect(() => {
    const params = { limit: 50 };
    if (severity) params.severity = severity;
    if (eventType && eventType.length > 0) params.event_type = eventType;

    api.get('/logs', { params })
      .then((res) => setLogs(res.data))
      .catch((err) => {
        console.error("Failed to fetch filtered logs:", err);
        setError('Failed to fetch logs.');
      });
  }, [severity, eventType]);

  const filteredLogs = logs.filter((log) => {
    const rawMsg = log.raw_message || '';
    const srcIp = log.source_ip || '';
    return rawMsg.toLowerCase().includes((search || '').toLowerCase()) ||
           srcIp.includes(search || '');
  });

  return (
    <div className="page-content animation-fade-in">
      <div className="dashboard-header">
        <h1 className="dashboard-title">System Logs</h1>
      </div>

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

      <div className="tables-grid">
        <div className="card">
          <div className="filters-bar">
            <label htmlFor="severity-filter" style={{ display: 'none' }}>Filter by Severity</label>
            <select className="form-control" id="severity-filter" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">All Severities</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>

            <label htmlFor="event-filter" style={{ display: 'none' }}>Filter by Event Type</label>
            <select className="form-control" id="event-filter" value={eventType} onChange={(e) => setEventType(e.target.value)}>
              <option value="">All Event Types</option>
              <option value="login_attempt">Login Attempt</option>
              <option value="file_access">File Access</option>
              <option value="port_scan">Port Scan</option>
              <option value="malware_alert">Malware Alert</option>
              <option value="config_change">Config Change</option>
            </select>

            <label htmlFor="search-input" style={{ display: 'none' }}>Search logs</label>
            <input
              className="form-control search-input"
              id="search-input"
              type="text"
              placeholder="Search message or IP..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <div className="data-table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Source IP</th>
                  <th>Event Type</th>
                  <th>Severity</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.map((log) => (
                  <tr key={log.id}>
                    <td style={{ color: 'var(--text-secondary)' }}>{new Date(log.timestamp).toLocaleString()}</td>
                    <td style={{ fontFamily: 'monospace' }}>{log.source_ip}</td>
                    <td>{(log.event_type || '').replace('_', ' ')}</td>
                    <td>
                      <span className={`badge badge-${log.severity}`}>{log.severity}</span>
                    </td>
                    <td>{log.raw_message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

import { useEffect, useState } from 'react';
import axios from 'axios';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const API_URL = 'http://127.0.0.1:8000';
const COLORS = ['#22c55e', '#eab308', '#f97316', '#ef4444'];

function App() {
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [severity, setSeverity] = useState('');
  const [eventType, setEventType] = useState('');
  const [search, setSearch] = useState('');
  const [anomalies, setAnomalies] = useState([]);

  useEffect(() => {
  axios.get(`${API_URL}/logs/stats`).then((res) => setStats(res.data));
  axios.get(`${API_URL}/anomalies`).then((res) => setAnomalies(res.data));
}, []);

  useEffect(() => {
    const params = { limit: 50 };
    if (severity) params.severity = severity;
    if (event_type_safe(eventType)) params.event_type = eventType;

    axios.get(`${API_URL}/logs`, { params }).then((res) => setLogs(res.data));
  }, [severity, eventType]);

  function event_type_safe(val) {
    return val && val.length > 0;
  }

  const filteredLogs = logs.filter((log) =>
    log.raw_message.toLowerCase().includes(search.toLowerCase()) ||
    log.source_ip.includes(search)
  );

  if (!stats) return <div style={{ padding: 20 }}>Loading...</div>;

  return (
    <div style={{ padding: 20, fontFamily: 'sans-serif' }}>
      <h1>SIEM-lite Dashboard</h1>

      <h2>Severity Breakdown</h2>
      <ResponsiveContainer width="100%" height={250}>
        <PieChart>
          <Pie
            data={stats.severity_breakdown}
            dataKey="count"
            nameKey="severity"
            cx="50%"
            cy="50%"
            outerRadius={80}
            label
          >
            {stats.severity_breakdown.map((entry, index) => (
              <Cell key={entry.severity} fill={COLORS[index % COLORS.length]} />
            ))}
          </Pie>
          <Tooltip />
        </PieChart>
      </ResponsiveContainer>

      <h2>Event Type Breakdown</h2>
      <ResponsiveContainer width="100%" height={250}>
        <BarChart data={stats.event_type_breakdown}>
          <XAxis dataKey="event_type" />
          <YAxis />
          <Tooltip />
          <Bar dataKey="count" fill="#3b82f6" />
        </BarChart>
      </ResponsiveContainer>

      <h2>Anomalies ({anomalies.length})</h2>
{anomalies.length === 0 ? (
  <p>No anomalies detected.</p>
) : (
  <table border="1" cellPadding="6" style={{ borderCollapse: 'collapse', width: '100%', marginBottom: 20 }}>
    <thead>
      <tr>
        <th>Timestamp</th>
        <th>Source IP</th>
        <th>Reason</th>
        <th>Score</th>
        <th>Detector</th>
      </tr>
    </thead>
    <tbody>
      {anomalies.map((a) => (
        <tr key={a.id}>
          <td>{new Date(a.timestamp).toLocaleString()}</td>
          <td>{a.source_ip}</td>
          <td>{a.reason}</td>
          <td>{a.score}</td>
          <td>{a.source}</td>
        </tr>
      ))}
    </tbody>
  </table>
)}

<h2>Logs</h2>

      <div style={{ display: 'flex', gap: 10, marginBottom: 15 }}>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All Severities</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>

        <select value={eventType} onChange={(e) => setEventType(e.target.value)}>
          <option value="">All Event Types</option>
          <option value="login_attempt">Login Attempt</option>
          <option value="file_access">File Access</option>
          <option value="port_scan">Port Scan</option>
          <option value="malware_alert">Malware Alert</option>
          <option value="config_change">Config Change</option>
        </select>

        <input
          type="text"
          placeholder="Search message or IP..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ flex: 1, padding: 5 }}
        />
      </div>

      <table border="1" cellPadding="6" style={{ borderCollapse: 'collapse', width: '100%' }}>
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
              <td>{new Date(log.timestamp).toLocaleString()}</td>
              <td>{log.source_ip}</td>
              <td>{log.event_type}</td>
              <td>{log.severity}</td>
              <td>{log.raw_message}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default App;
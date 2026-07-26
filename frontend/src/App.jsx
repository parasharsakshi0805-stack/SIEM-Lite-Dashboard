import { useEffect, useState } from 'react';
import axios from 'axios';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

const API_URL = 'http://127.0.0.1:8000';
const COLORS = ['#22c55e', '#eab308', '#f97316', '#ef4444'];

function App() {
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);

  useEffect(() => {
    axios.get(`${API_URL}/logs/stats`).then((res) => setStats(res.data));
    axios.get(`${API_URL}/logs?limit=20`).then((res) => setLogs(res.data));
  }, []);

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

      <h2>Recent Logs</h2>
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
          {logs.map((log) => (
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
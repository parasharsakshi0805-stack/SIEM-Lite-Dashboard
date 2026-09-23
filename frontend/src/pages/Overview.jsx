import { useState } from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell, Sector, LineChart, Line, CartesianGrid } from 'recharts';

const COLORS = ['#00E5FF', '#F5A623', '#FF3366', '#FF003C'];

const tooltipStyle = {
  contentStyle: { backgroundColor: 'rgba(15, 15, 25, 0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', backdropFilter: 'blur(8px)' },
  itemStyle: { color: '#F8FAFC' },
};

const renderActiveShape = (props) => {
  const { cx, cy, innerRadius, outerRadius, startAngle, endAngle, fill, payload, percent, value } = props;
  return (
    <g>
      <text x={cx} y={cy - 6} textAnchor="middle" fill="#F8FAFC" fontSize={26} fontWeight={700}>
        {value}
      </text>
      <text x={cx} y={cy + 18} textAnchor="middle" fill="#94A3B8" fontSize={13}>
        {payload.severity} ({(percent * 100).toFixed(0)}%)
      </text>
      <Sector cx={cx} cy={cy} innerRadius={innerRadius} outerRadius={outerRadius + 10} startAngle={startAngle} endAngle={endAngle} fill={fill} />
      <Sector cx={cx} cy={cy} startAngle={startAngle} endAngle={endAngle} innerRadius={outerRadius + 14} outerRadius={outerRadius + 18} fill={fill} />
    </g>
  );
};

export default function Overview({ stats, timeline }) {
  const [activeIndex, setActiveIndex] = useState(0);

  if (!stats) return <div className="loading-container"><div className="spinner"></div><p>Loading overview...</p></div>;

  const summary = stats.summary || {};

  const timelineData = (timeline || []).map((point) => ({
    ...point,
    label: new Date(point.hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  }));

  return (
    <div className="page-content animation-fade-in">
      <div className="dashboard-header">
        <h1 className="dashboard-title">Overview</h1>
      </div>

      <div className="stat-cards-grid">
        <div className="stat-card">
          <span className="stat-label">Total Logs</span>
          <span className="stat-value">{summary.total_logs ?? 0}</span>
        </div>
        <div className="stat-card stat-card-warning">
          <span className="stat-label">Active Anomalies</span>
          <span className="stat-value">{summary.total_anomalies ?? 0}</span>
        </div>
        <div className="stat-card stat-card-critical">
          <span className="stat-label">Critical Events</span>
          <span className="stat-value">{summary.critical_count ?? 0}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Unique Source IPs</span>
          <span className="stat-value">{summary.unique_ips ?? 0}</span>
        </div>
      </div>

      <div className="charts-grid" style={{ marginBottom: 32 }}>
        <div className="card">
          <h2 className="card-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21.21 15.89A10 10 0 1 1 8 2.83"></path><path d="M22 12A10 10 0 0 0 12 2v10z"></path></svg>
            Severity Breakdown
          </h2>
          <ResponsiveContainer width="100%" height={340}>
            <PieChart aria-label="Severity Breakdown Chart">
              <Pie
                data={stats.severity_breakdown}
                dataKey="count"
                nameKey="severity"
                cx="50%"
                cy="50%"
                innerRadius={70}
                outerRadius={100}
                activeIndex={activeIndex}
                activeShape={renderActiveShape}
                onMouseEnter={(_, index) => setActiveIndex(index)}
              >
                {stats.severity_breakdown.map((entry, index) => (
                  <Cell key={entry.severity} fill={COLORS[index % COLORS.length]} style={{ cursor: 'pointer' }} />
                ))}
              </Pie>
              <Legend wrapperStyle={{ color: '#94A3B8', fontSize: 13 }} />
              <Tooltip {...tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h2 className="card-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
            Event Type Breakdown
          </h2>
          <ResponsiveContainer width="100%" height={340}>
            <BarChart data={stats.event_type_breakdown} aria-label="Event Type Breakdown Chart">
              <XAxis dataKey="event_type" stroke="#94A3B8" tick={{ fill: '#94A3B8', fontSize: 12 }} />
              <YAxis stroke="#94A3B8" tick={{ fill: '#94A3B8', fontSize: 12 }} allowDecimals={false} />
              <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} {...tooltipStyle} />
              <Bar dataKey="count" fill="#00E5FF" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 32 }}>
        <h2 className="card-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><line x1="2" y1="12" x2="22" y2="12"></line><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
          Top Source IPs
        </h2>
        <ResponsiveContainer width="100%" height={360}>
          <BarChart data={stats.top_source_ips} layout="vertical" aria-label="Top Source IPs Chart">
            <XAxis type="number" stroke="#94A3B8" tick={{ fill: '#94A3B8', fontSize: 12 }} allowDecimals={false} />
            <YAxis type="category" dataKey="ip" stroke="#94A3B8" tick={{ fill: '#94A3B8', fontSize: 12 }} width={130} />
            <Tooltip cursor={{ fill: 'rgba(255,255,255,0.05)' }} {...tooltipStyle} />
            <Bar dataKey="count" fill="#F5A623" radius={[0, 6, 6, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="card">
        <h2 className="card-title">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 17 9 11 13 15 21 7"></polyline></svg>
          Log Volume (Last 24 Hours)
        </h2>
        <ResponsiveContainer width="100%" height={260}>
          <LineChart data={timelineData} aria-label="Log Volume Timeline">
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
            <XAxis dataKey="label" stroke="#94A3B8" tick={{ fill: '#94A3B8', fontSize: 12 }} />
            <YAxis stroke="#94A3B8" tick={{ fill: '#94A3B8', fontSize: 12 }} allowDecimals={false} />
            <Tooltip {...tooltipStyle} />
            <Line type="monotone" dataKey="count" stroke="#00E5FF" strokeWidth={2} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
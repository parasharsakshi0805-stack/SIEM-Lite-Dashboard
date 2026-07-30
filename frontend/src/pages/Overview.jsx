import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';

// Colors for Recharts that match our dark mode CSS variables
const COLORS = ['#00E5FF', '#F5A623', '#FF3366', '#FF003C'];

export default function Overview({ stats }) {
  if (!stats) return <div className="loading-container"><div className="spinner"></div><p>Loading overview...</p></div>;

  return (
    <div className="page-content animation-fade-in">
      <div className="dashboard-header">
        <h1 className="dashboard-title">Overview</h1>
      </div>
      
      <div className="charts-grid">
        <div className="card">
          <h2 className="card-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21.21 15.89A10 10 0 1 1 8 2.83"></path><path d="M22 12A10 10 0 0 0 12 2v10z"></path></svg>
            Severity Breakdown
          </h2>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart aria-label="Severity Breakdown Chart">
              <Pie
                data={stats.severity_breakdown}
                dataKey="count"
                nameKey="severity"
                cx="50%"
                cy="50%"
                outerRadius={100}
                label={({ severity }) => severity}
              >
                {stats.severity_breakdown.map((entry, index) => (
                  <Cell key={entry.severity} fill={COLORS[index % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ backgroundColor: 'rgba(15, 15, 25, 0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', backdropFilter: 'blur(8px)' }}
                itemStyle={{ color: '#F8FAFC' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <h2 className="card-title">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="20" x2="18" y2="10"></line><line x1="12" y1="20" x2="12" y2="4"></line><line x1="6" y1="20" x2="6" y2="14"></line></svg>
            Event Type Breakdown
          </h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={stats.event_type_breakdown} aria-label="Event Type Breakdown Chart">
              <XAxis dataKey="event_type" stroke="#94A3B8" tick={{fill: '#94A3B8', fontSize: 12}} />
              <YAxis stroke="#94A3B8" tick={{fill: '#94A3B8', fontSize: 12}} />
              <Tooltip 
                cursor={{fill: 'rgba(255,255,255,0.05)'}}
                contentStyle={{ backgroundColor: 'rgba(15, 15, 25, 0.9)', border: '1px solid rgba(255,255,255,0.1)', borderRadius: '12px', backdropFilter: 'blur(8px)' }}
              />
              <Bar dataKey="count" fill="#00E5FF" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

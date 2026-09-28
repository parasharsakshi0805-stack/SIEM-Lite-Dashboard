export default function Anomalies({ anomalies }) {
  const uniqueIps = new Set(anomalies.map((a) => a.source_ip)).size;
  const latest = anomalies.length > 0 ? new Date(anomalies[0].timestamp).toLocaleString() : '—';
  const ranked = [...anomalies].sort((a, b) => b.score - a.score);

  const stats = [
    { label: 'Total anomalies', value: anomalies.length, color: '#FF3366' },
    { label: 'Unique source IPs', value: uniqueIps, color: '#00E5FF' },
    { label: 'Most recent', value: latest, color: '#F8FAFC', small: true },
  ];

  return (
    <div className="page-content animation-fade-in">
      <div className="dashboard-header">
        <h1 className="dashboard-title">Active Anomalies</h1>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))',
          gap: '16px',
          marginBottom: '20px',
        }}
      >
        {stats.map((s) => (
          <div key={s.label} className="card" style={{ borderColor: `${s.color}44` }}>
            <div style={{ fontSize: '1rem', color: 'var(--text-secondary)', marginBottom: '8px' }}>{s.label}</div>
            <div
              style={{
                fontSize: s.small ? '1.3rem' : '3rem',
                fontWeight: 700,
                color: s.color,
                lineHeight: 1.1,
              }}
            >
              {s.value}
            </div>
          </div>
        ))}
      </div>

      <div className="tables-grid">
        <div className="card" style={{ borderColor: anomalies.length > 0 ? 'rgba(255, 0, 60, 0.4)' : '' }}>
          <h2 className="card-title" style={{ color: anomalies.length > 0 ? '#FFB3B3' : '' }}>
            Anomalies ({anomalies.length})
          </h2>

          {anomalies.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)', fontSize: '1rem' }}>No anomalies detected at this time.</p>
          ) : (
            <div className="data-table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Why it was flagged</th>
                    <th>Score</th>
                  </tr>
                </thead>
                <tbody>
                  {ranked.map((a) => (
                    <tr key={a.id}>
                      <td style={{ color: 'var(--text-secondary)' }}>{new Date(a.timestamp).toLocaleString()}</td>
                      <td style={{ fontFamily: 'monospace', color: '#00E5FF' }}>{a.source_ip}</td>
                      <td>{a.reason}</td>
                      <td>
                        <span className="badge badge-critical">{a.score}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
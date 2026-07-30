export default function Anomalies({ anomalies }) {
  return (
    <div className="page-content animation-fade-in">
      <div className="dashboard-header">
        <h1 className="dashboard-title">Active Anomalies</h1>
      </div>

      <div className="tables-grid">
        <div className="card" style={{ borderColor: anomalies.length > 0 ? 'rgba(255, 0, 60, 0.4)' : '' }}>
          <h2 className="card-title" style={{ color: anomalies.length > 0 ? '#FFB3B3' : '' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>
            Active Anomalies ({anomalies.length})
          </h2>
          
          {anomalies.length === 0 ? (
            <p style={{ color: 'var(--text-secondary)' }}>No anomalies detected at this time.</p>
          ) : (
            <div className="data-table-container">
              <table className="data-table">
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
                      <td style={{ color: 'var(--text-secondary)' }}>{new Date(a.timestamp).toLocaleString()}</td>
                      <td style={{ fontFamily: 'monospace', color: '#00E5FF' }}>{a.source_ip}</td>
                      <td>{a.reason}</td>
                      <td>
                        <span className="badge badge-critical">{a.score}</span>
                      </td>
                      <td>{a.source}</td>
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

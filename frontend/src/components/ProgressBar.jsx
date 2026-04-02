/**
 * ProgressBar — shows enrichment progress and VT rate-limit wait indicator.
 */
export default function ProgressBar({ processed, total, waitingMs }) {
  if (total === 0) return null;

  const pct = total > 0 ? Math.round((processed / total) * 100) : 0;
  const isWaiting = waitingMs > 0;

  return (
    <div style={{ marginTop: '12px' }}>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '6px'
      }}>
        <span style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: "'JetBrains Mono', monospace" }}>
          {processed}/{total} IOCs enriched
        </span>
        {isWaiting && (
          <span style={{
            fontSize: '11px',
            color: 'var(--accent-amber)',
            display: 'flex',
            alignItems: 'center',
            gap: '4px'
          }}>
            <span style={{
              display: 'inline-block',
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              backgroundColor: 'var(--accent-amber)',
              animation: 'pulse 1s ease-in-out infinite'
            }} />
            VT rate limit — waiting {Math.ceil(waitingMs / 1000)}s
          </span>
        )}
        <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{pct}%</span>
      </div>
      <div style={{
        height: '4px',
        backgroundColor: 'var(--bg-elevated)',
        borderRadius: '2px',
        overflow: 'hidden'
      }}>
        <div style={{
          height: '100%',
          width: `${pct}%`,
          backgroundColor: isWaiting ? 'var(--accent-amber)' : 'var(--accent-teal)',
          borderRadius: '2px',
          transition: 'width 0.3s ease, background-color 0.3s ease'
        }} />
      </div>
    </div>
  );
}

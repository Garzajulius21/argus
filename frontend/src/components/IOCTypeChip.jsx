/**
 * IOCTypeChip — colored badge showing the IOC type.
 */
export default function IOCTypeChip({ type }) {
  const styles = {
    sha256: { color: 'var(--accent-amber)', border: '1px solid rgba(240,136,62,0.4)', bg: 'rgba(240,136,62,0.1)' },
    sha1: { color: 'var(--accent-amber)', border: '1px solid rgba(240,136,62,0.4)', bg: 'rgba(240,136,62,0.1)' },
    md5: { color: 'var(--accent-amber)', border: '1px solid rgba(240,136,62,0.4)', bg: 'rgba(240,136,62,0.1)' },
    ipv4: { color: 'var(--accent-blue)', border: '1px solid rgba(56,139,253,0.4)', bg: 'rgba(56,139,253,0.1)' },
    domain: { color: 'var(--accent-teal)', border: '1px solid rgba(57,211,83,0.4)', bg: 'rgba(57,211,83,0.1)' },
    url: { color: 'var(--accent-purple)', border: '1px solid rgba(188,140,255,0.4)', bg: 'rgba(188,140,255,0.1)' },
  };

  const s = styles[type] || { color: 'var(--text-secondary)', border: '1px solid var(--border)', bg: 'transparent' };

  return (
    <span
      style={{
        display: 'inline-block',
        padding: '2px 7px',
        borderRadius: '4px',
        fontSize: '11px',
        fontFamily: "'JetBrains Mono', monospace",
        fontWeight: 600,
        letterSpacing: '0.05em',
        textTransform: 'uppercase',
        color: s.color,
        border: s.border,
        backgroundColor: s.bg,
        userSelect: 'none'
      }}
    >
      {type}
    </span>
  );
}

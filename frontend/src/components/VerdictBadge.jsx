import { useEffect, useRef, useState } from 'react';

/**
 * VerdictBadge — CLEAN / SUSPICIOUS / MALICIOUS pill with flash animation on change.
 */
export default function VerdictBadge({ verdict }) {
  const [key, setKey] = useState(0);
  const prevVerdict = useRef(verdict);

  useEffect(() => {
    if (verdict !== prevVerdict.current) {
      prevVerdict.current = verdict;
      setKey(k => k + 1);
    }
  }, [verdict]);

  const styles = {
    MALICIOUS: {
      bg: 'rgba(218,54,51,0.2)',
      border: '1px solid rgba(218,54,51,0.5)',
      color: '#ff7b7b',
      dot: '#da3633'
    },
    SUSPICIOUS: {
      bg: 'rgba(158,106,3,0.2)',
      border: '1px solid rgba(158,106,3,0.5)',
      color: '#ffa657',
      dot: '#f0883e'
    },
    CLEAN: {
      bg: 'rgba(35,134,54,0.2)',
      border: '1px solid rgba(35,134,54,0.5)',
      color: '#56d364',
      dot: '#238636'
    }
  };

  const s = styles[verdict] || styles.CLEAN;
  const label = verdict || 'CLEAN';

  return (
    <span
      key={key}
      className="verdict-flash"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '5px',
        padding: '3px 9px',
        borderRadius: '12px',
        fontSize: '11px',
        fontFamily: "'IBM Plex Sans', sans-serif",
        fontWeight: 600,
        letterSpacing: '0.08em',
        textTransform: 'uppercase',
        backgroundColor: s.bg,
        border: s.border,
        color: s.color,
        userSelect: 'none',
        whiteSpace: 'nowrap'
      }}
    >
      <span style={{
        width: '6px',
        height: '6px',
        borderRadius: '50%',
        backgroundColor: s.dot,
        flexShrink: 0
      }} />
      {label}
    </span>
  );
}

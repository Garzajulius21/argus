import { defang } from '../lib/defang.js';

const HISTORY_KEY = 'argus_search_history';
const MAX_ENTRIES = 15;

export function loadHistory() {
  try {
    return JSON.parse(localStorage.getItem(HISTORY_KEY) || '[]');
  } catch {
    return [];
  }
}

export function saveToHistory(iocs, results) {
  try {
    const verdicts = results.reduce((acc, r) => {
      const v = (r.verdict || 'CLEAN').toUpperCase();
      acc[v] = (acc[v] || 0) + 1;
      return acc;
    }, {});

    const entry = {
      id: Date.now(),
      timestamp: new Date().toISOString(),
      iocCount: iocs.length,
      iocs: iocs.map(i => i.value),
      verdicts
    };

    const history = loadHistory();
    const updated = [entry, ...history].slice(0, MAX_ENTRIES);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(updated));
    return updated;
  } catch {
    return [];
  }
}

function formatTime(iso) {
  const d = new Date(iso);
  const now = new Date();
  const diffMs = now - d;
  const diffMin = Math.floor(diffMs / 60000);
  const diffHr = Math.floor(diffMs / 3600000);
  const diffDay = Math.floor(diffMs / 86400000);

  if (diffMin < 1) return 'just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHr < 24) return `${diffHr}h ago`;
  if (diffDay < 7) return `${diffDay}d ago`;
  return d.toLocaleDateString();
}

function VerdictPill({ label, count, color }) {
  if (!count) return null;
  return (
    <span style={{
      fontSize: '10px',
      padding: '1px 6px',
      borderRadius: '3px',
      backgroundColor: `${color}18`,
      border: `1px solid ${color}40`,
      color,
      fontFamily: "'JetBrains Mono', monospace",
      fontWeight: 600
    }}>
      {count} {label}
    </span>
  );
}

export default function SearchHistory({ history, onReload }) {
  if (!history || history.length === 0) return null;

  return (
    <div style={{
      backgroundColor: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: '6px',
      overflow: 'hidden'
    }}>
      <div style={{
        padding: '8px 12px',
        borderBottom: '1px solid var(--border)',
        fontSize: '10px',
        fontWeight: 600,
        color: 'var(--text-secondary)',
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <span>Recent Searches</span>
        <span style={{ color: 'var(--border)', fontWeight: 400 }}>{history.length}/{MAX_ENTRIES}</span>
      </div>

      <div style={{ maxHeight: '280px', overflowY: 'auto' }}>
        {history.map((entry, i) => (
          <div
            key={entry.id}
            onClick={() => onReload(entry.iocs)}
            style={{
              padding: '8px 12px',
              borderBottom: i < history.length - 1 ? '1px solid var(--border)' : 'none',
              cursor: 'pointer',
              transition: 'background-color 0.1s',
              display: 'flex',
              flexDirection: 'column',
              gap: '4px'
            }}
            onMouseEnter={e => e.currentTarget.style.backgroundColor = 'rgba(56,139,253,0.05)'}
            onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
          >
            {/* Top row: IOC count + time */}
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <span style={{
                fontSize: '11px',
                color: 'var(--text-primary)',
                fontFamily: "'JetBrains Mono', monospace"
              }}>
                {entry.iocCount} IOC{entry.iocCount !== 1 ? 's' : ''}
              </span>
              <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>
                {formatTime(entry.timestamp)}
              </span>
            </div>

            {/* Verdict pills */}
            <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
              <VerdictPill label="MALICIOUS" count={entry.verdicts?.MALICIOUS} color="#da3633" />
              <VerdictPill label="SUSPICIOUS" count={entry.verdicts?.SUSPICIOUS} color="#f0883e" />
              <VerdictPill label="CLEAN" count={entry.verdicts?.CLEAN} color="#39d353" />
            </div>

            {/* IOC preview */}
            <div style={{
              fontSize: '10px',
              color: 'var(--text-secondary)',
              fontFamily: "'JetBrains Mono', monospace",
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap'
            }}>
              {entry.iocs.slice(0, 3).map(v => defang(v, '')).join(' · ')}
              {entry.iocs.length > 3 && ` +${entry.iocs.length - 3} more`}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

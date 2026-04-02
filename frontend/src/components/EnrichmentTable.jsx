import IOCTypeChip from './IOCTypeChip.jsx';
import VerdictBadge from './VerdictBadge.jsx';
import { defang } from '../lib/defang.js';

function SkeletonRow() {
  return (
    <tr style={{ borderBottom: '1px solid var(--border)' }}>
      {[1, 2, 3, 4, 5].map(i => (
        <td key={i} style={{ padding: '10px 12px' }}>
          <div className="skeleton" style={{ height: '14px', width: i === 1 ? '80%' : '60%' }} />
        </td>
      ))}
    </tr>
  );
}

function ScoreCell({ value, threshold75, threshold25 }) {
  if (value === null || value === undefined) {
    return <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>—</span>;
  }
  let color = 'var(--text-secondary)';
  if (value >= threshold75) color = '#ff7b7b';
  else if (value >= threshold25) color = 'var(--accent-amber)';
  else if (value === 0) color = 'var(--accent-teal)';

  return (
    <span style={{
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: '12px',
      color,
      fontWeight: 600
    }}>
      {value}
    </span>
  );
}

function VTCell({ data, error, queried }) {
  if (!queried) return <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>N/A</span>;
  if (error) return <span style={{ color: '#ff7b7b', fontSize: '11px' }}>ERR</span>;
  if (!data) return <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>—</span>;

  const malicious = data.malicious || 0;
  const total = data.total || 0;
  let color = 'var(--accent-teal)';
  if (malicious > 2) color = '#ff7b7b';
  else if (malicious > 0) color = 'var(--accent-amber)';

  return (
    <span style={{
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: '12px',
      color,
      fontWeight: 600
    }}>
      {malicious}/{total}
    </span>
  );
}

function TagsCell({ tags }) {
  if (!tags || tags.length === 0) {
    return <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>—</span>;
  }
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px' }}>
      {tags.slice(0, 3).map((tag, i) => (
        <span key={i} style={{
          fontSize: '10px',
          padding: '1px 5px',
          backgroundColor: 'rgba(188,140,255,0.1)',
          border: '1px solid rgba(188,140,255,0.3)',
          borderRadius: '3px',
          color: 'var(--accent-purple)',
          fontFamily: "'JetBrains Mono', monospace"
        }}>
          {tag}
        </span>
      ))}
      {tags.length > 3 && (
        <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>+{tags.length - 3}</span>
      )}
    </div>
  );
}

export default function EnrichmentTable({ results, loading, pendingCount }) {
  const hasResults = results && results.length > 0;

  if (!hasResults && !loading) return null;

  return (
    <div style={{
      backgroundColor: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: '8px',
      overflow: 'hidden',
      marginTop: '16px'
    }}>
      <div style={{
        padding: '10px 14px',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <span style={{
          fontSize: '12px',
          fontWeight: 600,
          color: 'var(--text-secondary)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em'
        }}>
          Enrichment Results
        </span>
        {hasResults && (
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
            {results.length} IOC{results.length !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{
          width: '100%',
          borderCollapse: 'collapse',
          fontSize: '12px'
        }}>
          <thead>
            <tr style={{ backgroundColor: 'var(--bg-elevated)' }}>
              {['IOC', 'Type', 'VT Score', 'Abuse %', 'Tags / Status', 'Verdict'].map(h => (
                <th key={h} style={{
                  padding: '8px 12px',
                  textAlign: 'left',
                  color: 'var(--text-secondary)',
                  fontWeight: 600,
                  fontSize: '11px',
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                  borderBottom: '1px solid var(--border)',
                  whiteSpace: 'nowrap'
                }}>
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {results.map((item, i) => {
              const { ioc, enrichment, verdict } = item;
              const vt = enrichment?.virustotal;
              const abuse = enrichment?.abuseipdb;
              const mb = enrichment?.malwarebazaar;

              // Collect tags from VT and MB
              const allTags = [
                ...(vt?.data?.tags || []),
                ...(mb?.data?.tags || []),
                ...(mb?.data?.found ? ['malware-db'] : [])
              ];

              return (
                <tr key={i} style={{
                  borderBottom: '1px solid var(--border)',
                  backgroundColor: i % 2 === 0 ? 'transparent' : 'rgba(33,38,45,0.3)',
                  transition: 'background-color 0.1s'
                }}
                onMouseEnter={e => e.currentTarget.style.backgroundColor = 'rgba(56,139,253,0.05)'}
                onMouseLeave={e => e.currentTarget.style.backgroundColor = i % 2 === 0 ? 'transparent' : 'rgba(33,38,45,0.3)'}
                >
                  {/* IOC value */}
                  <td style={{ padding: '10px 12px', maxWidth: '240px' }}>
                    <span style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      color: 'var(--text-mono)',
                      fontSize: '12px',
                      display: 'block',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap'
                    }}
                    title={defang(ioc.value, ioc.type)}
                    >
                      {defang(ioc.value, ioc.type)}
                    </span>
                  </td>

                  {/* Type */}
                  <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                    <IOCTypeChip type={ioc.type} />
                  </td>

                  {/* VT Score */}
                  <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                    <VTCell
                      data={vt?.data}
                      error={vt?.error}
                      queried={vt?.queried}
                    />
                  </td>

                  {/* Abuse score */}
                  <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                    {abuse?.queried ? (
                      <ScoreCell
                        value={abuse?.data?.abuseScore}
                        threshold75={75}
                        threshold25={26}
                      />
                    ) : (
                      <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>N/A</span>
                    )}
                  </td>

                  {/* Tags / MalwareBazaar status */}
                  <td style={{ padding: '10px 12px' }}>
                    <TagsCell tags={allTags} />
                  </td>

                  {/* Verdict */}
                  <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                    <VerdictBadge verdict={verdict} />
                  </td>
                </tr>
              );
            })}

            {/* Skeleton rows for pending IOCs */}
            {loading && Array.from({ length: Math.min(pendingCount || 3, 5) }).map((_, i) => (
              <SkeletonRow key={`skel-${i}`} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

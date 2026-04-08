import { useState } from 'react';
import IOCTypeChip from './IOCTypeChip.jsx';
import VerdictBadge from './VerdictBadge.jsx';
import { defang } from '../lib/defang.js';

function SkeletonRow({ cols = 6 }) {
  return (
    <tr style={{ borderBottom: '1px solid var(--border)' }}>
      {Array.from({ length: cols }).map((_, i) => (
        <td key={i} style={{ padding: '10px 12px' }}>
          <div className="skeleton" style={{ height: '14px', width: i === 0 ? '80%' : '60%' }} />
        </td>
      ))}
    </tr>
  );
}

const countryFlag = (code) => {
  if (!code || code.length !== 2) return '';
  return code.toUpperCase().split('').map(c => String.fromCodePoint(127397 + c.charCodeAt(0))).join('');
};

function GeoCell({ geo }) {
  if (!geo || !geo.queried) {
    return <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>N/A</span>;
  }
  if (geo.error || !geo.data?.found) {
    return <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>—</span>;
  }
  const { country, countryCode, as: asn, asName } = geo.data;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '2px', minWidth: '120px' }}>
      {country && (
        <span style={{ fontSize: '12px', color: 'var(--text-primary)', whiteSpace: 'nowrap' }}>
          {countryFlag(countryCode)} {country}
        </span>
      )}
      {asn && (
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '10px',
          color: 'var(--accent-teal)',
          whiteSpace: 'nowrap'
        }}>
          {asn}
        </span>
      )}
      {asName && (
        <span style={{
          fontSize: '10px',
          color: 'var(--text-secondary)',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          whiteSpace: 'nowrap',
          maxWidth: '160px'
        }}
        title={asName}
        >
          {asName}
        </span>
      )}
    </div>
  );
}

function VTCell({ data, error, queried, vtLink }) {
  const [copied, setCopied] = useState(false);

  if (!queried) return <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>N/A</span>;
  if (error) return <span style={{ color: '#ff7b7b', fontSize: '11px' }}>ERR</span>;
  if (!data) return <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>—</span>;

  const malicious = data.malicious || 0;
  const total = data.total || 0;
  let color = 'var(--accent-teal)';
  if (malicious > 2) color = '#ff7b7b';
  else if (malicious > 0) color = 'var(--accent-amber)';

  const handleCopyLink = async (e) => {
    e.stopPropagation();
    if (!vtLink) return;
    try {
      await navigator.clipboard.writeText(vtLink);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {}
  };

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
      <span style={{
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: '12px',
        color,
        fontWeight: 600
      }}>
        {malicious}/{total}
      </span>
      {vtLink && (
        <button
          onClick={handleCopyLink}
          title="Copy VirusTotal link"
          style={{
            background: 'none',
            border: `1px solid ${copied ? 'rgba(57,211,83,0.4)' : 'var(--border)'}`,
            borderRadius: '3px',
            padding: '1px 5px',
            fontSize: '9px',
            cursor: 'pointer',
            color: copied ? 'var(--accent-teal)' : 'var(--text-secondary)',
            fontFamily: "'JetBrains Mono', monospace",
            transition: 'all 0.15s'
          }}
          onMouseEnter={e => { if (!copied) e.currentTarget.style.borderColor = 'var(--accent-blue)'; }}
          onMouseLeave={e => { if (!copied) e.currentTarget.style.borderColor = 'var(--border)'; }}
        >
          {copied ? '✓' : 'VT'}
        </button>
      )}
    </div>
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

function SandboxCell({ urlscan, greynoise, iocType }) {
  const hasURLScan = urlscan?.queried && urlscan?.data?.found;
  const hasGN = greynoise?.queried && greynoise?.data?.found;

  if (!hasURLScan && !hasGN) {
    return <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>—</span>;
  }

  const usVerdict = urlscan?.data?.verdict;
  const usColor = usVerdict === 'malicious' ? '#ff7b7b' : usVerdict === 'suspicious' ? 'var(--accent-amber)' : 'var(--accent-teal)';

  const gnClass = greynoise?.data?.classification;
  const gnNoise = greynoise?.data?.noise;
  const gnRiot = greynoise?.data?.riot;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
      {hasURLScan && (
        <span style={{
          fontSize: '10px',
          fontWeight: 700,
          fontFamily: "'JetBrains Mono', monospace",
          padding: '1px 5px',
          borderRadius: '3px',
          backgroundColor: `${usColor}18`,
          border: `1px solid ${usColor}55`,
          color: usColor,
          whiteSpace: 'nowrap'
        }}>
          US: {usVerdict?.toUpperCase() || 'OK'}
        </span>
      )}
      {hasGN && (
        <span style={{
          fontSize: '10px',
          fontWeight: 700,
          fontFamily: "'JetBrains Mono', monospace",
          padding: '1px 5px',
          borderRadius: '3px',
          backgroundColor: gnClass === 'malicious'
            ? 'rgba(255,123,123,0.1)'
            : gnRiot
            ? 'rgba(57,211,83,0.1)'
            : gnNoise
            ? 'rgba(188,140,255,0.1)'
            : 'rgba(255,255,255,0.05)',
          border: `1px solid ${gnClass === 'malicious' ? 'rgba(255,123,123,0.4)' : gnRiot ? 'rgba(57,211,83,0.3)' : 'rgba(188,140,255,0.3)'}`,
          color: gnClass === 'malicious' ? '#ff7b7b' : gnRiot ? 'var(--accent-teal)' : 'var(--accent-purple)',
          whiteSpace: 'nowrap'
        }}
        title={greynoise?.data?.name || ''}
        >
          GN: {gnClass ? gnClass.toUpperCase() : gnRiot ? 'RIOT' : gnNoise ? 'NOISE' : 'OK'}
        </span>
      )}
    </div>
  );
}

function VerdictSummaryBar({ results }) {
  const counts = results.reduce((acc, r) => {
    const v = (r.verdict || 'CLEAN').toUpperCase();
    acc[v] = (acc[v] || 0) + 1;
    return acc;
  }, {});

  const items = [
    { label: 'MALICIOUS', color: '#da3633', bg: 'rgba(218,54,51,0.12)', border: 'rgba(218,54,51,0.3)' },
    { label: 'SUSPICIOUS', color: '#f0883e', bg: 'rgba(240,136,62,0.12)', border: 'rgba(240,136,62,0.3)' },
    { label: 'CLEAN', color: '#39d353', bg: 'rgba(57,211,83,0.1)', border: 'rgba(57,211,83,0.25)' },
  ].filter(i => counts[i.label]);

  if (items.length === 0) return null;

  return (
    <div style={{
      display: 'flex',
      gap: '8px',
      alignItems: 'center',
      padding: '8px 14px',
      borderBottom: '1px solid var(--border)',
      backgroundColor: 'rgba(0,0,0,0.15)',
      flexWrap: 'wrap'
    }}>
      <span style={{
        fontSize: '10px',
        color: 'var(--text-secondary)',
        textTransform: 'uppercase',
        letterSpacing: '0.08em',
        fontWeight: 600,
        marginRight: '4px'
      }}>
        Summary
      </span>
      {items.map(({ label, color, bg, border }) => (
        <span key={label} style={{
          fontSize: '11px',
          fontWeight: 700,
          fontFamily: "'JetBrains Mono', monospace",
          padding: '2px 8px',
          borderRadius: '4px',
          backgroundColor: bg,
          border: `1px solid ${border}`,
          color
        }}>
          {counts[label]} {label}
        </span>
      ))}
      <span style={{
        fontSize: '10px',
        color: 'var(--text-secondary)',
        marginLeft: 'auto'
      }}>
        {results.length} total
      </span>
    </div>
  );
}

function FilterBar({ active, onChange, counts }) {
  const filters = ['ALL', 'MALICIOUS', 'SUSPICIOUS', 'CLEAN'];

  return (
    <div style={{
      display: 'flex',
      gap: '4px',
      padding: '8px 14px',
      borderBottom: '1px solid var(--border)',
      backgroundColor: 'var(--bg-elevated)'
    }}>
      {filters.map(f => {
        const isActive = active === f;
        const count = f === 'ALL' ? null : counts[f] || 0;
        const colors = {
          MALICIOUS: '#da3633',
          SUSPICIOUS: '#f0883e',
          CLEAN: '#39d353',
          ALL: 'var(--accent-blue)'
        };

        return (
          <button
            key={f}
            onClick={() => onChange(f)}
            style={{
              padding: '3px 10px',
              borderRadius: '4px',
              fontSize: '11px',
              fontWeight: 600,
              fontFamily: "'JetBrains Mono', monospace",
              cursor: 'pointer',
              border: `1px solid ${isActive ? colors[f] : 'var(--border)'}`,
              backgroundColor: isActive ? `${colors[f]}18` : 'transparent',
              color: isActive ? colors[f] : 'var(--text-secondary)',
              transition: 'all 0.15s'
            }}
            onMouseEnter={e => { if (!isActive) e.currentTarget.style.borderColor = colors[f]; }}
            onMouseLeave={e => { if (!isActive) e.currentTarget.style.borderColor = 'var(--border)'; }}
          >
            {f}{count !== null && count > 0 ? ` (${count})` : ''}
          </button>
        );
      })}
    </div>
  );
}

function buildVTLink(ioc) {
  const base = 'https://www.virustotal.com/gui';
  switch (ioc.type) {
    case 'sha256':
    case 'sha1':
    case 'md5':
      return `${base}/file/${ioc.value}`;
    case 'ipv4':
      return `${base}/ip-address/${ioc.value}`;
    case 'domain':
      return `${base}/domain/${ioc.value}`;
    case 'url':
      return `${base}/url/${btoa(ioc.value).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')}`;
    default:
      return null;
  }
}

export default function EnrichmentTable({ results, loading, pendingCount }) {
  const [filter, setFilter] = useState('ALL');
  const hasResults = results && results.length > 0;
  const showGeo = results.some(r => r.ioc?.type === 'ipv4');
  const showSandbox = results.some(r => ['ipv4', 'domain', 'url'].includes(r.ioc?.type));
  const colCount = 6 + (showGeo ? 1 : 0) + (showSandbox ? 1 : 0);

  if (!hasResults && !loading) return null;

  const verdictCounts = results.reduce((acc, r) => {
    const v = (r.verdict || 'CLEAN').toUpperCase();
    acc[v] = (acc[v] || 0) + 1;
    return acc;
  }, {});

  const filteredResults = filter === 'ALL'
    ? results
    : results.filter(r => (r.verdict || 'CLEAN').toUpperCase() === filter);

  return (
    <div style={{
      backgroundColor: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: '8px',
      overflow: 'hidden',
      marginTop: '16px'
    }}>
      {/* Header */}
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

      {/* Verdict summary bar — only show when enrichment complete */}
      {hasResults && !loading && (
        <VerdictSummaryBar results={results} />
      )}

      {/* Filter bar — only show when there are results */}
      {hasResults && (
        <FilterBar active={filter} onChange={setFilter} counts={verdictCounts} />
      )}

      <div style={{ overflowX: 'auto' }}>
        <table style={{
          width: '100%',
          borderCollapse: 'collapse',
          fontSize: '12px'
        }}>
          <thead>
            <tr style={{ backgroundColor: 'var(--bg-elevated)' }}>
              {['IOC', 'Type', 'VT Score', 'Abuse %', ...(showGeo ? ['Geo'] : []), ...(showSandbox ? ['URLScan / GN'] : []), 'Tags / Status', 'Verdict'].map(h => (
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
            {filteredResults.map((item, i) => {
              const { ioc, enrichment, verdict } = item;
              const vt = enrichment?.virustotal;
              const abuse = enrichment?.abuseipdb;
              const mb = enrichment?.malwarebazaar;
              const geo = enrichment?.geo;
              const urlscan = enrichment?.urlscan;
              const greynoise = enrichment?.greynoise;

              const allTags = [
                ...(vt?.data?.tags || []),
                ...(mb?.data?.tags || []),
                ...(mb?.data?.found ? ['malware-db'] : [])
              ];

              const vtLink = buildVTLink(ioc);

              return (
                <tr key={i} style={{
                  borderBottom: '1px solid var(--border)',
                  backgroundColor: i % 2 === 0 ? 'transparent' : 'rgba(33,38,45,0.3)',
                  transition: 'background-color 0.1s'
                }}
                onMouseEnter={e => e.currentTarget.style.backgroundColor = 'rgba(56,139,253,0.05)'}
                onMouseLeave={e => e.currentTarget.style.backgroundColor = i % 2 === 0 ? 'transparent' : 'rgba(33,38,45,0.3)'}
                >
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

                  <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                    <IOCTypeChip type={ioc.type} />
                  </td>

                  <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                    <VTCell
                      data={vt?.data}
                      error={vt?.error}
                      queried={vt?.queried}
                      vtLink={vtLink}
                    />
                  </td>

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

                  {showGeo && (
                    <td style={{ padding: '10px 12px' }}>
                      <GeoCell geo={geo} />
                    </td>
                  )}

                  {showSandbox && (
                    <td style={{ padding: '10px 12px' }}>
                      <SandboxCell urlscan={urlscan} greynoise={greynoise} iocType={ioc.type} />
                    </td>
                  )}

                  <td style={{ padding: '10px 12px' }}>
                    <TagsCell tags={allTags} />
                  </td>

                  <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                    <VerdictBadge verdict={verdict} />
                  </td>
                </tr>
              );
            })}

            {loading && Array.from({ length: Math.min(pendingCount || 3, 5) }).map((_, i) => (
              <SkeletonRow key={`skel-${i}`} cols={colCount} />
            ))}

            {/* Empty state when filter has no matches */}
            {!loading && filteredResults.length === 0 && results.length > 0 && (
              <tr>
                <td colSpan={colCount} style={{
                  padding: '24px',
                  textAlign: 'center',
                  color: 'var(--text-secondary)',
                  fontSize: '12px'
                }}>
                  No {filter.toLowerCase()} IOCs in this batch
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

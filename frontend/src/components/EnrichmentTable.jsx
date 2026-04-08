import { useState } from 'react';
import IOCTypeChip from './IOCTypeChip.jsx';
import VerdictBadge from './VerdictBadge.jsx';
import { defang } from '../lib/defang.js';
import { computeVerdict, DEFAULT_THRESHOLDS } from '../lib/verdict.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const COLS = 5; // IOC | Type | VT Score | Abuse % | Verdict — never changes

// ─── Helpers ──────────────────────────────────────────────────────────────────

const countryFlag = (code) => {
  if (!code || code.length !== 2) return '';
  return code.toUpperCase().split('').map(c =>
    String.fromCodePoint(127397 + c.charCodeAt(0))
  ).join('');
};

function buildVTLink(ioc) {
  const base = 'https://www.virustotal.com/gui';
  switch (ioc.type) {
    case 'sha256': case 'sha1': case 'md5': return `${base}/file/${ioc.value}`;
    case 'ipv4':   return `${base}/ip-address/${ioc.value}`;
    case 'domain': return `${base}/domain/${ioc.value}`;
    case 'url':    return `${base}/url/${btoa(ioc.value).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'')}`;
    default:       return null;
  }
}

// ─── Skeleton row ─────────────────────────────────────────────────────────────

function SkeletonRow() {
  return (
    <tr style={{ borderBottom: '1px solid var(--border)' }}>
      {Array.from({ length: COLS }).map((_, i) => (
        <td key={i} style={{ padding: '10px 12px' }}>
          <div className="skeleton" style={{ height: '14px', width: i === 0 ? '75%' : '50%' }} />
        </td>
      ))}
    </tr>
  );
}

// ─── Detail section label ─────────────────────────────────────────────────────

function SectionLabel({ children }) {
  return (
    <div style={{
      fontSize: '9px', fontWeight: 700,
      color: 'var(--text-secondary)',
      textTransform: 'uppercase',
      letterSpacing: '0.1em',
      marginBottom: '5px'
    }}>
      {children}
    </div>
  );
}

// ─── Expanded detail row ──────────────────────────────────────────────────────

function ExpandedDetail({ ioc, enrichment }) {
  const [copied, setCopied] = useState(false);

  const vt       = enrichment?.virustotal;
  const abuse    = enrichment?.abuseipdb;
  const mb       = enrichment?.malwarebazaar;
  const geo      = enrichment?.geo;
  const urlscan  = enrichment?.urlscan;
  const gn       = enrichment?.greynoise;
  const vtLink   = buildVTLink(ioc);


  const allTags = [
    ...(vt?.data?.tags  || []),
    ...(mb?.data?.tags  || []),
    ...(mb?.data?.found ? ['malware-db'] : [])
  ];

  const handleCopyVT = async (e) => {
    e.stopPropagation();
    if (!vtLink) return;
    try { await navigator.clipboard.writeText(vtLink); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch {}
  };

  const sections = [];

  // Geolocation
  if (geo?.queried && geo?.data?.found) {
    const { country, countryCode, as: asn, asName } = geo.data;
    sections.push(
      <div key="geo" style={{ minWidth: '120px' }}>
        <SectionLabel>Geolocation</SectionLabel>
        {country  && <div style={{ fontSize: '12px', color: 'var(--text-primary)', marginBottom: '2px' }}>{countryFlag(countryCode)} {country}</div>}
        {asn      && <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px', color: 'var(--accent-teal)', marginBottom: '2px' }}>{asn}</div>}
        {asName   && <div style={{ fontSize: '11px', color: 'var(--text-secondary)', maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={asName}>{asName}</div>}
      </div>
    );
  }

  // GreyNoise
  if (gn?.queried && gn?.data?.found) {
    const { classification: gnClass, noise: gnNoise, riot: gnRiot, name: gnName, lastSeen: gnSeen } = gn.data;
    // Prioritise riot/noise labels over the generic classification string
    const gnLabel = gnRiot ? 'RIOT' : gnNoise ? 'NOISE' : gnClass ? gnClass.toUpperCase() : 'OK';
    const gnColor = gnClass === 'malicious' ? '#ff7b7b' : gnRiot ? 'var(--accent-teal)' : 'var(--accent-purple)';
    sections.push(
      <div key="gn" style={{ minWidth: '100px' }}>
        <SectionLabel>GreyNoise</SectionLabel>
        <span style={{
          display: 'inline-block', fontSize: '11px', fontWeight: 700,
          fontFamily: "'JetBrains Mono', monospace",
          padding: '2px 8px', borderRadius: '3px',
          backgroundColor: `${gnColor}18`, border: `1px solid ${gnColor}55`, color: gnColor,
          marginBottom: '3px'
        }}>{gnLabel}</span>
        {gnName   && <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{gnName}</div>}
        {gnSeen   && <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '2px' }}>Last seen {gnSeen}</div>}
      </div>
    );
  }

  // URLScan
  if (urlscan?.queried && urlscan?.data?.found) {
    const { verdict: usVerdict, totalScans, score: usScore } = urlscan.data;
    const usColor = usVerdict === 'malicious' ? '#ff7b7b' : usVerdict === 'suspicious' ? 'var(--accent-amber)' : 'var(--accent-teal)';
    sections.push(
      <div key="urlscan" style={{ minWidth: '100px' }}>
        <SectionLabel>URLScan.io</SectionLabel>
        <span style={{
          display: 'inline-block', fontSize: '11px', fontWeight: 700,
          fontFamily: "'JetBrains Mono', monospace",
          padding: '2px 8px', borderRadius: '3px',
          backgroundColor: `${usColor}18`, border: `1px solid ${usColor}55`, color: usColor,
          marginBottom: '3px'
        }}>{usVerdict?.toUpperCase() || 'UNRATED'}</span>
        <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{totalScans} scan{totalScans !== 1 ? 's' : ''}</div>
        {usScore > 0 && <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '2px' }}>Score: {usScore}</div>}
      </div>
    );
  }

  // MalwareBazaar
  if (mb?.queried) {
    sections.push(
      <div key="mb" style={{ minWidth: '110px' }}>
        <SectionLabel>MalwareBazaar</SectionLabel>
        {mb.data?.found ? (
          <>
            <div style={{ fontSize: '11px', color: '#ff7b7b', fontWeight: 600, marginBottom: '2px' }}>✓ Found in DB</div>
            {mb.data.name      && <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{mb.data.name}</div>}
            {mb.data.signature && <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '10px', color: 'var(--accent-purple)', marginTop: '2px' }}>{mb.data.signature}</div>}
          </>
        ) : (
          <div style={{ fontSize: '11px', color: 'var(--accent-teal)' }}>Not in DB</div>
        )}
      </div>
    );
  }

  // AbuseIPDB detail
  if (abuse?.queried && abuse?.data) {
    const { totalReports, lastSeen: abuseSeen, country: abuseCountry } = abuse.data;
    if (totalReports > 0) {
      sections.push(
        <div key="abuse" style={{ minWidth: '100px' }}>
          <SectionLabel>AbuseIPDB</SectionLabel>
          <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>{totalReports} report{totalReports !== 1 ? 's' : ''}</div>
          {abuseCountry && <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>Country: {abuseCountry}</div>}
          {abuseSeen    && <div style={{ fontSize: '10px', color: 'var(--text-secondary)', marginTop: '2px' }}>Last seen {new Date(abuseSeen).toLocaleDateString()}</div>}
        </div>
      );
    }
  }

  // Tags
  if (allTags.length > 0) {
    sections.push(
      <div key="tags" style={{ minWidth: '100px' }}>
        <SectionLabel>Tags</SectionLabel>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '3px' }}>
          {allTags.map((tag, i) => (
            <span key={i} style={{
              fontSize: '10px', padding: '1px 5px',
              backgroundColor: 'rgba(188,140,255,0.1)',
              border: '1px solid rgba(188,140,255,0.3)',
              borderRadius: '3px', color: 'var(--accent-purple)',
              fontFamily: "'JetBrains Mono', monospace"
            }}>{tag}</span>
          ))}
        </div>
      </div>
    );
  }

  // VirusTotal meta + link
  if (vt?.queried && !vt?.error) {
    sections.push(
      <div key="vt-meta" style={{ minWidth: '100px' }}>
        <SectionLabel>VirusTotal</SectionLabel>
        {vt.data?.lastSeen && (
          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
            Last seen {new Date(vt.data.lastSeen).toLocaleDateString()}
          </div>
        )}
        {vtLink && (
          <button
            onClick={handleCopyVT}
            style={{
              background: 'none',
              border: `1px solid ${copied ? 'rgba(57,211,83,0.4)' : 'var(--border)'}`,
              borderRadius: '3px', padding: '2px 8px',
              fontSize: '10px', cursor: 'pointer',
              color: copied ? 'var(--accent-teal)' : 'var(--text-secondary)',
              fontFamily: "'JetBrains Mono', monospace",
              transition: 'all 0.15s'
            }}
          >
            {copied ? '✓ Copied' : 'Copy VT link'}
          </button>
        )}
      </div>
    );
  }

  return (
    <tr>
      <td colSpan={COLS} style={{
        padding: '10px 14px 14px 44px',
        backgroundColor: 'rgba(0,0,0,0.2)',
        borderBottom: '2px solid var(--border)',
        borderLeft: '3px solid var(--accent-blue)'
      }}>
        {sections.length > 0 ? (
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '20px 32px' }}>
            {sections}
          </div>
        ) : (
          <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>No additional detail available.</span>
        )}
      </td>
    </tr>
  );
}

// ─── Verdict summary bar ──────────────────────────────────────────────────────

function VerdictSummaryBar({ results }) {
  const counts = results.reduce((acc, r) => {
    const v = (r.verdict || 'CLEAN').toUpperCase();
    acc[v] = (acc[v] || 0) + 1;
    return acc;
  }, {});

  const items = [
    { label: 'MALICIOUS',  color: '#da3633', bg: 'rgba(218,54,51,0.12)',  border: 'rgba(218,54,51,0.3)' },
    { label: 'SUSPICIOUS', color: '#f0883e', bg: 'rgba(240,136,62,0.12)', border: 'rgba(240,136,62,0.3)' },
    { label: 'CLEAN',      color: '#39d353', bg: 'rgba(57,211,83,0.1)',   border: 'rgba(57,211,83,0.25)' },
  ].filter(i => counts[i.label]);

  if (items.length === 0) return null;

  return (
    <div style={{
      display: 'flex', gap: '8px', alignItems: 'center',
      padding: '8px 14px', borderBottom: '1px solid var(--border)',
      backgroundColor: 'rgba(0,0,0,0.15)', flexWrap: 'wrap'
    }}>
      <span style={{
        fontSize: '10px', color: 'var(--text-secondary)',
        textTransform: 'uppercase', letterSpacing: '0.08em',
        fontWeight: 600, marginRight: '4px'
      }}>Summary</span>
      {items.map(({ label, color, bg, border }) => (
        <span key={label} style={{
          fontSize: '11px', fontWeight: 700,
          fontFamily: "'JetBrains Mono', monospace",
          padding: '2px 8px', borderRadius: '4px',
          backgroundColor: bg, border: `1px solid ${border}`, color
        }}>{counts[label]} {label}</span>
      ))}
      <span style={{ fontSize: '10px', color: 'var(--text-secondary)', marginLeft: 'auto' }}>
        {results.length} total
      </span>
    </div>
  );
}

// ─── Filter bar ───────────────────────────────────────────────────────────────

function FilterBar({ active, onChange, counts }) {
  const filters = ['ALL', 'MALICIOUS', 'SUSPICIOUS', 'CLEAN'];
  const colors = { MALICIOUS: '#da3633', SUSPICIOUS: '#f0883e', CLEAN: '#39d353', ALL: 'var(--accent-blue)' };

  return (
    <div style={{
      display: 'flex', gap: '4px', padding: '8px 14px',
      borderBottom: '1px solid var(--border)',
      backgroundColor: 'var(--bg-elevated)'
    }}>
      {filters.map(f => {
        const isActive = active === f;
        const count = f === 'ALL' ? null : counts[f] || 0;
        return (
          <button key={f} onClick={() => onChange(f)} style={{
            padding: '3px 10px', borderRadius: '4px',
            fontSize: '11px', fontWeight: 600,
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
      <span style={{
        marginLeft: 'auto', fontSize: '10px',
        color: 'var(--text-secondary)',
        alignSelf: 'center', fontStyle: 'italic'
      }}>
        Click any row to expand
      </span>
    </div>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function EnrichmentTable({ results, loading, pendingCount, thresholds = DEFAULT_THRESHOLDS }) {
  const [filter, setFilter] = useState('ALL');
  const [expandedRows, setExpandedRows] = useState(new Set());

  const hasResults = results && results.length > 0;

  if (!hasResults && !loading) return null;

  // Re-compute verdicts using current thresholds so they update instantly
  // when settings change, without needing to re-run enrichment.
  const resultsWithVerdict = results.map(r => ({
    ...r,
    verdict: computeVerdict(r.enrichment, thresholds)
  }));

  const verdictCounts = resultsWithVerdict.reduce((acc, r) => {
    const v = (r.verdict || 'CLEAN').toUpperCase();
    acc[v] = (acc[v] || 0) + 1;
    return acc;
  }, {});

  const filteredResults = filter === 'ALL'
    ? resultsWithVerdict
    : resultsWithVerdict.filter(r => (r.verdict || 'CLEAN').toUpperCase() === filter);

  const toggleRow = (idx) => {
    setExpandedRows(prev => {
      const next = new Set(prev);
      next.has(idx) ? next.delete(idx) : next.add(idx);
      return next;
    });
  };

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
        padding: '10px 14px', borderBottom: '1px solid var(--border)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center'
      }}>
        <span style={{
          fontSize: '12px', fontWeight: 600,
          color: 'var(--text-secondary)',
          textTransform: 'uppercase', letterSpacing: '0.08em'
        }}>Enrichment Results</span>
        {hasResults && (
          <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
            {results.length} IOC{results.length !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {hasResults && !loading && <VerdictSummaryBar results={results} />}
      {hasResults && <FilterBar active={filter} onChange={setFilter} counts={verdictCounts} />}

      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px' }}>
        <thead>
          <tr style={{ backgroundColor: 'var(--bg-elevated)' }}>
            {['IOC', 'Type', 'VT Score', 'Abuse %', 'Verdict'].map(h => (
              <th key={h} style={{
                padding: '8px 12px', textAlign: 'left',
                color: 'var(--text-secondary)', fontWeight: 600,
                fontSize: '11px', letterSpacing: '0.06em',
                textTransform: 'uppercase',
                borderBottom: '1px solid var(--border)',
                whiteSpace: 'nowrap'
              }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {filteredResults.map((item, i) => {
            const { ioc, enrichment, verdict } = item;
            const vt    = enrichment?.virustotal;
            const abuse = enrichment?.abuseipdb;
            const isExpanded = expandedRows.has(i);

            const malicious = vt?.data?.malicious || 0;
            const total     = vt?.data?.total || 0;
            const vtColor   = malicious > 2 ? '#ff7b7b' : malicious > 0 ? 'var(--accent-amber)' : 'var(--accent-teal)';

            const abuseScore = abuse?.data?.abuseScore;
            const abuseColor = abuseScore >= 75 ? '#ff7b7b' : abuseScore >= 26 ? 'var(--accent-amber)' : 'var(--accent-teal)';

            const rowBg = i % 2 === 0 ? 'transparent' : 'rgba(33,38,45,0.3)';

            return [
              // ── Main row ──────────────────────────────────────────────────
              <tr
                key={`row-${i}`}
                onClick={() => toggleRow(i)}
                style={{
                  borderBottom: isExpanded ? 'none' : '1px solid var(--border)',
                  backgroundColor: isExpanded ? 'rgba(56,139,253,0.06)' : rowBg,
                  cursor: 'pointer',
                  transition: 'background-color 0.1s',
                  userSelect: 'none'
                }}
                onMouseEnter={e => { if (!isExpanded) e.currentTarget.style.backgroundColor = 'rgba(56,139,253,0.05)'; }}
                onMouseLeave={e => { if (!isExpanded) e.currentTarget.style.backgroundColor = rowBg; }}
              >
                {/* IOC value + expand chevron */}
                <td style={{ padding: '10px 12px', maxWidth: '260px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{
                      fontSize: '10px',
                      color: isExpanded ? 'var(--accent-blue)' : 'var(--text-secondary)',
                      transition: 'transform 0.15s, color 0.15s',
                      transform: isExpanded ? 'rotate(90deg)' : 'none',
                      display: 'inline-block',
                      lineHeight: 1,
                      flexShrink: 0
                    }}>▶</span>
                    <span style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      color: 'var(--text-mono)', fontSize: '12px',
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                    }} title={defang(ioc.value, ioc.type)}>
                      {defang(ioc.value, ioc.type)}
                    </span>
                  </div>
                </td>

                {/* Type */}
                <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                  <IOCTypeChip type={ioc.type} />
                </td>

                {/* VT Score */}
                <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                  {vt?.queried ? (
                    vt.error
                      ? <span style={{ color: '#ff7b7b', fontSize: '11px' }}>ERR</span>
                      : <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: vtColor, fontWeight: 600 }}>
                          {malicious}/{total}
                        </span>
                  ) : (
                    <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>N/A</span>
                  )}
                </td>

                {/* Abuse % */}
                <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                  {abuse?.queried ? (
                    abuseScore !== null && abuseScore !== undefined
                      ? <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '12px', color: abuseColor, fontWeight: 600 }}>{abuseScore}</span>
                      : <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>—</span>
                  ) : (
                    <span style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>N/A</span>
                  )}
                </td>

                {/* Verdict */}
                <td style={{ padding: '10px 12px', whiteSpace: 'nowrap' }}>
                  <VerdictBadge verdict={verdict} />
                </td>
              </tr>,

              // ── Expanded detail row ───────────────────────────────────────
              isExpanded && (
                <ExpandedDetail
                  key={`detail-${i}`}
                  ioc={ioc}
                  enrichment={enrichment}
                />
              )
            ];
          })}

          {/* Skeleton rows while loading */}
          {loading && Array.from({ length: Math.min(pendingCount || 3, 5) }).map((_, i) => (
            <SkeletonRow key={`skel-${i}`} />
          ))}

          {/* Empty filter state */}
          {!loading && filteredResults.length === 0 && results.length > 0 && (
            <tr>
              <td colSpan={COLS} style={{
                padding: '24px', textAlign: 'center',
                color: 'var(--text-secondary)', fontSize: '12px'
              }}>
                No {filter.toLowerCase()} IOCs in this batch
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

import { useState, useCallback } from 'react';
import { parseIOCs, MAX_IOCS } from '../lib/iocParser.js';
import IOCTypeChip from './IOCTypeChip.jsx';
import { defang } from '../lib/defang.js';

export default function IOCInput({ onAnalyze, loading }) {
  const [text, setText] = useState('');
  const [parsedIocs, setParsedIocs] = useState([]);

  const handleChange = useCallback((e) => {
    const val = e.target.value;
    setText(val);
    setParsedIocs(parseIOCs(val));
  }, []);

  const handleSubmit = useCallback(() => {
    if (parsedIocs.length === 0 || loading) return;
    onAnalyze(parsedIocs);
  }, [parsedIocs, loading, onAnalyze]);

  const handleKeyDown = useCallback((e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      handleSubmit();
    }
  }, [handleSubmit]);

  const handleClear = useCallback(() => {
    setText('');
    setParsedIocs([]);
  }, []);

  const iocCount = parsedIocs.length;
  const atLimit = iocCount >= MAX_IOCS;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <h2 style={{
          margin: 0,
          fontSize: '13px',
          fontWeight: 600,
          color: 'var(--text-secondary)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em'
        }}>
          IOC Input
        </h2>
        {text && (
          <button
            onClick={handleClear}
            disabled={loading}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-secondary)',
              cursor: loading ? 'not-allowed' : 'pointer',
              fontSize: '12px',
              padding: '2px 6px',
              borderRadius: '4px'
            }}
          >
            Clear
          </button>
        )}
      </div>

      {/* Textarea */}
      <textarea
        value={text}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        disabled={loading}
        placeholder={`Paste IOCs here — hashes, IPs, domains, URLs.\nOne per line, or comma/space separated.\nDefanged formats supported (hxxp://, [.]).\n\nCtrl+Enter to analyze.`}
        style={{
          width: '100%',
          height: '200px',
          padding: '12px',
          backgroundColor: 'var(--bg-elevated)',
          border: '1px solid var(--border)',
          borderRadius: '6px',
          color: 'var(--text-primary)',
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '13px',
          lineHeight: '1.6',
          resize: 'vertical',
          outline: 'none',
          transition: 'border-color 0.2s',
          opacity: loading ? 0.6 : 1
        }}
        onFocus={e => e.target.style.borderColor = 'var(--accent-blue)'}
        onBlur={e => e.target.style.borderColor = 'var(--border)'}
      />

      {/* IOC chip preview */}
      {parsedIocs.length > 0 && (
        <div>
          <div style={{
            fontSize: '11px',
            color: 'var(--text-secondary)',
            marginBottom: '6px',
            display: 'flex',
            justifyContent: 'space-between'
          }}>
            <span>{iocCount} IOC{iocCount !== 1 ? 's' : ''} detected</span>
            {atLimit && (
              <span style={{ color: 'var(--accent-amber)' }}>
                Max {MAX_IOCS} reached — additional IOCs ignored
              </span>
            )}
          </div>
          <div style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '6px',
            maxHeight: '120px',
            overflowY: 'auto',
            padding: '8px',
            backgroundColor: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: '6px'
          }}>
            {parsedIocs.map((ioc, i) => (
              <div key={i} style={{
                display: 'flex',
                alignItems: 'center',
                gap: '5px',
                padding: '3px 8px',
                backgroundColor: 'var(--bg-elevated)',
                borderRadius: '4px',
                border: '1px solid var(--border)'
              }}>
                <IOCTypeChip type={ioc.type} />
                <span style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '11px',
                  color: 'var(--text-mono)',
                  maxWidth: '180px',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap'
                }}>
                  {defang(ioc.value, ioc.type)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Analyze button */}
      <button
        onClick={handleSubmit}
        disabled={parsedIocs.length === 0 || loading}
        style={{
          width: '100%',
          padding: '10px 16px',
          backgroundColor: parsedIocs.length > 0 && !loading
            ? 'var(--accent-blue)'
            : 'var(--bg-elevated)',
          color: parsedIocs.length > 0 && !loading
            ? '#fff'
            : 'var(--text-secondary)',
          border: '1px solid ' + (parsedIocs.length > 0 && !loading ? 'transparent' : 'var(--border)'),
          borderRadius: '6px',
          fontSize: '13px',
          fontWeight: 600,
          fontFamily: "'IBM Plex Sans', sans-serif",
          cursor: parsedIocs.length === 0 || loading ? 'not-allowed' : 'pointer',
          transition: 'all 0.2s',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: '8px'
        }}
      >
        {loading ? (
          <>
            <span style={{
              display: 'inline-block',
              width: '12px',
              height: '12px',
              border: '2px solid var(--text-secondary)',
              borderTopColor: 'transparent',
              borderRadius: '50%',
              animation: 'spin 0.8s linear infinite'
            }} />
            Enriching {iocCount} IOC{iocCount !== 1 ? 's' : ''}...
          </>
        ) : (
          <>
            Analyze {iocCount > 0 ? `${iocCount} IOC${iocCount !== 1 ? 's' : ''}` : 'IOCs'}
            {iocCount > 0 && (
              <span style={{ fontSize: '11px', opacity: 0.7 }}>⌘↵</span>
            )}
          </>
        )}
      </button>

      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

import { useState, useCallback, useEffect, useRef } from 'react';
import { parseIOCs, MAX_IOCS } from '../lib/iocParser.js';
import IOCTypeChip from './IOCTypeChip.jsx';
import { defang } from '../lib/defang.js';

export default function IOCInput({ onAnalyze, loading, injectedValue, onInjectedValueConsumed }) {
  const [text, setText] = useState('');
  const [parsedIocs, setParsedIocs] = useState([]);
  const [isDragging, setIsDragging] = useState(false);
  const [fileInfo, setFileInfo] = useState(null); // { name, count }
  const fileInputRef = useRef(null);

  useEffect(() => {
    if (injectedValue) {
      setText(injectedValue);
      setParsedIocs(parseIOCs(injectedValue));
      onInjectedValueConsumed?.();
    }
  }, [injectedValue, onInjectedValueConsumed]);

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
    setFileInfo(null);
  }, []);

  const handleFile = useCallback((file) => {
    if (!file) return;
    const allowed = ['text/plain', 'text/csv', 'application/csv', ''];
    const ext = file.name.split('.').pop().toLowerCase();
    if (!['txt', 'csv', 'log', 'md'].includes(ext) && !allowed.includes(file.type)) return;

    const reader = new FileReader();
    reader.onload = (e) => {
      const fileText = e.target.result || '';
      setText(prev => {
        const merged = prev.trim() ? prev.trim() + '\n' + fileText : fileText;
        const parsed = parseIOCs(merged);
        setParsedIocs(parsed);
        setFileInfo({ name: file.name, count: parseIOCs(fileText).length });
        return merged;
      });
    };
    reader.readAsText(file);
  }, []);

  const handleDragOver = useCallback((e) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setIsDragging(false);
    const file = e.dataTransfer.files?.[0];
    handleFile(file);
  }, [handleFile]);

  const handleFileInputChange = useCallback((e) => {
    handleFile(e.target.files?.[0]);
    e.target.value = '';
  }, [handleFile]);

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

      {/* Hidden file input */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".txt,.csv,.log,.md"
        style={{ display: 'none' }}
        onChange={handleFileInputChange}
      />

      {/* File badge */}
      {fileInfo && (
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '5px 10px',
          backgroundColor: 'rgba(56,189,248,0.08)',
          border: '1px solid rgba(56,189,248,0.25)',
          borderRadius: '5px',
          fontSize: '12px',
          color: 'var(--accent-blue)'
        }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace" }}>📄</span>
          <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            <strong>{fileInfo.count}</strong> IOCs from <em>{fileInfo.name}</em>
          </span>
          <button
            onClick={() => setFileInfo(null)}
            style={{
              background: 'none', border: 'none',
              color: 'var(--text-secondary)', cursor: 'pointer',
              fontSize: '14px', padding: '0 2px', lineHeight: 1
            }}
            title="Dismiss"
          >×</button>
        </div>
      )}

      {/* Textarea with drag-and-drop zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        style={{ position: 'relative' }}
      >
        <textarea
          value={text}
          onChange={handleChange}
          onKeyDown={handleKeyDown}
          disabled={loading}
          placeholder={`Paste IOCs here — hashes, IPs, domains, URLs.\nOne per line, or comma/space separated.\nDefanged formats supported (hxxp://, [.]).\n\nDrag & drop a .txt or .csv file, or use Upload File.\nCtrl+Enter to analyze.`}
          style={{
            width: '100%',
            height: '200px',
            padding: '12px',
            backgroundColor: isDragging ? 'rgba(56,189,248,0.06)' : 'var(--bg-elevated)',
            border: `1px solid ${isDragging ? 'var(--accent-blue)' : 'var(--border)'}`,
            borderRadius: '6px',
            color: 'var(--text-primary)',
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: '13px',
            lineHeight: '1.6',
            resize: 'vertical',
            outline: 'none',
            transition: 'border-color 0.2s, background-color 0.2s',
            opacity: loading ? 0.6 : 1,
            boxSizing: 'border-box'
          }}
          onFocus={e => { if (!isDragging) e.target.style.borderColor = 'var(--accent-blue)'; }}
          onBlur={e => { if (!isDragging) e.target.style.borderColor = 'var(--border)'; }}
        />
        {isDragging && (
          <div style={{
            position: 'absolute', inset: 0,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            pointerEvents: 'none',
            borderRadius: '6px',
            backgroundColor: 'rgba(56,189,248,0.06)'
          }}>
            <span style={{ fontSize: '13px', color: 'var(--accent-blue)', fontWeight: 600 }}>
              Drop file to import IOCs
            </span>
          </div>
        )}
      </div>

      {/* Upload file button */}
      <button
        onClick={() => fileInputRef.current?.click()}
        disabled={loading}
        style={{
          width: '100%',
          padding: '7px 12px',
          backgroundColor: 'transparent',
          border: '1px dashed var(--border)',
          borderRadius: '6px',
          color: 'var(--text-secondary)',
          fontSize: '12px',
          fontFamily: "'IBM Plex Sans', sans-serif",
          cursor: loading ? 'not-allowed' : 'pointer',
          transition: 'border-color 0.2s, color 0.2s'
        }}
        onMouseEnter={e => { e.target.style.borderColor = 'var(--accent-blue)'; e.target.style.color = 'var(--accent-blue)'; }}
        onMouseLeave={e => { e.target.style.borderColor = 'var(--border)'; e.target.style.color = 'var(--text-secondary)'; }}
      >
        Upload file (.txt · .csv · .log)
      </button>

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

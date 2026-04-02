import { useState, useCallback, useRef } from 'react';
import IOCInput from './components/IOCInput.jsx';
import EnrichmentTable from './components/EnrichmentTable.jsx';
import AnalystReport from './components/AnalystReport.jsx';
import ProgressBar from './components/ProgressBar.jsx';
import ExportButton from './components/ExportButton.jsx';

export default function App() {
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState([]);
  const [progress, setProgress] = useState({ processed: 0, total: 0, waitingMs: 0 });
  const [reportText, setReportText] = useState('');
  const [reportStreaming, setReportStreaming] = useState(false);
  const [error, setError] = useState(null);
  const abortRef = useRef(null);

  const handleAnalyze = useCallback(async (parsedIocs) => {
    // Cancel any in-flight request
    if (abortRef.current) {
      abortRef.current.abort();
    }

    setLoading(true);
    setResults([]);
    setReportText('');
    setReportStreaming(false);
    setError(null);
    setProgress({ processed: 0, total: parsedIocs.length, waitingMs: 0 });

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const response = await fetch('/api/enrich', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ iocs: parsedIocs.map(ioc => ioc.value) }),
        signal: controller.signal
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
        throw new Error(err.error || `Request failed with status ${response.status}`);
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop(); // keep incomplete line

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          const jsonStr = line.slice(6).trim();
          if (!jsonStr) continue;

          let event;
          try {
            event = JSON.parse(jsonStr);
          } catch {
            continue;
          }

          switch (event.type) {
            case 'progress':
              setProgress({
                processed: event.processed,
                total: event.total,
                waitingMs: event.waitingMs || 0
              });
              break;

            case 'result':
              setResults(prev => [...prev, {
                ioc: event.ioc,
                enrichment: event.enrichment,
                verdict: event.verdict,
                enrichedAt: event.enrichedAt
              }]);
              setProgress(prev => ({
                ...prev,
                processed: Math.max(prev.processed, event.ioc ? prev.processed + 1 : prev.processed)
              }));
              break;

            case 'report_chunk':
              if (!reportStreaming) setReportStreaming(true);
              setReportText(prev => prev + (event.text || ''));
              break;

            case 'done':
              setReportStreaming(false);
              setLoading(false);
              break;

            case 'error':
              setError(event.message || 'Unknown enrichment error');
              setReportStreaming(false);
              setLoading(false);
              break;
          }
        }
      }
    } catch (err) {
      if (err.name === 'AbortError') return;
      setError(err.message || 'Failed to connect to ARGUS backend');
    } finally {
      setReportStreaming(false);
      setLoading(false);
    }
  }, []);

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      minHeight: '100vh',
      backgroundColor: 'var(--bg-primary)'
    }}>
      {/* Header */}
      <header style={{
        borderBottom: '1px solid var(--border)',
        padding: '12px 24px',
        display: 'flex',
        alignItems: 'center',
        gap: '12px',
        backgroundColor: 'var(--bg-surface)'
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px'
        }}>
          <div style={{
            width: '28px',
            height: '28px',
            borderRadius: '6px',
            backgroundColor: 'var(--accent-blue)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '14px',
            fontWeight: 700,
            color: '#fff',
            fontFamily: "'JetBrains Mono', monospace"
          }}>
            A
          </div>
          <div>
            <div style={{
              fontSize: '14px',
              fontWeight: 700,
              color: 'var(--text-primary)',
              letterSpacing: '0.1em',
              fontFamily: "'IBM Plex Sans', sans-serif"
            }}>
              ARGUS
            </div>
            <div style={{
              fontSize: '10px',
              color: 'var(--text-secondary)',
              letterSpacing: '0.06em'
            }}>
              IOC Enrichment Engine
            </div>
          </div>
        </div>

        <div style={{ marginLeft: 'auto', display: 'flex', gap: '8px', alignItems: 'center' }}>
          <span style={{
            fontSize: '11px',
            color: 'var(--text-secondary)',
            padding: '3px 8px',
            border: '1px solid var(--border)',
            borderRadius: '4px',
            fontFamily: "'JetBrains Mono', monospace"
          }}>
            VT · AbuseIPDB · MalwareBazaar
          </span>
        </div>
      </header>

      {/* Main content — two panel layout */}
      <main style={{
        flex: 1,
        display: 'flex',
        gap: '0',
        overflow: 'hidden'
      }}>
        {/* Left panel: Input (40%) */}
        <div style={{
          width: '40%',
          minWidth: '320px',
          borderRight: '1px solid var(--border)',
          padding: '20px',
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px'
        }}>
          <IOCInput onAnalyze={handleAnalyze} loading={loading} />

          {/* Progress indicator */}
          {(loading || progress.total > 0) && (
            <ProgressBar
              processed={progress.processed}
              total={progress.total}
              waitingMs={progress.waitingMs}
            />
          )}

          {/* Error display */}
          {error && (
            <div style={{
              padding: '10px 14px',
              backgroundColor: 'rgba(218,54,51,0.1)',
              border: '1px solid rgba(218,54,51,0.3)',
              borderRadius: '6px',
              fontSize: '13px',
              color: '#ff7b7b'
            }}>
              <strong>Error:</strong> {error}
            </div>
          )}

          {/* Tips */}
          {!loading && results.length === 0 && !error && (
            <div style={{
              padding: '12px',
              backgroundColor: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: '6px',
              fontSize: '12px',
              color: 'var(--text-secondary)',
              lineHeight: '1.7'
            }}>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>
                Supported IOC formats
              </div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '11px' }}>
                <div style={{ color: 'var(--accent-amber)' }}>MD5 · SHA1 · SHA256</div>
                <div style={{ color: 'var(--accent-blue)' }}>IPv4 addresses</div>
                <div style={{ color: 'var(--accent-teal)' }}>Domains</div>
                <div style={{ color: 'var(--accent-purple)' }}>URLs (http/https)</div>
              </div>
              <div style={{ marginTop: '8px', fontSize: '11px' }}>
                Defanged formats supported: <code style={{ color: 'var(--text-mono)', fontSize: '10px' }}>hxxp://</code>, <code style={{ color: 'var(--text-mono)', fontSize: '10px' }}>[.]</code>, <code style={{ color: 'var(--text-mono)', fontSize: '10px' }}>[dot]</code>
              </div>
            </div>
          )}
        </div>

        {/* Right panel: Results (60%) */}
        <div style={{
          flex: 1,
          padding: '20px',
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: '16px'
        }}>
          {results.length === 0 && !loading ? (
            <div style={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--text-secondary)',
              gap: '12px',
              padding: '40px'
            }}>
              <div style={{
                fontSize: '48px',
                opacity: 0.2,
                fontFamily: "'JetBrains Mono', monospace",
                fontWeight: 700
              }}>
                []
              </div>
              <div style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  No IOCs analyzed yet
                </div>
                <div style={{ fontSize: '12px', color: 'var(--border)' }}>
                  Paste IOCs in the input panel and click Analyze
                </div>
              </div>
            </div>
          ) : (
            <>
              <EnrichmentTable
                results={results}
                loading={loading}
                pendingCount={progress.total - progress.processed}
              />

              {(reportText || reportStreaming) && (
                <AnalystReport
                  reportText={reportText}
                  streaming={reportStreaming}
                />
              )}

              {results.length > 0 && !loading && (
                <ExportButton results={results} reportText={reportText} />
              )}
            </>
          )}
        </div>
      </main>
    </div>
  );
}

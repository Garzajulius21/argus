import { useEffect, useRef } from 'react';

/**
 * AnalystReport — streaming markdown panel for Claude's correlation brief.
 * Simple markdown rendering without external deps.
 */
function renderMarkdown(text) {
  if (!text) return '';

  const lines = text.split('\n');
  const result = [];
  let inList = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Headings
    if (line.startsWith('## ')) {
      if (inList) { inList = false; result.push('</ul>'); }
      result.push(`<h3 style="color:var(--text-primary);font-size:14px;font-weight:600;margin:18px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--border);">${escHtml(line.slice(3))}</h3>`);
    } else if (line.startsWith('# ')) {
      if (inList) { inList = false; result.push('</ul>'); }
      result.push(`<h2 style="color:var(--text-primary);font-size:16px;font-weight:700;margin:20px 0 10px;">${escHtml(line.slice(2))}</h2>`);
    }
    // Bullet points
    else if (line.startsWith('- ') || line.startsWith('* ')) {
      if (!inList) { inList = true; result.push('<ul style="margin:6px 0;padding-left:18px;">'); }
      const content = formatInline(line.slice(2));
      result.push(`<li style="color:var(--text-primary);font-size:13px;line-height:1.7;margin:3px 0;">${content}</li>`);
    }
    // Numbered list
    else if (/^\d+\.\s/.test(line)) {
      if (inList) { inList = false; result.push('</ul>'); }
      const content = formatInline(line.replace(/^\d+\.\s/, ''));
      result.push(`<p style="color:var(--text-primary);font-size:13px;line-height:1.7;margin:3px 0;padding-left:4px;">${content}</p>`);
    }
    // Empty line
    else if (line.trim() === '') {
      if (inList) { inList = false; result.push('</ul>'); }
      result.push('<div style="height:6px;"></div>');
    }
    // Normal paragraph
    else {
      if (inList) { inList = false; result.push('</ul>'); }
      result.push(`<p style="color:var(--text-primary);font-size:13px;line-height:1.7;margin:4px 0;">${formatInline(line)}</p>`);
    }
  }

  if (inList) result.push('</ul>');
  return result.join('');
}

function escHtml(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatInline(text) {
  // Bold **text**
  text = text.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:var(--text-primary);font-weight:600;">$1</strong>');
  // Inline code `text`
  text = text.replace(/`([^`]+)`/g, '<code style="font-family:\'JetBrains Mono\',monospace;font-size:11px;padding:1px 4px;background:var(--bg-elevated);border-radius:3px;color:var(--text-mono);">$1</code>');
  // Italic *text*
  text = text.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  return text;
}

export default function AnalystReport({ reportText, streaming }) {
  const containerRef = useRef(null);
  const prevLengthRef = useRef(0);

  // Auto-scroll to bottom when new content arrives during streaming
  useEffect(() => {
    if (streaming && containerRef.current) {
      const newLength = reportText?.length || 0;
      if (newLength > prevLengthRef.current) {
        containerRef.current.scrollTop = containerRef.current.scrollHeight;
        prevLengthRef.current = newLength;
      }
    }
  }, [reportText, streaming]);

  if (!reportText && !streaming) return null;

  const html = renderMarkdown(reportText || '');

  return (
    <div style={{
      backgroundColor: 'var(--bg-surface)',
      border: '1px solid var(--border)',
      borderRadius: '8px',
      overflow: 'hidden'
    }}>
      {/* Header */}
      <div style={{
        padding: '10px 14px',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
        backgroundColor: 'var(--bg-elevated)'
      }}>
        <div style={{
          width: '8px',
          height: '8px',
          borderRadius: '50%',
          backgroundColor: streaming ? 'var(--accent-teal)' : 'var(--text-secondary)',
          animation: streaming ? 'pulse 1s ease-in-out infinite' : 'none'
        }} />
        <span style={{
          fontSize: '12px',
          fontWeight: 600,
          color: 'var(--text-secondary)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em'
        }}>
          ARGUS Intelligence Brief
        </span>
        {streaming && (
          <span style={{ fontSize: '11px', color: 'var(--accent-teal)', marginLeft: 'auto' }}>
            Generating...
          </span>
        )}
      </div>

      {/* Content */}
      <div
        ref={containerRef}
        style={{
          padding: '16px',
          maxHeight: '500px',
          overflowY: 'auto',
          lineHeight: '1.7'
        }}
      >
        {html ? (
          <div dangerouslySetInnerHTML={{ __html: html }} />
        ) : (
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <div className="skeleton" style={{ height: '13px', width: '60%' }} />
          </div>
        )}

        {/* Blinking cursor while streaming */}
        {streaming && (
          <span style={{
            display: 'inline-block',
            width: '8px',
            height: '14px',
            backgroundColor: 'var(--accent-teal)',
            marginLeft: '2px',
            verticalAlign: 'text-bottom',
            animation: 'pulse 0.8s ease-in-out infinite'
          }} />
        )}
      </div>
    </div>
  );
}

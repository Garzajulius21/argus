import { useState } from 'react';
import { DEFAULT_THRESHOLDS, saveThresholds } from '../lib/verdict.js';

function ThresholdControl({ label, description, value, min, max, onChange }) {
  return (
    <div style={{ marginBottom: '20px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: '4px' }}>
        <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>{label}</span>
        <span style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '13px', fontWeight: 700,
          color: 'var(--accent-blue)',
          minWidth: '28px', textAlign: 'right'
        }}>{value}</span>
      </div>
      <p style={{ fontSize: '11px', color: 'var(--text-secondary)', margin: '0 0 8px 0', lineHeight: 1.5 }}>
        {description}
      </p>
      <input
        type="range"
        min={min}
        max={max}
        value={value}
        onChange={e => onChange(Number(e.target.value))}
        style={{ width: '100%', accentColor: 'var(--accent-blue)', cursor: 'pointer' }}
      />
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '2px' }}>
        <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>{min}</span>
        <span style={{ fontSize: '10px', color: 'var(--text-secondary)' }}>{max}</span>
      </div>
    </div>
  );
}

export default function SettingsDrawer({ thresholds, onChange, onClose }) {
  const isModified = JSON.stringify(thresholds) !== JSON.stringify(DEFAULT_THRESHOLDS);

  const update = (key, value) => {
    const next = { ...thresholds, [key]: value };
    // Keep suspicious < malicious for each source
    if (key === 'vtSuspiciousMin'     && value >= next.vtMaliciousMin)    next.vtMaliciousMin    = value + 1;
    if (key === 'vtMaliciousMin'      && value <= next.vtSuspiciousMin)   next.vtSuspiciousMin   = Math.max(1, value - 1);
    if (key === 'abuseSuspiciousMin'  && value >= next.abuseMaliciousMin) next.abuseMaliciousMin = value + 1;
    if (key === 'abuseMaliciousMin'   && value <= next.abuseSuspiciousMin) next.abuseSuspiciousMin = Math.max(1, value - 1);
    saveThresholds(next);
    onChange(next);
  };

  const reset = () => {
    saveThresholds(DEFAULT_THRESHOLDS);
    onChange({ ...DEFAULT_THRESHOLDS });
  };

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0,
          backgroundColor: 'rgba(0,0,0,0.4)',
          zIndex: 100
        }}
      />

      {/* Drawer */}
      <div style={{
        position: 'fixed', top: 0, right: 0, bottom: 0,
        width: '320px',
        backgroundColor: 'var(--bg-surface)',
        borderLeft: '1px solid var(--border)',
        zIndex: 101,
        display: 'flex', flexDirection: 'column',
        boxShadow: '-8px 0 32px rgba(0,0,0,0.4)'
      }}>
        {/* Drawer header */}
        <div style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border)',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center'
        }}>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Verdict Thresholds
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
              Adjustments apply to current results instantly
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none', border: 'none',
              color: 'var(--text-secondary)', cursor: 'pointer',
              fontSize: '18px', lineHeight: 1, padding: '2px 6px',
              borderRadius: '4px'
            }}
          >×</button>
        </div>

        {/* Controls */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px' }}>

          {/* VT section */}
          <div style={{
            fontSize: '10px', fontWeight: 700,
            color: 'var(--text-secondary)',
            textTransform: 'uppercase', letterSpacing: '0.1em',
            marginBottom: '14px'
          }}>
            VirusTotal
          </div>

          <ThresholdControl
            label="Suspicious at ≥ N detections"
            description="Flag an IOC as SUSPICIOUS when at least this many VT engines flag it."
            value={thresholds.vtSuspiciousMin}
            min={1}
            max={10}
            onChange={v => update('vtSuspiciousMin', v)}
          />
          <ThresholdControl
            label="Malicious at ≥ N detections"
            description="Flag an IOC as MALICIOUS when at least this many VT engines flag it."
            value={thresholds.vtMaliciousMin}
            min={2}
            max={20}
            onChange={v => update('vtMaliciousMin', v)}
          />

          <div style={{ borderTop: '1px solid var(--border)', margin: '4px 0 18px' }} />

          {/* AbuseIPDB section */}
          <div style={{
            fontSize: '10px', fontWeight: 700,
            color: 'var(--text-secondary)',
            textTransform: 'uppercase', letterSpacing: '0.1em',
            marginBottom: '14px'
          }}>
            AbuseIPDB
          </div>

          <ThresholdControl
            label="Suspicious at score ≥ N"
            description="Flag an IP as SUSPICIOUS when the AbuseIPDB confidence score reaches this value."
            value={thresholds.abuseSuspiciousMin}
            min={1}
            max={74}
            onChange={v => update('abuseSuspiciousMin', v)}
          />
          <ThresholdControl
            label="Malicious at score ≥ N"
            description="Flag an IP as MALICIOUS when the AbuseIPDB confidence score reaches this value."
            value={thresholds.abuseMaliciousMin}
            min={2}
            max={100}
            onChange={v => update('abuseMaliciousMin', v)}
          />

          <div style={{ borderTop: '1px solid var(--border)', margin: '4px 0 18px' }} />

          {/* Fixed signals note */}
          <div style={{
            padding: '10px 12px',
            backgroundColor: 'var(--bg-elevated)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.6
          }}>
            <strong style={{ color: 'var(--text-primary)' }}>Fixed signals</strong><br />
            MalwareBazaar hits always → MALICIOUS<br />
            URLScan malicious always → MALICIOUS<br />
            GreyNoise malicious always → MALICIOUS
          </div>
        </div>

        {/* Footer */}
        <div style={{
          padding: '14px 20px',
          borderTop: '1px solid var(--border)',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center'
        }}>
          <button
            onClick={reset}
            disabled={!isModified}
            style={{
              background: 'none',
              border: `1px solid ${isModified ? 'var(--border)' : 'transparent'}`,
              borderRadius: '5px', padding: '6px 12px',
              fontSize: '12px', cursor: isModified ? 'pointer' : 'default',
              color: isModified ? 'var(--text-secondary)' : 'transparent',
              transition: 'all 0.15s'
            }}
          >
            Reset to defaults
          </button>
          {isModified && (
            <span style={{
              fontSize: '10px', color: 'var(--accent-amber)',
              fontFamily: "'JetBrains Mono', monospace"
            }}>
              Custom thresholds active
            </span>
          )}
        </div>
      </div>
    </>
  );
}

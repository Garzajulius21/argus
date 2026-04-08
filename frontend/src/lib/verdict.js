// Mirrors backend computeVerdict but accepts configurable thresholds.
// Used by the frontend so verdict display updates instantly when settings change.

export const DEFAULT_THRESHOLDS = {
  vtMaliciousMin:      3,   // VT detections >= N → MALICIOUS
  vtSuspiciousMin:     1,   // VT detections >= N → SUSPICIOUS
  abuseMaliciousMin:  75,   // AbuseIPDB score >= N → MALICIOUS
  abuseSuspiciousMin: 26,   // AbuseIPDB score >= N → SUSPICIOUS
};

const STORAGE_KEY = 'argus_thresholds';

export function loadThresholds() {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) return { ...DEFAULT_THRESHOLDS, ...JSON.parse(stored) };
  } catch {}
  return { ...DEFAULT_THRESHOLDS };
}

export function saveThresholds(thresholds) {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(thresholds)); } catch {}
}

export function computeVerdict(enrichment, thresholds = DEFAULT_THRESHOLDS) {
  const vt    = enrichment?.virustotal;
  const abuse = enrichment?.abuseipdb;
  const mb    = enrichment?.malwarebazaar;
  const us    = enrichment?.urlscan;
  const gn    = enrichment?.greynoise;

  const { vtMaliciousMin, vtSuspiciousMin, abuseMaliciousMin, abuseSuspiciousMin } = thresholds;

  const vtDetections  = vt?.data?.malicious ?? -1;
  const abuseScore    = abuse?.data?.abuseScore ?? -1;

  if (
    (vt?.queried    && vtDetections  >= vtMaliciousMin)    ||
    (abuse?.queried && abuseScore    >= abuseMaliciousMin) ||
    (mb?.data?.found === true)                             ||
    (us?.data?.verdict === 'malicious')                    ||
    (gn?.data?.classification === 'malicious')
  ) return 'MALICIOUS';

  if (
    (vt?.queried    && vtDetections  >= vtSuspiciousMin  && vtDetections  < vtMaliciousMin)  ||
    (abuse?.queried && abuseScore    >= abuseSuspiciousMin && abuseScore  < abuseMaliciousMin) ||
    (us?.data?.verdict === 'suspicious')
  ) return 'SUSPICIOUS';

  return 'CLEAN';
}

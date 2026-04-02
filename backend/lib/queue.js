'use strict';

const BATCH_SIZE = 4;
const WINDOW_MS = 60_000;
const MAX_RETRIES = 3;

async function queueVTRequests(iocs, enrichFn, onProgress) {
  const results = new Array(iocs.length).fill(null);

  for (let i = 0; i < iocs.length; i += BATCH_SIZE) {
    const windowStart = Date.now();
    const batch = iocs.slice(i, i + BATCH_SIZE);
    const batchIndices = batch.map((_, j) => i + j);

    await Promise.all(batch.map(async (ioc, j) => {
      const idx = batchIndices[j];
      let lastError;
      for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
        try {
          results[idx] = await enrichFn(ioc);
          if (onProgress) onProgress({ processed: idx + 1, total: iocs.length, waitingMs: 0 });
          return;
        } catch (err) {
          if (err.status === 429 || (err.response && err.response.status === 429)) {
            const backoff = Math.pow(2, attempt + 1) * 1000;
            await sleep(backoff);
            lastError = err;
          } else {
            results[idx] = { source: 'virustotal', queried: true, error: err.message, data: emptyData() };
            if (onProgress) onProgress({ processed: idx + 1, total: iocs.length, waitingMs: 0 });
            return;
          }
        }
      }
      results[idx] = {
        source: 'virustotal',
        queried: true,
        error: lastError?.message || 'Rate limit exceeded after retries',
        data: emptyData()
      };
      if (onProgress) onProgress({ processed: idx + 1, total: iocs.length, waitingMs: 0 });
    }));

    // Wait for remainder of 60s window before next batch
    if (i + BATCH_SIZE < iocs.length) {
      const elapsed = Date.now() - windowStart;
      const waitMs = Math.max(0, WINDOW_MS - elapsed);
      if (waitMs > 0) {
        if (onProgress) onProgress({ processed: Math.min(i + BATCH_SIZE, iocs.length), total: iocs.length, waitingMs: waitMs });
        await sleep(waitMs);
      }
    }
  }

  return results;
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function emptyData() {
  return {
    malicious: 0,
    suspicious: 0,
    harmless: 0,
    undetected: 0,
    total: 0,
    abuseScore: 0,
    totalReports: 0,
    lastSeen: null,
    tags: [],
    country: null,
    found: false,
    name: null,
    signature: null,
    raw: {}
  };
}

module.exports = { queueVTRequests };

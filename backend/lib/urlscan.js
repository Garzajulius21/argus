'use strict';

const axios = require('axios');

const URLSCAN_BASE = 'https://urlscan.io/api/v1';

function emptyData() {
  return { verdict: null, score: 0, totalScans: 0, lastScan: null, found: false };
}

function buildQuery(ioc) {
  switch (ioc.type) {
    case 'url':    return `page.url:"${ioc.value}"`;
    case 'domain': return `domain:${ioc.value}`;
    case 'ipv4':   return `ip:${ioc.value}`;
    default:       return null;
  }
}

async function enrichWithURLScan(ioc) {
  const query = buildQuery(ioc);
  if (!query) {
    return { source: 'urlscan', queried: false, error: null, data: emptyData() };
  }

  const apiKey = process.env.URLSCAN_API_KEY;
  const headers = { 'Content-Type': 'application/json' };
  if (apiKey && apiKey !== 'your_urlscan_api_key_here') {
    headers['API-Key'] = apiKey;
  }

  try {
    const response = await axios.get(`${URLSCAN_BASE}/search/`, {
      headers,
      params: { q: query, size: 10 },
      timeout: 8000
    });

    console.log(`[urlscan] query="${query}" status=${response.status} results=${response.data?.results?.length ?? 0}`);
    const results = response.data?.results || [];
    if (results.length === 0) {
      return { source: 'urlscan', queried: true, error: null, data: emptyData() };
    }

    // Aggregate verdict across most recent scans
    let maliciousCount = 0;
    let suspiciousCount = 0;
    let highestScore = 0;
    const lastScan = results[0]?.task?.time || null;

    for (const r of results) {
      const v = r.verdicts?.overall;
      if (!v) continue;
      if (v.malicious) maliciousCount++;
      else if (v.score && v.score >= 50) suspiciousCount++;
      if ((v.score || 0) > highestScore) highestScore = v.score || 0;
    }

    let verdict = 'unrated';
    if (maliciousCount > 0) verdict = 'malicious';
    else if (suspiciousCount > 0) verdict = 'suspicious';

    return {
      source: 'urlscan',
      queried: true,
      error: null,
      data: {
        verdict,
        score: highestScore,
        totalScans: results.length,
        lastScan,
        found: true
      }
    };
  } catch (err) {
    if (err.response) {
      console.error(`[urlscan] API error: HTTP ${err.response.status}`, err.response.data);
      return {
        source: 'urlscan',
        queried: true,
        error: `URLScan API error: HTTP ${err.response.status}`,
        data: emptyData()
      };
    }
    console.error(`[urlscan] Request failed:`, err.message);
    return {
      source: 'urlscan',
      queried: true,
      error: `URLScan request failed: ${err.message}`,
      data: emptyData()
    };
  }
}

module.exports = { enrichWithURLScan };

'use strict';

const axios = require('axios');

const VT_BASE = 'https://www.virustotal.com/api/v3';

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

function buildResult(data) {
  return {
    source: 'virustotal',
    queried: true,
    error: null,
    data
  };
}

function normalizeStats(stats, raw) {
  return {
    malicious: stats.malicious || 0,
    suspicious: stats.suspicious || 0,
    harmless: stats.harmless || 0,
    undetected: stats.undetected || 0,
    total: Object.values(stats).reduce((s, v) => s + (v || 0), 0),
    abuseScore: 0,
    totalReports: 0,
    lastSeen: raw.last_analysis_date
      ? new Date(raw.last_analysis_date * 1000).toISOString()
      : null,
    tags: raw.tags || [],
    country: raw.country || null,
    found: true,
    name: raw.meaningful_name || raw.name || raw.last_https_certificate?.subject?.CN || raw.as_owner || null,
    signature: raw.signature_info?.subject || null,
    raw
  };
}

function getUrlId(url) {
  return Buffer.from(url).toString('base64url');
}

async function enrichWithVT(ioc) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey || apiKey === 'your_virustotal_api_key_here') {
    return {
      source: 'virustotal',
      queried: false,
      error: 'API key not configured',
      data: emptyData()
    };
  }

  const headers = { 'x-apikey': apiKey };
  let url;

  switch (ioc.type) {
    case 'sha256':
    case 'sha1':
    case 'md5':
      url = `${VT_BASE}/files/${ioc.value.toLowerCase()}`;
      break;
    case 'ipv4':
      url = `${VT_BASE}/ip_addresses/${ioc.value}`;
      break;
    case 'domain':
      url = `${VT_BASE}/domains/${ioc.value.toLowerCase()}`;
      break;
    case 'url':
      url = `${VT_BASE}/urls/${getUrlId(ioc.value)}`;
      break;
    default:
      return {
        source: 'virustotal',
        queried: false,
        error: `Unsupported IOC type: ${ioc.type}`,
        data: emptyData()
      };
  }

  try {
    const response = await axios.get(url, {
      headers,
      timeout: 10000
    });

    const raw = response.data?.data?.attributes || {};
    const stats = raw.last_analysis_stats || {};
    const data = normalizeStats(stats, raw);
    return buildResult(data);
  } catch (err) {
    if (err.response) {
      const status = err.response.status;
      if (status === 404) {
        const notFound = emptyData();
        notFound.found = false;
        return buildResult(notFound);
      }
      if (status === 429) {
        const rateLimitErr = new Error('VT rate limit exceeded');
        rateLimitErr.status = 429;
        rateLimitErr.response = err.response;
        throw rateLimitErr;
      }
      return {
        source: 'virustotal',
        queried: true,
        error: `VT API error: HTTP ${status}`,
        data: emptyData()
      };
    }
    return {
      source: 'virustotal',
      queried: true,
      error: `VT request failed: ${err.message}`,
      data: emptyData()
    };
  }
}

module.exports = { enrichWithVT };

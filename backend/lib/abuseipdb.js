'use strict';

const axios = require('axios');

const ABUSEIPDB_BASE = 'https://api.abuseipdb.com/api/v2';

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

async function enrichWithAbuseIPDB(ioc) {
  if (ioc.type !== 'ipv4') {
    return {
      source: 'abuseipdb',
      queried: false,
      error: null,
      data: emptyData()
    };
  }

  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey || apiKey === 'your_abuseipdb_api_key_here') {
    return {
      source: 'abuseipdb',
      queried: false,
      error: 'API key not configured',
      data: emptyData()
    };
  }

  try {
    const response = await axios.get(`${ABUSEIPDB_BASE}/check`, {
      headers: {
        'Key': apiKey,
        'Accept': 'application/json'
      },
      params: {
        ipAddress: ioc.value,
        maxAgeInDays: 90,
        verbose: true
      },
      timeout: 10000
    });

    const d = response.data?.data || {};
    const data = {
      malicious: 0,
      suspicious: 0,
      harmless: 0,
      undetected: 0,
      total: 0,
      abuseScore: d.abuseConfidenceScore || 0,
      totalReports: d.totalReports || 0,
      lastSeen: d.lastReportedAt || null,
      tags: [],
      country: d.countryCode || null,
      found: (d.totalReports || 0) > 0,
      name: d.isp || null,
      signature: d.domain || null,
      raw: d
    };

    return {
      source: 'abuseipdb',
      queried: true,
      error: null,
      data
    };
  } catch (err) {
    if (err.response) {
      return {
        source: 'abuseipdb',
        queried: true,
        error: `AbuseIPDB API error: HTTP ${err.response.status}`,
        data: emptyData()
      };
    }
    return {
      source: 'abuseipdb',
      queried: true,
      error: `AbuseIPDB request failed: ${err.message}`,
      data: emptyData()
    };
  }
}

module.exports = { enrichWithAbuseIPDB };

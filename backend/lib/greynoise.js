'use strict';

const axios = require('axios');

const GN_BASE = 'https://api.greynoise.io/v3/community';

function emptyData() {
  return { noise: false, riot: false, classification: null, name: null, lastSeen: null, found: false };
}

const PRIVATE_IP_RE = /^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})$/;

async function enrichWithGreyNoise(ioc) {
  if (ioc.type !== 'ipv4') {
    return { source: 'greynoise', queried: false, error: null, data: emptyData() };
  }

  // GreyNoise only tracks internet-facing IPs — skip private ranges
  if (PRIVATE_IP_RE.test(ioc.value)) {
    return { source: 'greynoise', queried: false, error: null, data: emptyData() };
  }

  const apiKey = process.env.GREYNOISE_API_KEY;
  if (!apiKey || apiKey === 'your_greynoise_api_key_here') {
    return { source: 'greynoise', queried: false, error: 'API key not configured', data: emptyData() };
  }

  try {
    const response = await axios.get(`${GN_BASE}/${encodeURIComponent(ioc.value)}`, {
      headers: { key: apiKey, 'Accept': 'application/json' },
      timeout: 8000
    });

    const d = response.data || {};

    // message field is set on "not found" 404-like responses with 200 status
    if (d.message && !d.ip) {
      return { source: 'greynoise', queried: true, error: null, data: emptyData() };
    }

    return {
      source: 'greynoise',
      queried: true,
      error: null,
      data: {
        noise: d.noise === true,
        riot: d.riot === true,
        classification: d.classification || null,
        name: d.name || null,
        lastSeen: d.last_seen || null,
        found: true
      }
    };
  } catch (err) {
    if (err.response) {
      const status = err.response.status;
      // 404 = IP not in GreyNoise dataset — not an error, just unknown
      if (status === 404) {
        return { source: 'greynoise', queried: true, error: null, data: emptyData() };
      }
      return {
        source: 'greynoise',
        queried: true,
        error: `GreyNoise API error: HTTP ${status}`,
        data: emptyData()
      };
    }
    return {
      source: 'greynoise',
      queried: true,
      error: `GreyNoise request failed: ${err.message}`,
      data: emptyData()
    };
  }
}

module.exports = { enrichWithGreyNoise };

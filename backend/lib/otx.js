'use strict';

const axios = require('axios');

const OTX_BASE = 'https://otx.alienvault.com/api/v1/indicators';

function emptyData() {
  return { found: false, pulseCount: 0, tags: [], adversaries: [], malwareFamilies: [], attackIds: [] };
}

function iocTypeToOTX(ioc) {
  switch (ioc.type) {
    case 'ipv4':   return 'IPv4';
    case 'domain': return 'domain';
    case 'url':    return 'url';
    case 'md5':    return 'file';
    case 'sha1':   return 'file';
    case 'sha256': return 'file';
    default:       return null;
  }
}

async function enrichWithOTX(ioc) {
  const apiKey = process.env.OTX_API_KEY;
  if (!apiKey || apiKey === 'your_otx_api_key_here') {
    return { source: 'otx', queried: false, error: 'API key not configured', data: emptyData() };
  }

  const otxType = iocTypeToOTX(ioc);
  if (!otxType) {
    return { source: 'otx', queried: false, error: null, data: emptyData() };
  }

  // For file hashes, use the hash value directly under /file/{hash}/general
  const indicator = ioc.type === 'md5' || ioc.type === 'sha1' || ioc.type === 'sha256'
    ? `file/${ioc.value}`
    : `${otxType}/${ioc.value}`;

  try {
    const response = await axios.get(`${OTX_BASE}/${indicator}/general`, {
      headers: { 'X-OTX-API-KEY': apiKey },
      timeout: 10000
    });

    const pulseInfo = response.data?.pulse_info || {};
    const pulses = pulseInfo.pulses || [];
    const pulseCount = pulseInfo.count || 0;

    if (pulseCount === 0) {
      return { source: 'otx', queried: true, error: null, data: emptyData() };
    }

    // Aggregate tags, adversaries, malware families across all pulses
    const tagSet = new Set();
    const adversarySet = new Set();
    const familySet = new Set();
    const attackSet = new Set();

    for (const pulse of pulses.slice(0, 20)) {
      (pulse.tags || []).forEach(t => tagSet.add(t.toLowerCase()));
      if (pulse.adversary) adversarySet.add(pulse.adversary);
      (pulse.malware_families || []).forEach(f => {
        if (f.display_name) familySet.add(f.display_name);
      });
      (pulse.attack_ids || []).forEach(a => {
        if (a.id) attackSet.add(a.id);
      });
    }

    return {
      source: 'otx',
      queried: true,
      error: null,
      data: {
        found: true,
        pulseCount,
        tags: [...tagSet].slice(0, 10),
        adversaries: [...adversarySet].slice(0, 5),
        malwareFamilies: [...familySet].slice(0, 5),
        attackIds: [...attackSet].slice(0, 5)
      }
    };
  } catch (err) {
    if (err.response) {
      if (err.response.status === 404) {
        return { source: 'otx', queried: true, error: null, data: emptyData() };
      }
      console.error(`[otx] API error: HTTP ${err.response.status}`, err.response.data);
      return { source: 'otx', queried: true, error: `OTX API error: HTTP ${err.response.status}`, data: emptyData() };
    }
    console.error(`[otx] Request failed:`, err.message);
    return { source: 'otx', queried: true, error: `OTX request failed: ${err.message}`, data: emptyData() };
  }
}

module.exports = { enrichWithOTX };

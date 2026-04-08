'use strict';

const axios = require('axios');

function emptyData() {
  return { country: null, countryCode: null, org: null, as: null, asName: null, found: false };
}

async function enrichWithGeo(ioc) {
  if (ioc.type !== 'ipv4') {
    return { source: 'ipapi', queried: false, error: null, data: emptyData() };
  }

  try {
    const response = await axios.get(
      `http://ip-api.com/json/${encodeURIComponent(ioc.value)}`,
      {
        params: { fields: 'status,message,country,countryCode,org,as' },
        timeout: 5000
      }
    );

    const d = response.data || {};

    if (d.status !== 'success') {
      return {
        source: 'ipapi',
        queried: true,
        error: `ip-api: ${d.message || 'lookup failed'}`,
        data: emptyData()
      };
    }

    // "as" field is "AS15169 Google LLC" — split into number and name
    const asStr = d.as || '';
    const asMatch = asStr.match(/^(AS\d+)\s*(.*)/);

    return {
      source: 'ipapi',
      queried: true,
      error: null,
      data: {
        country: d.country || null,
        countryCode: d.countryCode || null,
        org: d.org || null,
        as: asMatch ? asMatch[1] : null,
        asName: asMatch ? asMatch[2].trim() : (d.org || null),
        found: true
      }
    };
  } catch (err) {
    return {
      source: 'ipapi',
      queried: true,
      error: `Geo lookup failed: ${err.message}`,
      data: emptyData()
    };
  }
}

module.exports = { enrichWithGeo };

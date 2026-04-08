'use strict';

const express = require('express');
const router = express.Router();

const { parseIOCs } = require('../lib/iocParser');
const { enrichWithVT } = require('../lib/virustotal');
const { enrichWithAbuseIPDB } = require('../lib/abuseipdb');
const { enrichWithMalwareBazaar } = require('../lib/malwarebazaar');
const { enrichWithGeo } = require('../lib/geolocation');
const { enrichWithURLScan } = require('../lib/urlscan');
const { enrichWithGreyNoise } = require('../lib/greynoise');
const { queueVTRequests } = require('../lib/queue');
const { generateReport, computeVerdict } = require('../lib/claude');
const { validateEnrichRequest } = require('../middleware/validate');

function sseWrite(res, data) {
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

router.post('/', validateEnrichRequest, async (req, res) => {
  // Set SSE headers
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  // Handle client disconnect
  let clientGone = false;
  req.on('close', () => { clientGone = true; });

  try {
    const rawIocs = req.body.iocs;

    // Parse IOCs from the raw array (join them and parse)
    const iocs = parseIOCs(rawIocs.join('\n'));

    if (iocs.length === 0) {
      sseWrite(res, { type: 'error', message: 'No valid IOCs found after parsing. Check input format.' });
      res.end();
      return;
    }

    sseWrite(res, { type: 'progress', processed: 0, total: iocs.length, waitingMs: 0 });

    // Run AbuseIPDB and MalwareBazaar in parallel (no rate limit)
    const nonVtResults = await Promise.all(
      iocs.map(async (ioc) => {
        const [abuse, mb, geo, urlscan, greynoise] = await Promise.all([
          enrichWithAbuseIPDB(ioc),
          enrichWithMalwareBazaar(ioc),
          enrichWithGeo(ioc),
          enrichWithURLScan(ioc),
          enrichWithGreyNoise(ioc)
        ]);
        return { ioc, abuse, mb, geo, urlscan, greynoise };
      })
    );

    // Build intermediate enrichment map
    const enrichmentMap = new Map();
    for (const { ioc, abuse, mb } of nonVtResults) {
      enrichmentMap.set(ioc.value, { ioc, abuseipdb: abuse, malwarebazaar: mb, geo, urlscan, greynoise });
    }

    // Run VT with rate limit queue
    let vtProcessed = 0;
    const vtResults = await queueVTRequests(
      iocs,
      enrichWithVT,
      (progress) => {
        if (!clientGone) {
          sseWrite(res, {
            type: 'progress',
            processed: progress.processed,
            total: progress.total,
            waitingMs: progress.waitingMs
          });
        }
      }
    );

    // Merge enrichment results and emit per-IOC results
    const enrichedResults = [];

    for (let i = 0; i < iocs.length; i++) {
      const ioc = iocs[i];
      const vtResult = vtResults[i] || { source: 'virustotal', queried: false, error: null, data: {} };
      const stored = enrichmentMap.get(ioc.value);

      const enrichment = {
        virustotal: vtResult,
        abuseipdb: stored ? stored.abuseipdb : null,
        malwarebazaar: stored ? stored.malwarebazaar : null,
        geo: stored ? stored.geo : null,
        urlscan: stored ? stored.urlscan : null,
        greynoise: stored ? stored.greynoise : null
      };

      // Compute per-IOC verdict
      const verdict = computeVerdict({
        [ioc.value]: enrichment
      });

      const resultItem = {
        ioc: { value: ioc.value, type: ioc.type },
        enrichment,
        verdict,
        enrichedAt: new Date().toISOString()
      };

      enrichedResults.push(resultItem);

      if (!clientGone) {
        sseWrite(res, { type: 'result', ioc: resultItem.ioc, enrichment, verdict, enrichedAt: resultItem.enrichedAt });
      }
    }

    // Generate Claude correlation report via streaming
    if (!clientGone) {
      await generateReport(
        enrichedResults,
        (data) => {
          if (!clientGone) sseWrite(res, data);
        }
      );
    }

    if (!clientGone) {
      sseWrite(res, { type: 'done' });
    }

    res.end();
  } catch (err) {
    if (!clientGone) {
      try {
        sseWrite(res, { type: 'error', message: 'Internal server error during enrichment.' });
        res.end();
      } catch (_) {
        // Response already ended
      }
    }
  }
});

module.exports = router;

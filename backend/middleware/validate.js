'use strict';

const MAX_IOC_COUNT = 100;
const MAX_IOC_LENGTH = 2083;
// Regex to strip non-printable characters (keep printable ASCII + common whitespace)
const NON_PRINTABLE_RE = /[^\x20-\x7E\t\n\r]/g;

function validateEnrichRequest(req, res, next) {
  // Must have JSON content-type
  const contentType = req.headers['content-type'] || '';
  if (!contentType.includes('application/json')) {
    return res.status(415).json({ error: 'Content-Type must be application/json' });
  }

  const { iocs } = req.body;

  if (!iocs) {
    return res.status(400).json({ error: 'Missing required field: iocs' });
  }

  if (!Array.isArray(iocs)) {
    return res.status(400).json({ error: 'iocs must be an array' });
  }

  if (iocs.length === 0) {
    return res.status(400).json({ error: 'iocs array must not be empty' });
  }

  if (iocs.length > MAX_IOC_COUNT) {
    return res.status(400).json({
      error: `Too many IOCs. Maximum allowed: ${MAX_IOC_COUNT}. Received: ${iocs.length}`
    });
  }

  const sanitized = [];
  for (let i = 0; i < iocs.length; i++) {
    const item = iocs[i];

    if (typeof item !== 'string') {
      return res.status(400).json({ error: `iocs[${i}] must be a string` });
    }

    if (item.length > MAX_IOC_LENGTH) {
      return res.status(400).json({
        error: `iocs[${i}] exceeds maximum length of ${MAX_IOC_LENGTH} characters`
      });
    }

    // Strip non-printable characters
    const clean = item.replace(NON_PRINTABLE_RE, '').trim();
    if (clean.length > 0) {
      sanitized.push(clean);
    }
  }

  if (sanitized.length === 0) {
    return res.status(400).json({ error: 'No valid IOC strings after sanitization' });
  }

  // Replace iocs with sanitized version for downstream handlers
  req.body.iocs = sanitized;
  next();
}

module.exports = { validateEnrichRequest };

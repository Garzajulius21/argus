'use strict';

require('dotenv').config({ override: true });

const express = require('express');
const { applySecurityMiddleware } = require('./middleware/security');
const enrichRouter = require('./routes/enrich');

const app = express();
const PORT = process.env.PORT || 3001;

// Apply security middleware (helmet, cors, body parser, rate limiters)
applySecurityMiddleware(app);

// Health check endpoint
app.get('/health', (req, res) => {
  const pkg = require('./package.json');
  res.json({ status: 'ok', version: pkg.version });
});

// API routes
app.use('/api/enrich', enrichRouter);

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Global error handler — never expose stack traces or API keys
app.use((err, req, res, next) => {
  // Log error for debugging (server-side only)
  if (process.env.NODE_ENV !== 'production') {
    console.error('Unhandled error:', err.message);
  }
  res.status(500).json({ error: 'Internal server error' });
});

const server = app.listen(PORT, () => {
  if (process.env.NODE_ENV !== 'production') {
    console.log(`ARGUS backend listening on http://localhost:${PORT}`);
    console.log(`  VT:         ${process.env.VIRUSTOTAL_API_KEY ? '✓' : '✗ missing'}`);
    console.log(`  AbuseIPDB:  ${process.env.ABUSEIPDB_API_KEY && process.env.ABUSEIPDB_API_KEY !== 'your_abuseipdb_api_key_here' ? '✓' : '✗ not configured'}`);
    console.log(`  GreyNoise:  ${process.env.GREYNOISE_API_KEY && process.env.GREYNOISE_API_KEY !== 'your_greynoise_api_key_here' ? '✓' : '✗ not configured'}`);
    console.log(`  URLScan:    ${process.env.URLSCAN_API_KEY && process.env.URLSCAN_API_KEY !== 'your_urlscan_api_key_here' ? '✓' : '✗ not configured (optional)'}`);
    console.log(`  OTX:        ${process.env.OTX_API_KEY && process.env.OTX_API_KEY !== 'your_otx_api_key_here' ? '✓' : '✗ not configured (optional)'}`);
    console.log(`  Anthropic:  ${process.env.ANTHROPIC_API_KEY && process.env.ANTHROPIC_API_KEY !== 'your_anthropic_api_key_here' ? '✓' : '✗ not configured (optional)'}`);
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  server.close(() => {
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  server.close(() => {
    process.exit(0);
  });
});

module.exports = app;

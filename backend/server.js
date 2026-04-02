'use strict';

require('dotenv').config();

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

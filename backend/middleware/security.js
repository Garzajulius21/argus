'use strict';

const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const express = require('express');

function applySecurityMiddleware(app) {
  // Helmet with strict CSP
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          imgSrc: ["'self'", 'data:'],
          connectSrc: ["'self'"],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          frameAncestors: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"]
        }
      },
      crossOriginEmbedderPolicy: false
    })
  );

  // CORS: restricted to ALLOWED_ORIGIN only
  const allowedOrigin = process.env.ALLOWED_ORIGIN;
  app.use(
    cors({
      origin: (origin, callback) => {
        // Allow requests with no origin (e.g. health checks, curl)
        if (!origin) return callback(null, true);
        if (origin === allowedOrigin) return callback(null, true);
        callback(new Error(`CORS: origin ${origin} not allowed`));
      },
      credentials: false,
      methods: ['GET', 'POST'],
      allowedHeaders: ['Content-Type']
    })
  );

  // Body size limit: 50KB
  app.use(express.json({ limit: '50kb' }));

  // Global rate limit: 200 req / 15 min
  const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' }
  });
  app.use(globalLimiter);

  // Enrich-specific rate limit: 30 req / 15 min
  const enrichLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Enrichment rate limit exceeded. Try again in 15 minutes.' }
  });
  app.use('/api/enrich', enrichLimiter);
}

module.exports = { applySecurityMiddleware };

'use strict';

const PRIVATE_IP_RE = /^(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})$/;
const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
const DOMAIN_RE = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
const URL_RE = /^https?:\/\/.+/;
const MD5_RE = /^[a-fA-F0-9]{32}$/;
const SHA1_RE = /^[a-fA-F0-9]{40}$/;
const SHA256_RE = /^[a-fA-F0-9]{64}$/;
const MAX_IOCS = 100;

function normalize(raw) {
  return raw
    .replace(/hxxps?:\/\//gi, (m) => m.replace(/hxxp/i, 'http'))
    .replace(/\[\.\]/g, '.')
    .replace(/\[dot\]/gi, '.');
}

function detectType(value) {
  if (SHA256_RE.test(value)) return 'sha256';
  if (SHA1_RE.test(value)) return 'sha1';
  if (MD5_RE.test(value)) return 'md5';
  if (IPV4_RE.test(value)) {
    const parts = value.split('.').map(Number);
    if (parts.every(p => p >= 0 && p <= 255)) return 'ipv4';
  }
  if (URL_RE.test(value)) return 'url';
  if (DOMAIN_RE.test(value)) return 'domain';
  return null;
}

function parseIOCs(text) {
  if (!text || typeof text !== 'string') return [];

  const tokens = text.split(/[\s,;]+/).map(t => t.trim()).filter(Boolean);
  const seen = new Set();
  const results = [];
  let truncated = false;

  for (const raw of tokens) {
    if (results.length >= MAX_IOCS) { truncated = true; break; }
    const normalized = normalize(raw);
    const type = detectType(normalized);
    if (!type) continue;
    // Private IPs allowed — GreyNoise skips them, other APIs handle gracefully
    if (type === 'domain' && (normalized === 'localhost' || normalized.endsWith('.local'))) continue;
    const key = `${type}:${normalized.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    results.push({ value: normalized, type });
  }

  return results;
}

module.exports = { parseIOCs, MAX_IOCS };

# ARGUS — IOC Enrichment Engine

![Status](https://img.shields.io/badge/Status-Production--Ready-success)
![Stack](https://img.shields.io/badge/Stack-Node.js%20%2B%20React-blue)
![APIs](https://img.shields.io/badge/APIs-VirusTotal%20%7C%20AbuseIPDB%20%7C%20MalwareBazaar-red)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

ARGUS is a local IOC (Indicator of Compromise) enrichment engine built for SOC analysts. Paste a raw blob of text containing hashes, IP addresses, domains, or URLs — ARGUS automatically detects each IOC type, fans out to VirusTotal, AbuseIPDB, and MalwareBazaar in parallel, and renders a live enrichment table with verdicts.

Designed to run locally. API keys never leave the backend process. Nothing is sent to the cloud except the IOC values themselves when querying enrichment APIs.

---

## What It Does

1. **Paste anything** — mixed hashes, IPs, domains, URLs in any format. Defanged IOCs (`hxxp://`, `[.]`) handled automatically.
2. **Auto-detection** — IOC types identified in real time as you type with color-coded badges.
3. **Parallel enrichment** — VirusTotal (rate-limited to 4/min automatically), MalwareBazaar, and AbuseIPDB all queried simultaneously.
4. **Live results table** — rows populate as each API responds, no waiting for everything to finish.
5. **Verdicts** — each IOC gets CLEAN, SUSPICIOUS, or MALICIOUS based on combined signal from all three sources.
6. **AI threat brief** — optional Claude-powered intelligence report streams in real time after enrichment completes (requires Anthropic API key).
7. **Export** — download the full enrichment report as a `.md` file for tickets or incident documentation.

---

## Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + Vite + Tailwind CSS |
| Backend | Node.js + Express |
| Security | Helmet.js, CORS, express-rate-limit |
| Enrichment | VirusTotal v3, AbuseIPDB v2, MalwareBazaar |
| AI Report | Anthropic Claude API (optional) |
| Testing | Jest (99 tests, 97% coverage) |

---

## Supported IOC Types

| Type | Examples |
|------|---------|
| SHA256 | 64-character hex hash |
| SHA1 | 40-character hex hash |
| MD5 | 32-character hex hash |
| IPv4 | Public IPs only — RFC1918 private ranges excluded |
| Domain | Any valid hostname |
| URL | http/https, including defanged hxxp:// |

---

## Setup

### Prerequisites
- Node.js v18+
- VirusTotal API key (free) — virustotal.com
- Optional: AbuseIPDB key (free), Anthropic API key (paid ~$0.01–0.03/run)

### First-time install
```bash
cd backend && npm install
cd ../frontend && npm install
```

### Add API keys
```bash
open -a TextEdit backend/.env
```
Fill in `VIRUSTOTAL_API_KEY` and optionally `ABUSEIPDB_API_KEY` and `ANTHROPIC_API_KEY`.

### Start the app
Double-click `start-argus.command` in the project folder, then open **http://localhost:5173**.

Or manually in two terminals:
```bash
# Terminal 1
cd backend && npm run dev

# Terminal 2
cd frontend && npm run dev
```

---

## Security

- API keys are isolated in the backend process — the browser never sees them
- All external API calls are proxied through Express — no direct frontend calls
- Input validated and sanitized before touching any external API
- IOC values defanged in the UI at all times — no raw clickable URLs or domains
- Helmet.js strict CSP, CORS locked to localhost, rate limiting on all endpoints
- Max 100 IOCs per request, 50KB body limit

---

## Project Structure

```
argus/
├── backend/
│   ├── lib/          ← IOC parser, enrichment wrappers, rate queue, Claude
│   ├── middleware/   ← Security headers, input validation
│   ├── routes/       ← POST /api/enrich (SSE streaming)
│   └── tests/        ← Jest test suite
├── frontend/
│   └── src/
│       ├── components/   ← IOCInput, EnrichmentTable, VerdictBadge, AnalystReport
│       └── lib/          ← IOC parser mirror, defang utility
├── SPEC.md               ← Full technical specification and architecture
└── start-argus.command   ← One-click startup script
```

See `SPEC.md` for full technical documentation including API schemas, security architecture, and enrichment response format.

# ARGUS — IOC Enrichment Engine

![Status](https://img.shields.io/badge/Status-Production--Ready-success)
![Stack](https://img.shields.io/badge/Stack-Node.js%20%2B%20React-blue)
![APIs](https://img.shields.io/badge/APIs-VirusTotal%20%7C%20AbuseIPDB%20%7C%20MalwareBazaar%20%7C%20URLScan%20%7C%20GreyNoise%20%7C%20OTX%20%7C%20ip--api-red)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Overview

ARGUS is a local IOC (Indicator of Compromise) enrichment engine built for SOC analysts. Paste or import a raw blob of text containing hashes, IP addresses, domains, or URLs — ARGUS automatically detects each IOC type, fans out to VirusTotal, AbuseIPDB, MalwareBazaar, URLScan.io, GreyNoise, AlienVault OTX, and ip-api in parallel, and renders a live enrichment table with verdicts, geolocation, and threat intelligence context.

Designed to run locally. API keys never leave the backend process. Nothing is sent to the cloud except the IOC values themselves when querying enrichment APIs.

---

## What It Does

1. **Paste anything** — mixed hashes, IPs, domains, URLs in any format. Defanged IOCs (`hxxp://`, `[.]`, `[dot]`) handled automatically. Duplicates silently removed before enrichment.
2. **Bulk file import** — drag and drop a `.txt`, `.csv`, or `.log` file onto the input area, or use the Upload File button. IOCs are extracted and merged with anything already typed. A badge shows the filename and IOC count.
3. **Auto-detection** — IOC types identified in real time as you type with color-coded badges.
4. **Parallel enrichment** — VirusTotal (rate-limited to 4/min), MalwareBazaar, AbuseIPDB, URLScan.io, GreyNoise, AlienVault OTX, and ip-api all queried simultaneously.
5. **Live results table** — rows populate as each API responds, no waiting for everything to finish. MALICIOUS rows auto-expand immediately.
6. **Geolocation** — IPv4 addresses automatically enriched with country (flag + name), ASN number, and organisation via ip-api.com (free, no key required).
7. **URLScan.io sandbox** — URLs, domains, and IPs checked against URLScan.io's scan history. Returns MALICIOUS / SUSPICIOUS / UNRATED verdict and scan count. Click the verdict badge to open URLScan directly. Works without an API key; optional key increases rate limits.
8. **GreyNoise classification** — IPv4 addresses checked against GreyNoise to identify internet background noise (scanners, crawlers) vs. targeted activity. NOISE / RIOT / MALICIOUS badges. Click badge to open GreyNoise viz. Requires a free GreyNoise API key.
9. **AlienVault OTX** — all IOC types checked against OTX threat intelligence pulses. Shows pulse count, adversary attribution, malware families, and MITRE ATT&CK IDs. 3+ pulses → MALICIOUS verdict. Click pulse count to open OTX indicator page. Requires a free OTX API key.
10. **WHOIS for domains** — registrar, registration year, and expiry date extracted from VirusTotal's domain response. Age color-coded: red < 1yr (phishing signal), amber < 2yr, teal established. Click "Full WHOIS ↗" to open whois.domaintools.com.
11. **Verdicts** — each IOC gets CLEAN, SUSPICIOUS, or MALICIOUS based on combined signal from all sources (VT, AbuseIPDB, MalwareBazaar, URLScan, GreyNoise, OTX).
12. **Configurable thresholds** — click ⚙ in the header to open the settings drawer. Adjust VT detection count and AbuseIPDB score thresholds independently. Verdicts update instantly without re-running enrichment. Saved to localStorage.
13. **Sort and filter** — filter results by verdict (ALL / MALICIOUS / SUSPICIOUS / CLEAN). Click VT Score, Abuse %, or Verdict column headers to sort ascending/descending.
14. **Clickable source links** — VT Score opens VirusTotal, Abuse % opens AbuseIPDB, all badges in expanded rows link directly to the source for deeper investigation.
15. **Copy malicious IOCs** — one-click button copies all MALICIOUS IOC values to clipboard for blocklisting or escalation. Appears automatically when malicious results exist.
16. **Pivot search** — each expanded row shows a contextual Pivot button when a related IOC can be derived (URL → domain, domain → URL, IP → associated domain, hash → VT name). One click pre-fills the input for immediate follow-on enrichment.
17. **Search history** — last 15 searches stored automatically in the browser. Each entry shows verdict summary and IOC preview. Click any entry to reload instantly.
18. **Persistent results** — last enrichment session survives a page refresh. Results and AI brief restored automatically. Cleared when a new analysis begins.
19. **AI threat brief** — optional Claude-powered intelligence report streams in real time after enrichment completes. Incorporates VT, AbuseIPDB, GreyNoise, OTX adversary/campaign data. Requires Anthropic API key.
20. **Export** — download the full enrichment report as `.md`, `.csv`, or `.json`. CSV and JSON include all enrichment sources (VT, AbuseIPDB, URLScan, GreyNoise, OTX, Geo). Copy markdown directly to clipboard.

---

## Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + Vite + Tailwind CSS |
| Backend | Node.js + Express |
| Security | Helmet.js, CORS, express-rate-limit |
| Enrichment | VirusTotal v3, AbuseIPDB v2, MalwareBazaar, URLScan.io, GreyNoise, AlienVault OTX, ip-api.com |
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
- Optional: AbuseIPDB key (free) — abuseipdb.com
- Optional: GreyNoise key (free) — greynoise.io
- Optional: URLScan.io key (free) — urlscan.io (works without one, key increases rate limit)
- Optional: AlienVault OTX key (free) — otx.alienvault.com
- Optional: Anthropic API key (paid ~$0.05–0.15/run) — console.anthropic.com
- ip-api.com — no key required (free tier, 45 req/min)

### First-time install
```bash
cd backend && npm install
cd ../frontend && npm install
```

### Add API keys
```bash
open -a TextEdit backend/.env
```
Fill in `VIRUSTOTAL_API_KEY` and optionally `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY`, `URLSCAN_API_KEY`, `OTX_API_KEY`, and `ANTHROPIC_API_KEY`.

### Start the app
Double-click `start-argus.command` in the project folder, then open **http://localhost:5173**.

Or manually in two terminals:
```bash
# Terminal 1
cd backend && npm run dev

# Terminal 2
cd frontend && npm run dev
```

### Syncing across machines
The project is version-controlled on GitHub. On any machine with the repo cloned:
```bash
cd ~/Documents/argus && git pull
```
Note: `.env` is gitignored and never synced — add API keys manually on each machine.

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
│   ├── lib/
│   │   ├── iocParser.js       ← IOC detection and type classification
│   │   ├── virustotal.js      ← VirusTotal v3 enrichment + WHOIS extraction
│   │   ├── abuseipdb.js       ← AbuseIPDB v2 enrichment
│   │   ├── malwarebazaar.js   ← MalwareBazaar enrichment
│   │   ├── geolocation.js     ← IP geolocation via ip-api.com (no key)
│   │   ├── urlscan.js         ← URLScan.io sandbox verdict (optional key)
│   │   ├── greynoise.js       ← GreyNoise IP noise classification (free key)
│   │   ├── otx.js             ← AlienVault OTX threat intelligence (free key)
│   │   ├── queue.js           ← VT rate-limit queue (4/min)
│   │   └── claude.js          ← AI report generation + verdict logic
│   ├── middleware/            ← Security headers, input validation
│   ├── routes/                ← POST /api/enrich (SSE streaming)
│   └── tests/                 ← Jest test suite
├── frontend/
│   └── src/
│       ├── components/
│       │   ├── IOCInput.jsx        ← Paste + drag-and-drop file import
│       │   ├── EnrichmentTable.jsx ← Results table, sort, filter, expand
│       │   ├── VerdictBadge.jsx
│       │   ├── AnalystReport.jsx
│       │   ├── SearchHistory.jsx
│       │   ├── SettingsDrawer.jsx  ← Configurable verdict thresholds
│       │   └── ExportButton.jsx    ← MD / CSV / JSON export
│       └── lib/
│           ├── iocParser.js   ← Frontend IOC parser mirror
│           ├── defang.js      ← IOC defanging utility
│           └── verdict.js     ← Frontend verdict logic + threshold storage
├── SPEC.md               ← Full technical specification and architecture
└── start-argus.command   ← One-click startup script
```

See `SPEC.md` for full technical documentation including API schemas, security architecture, and enrichment response format.

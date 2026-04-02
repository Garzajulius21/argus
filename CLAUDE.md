# ARGUS — IOC Enrichment Engine
> Living project document. Claude Code updates this file after every meaningful change.
> Last updated: 2026-04-02 — Added startup script, deployment instructions, transfer notes
> Version: 1.0.1

---

## Quick Start

### Prerequisites
- Node.js installed (v18+) — download free at nodejs.org (LTS version)
- VirusTotal API key (free) — virustotal.com → sign in → API Key
- Optional: AbuseIPDB key (free), Anthropic API key (paid, ~$0.01–0.03/run)

### First-time setup (run once per machine)
```bash
cd "/path/to/argus/backend" && npm install
cd "/path/to/argus/frontend" && npm install
```

### Option A — One-click startup (recommended)
Double-click `start-argus.command` in the argus folder.

**First time only on each Mac:** macOS will block it with a security warning.
- Right-click → Open → Open (to permanently allow it), OR
- Run this in Terminal to remove the quarantine flag:
  ```bash
  xattr -d com.apple.quarantine /path/to/argus/start-argus.command
  ```
  Then double-click normally from then on.

### Option B — Manual startup (two terminals)

**Terminal 1 — Backend:**
```bash
cd "/path/to/argus/backend" && npm run dev
```
Wait until you see: `ARGUS backend listening on port 3001`

**Terminal 2 — Frontend:**
```bash
cd "/path/to/argus/frontend" && npm run dev
```
Wait until you see: `Local: http://localhost:5173`

Then open **http://localhost:5173** in your browser. Both terminals must stay open.

### How to use ARGUS
1. Paste any mix of IOCs into the text box — hashes (MD5/SHA1/SHA256), IP addresses, domains, or URLs. One per line or all mixed together. Defanged formats (`hxxp://`, `[.]`) are handled automatically.
2. ARGUS auto-detects and labels each type in real time as you type.
3. Click **Analyze**. ARGUS will:
   - Query VirusTotal for all IOC types (rate-limited to 4/min automatically — progress shown)
   - Query MalwareBazaar for any file hashes (no key required)
   - Query AbuseIPDB for any IP addresses (requires AbuseIPDB key)
4. The enrichment table populates live as results come back — you don't wait for everything to finish.
5. Once enrichment finishes, Claude streams a threat intelligence brief (requires Anthropic key).
6. Use the **Export** button to copy or download the full report as a `.md` file.

### API Keys
| Key | Where to get it | Required for |
|-----|----------------|----------|
| `VIRUSTOTAL_API_KEY` | virustotal.com → Sign in → API Key | VT enrichment |
| `ABUSEIPDB_API_KEY` | abuseipdb.com → Account → API | IP reputation scores |
| `ANTHROPIC_API_KEY` | console.anthropic.com | AI threat brief (costs ~$0.01–0.03/run) |

Add keys to `backend/.env`. To open it:
```bash
open -a TextEdit "/path/to/argus/backend/.env"
```

### What works without all keys
- **VT key only:** Enrichment table works for all IOC types, MalwareBazaar hash lookups work, no AI report
- **VT + AbuseIPDB:** Adds IP reputation scores (0–100%) to the table
- **All three:** Full experience including streaming AI threat brief

---

## Transferring to Another Machine

ARGUS is just a folder — no installer, no database, no cloud account needed.

1. Copy the `argus/` folder to the new machine (AirDrop, USB, shared drive)
2. Install Node.js on the new machine if not already installed (nodejs.org, LTS)
3. Run first-time setup (see above)
4. Add your API keys to `backend/.env` on the new machine
5. Start with `start-argus.command` or the manual method

**If `start-argus.command` is blocked on the new machine** (macOS Gatekeeper), run:
```bash
xattr -d com.apple.quarantine /path/to/argus/start-argus.command
```

---

## Privacy & Safety Notes

- **API keys never leave the backend process** — the browser never sees them
- **The app only listens on localhost** — nothing on your network can reach it
- **IOC values are sent to VirusTotal and MalwareBazaar** — that's intentional, it's how enrichment works. Both services log queries. This is standard SOC practice but check your org policy before submitting sensitive indicators from an active IR engagement.
- **Nothing is stored between sessions** — no database, no logs saved to disk by default
- **AbuseIPDB key is optional** — without it, IP reputation scoring is skipped gracefully

---

## What ARGUS Is

ARGUS is a local SOC analyst workbench for enriching indicators of compromise (IOCs). An analyst pastes a raw blob of text containing hashes, IPs, domains, or URLs. ARGUS auto-detects IOC types, fans out to enrichment APIs in parallel, and streams a Claude-generated threat intelligence brief with a verdict, confidence score, and MITRE ATT&CK mapping.

**Primary users:** Incident responders and SOC analysts on a local or internal network.
**Not a public web app.** Designed for local deployment or internal hosting only.

---

## Project Structure

```
argus/
├── CLAUDE.md                  <- This file. Update it as you build.
├── .gitignore
├── start-argus.command        <- Double-click to start both servers at once
├── .env.example               <- Template only. Never commit .env.
├── backend/
│   ├── package.json
│   ├── server.js              <- Express entry point
│   ├── .env                   <- Never committed. Contains API keys.
│   ├── routes/
│   │   └── enrich.js          <- POST /api/enrich
│   ├── lib/
│   │   ├── iocParser.js       <- Regex-based IOC type detection
│   │   ├── virustotal.js      <- VirusTotal v3 API wrapper
│   │   ├── abuseipdb.js       <- AbuseIPDB API wrapper
│   │   ├── malwarebazaar.js   <- MalwareBazaar (no key required)
│   │   ├── claude.js          <- Anthropic SDK, streaming report
│   │   └── queue.js           <- VT rate limit queue (4 req/min)
│   └── middleware/
│       ├── validate.js        <- Input sanitization and size limits
│       └── security.js        <- Helmet config, CORS, rate limiting
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── components/
│       │   ├── IOCInput.jsx           <- Paste area + parse trigger
│       │   ├── IOCTypeChip.jsx        <- Colored badge per IOC type
│       │   ├── EnrichmentTable.jsx    <- Per-IOC enrichment grid
│       │   ├── VerdictBadge.jsx       <- CLEAN / SUSPICIOUS / MALICIOUS
│       │   ├── AnalystReport.jsx      <- Streaming Claude output panel
│       │   ├── ProgressBar.jsx        <- Rate-limit queue progress
│       │   └── ExportButton.jsx       <- Copy/download report as markdown
│       └── lib/
│           ├── iocParser.js           <- Mirror of backend parser (UI preview)
│           └── defang.js              <- Defang IOCs for safe display
└── tests/
    ├── iocParser.test.js
    ├── virustotal.test.js
    └── fixtures/
        └── sampleIOCs.txt
```

---

## Tech Stack

| Layer | Technology | Notes |
|---|---|---|
| Frontend | React 18 + Vite | Fast local dev |
| Styling | Tailwind CSS | Dark SOC aesthetic |
| Backend | Node.js + Express | API key isolation |
| AI | Anthropic SDK (claude-sonnet-4-20250514) | Streaming via SSE |
| Enrichment 1 | VirusTotal v3 | Free tier: 4 req/min, 500/day |
| Enrichment 2 | AbuseIPDB | Free tier: 1,000 IP checks/day |
| Enrichment 3 | MalwareBazaar | Free, no API key |
| Security | Helmet.js | HTTP security headers |
| Testing | Jest | IOC parser + API wrappers |

---

## Environment Variables

Backend `.env` (never committed):

```
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
ANTHROPIC_API_KEY=
PORT=3001
NODE_ENV=development
ALLOWED_ORIGIN=http://localhost:5173
```

`.env.example` (always committed, no real values):
Mirrors the above with empty values and inline comments explaining what each key does and where to get it.

---

## API Configuration

### VirusTotal v3

Base URL: `https://www.virustotal.com/api/v3/`
Auth: `x-apikey` header
Endpoints used:
- `GET /files/{hash}` — MD5, SHA1, SHA256 lookup
- `GET /ip_addresses/{ip}` — IPv4 enrichment
- `GET /domains/{domain}` — Domain enrichment
- `GET /urls/{url_id}` — URL enrichment (URL must be base64url-encoded, no padding)

Rate limit: 4 requests per minute on free tier. Handled by `backend/lib/queue.js`.

### AbuseIPDB

Base URL: `https://api.abuseipdb.com/api/v2/`
Auth: `Key` header
Endpoint used:
- `GET /check?ipAddress={ip}&maxAgeInDays=90&verbose`

Only called for IPv4 IOCs. Skipped gracefully for all other types.

### MalwareBazaar

Base URL: `https://mb-api.abuse.ch/api/v1/`
Auth: None required
Called via POST with `query=get_info&hash={hash}` for all hash types.

### Anthropic API

Model: `claude-sonnet-4-20250514`
Max tokens: 1500
Stream: true (SSE to frontend)
Called after all enrichment resolves. Never called with raw user input — only structured enrichment results.

---

## IOC Detection Logic

Regex-based, runs client-side for UI preview and server-side for actual enrichment.

| Type | Pattern |
|---|---|
| SHA256 | `/^[a-fA-F0-9]{64}$/` |
| SHA1 | `/^[a-fA-F0-9]{40}$/` |
| MD5 | `/^[a-fA-F0-9]{32}$/` |
| IPv4 | Standard dotted-quad, excludes private RFC1918 ranges |
| Domain | RFC-compliant hostname regex, excludes bare IPs |
| URL | Starts with `http://` or `https://`, also matches defanged `hxxp[s]://` |

Parser is fault-tolerant: handles line breaks, commas, semicolons, whitespace, and mixed formats in the same paste. Deduplicates before enrichment.

**Defanging:** IOCs are displayed in defanged format throughout the UI (`hxxp://`, `[.]` instead of `.` in domains). Raw IOCs are only sent to the backend for API calls, never rendered as clickable links.

---

## Security Architecture

This section is non-negotiable. Do not deviate from these controls.

### API Key Isolation
All API keys live exclusively in `backend/.env`. The frontend never receives, stores, or transmits API keys. All enrichment requests from the frontend go to `/api/enrich` on the Express backend.

### Input Validation (backend/middleware/validate.js)
- Maximum payload size: 50KB (express.json limit)
- Maximum IOC count per request: 100
- Each IOC string maximum length: 2,083 characters (max URL length)
- Strip non-printable characters before parsing
- Reject requests with Content-Type other than application/json

### CORS
Restricted to `ALLOWED_ORIGIN` from `.env` (default: `http://localhost:5173`). No wildcard. Credentials not allowed.

### HTTP Security Headers (Helmet.js)
- `Content-Security-Policy`: restrict script sources, no inline eval
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Strict-Transport-Security` (when TLS is available)
- `Referrer-Policy: no-referrer`

### Rate Limiting (express-rate-limit)
- `/api/enrich`: 30 requests per 15-minute window per IP
- Global: 200 requests per 15-minute window per IP
- Returns 429 with `Retry-After` header

### No Sensitive Logging
Analyst IOC submissions are never written to log files or stdout in production. Only errors and request metadata (method, path, status, response time) are logged. Set `NODE_ENV=production` to enforce this.

### Dependency Management
- `npm audit` runs as part of `npm test`
- `.gitignore` includes `node_modules/`, `.env`, `*.log`, `dist/`
- Lock files (`package-lock.json`) are committed

### Request Timeouts
All outbound API calls have a 10-second timeout. The overall `/api/enrich` route times out at 120 seconds to account for VT rate-limit queuing on large batches.

### No Eval / Dynamic Execution
No use of `eval()`, `new Function()`, or `child_process` anywhere in the codebase.

---

## Claude Correlation Prompt

The system prompt passed to the Anthropic API on every enrichment request. This is the heart of the analyst report. Do not modify without updating this document.

```
You are a senior threat intelligence analyst embedded in a SOC. You have just received enrichment data from VirusTotal, AbuseIPDB, and MalwareBazaar for a set of indicators of compromise (IOCs) submitted by an analyst.

Your task: Write a structured threat intelligence brief.

The brief must include:

1. OVERALL VERDICT — One of: CLEAN, SUSPICIOUS, or MALICIOUS. With a confidence percentage (0-100%) and one sentence of reasoning.

2. IOC SUMMARY TABLE — For each IOC: the defanged indicator, its type, your verdict for that specific indicator, and the key data point that drove your conclusion.

3. THREAT CONTEXT — 2-3 sentences describing what this activity looks like in aggregate. If the IOCs are unrelated, say so. If they suggest a campaign, name the pattern.

4. MITRE ATT&CK MAPPING — List any techniques the observed behaviors map to, with technique IDs (e.g. T1071.001 - Application Layer Protocol: Web Protocols). Only include techniques supported by the enrichment data. If none, say "Insufficient behavioral data for ATT&CK mapping."

5. RECOMMENDED ANALYST ACTIONS — 3-5 concrete next steps. Be specific. Examples: "Block at perimeter firewall", "Search SIEM for connections to this IP in the last 30 days", "Submit file hash to sandbox for dynamic analysis".

Tone: Authoritative and direct. Written for a Tier 2 analyst. No hedging. No generic advice. If the data is clean, say so confidently and explain why. Do not invent threat intel not present in the enrichment data.

Format: Use markdown. The brief will be rendered in a monospace-friendly panel.
```

---

## Enrichment Response Schema

Normalized schema returned by all enrichment wrappers. Claude Code must ensure all wrappers return this exact shape:

```javascript
{
  ioc: String,           // original value
  type: String,          // "sha256" | "sha1" | "md5" | "ipv4" | "domain" | "url"
  sources: {
    virustotal: {
      queried: Boolean,
      malicious: Number,     // engine count
      suspicious: Number,
      harmless: Number,
      undetected: Number,
      communityScore: Number,
      lastAnalysisDate: String,
      permalink: String,
      error: String | null
    },
    abuseipdb: {
      queried: Boolean,
      abuseScore: Number,    // 0-100
      country: String,
      isp: String,
      totalReports: Number,
      lastReported: String,
      error: String | null
    },
    malwarebazaar: {
      queried: Boolean,
      found: Boolean,
      fileName: String | null,
      fileType: String | null,
      tags: Array,
      firstSeen: String | null,
      error: String | null
    }
  },
  verdict: String | null,   // Populated by Claude after full enrichment
  enrichedAt: String         // ISO timestamp
}
```

---

## UI Design Specification

**Aesthetic:** Dark SOC terminal — authoritative, dense, readable. Inspired by Bloomberg Terminal and Splunk's dark mode. Not playful. Not corporate dashboard.

**Colors:**
```css
--bg-primary: #0a0d0f;
--bg-surface: #0f1317;
--bg-card: #141a1f;
--border: #1e2730;
--text-primary: #e2e8f0;
--text-secondary: #94a3b8;
--text-mono: #a8d8a8;
--accent: #f59e0b;           /* amber — used for highlights, active states */
--verdict-clean: #22c55e;
--verdict-suspicious: #f59e0b;
--verdict-malicious: #ef4444;
--vt-hit: #ef4444;
```

**Typography:**
- Monospace: `JetBrains Mono` (Google Fonts) — used for IOC values, hashes, all raw indicator data
- Sans: `IBM Plex Sans` — used for UI chrome, labels, analyst report body
- Do not use system fonts or Inter

**Key UX behaviors:**
- Parsing is instant and visual: as the analyst types/pastes, IOC chips appear below the input showing detected types in real time
- Enrichment shows per-IOC progress indicators as APIs return (not a single spinner for everything)
- The Claude report panel streams token by token — analysts see it writing in real time
- Verdict badges animate in with a brief flash on state change
- All IOC values in the UI are defanged and not clickable
- VirusTotal permalink opens via a copy-to-clipboard action only, never a direct link
- Export button generates a markdown report that can be pasted into a ticket

---

## Rate Limit Queue Design

VirusTotal free tier: 4 requests per minute.

The queue in `backend/lib/queue.js` must:
- Process a maximum of 4 VT requests per 60-second window
- If a batch exceeds 4 IOCs, process first 4 immediately, then wait and process in 4-IOC windows
- Emit progress events to the frontend via SSE: `{processed: N, total: M, waitingMs: N}`
- Never fail silently — if VT rate limit is hit (429), wait and retry up to 3 times with exponential backoff
- AbuseIPDB and MalwareBazaar run in parallel without queuing (they have generous limits)

---

## Changelog

Claude Code appends an entry here after every meaningful build session.

| Date | Version | What Changed |
|---|---|---|
| 2026-04-02 | 0.1.0 | Initial CLAUDE.md created |
| 2026-04-02 | 1.0.0 | Full build: all 6 phases complete — scaffold, IOC parser, enrichment wrappers (VT/AbuseIPDB/MalwareBazaar), rate limit queue, Express backend with security middleware, React frontend |
| 2026-04-02 | 1.0.1 | Added `start-argus.command` one-click startup script; updated CLAUDE.md with transfer instructions, Gatekeeper workaround, privacy notes, and per-key capability breakdown |

---

## Known Issues / Tech Debt

Claude Code tracks issues here as they are discovered during build.

- [ ] None yet

---

## Build Status

Claude Code updates this section to reflect what has and has not been built yet.

- [x] Project scaffold and dependencies
- [x] IOC parser with unit tests (99 tests, 97% coverage)
- [x] VirusTotal v3 wrapper
- [x] AbuseIPDB wrapper
- [x] MalwareBazaar wrapper
- [x] Rate limit queue (4 req/60s, exponential backoff retry)
- [x] Express backend with security middleware (Helmet CSP, CORS, rate limits)
- [x] /api/enrich route (SSE streaming)
- [x] Claude streaming correlation report (claude-sonnet-4-6)
- [x] Frontend: IOCInput component with real-time chip preview
- [x] Frontend: EnrichmentTable component with loading skeletons
- [x] Frontend: AnalystReport streaming panel
- [x] Frontend: Export to markdown (clipboard + download)
- [x] One-click startup script (start-argus.command)
- [ ] End-to-end test with live APIs (requires real API keys)

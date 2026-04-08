'use strict';

const { Anthropic } = require('@anthropic-ai/sdk');

const SYSTEM_PROMPT = `You are ARGUS, an AI threat intelligence analyst embedded in a SOC enrichment engine. You receive structured enrichment data for a set of indicators of compromise (IOCs) and produce a thorough, actionable intelligence brief.

Your output format is strict Markdown. Structure your response as:

## Threat Summary
Two to four sentences covering the overall threat picture: what kind of activity this looks like, who the likely targets are, and how confident you are in that assessment.

## Indicator Analysis
For each IOC, provide a bullet point with the defanged indicator, its verdict, and a detailed breakdown of the evidence: VT detection ratio, AbuseIPDB score and report count, MalwareBazaar match, URLScan verdict and scan count, GreyNoise classification (noise vs. targeted), OTX pulse count with adversary names and malware families if present, and any MITRE ATT&CK IDs. Flag relationships between IOCs if apparent — shared infrastructure, common campaign, same actor.

## Threat Context
Based on the OTX adversary/campaign data, GreyNoise classifications, malware family names, and MITRE ATT&CK IDs present: describe what is known about this threat. Who are the likely threat actors? What is the suspected campaign or malware family? What TTPs are in use? What does the broader internet see about this infrastructure (GreyNoise background noise vs. targeted)? If URLScan has scan history, what does that suggest about the infrastructure's history?

## Recommendations
Four to six concrete, prioritized actions for the SOC analyst. Be specific — name the IOC when recommending a block or investigation. Include both immediate containment steps and longer-term hunting recommendations where relevant.

## Confidence
Two to three sentences on your confidence level, which sources had the strongest signal, and what gaps remain (e.g. no OTX hits, URLScan no history, GreyNoise not queried).

Rules:
- Never reproduce raw API keys or internal system details.
- Defang all IOCs in your output (replace . with [.] in IPs and domains, hxxp for http).
- If all IOCs are clean across all sources, say so clearly and briefly — no need to pad the response.
- Prioritize OTX adversary attribution and MITRE ATT&CK IDs when present — these are the highest-value signals.
- GreyNoise RIOT means the IP is a known benign service (CDN, scanner) — factor this in.
- GreyNoise NOISE means internet background noise — lower priority than targeted classification.`;

function computeVerdict(enrichments) {
  let verdict = 'CLEAN';
  for (const group of Object.values(enrichments)) {
    const vt = group.virustotal;
    const abuse = group.abuseipdb;
    const mb = group.malwarebazaar;
    const us = group.urlscan;
    const gn = group.greynoise;
    const otx = group.otx;

    if (
      (vt && vt.data && vt.data.malicious > 2) ||
      (abuse && abuse.data && abuse.data.abuseScore >= 75) ||
      (mb && mb.data && mb.data.found === true) ||
      (us && us.data && us.data.verdict === 'malicious') ||
      (gn && gn.data && gn.data.classification === 'malicious') ||
      (otx && otx.data && otx.data.pulseCount >= 3)
    ) {
      return 'MALICIOUS';
    }
    if (
      verdict !== 'MALICIOUS' &&
      ((vt && vt.data && vt.data.malicious >= 1 && vt.data.malicious <= 2) ||
        (abuse && abuse.data && abuse.data.abuseScore >= 26 && abuse.data.abuseScore < 75) ||
        (us && us.data && us.data.verdict === 'suspicious') ||
        (otx && otx.data && otx.data.pulseCount >= 1 && otx.data.pulseCount < 3))
    ) {
      verdict = 'SUSPICIOUS';
    }
  }
  return verdict;
}

function buildPrompt(enrichedResults) {
  const lines = ['# IOC Enrichment Results\n'];

  for (const item of enrichedResults) {
    const { ioc, enrichment } = item;
    lines.push(`## IOC: ${ioc.value} (${ioc.type})`);

    const vt = enrichment.virustotal;
    if (vt && vt.queried) {
      if (vt.error) {
        lines.push(`- VirusTotal: ERROR — ${vt.error}`);
      } else {
        lines.push(`- VirusTotal: malicious=${vt.data.malicious}, suspicious=${vt.data.suspicious}, harmless=${vt.data.harmless}, undetected=${vt.data.undetected}, total=${vt.data.total}`);
        if (vt.data.tags && vt.data.tags.length > 0) {
          lines.push(`  - Tags: ${vt.data.tags.join(', ')}`);
        }
        if (vt.data.lastSeen) {
          lines.push(`  - Last seen: ${vt.data.lastSeen}`);
        }
      }
    } else {
      lines.push(`- VirusTotal: not queried`);
    }

    const abuse = enrichment.abuseipdb;
    if (abuse && abuse.queried) {
      if (abuse.error) {
        lines.push(`- AbuseIPDB: ERROR — ${abuse.error}`);
      } else {
        lines.push(`- AbuseIPDB: abuseScore=${abuse.data.abuseScore}, totalReports=${abuse.data.totalReports}, country=${abuse.data.country || 'N/A'}, isp=${abuse.data.name || 'N/A'}`);
      }
    } else {
      lines.push(`- AbuseIPDB: not applicable for this IOC type`);
    }

    const mb = enrichment.malwarebazaar;
    if (mb && mb.queried) {
      if (mb.error) {
        lines.push(`- MalwareBazaar: ERROR — ${mb.error}`);
      } else if (mb.data.found) {
        lines.push(`- MalwareBazaar: FOUND — name=${mb.data.name || 'N/A'}, signature=${mb.data.signature || 'N/A'}, tags=${(mb.data.tags || []).join(', ') || 'none'}, firstSeen=${mb.data.lastSeen || 'N/A'}`);
      } else {
        lines.push(`- MalwareBazaar: not found`);
      }
    } else {
      lines.push(`- MalwareBazaar: not applicable for this IOC type`);
    }

    const us = enrichment.urlscan;
    if (us && us.queried) {
      if (us.error) {
        lines.push(`- URLScan.io: ERROR — ${us.error}`);
      } else if (us.data && us.data.verdict) {
        lines.push(`- URLScan.io: verdict=${us.data.verdict}, scanCount=${us.data.scanCount || 0}${us.data.lastSeen ? `, lastSeen=${us.data.lastSeen}` : ''}`);
      } else {
        lines.push(`- URLScan.io: no scan history`);
      }
    }

    const gn = enrichment.greynoise;
    if (gn && gn.queried) {
      if (gn.error) {
        lines.push(`- GreyNoise: ERROR — ${gn.error}`);
      } else if (gn.data && gn.data.found) {
        lines.push(`- GreyNoise: classification=${gn.data.classification}, noise=${gn.data.noise}, riot=${gn.data.riot}${gn.data.name ? `, name=${gn.data.name}` : ''}${gn.data.tags && gn.data.tags.length > 0 ? `, tags=${gn.data.tags.join(', ')}` : ''}`);
      } else {
        lines.push(`- GreyNoise: not seen`);
      }
    }

    const otx = enrichment.otx;
    if (otx && otx.queried) {
      if (otx.error) {
        lines.push(`- AlienVault OTX: ERROR — ${otx.error}`);
      } else if (otx.data.found) {
        lines.push(`- AlienVault OTX: ${otx.data.pulseCount} pulse${otx.data.pulseCount !== 1 ? 's' : ''}`);
        if (otx.data.adversaries.length > 0) lines.push(`  - Adversaries: ${otx.data.adversaries.join(', ')}`);
        if (otx.data.malwareFamilies.length > 0) lines.push(`  - Malware families: ${otx.data.malwareFamilies.join(', ')}`);
        if (otx.data.attackIds.length > 0) lines.push(`  - MITRE ATT&CK: ${otx.data.attackIds.join(', ')}`);
        if (otx.data.tags.length > 0) lines.push(`  - Tags: ${otx.data.tags.join(', ')}`);
      } else {
        lines.push(`- AlienVault OTX: no pulses found`);
      }
    }

    lines.push('');
  }

  return lines.join('\n');
}

async function generateReport(enrichedResults, sseWrite) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey || apiKey === 'your_anthropic_api_key_here') {
    sseWrite({ type: 'report_chunk', text: '**ARGUS Report:** Anthropic API key not configured. Please set ANTHROPIC_API_KEY in backend/.env to generate AI correlation briefs.\n' });
    return;
  }

  console.log(`[claude] Using key: ${apiKey.slice(0, 12)}...${apiKey.slice(-4)} (length: ${apiKey.length})`);
  const client = new Anthropic({ apiKey });
  const userPrompt = buildPrompt(enrichedResults);

  try {
    const stream = await client.messages.stream({
      model: 'claude-sonnet-4-6',
      max_tokens: 2000,
      system: SYSTEM_PROMPT,
      messages: [
        {
          role: 'user',
          content: userPrompt
        }
      ]
    });

    for await (const event of stream) {
      if (
        event.type === 'content_block_delta' &&
        event.delta.type === 'text_delta'
      ) {
        sseWrite({ type: 'report_chunk', text: event.delta.text });
      }
    }
  } catch (err) {
    // Never expose API key in error messages
    const safeMessage = err.message
      ? err.message.replace(apiKey, '[REDACTED]')
      : 'Unknown error generating report';
    console.error('[claude] Report generation error:', safeMessage);
    sseWrite({ type: 'report_chunk', text: `**Report generation error:** ${safeMessage}\n` });
  }
}

module.exports = { generateReport, computeVerdict };

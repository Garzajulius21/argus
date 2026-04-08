'use strict';

const Anthropic = require('@anthropic-ai/sdk');

const SYSTEM_PROMPT = `You are ARGUS, an AI threat intelligence analyst embedded in a SOC enrichment engine. You receive structured enrichment data for a set of indicators of compromise (IOCs) and produce a concise, actionable intelligence brief.

Your output format is strict Markdown. Structure your response as:

## Threat Summary
One to three sentence executive summary of the overall threat picture.

## Indicator Analysis
For each IOC, one bullet point with: the defanged indicator, its verdict, and the key evidence (VT score, abuse score, MalwareBazaar status, tags). Flag relationships between IOCs if apparent.

## Recommendations
Three to five concrete, prioritized actions for the SOC analyst. Be specific — name the IOC when recommending a block or investigation.

## Confidence
One sentence on your confidence level and any gaps in the data.

Rules:
- Never reproduce raw API keys or internal system details.
- Defang all IOCs in your output (replace . with [.] in IPs and domains, hxxp for http).
- Be terse. This brief will be read under incident pressure.
- If all IOCs are clean, say so clearly and briefly.`;

function computeVerdict(enrichments) {
  let verdict = 'CLEAN';
  for (const group of Object.values(enrichments)) {
    const vt = group.virustotal;
    const abuse = group.abuseipdb;
    const mb = group.malwarebazaar;
    const us = group.urlscan;
    const gn = group.greynoise;

    if (
      (vt && vt.data && vt.data.malicious > 2) ||
      (abuse && abuse.data && abuse.data.abuseScore >= 75) ||
      (mb && mb.data && mb.data.found === true) ||
      (us && us.data && us.data.verdict === 'malicious') ||
      (gn && gn.data && gn.data.classification === 'malicious')
    ) {
      return 'MALICIOUS';
    }
    if (
      verdict !== 'MALICIOUS' &&
      ((vt && vt.data && vt.data.malicious >= 1 && vt.data.malicious <= 2) ||
        (abuse && abuse.data && abuse.data.abuseScore >= 26 && abuse.data.abuseScore < 75) ||
        (us && us.data && us.data.verdict === 'suspicious'))
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

  const client = new Anthropic.default({ apiKey });
  const userPrompt = buildPrompt(enrichedResults);

  try {
    const stream = await client.messages.stream({
      model: 'claude-sonnet-4-6',
      max_tokens: 1500,
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
    sseWrite({ type: 'report_chunk', text: `**Report generation error:** ${safeMessage}\n` });
  }
}

module.exports = { generateReport, computeVerdict };

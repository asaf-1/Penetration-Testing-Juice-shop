/**
 * Maps security findings to SARIF 2.1.0 so they can be uploaded to GitHub
 * code scanning and rendered in the repository Security tab.
 *
 * @see https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 * @see https://docs.github.com/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
 */

import type { Finding, Severity } from './findings';

const TOOL_NAME = 'playwright-security-lab';
const TOOL_VERSION = '1.0.0';
const INFORMATION_URI = 'https://github.com/asaf-1/Penetration-Testing-Juice-shop';

type SarifLevel = 'error' | 'warning' | 'note';

/** SARIF level used for the result and the rule's default configuration. */
const severityToLevel: Record<Severity, SarifLevel> = {
  Critical: 'error',
  High: 'error',
  Medium: 'warning',
  Low: 'note',
  Info: 'note'
};

/**
 * GitHub code scanning ranks results using the numeric `security-severity`
 * property (0.0-10.0), independent of the SARIF level.
 */
const severityToScore: Record<Severity, string> = {
  Critical: '9.5',
  High: '8.0',
  Medium: '5.0',
  Low: '3.0',
  Info: '0.0'
};

interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: unknown[];
}

/** Build a deterministic SARIF log from the deduplicated finding set. */
export function toSarif(findings: Finding[], targetUrl: string): SarifLog {
  // One rule per unique finding id, in stable order.
  const ruleById = new Map<string, Finding>();
  for (const finding of findings) {
    if (!ruleById.has(finding.id)) {
      ruleById.set(finding.id, finding);
    }
  }

  const rules = Array.from(ruleById.values()).map((finding) => ({
    id: finding.id,
    name: toPascalCaseRuleName(finding.category),
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.impact },
    helpUri: finding.references?.[0],
    help: {
      text: `${finding.description}\n\nRemediation: ${finding.remediation}`
    },
    defaultConfiguration: { level: severityToLevel[finding.severity] },
    properties: {
      tags: ['security', finding.category],
      'security-severity': severityToScore[finding.severity]
    }
  }));

  const results = findings.map((finding) => ({
    ruleId: finding.id,
    level: severityToLevel[finding.severity],
    message: { text: buildMessage(finding) },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: locationForFinding(finding, targetUrl) },
          region: { startLine: 1 }
        }
      }
    ],
    partialFingerprints: {
      // Stable across runs so code scanning can track a finding over time.
      findingId: finding.id
    }
  }));

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: TOOL_NAME,
            version: TOOL_VERSION,
            informationUri: INFORMATION_URI,
            rules
          }
        },
        properties: { targetUrl },
        results
      }
    ]
  };
}

function buildMessage(finding: Finding): string {
  const evidence = finding.evidence
    .filter((item) => item.details)
    .map((item) => `${item.label}: ${item.details}`)
    .join(' | ');

  const base = `[${finding.severity}] ${finding.title} — ${finding.description}`;
  return evidence ? `${base} (${evidence})` : base;
}

/**
 * Derive a code-scanning location from the finding's evidence. DAST findings
 * have no source file, so we surface the audited endpoint/URL path instead,
 * falling back to the target origin.
 */
function locationForFinding(finding: Finding, targetUrl: string): string {
  const urlLike = finding.evidence.find(
    (item) => item.label === 'Endpoint' || item.label === 'Target URL' || item.label === 'Requested route'
  )?.details;

  const candidate = urlLike ?? targetUrl;
  try {
    const url = new URL(candidate, targetUrl);
    // GitHub code scanning treats the artifact URI as a repo-relative path and
    // rejects anything that parses as a URI scheme. "host:port" would be read as
    // a scheme, so replace the colon to keep a clean, scheme-free relative path.
    const host = url.host.replace(/:/g, '_');
    const path = `${url.pathname}${url.search}`;
    return path === '/' || path === '' ? host : `${host}${path}`;
  } catch {
    return candidate;
  }
}

function toPascalCaseRuleName(category: string): string {
  return category
    .replace(/[^a-z0-9]+/gi, ' ')
    .trim()
    .split(/\s+/)
    .map(capitalize)
    .join('');
}

function capitalize(word: string): string {
  return word ? `${word[0]!.toUpperCase()}${word.slice(1)}` : word;
}

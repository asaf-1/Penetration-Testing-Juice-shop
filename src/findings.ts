/**
 * Single source of truth for the security finding domain model.
 *
 * Both the Playwright specs (which emit findings as test attachments) and the
 * custom reporter (which aggregates them into HTML/Markdown/JSON/SARIF) import
 * these types and helpers so the schema can never drift between producer and
 * consumer.
 */

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type FindingStatus = 'observed' | 'not-observed' | 'manual-review';

export interface Evidence {
  label: string;
  details?: string;
  /** Report-relative path to an artifact such as a screenshot. */
  path?: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  status: FindingStatus;
  description: string;
  impact: string;
  remediation: string;
  evidence: Evidence[];
  references?: string[];
}

export type SeverityCounts = Record<Severity, number>;

/** Highest severity first when sorting; also used by the CI severity gate. */
export const severityOrder: Record<Severity, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Info: 1
};

export const ALL_SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Info'];

/** Sort findings by severity (highest first), then by stable id. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (left, right) =>
      severityOrder[right.severity] - severityOrder[left.severity] || left.id.localeCompare(right.id)
  );
}

/**
 * Collapse repeated findings that share an id, merging any new evidence so a
 * check that fires across several requests is reported once with combined
 * evidence rather than as duplicates.
 */
export function deduplicateFindings(findings: Finding[]): Finding[] {
  const byId = new Map<string, Finding>();

  for (const finding of findings) {
    const existing = byId.get(finding.id);
    if (!existing) {
      byId.set(finding.id, { ...finding, evidence: [...finding.evidence] });
      continue;
    }

    for (const evidence of finding.evidence) {
      const alreadyPresent = existing.evidence.some(
        (current) => current.label === evidence.label && current.details === evidence.details
      );
      if (!alreadyPresent) {
        existing.evidence.push(evidence);
      }
    }
  }

  return Array.from(byId.values());
}

export function countBySeverity(findings: Finding[]): SeverityCounts {
  return findings.reduce<SeverityCounts>(
    (counts, finding) => {
      counts[finding.severity] += 1;
      return counts;
    },
    { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 }
  );
}

/** Normalize an arbitrary label into a safe, bounded artifact filename slug. */
export function cleanFileName(input: string): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
}

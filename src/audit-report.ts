import fs from 'node:fs';
import path from 'node:path';

export type Severity = 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
export type FindingStatus = 'observed' | 'not-observed' | 'manual-review';

export interface Evidence {
  label: string;
  details?: string;
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

const severityOrder: Record<Severity, number> = {
  Critical: 5,
  High: 4,
  Medium: 3,
  Low: 2,
  Info: 1
};

export class AuditReport {
  private readonly generatedAt = new Date().toISOString();
  private readonly findings: Finding[] = [];

  constructor(
    private readonly targetUrl: string,
    private readonly outputDir = 'reports'
  ) {}

  add(finding: Finding): void {
    this.findings.push(finding);
  }

  write(): void {
    const resolvedOutputDir = path.resolve(this.outputDir);
    fs.mkdirSync(resolvedOutputDir, { recursive: true });

    const sortedFindings = [...this.findings].sort((left, right) => {
      return severityOrder[right.severity] - severityOrder[left.severity] || left.id.localeCompare(right.id);
    });

    const payload = {
      targetUrl: this.targetUrl,
      generatedAt: this.generatedAt,
      findingCount: sortedFindings.length,
      findings: sortedFindings
    };

    fs.writeFileSync(
      path.join(resolvedOutputDir, 'findings.json'),
      `${JSON.stringify(payload, null, 2)}\n`,
      'utf8'
    );
    fs.writeFileSync(path.join(resolvedOutputDir, 'security-report.md'), this.toMarkdown(sortedFindings), 'utf8');
  }

  private toMarkdown(findings: Finding[]): string {
    const summary = this.countBySeverity(findings);
    const lines = [
      '# Playwright Security Automation Report',
      '',
      `Target: ${this.targetUrl}`,
      `Generated: ${this.generatedAt}`,
      '',
      'Scope: non-destructive browser and HTTP automation against an intentionally vulnerable lab target.',
      '',
      '## Summary',
      '',
      '| Severity | Count |',
      '| --- | ---: |',
      `| Critical | ${summary.Critical} |`,
      `| High | ${summary.High} |`,
      `| Medium | ${summary.Medium} |`,
      `| Low | ${summary.Low} |`,
      `| Info | ${summary.Info} |`,
      '',
      '## Methodology',
      '',
      '- Loaded the target in Chromium through Playwright.',
      '- Captured page evidence screenshots for repeatable reporting.',
      '- Checked common browser security headers.',
      '- Sampled lab browser routes and public endpoints.',
      '- Used harmless markers for input reflection checks.',
      '- Avoided brute force, destructive requests, account takeover, and data modification.',
      '',
      '## Findings',
      ''
    ];

    if (findings.length === 0) {
      lines.push('No findings were recorded.');
      return `${lines.join('\n')}\n`;
    }

    for (const finding of findings) {
      lines.push(`### ${finding.id}: ${finding.title}`);
      lines.push('');
      lines.push(`Severity: ${finding.severity}`);
      lines.push(`Status: ${finding.status}`);
      lines.push(`Category: ${finding.category}`);
      lines.push('');
      lines.push(`Description: ${finding.description}`);
      lines.push('');
      lines.push(`Impact: ${finding.impact}`);
      lines.push('');
      lines.push('Evidence:');
      for (const evidence of finding.evidence) {
        const detail = evidence.details ? ` - ${evidence.details}` : '';
        const evidencePath = evidence.path ? ` ([artifact](${evidence.path}))` : '';
        lines.push(`- ${evidence.label}${detail}${evidencePath}`);
      }
      lines.push('');
      lines.push(`Remediation: ${finding.remediation}`);

      if (finding.references?.length) {
        lines.push('');
        lines.push('References:');
        for (const reference of finding.references) {
          lines.push(`- ${reference}`);
        }
      }

      lines.push('');
    }

    return `${lines.join('\n')}\n`;
  }

  private countBySeverity(findings: Finding[]): Record<Severity, number> {
    return findings.reduce<Record<Severity, number>>(
      (counts, finding) => {
        counts[finding.severity] += 1;
        return counts;
      },
      {
        Critical: 0,
        High: 0,
        Medium: 0,
        Low: 0,
        Info: 0
      }
    );
  }
}

export function cleanFileName(input: string): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 80);
}

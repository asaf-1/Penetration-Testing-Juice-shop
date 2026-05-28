#!/usr/bin/env node
/**
 * Render a Markdown summary of the audit findings.
 *
 * In CI this is appended to the GitHub Actions job summary
 * ($GITHUB_STEP_SUMMARY) so reviewers see the severity breakdown and the
 * notable findings directly on the workflow run page. Locally it prints to
 * stdout.
 *
 * Env:
 *   REPORTS_DIR          Directory containing findings.json (default: reports)
 *   GITHUB_STEP_SUMMARY  When set, the summary is appended to this file.
 */

import fs from 'node:fs';
import path from 'node:path';

const reportsDir = path.resolve(process.env.REPORTS_DIR ?? 'reports');
const findingsPath = path.join(reportsDir, 'findings.json');

if (!fs.existsSync(findingsPath)) {
  const message = `> No findings file found at \`${findingsPath}\`. The audit may not have run.\n`;
  emit(message);
  process.exit(0);
}

const report = JSON.parse(fs.readFileSync(findingsPath, 'utf8'));
const findings = Array.isArray(report.findings) ? report.findings : [];

const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
for (const finding of findings) {
  if (finding.severity in counts) {
    counts[finding.severity] += 1;
  }
}

const icon = { Critical: '🟥', High: '🟧', Medium: '🟨', Low: '🟦', Info: '🟩' };
const notable = findings
  .filter((finding) => finding.severity !== 'Info')
  .sort(
    (a, b) =>
      ({ Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 })[b.severity] -
      { Critical: 5, High: 4, Medium: 3, Low: 2, Info: 1 }[a.severity]
  );

const lines = [
  '## 🛡️ Security Audit Summary',
  '',
  `**Target:** \`${report.targetUrl ?? 'unknown'}\``,
  `**Generated:** ${report.generatedAt ?? 'unknown'}`,
  `**Total findings:** ${findings.length}`,
  '',
  '| Severity | Count |',
  '| --- | ---: |',
  `| ${icon.Critical} Critical | ${counts.Critical} |`,
  `| ${icon.High} High | ${counts.High} |`,
  `| ${icon.Medium} Medium | ${counts.Medium} |`,
  `| ${icon.Low} Low | ${counts.Low} |`,
  `| ${icon.Info} Info | ${counts.Info} |`,
  ''
];

if (notable.length > 0) {
  lines.push('### Notable findings (non-informational)', '');
  lines.push('| ID | Severity | Category | Title |');
  lines.push('| --- | --- | --- | --- |');
  for (const finding of notable.slice(0, 25)) {
    lines.push(
      `| \`${finding.id}\` | ${icon[finding.severity] ?? ''} ${finding.severity} | ${finding.category} | ${finding.title} |`
    );
  }
  lines.push('');
} else {
  lines.push('_No non-informational findings recorded in this run._', '');
}

lines.push(
  '> The target is an intentionally vulnerable OWASP Juice Shop lab, so findings are expected. ' +
    'This pipeline is report-only by default (`FAIL_ON=off`).'
);

emit(`${lines.join('\n')}\n`);

function emit(text) {
  const summaryFile = process.env.GITHUB_STEP_SUMMARY;
  if (summaryFile) {
    fs.appendFileSync(summaryFile, text);
  }
  process.stdout.write(text);
}

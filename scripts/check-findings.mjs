#!/usr/bin/env node
/**
 * Severity gate for the security audit.
 *
 * Reads the findings produced by the audit and, when configured, exits non-zero
 * if any finding meets or exceeds a threshold severity. This lets the same tool
 * stay report-only against an intentionally vulnerable lab (the default) while
 * also being able to *block* a real CI/CD pipeline on regressions.
 *
 * Usage:
 *   node scripts/check-findings.mjs                # report-only (default)
 *   FAIL_ON=High node scripts/check-findings.mjs   # exit 1 on High or Critical
 *
 * Env:
 *   FAIL_ON      One of: off | Info | Low | Medium | High | Critical (default: off)
 *   REPORTS_DIR  Directory containing findings.json (default: reports)
 */

import fs from 'node:fs';
import path from 'node:path';

const SEVERITY_ORDER = { Info: 1, Low: 2, Medium: 3, High: 4, Critical: 5 };

const reportsDir = path.resolve(process.env.REPORTS_DIR ?? 'reports');
const findingsPath = path.join(reportsDir, 'findings.json');
const failOn = (process.env.FAIL_ON ?? 'off').trim();

function fail(message) {
  console.error(`[check-findings] ${message}`);
  process.exit(1);
}

if (!fs.existsSync(findingsPath)) {
  fail(`No findings file at ${findingsPath}. Run the audit first.`);
}

/** @type {{ findings: Array<{ id: string, title: string, severity: keyof typeof SEVERITY_ORDER }> }} */
const report = JSON.parse(fs.readFileSync(findingsPath, 'utf8'));
const findings = Array.isArray(report.findings) ? report.findings : [];

const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
for (const finding of findings) {
  if (finding.severity in counts) {
    counts[finding.severity] += 1;
  }
}

const summary = `Findings — Critical: ${counts.Critical}, High: ${counts.High}, Medium: ${counts.Medium}, Low: ${counts.Low}, Info: ${counts.Info}`;
console.log(`[check-findings] ${summary}`);

if (failOn === 'off' || failOn === '') {
  console.log('[check-findings] FAIL_ON is off — reporting only, not gating the build.');
  process.exit(0);
}

const threshold = SEVERITY_ORDER[failOn];
if (!threshold) {
  fail(`Invalid FAIL_ON value "${failOn}". Use one of: off, Info, Low, Medium, High, Critical.`);
}

const offending = findings.filter((finding) => (SEVERITY_ORDER[finding.severity] ?? 0) >= threshold);

if (offending.length > 0) {
  console.error(`[check-findings] ${offending.length} finding(s) at or above "${failOn}":`);
  for (const finding of offending) {
    console.error(`  - [${finding.severity}] ${finding.id}: ${finding.title}`);
  }
  process.exit(1);
}

console.log(`[check-findings] No findings at or above "${failOn}". Gate passed.`);
process.exit(0);

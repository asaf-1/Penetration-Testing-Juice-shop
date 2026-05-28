import fs from 'node:fs';
import path from 'node:path';
import type { Reporter, TestCase, TestResult, FullResult } from '@playwright/test/reporter';
import { loadAuditConfig } from '../config';
import { countBySeverity, deduplicateFindings, sortFindings, type Finding } from '../findings';
import { toSarif } from '../sarif';

export default class SecurityReporter implements Reporter {
  private findings: Finding[] = [];
  private generatedAt = new Date().toISOString();

  onTestEnd(test: TestCase, result: TestResult): void {
    for (const attachment of result.attachments) {
      if (attachment.name === 'security-finding' && attachment.body) {
        try {
          const finding = JSON.parse(attachment.body.toString('utf8')) as Finding;
          this.findings.push(finding);
        } catch (error) {
          console.error(
            `[SecurityReporter] Failed to parse security-finding attachment in test "${test.title}":`,
            error
          );
        }
      }
    }
  }

  async onEnd(_result: FullResult): Promise<void> {
    const config = loadAuditConfig();
    const reportsDir = config.reportsDir;
    const targetUrl = config.targetUrl;

    fs.mkdirSync(reportsDir, { recursive: true });

    // Deduplicate (merging evidence) and sort by severity then id.
    const sortedFindings = sortFindings(deduplicateFindings(this.findings));

    const payload = {
      targetUrl,
      generatedAt: this.generatedAt,
      findingCount: sortedFindings.length,
      findings: sortedFindings
    };

    // 1. Write findings.json
    fs.writeFileSync(path.join(reportsDir, 'findings.json'), `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    console.log(`[SecurityReporter] Wrote raw findings to ${path.join(reportsDir, 'findings.json')}`);

    // 2. Write security-report.md
    fs.writeFileSync(
      path.join(reportsDir, 'security-report.md'),
      this.toMarkdown(sortedFindings, targetUrl),
      'utf8'
    );
    console.log(`[SecurityReporter] Wrote markdown report to ${path.join(reportsDir, 'security-report.md')}`);

    // 3. Write security-report.html (Interactive Dashboard)
    fs.writeFileSync(
      path.join(reportsDir, 'security-report.html'),
      this.toHtml(sortedFindings, targetUrl),
      'utf8'
    );
    console.log(
      `[SecurityReporter] Wrote custom HTML dashboard to ${path.join(reportsDir, 'security-report.html')}`
    );

    // 4. Write SARIF 2.1.0 for GitHub code scanning (Security tab).
    fs.writeFileSync(
      path.join(reportsDir, 'security-report.sarif'),
      `${JSON.stringify(toSarif(sortedFindings, targetUrl), null, 2)}\n`,
      'utf8'
    );
    console.log(`[SecurityReporter] Wrote SARIF report to ${path.join(reportsDir, 'security-report.sarif')}`);
  }

  private toMarkdown(findings: Finding[], targetUrl: string): string {
    const summary = countBySeverity(findings);
    const lines = [
      '# Playwright Security Automation Report',
      '',
      `**Target:** ${targetUrl}`,
      `**Generated:** ${this.generatedAt}`,
      '',
      'Scope: Non-destructive browser and HTTP automation against an intentionally vulnerable lab target.',
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
      lines.push(`- **Severity:** ${finding.severity}`);
      lines.push(`- **Status:** ${finding.status}`);
      lines.push(`- **Category:** ${finding.category}`);
      lines.push('');
      lines.push(`**Description:** ${finding.description}`);
      lines.push('');
      lines.push(`**Impact:** ${finding.impact}`);
      lines.push('');
      lines.push('**Evidence:**');
      for (const evidence of finding.evidence) {
        const detail = evidence.details ? ` - ${evidence.details}` : '';
        const evidencePath = evidence.path ? ` ([artifact](${evidence.path}))` : '';
        lines.push(`- ${evidence.label}${detail}${evidencePath}`);
      }
      lines.push('');
      lines.push(`**Remediation:** ${finding.remediation}`);

      if (finding.references?.length) {
        lines.push('');
        lines.push('**References:**');
        for (const reference of finding.references) {
          lines.push(`- [${reference}](${reference})`);
        }
      }

      lines.push('');
      lines.push('---');
      lines.push('');
    }

    return `${lines.join('\n')}\n`;
  }

  private toHtml(findings: Finding[], targetUrl: string): string {
    const summary = countBySeverity(findings);
    const findingsJson = JSON.stringify(findings);
    const parts = this.generatedAt.split('T');
    const datePart = parts[0] ?? '';
    const timePart = parts[1] ? parts[1].slice(0, 5) : '';

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Audit Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-dark: #0f172a;
      --bg-card: #1e293b;
      --border-color: #334155;
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      
      --accent: #6366f1;
      --accent-hover: #4f46e5;
      
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --info: #10b981;
    }

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      font-family: 'Outfit', sans-serif;
      background-color: var(--bg-dark);
      color: var(--text-main);
      line-height: 1.5;
      overflow-x: hidden;
      padding: 2rem;
    }

    header {
      margin-bottom: 2rem;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: flex-end;
      flex-wrap: wrap;
      gap: 1rem;
    }

    .brand h1 {
      font-size: 2.25rem;
      font-weight: 700;
      letter-spacing: -0.025em;
      background: linear-gradient(to right, #818cf8, #a78bfa, #f472b6);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      margin-bottom: 0.25rem;
    }

    .brand p {
      color: var(--text-muted);
      font-size: 0.95rem;
    }

    .meta-details {
      text-align: right;
      font-size: 0.9rem;
      color: var(--text-muted);
    }

    .meta-details strong {
      color: var(--text-main);
    }

    /* Summary Stats Grid */
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }

    .stat-card {
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 1.25rem;
      text-align: center;
      transition: transform 0.2s ease, border-color 0.2s ease;
      cursor: pointer;
      position: relative;
      overflow: hidden;
    }

    .stat-card:hover {
      transform: translateY(-2px);
      border-color: var(--accent);
    }

    .stat-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 4px;
    }

    .stat-card.critical::before { background-color: var(--critical); }
    .stat-card.high::before { background-color: var(--high); }
    .stat-card.medium::before { background-color: var(--medium); }
    .stat-card.low::before { background-color: var(--low); }
    .stat-card.info::before { background-color: var(--info); }
    .stat-card.total::before { background-color: var(--accent); }

    .stat-val {
      font-size: 2.25rem;
      font-weight: 700;
      margin-bottom: 0.25rem;
    }

    .stat-label {
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-muted);
      font-weight: 600;
    }

    /* Layout Containers */
    .container {
      display: grid;
      grid-template-columns: 320px 1fr;
      gap: 2rem;
      align-items: start;
    }

    @media (max-width: 900px) {
      .container {
        grid-template-columns: 1fr;
      }
    }

    /* Left Sidebar: Finding List */
    .sidebar {
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 1.25rem;
      max-height: 70vh;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }

    .sidebar h2 {
      font-size: 1.1rem;
      font-weight: 600;
      margin-bottom: 0.25rem;
      color: var(--text-main);
    }

    .sidebar-controls {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 0.5rem;
    }

    .filter-btn {
      flex: 1;
      background: #0f172a;
      border: 1px solid var(--border-color);
      color: var(--text-muted);
      font-size: 0.75rem;
      padding: 0.35rem;
      border-radius: 6px;
      cursor: pointer;
      font-family: inherit;
      font-weight: 500;
      transition: all 0.2s ease;
    }

    .filter-btn.active, .filter-btn:hover {
      background: var(--accent);
      color: var(--text-main);
      border-color: var(--accent);
    }

    .finding-item {
      padding: 1rem;
      border-radius: 10px;
      border: 1px solid transparent;
      background-color: #0f172a;
      cursor: pointer;
      transition: all 0.2s ease;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }

    .finding-item:hover {
      background-color: #1e293b;
      border-color: #475569;
    }

    .finding-item.active {
      background-color: #1e1b4b;
      border-color: var(--accent);
    }

    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.5rem;
    }

    .finding-title {
      font-weight: 600;
      font-size: 0.9rem;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    .badge {
      font-size: 0.7rem;
      font-weight: 700;
      text-transform: uppercase;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      letter-spacing: 0.025em;
    }

    .badge.critical { background-color: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge.high { background-color: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }
    .badge.medium { background-color: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }
    .badge.low { background-color: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
    .badge.info { background-color: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }

    .finding-sub {
      display: flex;
      justify-content: space-between;
      color: var(--text-muted);
      font-size: 0.75rem;
    }

    /* Right Main Panel: Detailed View */
    .detail-view {
      background-color: var(--bg-card);
      border: 1px solid var(--border-color);
      border-radius: 16px;
      padding: 2rem;
      min-height: 60vh;
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }

    .empty-state {
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      color: var(--text-muted);
      height: 100%;
      text-align: center;
      gap: 1rem;
      margin-top: 5rem;
    }

    .empty-state svg {
      width: 48px;
      height: 48px;
      stroke: var(--text-muted);
      opacity: 0.5;
    }

    .section-title {
      font-size: 0.85rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      border-bottom: 1px solid var(--border-color);
      padding-bottom: 0.5rem;
      margin-bottom: 0.5rem;
    }

    .detail-title-row {
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 1rem;
      flex-wrap: wrap;
    }

    .detail-title-group h2 {
      font-size: 1.6rem;
      font-weight: 700;
      letter-spacing: -0.02em;
    }

    .detail-meta {
      display: flex;
      gap: 1rem;
      color: var(--text-muted);
      font-size: 0.85rem;
      margin-top: 0.25rem;
    }

    .detail-meta span strong {
      color: var(--text-main);
    }

    .detail-badges {
      display: flex;
      gap: 0.5rem;
    }

    .finding-block {
      background-color: rgba(15, 23, 42, 0.4);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 1.25rem;
    }

    .finding-block p {
      font-size: 0.95rem;
      color: #cbd5e1;
    }

    /* Evidence List */
    .evidence-list {
      display: flex;
      flex-direction: column;
      gap: 0.75rem;
    }

    .evidence-item {
      background: #0f172a;
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 0.75rem 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.5rem;
    }

    .evidence-label {
      font-weight: 600;
      font-size: 0.85rem;
      color: var(--text-main);
    }

    .evidence-detail {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8rem;
      background: #1e293b;
      padding: 0.5rem 0.75rem;
      border-radius: 6px;
      border: 1px solid #334155;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
      color: #38bdf8;
    }

    .evidence-screenshot-link {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      color: var(--accent);
      text-decoration: none;
      font-size: 0.85rem;
      font-weight: 600;
      transition: color 0.2s ease;
      cursor: pointer;
      margin-top: 0.25rem;
    }

    .evidence-screenshot-link:hover {
      color: var(--text-main);
    }

    .references-list {
      list-style-position: inside;
      padding-left: 0.5rem;
      font-size: 0.9rem;
    }

    .references-list li {
      margin-bottom: 0.35rem;
    }

    .references-list a {
      color: var(--accent);
      text-decoration: none;
    }

    .references-list a:hover {
      text-decoration: underline;
    }

    /* Screenshot Overlay Modal */
    .modal {
      display: none;
      position: fixed;
      z-index: 1000;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(15, 23, 42, 0.9);
      backdrop-filter: blur(8px);
      justify-content: center;
      align-items: center;
      padding: 2rem;
    }

    .modal.active {
      display: flex;
    }

    .modal-content {
      position: relative;
      max-width: 90%;
      max-height: 90%;
      border-radius: 12px;
      border: 1px solid var(--border-color);
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      background-color: var(--bg-card);
      padding: 0.5rem;
    }

    .modal-img {
      max-width: 100%;
      max-height: 80vh;
      display: block;
      border-radius: 8px;
    }

    .modal-close {
      position: absolute;
      top: -1.5rem;
      right: 0;
      color: var(--text-main);
      font-size: 1.5rem;
      cursor: pointer;
      font-weight: 700;
    }

    /* Print Styles Optimization */
    @media print {
      body {
        background-color: #fff;
        color: #000;
        padding: 0;
      }
      header, .summary-grid, .sidebar, .sidebar-controls, .filter-btn, .modal, .evidence-screenshot-link {
        display: none !important;
      }
      .container {
        grid-template-columns: 1fr;
      }
      .detail-view {
        border: none;
        padding: 0;
        background: none;
      }
      .finding-block, .evidence-item, .evidence-detail {
        background: #f8fafc !important;
        color: #0f172a !important;
        border: 1px solid #cbd5e1 !important;
      }
      .badge {
        border: 1px solid #000 !important;
        color: #000 !important;
        background: none !important;
      }
      .section-title {
        border-bottom-color: #000;
      }
      h1, h2, h3 {
        color: #000 !important;
        background: none !important;
        -webkit-text-fill-color: initial !important;
      }
      .detail-view {
        page-break-after: always;
      }
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <h1>Security Automation Lab Report</h1>
      <p>Continuous validation and threat boundary audits</p>
    </div>
    <div class="meta-details">
      <div>Target Scope: <strong>${targetUrl}</strong></div>
      <div>Audit Run: <strong>${datePart} ${timePart} UTC</strong></div>
    </div>
  </header>

  <div class="summary-grid">
    <div class="stat-card total" onclick="filterFindings('all')">
      <div class="stat-val">${findings.length}</div>
      <div class="stat-label">Total Findings</div>
    </div>
    <div class="stat-card critical" onclick="filterFindings('Critical')">
      <div class="stat-val" style="color: var(--critical);">${summary.Critical}</div>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat-card high" onclick="filterFindings('High')">
      <div class="stat-val" style="color: var(--high);">${summary.High}</div>
      <div class="stat-label">High</div>
    </div>
    <div class="stat-card medium" onclick="filterFindings('Medium')">
      <div class="stat-val" style="color: var(--medium);">${summary.Medium}</div>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat-card low" onclick="filterFindings('Low')">
      <div class="stat-val" style="color: var(--low);">${summary.Low}</div>
      <div class="stat-label">Low</div>
    </div>
    <div class="stat-card info" onclick="filterFindings('Info')">
      <div class="stat-val" style="color: var(--info);">${summary.Info}</div>
      <div class="stat-label">Info</div>
    </div>
  </div>

  <div class="container">
    <!-- Left: Finding List -->
    <div class="sidebar">
      <h2>Audited Targets</h2>
      <div class="sidebar-controls">
        <button class="filter-btn active" id="btn-all" onclick="filterFindings('all')">All</button>
        <button class="filter-btn" id="btn-vuln" onclick="filterFindings('vuln')">Issues</button>
        <button class="filter-btn" id="btn-info" onclick="filterFindings('Info')">Info</button>
      </div>
      <div id="findings-list-container">
        <!-- JS populated -->
      </div>
    </div>

    <!-- Right: Detailed Description -->
    <div class="detail-view" id="finding-details-pane">
      <div class="empty-state">
        <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <h3>Select a finding from the sidebar to inspect its security details, impact assessments, evidence logs, and remediation pathways.</h3>
      </div>
    </div>
  </div>

  <!-- Screenshot Modal -->
  <div class="modal" id="screenshot-modal" onclick="closeModal()">
    <div class="modal-content" onclick="event.stopPropagation()">
      <span class="modal-close" onclick="closeModal()">&times;</span>
      <img src="" alt="Evidence Screenshot" class="modal-img" id="modal-image">
    </div>
  </div>

  <script>
    const findings = ${findingsJson};
    let currentFilter = 'all';

    function renderList() {
      const container = document.getElementById('findings-list-container');
      container.innerHTML = '';

      const filtered = findings.filter(f => {
        if (currentFilter === 'all') return true;
        if (currentFilter === 'vuln') return f.severity !== 'Info';
        return f.severity === currentFilter;
      });

      if (filtered.length === 0) {
        container.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem; text-align: center; padding: 1rem;">No findings found</div>';
        return;
      }

      filtered.forEach(f => {
        const item = document.createElement('div');
        item.className = 'finding-item';
        item.id = 'item-' + f.id;
        item.onclick = () => selectFinding(f.id);

        const sevClass = f.severity.toLowerCase();

        item.innerHTML = \`
          <div class="finding-header">
            <span class="finding-title" title="\${f.title}">\${f.title}</span>
            <span class="badge \${sevClass}">\${f.severity}</span>
          </div>
          <div class="finding-sub">
            <span>\${f.id}</span>
            <span>\${f.category}</span>
          </div>
        \`;
        container.appendChild(item);
      });
    }

    function filterFindings(filter) {
      currentFilter = filter;
      
      // Update filter button styles
      document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
      if (filter === 'all') document.getElementById('btn-all').classList.add('active');
      else if (filter === 'vuln') document.getElementById('btn-vuln').classList.add('active');
      else if (filter === 'Info') document.getElementById('btn-info').classList.add('active');

      renderList();
      
      // Auto-select first in filtered list if available
      const filtered = findings.filter(f => {
        if (filter === 'all') return true;
        if (filter === 'vuln') return f.severity !== 'Info';
        return f.severity === filter;
      });
      if (filtered.length > 0) {
        selectFinding(filtered[0].id);
      } else {
        showEmptyState();
      }
    }

    function showEmptyState() {
      document.getElementById('finding-details-pane').innerHTML = \`
        <div class="empty-state">
          <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h3>No findings match the current filter selection.</h3>
        </div>
      \`;
    }

    function selectFinding(id) {
      document.querySelectorAll('.finding-item').forEach(item => item.classList.remove('active'));
      const activeItem = document.getElementById('item-' + id);
      if (activeItem) activeItem.classList.add('active');

      const finding = findings.find(f => f.id === id);
      if (!finding) return;

      const pane = document.getElementById('finding-details-pane');
      const sevClass = finding.severity.toLowerCase();

      let evidenceHtml = '';
      finding.evidence.forEach(ev => {
        let detailsHtml = '';
        if (ev.details) {
          detailsHtml = \`<pre class="evidence-detail">\${escapeHtml(ev.details)}</pre>\`;
        }
        
        let screenshotHtml = '';
        if (ev.path) {
          screenshotHtml = \`
            <span class="evidence-screenshot-link" onclick="openModal('\${ev.path}')">
              <svg style="width:16px;height:16px;stroke:currentColor;fill:none" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
              </svg>
              View Screenshot Evidence
            </span>
          \`;
        }

        evidenceHtml += \`
          <div class="evidence-item">
            <div class="evidence-label">\${escapeHtml(ev.label)}</div>
            \${detailsHtml}
            \${screenshotHtml}
          </div>
        \`;
      });

      let refsHtml = '';
      if (finding.references && finding.references.length > 0) {
        let listItems = '';
        finding.references.forEach(ref => {
          listItems += \`<li><a href="\${ref}" target="_blank">\${escapeHtml(ref)}</a></li>\`;
        });
        refsHtml = \`
          <div>
            <div class="section-title">References</div>
            <ul class="references-list">\${listItems}</ul>
          </div>
        \`;
      }

      pane.innerHTML = \`
        <div class="detail-title-row">
          <div class="detail-title-group">
            <h2>\${escapeHtml(finding.title)}</h2>
            <div class="detail-meta">
              <span>Finding ID: <strong>\${finding.id}</strong></span>
              <span>Category: <strong>\${finding.category}</strong></span>
            </div>
          </div>
          <div class="detail-badges">
            <span class="badge \${sevClass}">\${finding.severity}</span>
            <span class="badge" style="background:#475569; color:#cbd5e1">\${finding.status}</span>
          </div>
        </div>

        <div>
          <div class="section-title">Description</div>
          <div class="finding-block">
            <p>\${escapeHtml(finding.description)}</p>
          </div>
        </div>

        <div>
          <div class="section-title">Impact Assessment</div>
          <div class="finding-block">
            <p>\${escapeHtml(finding.impact)}</p>
          </div>
        </div>

        <div>
          <div class="section-title">Collected Evidence</div>
          <div class="evidence-list">
            \${evidenceHtml}
          </div>
        </div>

        <div>
          <div class="section-title">Remediation Action Plan</div>
          <div class="finding-block" style="border-left: 4px solid var(--info);">
            <p>\${escapeHtml(finding.remediation)}</p>
          </div>
        </div>

        \${refsHtml}
      \`;
    }

    function escapeHtml(text) {
      if (!text) return '';
      return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

    function openModal(path) {
      const modal = document.getElementById('screenshot-modal');
      const img = document.getElementById('modal-image');
      img.src = path;
      modal.classList.add('active');
    }

    function closeModal() {
      document.getElementById('screenshot-modal').classList.remove('active');
    }

    // Escape listener for modal
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeModal();
    });

    // Init page
    renderList();
    if (findings.length > 0) {
      selectFinding(findings[0].id);
    }
  </script>
</body>
</html>`;
  }
}

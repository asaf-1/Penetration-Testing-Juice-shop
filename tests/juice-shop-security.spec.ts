import fs from 'node:fs';
import path from 'node:path';
import { test, type APIRequestContext, type APIResponse, type Page } from '@playwright/test';
import { AuditReport, cleanFileName, type Evidence } from '../src/audit-report';
import { loadAuditConfig } from '../src/config';
import {
  closeJuiceShopOverlays,
  hashRouteUrl,
  sanitizeDetail,
  textPreview,
  tryClick,
  tryFill
} from '../src/juice-shop-helpers';
import {
  cookieFindings,
  corsFinding,
  headerRules,
  missingHeaderFinding,
  sensitivePathChecks,
  unauthenticatedApiChecks,
  unauthenticatedRoutes
} from '../src/security-rules';

const config = loadAuditConfig();
const targetUrl = config.targetUrl;
const reportsDir = config.reportsDir;
const evidenceDir = config.evidenceDir;
const audit = new AuditReport(targetUrl, reportsDir);
let targetReachable = false;
let targetStatus: number | null = null;
let targetHeaders: Record<string, string> = {};
let targetError: string | null = null;

test.describe.serial('authorized lab security automation', () => {
  test.beforeAll(async ({ request }) => {
    clearDirectoryContents(reportsDir);
    fs.mkdirSync(evidenceDir, { recursive: true });

    try {
      const response = await waitForTarget(request, targetUrl);
      targetStatus = response.status();
      targetHeaders = response.headers();
      targetReachable = response.status() < 400;

      if (!targetReachable) { 
        audit.add({
          id: 'TARGET-001',
          title: 'Target was not reachable for active checks',
          severity: 'High',
          category: 'Execution',
          status: 'observed',
          description: 'The configured target returned a non-success status before browser checks could run.',
          impact: 'The audit could not exercise the application. Findings from this run are limited to availability.',
          remediation:
            'Start a local OWASP Juice Shop instance or set TARGET_URL to a reachable authorized lab target, then rerun the audit.',
          evidence: [
            { label: 'Target URL', details: targetUrl },
            { label: 'HTTP status', details: String(response.status()) },
            { label: 'Response preview', details: textPreview(await response.text().catch(() => '')) }
          ]
        });
      }
    } catch (error) {
      targetError = sanitizeDetail(error instanceof Error ? error.message : String(error));
      audit.add({
        id: 'TARGET-001',
        title: 'Target connection failed before active checks',
        severity: 'High',
        category: 'Execution',
        status: 'observed',
        description: 'Playwright could not connect to the configured target URL.',
        impact: 'The audit could not exercise the application. Findings from this run are limited to connectivity.',
        remediation:
          'Start a local OWASP Juice Shop instance or set TARGET_URL to a reachable authorized lab target, then rerun the audit.',
        evidence: [
          { label: 'Target URL', details: targetUrl },
          { label: 'Connection error', details: targetError }
        ]
      });
    }
  });

  test.afterAll(() => {
    audit.write();
  });

  test('recon and response header audit', async ({ page }) => {
    test.skip(!targetReachable, unavailableReason());

    await page.goto(targetUrl, { waitUntil: 'domcontentloaded' });
    await closeJuiceShopOverlays(page);
    await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => undefined);

    const homepageEvidence = await screenshotEvidence(page, '01-homepage');
    audit.add({
      id: 'RECON-001',
      title: 'Target reachable and browser evidence captured',
      severity: 'Info',
      category: 'Reconnaissance',
      status: 'observed',
      description: 'The target loaded successfully in Chromium and a homepage screenshot was captured for the report.',
      impact: 'This confirms that the automation can reach the scoped lab target and collect repeatable evidence.',
      remediation: 'No remediation required for the lab report.',
      evidence: [
        { label: 'HTTP status', details: String(targetStatus) },
        { label: 'Page title', details: await page.title() },
        homepageEvidence
      ]
    });

    const headers = targetHeaders;
    for (const rule of headerRules) {
      const finding = missingHeaderFinding(headers, rule, targetUrl);
      if (finding) {
        audit.add(finding);
      }
    }

    const cors = corsFinding(headers);
    if (cors) {
      audit.add(cors);
    }

    const serverHeader = headers.server;
    if (serverHeader) {
      audit.add({
        id: 'HDR-005',
        title: 'Server banner is exposed',
        severity: 'Info',
        category: 'Header Hardening',
        status: 'observed',
        description: 'The HTTP response includes a Server header.',
        impact: 'Technology hints can help attackers tune follow-up research and payloads.',
        remediation: 'Minimize or normalize server banner details at the reverse proxy or application server.',
        evidence: [{ label: 'Server header', details: serverHeader }]
      });
    }

    const cacheControl = headers['cache-control'];
    if (!cacheControl || !/no-store|no-cache|private/i.test(cacheControl)) {
      audit.add({
        id: 'HDR-008',
        title: 'Homepage cache policy should be reviewed',
        severity: 'Info',
        category: 'Header Hardening',
        status: 'manual-review',
        description: 'The initial response did not include a clearly restrictive cache-control policy.',
        impact: 'Sensitive pages can be stored by browsers or intermediary caches if cache policy is too broad.',
        remediation: 'Use no-store for sensitive authenticated pages and explicit cache lifetimes for public assets.',
        evidence: [{ label: 'Cache-Control', details: cacheControl ?? 'missing' }]
      });
    }
  });

  test('client-side surface inventory', async ({ page }) => {
    test.skip(!targetReachable, unavailableReason());

    const observedRequests = new Set<string>();
    page.on('request', (request) => {
      const resourceType = request.resourceType();
      if (['xhr', 'fetch', 'document', 'script'].includes(resourceType)) {
        observedRequests.add(`${resourceType.toUpperCase()} ${request.url()}`);
      }
    });

    await page.goto(targetUrl, { waitUntil: 'domcontentloaded' });
    await closeJuiceShopOverlays(page);
    await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => undefined);

    const inventory = await page.evaluate(() => {
      return {
        title: document.title,
        scriptSources: Array.from(document.scripts)
          .map((script) => script.src)
          .filter(Boolean)
          .slice(0, 20),
        localStorageKeys: Object.keys(localStorage).sort(),
        sessionStorageKeys: Object.keys(sessionStorage).sort(),
        linkHrefs: Array.from(document.querySelectorAll('a[href]'))
          .map((link) => (link as HTMLAnchorElement).href)
          .filter(Boolean)
          .slice(0, 20)
      };
    });

    audit.add({
      id: 'RECON-002',
      title: 'Client-side application inventory captured',
      severity: 'Info',
      category: 'Reconnaissance',
      status: 'observed',
      description: 'The browser collected page title, script references, storage keys, and visible links.',
      impact: 'Client-side inventory helps focus manual review on exposed routes, bundled scripts, and browser storage.',
      remediation: 'No remediation required for the lab report. In production, avoid storing secrets in browser storage.',
      evidence: [
        { label: 'Title', details: inventory.title },
        { label: 'Script count sampled', details: String(inventory.scriptSources.length) },
        { label: 'Local storage keys', details: inventory.localStorageKeys.join(', ') || 'none observed' },
        { label: 'Session storage keys', details: inventory.sessionStorageKeys.join(', ') || 'none observed' },
        { label: 'Observed browser requests', details: Array.from(observedRequests).slice(0, 15).join(' | ') }
      ]
    });
  });

  test('cookie and browser storage hygiene checks', async ({ page, context }) => {
    test.skip(!targetReachable, unavailableReason());

    await page.goto(targetUrl, { waitUntil: 'domcontentloaded' });
    await closeJuiceShopOverlays(page);
    await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => undefined);

    for (const finding of await cookieFindings(context, targetUrl)) {
      audit.add(finding);
    }
  });

  test('browser form and external link hygiene checks', async ({ page }) => {
    test.skip(!targetReachable, unavailableReason());

    await page.goto(targetUrl, { waitUntil: 'domcontentloaded' });
    await closeJuiceShopOverlays(page);
    await page.goto(hashRouteUrl(targetUrl, '/login'), { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(1_000);

    const hygiene = await page.evaluate(() => {
      const passwordInputs = Array.from(document.querySelectorAll('input[type="password"]')).map((input) => {
        const element = input as HTMLInputElement;
        return {
          id: element.id,
          name: element.name,
          autocomplete: element.getAttribute('autocomplete') ?? ''
        };
      });
      const blankLinks = Array.from(document.querySelectorAll('a[target="_blank"]')).map((link) => {
        const element = link as HTMLAnchorElement;
        return {
          href: element.href,
          rel: element.rel
        };
      });
      const forms = Array.from(document.forms).map((form) => {
        return {
          id: form.id,
          method: form.method,
          autocomplete: form.getAttribute('autocomplete') ?? ''
        };
      });

      return { passwordInputs, blankLinks, forms };
    });

    const passwordInputsWithoutAutocomplete = hygiene.passwordInputs.filter((input) => !input.autocomplete);
    const blankLinksWithoutNoopener = hygiene.blankLinks.filter((link) => !/\bnoopener\b/i.test(link.rel));

    audit.add({
      id: 'BR-001',
      title:
        passwordInputsWithoutAutocomplete.length > 0
          ? 'Password fields missing explicit autocomplete policy'
          : 'Password field autocomplete policy reviewed',
      severity: passwordInputsWithoutAutocomplete.length > 0 ? 'Low' : 'Info',
      category: 'Browser Hygiene',
      status: passwordInputsWithoutAutocomplete.length > 0 ? 'manual-review' : 'not-observed',
      description: 'The login view was inspected for password input autocomplete attributes.',
      impact:
        'Explicit autocomplete values help browsers and password managers handle login fields predictably and reduce accidental credential handling issues.',
      remediation: 'Set appropriate autocomplete values such as current-password or new-password on password inputs.',
      evidence: [
        { label: 'Password input count', details: String(hygiene.passwordInputs.length) },
        {
          label: 'Missing autocomplete',
          details: passwordInputsWithoutAutocomplete.map((input) => input.id || input.name || 'unnamed').join(', ') || 'none observed'
        }
      ]
    });

    audit.add({
      id: 'BR-002',
      title:
        blankLinksWithoutNoopener.length > 0
          ? 'External new-tab links missing noopener'
          : 'External new-tab link rel policy reviewed',
      severity: blankLinksWithoutNoopener.length > 0 ? 'Low' : 'Info',
      category: 'Browser Hygiene',
      status: blankLinksWithoutNoopener.length > 0 ? 'observed' : 'not-observed',
      description: 'Links that open new tabs were checked for rel=noopener.',
      impact: 'New-tab links without noopener can allow the opened page to manipulate the original page through window.opener.',
      remediation: 'Add rel="noopener noreferrer" to links that use target="_blank".',
      evidence: [
        { label: 'New-tab link count', details: String(hygiene.blankLinks.length) },
        {
          label: 'Missing noopener',
          details: blankLinksWithoutNoopener.map((link) => link.href).slice(0, 10).join(', ') || 'none observed'
        }
      ]
    });
  });

  test('static asset and source map exposure checks', async ({ page, request }) => {
    test.skip(!targetReachable, unavailableReason());

    await page.goto(targetUrl, { waitUntil: 'domcontentloaded' });
    await closeJuiceShopOverlays(page);

    const scriptUrls = await page.evaluate(() => {
      return Array.from(document.scripts)
        .map((script) => script.src)
        .filter((source) => source.endsWith('.js'))
        .slice(0, 10);
    });
    const sourceMapCandidates: string[] = [];
    const exposedSourceMaps: string[] = [];
    const bundleSecretHints: string[] = [];
    const sampledScripts: string[] = [];

    for (const scriptUrl of scriptUrls) {
      const scriptResponse = await request.get(scriptUrl, { failOnStatusCode: false, timeout: 10_000 });
      sampledScripts.push(urlPath(scriptUrl));

      if (!scriptResponse.ok()) {
        continue;
      }

      const scriptBody = await scriptResponse.text();
      const sourceMappingUrl = scriptBody.match(/\/\/# sourceMappingURL=(.+)\s*$/m)?.[1]?.trim();
      const candidates = new Set<string>([`${scriptUrl}.map`]);
      if (sourceMappingUrl) {
        candidates.add(new URL(sourceMappingUrl, scriptUrl).toString());
      }

      if (/(api[_-]?key|private[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]/i.test(scriptBody)) {
        bundleSecretHints.push(urlPath(scriptUrl));
      }

      for (const candidate of candidates) {
        sourceMapCandidates.push(urlPath(candidate));
        const mapResponse = await request.get(candidate, { failOnStatusCode: false, timeout: 8_000 });
        if (!mapResponse.ok()) {
          continue;
        }

        const mapBody = await mapResponse.text();
        if (/"sources"\s*:|"mappings"\s*:/i.test(mapBody)) {
          exposedSourceMaps.push(urlPath(candidate));
        }
      }
    }

    audit.add({
      id: 'CLT-001',
      title: exposedSourceMaps.length > 0 ? 'Client source maps are publicly reachable' : 'Client source map exposure not observed',
      severity: exposedSourceMaps.length > 0 ? 'Low' : 'Info',
      category: 'Client-Side Exposure',
      status: exposedSourceMaps.length > 0 ? 'manual-review' : 'not-observed',
      description: 'JavaScript bundles were sampled for sourceMappingURL references and common .map endpoints.',
      impact:
        'Public source maps can reveal original source structure, comments, hidden routes, and implementation details that help attackers.',
      remediation: 'Do not publish production source maps publicly, or restrict access to authorized debugging environments.',
      evidence: [
        { label: 'Sampled scripts', details: sampledScripts.join(', ') || 'none observed' },
        { label: 'Source map candidates', details: sourceMapCandidates.slice(0, 20).join(', ') || 'none observed' },
        { label: 'Reachable source maps', details: exposedSourceMaps.join(', ') || 'none observed' }
      ],
      references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/']
    });

    audit.add({
      id: 'CLT-002',
      title: bundleSecretHints.length > 0 ? 'Potential secret-like strings observed in client bundles' : 'Client bundle secret hint scan clean',
      severity: bundleSecretHints.length > 0 ? 'Medium' : 'Info',
      category: 'Client-Side Exposure',
      status: bundleSecretHints.length > 0 ? 'manual-review' : 'not-observed',
      description: 'Sampled JavaScript bundles were scanned for high-signal secret-like assignment patterns.',
      impact: 'Secrets embedded in browser-delivered code are exposed to every user of the application.',
      remediation: 'Keep secrets server-side and expose only short-lived, least-privilege public configuration where required.',
      evidence: [{ label: 'Bundles with secret-like hints', details: bundleSecretHints.join(', ') || 'none observed' }],
      references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/']
    });
  });

  test('public API and directory exposure checks', async ({ request }) => {
    test.skip(!targetReachable, unavailableReason());

    const productSearchUrl = new URL('/rest/products/search', targetUrl);
    productSearchUrl.searchParams.set('q', 'apple');
    const productResponse = await request.get(productSearchUrl.toString());

    if (productResponse.ok()) {
      const body = await productResponse.text();
      audit.add({
        id: 'API-001',
        title: 'Public product search API discovered',
        severity: 'Info',
        category: 'API Surface',
        status: 'observed',
        description: 'The product search endpoint is reachable without authentication.',
        impact: 'Public APIs should be reviewed for filtering, rate limits, and safe error handling.',
        remediation: 'Confirm the endpoint is intentionally public and enforce validation, pagination, and rate limits.',
        evidence: [
          { label: 'Endpoint', details: productSearchUrl.toString() },
          { label: 'Response preview', details: textPreview(body) }
        ]
      });
    }

    const ftpUrl = new URL('/ftp', targetUrl);
    const ftpResponse = await request.get(ftpUrl.toString());
    if (ftpResponse.ok()) {
      const body = await ftpResponse.text();
      const looksLikeListing = /acquisitions|legal|package|incident|quarantine/i.test(body);
      audit.add({
        id: 'API-002',
        title: looksLikeListing ? 'Exposed file listing endpoint is reachable' : 'FTP-style endpoint is reachable',
        severity: looksLikeListing ? 'Medium' : 'Low',
        category: 'Sensitive File Exposure',
        status: 'observed',
        description: 'The /ftp endpoint returned content to an unauthenticated request.',
        impact: 'Directory-style file exposure can disclose documents, backups, or metadata useful for later attacks.',
        remediation: 'Disable public directory listings and require authorization for downloadable files.',
        evidence: [
          { label: 'Endpoint', details: ftpUrl.toString() },
          { label: 'Response preview', details: textPreview(body) }
        ],
        references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/']
      });
    } else {
      audit.add({
        id: 'API-002',
        title: 'FTP-style endpoint was not publicly reachable',
        severity: 'Info',
        category: 'Sensitive File Exposure',
        status: 'not-observed',
        description: 'The /ftp endpoint did not return a successful response to an unauthenticated request.',
        impact: 'No unauthenticated file listing exposure was observed in this run.',
        remediation: 'No remediation required for this observation.',
        evidence: [
          { label: 'Endpoint', details: ftpUrl.toString() },
          { label: 'HTTP status', details: String(ftpResponse.status()) }
        ]
      });
    }

    const quoteProbeUrl = new URL('/rest/products/search', targetUrl);
    quoteProbeUrl.searchParams.set('q', "'");
    const quoteProbeResponse = await request.get(quoteProbeUrl.toString());
    const quoteProbeBody = await quoteProbeResponse.text();
    const errorLeakObserved =
      quoteProbeResponse.status() >= 500 || /sql|sqlite|sequelize|syntax|stack trace|exception/i.test(quoteProbeBody);

    audit.add({
      id: 'API-003',
      title: errorLeakObserved ? 'Search API returned error details to a quote probe' : 'Search API quote probe handled cleanly',
      severity: errorLeakObserved ? 'Medium' : 'Info',
      category: 'Input Handling',
      status: errorLeakObserved ? 'observed' : 'not-observed',
      description: 'A single harmless quote character was submitted to the public search endpoint.',
      impact: errorLeakObserved
        ? 'Verbose errors can reveal database or framework details and may indicate unsafe query construction.'
        : 'No verbose SQL or stack trace leakage was observed from this single probe.',
      remediation: errorLeakObserved
        ? 'Use parameterized queries, centralized validation, and generic production error responses.'
        : 'Keep centralized validation and generic error handling in place.',
      evidence: [
        { label: 'Endpoint', details: quoteProbeUrl.toString() },
        { label: 'HTTP status', details: String(quoteProbeResponse.status()) },
        { label: 'Response preview', details: textPreview(quoteProbeBody) }
      ],
      references: ['https://owasp.org/Top10/A03_2021-Injection/']
    });

    const exposedPaths: string[] = [];
    const publicMetadataPaths: string[] = [];
    const sampledStatuses: string[] = [];
    for (const check of sensitivePathChecks) {
      const url = new URL(check.path, targetUrl);
      const response = await request.get(url.toString(), {
        failOnStatusCode: false,
        timeout: 8_000
      });
      sampledStatuses.push(`${check.path}:${response.status()}`);

      if (response.ok()) {
        const body = await response.text();
        if (check.sensitive && isSensitivePathExposure(check.path, response, body)) {
          exposedPaths.push(`${check.label} (${check.path})`);
        } else if (!check.sensitive) {
          publicMetadataPaths.push(`${check.label} (${check.path})`);
        }
      }
    }

    audit.add({
      id: 'API-004',
      title: exposedPaths.length > 0 ? 'Potentially sensitive public paths responded successfully' : 'Sensitive path spot-checks did not expose content',
      severity: exposedPaths.length > 0 ? 'Medium' : 'Info',
      category: 'Sensitive File Exposure',
      status: exposedPaths.length > 0 ? 'manual-review' : 'not-observed',
      description: 'A short allowlisted set of common sensitive paths was requested with unauthenticated GET requests.',
      impact: exposedPaths.length > 0
        ? 'Public configuration, backup, or API documentation endpoints can accelerate attack planning.'
        : 'No sensitive content was observed from this limited spot-check.',
      remediation: exposedPaths.length > 0
        ? 'Remove public access to sensitive files and require authentication for internal documentation.'
        : 'Keep sensitive files outside the web root and block accidental publication in CI/CD.',
      evidence: [
        { label: 'Exposed candidates', details: exposedPaths.join(', ') || 'none observed' },
        { label: 'Public metadata', details: publicMetadataPaths.join(', ') || 'none observed' },
        { label: 'Sampled statuses', details: sampledStatuses.join(', ') }
      ],
      references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/']
    });

    const optionsResponse = await request.fetch(targetUrl, {
      method: 'OPTIONS',
      failOnStatusCode: false,
      timeout: 8_000
    });
    const allowHeader = optionsResponse.headers().allow ?? optionsResponse.headers()['access-control-allow-methods'];
    const riskyMethods = allowHeader?.match(/\b(PUT|DELETE|TRACE|CONNECT)\b/gi) ?? [];
    audit.add({
      id: 'API-005',
      title: riskyMethods.length > 0 ? 'Potentially risky HTTP methods advertised' : 'HTTP method advertisement reviewed',
      severity: riskyMethods.length > 0 ? 'Low' : 'Info',
      category: 'API Surface',
      status: riskyMethods.length > 0 ? 'manual-review' : 'not-observed',
      description: 'The target was queried with an OPTIONS request to inspect advertised HTTP methods.',
      impact: riskyMethods.length > 0
        ? 'Unneeded HTTP methods can expose accidental write, debug, or proxy behavior.'
        : 'No risky methods were advertised by the sampled OPTIONS response.',
      remediation: riskyMethods.length > 0
        ? 'Disable methods that are not required by the application and enforce method allowlists at the edge.'
        : 'Keep method allowlists explicit at the reverse proxy or application routing layer.',
      evidence: [
        { label: 'HTTP status', details: String(optionsResponse.status()) },
        { label: 'Allow / AC-Allow-Methods', details: allowHeader ?? 'missing' }
      ]
    });
  });

  test('direct unauthenticated API authorization checks', async ({ request }) => {
    test.skip(!targetReachable, unavailableReason());

    for (const check of unauthenticatedApiChecks) {
      const url = new URL(check.path, targetUrl);
      const response = await request.get(url.toString(), { failOnStatusCode: false, timeout: 10_000 });
      const body = await response.text().catch(() => '');
      const blocked = isAccessBlocked(response.status(), body);
      const sensitiveDataObserved = response.ok() && Boolean(check.sensitivePattern?.test(body));
      const unexpectedAccess = check.expectedProtected && !blocked;

      audit.add({
        id: `API-AUTH-${cleanFileName(check.label).toUpperCase()}`,
        title: `${check.label} unauthenticated API access check`,
        severity: unexpectedAccess && sensitiveDataObserved ? 'Medium' : unexpectedAccess ? 'Low' : 'Info',
        category: 'Access Control',
        status: unexpectedAccess ? 'manual-review' : 'not-observed',
        description: `The ${check.label} endpoint was requested without an authenticated session.`,
        impact: unexpectedAccess
          ? 'The endpoint returned data or behavior without an authenticated session and should be manually reviewed for authorization gaps.'
          : 'The endpoint appeared blocked, unavailable, or intentionally public without sensitive data in this run.',
        remediation: unexpectedAccess
          ? 'Require server-side authorization checks for protected API resources and avoid exposing sensitive object collections.'
          : 'Keep API authorization enforced server-side and add regression tests for protected resources.',
        evidence: [
          { label: 'Endpoint', details: url.toString() },
          { label: 'HTTP status', details: String(response.status()) },
          { label: 'Blocked signal', details: String(blocked) },
          { label: 'Sensitive data pattern observed', details: String(sensitiveDataObserved) },
          { label: 'Response preview', details: textPreview(body) }
        ],
        references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/']
      });
    }
  });

  test('error handling and unexpected path behavior checks', async ({ request }) => {
    test.skip(!targetReachable, unavailableReason());

    const notFoundUrl = new URL(`/definitely-not-real-${Date.now()}`, targetUrl);
    const response = await request.get(notFoundUrl.toString(), { failOnStatusCode: false, timeout: 10_000 });
    const body = await response.text().catch(() => '');
    const verboseErrorObserved = response.status() >= 500 || /stack trace|exception|sequelize|sqlite|syntaxerror|traceback/i.test(body);
    const spaFallbackObserved = response.ok() && isLikelySpaFallback(response.headers()['content-type'] ?? '', body);

    audit.add({
      id: 'ERR-001',
      title: verboseErrorObserved
        ? 'Unexpected path returned verbose error details'
        : spaFallbackObserved
          ? 'Unexpected path returned SPA fallback'
          : 'Unexpected path handled without verbose errors',
      severity: verboseErrorObserved ? 'Medium' : 'Info',
      category: 'Error Handling',
      status: verboseErrorObserved ? 'observed' : spaFallbackObserved ? 'manual-review' : 'not-observed',
      description: 'A unique non-existent path was requested to review generic error handling behavior.',
      impact: verboseErrorObserved
        ? 'Verbose errors can disclose framework, database, path, or stack information useful for follow-up attacks.'
        : 'No verbose server error was observed for this non-existent path.',
      remediation: verboseErrorObserved
        ? 'Return generic production errors and log detailed exceptions server-side only.'
        : 'Keep production error handling generic and monitor unexpected route requests.',
      evidence: [
        { label: 'Endpoint', details: notFoundUrl.toString() },
        { label: 'HTTP status', details: String(response.status()) },
        { label: 'SPA fallback observed', details: String(spaFallbackObserved) },
        { label: 'Response preview', details: textPreview(body) }
      ],
      references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/']
    });

    const sampledCachePaths = ['/', '/rest/products/search?q=apple', '/ftp'];
    const missingCachePolicy: string[] = [];
    const sampledPolicies: string[] = [];
    for (const pathName of sampledCachePaths) {
      const cacheUrl = new URL(pathName, targetUrl);
      const cacheResponse = await request.get(cacheUrl.toString(), { failOnStatusCode: false, timeout: 8_000 });
      const cacheControl = cacheResponse.headers()['cache-control'] ?? '';
      sampledPolicies.push(`${pathName}:${cacheControl || 'missing'}`);

      if (cacheResponse.status() < 400 && !/no-store|no-cache|private|max-age/i.test(cacheControl)) {
        missingCachePolicy.push(pathName);
      }
    }

    audit.add({
      id: 'HDR-009',
      title: missingCachePolicy.length > 0 ? 'Sampled responses missing explicit cache policy' : 'Sampled response cache policies reviewed',
      severity: missingCachePolicy.length > 0 ? 'Low' : 'Info',
      category: 'Header Hardening',
      status: missingCachePolicy.length > 0 ? 'manual-review' : 'not-observed',
      description: 'A small set of application and API responses was checked for explicit Cache-Control behavior.',
      impact: 'Responses without explicit cache policy can be stored unexpectedly by browsers or intermediary caches.',
      remediation: 'Set explicit cache policy by content type and sensitivity, using no-store for sensitive responses.',
      evidence: [
        { label: 'Missing explicit policy', details: missingCachePolicy.join(', ') || 'none observed' },
        { label: 'Sampled policies', details: sampledPolicies.join(' | ') }
      ]
    });
  });

  test('negative authentication workflow', async ({ page }) => {
    test.skip(!targetReachable, unavailableReason());

    await page.goto(hashRouteUrl(targetUrl, '/login'), { waitUntil: 'domcontentloaded' });
    await closeJuiceShopOverlays(page);

    const emailFilled = await tryFill(
      page,
      [
        (targetPage) => targetPage.getByPlaceholder(/email/i),
        (targetPage) => targetPage.getByLabel(/email/i),
        (targetPage) => targetPage.locator('input[type="email"]'),
        (targetPage) => targetPage.locator('#email')
      ],
      'not-a-real-user@example.test'
    );
    const passwordFilled = await tryFill(
      page,
      [
        (targetPage) => targetPage.getByPlaceholder(/password/i),
        (targetPage) => targetPage.getByLabel(/password/i),
        (targetPage) => targetPage.locator('input[type="password"]'),
        (targetPage) => targetPage.locator('#password')
      ],
      'NotARealPassword123!'
    );
    const submitClicked = await tryClick(page, [
      (targetPage) => targetPage.getByRole('button', { name: /^log in$/i }),
      (targetPage) => targetPage.getByRole('button', { name: /login/i }),
      (targetPage) => targetPage.locator('#loginButton'),
      (targetPage) => targetPage.locator('button[type="submit"]')
    ]);

    await page.waitForTimeout(1_500);
    const bodyText = await page.locator('body').innerText().catch(() => '');
    const authEvidence = await screenshotEvidence(page, '02-negative-login');

    audit.add({
      id: 'AUTH-001',
      title: 'Negative login workflow automated',
      severity: emailFilled && passwordFilled && submitClicked ? 'Info' : 'Low',
      category: 'Authentication',
      status: emailFilled && passwordFilled && submitClicked ? 'observed' : 'manual-review',
      description: 'Playwright attempted a login with a non-existent demo user and captured the resulting page state.',
      impact:
        'Automating negative auth flows provides regression coverage for login behavior and creates evidence for manual review.',
      remediation:
        'Use generic authentication errors, rate limiting, monitoring, and account lockout controls for production systems.',
      evidence: [
        { label: 'Email field automated', details: String(emailFilled) },
        { label: 'Password field automated', details: String(passwordFilled) },
        { label: 'Submit clicked', details: String(submitClicked) },
        { label: 'Visible page text preview', details: textPreview(bodyText) },
        authEvidence
      ],
      references: ['https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/']
    });
  });

  test('safe search input reflection check', async ({ page }) => {
    test.skip(!targetReachable, unavailableReason());

    const marker = `PWT_MARKER_${Date.now()}`;
    await page.goto(hashRouteUrl(targetUrl, `/search?q=${encodeURIComponent(marker)}`), {
      waitUntil: 'domcontentloaded'
    });
    await closeJuiceShopOverlays(page);
    await page.waitForTimeout(2_000);

    const bodyText = await page.locator('body').innerText().catch(() => '');
    const reflected = bodyText.includes(marker);
    const searchEvidence = await screenshotEvidence(page, '03-search-reflection');

    audit.add({
      id: 'INP-001',
      title: reflected ? 'Search marker reflected in the browser UI' : 'Search marker was not reflected in visible text',
      severity: reflected ? 'Low' : 'Info',
      category: 'Input Handling',
      status: reflected ? 'observed' : 'not-observed',
      description: 'A harmless unique marker was submitted through the search route and checked in rendered page text.',
      impact: reflected
        ? 'Reflected input should be manually reviewed for context-aware output encoding and script execution controls.'
        : 'No visible reflection was observed from this safe marker check.',
      remediation: reflected
        ? 'Encode untrusted data by output context and keep framework sanitization, CSP, and tests in place.'
        : 'Continue validating and encoding search input before rendering it back to users.',
      evidence: [
        { label: 'Marker', details: marker },
        { label: 'Visible page text preview', details: textPreview(bodyText) },
        searchEvidence
      ],
      references: ['https://owasp.org/Top10/A03_2021-Injection/']
    });
  });

  test('unauthenticated route boundary checks', async ({ page }) => {
    test.skip(!targetReachable, unavailableReason());

    for (const route of unauthenticatedRoutes) {
      await page.goto(hashRouteUrl(targetUrl, route.route), { waitUntil: 'domcontentloaded' });
      await closeJuiceShopOverlays(page);
      await page.waitForTimeout(1_500);

      const currentUrl = page.url();
      const bodyText = await page.locator('body').innerText().catch(() => '');
      const blockedByLogin =
        /login|email|password/i.test(currentUrl) ||
        /please log in|not authorized|unauthorized|not allowed|forbidden|\b403\b|login/i.test(bodyText);
      const evidence = await screenshotEvidence(page, `04-route-${route.label}`);

      audit.add({
        id: `AC-${route.label.toUpperCase()}`,
        title: `${route.label} route unauthenticated access check`,
        severity: blockedByLogin ? 'Info' : route.label === 'Administration' ? 'Medium' : 'Low',
        category: 'Access Control',
        status: blockedByLogin ? 'not-observed' : 'manual-review',
        description: `Playwright loaded the ${route.label} route without an authenticated session.`,
        impact: blockedByLogin
          ? 'The route appeared to require authentication or did not expose protected content in this run.'
          : 'The route rendered without an authenticated session and should be manually reviewed for sensitive content exposure.',
        remediation: blockedByLogin
          ? 'Keep route guards and server-side authorization checks in place.'
          : 'Enforce server-side authorization for protected data and avoid relying only on client-side route guards.',
        evidence: [
          { label: 'Requested route', details: route.route },
          { label: 'Final URL', details: currentUrl },
          { label: 'Visible page text preview', details: textPreview(bodyText) },
          evidence
        ],
        references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/']
      });
    }
  });
});

function unavailableReason(): string {
  if (targetError) {
    return `Target unavailable: ${targetError}`;
  }

  return `Target unavailable: HTTP ${targetStatus ?? 'unknown'}`;
}

function clearDirectoryContents(directory: string): void {
  fs.mkdirSync(directory, { recursive: true });
  const preservedEntries = new Set(['project-explanation.md']);

  for (const entry of fs.readdirSync(directory)) {
    if (preservedEntries.has(entry)) {
      continue;
    }

    fs.rmSync(path.join(directory, entry), { recursive: true, force: true });
  }
}

function isSensitivePathExposure(pathName: string, response: APIResponse, body: string): boolean {
  const contentType = response.headers()['content-type'] ?? '';

  if (isLikelySpaFallback(contentType, body)) {
    return false;
  }

  if (pathName === '/.env') {
    return /(^|\n)[A-Z0-9_]*(SECRET|PASSWORD|TOKEN|KEY|DATABASE|DB)[A-Z0-9_]*=/i.test(body);
  }

  if (pathName === '/config.json') {
    return /json/i.test(contentType) || /"?(password|secret|token|apiKey|database|admin|jwt)"?\s*:/i.test(body);
  }

  if (pathName === '/backup.zip') {
    return !/text\/html/i.test(contentType);
  }

  if (pathName === '/api-docs' || pathName === '/swagger.json') {
    return /swagger|openapi/i.test(body);
  }

  return false;
}

function isLikelySpaFallback(contentType: string, body: string): boolean {
  return /text\/html/i.test(contentType) && /<app-root|OWASP Juice Shop|main\.[a-z0-9]+\.js|polyfills\.[a-z0-9]+\.js/i.test(body);
}

function isAccessBlocked(status: number, body: string): boolean {
  return [401, 403, 404].includes(status) || /not authorized|unauthorized|forbidden|not allowed|please log in|\b403\b/i.test(body);
}

function urlPath(input: string): string {
  try {
    const url = new URL(input);
    return `${url.pathname}${url.search}`;
  } catch {
    return input;
  }
}

async function waitForTarget(
  request: APIRequestContext,
  url: string,
  timeoutMs = 120_000,
  intervalMs = 2_000
): Promise<APIResponse> {
  const startedAt = Date.now();
  let lastError: unknown;
  let lastResponse: APIResponse | undefined;

  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await request.get(url, {
        timeout: 10_000,
        failOnStatusCode: false
      });
      lastResponse = response;

      if (response.status() < 500) {
        return response;
      }
    } catch (error) {
      lastError = error;
    }

    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }

  if (lastResponse) {
    return lastResponse;
  }

  throw lastError instanceof Error ? lastError : new Error(`Target did not become reachable within ${timeoutMs}ms`);
}

async function screenshotEvidence(page: Page, name: string): Promise<Evidence> {
  const fileName = `${cleanFileName(name)}.png`;
  const absolutePath = path.join(evidenceDir, fileName);
  await page.screenshot({ path: absolutePath, fullPage: true });

  return {
    label: 'Screenshot',
    path: path.posix.join('evidence', fileName)
  };
}

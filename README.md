# Playwright Security Automation Lab

Professional Playwright infrastructure for a legal, non-destructive web security testing demo. The default Docker workflow runs OWASP Juice Shop and the Playwright runner on an isolated internal Docker network.

## Safety Model

- Tests only target `TARGET_URL`.
- The Docker workflow does not expose Juice Shop to your host network by default.
- The runner uses safe GET, OPTIONS, browser navigation, and negative-login checks.
- No brute force, malware, destructive requests, credential theft, or filesystem access outside the project artifacts.
- Use only the included lab, OWASP Juice Shop, or systems where you have explicit written permission.

## Recommended Interview Demo

```powershell
npm.cmd run docker:audit
```

Outputs are written back to:

- `reports/security-report.md`
- `reports/findings.json`
- `reports/evidence/*.png`
- `playwright-report/index.html`

Stop and clean the compose stack:

```powershell
npm.cmd run docker:down
```

## Local Non-Docker Demo

Run the small built-in lab in one terminal:

```powershell
npm.cmd run lab
```

Run the audit in another terminal:

```powershell
npm.cmd run audit
```

## OWASP Juice Shop on Host Docker

If you want to inspect Juice Shop in a browser while testing:

```powershell
npm.cmd run juice-shop:docker
$env:TARGET_URL = "http://localhost:3000"
npm.cmd run audit
```

## Coverage

- Target reachability and screenshot evidence
- Security headers: CSP, frame protection, Referrer-Policy, Permissions-Policy, HSTS on HTTPS
- CORS policy review
- Server banner and cache policy review
- Browser-side surface inventory
- Browser form hygiene and external-link `noopener` checks
- Cookie flag hygiene
- Public API discovery
- Direct unauthenticated API authorization checks
- File listing and sensitive path spot-checks
- Static asset, source-map, and client bundle secret-hint checks
- Safe input handling probes
- Negative authentication workflow
- Unauthenticated protected-route checks
- Generic error handling and unexpected route behavior
- HTTP method advertisement review

## Test Suite

The Docker audit currently runs these Playwright specs:

- Recon and response header audit
- Client-side surface inventory
- Cookie and browser storage hygiene checks
- Browser form and external link hygiene checks
- Static asset and source map exposure checks
- Public API and directory exposure checks
- Direct unauthenticated API authorization checks
- Error handling and unexpected path behavior checks
- Negative authentication workflow
- Safe search input reflection check
- Unauthenticated route boundary checks

The suite is intentionally non-destructive. It uses browser navigation, safe GET/OPTIONS requests, a single fake negative-login workflow, and harmless input markers.

## Project Structure

```text
compose.yaml                 Docker-isolated Juice Shop + Playwright runner
Dockerfile                   Playwright runner image
playwright.config.ts         Test runner config
tests/                       Security automation specs
src/config.ts                Environment-driven runtime config
src/security-rules.ts        Reusable security rules and findings
src/audit-report.ts          Markdown and JSON report writer
src/juice-shop-helpers.ts    Browser helpers and safe text cleanup
scripts/local-lab.mjs        Tiny local demo target for offline verification
docs/SAFETY.md               Safety boundaries and operational guidance
reports/project-explanation.md Plain-English pentest project explanation
```

## Useful Commands

```powershell
npm.cmd install
npm.cmd run setup:browsers
npm.cmd run typecheck
npm.cmd run audit
npm.cmd run docker:audit
npm.cmd run report
```

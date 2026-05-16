# Interview Walkthrough

## Positioning

This is a security automation framework, not an exploit script. It demonstrates how to use Playwright for repeatable browser-driven checks, evidence capture, and professional reporting against an authorized lab target.

## Architecture

- Docker Compose starts OWASP Juice Shop on an isolated internal network.
- A separate Playwright runner container waits for the target health check.
- Tests collect findings instead of failing on expected lab vulnerabilities.
- Reports are exported as Markdown, JSON, screenshots, and the Playwright HTML report.

## Talking Points

- Separation between target and runner improves safety and reproducibility.
- Findings are structured with severity, status, impact, evidence, remediation, and references.
- Test categories map to OWASP themes: injection, access control, authentication, misconfiguration, and session management.
- The project avoids noisy or unsafe behavior such as brute force and destructive mutation.
- Environment variables allow the same suite to run against local lab, Docker Juice Shop, or another authorized target.

## Demo Flow

```powershell
npm.cmd run docker:audit
Get-Content reports/security-report.md
npm.cmd run report
```

## Extension Ideas

- Add authenticated fixtures with disposable lab accounts.
- Add OWASP ZAP passive scanning as a separate Docker service.
- Add GitHub Actions to run typecheck and local lab tests.
- Add a SARIF exporter for security tooling integrations.


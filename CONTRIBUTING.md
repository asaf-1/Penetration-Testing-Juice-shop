# Contributing

Thanks for your interest in improving this security-automation lab. This guide
covers local setup, the quality gates, and how findings are structured.

## Prerequisites

- Node.js `>= 20`
- Docker (for the isolated end-to-end audit)

## Setup

```bash
npm install
npm run setup:browsers   # one-time Playwright Chromium download (for headed/local runs)
```

A git pre-commit hook (via Husky + lint-staged) automatically formats and lints
staged files, then runs typecheck and unit tests.

## Quality gates

Run everything CI runs, locally, with one command:

```bash
npm run verify   # prettier --check + eslint + tsc --noEmit + vitest
```

Individual gates:

| Command                                   | Purpose                                        |
| ----------------------------------------- | ---------------------------------------------- |
| `npm run format` / `npm run format:check` | Prettier write / check                         |
| `npm run lint` / `npm run lint:fix`       | ESLint                                         |
| `npm run typecheck`                       | TypeScript (`--noEmit`, strict)                |
| `npm run test:unit`                       | Vitest unit tests                              |
| `npm run coverage`                        | Unit tests + V8 coverage (thresholds enforced) |

## Running the audit

```bash
npm run lab            # terminal 1: tiny offline target
npm run audit          # terminal 2: run the suite against it

# or, fully isolated end-to-end against OWASP Juice Shop:
npm run docker:audit
```

## Adding a new check

1. If the check is **pure logic** (header/cookie/CORS rules, etc.), add it to
   [src/security-rules.ts](src/security-rules.ts) and cover it with a unit test
   in [tests/unit/](tests/unit/).
2. If it needs a **browser or HTTP request**, add a spec step in
   [tests/juice-shop-security.spec.ts](tests/juice-shop-security.spec.ts) and
   emit a `Finding` via `audit.add(...)`.
3. Every finding must conform to the `Finding` interface in
   [src/findings.ts](src/findings.ts). The reporter automatically renders it to
   JSON, Markdown, HTML, and SARIF — no reporter changes needed.
4. Keep checks **non-destructive**. Anything that could modify state, brute
   force, or exfiltrate data will not be accepted.

## Commit style

Small, focused commits with descriptive messages. PRs should pass `npm run
verify` and keep coverage above the configured thresholds.

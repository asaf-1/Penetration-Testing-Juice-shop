# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **SARIF 2.1.0 output** (`src/sarif.ts`) so findings publish to the GitHub
  Security tab via code scanning.
- **Unit test suite** (Vitest) covering the pure rule, finding, SARIF, and helper
  logic, with enforced V8 coverage thresholds.
- **Quality tooling**: ESLint (flat config) + Prettier + EditorConfig, wired into
  an `npm run verify` gate and a Husky + lint-staged pre-commit hook.
- **Configurable severity gate** (`scripts/check-findings.mjs`, `FAIL_ON`,
  default `off`) so the same tool can report-only on the lab yet block a real
  pipeline.
- **CI hardening**: split into `quality` and `security-audit` jobs, build
  concurrency, GitHub Actions job summary, and SARIF upload.
- **Static analysis & supply chain**: CodeQL workflow and Dependabot config.
- **Repository hygiene**: LICENSE, SECURITY policy, contributing guide, code of
  conduct, CODEOWNERS, issue/PR templates.
- **Developer experience**: dev container and a JSON Schema for findings.

### Changed

- Consolidated the duplicated `Finding`/`Severity` domain model into a single
  source of truth (`src/findings.ts`) consumed by the specs and the reporter.

### Removed

- Dead, superseded `src/audit-report.ts` module.

## [1.0.0]

### Added

- Initial Playwright security-automation lab targeting OWASP Juice Shop on an
  isolated, hardened Docker network, with a custom reporter emitting HTML,
  Markdown, and JSON reports plus screenshot evidence.

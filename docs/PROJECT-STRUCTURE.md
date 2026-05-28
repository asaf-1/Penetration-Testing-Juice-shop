# Project Structure & Architecture

This document is an exhaustive map of the repository: every file and folder, what
it does, and **why** it exists. It is written for engineers and reviewers who want
to understand how the Playwright security-automation lab is wired together as a
production-grade tool rather than a script dump.

> The project runs **non-destructive** security checks against an isolated OWASP
> Juice Shop target, then publishes structured findings as JSON, Markdown, an
> interactive HTML dashboard, and SARIF. See [SAFETY.md](SAFETY.md) for the
> safety model and [../README.md](../README.md) for the quick start.

---

## 1. Directory map

```text
.
├── .github/                       GitHub automation
│   ├── workflows/
│   │   ├── audit.yml               CI: quality gates → isolated DAST audit → SARIF upload
│   │   └── codeql.yml              CodeQL static analysis (SAST), incl. weekly schedule
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.yml          Structured bug issue form
│   │   ├── feature_request.yml     Structured feature issue form (safety acknowledgement)
│   │   └── config.yml              Disables blank issues; routes vulns to private disclosure
│   ├── CODEOWNERS                  Default reviewer ownership
│   ├── PULL_REQUEST_TEMPLATE.md    PR checklist (verify gate + safety model)
│   └── dependabot.yml              Weekly npm / Actions / Docker update PRs
├── .devcontainer/
│   └── devcontainer.json           One-click VS Code / Codespaces dev environment
├── .husky/
│   └── pre-commit                  Local pre-commit gate (lint-staged + typecheck + unit tests)
├── docs/
│   ├── PROJECT-STRUCTURE.md        This document
│   ├── SAFETY.md                   Non-destructive safety boundary
│   └── INTERVIEW-WALKTHROUGH.md    Presentation/talking-points aid
├── reports/
│   └── project-explanation.md      Plain-English scope & methodology (the only versioned report)
├── schemas/
│   └── findings.schema.json        JSON Schema (Draft 2020-12) contract for findings.json
├── scripts/
│   ├── local-lab.mjs               Zero-dependency offline target that mimics Juice Shop
│   ├── prepare-artifacts.mjs       Pre-creates output directories
│   ├── check-findings.mjs          Configurable severity gate (FAIL_ON)
│   └── report-summary.mjs          Renders the GitHub Actions job summary
├── src/
│   ├── findings.ts                 Shared finding domain model + pure helpers (single source of truth)
│   ├── sarif.ts                    SARIF 2.1.0 serializer for GitHub code scanning
│   ├── security-rules.ts           Declarative check catalog + pure detection functions
│   ├── config.ts                   Environment-driven runtime config
│   ├── juice-shop-helpers.ts       Resilient browser helpers + text sanitization
│   └── reporters/
│       └── security-reporter.ts    Custom Playwright reporter → JSON/MD/HTML/SARIF
├── tests/
│   ├── juice-shop-security.spec.ts End-to-end Playwright security audit (the working core)
│   └── unit/                        Fast Vitest unit tests over the pure logic
│       ├── findings.test.ts
│       ├── sarif.test.ts
│       ├── security-rules.test.ts
│       ├── helpers.test.ts
│       └── schema.test.ts
├── Dockerfile                     Audit-runner image (non-root, browsers preinstalled)
├── compose.yaml                   Two-service isolated lab (target + runner)
├── playwright.config.ts           E2E runner config (testMatch *.spec.ts)
├── vitest.config.ts               Unit runner config + enforced coverage thresholds
├── eslint.config.mjs              ESLint flat config (TypeScript + Prettier-compatible)
├── tsconfig.json                  Strict TypeScript config (type-check only, no emit)
├── package.json                   Manifest, scripts, devDependencies, lint-staged wiring
├── package-lock.json              Pinned, integrity-hashed dependency lockfile
├── .prettierrc.json               Prettier style
├── .prettierignore                Paths Prettier must not touch
├── .editorconfig                  Editor-level whitespace/encoding baseline
├── .gitignore                     Untracked paths (incl. .env secret safety)
├── .dockerignore                  Excludes from the Docker build context
├── .env.example                   Documented env-var template
├── README.md                      Primary entry point / engineering showcase
├── CONTRIBUTING.md                Onboarding + how to add a check
├── SECURITY.md                    Security policy & private disclosure
├── CODE_OF_CONDUCT.md             Contributor Covenant 2.1
├── CHANGELOG.md                   Keep a Changelog history
└── LICENSE                        MIT
```

Generated/ignored directories that are **not** committed: `node_modules/`,
`reports/` output (except `project-explanation.md`), `playwright-report/`,
`test-results/`, and `coverage/`.

---

## 2. Toolchain at a glance

| Tool                     | Role in this project                                   | Why it's here                                                                                                    |
| ------------------------ | ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| **TypeScript** (strict)  | Static typing for all source/specs                     | Catches null/undefined and shape bugs before runtime; `noUncheckedIndexedAccess` + `strict` raise the safety bar |
| **Playwright**           | Browser + HTTP automation engine for the audit         | Drives Chromium and makes safe `GET`/`OPTIONS` requests; its reporter API powers custom report output            |
| **Vitest**               | Fast unit-test runner with V8 coverage                 | Tests the pure detection/report logic headlessly and **enforces coverage thresholds** as a quality gate          |
| **ESLint** (flat config) | Static analysis / linting                              | Bans `any`, unused vars, loose equality; formatting is delegated to Prettier to avoid conflicts                  |
| **Prettier**             | Opinionated formatter                                  | Uniform style with zero debate; runs in CI and on pre-commit                                                     |
| **EditorConfig**         | Editor-level whitespace/encoding                       | Consistency before Prettier even runs, across any editor                                                         |
| **Husky + lint-staged**  | Git pre-commit hook                                    | Shifts quality enforcement left — format/lint/typecheck/test before code is committed                            |
| **Docker + Compose**     | Isolated runtime for target + runner                   | Network-isolated, hardened sandbox so the deliberately vulnerable app is never exposed                           |
| **CodeQL**               | First-party static application security testing (SAST) | Scans the project's _own_ code for vulnerable patterns; weekly cron catches newly disclosed queries              |
| **Dependabot**           | Automated dependency updates                           | Keeps npm/Actions/Docker dependencies patched — supply-chain hygiene                                             |
| **Ajv + ajv-formats**    | JSON Schema validation (in tests)                      | Makes the findings report a _tested_ contract, not an ad-hoc shape                                               |
| **SARIF 2.1.0**          | Security results interchange format                    | Surfaces findings natively in GitHub's Security → Code scanning tab                                              |
| **GitHub Actions**       | CI/CD orchestration                                    | Runs the two-stage pipeline (quality, then isolated DAST audit) on every push/PR                                 |

---

## 3. How it fits together (runtime flow)

```text
loadAuditConfig()  ──► TARGET_URL / REPORTS_DIR
        │
        ▼
Playwright spec (tests/juice-shop-security.spec.ts)
   • drives Chromium + APIRequestContext against the target
   • evaluates rules from src/security-rules.ts
   • emits each Finding as a "security-finding" test attachment
        │
        ▼
Custom reporter (src/reporters/security-reporter.ts)  [onTestEnd → onEnd]
   • collects attachments, dedups + sorts (src/findings.ts)
   • writes findings.json, security-report.md, security-report.html
   • writes security-report.sarif (src/sarif.ts)
        │
        ├──► scripts/report-summary.mjs  → GitHub Actions job summary
        ├──► scripts/check-findings.mjs  → severity gate (FAIL_ON)
        └──► github/codeql-action/upload-sarif → Security tab
```

The **domain model in [`src/findings.ts`](../src/findings.ts) is the contract**
that keeps producers (the specs) and consumers (the reporter, SARIF, the JSON
Schema, the gate) from drifting apart.

---

## 4. Source — core logic (`src/`)

The framework-agnostic backbone. Detection logic is deliberately separated from
Playwright orchestration so checks stay pure, testable, and reusable.

### [`src/findings.ts`](../src/findings.ts)

- **What:** The single source-of-truth domain model — types, severity ordering, and pure helpers to sort, deduplicate, count, and slug-name findings.
- **Why:** Guarantees the finding schema can never drift between the specs (producers) and the reporter/SARIF/gate (consumers); provides deterministic ordering and dedup so reports and CI gating are reproducible.
- **Types & constants:** `Severity` (`Critical|High|Medium|Low|Info`), `FindingStatus` (`observed|not-observed|manual-review`), the `Evidence` and `Finding` interfaces, `SeverityCounts`; `severityOrder` (Critical:5 … Info:1) and `ALL_SEVERITIES`.
- **Functions:**

| Function                        | What it does                                                            | Why it exists                                                                                                   |
| ------------------------------- | ----------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `sortFindings(findings)`        | Returns a new array ordered by severity desc, then `id` asc             | Deterministic, highest-severity-first ordering for every report and the CI gate; copies the input (no mutation) |
| `deduplicateFindings(findings)` | Collapses findings sharing an `id`, merging only non-duplicate evidence | A check that fires across many requests reports **once** with combined evidence instead of as duplicates        |
| `countBySeverity(findings)`     | Reduces into a zero-filled `{Critical,High,Medium,Low,Info}` count      | Powers the summary tables in the Markdown/HTML reports and the job summary                                      |
| `cleanFileName(input)`          | Lowercases, slugifies non-alphanumerics, trims dashes, caps at 80 chars | Safe, bounded artifact filenames (e.g. screenshot/evidence names) from arbitrary labels                         |
| `severityOrder` (const)         | Numeric rank per severity                                               | Shared ranking reused by `sortFindings` **and** the `check-findings` severity gate so ordering can't diverge    |

### [`src/sarif.ts`](../src/sarif.ts)

- **What:** Maps the finding set into a deterministic SARIF 2.1.0 log for GitHub code scanning.
- **Why:** Bridges DAST findings into the standard static-analysis ecosystem so results render in the Security tab; stable `partialFingerprints` let code scanning track a finding across runs.
- **Functions:**

| Function                                  | What it does                                                                                                       | Why it exists                                                                             |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------- |
| `toSarif(findings, targetUrl)` (exported) | Builds the SARIF 2.1.0 log: one **rule per unique finding id** + one **result per finding**                        | The single entry point the reporter calls to produce code-scanning output                 |
| `buildMessage(finding)`                   | Composes `[severity] title — description (evidence…)`                                                              | Gives each SARIF result a self-contained, human-readable message in the Security tab      |
| `locationForFinding(finding, targetUrl)`  | Derives a `host+path` URI from `Endpoint`/`Target URL`/`Requested route` evidence, falling back to the target host | DAST findings have **no source file**, so the audited URL stands in as the SARIF location |
| `toPascalCaseRuleName` / `capitalize`     | Convert a category like "Header Hardening" → `HeaderHardening`                                                     | SARIF rule `name`s must be identifier-like                                                |

- **Mapping constants:** `severityToLevel` (Critical/High→`error`, Medium→`warning`, Low/Info→`note`) and `severityToScore` (GitHub's numeric `security-severity`: Critical `9.5` … Info `0.0`). Each result also carries `partialFingerprints.findingId` so code scanning tracks the same finding across runs.

### [`src/security-rules.ts`](../src/security-rules.ts)

- **What:** The declarative catalog of checks (header rules, sensitive-path probes, unauthenticated route/API authorization checks) plus the pure functions that turn observed state into `Finding`s.
- **Why:** Centralizes the lab's security knowledge as **data + side-effect-light detectors**, so adding/tuning a check is a data edit and the logic stays unit-testable without Playwright.
- **Data catalogs (the "what to check" as data):** `headerRules` — CSP (HDR-001, Medium), clickjacking/X-Frame-Options (HDR-002, Low; accepts CSP `frame-ancestors` as an alternate), Referrer-Policy (HDR-003), Permissions-Policy (HDR-004), HSTS (HDR-006, `httpsOnly`). `sensitivePathChecks` — `/.env`, `/config.json`, `/backup.zip`, `/api-docs`, `/swagger.json` (sensitive) + `/robots.txt`, `/security.txt` (metadata). `unauthenticatedRoutes` — `/basket`, `/administration`, `/profile`, `/order-history`. `unauthenticatedApiChecks` — `/api/Users`, `/api/BasketItems`, `/api/Complaints`, `/rest/basket/1`, `/rest/admin/application-configuration`, `/rest/user/whoami` (each with a `sensitivePattern`).
- **Functions (the "how to judge" as pure detectors):**

| Function                                   | What it does                                                                                                 | Why it exists                                                                                                                          |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------- |
| `missingHeaderFinding(headers, rule, url)` | Returns a Header-Hardening `Finding` when a header is absent, or `null`                                      | Encapsulates header logic incl. **skipping HTTPS-only rules on HTTP** and treating CSP `frame-ancestors` as satisfying X-Frame-Options |
| `corsFinding(headers)`                     | Grades CORS: wildcard **+ credentials** → High `HDR-007`; bare wildcard → Low/manual-review; scoped → `null` | Credentialed wildcard CORS is genuinely dangerous; bare wildcard only warrants review — the severity split reflects real risk          |
| `cookieFindings(context, url)` (async)     | Inspects issued cookies, emitting `CK-000`–`CK-003`                                                          | Flags missing HttpOnly, missing Secure (**HTTPS only**), and `SameSite=None`, or a clean baseline — session-hardening judgment         |

### [`src/config.ts`](../src/config.ts)

- **What:** Resolves runtime config (`targetUrl`, `reportsDir`, `evidenceDir`) from environment variables with defaults.
- **Why:** Decouples target and output locations from code so the same suite runs against the local lab, Docker, or CI without edits.
- **Details:** `loadAuditConfig()` returns `targetUrl` (`TARGET_URL` ?? `http://localhost:3000`), `reportsDir` (`REPORTS_DIR` ?? `reports`, resolved), and `evidenceDir` (`<reportsDir>/evidence`).

### [`src/juice-shop-helpers.ts`](../src/juice-shop-helpers.ts)

- **What:** Resilient browser-interaction utilities (dismiss overlays, best-effort fill/click across selector variants) plus URL and text-sanitization helpers.
- **Why:** Makes the e2e audit robust to Juice Shop version drift, and `sanitizeDetail` strips control/ANSI characters before findings are reported — preventing log/terminal injection in generated output.
- **Functions:**

| Function                           | What it does                                                                                                                      | Why it exists                                                                                                                                    |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `hashRouteUrl(baseUrl, route)`     | Builds a full URL with an Angular-style `#/route` hash (strips a leading `#`, ensures a leading `/`)                              | Juice Shop is a single-page app routed by hash; the audit must navigate to `#/login`, `#/search`, etc. reliably                                  |
| `closeJuiceShopOverlays(page)`     | Clicks the first visible of seven candidate locators (welcome banner, dismiss/accept/"me want it", cookie message, dialog action) | The welcome/cookie overlays block interaction and **differ across Juice Shop versions**; swallowing misses keeps the audit resilient to UI drift |
| `tryFill(page, candidates, value)` | Fills the first visible locator from a candidate list; returns success boolean                                                    | Form fields (email/password) have version-varying selectors; the candidate list makes the negative-login flow robust without hard failing        |
| `tryClick(page, candidates)`       | Clicks the first visible locator from a candidate list; returns success boolean                                                   | Same resilience rationale for buttons (e.g. the login submit)                                                                                    |
| `textPreview(input, max=600)`      | `sanitizeDetail` + collapse whitespace + trim + truncate                                                                          | Produces short, clean response previews for evidence without dumping raw page text                                                               |
| `sanitizeDetail(input, max=1200)`  | Strips ANSI escapes, replaces non-printable control chars with `?`, trims, truncates                                              | **Report-safety**: untrusted target output flows into terminals/HTML/JSON — neutralizing control chars prevents log/terminal injection           |

- **Notes:** A file-top `eslint-disable no-control-regex` documents the intentional control-char regex; a `/* v8 ignore */` block wraps the live-`Page` helpers (`closeJuiceShopOverlays`/`tryFill`/`tryClick`) since they are exercised by the e2e audit, not unit tests.

---

## 5. Source — custom reporter (`src/reporters/`)

### [`src/reporters/security-reporter.ts`](../src/reporters/security-reporter.ts)

- **What:** A custom Playwright `Reporter` that collects `security-finding` attachments during the run and, at the end, writes the four report artifacts.
- **Why:** Decouples detection (in tests) from reporting, producing durable deliverables for multiple audiences — machine-readable JSON, human Markdown, an interactive HTML dashboard, and SARIF for GitHub code scanning.
- **Methods:**

| Method                                | What it does                                                                                                                  | Why it exists                                                                     |
| ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- |
| `onTestEnd(test, result)`             | Parses each `security-finding` attachment into a `Finding`; malformed ones are logged and skipped (never thrown)              | Resilient collection — one bad attachment can't crash the whole report            |
| `onEnd(_result)`                      | Dedups + sorts (via [`src/findings.ts`](../src/findings.ts)) then writes the four artifacts                                   | The single fan-out point turning ephemeral test signals into durable deliverables |
| `toMarkdown(findings, url)` (private) | Renders the Markdown report — severity table, fixed methodology section, per-finding sections                                 | Human/PR-friendly summary                                                         |
| `toHtml(findings, url)` (private)     | Renders a self-contained dark dashboard (severity filters, master-detail view, `escapeHtml` for XSS safety, screenshot modal) | Stakeholder-facing interactive view that needs no server or build step            |

- **Outputs:** `findings.json`, `security-report.md`, `security-report.html`, and `security-report.sarif` (via [`src/sarif.ts`](../src/sarif.ts)).

---

## 6. Tests & runners (`tests/`)

### Testing strategy — why two tiers

Testing is split into two deliberately separated layers (scoped by glob so they
never overlap):

1. **Vitest unit tests** (`tests/unit/*.test.ts`) exercise the project's
   **security _judgment_ and report plumbing** — the pure functions that decide a
   finding's severity, map findings to SARIF, dedup/sort for reproducible output,
   sanitize untrusted text, and define the JSON contract. This logic must be
   provably correct **independent of any running target**, so it is tested fast,
   headlessly, and deterministically, and its coverage is **enforced as a gate**.
2. **Playwright end-to-end audit** (`tests/*.spec.ts`) exercises the **live
   behavior** against a running app. Because the target (OWASP Juice Shop) is
   _intentionally vulnerable_, this layer cannot meaningfully assert pass/fail —
   instead it **collects evidence** and emits structured findings for the report.

In short: unit tests prove the rules are right; the e2e audit proves the rules
run against a real app and produces an auditable deliverable.

### A. End-to-end security audit — [`tests/juice-shop-security.spec.ts`](../tests/juice-shop-security.spec.ts)

- **What:** The single Playwright spec that performs the whole authorized audit and emits each observation as a structured `Finding`.
- **Why:** The working core. Findings are **emitted as attachments** (not asserted red/green) so a run produces an auditable report; a fail-fast unreachable-target path keeps CI deterministic, and findings carry OWASP Top 10 references.
- **Details:** One `test.describe.serial`. `audit.add(finding)` pushes findings onto `testInfo.attachments`. `beforeAll` clears the reports dir (preserving `project-explanation.md`) and polls the target (`waitForTarget`, default 20s via `TARGET_WAIT_MS`); unreachable → High `TARGET-001`. Every test `test.skip`s when the target is unreachable. Heuristics (`isSensitivePathExposure`, `isLikelySpaFallback`, `isAccessBlocked`) cut false positives; `screenshotEvidence` writes full-page PNG evidence.

**The checks it performs — what each tests and the reason:**

| Check group (finding IDs)                          | What it tests                                                                                                                    | Why / OWASP rationale                                                                                                              |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Recon & inventory (`RECON-001/002`)                | Target is reachable; captures homepage screenshot, scripts, storage keys, links                                                  | Confirms scope is alive and builds an evidence baseline + attack-surface map before deeper checks                                  |
| Response headers (`HDR-001`–`HDR-009`)             | CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy, HSTS (HTTPS), CORS, cache policy, server banner                       | Defense-in-depth browser controls — **A05 Security Misconfiguration**; weak/absent headers reduce protection if another bug exists |
| Cookie & storage hygiene (`CK-000`–`CK-003`)       | HttpOnly, Secure (HTTPS only), SameSite flags on issued cookies                                                                  | Session-token protection — **A05 / A07**; flags limit theft and CSRF exposure                                                      |
| Browser form & link hygiene (`BR-001/002`)         | Password-field `autocomplete`, `target="_blank"` missing `rel=noopener`                                                          | Client-side hardening; `noopener` prevents reverse-tabnabbing via `window.opener`                                                  |
| Client-side exposure (`CLT-001/002`)               | Public source maps; secret-like strings in JS bundles                                                                            | Information/secret disclosure — **A02 Cryptographic Failures**; shipped secrets are exposed to every user                          |
| Public API & sensitive paths (`API-001`–`API-005`) | Product-search API, `/ftp` listing, a single quote-probe for verbose errors, sensitive-path spot-checks, advertised HTTP methods | Surface discovery + **A01 / A03 / A05**; exposed files/verbose errors/risky methods aid attackers (probe is non-destructive)       |
| Unauthenticated API authorization (`API-AUTH-*`)   | Protected REST/`/api` endpoints requested with **no session**                                                                    | **A01 Broken Access Control** — server-side authz must not depend on the client                                                    |
| Error handling (`ERR-001`)                         | An unknown path's response for stack traces / verbose errors vs. SPA fallback                                                    | **A05** information disclosure via error verbosity                                                                                 |
| Negative authentication (`AUTH-001`)               | One fake invalid login and the resulting UI state                                                                                | **A07 Identification & Authentication Failures**; regression evidence for login behavior (no brute force)                          |
| Input reflection (`INP-001`)                       | A unique harmless marker submitted via search, checked in rendered text                                                          | **A03 Injection** reflection signal — flags for manual XSS review without executing a payload                                      |
| Route boundaries (`AC-*`)                          | `/basket`, `/administration`, `/profile`, `/order-history` loaded unauthenticated                                                | **A01 Broken Access Control** — protected views should not render server-side data without a session                               |

### B. Unit tests (`tests/unit/`) — what each guards and why

- [`findings.test.ts`](../tests/unit/findings.test.ts) — **What:** sorting, dedup (incl. evidence merge), severity counting, ranking, and `cleanFileName`. **Why:** the report-shaping logic every consumer depends on; verifies **deterministic ordering** and **input immutability** so regenerated reports diff cleanly in CI.
- [`sarif.test.ts`](../tests/unit/sarif.test.ts) — **What:** SARIF envelope/version, one-rule-per-id, severity→level mapping, `security-severity` scoring, location derivation, stable fingerprints. **Why:** guards the **GitHub code-scanning integration contract** so findings ingest correctly and the same finding is tracked across runs.
- [`security-rules.test.ts`](../tests/unit/security-rules.test.ts) — **What:** header detection (incl. HTTPS-only gating and CSP `frame-ancestors` equivalence), CORS grading, cookie hygiene, via a `fakeContext()` stub. **Why:** this is the tool's **security judgment**; testing the conditional severity/status logic headlessly is what makes the rule set trustworthy in a gate.
- [`helpers.test.ts`](../tests/unit/helpers.test.ts) — **What:** `hashRouteUrl`, ANSI/control-char stripping, length bounding, `loadAuditConfig` defaults/invariants. **Why:** these feed target-controlled strings into reports and navigation, so this is both correctness **and a report-safety/sanitization** guarantee (no log/terminal injection).
- [`schema.test.ts`](../tests/unit/schema.test.ts) — **What:** compiles `schemas/findings.schema.json` with Ajv2020 and asserts it accepts well-formed reports and rejects bad enums, missing required fields, and unknown properties. **Why:** makes the published report format a **tested contract**, preventing schema drift from silently shipping to downstream consumers.

### [`playwright.config.ts`](../playwright.config.ts)

- **What:** Playwright runner config for the e2e audit.
- **Why:** Reproducible, CI-friendly execution — single-worker serial runs avoid racing the target, `retries:0` keeps findings honest, and `testMatch` keeps unit tests out of the Playwright run.
- **Details:** `testDir './tests'`, `testMatch '**/*.spec.ts'`, `timeout 45000`, `fullyParallel:false`, `workers:1`. Reporters: `list`, `html` (`open:'never'`), and the custom `./src/reporters/security-reporter.ts`. `use.baseURL` from `loadAuditConfig()`; single `chromium` project.

### [`vitest.config.ts`](../vitest.config.ts)

- **What:** Vitest runner config for the unit tests.
- **Why:** The quality gate — includes only the pure modules and **enforces coverage thresholds** (lines/functions/statements 85%, branches 80%), explicitly excluding the reporter (covered end-to-end by Playwright).
- **Details:** `include ['tests/unit/**/*.test.ts']`, `environment 'node'`, V8 coverage scoped to `findings.ts`, `sarif.ts`, `security-rules.ts`, `juice-shop-helpers.ts`, `config.ts`; reporters `text`/`html`/`lcov`.

---

## 7. Automation scripts (`scripts/`)

Four dependency-free Node ES-module helpers (`node scripts/*.mjs`) that surround
the audit and make the pipeline self-contained and CI-ready.

### [`scripts/local-lab.mjs`](../scripts/local-lab.mjs)

- **What:** A zero-dependency local HTTP server (`node:http`) that mimics the Juice Shop surface for offline runs.
- **Why:** A deterministic, self-hosted target so the suite runs safely in CI and on dev machines without an external vulnerable app.
- **Details:** Routes `/health`, `/rest/products/search` (returns a simulated SQLite error for a `'` query), `/ftp` (directory listing), `/security.txt`, an SPA hash-router, and a 404 fallback. HTML responses set `cache-control:no-store` and a demo cookie; input is HTML-escaped (no real XSS). Graceful shutdown on SIGINT/SIGTERM.

### [`scripts/prepare-artifacts.mjs`](../scripts/prepare-artifacts.mjs)

- **What:** Pre-creates `reports/`, `reports/evidence/`, `test-results/`, `playwright-report/`.
- **Why:** Idempotent setup that prevents "no such directory" flakiness on fresh checkouts and CI runners.
- **Details:** Loops `fs.mkdirSync(dir, { recursive: true })`.

### [`scripts/check-findings.mjs`](../scripts/check-findings.mjs)

- **What:** A severity gate that reads `findings.json` and exits non-zero when any finding meets/exceeds a configurable threshold.
- **Why:** Lets the same tooling stay **report-only** against the intentionally vulnerable lab (default) yet **block** a real pipeline on regressions — the production-readiness policy control.
- **Details:** `FAIL_ON` (`off|Info|Low|Medium|High|Critical`, default `off`) and `REPORTS_DIR` envs. Logs a per-severity summary; exits 0 when report-only or under threshold, 1 when over threshold (listing offenders) or on a missing/invalid input.

### [`scripts/report-summary.mjs`](../scripts/report-summary.mjs)

- **What:** Renders a Markdown summary (severity table + notable non-Info findings) to stdout and, in CI, to the GitHub Actions job summary.
- **Why:** Surfaces results at-a-glance on the workflow run page without downloading artifacts.
- **Details:** Reads `findings.json` (`REPORTS_DIR`); appends to `GITHUB_STEP_SUMMARY` when set; emoji severity table; first 25 notable findings; report-only footer.

---

## 8. Containerization & dev environment

A hardened, reproducible stack. The runner image and the devcontainer pin the same
Playwright base image and run as the non-root `pwuser`.

### [`Dockerfile`](../Dockerfile)

- **What:** Builds the audit-runner image.
- **Why:** A deterministic, browser-ready environment that behaves identically locally and in CI; least-privilege (non-root + pre-chowned output dirs) keeps it compatible with the read-only root filesystem enforced in compose.
- **Details:** `FROM mcr.microsoft.com/playwright:v1.60.0-noble`, layer-cached `npm ci`, creates/`chown`s `/work` output dirs, `ENV CI=true REPORTS_DIR=/work/reports`, `USER pwuser`, `CMD ["npm","run","audit"]`.

### [`compose.yaml`](../compose.yaml)

- **What:** Two services — the Juice Shop target and the audit runner — on an internal Docker network.
- **Why:** A self-contained, network-isolated environment so the vulnerable target is never exposed; container hardening shows defense-in-depth and prevents the lab from becoming an attack surface.
- **Details:** `juice-shop` uses `expose` only (not published). Both services: `no-new-privileges`, `cap_drop: ALL`. The `audit` service adds `read_only: true` rootfs with `tmpfs` scratch, `pids_limit: 512`, `mem_limit: 2g`, and bind-mounts `./reports` + `./playwright-report`. The `lab` network is `internal: true` (no egress).

### [`.devcontainer/devcontainer.json`](../.devcontainer/devcontainer.json)

- **What:** A VS Code / Codespaces dev container matching the runtime image, with Docker-in-Docker.
- **Why:** Zero-setup onboarding that matches the audit image and shares the project's lint/format/test config — removing "works on my machine" drift.
- **Details:** Same Playwright image pin, `docker-in-docker` feature, `postCreateCommand: npm ci`, preloaded ESLint/Prettier/Playwright/EditorConfig extensions, format-on-save, `remoteUser: pwuser`.

---

## 9. CI/CD & GitHub automation (`.github/`, `.husky/`)

### [`.github/workflows/audit.yml`](../.github/workflows/audit.yml)

- **What:** The primary CI pipeline — a `quality` job then, on success, a `security-audit` job running the isolated Dockerized DAST scan and publishing results.
- **Why:** The central gate: every push/PR is blocked unless format/lint/typecheck/unit tests pass, and the audit produces SARIF in the Security tab. The optional severity gate can promote the same workflow from report-only to a hard blocker without code changes.
- **Details:** Triggers on push/PR to main/master + `workflow_dispatch` (with a `fail_on` choice input). Concurrency cancels superseded runs. `quality`: `npm ci` → `format:check` → `lint` → `typecheck` → `coverage` (+ uploads coverage). `security-audit` (`needs: quality`, `security-events: write`): `docker:audit` → `audit:summary` → `audit:gate` (`FAIL_ON` from the input) → `upload-sarif` (continue-on-error) → artifact upload → `docker:down`.

### [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml)

- **What:** GitHub CodeQL static application security testing over the JS/TS code.
- **Why:** First-party SAST of the project's own code (distinct from the DAST audit); the weekly cron applies newly disclosed query patterns even without commits.
- **Details:** push/PR + weekly cron (`27 4 * * 1`); matrix `javascript-typescript`; `init` (queries `security-and-quality`) → `analyze`.

### [`.github/dependabot.yml`](../.github/dependabot.yml)

- **What:** Weekly dependency-update PRs for npm, GitHub Actions, and Docker.
- **Why:** Supply-chain hygiene — keeps dependencies and base images patched; grouping dev-dependency bumps avoids review noise.
- **Details:** Three `updates` entries; npm caps open PRs at 5 and groups dev minor/patch updates; labels per ecosystem.

### [`.github/CODEOWNERS`](../.github/CODEOWNERS)

- **What:** Default code ownership (`* @asaf-1`).
- **Why:** With branch protection, enforces owner review before merge — a governance control expected in production repos.

### [`.github/PULL_REQUEST_TEMPLATE.md`](../.github/PULL_REQUEST_TEMPLATE.md)

- **What:** Default PR body — summary, change type, verification checklist, reviewer notes.
- **Why:** Bakes the verify gate and the non-destructive safety model into the contribution flow.

### `.github/ISSUE_TEMPLATE/`

- [`bug_report.yml`](../.github/ISSUE_TEMPLATE/bug_report.yml) — structured bug form with a safety warning against pasting findings about unauthorized systems.
- [`feature_request.yml`](../.github/ISSUE_TEMPLATE/feature_request.yml) — feature form with a **required** non-destructive safety acknowledgement.
- [`config.yml`](../.github/ISSUE_TEMPLATE/config.yml) — disables blank issues and routes security reports to a private GitHub Security Advisory.

### [`.husky/pre-commit`](../.husky/pre-commit)

- **What:** A Husky v9 pre-commit hook.
- **Why:** Shifts quality enforcement to the developer's machine so broken commits never reach CI.
- **Details:** Runs `npx lint-staged` (eslint --fix + prettier on staged files), then `npm run typecheck`, then `npm run test:unit`. Installed via the `prepare` script.

---

## 10. Findings schema & report outputs

### [`schemas/findings.schema.json`](../schemas/findings.schema.json)

- **What:** A JSON Schema (Draft 2020-12) defining the structure of `reports/findings.json`.
- **Why:** A machine-readable contract that makes report generation verifiable — any validator can assert an emitted report conforms before it is trusted. Requiring `impact`/`remediation`/`evidence` makes every finding actionable.
- **Details:** Root requires `targetUrl`, `generatedAt` (date-time), `findingCount`, `findings[]` with `additionalProperties:false`. `$defs` define `severity`/`status` enums, a closed `evidence` object (only `label` required), and a closed `finding` object requiring id/title/severity/category/status/description/impact/remediation/evidence, with optional `references` (uri). Validated by [`tests/unit/schema.test.ts`](../tests/unit/schema.test.ts).

### [`reports/project-explanation.md`](../reports/project-explanation.md)

- **What:** A plain-English narrative of what the lab does, its scope, the safe-audit vs. real-pentest distinction, included/avoided checks, terminology, and commands.
- **Why:** Establishes the scope discipline and safety properties that make the lab interview-defensible; frames honest severity (including "0 Critical") as a virtue. It is the one report file kept under version control (via `.gitignore` allow-listing).

---

## 11. Documentation & repository hygiene

### [`README.md`](../README.md)

- **What:** The primary entry point and engineering showcase — what the lab does, how to run it, the safety model, the CI gates, and the project structure.
- **Why:** The first artifact a reviewer sees; ties every claim to concrete files and commands.
- **Details:** Status badges, a Mermaid architecture diagram, the command reference, the output list (incl. SARIF), the `FAIL_ON` gate, the two-job CI description, and a coverage-of-checks list.

### [`docs/SAFETY.md`](SAFETY.md)

- **What:** The explicit operational safety boundary — what the tests do and do not do, and the Docker isolation rationale.
- **Why:** Establishes the legal/ethical non-destructive guarantee essential for a security tool.

### [`docs/INTERVIEW-WALKTHROUGH.md`](INTERVIEW-WALKTHROUGH.md)

- **What:** A presentation aid — positioning, architecture, talking points, demo flow, and extension ideas.
- **Why:** Translates the design into a defensible story for the hiring-manager/engineer audience.
- **Note:** This file predates later work; two of its "extension ideas" (SARIF export and GitHub Actions CI) are **now implemented** — see [`src/sarif.ts`](../src/sarif.ts) and [`.github/workflows/`](../.github/workflows/).

### [`CONTRIBUTING.md`](../CONTRIBUTING.md)

- **What:** Onboarding — prerequisites, setup, the quality gates, and the exact workflow for adding a check.
- **Why:** Encodes the quality bar (verify gate, coverage thresholds) and the core invariant that all checks stay non-destructive.

### [`SECURITY.md`](../SECURITY.md)

- **What:** The security policy — defensive scope, authorized-use-only, and a private vulnerability-disclosure process.
- **Why:** A responsible-disclosure policy is a hallmark of a mature security project.

### [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md)

- **What:** Contributor Covenant 2.1 community standard.
- **Why:** Signals professional, inclusive project governance.

### [`CHANGELOG.md`](../CHANGELOG.md)

- **What:** Keep a Changelog / SemVer history with an Unreleased section and the 1.0.0 baseline.
- **Why:** Demonstrates disciplined release management and traces the project's evolution into a hardened, quality-gated tool.

### [`LICENSE`](../LICENSE)

- **What:** The MIT License (© 2026 Asaf Nuri).
- **Why:** Clear legal terms for reuse plus the warranty/liability disclaimer; the README scopes it to authorized, educational, and defensive use only.

---

## 12. Root tooling & configuration

| File                                        | What & why                                                                                                                                                                                    |
| ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`package.json`](../package.json)           | Manifest + scripts + devDependencies + lint-staged. Single source of truth for every workflow; the `verify` script and pre-commit hook form the CI-style quality gate. All deps are dev-only. |
| [`package-lock.json`](../package-lock.json) | Pinned, integrity-hashed lockfile for deterministic `npm ci` installs and supply-chain tamper detection. Tracked in git; ignored by Prettier.                                                 |
| [`tsconfig.json`](../tsconfig.json)         | Strict TypeScript (`strict`, `noUncheckedIndexedAccess`, ES2022, Node16, `noEmit`). Powers the `typecheck` gate.                                                                              |
| [`eslint.config.mjs`](../eslint.config.mjs) | ESLint flat config: JS + typescript-eslint recommended, custom rules (`no-explicit-any`, `eqeqeq`, `^_` unused-arg pattern), Node globals for `.mjs`, Prettier compatibility last.            |
| [`.prettierrc.json`](../.prettierrc.json)   | Canonical style (printWidth 110, single quotes, no trailing commas, LF).                                                                                                                      |
| [`.prettierignore`](../.prettierignore)     | Keeps Prettier off generated artifacts, the lockfile, and `*.sarif`.                                                                                                                          |
| [`.editorconfig`](../.editorconfig)         | Editor-level whitespace/encoding baseline (LF, UTF-8, 2-space; Markdown preserves trailing whitespace).                                                                                       |
| [`.gitignore`](../.gitignore)               | Untracks deps/artifacts and `.env`; allow-lists `reports/project-explanation.md`.                                                                                                             |
| [`.dockerignore`](../.dockerignore)         | Shrinks the Docker build context and keeps `.env`/artifacts out of images.                                                                                                                    |
| [`.env.example`](../.env.example)           | Documented env-var template (host vs. Docker target URL, image pin). Copy to `.env` (gitignored).                                                                                             |

---

_This document is maintained alongside the code. When you add a file or tool,
add a row/section here so the map stays exhaustive._

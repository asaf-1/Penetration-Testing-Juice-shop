# Production Readiness Assessment

_Last assessed: 2026-05-29. Produced via a multi-perspective review (architecture, AppSec
coverage, DevSecOps/CI, legal & safety, operability) against the repository as it stood._

## Verdict: Solid internal tool / portfolio piece — not yet a DAST for a real company's app

This project is **production-grade _engineering_ wrapped around an intentionally-vulnerable
teaching target.** The scaffolding — typed finding model, JSON/Markdown/HTML/SARIF
reporting, GitHub code-scanning upload, hardened Docker, gated CI, enforced
lint/type/coverage — is better than many real repositories and is directly reusable. The
**checks themselves are deliberately shallow smoke tests calibrated to OWASP Juice Shop.**
A clean run is evidence the harness works; it is **not** evidence that a real application is
secure.

Use it today as: a teaching tool, an interview/portfolio artifact, and a CI
security-regression harness **for Juice Shop specifically**. Do not treat it as a
general-purpose scanner for an arbitrary production system, and do not point it at a real
host until the P0 controls below exist.

## Dimension ratings

| Dimension                      | Rating                  | Why                                                                                                                                                                                                                                   |
| ------------------------------ | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Architecture & code quality    | **Solid internal tool** | Excellent CI/lint/type/coverage hygiene and a clean shared domain model — but a ~1,160-line serial spec, a ~940-line untested reporter, and a hand-maintained schema with no drift guard undercut the "single source of truth" claim. |
| AppSec coverage & methodology  | **Demo-only**           | Only OWASP A01/A02/A05/A07 are meaningfully covered; injection/XSS are token signals with near-total false-negative risk; no crawler/SCA/TLS; discovery is hardcoded Juice-Shop paths.                                                |
| DevSecOps / CI-CD              | **Demo-only**           | Pipeline mechanics are production-grade, but the product is hardwired to an ephemeral lab — no real-target plumbing, no scheduled scan, no secrets-based auth, no baseline/diff gating.                                               |
| Legal, safety & scope          | **Demo-only**           | Safe against the bundled lab, but the guardrails live in markdown, not in code: no target allowlist, no consent gate, no kill-switch/rate limit.                                                                                      |
| Operability for a real company | **Demo-only**           | Authenticated flow and most high-value probes are bound to Juice Shop's exact API/routes; no auth abstraction, no multi-env config, no cross-run triage/baseline/suppression.                                                         |

## What's genuinely strong

- **Production-grade engineering hygiene, verified green:** ESLint flat config
  (`no-explicit-any: error`), strict TS (`noUncheckedIndexedAccess`), Prettier,
  Husky + lint-staged, Vitest with enforced coverage thresholds; lint/typecheck clean,
  41/41 unit tests, 100% statement coverage on covered modules, 15/15 e2e checks.
- **Clean producer/consumer model:** `src/findings.ts` is the in-process source of truth
  imported by both the spec and the reporter, with isolated, unit-tested pure helpers
  (sort/dedup/count).
- **Correct, thoughtful SARIF → GitHub code-scanning integration:** valid SARIF 2.1.0 with
  `security-severity` scores and `partialFingerprints` for cross-run tracking.
- **Strong target isolation:** Docker compose on an `internal: true` network (no host
  port), `read_only`, `cap_drop: ALL`, `no-new-privileges`, pids/mem limits, non-root user.
- **Disciplined, honest output handling:** statuses are accurately self-deprecating
  (`manual-review` / `not-observed`); bounded evidence enforced in code (JWT lists claim
  _keys_ only, `/ftp` records status+length only, IDOR records owner UserIds only).
- **Two genuinely meaningful checks:** the authenticated basket BOLA/IDOR test and the
  header/cookie/CORS hygiene suite are real, reusable DAST signals.

## What blocks real-company production use

- **Coverage is a smoke test, not an assessment.** "SQLi" = one quote character matched
  against an error regex; "XSS" = one plaintext marker echoed in body text (no markup
  injected, execution never asserted). CSRF, SSRF, SSTI, deserialization, XXE, open
  redirect, file-upload abuse, business-logic flaws, and SCA/TLS analysis are absent.
- **Hardwired to Juice Shop.** Auth (`registerAndLogin` → `POST /api/Users` +
  `/rest/user/login`, reads `authentication.token`), IDOR (`/rest/basket/1-6`,
  `data.UserId`), routes, API endpoints, and the SPA-fallback fingerprint are all
  app-specific. On any other target most checks degrade to "not-observed" noise.
- **No scope/authorization enforcement in code.** `src/config.ts` accepts any `TARGET_URL`
  verbatim — no allowlist, no localhost/RFC1918 restriction, no consent gate. A single env
  var repoints every active probe (12-attempt login burst, IDOR enumeration, `%00`/`%2500`
  path-traversal bypass, account registration) at production with no friction.
- **No kill-switch or rate control**, and self-registered throwaway accounts
  (`pwt-token-*`, `pwt-idor-*`) are never cleaned up — unauthorized state mutation against a
  real user store.
- **No real-target DevSecOps plumbing:** no `TARGET_URL`/credential secret, no
  `environment:` gate, no scheduled scan of staging, no secrets-based authenticated
  scanning; `retries: 0` / `workers: 1` are tuned for a local container.
- **No triage model:** dedup is same-run/same-id only, no per-instance fingerprints, no
  accepted-risk baseline, no "new since last scan" diff — so gating can only pass-all or
  fail-on-absolute-count, and every run re-reports everything.
- **Untested core:** the ~940-line reporter is excluded from coverage; the schema is a
  hand-maintained copy of the TS type with no drift guard.

## Roadmap to production-usable

### P0 — must-fix before pointing at any real target

- [ ] **Fail-closed scope enforcement** in `src/config.ts`: a `TARGET_ALLOWLIST`
      (hosts/CIDRs) that `TARGET_URL` must match (default loopback/RFC1918); refuse to run
      otherwise.
- [ ] **Authorization/consent gate:** require a rules-of-engagement reference (scope,
      authorizing party, valid-until) recorded into every report; refuse to run or publish
      without it.
- [ ] **Make active/destructive probes opt-in, off by default:** gate account
      registration, the 12-attempt login burst, IDOR enumeration, and the null-byte traversal
      bypass behind explicit flags; default to passive read-only recon.
- [ ] **Kill-switch + rate control:** global request budget, per-host throttle/backoff,
      max-runtime ceiling, graceful SIGINT that flushes findings; guarantee cleanup/tagging of
      any created accounts.
- [x] **Keep SAFETY.md accurate** to current behavior (burst login, registration, IDOR
      enumeration, traversal probes). _(Done — see `docs/SAFETY.md`.)_

### P1 — required to be a credible scanner for a real app

- [ ] **Pluggable AuthProvider abstraction** (Playwright `storageState` / bearer token;
      form login, OAuth/OIDC/SSO, pre-seeded credentials) and refactor the three auth-dependent
      tests off Juice Shop's contract.
- [ ] **Externalize all target-specific paths/routes/signatures** into per-target profiles;
      mark Juice-Shop-only checks "not-applicable" rather than emitting "not-observed" noise.
- [ ] **Integrate a real DAST** (OWASP ZAP baseline/full or Nuclei) for injection/XSS; treat
      the bespoke checks as supplementary signal. Add SCA and a real TLS assessment.
- [ ] **Multi-identity, matrix authorization testing** (≥2 users + admin; read _and_ write
      BOLA; function-level authz/BFLA); parametrize object types/id ranges.
- [ ] **Baseline + diff gating:** stable per-instance fingerprints, accepted-risk/suppression
      file, "block only on NEW/regressed findings"; calibrate `FAIL_ON` against known-good/bad
      baselines and enforce it automatically on the right branch/environment.
- [ ] **Real-target CI plumbing:** `TARGET_URL`/credential secret + `environment:`
      reviewers, a scheduled (nightly/weekly) staging scan, retries/timeouts tuned for external
      hosts, and CA-trust/proxy config.

### P2 — quality, scale, and team adoption

- [ ] **Automated discovery:** crawler and/or OpenAPI/Swagger ingestion to derive endpoints
      dynamically; auth-state-driven navigation for post-login surface.
- [ ] **Schema drift guard:** generate `findings.schema.json` from the TS type (or add a
      divergence test) and validate the real `findings.json` against it.
- [ ] **Test the reporter:** remove the coverage exclusion or extract `toMarkdown`/`toHtml`;
      at minimum assert HTML-escaping to prevent dashboard injection regressions.
- [ ] **Decompose the monolith:** central typed Finding-ID registry/enum (catch
      collisions/typos), each check as a pure rule function, spec reduced to thin orchestration.
- [ ] **Findings handoff:** ticketing (Jira) + notification on new High/Critical, durable
      trend history; remove `continue-on-error` from the SARIF upload once it's a required signal.
- [ ] **Fix cross-platform gate:** align `core.autocrlf` / add `.editorconfig` so the format
      check and pre-commit hook pass consistently on Windows.

---

**Bottom line:** great engineering _around_ a teaching target — adopt the
reporting/SARIF/CI/Docker scaffolding today; do **not** treat a clean run as evidence your
real app is secure, and do **not** point it at a real host until the P0 scope/safety
controls exist.

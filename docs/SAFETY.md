# Safety Guidance

This project is safe to run **only** when it is pointed at a lab target that you own or
are explicitly authorized to test. It now performs a small number of _bounded active_
checks (account registration, a capped failed-login burst, authenticated object
enumeration, and path-traversal probes), so it must be treated as an authorized
security tool — not a passive observer.

## What The Tests Do

- Load the target in Chromium and capture screenshots.
- Send unauthenticated GET and OPTIONS requests for recon, header, and exposure checks.
- Register one or more throwaway accounts on the target (e.g. `pwt-token-*`, `pwt-idor-*`)
  and log in to obtain a session token.
- Decode — but never verify, modify, forge, or replay — the issued JWT to inspect its
  algorithm, expiry, and claim **keys** (values such as password hashes are never recorded).
- Send a small, fixed burst (12) of failed logins for a single throwaway identity to
  check for missing rate limiting / lockout.
- With one authenticated session, request a small bounded range of object ids
  (baskets 1–6) to check for broken object-level authorization (IDOR/BOLA), recording
  only the owner ids — never the record contents.
- Send a few encoded / null-byte path-traversal probes to the `/ftp` download endpoint,
  recording only the HTTP status and byte length — never the file contents.
- Submit one invalid login with fake credentials and harmless input markers to check
  reflection and error handling.
- Write local reports (JSON / Markdown / HTML / SARIF).

## What The Tests Do Not Do

- They do not scan your local network.
- They do not run unbounded password brute-force or credential-stuffing — the login
  check is a single fixed, bounded burst used only to detect missing rate limiting.
- They do not forge, tamper with, or replay authentication tokens.
- They do not read, store, or exfiltrate file contents, even when a download-allowlist
  bypass is detected (only status and byte length are recorded).
- They do not write, modify, or delete target data — the object-level checks are
  read-only GET requests.
- They do not upload files.
- They do not delete or modify files on your computer.
- They do not run system commands on the target.

## Scope And Limitations (Read Before Pointing At Anything Real)

- **There is currently no in-code target allowlist.** `TARGET_URL` is used verbatim, so
  scope enforcement is entirely your responsibility. Treat this as a known gap (see
  `docs/PRODUCTION-READINESS.md`, P0).
- **Throwaway accounts created during a run are not cleaned up.** Use an ephemeral,
  disposable target (the bundled Docker Juice Shop is ideal) so created state is discarded.
- The active checks are calibrated for an intentionally-vulnerable lab. Do **not** point
  them at a system you do not own or lack written authorization to test.

## Why Docker Is Recommended

OWASP Juice Shop is intentionally vulnerable. Running it inside Docker keeps the
vulnerable application isolated from your normal desktop environment. The provided
`compose.yaml` goes further by:

- keeping Juice Shop on an internal Docker network,
- avoiding a host port by default,
- dropping Linux capabilities where practical,
- enabling `no-new-privileges`,
- running the Playwright container with a read-only filesystem except report output mounts.

## Practical Rules

- Only point this at an ephemeral, authorized lab. The active checks create accounts and
  probe authorization and traversal behavior; never run them against systems you do not
  own or have written authorization to test.
- Do not enter real passwords, tokens, emails, or personal data into vulnerable labs.
- Do not point `TARGET_URL` at public systems without explicit permission.
- Prefer `npm.cmd run docker:audit` for repeatable interview demos.
- Delete `reports/`, `test-results/`, and `playwright-report/` if you want to clear local artifacts.

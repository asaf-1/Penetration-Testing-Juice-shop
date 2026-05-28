# Safety Guidance

This project is safe to run when it is pointed at a lab target that you own or are authorized to test.

## What The Tests Do

- Load the target in Chromium.
- Send safe unauthenticated GET and OPTIONS requests.
- Submit one invalid login attempt using fake credentials.
- Submit harmless input markers to check reflection and error handling.
- Capture screenshots and write local reports.

## What The Tests Do Not Do

- They do not scan your local network.
- They do not brute force passwords.
- They do not exploit accounts.
- They do not upload files.
- They do not delete or modify your PC files.
- They do not run system commands on the target.

## Why Docker Is Recommended

OWASP Juice Shop is intentionally vulnerable. Running it inside Docker keeps the vulnerable application isolated from your normal desktop environment. The provided `compose.yaml` goes further by:

- keeping Juice Shop on an internal Docker network,
- avoiding a host port by default,
- dropping Linux capabilities where practical,
- enabling `no-new-privileges`,
- running the Playwright container with a read-only filesystem except report output mounts.

## Practical Rules

- Do not enter real passwords, tokens, emails, or personal data into vulnerable labs.
- Do not point `TARGET_URL` at public systems without explicit permission.
- Prefer `npm.cmd run docker:audit` for repeatable interview demos.
- Delete `reports/`, `test-results/`, and `playwright-report/` if you want to clear local artifacts.

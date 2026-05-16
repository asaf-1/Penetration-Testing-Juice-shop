# Penetration Testing Project Explanation

## What This Project Is Actually Doing

This project is a controlled web security automation lab.

It does not pentest your PC. It does not scan your machine. It does not attack your network.

The only target is the configured lab URL:

```text
TARGET_URL=http://juice-shop:3000
```

Inside the Docker setup, that URL points to the OWASP Juice Shop container.

## What Is The Penetration Scope?

Scope means what we are allowed to test.

For this project, the scope is:

```text
OWASP Juice Shop inside Docker
```

Out of scope:

- your Windows host
- your LAN
- public websites
- Docker Desktop internals
- cloud accounts
- real credentials
- real users

This is important because professional pentesting always starts with clear scope.

## What The Audit Container Does

The audit container is the tester.

It runs Playwright and performs controlled checks against Juice Shop.

It does things like:

- open the app in Chromium
- visit selected pages
- send safe API requests
- check response headers
- check if certain pages are protected
- test harmless input markers
- try one fake negative login
- capture screenshots
- write findings into Markdown and JSON reports

It does not run aggressive exploitation.

## What The Juice Shop Container Does

The Juice Shop container is the target.

It is intentionally vulnerable. That is the point of the lab.

In a real penetration test, we would only test a real app with explicit permission. Here we use Juice Shop because it is built for security practice and safe demonstration.

## Safe Audit vs Real Pentest Validation

There are two levels of testing to understand.

### Safe Audit

This is what the project currently does by default.

It uses read-only or low-risk checks:

- browser navigation
- normal HTTP GET requests
- OPTIONS requests
- one fake negative login
- harmless input markers
- screenshot capture
- response/header inspection

Plain English: it looks for evidence without trying to fully break into the app.

### Pentest Validation

A real penetration test often goes one step further and proves impact.

In a lab, that could mean:

- confirming an authentication bypass
- proving an admin API exposes data
- proving another user's basket or order can be accessed
- proving a token or credential is publicly exposed
- chaining two findings together to show higher impact

Plain English: a real pentest does not only say "this looks risky." It tries to prove what an attacker could actually do, but still only inside the approved scope.

## Would High Or Critical Tests Harm My PC?

No, not if they stay inside the lab and follow the same boundaries.

High and Critical are severity labels. They describe the impact of a finding on the target application.

They do not automatically mean the test is dangerous for your computer.

Safe High/Critical-capable checks can still be read-only, for example:

- checking if an unauthenticated API returns user data
- checking if admin configuration is public
- checking if JavaScript bundles expose hardcoded secrets
- checking if public files expose credentials or tokens
- checking if CORS is dangerously open

These checks inspect lab responses. They do not need to attack Windows, Docker, your LAN, or your personal accounts.

## What Would Be Unsafe And Out Of Scope

These are the kinds of actions we avoid unless a real engagement explicitly allows them:

- brute force
- password spraying
- denial-of-service testing
- reverse shells
- malware behavior
- persistence
- destructive SQL payloads
- deleting or changing data
- attacking the host machine
- scanning networks outside the lab

Plain English: we can produce serious findings without doing unsafe behavior on your PC.

## What If The Report Shows Sensitive Data Exposure?

In this project, sensitive data exposure means Juice Shop lab data.

It does not mean your real personal data was exposed.

Examples of lab data:

- demo users
- demo emails
- demo admin configuration
- fake tokens
- intentionally exposed files
- challenge-related data

The report target tells you what system the finding belongs to:

```text
Target: http://juice-shop:3000
```

That means the finding belongs to the Docker lab target.

## When Should Something Be High Or Critical?

Severity should be based on evidence, not on wanting the report to look dramatic.

Good examples:

- `High`: unauthenticated API exposes user emails, roles, or admin data
- `High`: admin-only configuration is publicly reachable
- `High`: dangerous CORS policy exposes authenticated data
- `Critical`: public file exposes real credentials, private keys, access tokens, or password hashes
- `Critical`: a controlled lab validation proves full account takeover or command execution inside the target

For interview quality, it is better to have honest severities than fake Critical findings.

`0 Critical` is acceptable when the suite is intentionally non-destructive and the evidence does not prove Critical impact.

## Why This Is A Good Interview Setup

This setup shows professional thinking:

- target and tester are separated
- scope is clear
- tests are repeatable
- findings are documented
- evidence is captured
- the vulnerable app is isolated
- the test runner is hardened
- the test behavior is non-destructive
- the report explains impact and remediation

That is more professional than just running random payloads manually.

## What Kind Of Penetration Checks Are Included?

### Reconnaissance

The suite confirms the target is reachable and captures a homepage screenshot.

Plain English: first we prove the target is alive and document what we saw.

### Security Header Review

The suite checks headers such as:

- `Content-Security-Policy`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Strict-Transport-Security`

Plain English: these are browser security controls. Missing headers are not always critical alone, but they reduce defense-in-depth.

### Access Control Checks

The suite visits routes and APIs that may require authentication.

Plain English: it checks whether unauthenticated users can reach pages or API resources that should be protected.

### API Surface Checks

The suite checks public endpoints like:

- `/rest/products/search`
- `/ftp`
- `/api-docs`

Plain English: it looks for exposed API behavior and public file listings.

### Static Asset Checks

The suite samples JavaScript bundles and source-map candidates.

Plain English: it checks whether production client code exposes extra source details or secret-like strings.

### Input Handling Checks

The suite sends harmless input markers and a simple quote character to selected endpoints.

Plain English: it checks whether the app reflects input or leaks verbose errors. This is not destructive SQL injection exploitation.

### Session And Browser Hygiene Checks

The suite reviews cookie flags, password field attributes, and external new-tab links.

Plain English: it checks browser-side hardening details that can reduce attack impact.

### Evidence Collection

The suite saves screenshots and report data.

Plain English: findings are not just claims. They include evidence.

## What We Intentionally Avoid

This project avoids high-risk pentest actions:

- brute force
- credential stuffing
- password spraying
- destructive payloads
- malware behavior
- shell payloads
- persistence
- lateral movement
- host exploitation
- network scanning
- denial of service
- high-volume fuzzing

That is why it is appropriate for a local interview lab.

## What The Report Means

The report is about the Juice Shop lab target only.

Example:

```text
Target: http://juice-shop:3000
```

That means every finding belongs to that Docker target.

## Key Terms For This Project

### Target

The system being tested. Here: Juice Shop.

### Scope

The allowed test boundary. Here: only the lab target.

### Finding

A security observation found by the test.

### Severity

How important the finding is. Examples: `Medium`, `Low`, `Info`.

### Evidence

Proof attached to a finding. Examples: screenshot, status code, response preview.

### Remediation

How to fix the issue.

### Non-Destructive Testing

Testing that does not damage the target or host.

### False Positive

A finding that looks suspicious but may not be a real vulnerability.

### Manual Review

A human should verify the result before treating it as a confirmed vulnerability.

## Commands

Run the Docker audit:

```powershell
npm.cmd run docker:audit
```

Stop and remove the lab containers:

```powershell
npm.cmd run docker:down
```

Run TypeScript validation:

```powershell
npm.cmd run typecheck
```

## One-Sentence Interview Explanation

I built a Docker-isolated Playwright security automation framework that runs non-destructive checks against OWASP Juice Shop, captures evidence, and generates structured findings with severity, impact, and remediation.

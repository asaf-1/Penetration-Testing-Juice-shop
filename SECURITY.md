# Security Policy

## Scope and intent

This repository is a **defensive, educational security-automation lab**. It runs
non-destructive, read-only checks (safe `GET`/`OPTIONS` requests, browser
navigation, a single negative-login attempt, and harmless input markers) against
an intentionally vulnerable target — OWASP Juice Shop — running on an isolated
Docker network.

It is **not** an offensive tool. It performs no brute force, exploitation,
account takeover, data exfiltration, or destructive actions. See
[docs/SAFETY.md](docs/SAFETY.md) for the full safety model.

## Authorized use only

Only run this automation against:

- the bundled Docker lab,
- your own local OWASP Juice Shop instance, or
- systems for which you have **explicit, written authorization** to test.

Running security automation against systems you do not own or have permission to
test may be illegal.

## Reporting a vulnerability

If you find a security issue **in this project's own code or configuration**
(for example, the runner, reporter, or Docker setup), please report it privately:

1. Open a [GitHub Security Advisory](https://github.com/asaf-1/Penetration-Testing-Juice-shop/security/advisories/new)
   (preferred), or
2. email the maintainer listed in the repository profile.

Please do **not** open a public issue for an undisclosed vulnerability. We aim to
acknowledge reports within **5 business days** and to provide a remediation
timeline after triage.

## Supported versions

This is an actively developed demonstration project; only the latest `main`
branch is supported.

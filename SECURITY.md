# Security Policy

## Supported versions

Only the latest minor release receives security fixes. Older releases are not patched.

| Version | Supported          |
|---------|--------------------|
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Email the maintainer directly: see the contact link on the GitHub profile (https://github.com/Krimex1).

You can expect:

1. An acknowledgement within 72 hours.
2. A triage and impact assessment within 7 days.
3. A coordinated disclosure timeline — usually a fix is shipped before the report is made public.

Please include in your report:

- A clear description of the issue and its impact
- Steps to reproduce (preferably against `example.com` or a target you own)
- The SC Checker version (`Help` → `About`, or `internal/config/config.go` → `Version`)
- Any relevant log output (in-app log tab, or stdout for console builds)

## Scope

In-scope reports cover issues in the SC Checker Go codebase itself, including:

- Remote code execution or arbitrary file access via crafted plugin files, DSL rules, or webhook payloads
- TLS/verification bypass in the updater or HTTP client
- Encryption key handling, on-disk secret storage, or permission issues
- Sandbox escapes in the plugin system (exec plugins, JSON plugins)

Issues in **target systems** you scan with SC Checker are out of scope — those belong to the target's own security team.

## Out of scope

- Denial-of-service against the local scanner (closing the GUI counts as a self-DoS)
- Rate-limiting, WAF detection, or other defensive responses from third-party servers
- Findings that depend on the user pointing the scanner at a malicious target by hand
- Theoretical issues without a concrete reproduction

## Safe harbour

We will not pursue legal action against researchers who:

- Make a good-faith effort to avoid privacy violations and data destruction
- Only interact with accounts they own or have explicit permission to test
- Stop testing immediately if they encounter unintended user data and report it
- Give us a reasonable window to fix the issue before public disclosure

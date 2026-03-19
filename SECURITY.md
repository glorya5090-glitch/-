# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability, do **not** open a public GitHub issue.

Use one of these private channels:

1. GitHub Private Vulnerability Reporting for this repository (preferred).
2. If private reporting is unavailable, contact the repository maintainers directly and request an encrypted channel before sharing details.

## What to include in your report

- affected component(s) and version/commit
- vulnerability type and impact
- clear reproduction steps or proof-of-concept
- required privileges/assumptions
- suggested remediation (if available)

Please redact private keys, seed phrases, access tokens, and personal data.

## Response targets

- initial triage acknowledgment: within 3 business days
- status update after validation: within 7 business days
- target remediation timeline: based on severity and exploitability

## Disclosure policy

- We follow coordinated disclosure.
- Please do not disclose publicly until a fix is released and maintainers confirm disclosure timing.
- Once fixed, we may publish a security advisory and release notes.

## Scope notes

Security reports may include, but are not limited to:

- key management and secret handling
- signing, approval, and policy-bypass issues
- privilege escalation in daemon/CLI flows
- insecure defaults, auth bypass, replay, or injection paths
- supply-chain and dependency risks with practical impact

Out-of-scope examples (unless chained with exploitable impact):

- purely theoretical issues without practical exploit path
- missing best-practice headers in non-sensitive local interfaces
- vulnerabilities in third-party services not controlled by this project

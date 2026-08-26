# Security Policy

## Supported Versions

This repository currently treats the latest `main` branch and tagged release candidates as supported.

## Reporting a Vulnerability

Do not open a public issue for suspected leaks, redaction bypasses, unsafe dynamic probing behavior, credential exposure, or dependency vulnerabilities.

Use GitHub Private Vulnerability Reporting when it is enabled:

1. Open this repository's **Security** tab.
2. Open **Advisories**.
3. Select **Report a vulnerability** and create a private report.

If **Report a vulnerability** is not available, do not place technical details in an issue or discussion. Use only a private maintainer contact that the repository owner has actually published. Repository owners should enable **Settings > Code security and analysis > Private vulnerability reporting** before a public release. This policy intentionally does not invent an email address or external reporting URL.

Please include:

- A minimal reproduction.
- The affected command, MCP tool, or report format.
- The expected sanitized output and the observed raw output.
- Environment details, including Python version and operating system.
- Whether the target was localhost, owned, or explicitly authorized.
- A proposed disclosure timeline, if coordinated disclosure is needed.

## Handling Expectations

- Critical leak reports should receive initial triage within 2 business days.
- Confirmed leak paths should block release until fixed and covered by regression tests.
- Fixes must include a redaction or probe regression test where feasible.

## Safe Research Rules

- Do not test against third-party systems without authorization.
- Dynamic probe issues should be reproduced on localhost or an owned test service.
- Do not publish real personal data or live secrets in reports.

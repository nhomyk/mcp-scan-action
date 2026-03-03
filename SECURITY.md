# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| v1.x    | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in this action, please report it responsibly:

1. **Do not** open a public issue
2. Email **nickhomyk@gmail.com** with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
3. You will receive a response within 48 hours
4. A fix will be released as a patch version and the `v1` tag will be updated

## Scope

This action performs static analysis only. It does not execute scanned code, make network requests to external services, or access credentials. The scan runs in the GitHub Actions runner environment with the permissions granted to the workflow.

## Dependencies

This action installs `agenticqa` from PyPI at runtime. We pin to known-good versions and monitor for supply chain risks via Dependabot and CodeQL.

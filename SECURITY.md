# Security Policy

sentinel-inject is a security-focused library. We treat vulnerability reports as high priority.

## Supported versions

The latest release on `main` is actively supported. Older releases may not receive security fixes.

## Responsible disclosure

Please do not report vulnerabilities through public GitHub issues, discussions, or pull requests.

Report privately by emailing: **security@sentinel-inject.dev**

Include the following details:

- Vulnerability type and impact
- Affected package(s): Python, TypeScript, or both
- Affected version(s)
- Reproduction steps or proof-of-concept
- Suggested remediation (if available)

We aim to:

- Acknowledge reports within 72 hours
- Provide an initial triage update within 7 days
- Coordinate a fix and disclosure timeline with the reporter

## Scope

In scope:

- Bypasses in detection or sanitization logic that materially reduce protection
- Vulnerabilities in package publishing, dependency handling, or release workflow
- Injection, code execution, or data exposure issues in library code or official integrations
- Security issues in default middleware behavior and observability/audit trail handling

Out of scope:

- False positives or false negatives without a clear, reproducible security impact
- Misconfiguration in downstream applications using sentinel-inject
- Vulnerabilities in third-party services or SDKs not caused by this project
- Denial of service requiring unrealistic resource abuse with no practical exploit path

## Disclosure policy

After a fix is available, maintainers will publish a coordinated advisory and release notes entry. Please avoid public disclosure until a fix or mitigation is released.

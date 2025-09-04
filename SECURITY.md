
# Security Policy

## Reporting a Vulnerability

If you believe you have found a security vulnerability, **do not** open a public issue. Instead, email:

**security@example.com** (preferred)  
Subject line: `SIGNET-PQC: Potential Vulnerability`

Please include:
- A clear description (impact, affected component, version/commit)
- Steps to reproduce / PoC
- Any suggested remediation

Optionally encrypt your report with our GPG key:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v2

mQENBGVzExampleFakeKeyMaterialOnlyForDocPurposesuQENB...
-----END PGP PUBLIC KEY BLOCK-----
```

## Disclosure Timeline Targets

| Phase | Target SLA |
|-------|------------|
| Acknowledge receipt | 3 business days |
| Initial assessment / severity rating | 7 days |
| Fix or mitigation for High/Critical | 30 days |
| Fix for Medium | 60 days |
| Fix for Low | 90 days |

If a coordinated disclosure date is needed, we will negotiate reasonably with the reporter.

## Supported Versions

At this MVP stage only the `main` branch (latest commit) is supported for security fixes.

## Security Tooling

Automated supply-chain & vulnerability checks:
- Dependabot (weekly) for `pip` & GitHub Actions
- (Planned) `osv-scanner` & Bandit via `make security`

## Safe Harbor

We will not pursue legal action for good-faith security research that respects user privacy and does not lead to data destruction or service disruption.


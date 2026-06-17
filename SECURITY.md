# Security Policy

## Supported Versions

Proteos is in a pre-release (`0.x`) phase. Until `1.0.0`, only the latest released
version receives security fixes.

| Version | Supported |
|---------|-----------|
| `0.1.x` | ✅ (latest pre-release) |
| `< 0.1` | ❌ |

## Audit Status

Proteos.Encryption has not undergone an independent third-party security audit. Its design uses
standard, well-reviewed primitives (AES-256-GCM, HKDF-SHA256, HMAC-SHA256) and is covered by unit,
negative and known-answer tests, but the implementation has not been formally reviewed by an external
party. Evaluate it against your own requirements before relying on it for sensitive data.

The [threat model](docs/threat-model.md) documents what Proteos does and does not protect against.

## Reporting a Vulnerability

**Do not open a public GitHub issue, pull request, or discussion for security reports.**
Public disclosure before a fix is available puts every user at risk.

Report vulnerabilities privately by email to:

```
admin@proteos.de
```

Please include:

- a description of the issue and its impact,
- the affected package and version,
- steps to reproduce or a proof of concept,
- any suggested mitigation, if known.

## Responsible Disclosure

- We will acknowledge your report within a reasonable time and keep you updated on progress.
- Please give us a reasonable window to investigate and release a fix before any public disclosure.
- We will credit reporters who follow responsible disclosure, unless you prefer to remain anonymous.

## Security Contact

Security reports go to the maintainer, **Georgios Smyrlis**, at:

```
admin@proteos.de
```

This address is for security reports only. For non-security questions, use the normal
public channels.

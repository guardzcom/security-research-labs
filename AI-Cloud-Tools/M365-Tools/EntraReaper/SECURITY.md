# Security Policy

## Responsible Disclosure

If you discover a security vulnerability in EntraReaper itself (not in AADInternals or Microsoft Entra ID), we appreciate your help in disclosing it responsibly.

## Reporting a Vulnerability

**DO report:**

- Command injection bypasses in the PowerShell bridge (`bridge.py`)
- Token store leaks or cross-engagement token contamination
- OPSEC budget bypass (tools executing without budget check)
- Engagement data exposure (tokens, credentials, or loot accessible outside intended scope)
- Injection vulnerabilities in the MCP tool parameter handling
- Dependency vulnerabilities that affect EntraReaper's security posture

**DO NOT report:**

- Vulnerabilities in AADInternals itself -- report those to [Gerenios/AADInternals](https://github.com/Gerenios/AADInternals/issues)
- Vulnerabilities in Microsoft Entra ID -- report those to [MSRC](https://msrc.microsoft.com/create-report)
- Vulnerabilities in the MCP protocol or FastMCP framework -- report those to the respective maintainers
- "This tool can be used for malicious purposes" -- it is a red team tool by design

## How to Report

1. **Email:** [PLACEHOLDER -- add your security contact email]
2. **GitHub:** Open a [security advisory](../../security/advisories/new) (private by default)

Include in your report:

- Description of the vulnerability
- Steps to reproduce
- Impact assessment
- Suggested fix (if you have one)

## Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial assessment:** Within 7 days
- **Fix or mitigation:** Within 30 days for critical issues

## Scope

This policy applies to the EntraReaper codebase only:

- `server.py`, `bridge.py`, `token_store.py`, `opsec.py`, `opsec_governor.py`
- `evasion.py`, `analyzer.py`, `reporter.py`, `engagement_store.py`, `ioc_store.py`
- `compat.ps1`, `install.sh`, and configuration files

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.1.x   | Yes       |
| < 2.1   | No        |

## Recognition

We maintain a list of security researchers who have responsibly disclosed vulnerabilities. If you report a valid issue, we will credit you (with your permission) in the release notes.

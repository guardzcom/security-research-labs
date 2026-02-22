# Security Research Labs - Tools & Scripts

**Tools, scripts, and research PoCs for Purple Team, Red Team, AI Security, Forensic, and Cloud security. Authorized use only.**

[![GitHub stars](https://img.shields.io/github/stars/guardzcom/security-research-labs)](https://github.com/guardzcom/security-research-labs/stargazers)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/guardzcom/security-research-labs)](https://github.com/guardzcom/security-research-labs/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tools](https://img.shields.io/badge/tools-8-orange)](.)
[![Platform](https://img.shields.io/badge/Platform-Web%20%7C%20Windows%20%7C%20macOS%20%7C%20Linux-green)](.)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://docs.microsoft.com/powershell/)

Security Research Labs is the official Guardz repo for open-source security tooling: config analyzers, Microsoft 365 / Entra recon scripts, purple-team detection emulations, and AI skill security. MIT-licensed; each tool lives in a **dedicated folder with its own README**.

## GitHub Stats

Dynamic badges from the GitHub API (via [Shields.io](https://shields.io)) update automatically.

[![GitHub stars](https://img.shields.io/github/stars/guardzcom/security-research-labs?style=flat-square)](https://github.com/guardzcom/security-research-labs/stargazers) [![GitHub forks](https://img.shields.io/github/forks/guardzcom/security-research-labs?style=flat-square)](https://github.com/guardzcom/security-research-labs/forks) [![GitHub issues](https://img.shields.io/github/issues/guardzcom/security-research-labs?style=flat-square)](https://github.com/guardzcom/security-research-labs/issues) [![GitHub language count](https://img.shields.io/github/languages/count/guardzcom/security-research-labs?style=flat-square)](https://github.com/guardzcom/security-research-labs)

<details>
<summary><b>Contents</b></summary>

- <a href="#github-stats" target="_blank" rel="noopener noreferrer">GitHub Stats</a>
- <a href="#repository-layout" target="_blank" rel="noopener noreferrer">Repository layout</a>
- <a href="#who-its-for" target="_blank" rel="noopener noreferrer">Who it's for</a>
- <a href="#security-model-important" target="_blank" rel="noopener noreferrer">Security model</a>
- <a href="#support--community" target="_blank" rel="noopener noreferrer">Support & community</a>
- <a href="#license" target="_blank" rel="noopener noreferrer">License</a>

</details>

---

## Repository layout

| Folder | Contents |
|--------|----------|
| <a href="AI-Tools/" target="_blank" rel="noopener noreferrer">AI-Tools/</a> | AI security: OpenClaw Analyzer (config analysis), SkillScan (skill file/URL security scanning). |
| <a href="PurpleTeam-Emulation/" target="_blank" rel="noopener noreferrer">PurpleTeam-Emulation/</a> | Purple team / detection testing: Endpoint (certutil, EDR telemetry simulator, Office macro tampering emulation). |
| <a href="M365/" target="_blank" rel="noopener noreferrer">M365/</a> | Microsoft 365 / Entra: DeviceStrike, SPO Ext Recon, GraphRunner QuickStart. |
| <a href="GWS/" target="_blank" rel="noopener noreferrer">GWS/</a> | Google Workspace security tools (placeholder). |
| <a href="Threat-Hunting/" target="_blank" rel="noopener noreferrer">Threat-Hunting/</a> | IOCs, detection artifacts, threat intelligence (IOCs placeholder). |

**For teams that rely on the same caliber of intelligence and tooling as** <a href="https://www.microsoft.com/en-us/security/business/threat-intelligence" target="_blank" rel="noopener noreferrer">Microsoft Threat Intelligence</a> <a href="https://github.com/microsoft/msticpy" target="_blank" rel="noopener noreferrer">GitHub</a>, <a href="https://www.mandiant.com/" target="_blank" rel="noopener noreferrer">Mandiant</a> Google Cloud <a href="https://github.com/google/mandiant-ti-client" target="_blank" rel="noopener noreferrer">GitHub</a>, and <a href="https://www.anthropic.com/" target="_blank" rel="noopener noreferrer">Anthropic</a> <a href="https://github.com/anthropics" target="_blank" rel="noopener noreferrer">GitHub</a> open, actionable tools for defenders, red teams, and AI security.

---

## Who it's for

| Audience | Use case |
|----------|----------|
| **Cloud Security** | Microsoft 365 and Google Workspace. |
| **AI security** | Securing AI assistants and agents: config hardening, exposure detection, supply-chain and skill safety. |
| **Purple team** | Hardening checks, config review, detection-oriented recon. |
| **Red team** | Authorized recon, token flows, M365/cloud attack-surface mapping. |
| **Forensic** | Evidence gathering, mailbox/SharePoint/Teams search patterns, audit trails. |


Use only on systems and tenants you **own** or have **explicit permission** to test.

---

## Security model (important)

- **Authorized use only.** These tools are for security research, authorized testing, and defensive operations. Use them only on systems and tenants you **own** or have **explicit permission** to test.
- **No misuse.** Do not use this repo to gain unauthorized access, exfiltrate data, or violate laws or organizational policies. Misuse is your responsibility.
- **Operational risk.** Recon and auth scripts can trigger alerts or rate limits. Coordinate with stakeholders and follow change management where required.
- **Data handling.** Output may contain sensitive information. Handle and retain it according to your classification and retention policies.

By using this repository you agree to use it in a lawful and authorized manner. See <a href="SECURITY.md" target="_blank" rel="noopener noreferrer">SECURITY.md</a> for how to report vulnerabilities in the repo itself.

---

## Support & community

- **Bugs and features:** <a href="https://github.com/guardzcom/security-research-labs/issues" target="_blank" rel="noopener noreferrer">Open an issue</a>. Use the issue templates when possible.
- **Security vulnerabilities:** Do **not** report in public issues. See <a href="SECURITY.md" target="_blank" rel="noopener noreferrer">SECURITY.md</a> for private reporting.
- **Discussions:** Use <a href="https://github.com/guardzcom/security-research-labs/discussions" target="_blank" rel="noopener noreferrer">GitHub Discussions</a> for questions and ideas if enabled; otherwise open an issue.
- **Contributions:** Pull requests welcome. Read <a href="CONTRIBUTING.md" target="_blank" rel="noopener noreferrer">CONTRIBUTING.md</a> and <a href="CODE_OF_CONDUCT.md" target="_blank" rel="noopener noreferrer">CODE_OF_CONDUCT.md</a> first.

We do not provide formal SLAs or commercial support; we respond when we can.

---

## License

<a href="LICENSE" target="_blank" rel="noopener noreferrer">MIT License</a>. Subdirectories may contain their own license files; where present, they apply to that project.

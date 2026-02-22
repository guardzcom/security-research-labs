# Security Research Labs - Tools & Scripts

**Tools, scripts, and research PoCs for Blue Team, Red Team, AI Security, Forensic, and Cloud security. Authorized use only.**

[![GitHub stars](https://img.shields.io/github/stars/guardzcom/security-research-labs)](https://github.com/guardzcom/security-research-labs/stargazers)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/guardzcom/security-research-labs)](https://github.com/guardzcom/security-research-labs/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tools](https://img.shields.io/badge/tools-8-orange)](#all-tools-and-scripts)
[![Platform](https://img.shields.io/badge/Platform-Web%20%7C%20Windows%20%7C%20macOS%20%7C%20Linux-green)](.)
[![Discord](https://img.shields.io/badge/Discord-Community-5865F2?logo=discord)](https://github.com/guardzcom/security-research-labs/discussions)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://docs.microsoft.com/powershell/)

Security Research Labs is the official Guardz repo for open-source security tooling: config analyzers, Microsoft 365 / Entra recon scripts, purple-team detection emulations, and AI skill security. MIT-licensed; each tool lives in a **dedicated folder with its own README**.

<details>
<summary><b>Contents</b></summary>

- <a href="#repository-layout" target="_blank" rel="noopener noreferrer">Repository layout</a>
- <a href="#all-tools-and-scripts" target="_blank" rel="noopener noreferrer">All tools and scripts</a>
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
| <a href="BlueTeam-Emulation/" target="_blank" rel="noopener noreferrer">BlueTeam-Emulation/</a> | Purple team / detection testing: Endpoint (certutil, EDR telemetry simulator, Office macro tampering emulation). |
| <a href="M365/" target="_blank" rel="noopener noreferrer">M365/</a> | Microsoft 365 / Entra: DeviceStrike, SPO Ext Recon, GraphRunner QuickStart. |
| <a href="Cloud-Tools-Scrips/" target="_blank" rel="noopener noreferrer">Cloud-Tools-Scrips/</a> | Cloud security tools and scripts (placeholder). |
| <a href="GWS/" target="_blank" rel="noopener noreferrer">GWS/</a> | Google Workspace security tools (placeholder). |
| <a href="Threat-Hunting/" target="_blank" rel="noopener noreferrer">Threat-Hunting/</a> | IOCs, detection artifacts, threat intelligence (IOCs placeholder). |

---

## All tools and scripts

| Tool | Description |
|------|-------------|
| <a href="AI-Tools/OpenClaw-Analyzer/openclaw-security-analyzer/" target="_blank" rel="noopener noreferrer">OpenClaw Analyzer</a> | Analyze OpenClaw configs: 68-point checklist, risk detection, attack path viz. Single HTML file, client-side. |
| <a href="AI-Tools/skillscan/" target="_blank" rel="noopener noreferrer">SkillScan</a> | Scan skill files and URLs for malicious patterns: prompt injection, suspicious URLs, code execution, obfuscation. CLI and web. |
| <a href="BlueTeam-Emulation/Endpoint/certutil-emulation/" target="_blank" rel="noopener noreferrer">Certutil Emulation</a> | Emulate certutil -encode for EDR/SIEM detection testing; output to %TEMP%, refuses admin. |
| <a href="BlueTeam-Emulation/Endpoint/edr-telemetry-simulator/" target="_blank" rel="noopener noreferrer">EDR Telemetry Simulator</a> | Controlled API telemetry for EDR/AV/SIEM validation; harmless keylogger/process/network patterns. |
| <a href="BlueTeam-Emulation/Endpoint/office-macro-tampering-emulation/" target="_blank" rel="noopener noreferrer">Office Macro Emulation</a> | Registry activity mimicking Office macro-security tampering (sandbox path) for detection testing. |
| <a href="M365/device-strike/" target="_blank" rel="noopener noreferrer">DeviceStrike</a> | OAuth2 device-code flow for Microsoft Graph; optional token refresh. |
| <a href="M365/spo-ext-recon/" target="_blank" rel="noopener noreferrer">SPO Ext Recon</a> | SharePoint Online & OneDrive recon: site paths, anonymous access, metadata API. |
| <a href="M365/graphrunner-quickstart/" target="_blank" rel="noopener noreferrer">GraphRunner QuickStart</a> | Cookbook for <a href="https://github.com/dafthack/GraphRunner" target="_blank" rel="noopener noreferrer">GraphRunner</a>: auth, recon, CAPs, search. |

**For teams that rely on the same caliber of intelligence and tooling as** <a href="https://www.microsoft.com/en-us/security/business/threat-intelligence" target="_blank" rel="noopener noreferrer">Microsoft Threat Intelligence</a>, <a href="https://www.mandiant.com/" target="_blank" rel="noopener noreferrer">Mandiant</a> (Google Cloud), and <a href="https://www.anthropic.com/" target="_blank" rel="noopener noreferrer">Anthropic</a> — open, actionable tools for defenders, red teams, and AI security.

---

## Who it's for

| Audience | Use case |
|----------|----------|
| **Cloud Security** | Microsoft 365 and Google Workspace. |
| **AI security** | Securing AI assistants and agents: config hardening, exposure detection, supply-chain and skill safety. |
| **Blue team** | Hardening checks, config review, detection-oriented recon. |
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

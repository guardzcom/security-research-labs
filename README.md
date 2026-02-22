# Security Research Labs - Tools & Scripts

**Tools, scripts, and research PoCs for Blue Team, Red Team, AI Security, Forensic, and Cloud security. Authorized use only.**

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/guardzcom/security-research-labs)](https://github.com/guardzcom/security-research-labs/releases)
[![Discord](https://img.shields.io/badge/Discord-Community-5865F2?logo=discord)](https://github.com/guardzcom/security-research-labs/discussions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://docs.microsoft.com/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Web%20%7C%20Windows%20%7C%20macOS%20%7C%20Linux-green)](.)

Security Research Labs is the official Guardz repo for open-source security tooling: config analyzers, Microsoft 365 / Entra recon scripts, and purple-team detection emulations. Everything is MIT-licensed and maintained for defenders, red teams, and incident responders. Each tool or script lives in a **dedicated folder with its own README**.

---

## Repository layout

| Folder | Contents |
|--------|----------|
| [AI-Tools/](AI-Tools/) | AI security: OpenClaw Analyzer (config analysis), SkillScan (skill file/URL security scanning). |
| [BlueTeam-Emulation/](BlueTeam-Emulation/) | Purple team / detection testing: Endpoint (certutil, EDR telemetry simulator, Office macro tampering emulation). |
| [M365/](M365/) | Microsoft 365 / Entra: DeviceStrike, SPO Ext Recon, GraphRunner QuickStart. |
| [Cloud-Tools-Scrips/](Cloud-Tools-Scrips/) | Cloud security tools and scripts (placeholder). |
| [GWS/](GWS/) | Google Workspace security tools (placeholder). |

---

## All tools and scripts

| Tool | Description |
|------|-------------|
| [OpenClaw Analyzer](AI-Tools/OpenClaw-Analyzer/openclaw-security-analyzer/) | Analyze OpenClaw configs: 68-point checklist, risk detection, attack path viz. Single HTML file, client-side. |
| [SkillScan](AI-Tools/skillscan/) | Scan skill files and URLs for malicious patterns: prompt injection, suspicious URLs, code execution, obfuscation. CLI and web. |
| [Certutil Emulation](BlueTeam-Emulation/Endpoint/certutil-emulation/) | Emulate certutil -encode for EDR/SIEM detection testing; output to %TEMP%, refuses admin. |
| [EDR Telemetry Simulator](BlueTeam-Emulation/Endpoint/edr-telemetry-simulator/) | Controlled API telemetry for EDR/AV/SIEM validation; harmless keylogger/process/network patterns. |
| [Office Macro Emulation](BlueTeam-Emulation/Endpoint/office-macro-tampering-emulation/) | Registry activity mimicking Office macro-security tampering (sandbox path) for detection testing. |
| [DeviceStrike](M365/device-strike/) | OAuth2 device-code flow for Microsoft Graph; optional token refresh. |
| [SPO Ext Recon](M365/spo-ext-recon/) | SharePoint Online & OneDrive recon: site paths, anonymous access, metadata API. |
| [GraphRunner QuickStart](M365/graphrunner-quickstart/) | Cookbook for [GraphRunner](https://github.com/dafthack/GraphRunner): auth, recon, CAPs, search. |

---

## Who it's for

| Audience | Use case |
|----------|----------|
| **Blue team** | Hardening checks, config review, detection-oriented recon. |
| **Red team** | Authorized recon, token flows, M365/cloud attack-surface mapping. |
| **DFIR** | Evidence gathering, mailbox/SharePoint/Teams search patterns, audit trails. |
| **Cloud / M365 sec** | Entra ID, SharePoint, OneDrive, Conditional Access, app consent review. |
| **AI security** | Securing AI assistants and agents: config hardening, exposure detection, supply-chain and skill safety. |


Use only on systems and tenants you **own** or have **explicit permission** to test.

---

## Security model (important)

- **Authorized use only.** These tools are for security research, authorized testing, and defensive operations. Use them only on systems and tenants you **own** or have **explicit permission** to test.
- **No misuse.** Do not use this repo to gain unauthorized access, exfiltrate data, or violate laws or organizational policies. Misuse is your responsibility.
- **Operational risk.** Recon and auth scripts can trigger alerts or rate limits. Coordinate with stakeholders and follow change management where required.
- **Data handling.** Output may contain sensitive information. Handle and retain it according to your classification and retention policies.

By using this repository you agree to use it in a lawful and authorized manner. See [SECURITY.md](SECURITY.md) for how to report vulnerabilities in the repo itself.

---

## Support & community

- **Bugs and features:** [Open an issue](https://github.com/guardzcom/security-research-labs/issues). Use the issue templates when possible.
- **Security vulnerabilities:** Do **not** report in public issues. See [SECURITY.md](SECURITY.md) for private reporting.
- **Discussions:** Use [GitHub Discussions](https://github.com/guardzcom/security-research-labs/discussions) for questions and ideas if enabled; otherwise open an issue.
- **Contributions:** Pull requests welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) first.

We do not provide formal SLAs or commercial support; we respond when we can.

---

## License

[MIT License](LICENSE). Subdirectories may contain their own license files; where present, they apply to that project.

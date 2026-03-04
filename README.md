# Security Research Labs 

**Tools, scripts, and research PoCs for Purple Team, Red Team, AI Security, Forensic, and Cloud security. Authorized use only.**

[![GitHub stars](https://img.shields.io/github/stars/guardzcom/security-research-labs)](https://github.com/guardzcom/security-research-labs/stargazers)
[![GitHub release (latest by date)](https://img.shields.io/github/v/release/guardzcom/security-research-labs)](https://github.com/guardzcom/security-research-labs/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Tools](https://img.shields.io/badge/tools-8-orange)](.)
[![Platform](https://img.shields.io/badge/Platform-Web%20%7C%20Windows%20%7C%20macOS%20%7C%20Linux-green)](.)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://docs.microsoft.com/powershell/)

[![AI Security](https://img.shields.io/badge/AI%20Security-OpenClaw%20%7C%20SkillScan-orange?style=flat-square)](AI-Tools/) [![Purple Team](https://img.shields.io/badge/Purple%20Team-Detection%20testing-purple?style=flat-square)](Purple-Team-Emulation/) [![M365](https://img.shields.io/badge/M365-Entra%20%7C%20Graph-blue?style=flat-square)](CloudAdversary/M365/) [![Threat Intel](https://img.shields.io/badge/Threat%20Intel-IOCs%20%7C%20Hunting-red?style=flat-square)](Threat-Intel/) [![GWS](https://img.shields.io/badge/GWS-Google%20Workspace-green?style=flat-square)](Purple-Team-Emulation/GWS/)

Security Research Labs is the official Guardz repo for open-source security tooling: config analyzers, Microsoft 365 / Entra recon scripts, purple-team detection emulations, and AI skill security. MIT-licensed; each tool lives in a **dedicated folder with its own README**.

## GitHub Stats

Dynamic badges from the GitHub API (via [Shields.io](https://shields.io)) update automatically.

[![GitHub stars](https://img.shields.io/github/stars/guardzcom/security-research-labs?style=flat-square)](https://github.com/guardzcom/security-research-labs/stargazers) [![GitHub forks](https://img.shields.io/github/forks/guardzcom/security-research-labs?style=flat-square)](https://github.com/guardzcom/security-research-labs/forks) [![GitHub issues](https://img.shields.io/github/issues/guardzcom/security-research-labs?style=flat-square)](https://github.com/guardzcom/security-research-labs/issues) [![GitHub language count](https://img.shields.io/github/languages/count/guardzcom/security-research-labs?style=flat-square)](https://github.com/guardzcom/security-research-labs)

---

## Repository layout

| Category | Folder | Contents |
|----------|--------|----------|
| [![AI](https://img.shields.io/badge/AI-orange?style=flat-square)](AI-Tools/) | [AI-Tools/](AI-Tools/) | OpenClaw Analyzer (config analysis), SkillScan (skill file/URL security scanning). |
| [![Purple](https://img.shields.io/badge/Purple-purple?style=flat-square)](Purple-Team-Emulation/) | [Purple-Team-Emulation/](Purple-Team-Emulation/) | Endpoint: certutil emulation, EDR telemetry simulator, Office macro tampering emulation. |
| [![M365](https://img.shields.io/badge/M365-blue?style=flat-square)](CloudAdversary/M365/) | [CloudAdversary/M365/](CloudAdversary/M365/) | DeviceStrike, SPO Ext Recon, GraphRunner QuickStart. |
| [![GWS](https://img.shields.io/badge/GWS-green?style=flat-square)](Purple-Team-Emulation/GWS/) | [Purple-Team-Emulation/GWS/](Purple-Team-Emulation/GWS/) | Google Workspace security tools (placeholder). |
| [![Threat Intel](https://img.shields.io/badge/Threat%20Intel-red?style=flat-square)](Threat-Intel/) | [Threat-Intel/](Threat-Intel/) | IOCs, detection artifacts, threat intelligence. |

**For teams that rely on the same caliber of intelligence and tooling as** <a href="https://www.microsoft.com/en-us/security/business/threat-intelligence" target="_blank" rel="noopener noreferrer">Microsoft Threat Intelligence</a> <a href="https://github.com/microsoft/msticpy" target="_blank" rel="noopener noreferrer">GitHub</a>, <a href="https://www.mandiant.com/" target="_blank" rel="noopener noreferrer">Mandiant</a> Google Cloud <a href="https://github.com/google/mandiant-ti-client" target="_blank" rel="noopener noreferrer">GitHub</a>, and <a href="https://www.anthropic.com/" target="_blank" rel="noopener noreferrer">Anthropic</a> <a href="https://github.com/anthropics" target="_blank" rel="noopener noreferrer">GitHub</a> open, actionable tools for defenders, red teams, and AI security.

---

## Who it's for

| Category | Audience | Use case |
|----------|----------|----------|
| [![Cloud](https://img.shields.io/badge/Cloud-blue?style=flat-square)](#) | **Cloud Security** | Microsoft 365 and Google Workspace. |
| [![AI](https://img.shields.io/badge/AI-orange?style=flat-square)](#) | **AI security** | Securing AI assistants and agents: config hardening, exposure detection, supply-chain and skill safety. |
| [![Purple](https://img.shields.io/badge/Purple-purple?style=flat-square)](#) | **Purple team** | Hardening checks, config review, detection-oriented recon. |
| [![Red](https://img.shields.io/badge/Red-red?style=flat-square)](#) | **Red team** | Authorized recon, token flows, M365/cloud attack-surface mapping. |
| [![Forensic](https://img.shields.io/badge/Forensic-darkblue?style=flat-square)](#) | **Forensic** | Evidence gathering, mailbox/SharePoint/Teams search patterns, audit trails. |

> **Authorized use only.** Use only on systems and tenants you **own** or have **explicit permission** to test.

---

## Security model (important)

> **Compliance & authorized use**
>
> - **Authorized use only.** These tools are for security research, authorized testing, and defensive operations. Use them only on systems and tenants you **own** or have **explicit permission** to test.
> - **No misuse.** Do not use this repo to gain unauthorized access, exfiltrate data, or violate laws or organizational policies. Misuse is your responsibility.
> - **Operational risk.** Recon and auth scripts can trigger alerts or rate limits. Coordinate with stakeholders and follow change management where required.
> - **Data handling.** Output may contain sensitive information. Handle and retain it according to your classification and retention policies.
>
> By using this repository you agree to use it in a lawful and authorized manner. See [SECURITY.md](SECURITY.md) for how to report vulnerabilities in the repo itself.

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

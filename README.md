<p align="center">
  <a href="https://github.com/guardzcom/security-research-labs">
    <img src=".github/assets/hero.png" alt="Security Research Labs banner" width="100%" />
  </a>
</p>

<!-- Project badges -->
<p align="center">
  <a href="https://github.com/guardzcom/security-research-labs/stargazers"><img src="https://img.shields.io/github/stars/guardzcom/security-research-labs?style=flat-square&logo=github&color=FFD700" alt="GitHub stars"></a>
  <a href="https://github.com/guardzcom/security-research-labs/network/members"><img src="https://img.shields.io/github/forks/guardzcom/security-research-labs?style=flat-square&logo=github&color=5BB5F0" alt="GitHub forks"></a>
  <a href="https://github.com/guardzcom/security-research-labs/releases"><img src="https://img.shields.io/github/v/release/guardzcom/security-research-labs?style=flat-square&logo=semanticrelease&color=8A2BE2" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-3DA639?style=flat-square" alt="License: MIT"></a>
</p>

<!-- Tech & health badges -->
<p align="center">
  <img src="https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?style=flat-square&logo=powershell&logoColor=white" alt="PowerShell 5.1+">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-4CAF50?style=flat-square" alt="Platform">
  <a href="https://github.com/guardzcom/security-research-labs/commits/main"><img src="https://img.shields.io/github/last-commit/guardzcom/security-research-labs?style=flat-square&color=5B7FFF" alt="Last commit"></a>
  <a href="https://github.com/guardzcom/security-research-labs/graphs/contributors"><img src="https://img.shields.io/github/contributors/guardzcom/security-research-labs?style=flat-square&color=FF6B6B" alt="Contributors"></a>
  <a href="https://github.com/guardzcom/security-research-labs/issues"><img src="https://img.shields.io/github/issues/guardzcom/security-research-labs?style=flat-square&color=FFA500" alt="Open issues"></a>
</p>

<!-- Category quick-links -->
<p align="center">
  <a href="AI-Cloud-Tools/"><img src="https://img.shields.io/badge/AI%20%26%20Cloud-OpenClaw%20%7C%20SkillScan%20%7C%20EntraReaper-F39C12?style=for-the-badge" alt="AI & Cloud"></a>
  <a href="Purple-Team-Emulation/"><img src="https://img.shields.io/badge/Purple%20Team-Detection%20testing-8E44AD?style=for-the-badge" alt="Purple Team"></a>
  <a href="CloudAdversary/M365/"><img src="https://img.shields.io/badge/M365-Entra%20%7C%20Graph-2980B9?style=for-the-badge" alt="M365"></a>
  <a href="Threat-Intel/"><img src="https://img.shields.io/badge/Threat%20Intel-IOCs%20%7C%20Hunting-C0392B?style=for-the-badge" alt="Threat Intel"></a>
  <a href="Research/"><img src="https://img.shields.io/badge/Research-AiTM%20%7C%20Dormant-34495E?style=for-the-badge" alt="Research"></a>
</p>

Security Research Labs is the official Guardz repo for open-source security tooling: config analyzers, Microsoft 365 / Entra recon scripts, purple-team detection emulations, and AI skill security. MIT-licensed; each tool lives in a **dedicated folder with its own README**.

---

## Featured tools

<table>
  <tr>
    <td width="50%" valign="top">
      <h3>🩸 EntraReaper</h3>
      <p><em>Autonomous red-team platform for Microsoft Entra ID.</em></p>
      <p>MCP server that wraps <strong>238 AADInternals cmdlets</strong> into <strong>65 purpose-built tools</strong> across 12 MITRE ATT&amp;CK phases, with 13 kill chains, OPSEC governance, evasion engine, and auto-reporting.</p>
      <p>
        <code>Python 3.11+</code> · <code>PowerShell 7</code> · <code>macOS / Linux</code><br/>
        <a href="AI-Cloud-Tools/M365-Tools/EntraReaper/"><strong>Explore →</strong></a>
      </p>
    </td>
    <td width="50%" valign="top">
      <h3>🔬 SkillScan</h3>
      <p><em>Scan AI skill files for malicious patterns.</em></p>
      <p>Detects prompt injection, malware delivery, code execution, suspicious URLs, and obfuscated content in AI skill definitions — local files or URLs. Ships with CLI, local server, and browser UI.</p>
      <p>
        <code>Python 3</code> · <code>CLI / Server / Web</code> · <code>No cloud required</code><br/>
        <a href="AI-Cloud-Tools/AI/skillscan/"><strong>Explore →</strong></a>
      </p>
    </td>
  </tr>
  <tr>
    <td width="50%" valign="top">
      <h3>🧠 OpenClaw Analyzer</h3>
      <p><em>Security configuration analyzer for OpenClaw deployments.</em></p>
      <p>Single-file web app with a <strong>68-point checklist</strong>, risk detection, and attack-path visualization. No server required — open the HTML in a browser.</p>
      <p>
        <code>Web</code> · <code>Zero install</code> · <code>Offline</code><br/>
        <a href="AI-Cloud-Tools/AI/OpenClaw-Analyzer/"><strong>Explore →</strong></a>
      </p>
    </td>
    <td width="50%" valign="top">
      <h3>🕸️ GraphRunner QuickStart</h3>
      <p><em>Cookbook for <a href="https://github.com/dafthack/GraphRunner">dafthack/GraphRunner</a>.</em></p>
      <p>One-file quick reference and runnable command set: auth, tenant recon, Conditional Access enumeration, mailbox / SharePoint / Teams search, and token utilities.</p>
      <p>
        <code>PowerShell 5.1+</code> · <code>Windows / macOS / Linux</code><br/>
        <a href="CloudAdversary/M365/graphrunner-quickstart/"><strong>Explore →</strong></a>
      </p>
    </td>
  </tr>
</table>

<p align="right"><sub>See <a href="#repository-layout">repository layout</a> for the full catalog.</sub></p>

---

## Quick Start

Clone and pick a tool — every folder ships with its own README.

```bash
git clone https://github.com/guardzcom/security-research-labs.git
cd security-research-labs
```

**Try SkillScan in 30 seconds** — no tenant, no auth, no cloud required:

```bash
cd AI-Cloud-Tools/AI/skillscan
python3 skillscan.py scan file path/to/skill.md
# or scan a whole folder
python3 skillscan.py scan dir ./skills/ --pattern "*.md"
# or a URL
python3 skillscan.py scan url https://example.com/skill
```

**Try OpenClaw Analyzer in 10 seconds** — zero install:

```bash
open AI-Cloud-Tools/AI/OpenClaw-Analyzer/openclaw-security-analyzer/openclaw-analyzer.html
```

**Run EntraReaper against a tenant you own / are authorized to test:**

```bash
cd AI-Cloud-Tools/M365-Tools/EntraReaper
bash install.sh                    # installs PowerShell 7, AADInternals, uv
uv run python server.py            # standalone
# or wire it into Claude Code as an MCP server:
claude mcp add entrareaper -- uv run --directory "$PWD" python server.py
```

> **Authorized use only.** Run these tools only against systems and tenants you **own** or have **explicit permission** to test. See [Security model](#security-model-important).

---

## Repository layout

| Category | Folder | Contents |
|----------|--------|----------|
| [![AI](https://img.shields.io/badge/AI-orange?style=flat-square)](AI-Cloud-Tools/) | [AI-Cloud-Tools/](AI-Cloud-Tools/) | AI: OpenClaw Analyzer, SkillScan. M365-Tools: OAuth IOCs checker, [EntraReaper](AI-Cloud-Tools/M365-Tools/EntraReaper/) (MCP + AADInternals for authorized Entra ID red team). |
| [![Purple](https://img.shields.io/badge/Purple-purple?style=flat-square)](Purple-Team-Emulation/) | [Purple-Team-Emulation/](Purple-Team-Emulation/) | Endpoint: certutil, EDR telemetry simulator, Office macro tampering, BloodHound emulation, Nmap scanning emulation. |
| [![M365](https://img.shields.io/badge/M365-blue?style=flat-square)](CloudAdversary/M365/) | [CloudAdversary/M365/](CloudAdversary/M365/) | DeviceStrike, Entra ID Smart Lockout (Entra-ID-DOS), SPO Ext Recon, GraphRunner QuickStart. |
| [![GWS](https://img.shields.io/badge/GWS-green?style=flat-square)](Purple-Team-Emulation/GWS/) | [Purple-Team-Emulation/GWS/](Purple-Team-Emulation/GWS/) | Google Workspace security tools (placeholder). |
| [![Threat Intel](https://img.shields.io/badge/Threat%20Intel-red?style=flat-square)](Threat-Intel/) | [Threat-Intel/](Threat-Intel/) | IOCs, detection artifacts, threat intelligence. |
| [![Research](https://img.shields.io/badge/Research-gray?style=flat-square)](Research/) | [Research/](Research/) | Research outputs, landscape studies, and reference materials (e.g. [M365 AiTM](Research/M365/AiTM/), [hybrid AD MFA gap](Research/M365/Dormant/)). |

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

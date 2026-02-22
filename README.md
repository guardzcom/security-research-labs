# 🛡️ Security Research Labs — Cybersecurity Tools & Scripts

**Tools, scripts, and research PoCs for blue team, red team, DFIR, and cloud security. Authorized use only.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue?logo=powershell)](https://docs.microsoft.com/powershell/)
[![Platform](https://img.shields.io/badge/Platform-Web%20%7C%20Windows%20%7C%20macOS%20%7C%20Linux-green)](.)

**Security Research Labs** is the official Guardz repo for open-source security tooling: config analyzers, Microsoft 365 / Entra recon scripts, and research proof-of-concepts. Everything is MIT-licensed and maintained for defenders, red teams, and incident responders.

[OpenClaw Analyzer](AI-Tools/openclaw-security-analyzer/) · [M365 Scripts](M365/README.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Issues](https://github.com/guardzcom/security-research-labs/issues)

**Preferred path:** Clone the repo, open the [OpenClaw Security Analyzer](AI-Tools/openclaw-security-analyzer/openclaw-analyzer.html) in a browser for config review, or run the [M365](M365/) PowerShell scripts only against tenants you own or are authorized to test. See [Quick start](#quick-start-tldr) below.

---

## Who it's for

| Audience | Use case |
|----------|----------|
| **Blue team** | Hardening checks, config review, detection-oriented recon. |
| **Red team** | Authorized recon, token flows, M365/cloud attack-surface mapping. |
| **DFIR** | Evidence gathering, mailbox/SharePoint/Teams search patterns, audit trails. |
| **Cloud / M365 sec** | Entra ID, SharePoint, OneDrive, Conditional Access, app consent review. |
| **DevSecOps / platform** | Config and supply-chain security (e.g. [OpenClaw](https://github.com/openclaw/openclaw)-style deployments). |

Use only on systems and tenants you **own** or have **explicit permission** to test.

---

## Highlights

- **OpenClaw Security Analyzer** — Single-file web app: 68-point checklist, risk detection, attack path visualization. 100% client-side, no server.
- **M365 device-code auth** — OAuth2 device flow for Microsoft Graph with optional token caching and refresh ([DeviceStrike.ps1](M365/DeviceStrike.ps1)).
- **SharePoint / OneDrive recon** — Enumerate common site paths, anonymous access, metadata API exposure ([SPO_Ext_Recon.ps1](M365/SPO_Ext_Recon.ps1)).
- **GraphRunner cookbook** — Quick-start for [dafthack/GraphRunner](https://github.com/dafthack/GraphRunner): auth, recon, CAPs, apps, mailbox/SP/Teams search ([GraphRunner-QuickStart.ps1](M365/GraphRunner-QuickStart.ps1)).
- **Offline-capable** — Analyzer runs in the browser; scripts are plain PowerShell. No SaaS dependency.

---

## Quick start (TL;DR)

**OpenClaw Security Analyzer (browser):**

- Open [openclaw-analyzer.html](AI-Tools/openclaw-security-analyzer/openclaw-analyzer.html) in a browser → **Import** or drag-and-drop your `openclaw.json` → review findings and checklist.
- Runtime: any modern browser (Chrome 90+, Firefox 88+, Safari 14+, Edge 90+). No install.

**M365 scripts (PowerShell):**

- Runtime: **PowerShell 5.1+** (Windows, macOS, or Linux with PowerShell Core).
- Clone the repo, review the script, then run. Target only authorized tenants.

```bash
git clone https://github.com/guardzcom/security-research-labs.git
cd security-research-labs
```

```powershell
# Example: run SharePoint/OneDrive recon (edit $domain / $onedriveDomain first)
cd M365
.\SPO_Ext_Recon.ps1
```

For [GraphRunner-QuickStart.ps1](M365/GraphRunner-QuickStart.ps1), place [GraphRunner.ps1](https://github.com/dafthack/GraphRunner) in the same directory, then dot-source and run the commands in the script. See [M365/README.md](M365/README.md) for details.

**Running PowerShell safely:** Use `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` for the current session if needed, or `powershell -ExecutionPolicy Bypass -File .\Script.ps1`. Never commit script outputs (they're in [.gitignore](.gitignore)).

---

## What's in this repo

### AI & config security

| Tool | Description | Status |
|------|-------------|--------|
| [OpenClaw Security Analyzer](AI-Tools/openclaw-security-analyzer/) | Analyze [OpenClaw](https://openclaw.ai) configs: 68-point checklist, risk detection, attack path viz. Single HTML file, client-side only. | ✅ Maintained |

### M365 / Entra / cloud

| Script | Description | Status |
|--------|-------------|--------|
| [DeviceStrike.ps1](M365/DeviceStrike.ps1) | OAuth2 device-code flow for Microsoft Graph; optional refresh-token cache and auto-refresh. | ✅ Maintained |
| [SPO_Ext_Recon.ps1](M365/SPO_Ext_Recon.ps1) | SharePoint Online & OneDrive recon: common site paths, anonymous access, metadata API exposure. | ✅ Maintained |
| [GraphRunner-QuickStart.ps1](M365/GraphRunner-QuickStart.ps1) | Cookbook for [GraphRunner](https://github.com/dafthack/GraphRunner): auth, recon, CAPs, apps, mailbox/SP/Teams search. | ✅ Maintained |

Full usage and legal/operational notes: [M365/README.md](M365/README.md) · [OpenClaw Analyzer README](AI-Tools/openclaw-security-analyzer/README.md).

---

## How it works (short)

```
Config files (openclaw.json, etc.)     M365 tenants (SharePoint, Entra, Graph)
              │                                        │
              ▼                                        ▼
┌─────────────────────────────┐    ┌─────────────────────────────────────────┐
│  OpenClaw Security Analyzer  │    │  M365 scripts (DeviceStrike, SPO recon,  │
│  (browser, client-side only) │    │  GraphRunner-QuickStart)                 │
└──────────────┬───────────────┘    └──────────────────┬──────────────────────┘
               │                                        │
               ▼                                        ▼
       Findings, checklist,                    Recon output, tokens,
       attack path visualization               CSVs (handle per policy)
```

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

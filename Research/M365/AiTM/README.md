# M365 Research

Microsoft 365 and Entra ID–focused research artifacts: landscape studies, tool taxonomies, and reference materials for detection and investigation.

## Contents

| Artifact | Description |
|----------|-------------|
| **AiTM_Attack_Tools_Landscape_Feb2026.xlsx** (optional) | Adversary-in-the-Middle (AiTM) attack tools landscape (February 2026). Survey of tooling used in token-theft and MFA-bypass phishing against M365/Entra. When present (or a CSV export), use for detection prioritization, threat intel mapping, and purple-team scope. |

## Column reference

The landscape spreadsheet (and its CSV export) uses the following columns:

| Column | Meaning |
|--------|--------|
| **Tool Name** | Canonical name of the AiTM/phishing tool or framework. |
| **Type** | Classification of the tool (e.g. open-source, commercial, underground, PoC). |
| **First Seen** | When the tool or version first appeared in the wild or in public reporting. |
| **Status (Feb 2026)** | Current status as of the Feb 2026 snapshot (e.g. active, deprecated, rebranded). |
| **Price** | Cost or availability (e.g. free, subscription, one-time, underground pricing). |
| **Distribution** | How the tool is distributed (e.g. GitHub, dark web, private, as-a-service). |
| **Primary Target** | Main target ecosystem (e.g. M365/Entra, Azure AD, Okta, generic OAuth). |
| **AiTM Method** | How the proxy implements the man-in-the-middle (e.g. reverse proxy, reverse proxy + cookie injection, session relay). |
| **Proxy Type** | Technical proxy architecture (e.g. HTTP(S) reverse proxy, transparent, custom). |
| **MFA Bypass Approach** | How MFA is bypassed (e.g. session cookie theft, token relay, prompt bombing, hybrid). |
| **Key Capabilities** | Notable features (e.g. 2FA support, session hijack, credential harvest, token replay). |
| **Evasion Techniques** | Anti-detection or evasion behaviors (e.g. traffic normalization, TLS handling, header spoofing). |
| **Notable Intel** | References, IOCs, or brief notes from threat intel or public reports. |

## Related repo areas

- **Detection & investigation:** See repo skills and playbooks for [AiTM/token-theft](https://github.com/guardzcom/security-research-labs) and M365 forensics.
- **M365 tools:** [CloudAdversary/M365/](../../../CloudAdversary/M365/) — DeviceStrike, SPO Ext Recon, GraphRunner QuickStart.
- **Other M365 research:** [Dormant/](../Dormant/) — hybrid AD / Entra MFA registration gap scripts and Graph samples (blog companion artifacts).

## Usage

Artifacts here are reference-only. Do not execute untrusted macros or scripts from spreadsheets; open in read-only or in a sandbox when unsure.

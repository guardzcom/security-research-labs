# M365 Security Research Scripts

PowerShell scripts for **authorized** Microsoft 365 / Entra ID reconnaissance, authentication, and integration with [GraphRunner](https://github.com/dafthack/GraphRunner). Each tool lives in its own folder with a dedicated README.

> **Legal & operational notice**  
> Use these scripts only on tenants and assets you **own** or have **explicit permission** to test. Unauthorized access may violate laws and organizational policies. Coordinate with stakeholders and follow change management where applicable. Output may contain sensitive data -handle per your classification and retention policies.

---

## Tools (each in its own folder)

| Tool | Folder | Description |
|------|--------|-------------|
| **DeviceStrike** | [device-strike/](device-strike/) | `DeviceStrike.ps1`  - OAuth2 device-code flow for Microsoft Graph; optional token caching and auto-refresh. |
| **Entra ID Smart Lockout** | [Entra-ID-DOS/](Entra-ID-DOS/) | `Entra-ID-DOS.ps1`  - Validates Entra ID Smart Lockout in cloud-only and hybrid (PHS/PTA) environments; auto-detects deployment type and runs threshold/duration compliance checks. |
| **SPO Ext Recon** | [spo-ext-recon/](spo-ext-recon/) | `SPO_Ext_Recon.ps1`  - SharePoint Online & OneDrive recon: common site paths, anonymous access, metadata API exposure. |
| **GraphRunner QuickStart** | [graphrunner-quickstart/](graphrunner-quickstart/) | `GraphRunner-QuickStart.ps1`  - Cookbook for [dafthack/GraphRunner](https://github.com/dafthack/GraphRunner): auth, recon, CAPs, apps, mailbox/SP/Teams search. |

Open the folder link for usage, requirements, and file layout.

---

## Requirements

- **PowerShell 5.1+** (Windows, macOS, or Linux with PowerShell Core)
- **GraphRunner QuickStart:** [GraphRunner.ps1](https://github.com/dafthack/GraphRunner) must be placed in `graphrunner-quickstart/` (see that folder’s README).

---

## Output and sensitive data

Script outputs (user lists, group members, search results, recon files) can be highly sensitive. The repository `.gitignore` excludes common output files (e.g. `Exposed_SharePoint_Sites.txt`, `users.txt`, `out/`, `*.csv`). Keep all results in line with your data handling policies.

---

## Related research

- **Hybrid AD / Entra MFA gap (defensive):** [Research/M365/Dormant/](../../Research/M365/Dormant/) — Graph samples and PowerShell for MFA registration reporting, on-prem AD attribute review, and AD↔Entra correlation.

---

## License

Same as the root repository  - see [../LICENSE](../LICENSE).

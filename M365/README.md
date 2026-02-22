# M365 Security Research Scripts

PowerShell scripts for **authorized** Microsoft 365 / Entra ID reconnaissance, authentication, and integration with [GraphRunner](https://github.com/dafthack/GraphRunner).

> **Legal & operational notice**  
> Use these scripts only on tenants and assets you **own** or have **explicit permission** to test. Unauthorized access may violate laws and organizational policies. Coordinate with stakeholders and follow change management where applicable. Output may contain sensitive data—handle per your classification and retention policies.

---

## Scripts

| Script | Purpose |
|--------|--------|
| **DeviceStrike.ps1** | OAuth2 device-code flow for Microsoft Graph. Optional refresh-token caching and automatic token refresh. Use with apps/tenants you control. |
| **SPO_Ext_Recon.ps1** | SharePoint Online and OneDrive recon: enumerates common site paths (HR, finance, dev, Teams, public, partners, etc.), checks anonymous access, metadata API exposure, and shared document visibility. Results → `Exposed_SharePoint_Sites.txt`. |
| **GraphRunner-QuickStart.ps1** | Quick-start cookbook for [dafthack/GraphRunner.ps1](https://github.com/dafthack/GraphRunner). Dot-source GraphRunner, then run auth, recon, CAPs, apps, mailbox/SP/Teams search, and other modules. |

---

## Requirements

- **PowerShell 5.1+** (Windows, macOS, or Linux with PowerShell Core)
- **GraphRunner-QuickStart:** [GraphRunner.ps1](https://github.com/dafthack/GraphRunner) in the same directory (or adjust the dot-source path)
- **Permissions:** Only run against tenants you are authorized to test

---

## DeviceStrike.ps1

- Performs device-code auth against Entra ID (common or tenant-specific).
- Uses a built-in client ID; for production consider your own app registration and MSAL.
- **Security:** Caching tokens to disk increases risk—use encrypted storage and restrict file permissions if enabled.

**Usage:** Run in PowerShell; follow the prompt to open the verification URL and enter the user code. Tokens are printed to the console; optional logic can cache/refresh.

---

## SPO_Ext_Recon.ps1

1. Set `$domain` and `$onedriveDomain` to your target tenant (e.g. `contoso.sharepoint.com`, `contoso-my.sharepoint.com`).
2. Optionally add usernames to `$usernames` for OneDrive URL checks.
3. Run the script. Results are appended to `Exposed_SharePoint_Sites.txt`.

The script probes many common path patterns (business, engineering, Teams, public, demo, partners, etc.) and reports:

- Reachable SharePoint/OneDrive URLs
- Redirects
- Metadata API exposure (`_api/site`, `_api/web`, etc.)
- Anonymous visibility of Shared Documents where detectable

---

## GraphRunner-QuickStart.ps1

1. Save [GraphRunner.ps1](https://github.com/dafthack/GraphRunner) next to this file.
2. In PowerShell:  
   `. .\GraphRunner.ps1; . .\GraphRunner-QuickStart.ps1`
3. Run the commands shown in the script (e.g. `Get-GraphTokens`, `Invoke-GraphRunner`, `Invoke-DumpCAPS`, mailbox/SP/Teams search).

The script documents common operations: device-code auth, token refresh, recon, Conditional Access, app enumeration, user/group export, and search (mailbox, SharePoint/OneDrive, Teams). Adjust paths and output files as needed. Prefer environment variables or secure input for secrets; avoid hardcoding tokens.

---

## Output and sensitive data

Script outputs (user lists, group members, search results, recon files) can be highly sensitive. The repository `.gitignore` excludes common output files (e.g. `Exposed_SharePoint_Sites.txt`, `users.txt`, `out/`, `*.csv`). Keep all results in line with your data handling policies.

---

## License

Same as the root repository (see [../LICENSE](../LICENSE)).

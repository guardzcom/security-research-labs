# SPO Ext Recon  - SharePoint Online & OneDrive Reconnaissance

PowerShell script to automate reconnaissance of SharePoint Online and OneDrive for Business: enumerate common site paths, check for anonymous access, metadata API exposure, and shared document visibility. For red team, purple team, and DFIR use in authorized testing only.

> **Legal & operational notice**  
> Use only on tenants and assets you **own** or have **explicit permission** to test. Recon can trigger alerts or rate limits -coordinate with stakeholders. Output may contain sensitive data; handle per your classification and retention policies.

---

## What it does

- Enumerates a large set of **common path patterns** (business units, engineering, Teams, public, demo, partners, admin, etc.).
- Builds URLs for **SharePoint** (`https://$domain/sites/...`, `teams/...`) and **OneDrive** (`https://$onedriveDomain/personal/...`).
- For each URL: checks reachability, reports **redirects**, and when the page looks like SharePoint:
  - Probes **metadata API** endpoints (`_api/site`, `_api/web`, `_api/web/title`, `_api/web/lists`).
  - Tests whether **Shared Documents** appear anonymously visible.
- Writes results to **`Exposed_SharePoint_Sites.txt`** (path list + metadata/shared-doc notes).

---

## Requirements

- **PowerShell 5.1+** (Windows, macOS, or Linux with PowerShell Core)

---

## Usage

1. **Edit the script** (or set variables before dot-sourcing):
   - `$domain`  - Your tenant’s SharePoint domain (e.g. `contoso.sharepoint.com`).
   - `$onedriveDomain`  - Your tenant’s OneDrive domain (e.g. `contoso-my.sharepoint.com`).
   - Optionally, `$usernames`  - Array of usernames to build OneDrive personal URLs (e.g. `"john", "alice"`).
2. Run the script:
   ```powershell
   .\SPO_Ext_Recon.ps1
   ```
3. Review **`Exposed_SharePoint_Sites.txt`** and console output.

---

## Output

| Output | Description |
|--------|-------------|
| `Exposed_SharePoint_Sites.txt` | List of reachable SharePoint/OneDrive URLs and any metadata/shared-doc findings. |

This file is listed in the repository `.gitignore`; do not commit it.

---

## Files

| File | Description |
|------|-------------|
| `SPO_Ext_Recon.ps1` | Main recon script; edit `$domain`, `$onedriveDomain`, and optionally `$usernames` at the top. |

---

## License

Same as the root repository  - see [../../LICENSE](../../LICENSE).

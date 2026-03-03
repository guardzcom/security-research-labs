# GraphRunner QuickStart  - Cookbook for dafthack/GraphRunner

One-file quick reference and runnable command set for [dafthack/GraphRunner](https://github.com/dafthack/GraphRunner). Dot-source GraphRunner, then use the script as a cookbook for auth, recon, Conditional Access, app enumeration, mailbox/SharePoint/Teams search, and more.

> **Authorized use only.** Use only against tenants you **own** or have **explicit permission** to test. Output may contain sensitive data -handle per your classification and retention policies. Prefer environment variables or secure input for secrets; avoid hardcoding tokens.

---

## What it does

The script does not run autonomously; it **documents and invokes** GraphRunner modules. You dot-source it to load GraphRunner, then run the commands you need (e.g. auth, recon, CAPs, search). Typical use:

- **Authentication**  - Device-code or app auth; refresh tokens; check Graph reachability.
- **Recon & enumeration**  - Full tenant recon, Conditional Access (CAPs), app registrations and consents, users, security groups; export to JSON/CSV.
- **Pillage / search**  - Mailbox, SharePoint/OneDrive, Teams message search; export results to CSV.
- **Teams**  - Channels, apps, webhooks; optional webhook creation/send.
- **Utilities**  - Token refresh loop, HTTP server for email viewer, drive file download, token import.

---

## Requirements

- **PowerShell 5.1+** (Windows, macOS, or Linux with PowerShell Core)
- **[GraphRunner.ps1](https://github.com/dafthack/GraphRunner)**  - Place `GraphRunner.ps1` in **this folder** (same directory as `GraphRunner-QuickStart.ps1`).

---

## Usage

1. Download or clone [GraphRunner](https://github.com/dafthack/GraphRunner) and place **`GraphRunner.ps1`** in this folder.
2. In PowerShell, from this folder:
   ```powershell
   . .\GraphRunner.ps1; . .\GraphRunner-QuickStart.ps1
   ```
3. Run the commands you need from the script (e.g. `Get-GraphTokens`, `Invoke-GraphRunner`, `Invoke-DumpCAPS`, `Invoke-SearchMailbox`). Adjust parameters, output paths, and search terms as needed.

**Notes:**

- Device-code auth sets `$tokens` and `$tenantid`; most modules take `-Tokens $tokens`.
- Keep token scope minimal and rotate often. Do not hardcode secrets in the script.

---

## Files

| File | Description |
|------|-------------|
| `GraphRunner-QuickStart.ps1` | Cookbook: dot-source with GraphRunner, then run commands as needed. |
| `GraphRunner.ps1` | **You must add this**  - from [dafthack/GraphRunner](https://github.com/dafthack/GraphRunner). |

---

## Output

Scripts may write to `.\users.txt`, `.\security_groups.csv`, `.\mail.csv`, `.\sp_hits.csv`, `.\teams_hits.csv`, `.\out\`, etc. These paths are in the repository `.gitignore`; do not commit them.

---

## License

Same as the root repository  - see [../../LICENSE](../../LICENSE). GraphRunner has its own license; see the [GraphRunner repo](https://github.com/dafthack/GraphRunner).

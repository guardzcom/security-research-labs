# Shadow AI Audit

**Goal:** Inventory and risk-score **AI agents, LLM copilots, and OAuth AI tools** registered in your Microsoft 365 / Entra ID tenant. Runs ten independent, read-only checks over every AI-named service principal via Microsoft Graph and produces a self-contained HTML dashboard plus per-check CSV exports.

**Authorized use only.** Run only on tenants you own or have explicit permission to test. All Graph calls are read-only.

---

## What it does

`ShadowAIAudit.ps1` enumerates every service principal whose `DisplayName` matches a broad AI/LLM/agent vendor regex (Claude, OpenAI, GPT, Copilot, Gemini, Cursor, Perplexity, Mistral, LangChain, MCP, `agent`, `llm`, `ai`, `ml`, and many more), then runs ten independent risk checks and rolls them into a composite per-app score.

| # | Check | Severity logic |
|---|---|---|
| C01 | AI Vendor App Inventory | LOW (baseline) — one row per AI-named SP |
| C02 | Critical Graph Scopes (Mail/Files/Sites/Directory/Calendar/Teams/Security) | MEDIUM → HIGH → CRITICAL based on scope count |
| C03 | Application (App-Only) Permissions — runs with no user in the loop | HIGH, CRITICAL if any scope is in the critical list |
| C04 | Tenant-Wide Admin Consent (`consentType=AllPrincipals`) | HIGH, CRITICAL if a critical scope is tenant-wide |
| C05 | Unverified Publisher (no MPN attestation) | MEDIUM, HIGH if paired with critical scopes |
| C06 | Recently Added (< `RecentDays`, default 30) — supply-chain window | MEDIUM, HIGH if also has critical scopes / app-only perms |
| C07 | Multi-Tenant App Reach (`AzureADMultipleOrgs` / MSA) — cross-tenant pivot | MEDIUM, HIGH if paired with critical scopes |
| C08 | Directory Role Assignments to the app — Entra privilege escalation | CRITICAL |
| C09 | Risky Redirect URIs (`http://`, `localhost`, ngrok/serveo/trycloudflare/loca.lt/tunnelmole) | MEDIUM, HIGH for plain `http://` |
| C10 | Multiple App Credentials (secrets + certs ≥ 2) — persistence pattern | MEDIUM, HIGH if ≥ 4 |

Severity weights: `CRITICAL=40`, `HIGH=20`, `MEDIUM=8`, `LOW=2`. Each app's score is the sum of weights across all checks it trips.

### Output

Everything lands in a timestamped folder: `shadow-ai-audit-YYYYMMDD-HHMM/`

- `shadow-ai.html` — self-contained dashboard with severity tiles, severity doughnut, per-check bar chart, Top Risk Apps table, and a CSV download dropdown. Auto-opens unless `-NoOpen`.
- `01_Summary.csv` — one row per check with CRITICAL/HIGH/MEDIUM/LOW counts.
- `02_Apps-Rollup.csv` — composite risk per app (score, max severity, checks hit).
- `03_All-Findings.csv` — every finding row.
- `C01_*.csv` … `C10_*.csv` — one CSV per check (empty header file if zero findings).
- `shadow-ai-csvs.zip` — all CSVs bundled for one-click download from the HTML.

> Note: the HTML dashboard intentionally excludes the "Unverified Publisher" check (C05) to reduce noise, but it is always present in the CSVs.

---

## Usage

```powershell
# Default tenant, interactive sign-in, report auto-opens
.\ShadowAIAudit.ps1

# Target a specific tenant by UPN suffix or GUID
.\ShadowAIAudit.ps1 -TenantId contoso.onmicrosoft.com

# Custom output folder (a timestamped subfolder is created under it)
.\ShadowAIAudit.ps1 -OutputFolder C:\Audits\Contoso

# Tighten / widen the "recently added" window for check C06
.\ShadowAIAudit.ps1 -RecentDays 7

# CI / scheduled runs — don't launch the browser
.\ShadowAIAudit.ps1 -NoOpen
```

### Parameters

| Parameter | Default | Notes |
|---|---|---|
| `-TenantId` | *current signed-in tenant* | UPN suffix or tenant GUID. Omit for the interactive default-tenant flow. |
| `-OutputFolder` | `$PSScriptRoot` | Parent folder; a `shadow-ai-audit-<ts>` subfolder is always created inside it. |
| `-RecentDays` | `30` | Window for check C06 (Recently Added). |
| `-NoOpen` | *off* | Suppresses the auto-open of the HTML report. |

---

## Requirements

- **PowerShell 5.1+ or PowerShell 7+** (cross-platform: Windows / macOS / Linux — the script auto-detects and opens the report via `open` / `xdg-open` / `Start-Process`).
- **Microsoft Graph PowerShell SDK** — auto-installed on first run (`-Scope CurrentUser`):
  - `Microsoft.Graph.Authentication`
  - `Microsoft.Graph.Applications`
  - `Microsoft.Graph.Identity.SignIns`
  - `Microsoft.Graph.Identity.DirectoryManagement`
- **Delegated Graph scopes consented at sign-in** (read-only):
  - `Application.Read.All`
  - `Directory.Read.All`
  - `DelegatedPermissionGrant.Read.All`
  - `RoleManagement.Read.Directory`
- **Internet access** to `cdn.jsdelivr.net` for the Chart.js reference in the HTML (charts only; the report renders fine offline — you just lose the two charts).

---

## How it works (read-only, offline-after-fetch)

1. Connects to Graph with the delegated scopes above and pulls **all** service principals, OAuth2 permission grants, per-app app-role assignments, and directory role memberships **once** into in-memory caches.
2. Filters service principals by the AI vendor regex.
3. For each AI-named SP, runs C01–C10, aggregates findings, and computes the composite score.
4. Writes CSVs, zips them, renders the HTML, and (unless `-NoOpen`) launches the report.
5. Disconnects the Graph session on exit.

No data leaves the host running the script.

---

## License

Same as the root repository — see [../../../LICENSE](../../../LICENSE).

# OAuth IOCs Check

**Goal:** Scan your Microsoft 365 / Entra ID tenant for indicators of compromise (IOCs) associated with known OAuth abuse campaigns. Connects via Microsoft Graph (interactive/delegated auth) and checks for malicious app IDs, permission grants, and—with Entra ID P1/P2—sign-in and audit patterns.

**Authorized use only.** Run only on tenants you own or have explicit permission to test.

---

## What it does

- **Phase 1–3 (all tiers):** Service principals, OAuth2 permission grants, app role assignments for malicious client IDs.
- **Phase 4–5 (P1/P2):** Sign-in logs (malicious client IDs, OAuth URL patterns), audit logs (consent grants, service principal creation).
- Output: CSV and optional HTML report. IOC source: [Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md](../../../Threat-Intel/IOCs/OAuth-abuse/Microsoft-Intel-OAuth.md) (or same path in repo).

---

## Usage

```powershell
.\Check-OAuthIOCs.ps1
.\Check-OAuthIOCs.ps1 -DaysBack 90 -OutputPath C:\Reports
.\Check-OAuthIOCs.ps1 -SkipHtmlReport
```

---

## Requirements

- **PowerShell 5.1+.** Microsoft Graph PowerShell SDK or appropriate modules for Graph API access.
- **Permissions:** Delegated (interactive) sign-in; scopes as required for app registration read, sign-in logs (if P1/P2), audit logs (if P1/P2).

---

## License

Same as the root repository — see [../../../../LICENSE](../../../../LICENSE).

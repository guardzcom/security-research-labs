# Hybrid AD MFA Gap — Scripts & Queries

Scripts and queries referenced in the blog post: *"The Hidden MFA Gap in Hybrid Active Directory"*

This folder contains the artifacts that ship with the post: Graph `.http` samples, PowerShell for Entra ID and on-prem AD, and a small correlation helper.

## Graph API (`.http`)

Use with the [REST Client](https://marketplace.visualstudio.com/items?itemName=humao.rest-client) extension in VS Code (or any client that can send the request with your bearer token).

| # | File | Description |
|---|------|-------------|
| 01 | `01_graph_api_mfa_check.http` | `GET` user registration report: members with `isMfaRegistered eq false` (requires Entra ID P1+ for this reports API) |
| 02 | `02_graph_check_user_password_profile.http` | Fetch a user including `passwordProfile` (e.g. `forceChangePasswordNextSignIn`) |
| 03 | `03_graph_check_user_auth_methods.http` | List a single user’s registered authentication methods (works across tiers that allow the call) |

## PowerShell

| # | File | Description |
|---|------|-------------|
| 04 | `04_mfa_audit_all_users.ps1` | Audit all Entra ID users for MFA registration per user (`Get-MgUserAuthenticationMethod`); works without P1; exports `mfa_audit.csv` |
| 05 | `05_mfa_report_p1.ps1` | Bulk MFA gap export via `Get-MgReportAuthenticationMethodUserRegistrationDetail` (P1); writes `users_no_mfa.csv` |
| 06 | `06_find_synced_users_no_mfa.ps1` | From the P1 registration report, keep only **on-prem synced** users who are not MFA-registered |
| 07 | `07_ad_user_attributes_audit.ps1` | Table of critical AD attributes: UAC-derived flags, password / expiry fields, group count, `whenChanged` |
| 08 | `08_ad_entra_crosscheck.ps1` | For each enabled AD user, resolve Entra user by `ImmutableId`: synced or not, Entra enabled, UPN, last password change; exports `ad_entra_crosscheck.csv` |
| 09 | `09_ad_dangerous_uac_flags.ps1` | Enabled users with risky UAC bits: `PASSWD_NOTREQD`, delegation-related flags, password never expires |
| 10 | `10_ad_must_change_password.ps1` | Enabled users with `pwdLastSet` = 0 (must change password at next logon) |
| 11 | `11_graph_check_password_mfa_status.ps1` | Deep check for one UPN: password profile, P1 registration summary, and enrolled methods (edit `$targetUPN`) |
| 12 | `12_guid_conversion.ps1` | Snippets: `objectGUID` ↔ Base64 `ImmutableId`; comments for Graph / LDAP correlation |

## Prerequisites

| Requirement | Scripts |
|-------------|---------|
| Microsoft Graph PowerShell SDK (`Microsoft.Graph.*`) | 04, 05, 06, 08, 11 |
| AD RSAT / `ActiveDirectory` module | 07, 08, 09, 10, 12 |
| Entra ID P1 (reports / `userRegistrationDetails`) | 01, 05, 06, 11 |
| Graph scopes: `User.Read.All` | 04, 06, 08, 11 |
| Graph scopes: `UserAuthenticationMethod.Read.All` | 01 (token used for HTTP), 04, 05, 06, 11 |
| Graph scopes: `AuditLog.Read.All` | 01 (token used for HTTP), 05, 06, 11 |

For `.http` files, grant the same API permissions your tenant policy requires for the corresponding Graph paths, then acquire a token with those scopes.

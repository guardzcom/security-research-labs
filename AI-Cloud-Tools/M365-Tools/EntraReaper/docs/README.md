# EntraReaper v2.1

Autonomous red team platform for Microsoft Entra ID. Wraps 246 AADInternals PowerShell cmdlets into 65 MCP tools with OPSEC governance, noise budget, evasion engine, post-exploitation intelligence, and auto-reporting.

**Version:** 2.1
**Tools:** 65 MCP tools | **Scenarios:** 87 | **Kill Chains:** 13 (A-M) | **Modules:** 9
**Invoke:** `/entrareaper` | **Agent:** `aadinternals-red-agent.md`
**License:** Security research and authorized testing only

---

## Table of Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Claude Code Integration](#claude-code-integration)
- [Tool Reference](#tool-reference)
- [Attack Scenarios](#attack-scenarios)
- [Kill Chains](#kill-chains)
- [OPSEC Profiles](#opsec-profiles)
- [IOC Management](#ioc-management)
- [Token Management](#token-management)
- [macOS Compatibility](#macos-compatibility)
- [Security Design](#security-design)
- [File Reference](#file-reference)

---

## Architecture

```
Claude Code <--stdio--> MCP Server (Python/FastMCP)
                             |
                             v
                    PSBridge (asyncio.create_subprocess_exec)
                             |
                             v
                    pwsh 7 + AADInternals module
                             |
                             v
                    Microsoft Entra ID APIs
```

**Key design decisions:**

1. **FastMCP framework** -- Python MCP server using `mcp[cli]` with stdio transport
2. **PowerShell bridge** -- `asyncio.create_subprocess_exec` (no shell) for safe command execution
3. **Token store** -- Named token cache with persistence, expiry tracking, 25 resource types
4. **OPSEC profiles** -- Every tool declares its noise level and detection risk
5. **IOC store** -- Auto-collects indicators of compromise per engagement
6. **macOS polyfills** -- C# shims for `System.Web` and `JavaScriptSerializer` (Windows-only assemblies)

---

## Prerequisites

| Component | Version | Install |
|-----------|---------|---------|
| Python | 3.11+ | `brew install python@3.12` |
| uv | Latest | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| PowerShell 7 | 7.x | `brew install powershell` |
| AADInternals | 0.9.x | `pwsh -c 'Install-Module AADInternals -Scope CurrentUser -Force'` |
| mcp[cli] | 1.0+ | Auto-installed via `pyproject.toml` |
| pydantic | 2.0+ | Auto-installed via `pyproject.toml` |

---

## Installation

### 1. Verify environment

```bash
# Run the setup script
pwsh scripts/setup.ps1
```

This checks: PowerShell version, AADInternals module, API connectivity, and cmdlet count.

### 2. Install Python dependencies

```bash
cd tools/aadinternalsMCP
uv sync
```

### 3. Test the server

```bash
uv run python server.py
# Server starts on stdio -- Ctrl+C to stop
```

---

## Claude Code Integration

### Add as MCP server

```bash
claude mcp add entrareaper -- uv run --directory /path/to/aadinternalsMCP python server.py
```

Or add to `.claude/settings.json`:

```json
{
  "mcpServers": {
    "entrareaper": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/aadinternalsMCP",
        "python",
        "server.py"
      ],
      "description": "AADInternals Entra ID offensive security toolkit -- 35 tools across 12 attack phases"
    }
  }
}
```

### Verify registration

Once registered, Claude Code will have access to all 35 tools. Test with:

```
Use the aadinternals session_status tool to check the environment.
```

---

## Tool Reference

### 35 MCP Tools by MITRE ATT&CK Phase

#### Session and Environment (3 tools)

| Tool | Description | Auth Required |
|------|-------------|---------------|
| `session_status` | Check pwsh, AADInternals version, list cached tokens | None |
| `session_clear_tokens` | Clear all cached tokens | None |
| `opsec_check` | Get OPSEC profile for any tool before running it | None |

#### Phase 1: Reconnaissance -- Unauthenticated (5 tools)

| Tool | Cmdlet(s) | OPSEC | What It Returns |
|------|-----------|-------|-----------------|
| `recon_tenant` | `Invoke-AADIntReconAsOutsider` | Silent | Tenant ID, federation type, brand, auth endpoints, MDI |
| `recon_users` | `Invoke-AADIntUserEnumerationAsOutsider` | Low | List of valid/invalid usernames (no lockout, no logs) |
| `recon_domains` | `Get-AADIntTenantDomains` | Silent | All registered domains in the tenant |
| `recon_openid` | `Get-AADIntOpenIDConfiguration` | Silent | OIDC endpoints, signing keys, issuer, response types |
| `recon_dns` | `Get-AADIntLoginInformation`, `Get-AADIntTenantId` | Silent | MX records, federation URLs, autodiscover |

#### Phase 2: Reconnaissance -- Authenticated (4 tools)

| Tool | Cmdlet(s) | OPSEC | What It Returns |
|------|-----------|-------|-----------------|
| `recon_insider` | `Invoke-AADIntReconAsInsider` | Medium | All users, groups, apps, roles, domains, policies |
| `recon_guest` | `Invoke-AADIntReconAsGuest` | Low-Medium | Visible users, groups, apps, roles, devices |
| `recon_ca_policies` | `Get-AADIntConditionalAccessPolicies` | Medium | All CA policies (exclusions, legacy auth gaps) |
| `recon_sync_config` | `Get-AADIntSyncConfiguration` + features + SSO | Medium | PHS/PTA/SSO status, hybrid attack paths |

#### Phase 3: Credential Access (7 tools)

| Tool | Cmdlet(s) | OPSEC | What It Does |
|------|-----------|-------|-------------|
| `cred_token` | `Get-AADIntAccessTokenFor{Resource}` | Medium | Obtain token via interactive, credentials, or device code |
| `cred_device_code` | `Get-AADIntAccessTokenFor{Resource} -Device` | Low | Device code phishing flow with MS first-party client IDs |
| `cred_token_decode` | `Read-AADIntAccessToken` | None (local) | Decode JWT: audience, issuer, UPN, roles, scopes, expiry |
| `cred_prt_extract` | `Get-AADIntUserPRTKeys` / `New-AADIntUserPRTToken` | Medium | Extract or create PRT for device impersonation |
| `cred_cookie` | `Get-AADIntESTSAUTHCookie` | Medium | Extract or decode ESTSAUTH session cookies |
| `cred_nthash` | `Get-AADIntUserNTHash` | HIGH | Cloud DCSync -- extract NT hashes via DCaaS |
| `cred_mfa_read` | `Get-AADIntUserMFA` / `Get-AADIntUserMFAApps` | Medium | Read MFA methods, phone numbers, authenticator apps |

#### Phase 4: Initial Access (2 tools)

| Tool | Cmdlet(s) | OPSEC | What It Does |
|------|-----------|-------|-------------|
| `access_phishing` | `Invoke-AADIntPhishing` | Low-Medium | Send device code phishing emails, capture tokens |
| `access_guest_invite` | `New-AADIntGuestInvitation` | Medium | Invite external user as guest to the tenant |

#### Phase 5: Persistence (5 tools)

| Tool | Cmdlet(s) | OPSEC | What It Does |
|------|-----------|-------|-------------|
| `persist_federation` | `ConvertTo-AADIntBackdoor` / `Find-AADIntBackdoor` | LOUD | Install/detect Golden SAML federation backdoor |
| `persist_saml_forge` | `New-AADIntSAMLToken` / `New-AADIntSAML2Token` | Low (post-install) | Forge SAML token for any user |
| `persist_device` | `Join-AADIntDeviceToAzureAD` / `Join-AADIntDeviceToIntune` | Medium | Register rogue device, get device cert + PRT |
| `persist_pta_agent` | `Register-AADIntPTAAgent` | LOUD | Register rogue PTA agent (accepts any password) |
| `persist_mfa_app` | `Register-AADIntMFAApp` | Medium | Register rogue authenticator app for TOTP persistence |

#### Phase 6: Privilege Escalation (3 tools)

| Tool | Cmdlet(s) | OPSEC | What It Does |
|------|-----------|-------|-------------|
| `privesc_azure_admin` | `Grant-AADIntAzureUserAccessAdminRole` | HIGH | Self-elevate to Azure User Access Administrator |
| `privesc_password_reset` | `Set-AADIntUserPassword` | HIGH | Reset any password via Sync API (no old password, no MFA) |
| `privesc_role_assign` | `Set-AADIntAzureRoleAssignment` | HIGH | Assign Azure RBAC roles (Owner, Contributor, etc.) |

#### Phase 7: Defense Evasion (2 tools)

| Tool | Cmdlet(s) | OPSEC | What It Does |
|------|-----------|-------|-------------|
| `evade_audit_logs` | `Get/Set-AADIntUnifiedAuditLogSettings` | LOUD | Check/disable/enable Unified Audit Log |
| `evade_policy_weaken` | Various `Set-AADInt*` | HIGH | Weaken guest access, PTA, SSO settings |

#### Phase 8: Lateral Movement (3 tools)

| Tool | Cmdlet(s) | OPSEC | What It Does |
|------|-----------|-------|-------------|
| `move_vm_exec` | `Invoke-AADIntAzureVMScript` | HIGH | Run scripts on Azure VMs (RCE) |
| `move_messaging` | `Send-AADIntTeamsMessage` / `Send-AADIntOutlookMessage` | Medium | Internal phishing via Teams or Outlook |
| `move_partner_pivot` | `Get-AADIntMSPartnerContracts` | Medium | Pivot through MSP/GDAP relationships |

#### Phase 9: Collection (4 tools)

| Tool | Cmdlet(s) | OPSEC | What It Does |
|------|-----------|-------|-------------|
| `collect_onedrive` | `Get-AADIntOneDriveFiles` | Medium | List/download OneDrive files |
| `collect_sharepoint` | `Get-AADIntSPOSiteUsers` / `Export-AADIntSPOSiteFile` | Medium | SPO site users, groups, file download/upload |
| `collect_teams` | `Get-AADIntTeamsMessages` / `Get-AADIntMyTeams` | Medium | Teams messages and team listings |
| `collect_email` | `Open-AADIntOWA` | Medium | Open Outlook Web Access as token owner |

#### Phase 10: Impact (2 tools)

| Tool | Cmdlet(s) | OPSEC | What It Does |
|------|-----------|-------|-------------|
| `impact_user_ops` | `New/Remove/Set-AADIntUser`, `Set-AADIntUserMFA` | LOUD | Create/delete/modify users, disable MFA |
| `impact_config` | `Set-AADIntDeviceCompliant`, `New-AADIntMOERADomain` | LOUD | Spoof compliance, add domains, set domain auth |

#### Phase 11: Azure Resources (1 tool)

| Tool | Cmdlet(s) | OPSEC | What It Does |
|------|-----------|-------|-------------|
| `azure_enum` | `Get-AADIntAzureSubscriptions` / VMs / Tenants | Low-Medium | Enumerate Azure subscriptions, VMs, tenants, admins |

#### Phase 12: Kerberos and SSO (1 tool)

| Tool | Cmdlet(s) | OPSEC | What It Does |
|------|-----------|-------|-------------|
| `kerberos_ticket` | `New-AADIntKerberosTicket` | -- | Silver Ticket for Seamless SSO (requires AZUREADSSOACC$ hash) |

#### Escape Hatch (1 tool)

| Tool | Description | OPSEC |
|------|-------------|-------|
| `raw_invoke` | Run any AADInternals cmdlet directly | Varies |

---

## Attack Scenarios

### 65 scenarios organized by attack phase. Each has:

- **Hat color**: WHITE (authorized pentest), GRAY (bug bounty/research), BLACK (adversary simulation)
- **Perspective**: EXTERNAL, EXTERNAL+CRED, INTERNAL, PARTNER, PRIVILEGED
- **OPSEC rating**: Silent, Low, Medium, High, LOUD
- **MITRE ATT&CK mapping**

### Scenario Index

#### Reconnaissance -- Unauthenticated (S01-S08)

| # | Name | Hat | OPSEC | Tools |
|---|------|-----|-------|-------|
| S01 | Tenant Fingerprint | WHITE | Silent | `recon_tenant` |
| S02 | Domain Inventory | WHITE | Silent | `recon_domains` |
| S03 | User Enum -- C-Suite (targeted 10) | GRAY | Low | `recon_users` |
| S04 | User Enum -- Bulk OSINT (2000+) | GRAY | Low | `recon_users` |
| S05 | Federation Endpoint Discovery | WHITE | Silent | `recon_dns` |
| S06 | OpenID Config Harvest | WHITE | Silent | `recon_openid` |
| S07 | Multi-Tenant Supply Chain Recon | GRAY | Silent | `recon_tenant` x N |
| S08 | ActiveSync Protocol Probing | WHITE | Silent | `raw_invoke` |

#### Reconnaissance -- Authenticated (S09-S16)

| # | Name | Hat | OPSEC | Tools |
|---|------|-----|-------|-------|
| S09 | Full Insider Tenant Dump | WHITE | Medium | `recon_insider` |
| S10 | Conditional Access Gap Analysis | WHITE | Medium | `recon_ca_policies` |
| S11 | Hybrid Infrastructure Assessment | WHITE | Medium | `recon_sync_config` |
| S12 | Guest Access Boundary Testing | GRAY | Low | `recon_guest` |
| S13 | Dynamic Group Privesc Discovery | GRAY | Medium | `raw_invoke` |
| S14 | Service Principal / App Audit | WHITE | Medium | `raw_invoke` |
| S15 | MFA Method Weakness Assessment | WHITE | Medium | `cred_mfa_read` |
| S16 | Access Package Self-Service Escalation | GRAY | Medium | `raw_invoke` |

#### Credential Access (S17-S24)

| # | Name | Hat | OPSEC | Tools |
|---|------|-----|-------|-------|
| S17 | Device Code Phish -- Office | GRAY | Low | `cred_device_code` |
| S18 | Device Code Phish -- Teams | GRAY | Low | `cred_device_code` |
| S19 | FOCI Token Cross-Resource Pivot | GRAY | Medium | `cred_token` x N |
| S20 | JWT Token Forensic Analysis | WHITE | None | `cred_token_decode` |
| S21 | Browser Session Cookie Extraction | GRAY | Medium | `cred_cookie` |
| S22 | PRT Extraction for Device Impersonation | GRAY | Medium | `cred_prt_extract` |
| S23 | Cloud DCSync (NT Hash Extraction) | BLACK | HIGH | `cred_nthash` |
| S24 | Stolen Credential Validation | GRAY | Medium | `cred_token` |

#### Initial Access (S25-S26)

| # | Name | Hat | OPSEC | Tools |
|---|------|-----|-------|-------|
| S25 | Automated Phishing Campaign | GRAY | Medium | `access_phishing` |
| S26 | Guest Account Infiltration | GRAY | Medium | `access_guest_invite` |

#### Persistence (S27-S33)

| # | Name | Hat | OPSEC | Tools |
|---|------|-----|-------|-------|
| S27 | Golden SAML Backdoor Install | BLACK | LOUD | `persist_federation` |
| S28 | SAML Token Forging | BLACK | Low | `persist_saml_forge` |
| S29 | Rogue Device -- AAD Join | GRAY | Medium | `persist_device` |
| S30 | Rogue Device -- Intune Enrollment | GRAY | Medium | `persist_device` |
| S31 | Rogue PTA Agent -- Total Auth Bypass | BLACK | LOUD | `persist_pta_agent` |
| S32 | Rogue MFA Authenticator | GRAY | Medium | `persist_mfa_app` |
| S33 | Rogue Sync Agent | BLACK | HIGH | `raw_invoke` |

#### Privilege Escalation (S34-S37)

| # | Name | Hat | OPSEC | Tools |
|---|------|-----|-------|-------|
| S34 | Azure Subscription Takeover | BLACK | HIGH | `privesc_azure_admin` |
| S35 | Sync API Password Reset | BLACK | HIGH | `privesc_password_reset` |
| S36 | Azure RBAC Role Injection | GRAY | HIGH | `privesc_role_assign` |
| S37 | Group Membership Injection via Sync API | BLACK | HIGH | `raw_invoke` |

#### Defense Evasion (S38-S41)

| # | Name | Hat | OPSEC | Tools |
|---|------|-----|-------|-------|
| S38 | Audit Log Suppression | BLACK | LOUD | `evade_audit_logs` |
| S39 | Tenant Permissiveness Escalation | GRAY | HIGH | `evade_policy_weaken` |
| S40 | Disable PTA (Force Cloud Auth) | BLACK | HIGH | `evade_policy_weaken` |
| S41 | Disable Seamless SSO | GRAY | HIGH | `evade_policy_weaken` |

#### Lateral Movement (S42-S45)

| # | Name | Hat | OPSEC | Tools |
|---|------|-----|-------|-------|
| S42 | Azure VM Remote Code Execution | GRAY | HIGH | `move_vm_exec` |
| S43 | Teams Internal Spearphishing | GRAY | Medium | `move_messaging` |
| S44 | Business Email Compromise | BLACK | Medium | `move_messaging` |
| S45 | MSP Partner Tenant Pivot | BLACK | Medium | `move_partner_pivot` |

#### Collection and Exfiltration (S46-S49)

| # | Name | Hat | OPSEC | Tools |
|---|------|-----|-------|-------|
| S46 | OneDrive Data Exfiltration | GRAY | Medium | `collect_onedrive` |
| S47 | SharePoint Intelligence Gathering | GRAY | Medium | `collect_sharepoint` |
| S48 | Teams Message Harvest | GRAY | Medium | `collect_teams` |
| S49 | Full Mailbox Collection | GRAY | Medium | `collect_email` |

#### Impact (S50)

| # | Name | Hat | OPSEC | Tools |
|---|------|-----|-------|-------|
| S50 | Full Tenant Takeover -- Combined | BLACK | LOUD | `impact_user_ops` + `impact_config` + `persist_federation` |

#### Advanced Scenarios (S51-S65)

| # | Name | Hat | OPSEC | Tools |
|---|------|-----|-------|-------|
| S51 | OAuth Consent Grant Attack | BLACK | Medium | `raw_invoke` |
| S52 | AAD Connect Credential Extraction | BLACK | HIGH | `raw_invoke` |
| S53 | Cloud Shell Hijacking | GRAY | Medium | `raw_invoke` |
| S54 | Hybrid Health Service Event Injection | BLACK | HIGH | `raw_invoke` |
| S55 | WHfB Key Injection | BLACK | Medium | `raw_invoke` |
| S56 | App Proxy Agent Impersonation | BLACK | HIGH | `raw_invoke` |
| S57 | Staged Rollout Policy Manipulation | BLACK | HIGH | `raw_invoke` |
| S58 | Azure IMDS Token Theft | GRAY | Low | `raw_invoke` |
| S59 | SharePoint Site Membership Injection | GRAY | Medium | `raw_invoke` |
| S60 | Diagnostic Settings Manipulation | BLACK | HIGH | `raw_invoke` |
| S61 | ADFS Token Decryption and Forging | BLACK | HIGH | `raw_invoke` |
| S62 | B2C Tenant Key Extraction | GRAY | Medium | `raw_invoke` |
| S63 | ActiveSync Device Injection + MDM Bypass | GRAY | Medium | `raw_invoke` |
| S64 | Compliance Portal Data Mining | GRAY | Medium | `raw_invoke` |
| S65 | User Agent Masquerading | GRAY | Low | `raw_invoke` |

---

## Kill Chains

Pre-built multi-scenario attack sequences:

| Chain | Name | Sequence | Description |
|-------|------|----------|-------------|
| **A** | External to Global Admin | S01->S03->S17->S20->S09->S10->S15->S34 | Recon -> User Enum -> Phish -> Decode -> Insider Recon -> CA Audit -> MFA Audit -> Azure Escalate |
| **B** | Golden SAML Persistence | S01->S17->S09->S27->S28->S49->S38 | Recon -> Phish -> Map Tenant -> Backdoor -> Forge -> Exfil Mail -> Disable Logs |
| **C** | BEC Financial Fraud | S03->S17->S19->S49->S44->S46 | User Enum -> Phish -> FOCI Pivot -> Read Mail -> BEC -> Exfil OneDrive |
| **D** | MSP Supply Chain | S07->S03->S17->S45->S09->S50 | Supply Chain Recon -> User Enum -> Phish MSP -> Pivot Customers -> Map Tenant -> Full Takeover |
| **E** | Hybrid Infrastructure Takeover | S01->S17->S11->S31->S24->S34->S42 | Recon -> Phish -> Map Hybrid -> Rogue PTA -> Auth as Anyone -> Azure Escalate -> VM RCE |
| **F** | Silent Data Exfiltration | S03->S18->S19->S48->S46->S47->S49 | User Enum -> Phish (Teams) -> FOCI Pivot -> Teams -> OneDrive -> SharePoint -> Email |
| **G** | Device Trust Abuse | S01->S17->S10->S29->S22->S19 | Recon -> Phish -> CA Audit -> Rogue Device -> PRT Extract -> FOCI Access All |
| **H** | MFA Bypass Persistence | S03->S17->S15->S32->S24 | User Enum -> Phish -> MFA Audit -> Rogue Auth App -> Login Anytime |
| **I** | Silent Persistence (No Fed Mod) | S65->S17->S55->S32->S63 | Set UA -> Phish -> WHfB Key Inject -> Rogue MFA App -> EAS Device Inject |
| **J** | Insider Threat Data Miner | S65->S19->S59->S47->S64->S38 | Set UA -> FOCI Pivot -> SPO Inject -> SP Exfil -> Compliance Search -> Disable Logs |
| **K** | Hybrid Infrastructure Destruction | S52->S35->S31->S57->S54->S60 | Extract Sync Creds -> Reset Passwords -> Rogue PTA -> Downgrade Auth -> Health Inject -> Redirect Logs |

---

## OPSEC Profiles

Every tool has a pre-defined OPSEC profile accessible via `opsec_check(tool_name)`.

| Level | Meaning | Examples |
|-------|---------|---------|
| **Silent** | Zero logs, public APIs only | `recon_tenant`, `recon_domains`, `recon_dns`, `recon_openid` |
| **Low** | Minimal/no sign-in logs | `recon_users`, `cred_device_code` |
| **Medium** | Sign-in or audit logs generated | `recon_insider`, `cred_token`, `collect_*`, `move_messaging` |
| **High** | Privilege-level operations logged | `cred_nthash`, `privesc_*`, `move_vm_exec` |
| **LOUD** | High-fidelity security alerts triggered | `persist_federation`, `persist_pta_agent`, `evade_audit_logs`, `impact_user_ops` |

### Profile Fields

Each profile contains:

```json
{
  "tool": "persist_federation",
  "noise_level": "loud",
  "logs_generated": ["Entra ID audit logs (domain federation change)", "Azure Activity logs"],
  "detection_risk": "CRITICAL. Federation changes are high-fidelity alerts in most SIEM/ITDR products.",
  "evasion_notes": "Target a lesser-monitored domain. Change during maintenance windows. Revert after use."
}
```

**18 tools have OPSEC profiles** covering: recon (3), credential access (2), persistence (3), privilege escalation (2), defense evasion (1), lateral movement (2), collection (2), impact (1).

---

## IOC Management

The IOC store (`ioc_store.py`) auto-collects indicators during operations and persists them per engagement.

### IOC Types

| Type | Examples |
|------|---------|
| `tenant_id` | Entra ID tenant GUIDs |
| `domain` | Registered domains, federation domains |
| `user` | Confirmed UPNs from enumeration |
| `endpoint` | Exchange protocol URLs (ActiveSync, EWS, REST) |
| `url` | Federation URLs, OIDC endpoints, ADFS metadata |
| `metadata` | Auth type, brand name, SSO status, region |
| `token` | Captured tokens (stored in token store, referenced here) |
| `app_id` | OAuth application IDs |

### IOC Risk Classification

| Risk | Criteria |
|------|----------|
| `critical` | Admin accounts, federation backdoor certs |
| `high` | Admin/helpdesk users, federation endpoints, SSO indicators |
| `medium` | Test/dev/service accounts, ActiveSync endpoints |
| `low` | Regular user accounts |
| `info` | Tenant IDs, domains, OIDC config, region |

### IOC Output

Stored in `iocs/` directory:
- `{engagement}.json` -- Machine-readable IOC data
- `{engagement}_report.md` -- Markdown report grouped by type

### Auto-Extraction

The `extract_iocs_from_recon()` function automatically parses recon results and creates IOCs for:
- Tenant IDs, domains, confirmed users
- Federation endpoints and metadata URLs
- OIDC endpoints (issuer, token, authorization, JWKS)
- Exchange protocol endpoints
- Auth configuration (SSO, federation type, brand)

---

## Token Management

### Token Store

Tokens are cached in `~/.entrareaper/tokens.json` with:

| Field | Description |
|-------|-------------|
| `alias` | User-friendly name (e.g., "graph", "exo", "admin") |
| `resource` | Target API resource URL |
| `token_type` | `access`, `refresh`, `prt`, `saml`, `kerberos` |
| `expires_at` | Unix timestamp for expiry checking |
| `obtained_via` | How it was obtained (interactive, device_code, phishing, golden_saml) |
| `tenant_id` | Source tenant |
| `user_principal_name` | Token owner |

### 25 Supported Resources

```
graph, aad_graph, exo, spo, onedrive, teams, azure, azure_core,
intune, pta, compliance, admin, cloud_shell, partner, sara,
commerce, aad_join, office_apps, my_signins, onenote, whfb,
iam_api, azure_mgmt, spo_migration, access_packages
```

Each maps to a specific `Get-AADIntAccessTokenFor{Resource}` cmdlet.

### Token Lifecycle

1. Obtain via `cred_token`, `cred_device_code`, or `access_phishing`
2. Auto-cached with alias, metadata, and expiry
3. Referenced by alias in all authenticated tools
4. Expiry warnings on use
5. Clear all with `session_clear_tokens`

---

## macOS Compatibility

AADInternals was built for Windows PowerShell. The `compat.ps1` layer provides C# polyfills for two missing .NET assemblies:

### Problem

| Assembly | Windows | macOS |
|----------|---------|-------|
| `System.Web.dll` | Built-in | Missing |
| `System.Web.Extensions.dll` | Built-in | Missing |

AADInternals uses `HttpUtility.UrlEncode/UrlDecode/HtmlEncode/HtmlDecode` and `JavaScriptSerializer` extensively.

### Solution

`compat.ps1` defines polyfill C# classes in the exact namespaces AADInternals expects:

| Missing Class | Polyfill Implementation |
|---------------|------------------------|
| `System.Web.HttpUtility` | Maps to `System.Uri` + `System.Net.WebUtility` (.NET Core) |
| `System.Web.Script.Serialization.JavaScriptSerializer` | Maps to `System.Text.Json` (.NET Core 3.0+) |

**Load order matters**: `compat.ps1` loads FIRST (defines polyfill types), then AADInternals imports with `SilentlyContinue` (its `Add-Type -AssemblyName` calls fail on macOS, but polyfill types are already in memory).

---

## Security Design

### Three-Layer Injection Prevention

| Layer | File | Protection |
|-------|------|------------|
| 1. No shell | `bridge.py:157` | `create_subprocess_exec` -- OS passes arguments as discrete array elements, shell never interprets them |
| 2. Cmdlet validation | `bridge.py:57` | Regex: only `^[A-Za-z]+-AADInt[A-Za-z]+$` pattern allowed (plus `Get-Module`, `Get-Command`) |
| 3. String sanitization | `bridge.py:92` | PowerShell single-quote escaping (`'` -> `''`) on all parameter values |

**Layer 1** prevents OS-level injection (`;rm -rf /`).
**Layer 2** prevents arbitrary PowerShell cmdlets (`Invoke-Expression`, `Start-Process`).
**Layer 3** prevents breaking out of PowerShell string literals.

### Parameter Validation

| Check | Location | Rule |
|-------|----------|------|
| Cmdlet name | `bridge.py:57` | Must match AADInt naming pattern |
| Parameter names | `bridge.py:65` | Must match `^[A-Za-z][A-Za-z0-9_]*$` |
| String values | `bridge.py:92` | Single quotes escaped |
| Numeric values | `bridge.py:77` | Passed directly (no string interpolation) |
| Boolean values | `bridge.py:72` | Converted to PowerShell switch flags |
| Array values | `bridge.py:74` | Each item individually sanitized |

### Timeout Protection

| Scope | Default | Max |
|-------|---------|-----|
| Standard commands | 120s | -- |
| Long operations (enum/spray) | 600s | 600s |
| `raw_invoke` user-specified | 120s | 600s |

---

## File Reference

```
aadinternalsMCP/
|
|-- CORE (Python modules)
|   server.py                MCP server — 44 tools across 12 phases
|   bridge.py                PowerShell subprocess bridge (injection-safe)
|   token_store.py           Named token cache with persistence
|   opsec.py                 OPSEC profiles for 18 tools
|   ioc_store.py             IOC collection, dedup, and reporting
|   engagement_store.py      Auto-save engine for all 15 engagement folders
|   compat.ps1               macOS polyfills for System.Web + JavaScriptSerializer
|   pyproject.toml           Python project config
|   __init__.py              Package marker
|
|-- RECON DATA (what you learn about the target)
|   fingerprints/            Per-target tenant identity (markdown-kv, static)
|   behavior/                Evolving attack surface profiles (grows per cycle)
|   results/                 Point-in-time recon snapshots (immutable)
|   iocs/                    Indicators of compromise (JSON + markdown)
|
|-- CREDENTIALS (what you capture)
|   tokens/                  Per-engagement exported token dumps
|   creds/                   Captured credentials (hashes, MFA secrets, PRT keys)
|   certs/                   Cryptographic material (signing certs, device certs)
|
|-- COLLECTION (what you take)
|   loot/                    Downloaded files from collection phase
|
|-- OPERATIONS (how you operate)
|   playbooks/               Kill chain execution journal
|   noise/                   Actual telemetry footprint vs OPSEC predictions
|   persistence/             Live backdoor inventory (needs teardown)
|
|-- DEFENSE (what defenders should see)
|   signals/                 Detection opportunities per tool
|
|-- REPORTING (what you deliver)
|   reports/                 Engagement deliverables
|
|-- REFERENCE (playbooks and data)
|   scenarios/               65 attack scenarios + 11 kill chains
|   black-white/FOCI-app/    180+ Entra ID app IDs (FOCI, BroCI, phishing)
|   docs/                    This documentation + architecture diagrams
|   scripts/                 Setup scripts + MCP config
```

### Auto-Save Hooks (Real-Time)

Tools automatically save to the right folders on execution:

| Tool Category | Folders Written |
|---------------|----------------|
| `recon_*` | fingerprints/, behavior/, results/ |
| `cred_nthash`, `cred_prt_extract` | creds/, playbooks/, noise/ |
| `persist_*` | persistence/, certs/, creds/, playbooks/, noise/ |
| `access_*`, `privesc_*` | persistence/, playbooks/, noise/ |
| `collect_*` | loot/ (planned) |
| All tools | playbooks/ (execution log), noise/ (footprint) |

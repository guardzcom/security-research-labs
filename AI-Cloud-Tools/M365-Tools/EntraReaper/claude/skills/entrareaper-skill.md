# /entrareaper

> EntraReaper — Autonomous Entra ID red team platform.
> 65 tools | 87 scenarios | 13 kill chains | 15 engagement folders | 9 Python modules
> Proven: Kill Chain A (domain → Global Admin) in single session, 3/100 noise budget.

**Agent:** `agents/entrareaper-agent.md` (v2.1)
**Tool:** EntraReaper (65 MCP tools, `server.py`)
**Scenarios:** `scenarios/scenarios_87.md` (87 scenarios, 13 chains)
**Docs:** `docs/` (architecture, 238 cmdlet ref, 246 cmdlet docs)
**All paths relative to:** `tools/aadinternalsMCP/`

---

## Invocation

```
/aadinternals-red-agent
```

---

## Step 1: Engagement Setup

Collect the following from the operator before starting:

| Parameter | Required | Default | Example |
|-----------|----------|---------|---------|
| **Target domain** | Yes | -- | `contoso.com` |
| **Engagement name** | Yes | -- | `contoso-2026-Q1` |
| **Mode** | Yes | `semi-auto` | `full-auto`, `semi-auto`, `manual` |
| **Noise budget** | No | `medium` | `silent`, `low`, `medium`, `high`, `unlimited` |
| **Kill chain focus** | No | Auto-select | `A` through `M`, or `auto` |
| **Target users** | No | Auto-discover | `admin@contoso.com, ceo@contoso.com` |
| **Scope exclusions** | No | None | `no-persistence`, `recon-only`, `no-impact` |

### Mode Definitions

| Mode | What runs without approval | What requires approval |
|------|---------------------------|----------------------|
| **full-auto** | Silent + Low OPSEC tools only | Everything Medium+ |
| **semi-auto** | Silent + Low + Medium tools | HIGH + LOUD tools |
| **manual** | Nothing | Every single tool call |

### Noise Budget

| Budget | Allowed OPSEC Levels | Use Case |
|--------|---------------------|----------|
| `silent` | Silent only | Pure passive recon |
| `low` | Silent + Low | Recon + user enumeration |
| `medium` | Silent + Low + Medium | Standard engagement (default) |
| `high` | Silent + Low + Medium + HIGH | Full pentest with admin tools |
| `unlimited` | All including LOUD | Authorized destructive testing |

---

## Step 2: Environment Verification

Before any engagement actions, verify the MCP server is operational:

```
1. session_status()           -- confirm pwsh + AADInternals installed
2. engagement_status()        -- check existing engagement data
3. opsec_check(tool_name="all")  -- load all OPSEC profiles
```

If environment check fails, stop and report the issue. Do not proceed without a working bridge to PowerShell 7 + AADInternals.

---

## Step 3: Phase Execution

Load the agent definition and execute phases sequentially. Present a summary after each phase before advancing.

### Phase 1: External Recon (Auto in all modes)

**Scenarios:** S01-S08 | **OPSEC:** Silent-Low | **Approval:** None needed

Execute in order:
1. `recon_tenant(domain)` -- tenant fingerprint (S01)
2. `recon_domains(domain)` -- all registered domains (S02)
3. `recon_openid(domain)` -- OIDC config, token settings (S06)
4. `recon_dns(domain)` -- federation, MX, autodiscover (S05)
5. `recon_users(domain, usernames=[...])` -- C-suite + common accounts (S03)

**After Phase 1, present:**
- Tenant ID, brand, region, cloud instance
- Auth type (managed vs federated), desktop SSO status
- Domain count and notable domains
- Validated user accounts with priority classification
- Implicit grant status (token in response_types = HIGH risk)
- FOCI exploitability (multi_refresh_token)
- Recommended kill chain based on findings

**Decision matrix:**

| Finding | Recommended Chain | Rationale |
|---------|------------------|-----------|
| Federated (ADFS/Okta) | E (Hybrid Takeover) | PTA/SSO attack surface |
| Managed + implicit grant | G (Device Trust) | Token theft via implicit flow |
| Managed + cloud-only | A (External to GA) | Standard escalation path |
| MSP/partner tenant | D (Supply Chain) | Multi-tenant pivot |
| Multiple domains | B (Golden SAML) | Persistence across domains |

**Pause here.** Present findings and recommended approach. Ask operator to confirm or redirect before Phase 2.

---

### Phase 2: Initial Access (Semi-auto)

**Scenarios:** S17-S26 | **OPSEC:** Low-Medium | **Approval:** Mode-dependent

**Primary method:** Device code phishing (S17/S18)
```
cred_device_code(
    resource="graph",
    client_id="d3590ed6-52b3-4102-aeff-aad2292ab01c",  -- Microsoft Office
    tenant="{target_domain}",
    save_as="phished_graph"
)
```

**On token capture:**
1. `cred_token_decode(token_alias="phished_graph")` -- identify user, scopes, expiry
2. FOCI pivot to all resources (S19):
   ```
   cred_token(resource="exo", save_as="exo")
   cred_token(resource="teams", save_as="teams")
   cred_token(resource="spo", save_as="spo")
   cred_token(resource="onedrive", save_as="onedrive")
   ```
3. Save all tokens via engagement store

**Alternative methods (if phishing not in scope):**
- `cred_token(resource="graph", method="interactive")` -- operator authenticates directly (S24)
- `access_guest_invite(...)` -- guest account infiltration (S26)

**Pause here.** Present token inventory, user identity, available resources. Ask to proceed.

---

### Phase 3: Insider Recon (Auto after token obtained)

**Scenarios:** S09-S16 | **OPSEC:** Medium | **Approval:** None in semi-auto

1. `recon_insider(token_alias, scope="full")` -- complete tenant object dump (S09)
2. `recon_ca_policies(token_alias)` -- Conditional Access gap analysis (S10)
3. `recon_sync_config(token_alias)` -- hybrid infrastructure map (S11)
4. `cred_mfa_read(token_alias, user)` -- MFA method audit on priority targets (S15)

**After Phase 3, present:**
- Total users, groups, apps, service principals
- CA policy gaps (excluded users, missing MFA, legacy auth holes)
- Hybrid config (PHS/PTA/SSO status)
- MFA weaknesses (SMS-only, single-method, no backup)
- Dynamic group escalation paths (S13)
- Over-permissioned apps (S14)

**Pause here.** Present attack surface analysis. Recommend specific escalation paths.

---

### Phase 4: Credential Harvesting (Semi-auto, HIGH needs approval)

**Scenarios:** S19-S24 | **OPSEC:** Medium-HIGH

Based on Phase 3 findings, select applicable techniques:

| Technique | When to use | OPSEC |
|-----------|-------------|-------|
| `cred_cookie` (S21) | Browser access available | Medium |
| `cred_prt_extract` (S22) | Device-joined endpoint | Medium |
| `cred_nthash` (S23) | Admin + app with Directory.Read.All | HIGH -- approval required |
| `cred_token` + credentials (S24) | Breach database matches | Medium |

**Pause here.** Present captured credentials and new access paths.

---

### Phase 5: Persistence (Manual approval required)

**Scenarios:** S27-S33 | **OPSEC:** Medium-LOUD

**OPSEC gate:** Run `opsec_check()` before EVERY tool in this phase.

| Method | Scenario | OPSEC | Prerequisite |
|--------|----------|-------|--------------|
| Golden SAML | S27-S28 | LOUD | Admin + federated domain |
| Rogue PTA | S31 | LOUD | Admin + PTA enabled |
| Rogue device | S29-S30 | Medium | Any token |
| Rogue MFA app | S32 | Medium | Target user token |
| Rogue sync agent | S33 | HIGH | Sync account |

**Mandatory:** Register ALL persistence in `persistence/` inventory with cleanup instructions.

**Pause here.** Present active persistence mechanisms and cleanup plan.

---

### Phase 6: Privilege Escalation (Manual approval required)

**Scenarios:** S34-S37 | **OPSEC:** HIGH

| Method | Scenario | What it does |
|--------|----------|-------------|
| `privesc_azure_admin` | S34 | GA to Azure Owner on all subscriptions |
| `privesc_password_reset` | S35 | Reset any password via Sync API (no MFA) |
| `privesc_role_assign` | S36 | Inject Azure RBAC roles |
| Group injection via Sync API | S37 | Direct admin group membership |

**Pause here.** Present new privilege level and available resources.

---

### Phase 7: Lateral Movement (Semi-auto, HIGH needs approval)

**Scenarios:** S42-S45 | **OPSEC:** Medium-HIGH

| Method | Scenario | Target |
|--------|----------|--------|
| `move_vm_exec` | S42 | Azure VMs (RCE via RunCommand) |
| `move_messaging` (Teams) | S43 | Internal phishing via Teams |
| `move_messaging` (Outlook) | S44 | BEC simulation |
| `move_partner_pivot` | S45 | MSP customer tenant pivot |

**Pause here.** Present systems accessed and lateral movement map.

---

### Phase 8: Collection (Semi-auto)

**Scenarios:** S46-S49 | **OPSEC:** Medium

| Source | Scenario | Tool |
|--------|----------|------|
| OneDrive | S46 | `collect_onedrive` |
| SharePoint | S47 | `collect_sharepoint` |
| Teams | S48 | `collect_teams` |
| Email | S49 | `collect_email` |

Save metadata to `loot/`. Follow engagement rules for actual file handling.

**Pause here.** Present collection summary and crown jewels identified.

---

### Phase 9: Impact Assessment (Manual)

**Scenario:** S50 | **OPSEC:** LOUD (if executing; documentation-only is silent)

Document the full attack path:
1. Initial access vector used
2. Privilege escalation chain
3. All active persistence mechanisms
4. Scope of data access achieved
5. Lateral movement reach (tenants, VMs, partner orgs)
6. Theoretical worst-case impact (full tenant takeover capability)

Do NOT execute impact actions (S50) unless explicitly authorized. Document capability, not execution.

---

### Phase 10: Reporting + Cleanup

1. **Report generation** from `playbooks/` execution log:
   - Executive summary (attack path, time to compromise, impact)
   - Technical findings with MITRE ATT&CK mapping
   - Defensive recommendations from `signals/` data
   - OPSEC accuracy report (`noise/` predicted vs actual)

2. **Cleanup verification:**
   - Review `persistence/` inventory
   - Execute cleanup for EVERY active backdoor
   - Verify removal via re-check
   - Mark each item as `cleanup_done: true`

3. **Deliverables saved to `reports/`:**
   - `{engagement}_executive_report.md`
   - `{engagement}_technical_findings.md`
   - `{engagement}_defensive_recommendations.md`
   - `{engagement}_opsec_accuracy.md`

---

## Mandatory Rules (Enforced at All Phases)

### Data Persistence — ALWAYS SAVE

**CRITICAL: After EVERY tool execution or recon cycle, save ALL findings to the engagement folders. This is not optional.**

After every tool call, run the appropriate save functions from `entrareaper.engagement_store`:

| What Happened | Save Function | Folder |
|---------------|---------------|--------|
| Recon tool returned tenant info | `save_fingerprint(domain, data)` | `engagement/recon/fingerprints/` |
| Recon tool returned any findings | `save_recon_result(domain, scenario, data)` | `engagement/recon/results/` |
| Any finding changes attack surface | `update_attack_surface(domain, section, findings)` | `engagement/recon/behavior/` |
| Users enumerated | `save_user_enum(domain, valid_users, total, throttled)` | `engagement/recon/behavior/` |
| Token captured | `save_token(engagement, alias, token_data)` | `engagement/credentials/tokens/` |
| Credentials captured | `save_credential(engagement, type, target, data)` | `engagement/credentials/creds/` |
| Certificate created | `save_cert_reference(engagement, type, target, metadata)` | `engagement/credentials/certs/` |
| Persistence installed | `add_persistence(engagement, type, target, tool, access, cleanup)` | `engagement/operations/persistence/` |
| Tool with OPSEC >= Medium | `log_noise(engagement, tool, predicted, actual, details)` | `engagement/operations/noise/` |
| Any tool executed | `log_playbook_entry(engagement, tool, scenario, target, result)` | `engagement/operations/playbooks/` |
| IOCs discovered | `IOCStore(engagement).add(ioc)` + `save_markdown()` | `engagement/recon/iocs/` |

**If you run pwsh commands directly (not via MCP tools), you MUST manually call these save functions afterward using Python.** The MCP tools have auto-save hooks, but direct pwsh execution does not.

**Save pattern for direct pwsh recon:**
```python
import sys; sys.path.insert(0, 'src')
from entrareaper.engagement_store import save_fingerprint, save_recon_result, update_attack_surface, save_user_enum
from entrareaper.ioc_store import IOCStore, IOC, extract_iocs_from_recon

# After recon: save fingerprint + results + attack surface + IOCs
save_fingerprint(domain, {...})
save_recon_result(domain, scenario, {...})
update_attack_surface(domain, section, {...})
iocs = extract_iocs_from_recon(domain, findings)
store = IOCStore(engagement_name)
store.add_bulk(iocs)
store.save_markdown()
```

### OPSEC Rules

1. **Pre-flight check:** Run `opsec_check(tool_name)` before any tool with OPSEC >= Medium
2. **Noise tracking:** Log every tool execution to `noise/` via `log_noise()`
3. **Budget enforcement:** Compare cumulative noise against budget. Stop if exceeded.
4. **Timing jitter:** Wait 30-120 seconds between authenticated actions
5. **User-agent rotation:** Set appropriate UA per app context (S65) before authenticated phases
6. **LOUD gate:** `persist_federation`, `persist_pta_agent`, `evade_audit_logs`, `impact_user_ops`, `impact_config` ALWAYS require human approval, regardless of mode
7. **Playbook logging:** Every tool call logged to `playbooks/` with scenario reference, target, result, and next action

### Noise Budget Tracking

After each tool execution, the agent updates the running noise tally:

| OPSEC Level | Points |
|-------------|--------|
| Silent | 0 |
| Low | 1 |
| Medium | 5 |
| HIGH | 15 |
| LOUD | 50 |

| Budget | Max Points |
|--------|-----------|
| `silent` | 0 |
| `low` | 10 |
| `medium` | 50 |
| `high` | 150 |
| `unlimited` | No limit |

When budget reaches 80%, warn operator. When budget reaches 100%, stop and report.

---

## Kill Chain Quick-Select

If the operator specifies a kill chain, execute only those scenarios in order:

| Chain | Scenarios | Description |
|-------|-----------|-------------|
| A | S01 > S03 > S17 > S20 > S09 > S10 > S15 > S34 | External to Global Admin |
| B | S01 > S17 > S09 > S27 > S28 > S49 > S38 | Golden SAML persistence |
| C | S03 > S17 > S19 > S49 > S44 > S46 | BEC financial fraud |
| D | S07 > S03 > S17 > S45 > S09 > S50 | MSP supply chain |
| E | S01 > S17 > S11 > S31 > S24 > S34 > S42 | Hybrid infra takeover |
| F | S03 > S18 > S19 > S48 > S46 > S47 > S49 | Silent data exfil |
| G | S01 > S17 > S10 > S29 > S22 > S19 | Device trust abuse |
| H | S03 > S17 > S15 > S32 > S24 | MFA bypass persistence |
| I | S65 > S17 > S55 > S32 > S63 | Silent persistence (no federation) |
| J | S65 > S19 > S59 > S47 > S64 > S38 | Insider data miner |
| K | S52 > S35 > S31 > S57 > S54 > S60 | Hybrid destruction |
| L | S66 > S71 > S19 > S46 > S47 > S49 | FOCI token cascade |
| M | S01 > S03 > S17 > S09 > S67 > S69 > S34 > S86 | Zero-to-Admin speed run |

---

## Engagement Folder Reference (15 Folders)

All paths relative to EntraReaper root:

### Recon (what you learn) — `engagement/recon/`

| Folder | Contents | Save Function |
|--------|----------|---------------|
| `engagement/recon/fingerprints/` | Tenant identity (markdown-kv) | `save_fingerprint()` |
| `engagement/recon/behavior/` | Evolving attack surface profiles | `update_attack_surface()` |
| `engagement/recon/results/` | Point-in-time recon snapshots | `save_recon_result()` |
| `engagement/recon/iocs/` | Indicators of compromise | `IOCStore().add()` + `save_markdown()` |

### Credentials (what you capture) — `engagement/credentials/`

| Folder | Contents | Save Function |
|--------|----------|---------------|
| `engagement/credentials/tokens/` | JWT, refresh, PRT, SAML tokens | `save_token()` |
| `engagement/credentials/creds/` | NT hashes, MFA secrets, cookies | `save_credential()` |
| `engagement/credentials/certs/` | Signing certs, device certs | `save_cert_reference()` |

### Collection (what you take) — `engagement/collection/`

| Folder | Contents | Save Function |
|--------|----------|---------------|
| `engagement/collection/loot/` | Downloaded files, emails, docs | Manual save |

### Operations (how you operate) — `engagement/operations/`

| Folder | Contents | Save Function |
|--------|----------|---------------|
| `engagement/operations/playbooks/` | Execution journal | `log_playbook_entry()` |
| `engagement/operations/noise/` | Footprint + budget tracking | `log_noise()` |
| `engagement/operations/persistence/` | Active backdoor inventory | `add_persistence()` |

### Defense + Delivery — `engagement/defense/` + `engagement/delivery/`

| Folder | Contents | Save Function |
|--------|----------|---------------|
| `engagement/defense/signals/` | Detection opportunities | `save_signal()` |
| `engagement/delivery/reports/` | Final deliverables | `report_generate()` |

### Reference (read-only) — `reference/`

| Folder | Contents |
|--------|----------|
| `reference/scenarios/` | 87 scenarios + 13 kill chains |
| `reference/app-ids/` | 180+ FOCI/BroCI/known-bad app IDs |
| `reference/cmdlets/` | 238 cmdlet ref + 246 docs + source map |

---

## Advanced Scenarios (S51-S65)

These are available for targeted testing when standard phases identify specific attack surface:

| Scenario | Technique | When to Use |
|----------|-----------|-------------|
| S51 | OAuth consent grant attack | Tenant allows user consent to external apps |
| S52 | AAD Connect credential extraction | Hybrid with sync configured |
| S53 | Cloud Shell hijacking | User has Azure Cloud Shell enabled |
| S54 | Hybrid Health event injection | ADFS or AAD Connect in use |
| S55 | WHfB key injection | Device-based CA policies in place |
| S56 | App Proxy agent impersonation | App Proxy publishing internal apps |
| S57 | Staged rollout policy downgrade | PTA or federation in use |
| S58 | Azure IMDS token theft | Managed identities on Azure VMs |
| S59 | SharePoint membership injection | M365 Group-based SPO access |
| S60 | Diagnostic settings redirect | Azure Monitor / Log Analytics in use |
| S61 | ADFS token forging | On-prem ADFS with cert access |
| S62 | B2C key extraction | B2C tenant for customer auth |
| S63 | ActiveSync device injection | Exchange ActiveSync enabled |
| S64 | Compliance portal data mining | eDiscovery Manager role obtained |
| S65 | User-agent masquerading | Always (run before authenticated phases) |

### New Scenarios S66-S87 (from scenarios_87.md)

| Scenario | Technique | When to Use |
|----------|-----------|-------------|
| S66 | FOCI family enumeration | Map token pivot surface before FOCI exploitation |
| S67 | CA bypass scanner (automated) | After `analyze_ca` identifies gaps |
| S68 | Tenant multi-domain pivot | Multiple domains registered, find weakest |
| S69 | Service principal permission audit | Find over-permissioned apps with dangerous scopes |
| S70 | ROPC password spray via FOCI | `cred_token_universal` with FOCI client IDs |
| S71 | Token refresh chain (5+ resources) | `cred_token_refresh` across FOCI family |
| S72 | Temporary Access Pass exploitation | TAP obtained, bypass MFA |
| S73 | Certificate-based auth abuse | App cert for silent token acquisition |
| S74 | Teams phishing FakeInternal | `access_phishing_teams` with spoofed sender |
| S75 | Teams external phishing | Cross-tenant device code via Teams |
| S76 | Multi-target phishing campaign | Orchestrated phish to 10+ targets |
| S77 | Federated identity credential injection | Add federated cred to existing app |
| S78 | Multi-layer persistence stack | 3+ persistence mechanisms simultaneously |
| S79 | Access package self-escalation | Abuse access governance for privesc |
| S80 | Cross-tenant GDAP cascade | MSP pivot to 5+ customer tenants |
| S81 | Cloud Shell to on-prem bridge | Azure Cloud Shell → internal network |
| S82 | Managed identity chain | VM IMDS → Key Vault → DB creds |
| S83 | Compliance portal mass search | eDiscovery across all mailboxes |
| S84 | Selective exfil with DLP evasion | Small batch under DLP thresholds |
| S85 | Teams channel infiltration | Join private channels, harvest data |
| S86 | Zero-to-Admin in one session | Complete chain: domain → Global Admin |
| S87 | Silent APT simulation | Long-term persistent access, zero detection |

---

## Error Handling

| Error | Action |
|-------|--------|
| Tool returns error | Log to `noise/`, analyze error, adapt approach. Do NOT retry blindly. |
| Account lockout | Stop immediately. Log to `signals/`. Report to operator. |
| Token expired | Re-authenticate via stored refresh token or request new phish. |
| Rate limited | Apply exponential backoff. Log to `noise/`. Reduce throughput. |
| Budget exhausted | Stop all actions. Generate interim report. Present to operator. |
| MCP server crash | Run `session_status()` to verify. Restart server if needed. |
| Scope violation | Stop. Scope exclusions are hard limits. Never circumvent. |

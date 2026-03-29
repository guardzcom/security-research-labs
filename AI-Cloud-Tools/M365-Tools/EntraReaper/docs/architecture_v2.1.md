# EntraReaper v2.1 — Architecture

> Autonomous Red Team Platform for Entra ID
> 65 MCP tools | 9 Python modules | 15 engagement folders | 87 scenarios | 13 kill chains
> Proven: Kill Chain A (domain → Global Admin) in single session, 3/100 noise budget

---

## System Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                            CLAUDE CODE (Operator)                               │
│                                                                                 │
│  ┌───────────────────────────────────────────────────────────────────────────┐  │
│  │                Red Team Agent v2.1 (opus model)                           │  │
│  │                                                                           │  │
│  │  Mode: full-auto │ semi-auto │ manual                                    │  │
│  │  Scenarios: S01-S87 (87 total)          Kill Chains: A-M (13 total)      │  │
│  │  Adaptive routing: re-evaluates after every tool execution               │  │
│  │  OPSEC: noise budget enforcement, UA rotation, timing jitter             │  │
│  └──────────────────────────┬────────────────────────────────────────────────┘  │
│                              │ stdio (MCP protocol)                             │
└──────────────────────────────┼──────────────────────────────────────────────────┘
                               │
┌──────────────────────────────┼──────────────────────────────────────────────────┐
│                      MCP SERVER (server.py — 65 tools)                          │
│                                                                                 │
│  ┌─── LAYER 1: GOVERNANCE ──────────────────────────────────────────────────┐  │
│  │                                                                          │  │
│  │  opsec_governor.py          evasion.py              engagement_store.py  │  │
│  │  ├─ budget_check            ├─ set_ua (8 contexts)  ├─ auto-save hooks  │  │
│  │  ├─ budget_spend            ├─ jitter (4 profiles)  ├─ 15-folder write  │  │
│  │  ├─ budget_report           ├─ foci_list (37 apps)  ├─ playbook logging │  │
│  │  └─ budget_set              ├─ audience_switch      └─ noise tracking   │  │
│  │     (100 pts default)       └─ FOCI_FAMILY data                         │  │
│  │                                                                          │  │
│  │  4 tools: opsec_budget_*    4 tools: evasion_*      1 tool: engagement_ │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│  ┌─── LAYER 2: EXECUTION (50 attack tools) ─────────────────────────────────┐  │
│  │                                                                          │  │
│  │  RECON (9)        CREDENTIAL (13)     PERSISTENCE (5)    PRIVESC (3)    │  │
│  │  ┌──────────┐    ┌──────────────┐    ┌────────────┐    ┌──────────┐    │  │
│  │  │ tenant   │    │ token        │    │ federation │    │ azure    │    │  │
│  │  │ users    │    │ device_code  │    │ saml_forge │    │ password │    │  │
│  │  │ domains  │    │ token_decode │    │ device     │    │ role     │    │  │
│  │  │ openid   │    │ prt_extract  │    │ pta_agent  │    └──────────┘    │  │
│  │  │ dns      │    │ cookie       │    │ mfa_app    │                     │  │
│  │  │ insider  │    │ nthash       │    └────────────┘    EVASION (2)     │  │
│  │  │ guest    │    │ mfa_read     │                      ┌──────────┐    │  │
│  │  │ ca_pol   │    │ token_univ ★ │    ACCESS (3)        │ audit    │    │  │
│  │  │ sync_cfg │    │ token_refr ★ │    ┌────────────┐    │ policy   │    │  │
│  │  └──────────┘    │ otp_gen    ★ │    │ phishing   │    └──────────┘    │  │
│  │                  │ otp_secret ★ │    │ phish_team★│                     │  │
│  │  MOVEMENT (3)    │ imds_token ★ │    │ guest_inv  │    IMPACT (2)      │  │
│  │  ┌──────────┐    └──────────────┘    └────────────┘    ┌──────────┐    │  │
│  │  │ vm_exec  │                                          │ user_ops │    │  │
│  │  │ message  │    COLLECTION (4)      AZURE+KERB (2)    │ config   │    │  │
│  │  │ partner  │    ┌──────────────┐    ┌──────────┐      └──────────┘    │  │
│  │  └──────────┘    │ onedrive     │    │ enum     │                      │  │
│  │                  │ sharepoint   │    │ kerberos │      RAW (1)         │  │
│  │  SESSION (2)     │ teams        │    └──────────┘      ┌──────────┐    │  │
│  │  ┌──────────┐    │ email        │                      │ invoke   │    │  │
│  │  │ status   │    └──────────────┘    OPSEC (4)         │ (238     │    │  │
│  │  │ clear    │                        ┌──────────┐      │ cmdlets) │    │  │
│  │  └──────────┘                        │ check    │      └──────────┘    │  │
│  │                                      │ budget_* │                      │  │
│  │  ★ = new in v2.1                     └──────────┘                      │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│  ┌─── LAYER 3: INTELLIGENCE ────────────────────────────────────────────────┐  │
│  │                                                                          │  │
│  │  analyzer.py                                                             │  │
│  │  ├─ analyze_ca_policies      → CA gap finder, coverage score 0-100      │  │
│  │  ├─ find_privesc_paths       → abusable groups, over-perm apps, weak GA │  │
│  │  ├─ build_access_graph       → user→group→app→role→sub node/edge graph  │  │
│  │  └─ rank_attack_paths        → BFS shortest path with risk scoring      │  │
│  │                                                                          │  │
│  │  3 tools: analyze_ca, analyze_privesc, analyze_attack_graph              │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│  ┌─── LAYER 4: REPORTING ───────────────────────────────────────────────────┐  │
│  │                                                                          │  │
│  │  reporter.py                                                             │  │
│  │  ├─ generate_report          → 12-section markdown from 15 folders      │  │
│  │  ├─ generate_mitre_layer     → ATT&CK Navigator v4.5 JSON              │  │
│  │  ├─ generate_evidence_pkg    → SHA256 manifest for chain of custody     │  │
│  │  ├─ generate_cleanup_list    → teardown checklist from persistence/     │  │
│  │  └─ generate_narrative       → chronological attack story by tactic     │  │
│  │                                                                          │  │
│  │  5 tools: report_generate, report_mitre_layer, report_evidence_package, │  │
│  │           report_cleanup, report_narrative                               │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
│  ┌─── BRIDGE LAYER ────────────────────────────────────────────────────────┐   │
│  │  bridge.py → asyncio.create_subprocess_exec (NO SHELL)                  │   │
│  │  compat.ps1 → macOS polyfills (HttpUtility + JavaScriptSerializer)      │   │
│  │  3-layer injection prevention: exec → regex → sanitize                  │   │
│  └──────────────────────────┬──────────────────────────────────────────────┘   │
│                              │                                                  │
└──────────────────────────────┼──────────────────────────────────────────────────┘
                               ▼
                    pwsh 7 + AADInternals (238 cmdlets)
                               │
                               ▼
                    Microsoft Entra ID / Azure AD APIs
```

---

## Data Flow — Single Tool Execution

```
                    ┌──────────────┐
                    │  Operator    │
                    │  Request     │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  OPSEC       │ ← opsec_governor.py
                    │  Governor    │
                    │              │
                    │  Budget: OK? ├──── NO → STOP (budget exhausted)
                    │  Noise: ?    │
                    └──────┬───────┘
                           │ YES
                    ┌──────▼───────┐
                    │  Evasion     │ ← evasion.py
                    │  Engine      │
                    │              │
                    │  Set UA      │ → User-Agent header
                    │  Jitter      │ → Random delay (2-300s)
                    │  Audience    │ → FOCI swap if blocked
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐        ┌───────────────┐
                    │  Tool        │───────▶│  PSBridge     │──▶ pwsh + AADInt
                    │  Execution   │        │  (safe exec)  │
                    │  server.py   │        │               │◀── JSON result
                    └──────┬───────┘        └───────────────┘
                           │
                    ┌──────▼───────┐
                    │  Auto-Save   │ ← engagement_store.py
                    │  Hooks       │
                    │              │
                    ├─fingerprints/│ → tenant identity (recon tools)
                    ├─behavior/   │ → attack surface (all recon)
                    ├─results/    │ → snapshots (all recon)
                    ├─playbooks/  │ → execution log (every tool)
                    ├─noise/      │ → footprint (every tool)
                    ├─persistence/│ → backdoor inventory (persist_*)
                    ├─creds/      │ → credentials (cred_*)
                    ├─certs/      │ → certificates (persist_*)
                    ├─tokens/     │ → token exports (cred_*)
                    ├─signals/    │ → detection opps (medium+ OPSEC)
                    ├─iocs/       │ → indicators (ioc_store.py)
                    └─loot/       │ → collected files (collect_*)
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │  Return JSON │ → Claude (immediate, non-blocking)
                    └──────────────┘
```

---

## Module Dependency Graph

```
server.py (65 tools, entry point)
│
├── bridge.py ──────────────── pwsh subprocess (no shell injection)
│   └── compat.ps1 ──────── macOS polyfills (System.Web)
│
├── token_store.py ─────────── named token cache (~/.entrareaper/)
│
├── opsec.py ───────────────── 18 OPSEC profiles (noise/detection per tool)
│   └──▶ opsec_governor.py ── noise budget (check/spend/report)
│        └── noise/{eng}/budget.json
│
├── evasion.py ─────────────── stealth engine
│   ├── 8 UA contexts (outlook, teams, edge, azure_cli, powershell, mobile, onedrive, sharepoint)
│   ├── 37 FOCI client IDs
│   ├── 4 timing profiles (aggressive, normal, stealth, human)
│   └── 14 resource audience URIs
│
├── analyzer.py ────────────── post-exploitation intelligence
│   ├── CA policy gap analysis (coverage score 0-100)
│   ├── Privesc finder (16 high-value roles, 17 dangerous permissions, 20 group patterns)
│   ├── Access graph builder (node/edge from users, groups, apps, SPs, roles)
│   └── Attack path ranker (BFS shortest path with risk scoring)
│
├── reporter.py ────────────── engagement delivery
│   ├── 12-section auto-report from 15 folders
│   ├── MITRE ATT&CK Navigator v4.5 JSON (18 technique mappings)
│   ├── Evidence package (SHA256 per file)
│   ├── Cleanup checklist (from persistence/)
│   └── Kill chain narrative (chronological by tactic)
│
├── engagement_store.py ────── auto-save to 15 folders
│   ├── save_fingerprint, save_recon_result, update_attack_surface
│   ├── save_token, save_credential, save_cert_reference
│   ├── log_noise, add_persistence, log_playbook_entry
│   └── get_folder_status
│
└── ioc_store.py ───────────── IOC collection (dedup, export, markdown)
```

---

## 15 Engagement Folders

```
aadinternalsMCP/
│
├── INTELLIGENCE (what you learn)
│   ├── fingerprints/        Tenant identity — per-target, markdown-kv, static
│   ├── behavior/            Attack surface — evolving, grows per cycle
│   ├── results/             Recon snapshots — per-tool, immutable
│   └── iocs/                Indicators — JSON + markdown, for blue team
│
├── CREDENTIALS (what you capture)
│   ├── tokens/              JWT/refresh/PRT/SAML — per-engagement, per-alias
│   ├── creds/               NT hashes, MFA secrets, cookies — per-type JSON
│   └── certs/               Signing certs, device certs — per-type subdirs
│
├── COLLECTION (what you take)
│   └── loot/                Downloaded files — per-target, per-service
│
├── OPERATIONS (how you operate)
│   ├── playbooks/           Execution journal — auto-appended, every tool
│   ├── noise/               Footprint — predicted vs actual, budget tracking
│   └── persistence/         Live backdoors — MUST be cleaned up at end
│
├── DEFENSE (what defenders should see)
│   └── signals/             Detection opportunities — auto from OPSEC profiles
│
├── REPORTING (what you deliver)
│   └── reports/             Final deliverables — report, MITRE, evidence, cleanup
│
└── REFERENCE (read-only)
    ├── scenarios/           87 scenarios + 13 kill chains
    ├── black-white/         180+ Entra ID app IDs (FOCI, BroCI, known-bad)
    ├── docs/                Architecture, cmdlet ref (238), cmdlet docs (246)
    └── scripts/             Setup, MCP config
```

---

## 10-Phase Workflow

```
PHASE 1              PHASE 2              PHASE 3              PHASE 4
EXTERNAL RECON       INITIAL ACCESS       INSIDER RECON        CRED HARVEST
S01-S08 (8)          S17-S26 (10)         S09-S16 (8)          S19-S24 (6)
Auto │ Silent-Low    Semi │ Low-Med       Auto │ Medium        Semi │ Med-HIGH

 recon_tenant ──────▶ cred_device_code ─▶ recon_insider ─────▶ cred_cookie
 recon_users          cred_token_univ     recon_ca_policies    cred_prt_extract
 recon_domains        access_phishing     analyze_ca ★         cred_nthash
 recon_openid         access_phish_teams★ recon_sync_config    cred_token_refresh★
 recon_dns            cred_token_refresh★ analyze_privesc ★    cred_imds_token ★
                      evasion_set_ua ★    analyze_attack_graph★
                                          cred_mfa_read
        │                    │                    │                    │
        ▼                    ▼                    ▼                    ▼
  fingerprints/         tokens/            behavior/             creds/
  behavior/             playbooks/         results/              playbooks/
  results/              noise/             playbooks/            noise/
  iocs/

PHASE 5              PHASE 6              PHASE 7              PHASE 8
PERSISTENCE          PRIVILEGE ESCAL      LATERAL MOVEMENT     COLLECTION
S27-S33 (7)          S34-S37 (4)          S42-S45 (4)          S46-S49 (4)
Manual │ Med-LOUD    Manual │ HIGH        Semi │ Med-HIGH      Semi │ Medium

 persist_federation   privesc_azure_admin  move_vm_exec         collect_onedrive
 persist_saml_forge   privesc_password     move_messaging       collect_sharepoint
 persist_device       privesc_role_assign  move_partner_pivot   collect_teams
 persist_pta_agent                                              collect_email
 persist_mfa_app
        │                    │                    │                    │
        ▼                    ▼                    ▼                    ▼
  persistence/          behavior/           playbooks/           loot/
  certs/                playbooks/          noise/               playbooks/
  noise/                noise/

PHASE 9              PHASE 10
IMPACT               REPORTING + CLEANUP
S50, S51-S87         report_*
Manual │ LOUD        Auto │ None

 impact_user_ops      report_generate
 impact_config        report_mitre_layer
 evade_audit_logs     report_evidence_pkg
 evade_policy_weaken  report_cleanup
                      report_narrative
        │                    │
        ▼                    ▼
  persistence/          reports/
  noise/                (reads ALL 15 folders)
```

---

## OPSEC Budget System

```
┌──────────────────────────────────────────────────────────────┐
│                    NOISE BUDGET (default: 100 points)         │
│                                                              │
│   OPSEC Level    │  Cost  │  Examples                        │
│   ──────────────┼────────┼───────────────────────────────── │
│   Silent         │    0   │  recon_tenant, recon_domains     │
│   Low            │    1   │  recon_users, cred_device_code   │
│   Medium         │    5   │  recon_insider, collect_*        │
│   HIGH           │   20   │  cred_nthash, privesc_*          │
│   LOUD           │   50   │  persist_federation, evade_audit │
│                                                              │
│   Budget 100 allows:                                         │
│     ∞ silent + 100 low + 20 medium + 5 high + 2 loud        │
│     OR typical engagement: 1 loud + 2 high + 4 medium        │
│                                                              │
│   Proven: Kill Chain A completed with 3 pts (97% remaining)  │
└──────────────────────────────────────────────────────────────┘

  Budget Check Flow:
  ┌────────────┐    ┌────────────┐    ┌────────────┐
  │  Tool      │───▶│  Check     │───▶│  Allowed?  │
  │  Request   │    │  Budget    │    │            │
  └────────────┘    └────────────┘    ├─ YES ──▶ Execute
                                      ├─ NO  ──▶ STOP
                                      └─ FORCE ─▶ Execute (human override)
```

---

## Kill Chain Selection Logic

```
                         S01: recon_tenant
                               │
                     ┌─────────┴─────────┐
                     │                   │
               Federation?          Managed?
                     │                   │
             ┌───────┴───────┐     ┌─────┴──────┐
             │               │     │            │
          SSO on?        PTA on?  SSO on?    Cloud-only
             │               │     │            │
          Chain E         Chain E Chain G    ┌───┴───┐
          + Chain G                         │       │
                                        C-suite? No users?
                                            │       │
                                        Chain A/C  Chain F
                                            │
                              ┌─────────────┴─────────────┐
                              │                           │
                        Admin token?                 User token?
                              │                           │
                         Chain A                     Chain C/F
                         → Phase 6                   → Phase 3
                         (skip to escalation)        (insider recon)

  Kill Chains (13):
  A: External→GA       │ B: Golden SAML      │ C: BEC Fraud
  D: MSP Supply Chain  │ E: Hybrid Takeover  │ F: Silent Exfil
  G: Device Trust      │ H: MFA Persist      │ I: Silent Persist
  J: Insider Miner     │ K: Hybrid Destroy   │ L: FOCI Cascade ★
  M: Zero-to-Admin ★   │                     │  ★ = new in v2.1
```

---

## Security Controls

```
┌──────────────────────────────────────────────────────────────────┐
│                  THREE-LAYER INJECTION PREVENTION                 │
│                                                                  │
│  Layer 1: create_subprocess_exec ── No shell interpretation      │
│  Layer 2: Regex cmdlet validation ── Only AADInt* pattern        │
│  Layer 3: String sanitization ────── ' escaped to ''             │
├──────────────────────────────────────────────────────────────────┤
│                  OPERATIONAL SAFETY                               │
│                                                                  │
│  • Noise budget prevents runaway operations                      │
│  • LOUD tools require human approval (any mode)                  │
│  • Persistence inventory tracks all planted backdoors            │
│  • Cleanup checklist enforces teardown at engagement end         │
│  • Evidence hashing provides chain of custody                    │
│  • Per-engagement token store (never mix engagements)            │
│  • macOS stderr suppression (2>$null on Import-Module)           │
├──────────────────────────────────────────────────────────────────┤
│                  TIMEOUT PROTECTION                               │
│                                                                  │
│  Standard: 120s │ Long ops: 600s │ Max: 600s                    │
│  Applied per-command via asyncio.wait_for()                      │
└──────────────────────────────────────────────────────────────────┘
```

---

## Tool Inventory (65 total)

| Category | Count | Tools |
|----------|-------|-------|
| Recon (unauth) | 5 | tenant, users, domains, openid, dns |
| Recon (auth) | 4 | insider, guest, ca_policies, sync_config |
| Credential | **13** | token, device_code, decode, prt, cookie, nthash, mfa_read, **token_universal, token_refresh, otp_generate, otp_new_secret, imds_token** |
| Access | **3** | phishing, **phishing_teams**, guest_invite |
| Persistence | 5 | federation, saml_forge, device, pta_agent, mfa_app |
| Privilege Escalation | 3 | azure_admin, password_reset, role_assign |
| Defense Evasion | 2 | audit_logs, policy_weaken |
| Lateral Movement | 3 | vm_exec, messaging, partner_pivot |
| Collection | 4 | onedrive, sharepoint, teams, email |
| Impact | 2 | user_ops, config |
| Azure + Kerberos | 2 | enum, ticket |
| Raw + Session | 3 | invoke, status, clear_tokens |
| **OPSEC Governance** | **4** | opsec_check, budget_check, budget_set, budget_report |
| **Evasion** | **4** | set_ua, jitter, foci_list, audience_switch |
| **Analysis** | **3** | analyze_ca, analyze_privesc, analyze_attack_graph |
| **Reporting** | **5** | report_generate, mitre_layer, evidence_package, cleanup, narrative |
| **Engagement** | **1** | engagement_status |

**Bold** = new in v2.0/v2.1

---

## Module Inventory (9 total)

| Module | Lines | Purpose |
|--------|-------|---------|
| server.py | 2,140 | MCP server — 65 tools, auto-save hooks |
| bridge.py | 230 | PowerShell subprocess (injection-safe) |
| token_store.py | 186 | Named token cache with persistence |
| opsec.py | 188 | 18 OPSEC profiles (noise/detection) |
| ioc_store.py | 289 | IOC collection, dedup, markdown export |
| engagement_store.py | 597 | Auto-save to 15 folders |
| opsec_governor.py | 380 | Noise budget system |
| evasion.py | 453 | UA rotation, jitter, FOCI targets |
| analyzer.py | 868 | CA analysis, privesc, access graph |
| reporter.py | 965 | Auto-report, MITRE layer, evidence |
| **Total** | **~6,300** | |

---

## Documentation Inventory

| File | Lines | Content |
|------|-------|---------|
| architecture_v2.1.md | — | This file — system diagrams, data flow |
| README.md | 600 | Tool reference, security design |
| cmdlet_reference.md | 710 | 238 cmdlets with parameter signatures |
| cmdlet_documentation.md | 2,416 | 246 cmdlets with descriptions/examples |
| cmdlet_source_map.md | 963 | 244 exported + 274 internal from GitHub |
| scenarios_87.md | 1,648 | 87 scenarios + 13 kill chains |
| scenarios_full.md | 1,370 | Original 65 scenarios (detailed) |
| scenarios_core.md | 430 | 12 core scenarios (quick reference) |
| EntraID-EA.md | 500 | 180+ app IDs (FOCI, BroCI, known-bad) |

---

## Proven Attack Results

| Target | Date | Chain | Phases | Budget | Result |
|--------|------|-------|--------|--------|--------|
| m.grdz.org | 2026-03-26 | A | 1→2→3→4 | 3/100 | **Global Admin + FOCI pivot to Exchange, Teams, Azure** |
| microsoft.com | 2026-03-26 | Recon | 1 only | 2/100 | 25 users confirmed (CEO, CFO, CTO, EVP Security, CISO) |

### m.grdz.org Kill Chain A Proof

```
Phase 1: recon_tenant ─────── b9e2249e-..., EU, Managed, no fed, no SSO
         recon_openid ──────── implicit=true, MRT=true, FOCI=viable
         recon_users ──────── admin, test, secops, shared, david confirmed
                              Budget: 0 pts (silent)

Phase 2: cred_device_code ── Code CDYEHRUP7 → admin@m.grdz.org authenticated
         JWT decoded ──────── GLOBAL ADMIN (role 62e90394-...)
                              30+ scopes: Directory.AccessAsUser.All,
                              Files.ReadWrite.All, Mail.ReadWrite, Mail.Send
                              Budget: 1 pt (low)

Phase 3: FOCI pivot ────────  Exchange ✓  Teams ✓  Azure ✓
                              3 additional tokens from 1 refresh token
                              Budget: 3 pts total (97 remaining)

Result:  Total tenant compromise in single session
         4 tokens (Graph + EXO + Teams + Azure)
         Global Admin with full directory + mail + file access
```

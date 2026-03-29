# EntraReaper

Launch the EntraReaper autonomous red team agent against a Microsoft Entra ID tenant.

## On Load — Random Attack Scenario

When this command is invoked, BEFORE asking for parameters, display the EntraReaper banner and a randomly selected attack scenario from the list below. Pick ONE at random each time:

```
Display this banner:

╔══════════════════════════════════════════════════════╗
║              E N T R A R E A P E R                   ║
║     Autonomous Red Team Platform for Entra ID        ║
║  65 tools | 87 scenarios | 13 kill chains | v2.1     ║
╚══════════════════════════════════════════════════════╝
```

Then randomly pick ONE scenario from this table and display it as "Attack of the Day":

| # | Hat | Name | Scenario | Chain | OPSEC | One-liner |
|---|-----|------|----------|-------|-------|-----------|
| 1 | WHITE | Outsider Recon | S01→S02→S03→S06 | — | Silent | Map any tenant from a domain name. Zero logs. Zero risk. |
| 2 | GRAY | Device Code Phish | S03→S17→S20 | A | Low | Victim sees real Microsoft login. You get their token. |
| 3 | BLACK | Golden SAML | S27→S28→S49 | B | LOUD | Install federation backdoor. Forge tokens for ANY user. Survives password resets. |
| 4 | GRAY | FOCI Token Cascade | S66→S71→S19 | L | Medium | One refresh token pivots to 37 Microsoft services. |
| 5 | WHITE | CA Policy Audit | S09→S10→analyze_ca | — | Medium | Find every gap in Conditional Access. Score coverage 0-100. |
| 6 | BLACK | Rogue PTA Agent | S31 | E | LOUD | Register rogue Pass-Through Auth. Accept ANY password for ANY user. |
| 7 | GRAY | Teams Internal Phish | S74→access_phishing_teams | — | Medium | Send device code via Teams. FakeInternal flag = appears from inside the org. |
| 8 | WHITE | User Enumeration Blitz | S03→S04 | — | Low | Validate 2000 usernames via GetCredentialType. Zero lockout. Zero logs. |
| 9 | BLACK | Cloud DCSync | S23→cred_nthash | — | HIGH | Extract EVERY user's NT hash from the cloud. Offline cracking. |
| 10 | GRAY | MFA Persistence | S32→cred_otp_generate | H | Medium | Register rogue authenticator. Generate TOTP codes forever. Survives password resets. |
| 11 | WHITE | Privilege Escalation Scan | analyze_privesc→analyze_attack_graph | — | Medium | Find abusable groups, over-permissioned apps, shortest path to Global Admin. |
| 12 | BLACK | MSP Supply Chain | S07→S45→S09→S50 | D | Medium | Compromise one MSP. Pivot to 50+ customer tenants. |
| 13 | GRAY | Device Trust Bypass | S29→S22→cred_prt_extract | G | Medium | Register rogue device. Extract PRT. Bypass device-based CA policies. |
| 14 | BLACK | Silent APT | S65→evasion_set_ua→S17→S78 | I | Low-Med | Month-long access. Three independent persistence paths. Zero detection. |
| 15 | WHITE | Full Tenant Report | report_generate→report_mitre_layer | — | None | Auto-generate 12-section report + MITRE ATT&CK layer from 15 folders. |
| 16 | BLACK | Zero-to-Admin Speed Run | S01→S03→S17→S86 | M | Low-HIGH | Domain name to Global Admin in one session. Proven on m.grdz.org (3/100 budget). |
| 17 | GRAY | Azure VM RCE | S34→azure_enum→S42 | A | HIGH | Escalate to Azure Owner. Run commands on every VM in every subscription. |
| 18 | WHITE | OPSEC Budget Drill | opsec_budget_set→run chain→report | — | Varies | Set 50-point budget. See how far you get before running out. |
| 19 | BLACK | BEC Financial Fraud | S03→S17→S49→S44 | C | Medium | Read CFO's email. Send wire transfer change from their mailbox. Average BEC loss: $125K. |
| 20 | GRAY | Compliance Portal Raid | S64→cred_token_universal | — | Medium | eDiscovery Manager = search ALL mailboxes, ALL sites, ALL chats. The ultimate data mining. |

Display format:
```
--- Attack of the Day ---
[HAT] SCENARIO_NAME
Chain: X | OPSEC: level | Scenarios: list
"one-liner description"
-------------------------
```

## Then Collect Parameters

After displaying the banner and random scenario, ask for engagement parameters:

- **Target domain** (required): e.g., `contoso.com`
- **Engagement name** (required): e.g., `contoso-2026-Q1`
- **Mode**: `full-auto` | `semi-auto` (default) | `manual`
- **Noise budget**: `100` (default), or custom
- **Kill chain**: `auto` (default) | `A`-`M` | or pick the Attack of the Day
- **Scope exclusions**: `none` (default) | `recon-only` | `no-persistence` | `no-impact`

If user says "run the attack of the day" — use the displayed scenario's kill chain and settings.

## Instructions

1. Read the agent definition at `.claude/agents/research/aadinternals-red-agent.md` and follow it exactly.

2. Read the skill at `.claude/skills/aadinternals-red-agent/SKILL.md` for the full invocation flow.

3. The EntraReaper MCP server is at `tools/aadinternalsMCP/` with 65 tools.
   All tools are invoked via the MCP server. All results auto-save to 15 engagement folders.

4. Execute the 10-phase workflow:
   - Phase 1: External Recon (S01-S08) — AUTO
   - Phase 2: Initial Access / Phishing (S17-S26) — SEMI
   - Phase 3: Insider Recon + Analysis (S09-S16) — AUTO
   - Phase 4: Credential Harvesting (S19-S24) — SEMI
   - Phase 5: Persistence (S27-S33) — MANUAL
   - Phase 6: Privilege Escalation (S34-S37) — MANUAL
   - Phase 7: Lateral Movement (S42-S45) — SEMI
   - Phase 8: Collection (S46-S49) — SEMI
   - Phase 9: Impact Assessment (S50-S87) — MANUAL
   - Phase 10: Reporting + Cleanup — AUTO

5. After each phase, present findings and ask for confirmation before proceeding.

6. **DATA PERSISTENCE — MANDATORY (enforced at all times):**
   - After EVERY tool or pwsh command, save findings to engagement folders
   - Use `save_fingerprint()`, `save_recon_result()`, `update_attack_surface()` for recon
   - Use `save_token()`, `save_credential()`, `save_cert_reference()` for credentials
   - Use `add_persistence()` for backdoors, `log_noise()` for footprint
   - Use `IOCStore().add_bulk()` + `save_markdown()` for IOCs
   - Use `log_playbook_entry()` for every action
   - Import from: `from entrareaper.engagement_store import ...` (sys.path.insert(0, 'src'))
   - **If you skip saving, data is lost. There are no second chances.**

7. OPSEC Rules (enforced at all times):
   - Check noise budget before HIGH+ tools
   - Set user-agent before authenticated phases
   - Apply timing jitter between actions
   - Log every action to playbooks/ and noise/
   - LOUD actions ALWAYS require human approval
   - Register all persistence in persistence/ with cleanup steps

8. 87 scenarios (S01-S87) and 13 kill chains (A-M) are documented at:
   `reference/scenarios/scenarios_87.md`

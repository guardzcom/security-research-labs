# Persistence

Live inventory of active backdoors. What's currently planted and needs teardown.

NOT the same as `creds/` (what was captured) — this tracks what's RUNNING.

## Structure

```
persistence/{engagement}/
  inventory.md            — Live backdoor inventory (auto-updated)
  cleanup_status.md       — Teardown progress tracker
```

## Inventory Format (markdown-kv)

| Key | Value |
|-----|-------|
| type | rogue_mfa_app |
| target | admin@m.grdz.org |
| installed | 2026-03-26 14:30 UTC |
| tool_used | persist_mfa_app |
| access_method | TOTP secret: {reference to creds/} |
| status | ACTIVE |
| cleanup_action | Remove MFA app registration via Entra admin portal |
| cleanup_done | false |

## Backdoor Types Tracked

| Type | Source Tool | Cleanup Method |
|------|-----------|----------------|
| `rogue_mfa_app` | `persist_mfa_app` | Remove auth method in Entra ID |
| `rogue_device_aad` | `persist_device` (aad) | Delete device in Entra ID |
| `rogue_device_intune` | `persist_device` (intune) | Retire device in Intune |
| `rogue_pta_agent` | `persist_pta_agent` | Deregister PTA agent |
| `federation_backdoor` | `persist_federation` (install) | Revert federation settings |
| `guest_account` | `access_guest_invite` | Remove guest user |
| `azure_role_assignment` | `privesc_role_assign` | Remove role assignment |
| `compliance_spoof` | `impact_config` | Reset device compliance |

## Auto-populated by

| Tool | When |
|------|------|
| `persist_*` tools | On successful installation |
| `access_guest_invite` | On successful invitation |
| `privesc_role_assign` | On successful role grant |
| `impact_config` | On successful config change |

## CRITICAL: Engagement Teardown

Before closing an engagement, EVERY entry in `inventory.md` with `cleanup_done: false`
MUST be resolved. Use `cleanup/` for the formal checklist.

"""
OPSEC metadata for AADInternals operations.
Each tool declares what telemetry it generates so Claude can reason about stealth.
"""

from dataclasses import dataclass


@dataclass
class OpsecProfile:
    """What logs/telemetry an operation generates."""
    tool_name: str
    noise_level: str            # "silent", "low", "medium", "high", "loud"
    logs_generated: list[str]   # Which log sources capture this
    detection_risk: str         # What defenders might see
    evasion_notes: str          # Tips for reducing detection


# OPSEC profiles for each tool category
OPSEC_PROFILES: dict[str, OpsecProfile] = {
    # === RECON (Unauthenticated) ===
    "recon_tenant": OpsecProfile(
        tool_name="recon_tenant",
        noise_level="silent",
        logs_generated=["None - uses public APIs"],
        detection_risk="Zero. GetCredentialType and OpenID config are unauthenticated public endpoints.",
        evasion_notes="No evasion needed. These APIs are called by every browser visiting login.microsoftonline.com.",
    ),
    "recon_users": OpsecProfile(
        tool_name="recon_users",
        noise_level="low",
        logs_generated=["None - uses GetCredentialType API"],
        detection_risk="Very low. High-volume enumeration may trigger rate limiting but generates no sign-in logs.",
        evasion_notes="Throttle requests to <10/sec. Use multiple source IPs for large lists.",
    ),
    "recon_domains": OpsecProfile(
        tool_name="recon_domains",
        noise_level="silent",
        logs_generated=["None"],
        detection_risk="Zero. Uses OpenID autodiscovery.",
        evasion_notes="None needed.",
    ),

    # === RECON (Authenticated) ===
    "recon_insider": OpsecProfile(
        tool_name="recon_insider",
        noise_level="medium",
        logs_generated=["Entra ID sign-in logs", "Entra ID audit logs (if querying admin APIs)"],
        detection_risk="Moderate. Bulk enumeration of users/groups/apps may trigger anomaly detections.",
        evasion_notes="Use a legitimate user token. Spread queries over time. Avoid dumping all objects at once.",
    ),

    # === CREDENTIAL ACCESS ===
    "cred_token": OpsecProfile(
        tool_name="cred_token",
        noise_level="medium",
        logs_generated=["Entra ID sign-in logs"],
        detection_risk="Sign-in event logged. Failed attempts increment error counters (50126, 50053).",
        evasion_notes="Use device code flow for stealth. Interactive browser flow blends with normal traffic.",
    ),
    "cred_device_code": OpsecProfile(
        tool_name="cred_device_code",
        noise_level="low",
        logs_generated=["Entra ID sign-in logs (when victim authenticates)"],
        detection_risk="Sign-in from device code flow is logged but appears as normal auth. App ID may be suspicious.",
        evasion_notes="Use Microsoft first-party client IDs (e.g., Azure CLI, Teams) for the device code request.",
    ),
    "cred_nthash": OpsecProfile(
        tool_name="cred_nthash",
        noise_level="high",
        logs_generated=["Entra ID audit logs (app consent)", "Entra ID sign-in logs (app auth)"],
        detection_risk="HIGH. Requires app with Directory.Read.All + certificate. DCaaS replication is logged.",
        evasion_notes="Use existing app registration if possible. Avoid creating new high-privilege apps.",
    ),

    # === PERSISTENCE ===
    "persist_federation": OpsecProfile(
        tool_name="persist_federation",
        noise_level="loud",
        logs_generated=["Entra ID audit logs (domain federation change)", "Azure Activity logs"],
        detection_risk="CRITICAL. Federation changes are high-fidelity alerts in most SIEM/ITDR products.",
        evasion_notes="Target a lesser-monitored domain. Change during maintenance windows. Revert after use.",
    ),
    "persist_device": OpsecProfile(
        tool_name="persist_device",
        noise_level="medium",
        logs_generated=["Entra ID audit logs (device registration)"],
        detection_risk="Device registration logged. Unusual device joins from unexpected IPs are flagged.",
        evasion_notes="Register from a trusted IP/location. Use realistic device names and OS versions.",
    ),
    "persist_pta_agent": OpsecProfile(
        tool_name="persist_pta_agent",
        noise_level="loud",
        logs_generated=["Entra ID audit logs (PTA agent registration)", "Azure AD Connect logs"],
        detection_risk="CRITICAL. New PTA agent registration is a known attack indicator.",
        evasion_notes="Very hard to hide. Consider timing during legitimate AAD Connect maintenance.",
    ),

    # === PRIVILEGE ESCALATION ===
    "privesc_azure_admin": OpsecProfile(
        tool_name="privesc_azure_admin",
        noise_level="high",
        logs_generated=["Azure Activity logs", "Entra ID audit logs"],
        detection_risk="HIGH. User Access Administrator self-elevation is a known attack pattern.",
        evasion_notes="Use during off-hours. Immediately perform needed actions and revoke.",
    ),
    "privesc_password": OpsecProfile(
        tool_name="privesc_password",
        noise_level="high",
        logs_generated=["Entra ID audit logs (password reset)", "Sign-in logs (new auth)"],
        detection_risk="HIGH. Password reset via Sync API is logged as AAD Connect service account action.",
        evasion_notes="Target accounts with recent password changes to blend in.",
    ),

    # === DEFENSE EVASION ===
    "evade_audit": OpsecProfile(
        tool_name="evade_audit",
        noise_level="loud",
        logs_generated=["Entra ID audit logs (the disable action itself is logged before logs stop)"],
        detection_risk="CRITICAL. Disabling audit logs triggers immediate alerts in mature SOCs.",
        evasion_notes="The act of disabling logs is itself logged. Consider modifying diagnostic settings instead.",
    ),

    # === LATERAL MOVEMENT ===
    "move_vm_exec": OpsecProfile(
        tool_name="move_vm_exec",
        noise_level="high",
        logs_generated=["Azure Activity logs", "VM guest OS logs"],
        detection_risk="HIGH. RunCommand execution on VMs is logged in Azure Activity logs.",
        evasion_notes="Use existing automation runbooks if available. Cloud Shell leaves fewer traces.",
    ),
    "move_messaging": OpsecProfile(
        tool_name="move_messaging",
        noise_level="medium",
        logs_generated=["Exchange audit logs (email)", "Teams message logs"],
        detection_risk="Moderate. Sent messages are visible to recipients and in audit logs.",
        evasion_notes="Use existing conversation threads. Avoid mass messaging.",
    ),

    # === COLLECTION ===
    "collect_onedrive": OpsecProfile(
        tool_name="collect_onedrive",
        noise_level="medium",
        logs_generated=["SharePoint audit logs (FileAccessed, FileDownloaded)"],
        detection_risk="Moderate. Bulk file downloads trigger DLP and anomaly detections.",
        evasion_notes="Download selectively. Spread downloads over time. Target specific files.",
    ),
    "collect_email": OpsecProfile(
        tool_name="collect_email",
        noise_level="medium",
        logs_generated=["Exchange audit logs (MailItemsAccessed if E5)"],
        detection_risk="Moderate. MailItemsAccessed (E5 only) logs email access. OWA access logged in sign-in logs.",
        evasion_notes="Use EWS or REST API instead of OWA for less visible access.",
    ),

    # === IMPACT ===
    "impact_user_ops": OpsecProfile(
        tool_name="impact_user_ops",
        noise_level="loud",
        logs_generated=["Entra ID audit logs (user creation/deletion/modification)"],
        detection_risk="CRITICAL. User creation/deletion is always logged and often alerted.",
        evasion_notes="Modify existing accounts rather than creating new ones when possible.",
    ),
}


def get_opsec_profile(tool_name: str) -> dict:
    """Get OPSEC profile for a tool. Returns dict for MCP response."""
    profile = OPSEC_PROFILES.get(tool_name)
    if not profile:
        return {
            "tool": tool_name,
            "noise_level": "unknown",
            "warning": "No OPSEC profile available for this tool.",
        }
    return {
        "tool": profile.tool_name,
        "noise_level": profile.noise_level,
        "logs_generated": profile.logs_generated,
        "detection_risk": profile.detection_risk,
        "evasion_notes": profile.evasion_notes,
    }


def get_all_profiles() -> list[dict]:
    """Get all OPSEC profiles."""
    return [get_opsec_profile(name) for name in OPSEC_PROFILES]

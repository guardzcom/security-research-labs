"""
Engagement store for EntraReaper — auto-saves findings to structured folders.

Folder layout (15 folders):
  fingerprints/   — per-target tenant identity (markdown-kv, static)
  behavior/       — evolving attack surface profiles (markdown-kv, grows per cycle)
  results/        — point-in-time recon snapshots (markdown, immutable)
  iocs/           — indicators of compromise (JSON + markdown)
  signals/        — detection opportunities for blue team
  tokens/         — per-engagement exported token dumps
  loot/           — downloaded files from collection phase
  creds/          — captured credentials (hashes, MFA secrets, PRT keys)
  certs/          — cryptographic material (signing certs, device certs)
  reports/        — engagement deliverables
  playbooks/      — kill chain execution journal
  noise/          — actual telemetry footprint vs OPSEC predictions
  persistence/    — live backdoor inventory (what's active, needs teardown)
  scenarios/      — attack playbook reference
  black-white/    — app ID reference (FOCI, BroCI, known-bad)
"""

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("entrareaper.engagement")

# BASE_DIR = project root (aadinternalsMCP/), not src/entrareaper/
BASE_DIR = Path(__file__).parent.parent.parent
ENGAGEMENT_DIR = BASE_DIR / "engagement"
FINGERPRINTS_DIR = ENGAGEMENT_DIR / "recon" / "fingerprints"
BEHAVIOR_DIR = ENGAGEMENT_DIR / "recon" / "behavior"
RESULTS_DIR = ENGAGEMENT_DIR / "recon" / "results"
SIGNALS_DIR = ENGAGEMENT_DIR / "defense" / "signals"
TOKENS_DIR = ENGAGEMENT_DIR / "credentials" / "tokens"
LOOT_DIR = ENGAGEMENT_DIR / "collection" / "loot"
CREDS_DIR = ENGAGEMENT_DIR / "credentials" / "creds"
CERTS_DIR = ENGAGEMENT_DIR / "credentials" / "certs"
REPORTS_DIR = ENGAGEMENT_DIR / "delivery" / "reports"
PLAYBOOKS_DIR = ENGAGEMENT_DIR / "operations" / "playbooks"
NOISE_DIR = ENGAGEMENT_DIR / "operations" / "noise"
PERSISTENCE_DIR = ENGAGEMENT_DIR / "operations" / "persistence"
# IOC_DIR is already in ioc_store.py

# All dirs auto-created on first use
for d in (FINGERPRINTS_DIR, BEHAVIOR_DIR, RESULTS_DIR, SIGNALS_DIR,
          TOKENS_DIR, LOOT_DIR, CREDS_DIR, CERTS_DIR,
          REPORTS_DIR, PLAYBOOKS_DIR, NOISE_DIR, PERSISTENCE_DIR):
    d.mkdir(parents=True, exist_ok=True)


def _domain_slug(domain: str) -> str:
    """Convert domain to filename-safe slug: m.grdz.org -> m-grdz-org"""
    return domain.replace(".", "-").replace("@", "-").lower()


def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ---------------------------------------------------------------
# FINGERPRINT — static tenant identity (markdown-kv)
# ---------------------------------------------------------------

def save_fingerprint(domain: str, data: dict) -> Path:
    """
    Save or update a tenant fingerprint from recon data.
    Called after: recon_tenant, recon_dns, recon_openid
    """
    slug = _domain_slug(domain)
    fp_path = FINGERPRINTS_DIR / f"{slug}.md"

    # Extract fields from various recon sources
    tenant_id = data.get("tenant_id", data.get("TenantId", "unknown"))
    brand = data.get("Federation Brand Name", data.get("brand", "unknown"))
    region = data.get("tenant_region_scope", data.get("region", "unknown"))
    auth_type = data.get("Account Type", data.get("auth_type", "unknown"))
    desktop_sso = data.get("Desktop Sso Enabled", data.get("desktop_sso", "unknown"))
    federation = data.get("Federation Protocol", data.get("federation", "null"))
    has_password = data.get("Has Password", data.get("has_password", "unknown"))
    cloud = data.get("Cloud Instance", data.get("cloud_instance", "microsoftonline.com"))

    # OIDC fields
    issuer = data.get("issuer", "")
    response_types = data.get("response_types_supported", [])
    mrt = data.get("microsoft_multi_refresh_token", "unknown")
    signing = data.get("id_token_signing_alg_values_supported", [])
    auth_methods = data.get("token_endpoint_auth_methods_supported", [])

    lines = [
        f"# Tenant Fingerprint: {domain}",
        f"",
        f"> Unauthenticated OIDC + login API fingerprint. OPSEC: Silent.",
        f"> Last updated: {_now()}",
        f"",
        f"## Identity",
        f"",
        f"| Key | Value |",
        f"|-----|-------|",
        f"| tenant_id | `{tenant_id}` |",
        f"| domain | {domain} |",
        f"| brand | {brand} |",
        f"| cloud_instance | {cloud} |",
        f"| region | {region} |",
        f"",
        f"## Authentication",
        f"",
        f"| Key | Value |",
        f"|-----|-------|",
        f"| account_type | {auth_type} |",
        f"| has_password | {has_password} |",
        f"| desktop_sso_enabled | {desktop_sso} |",
        f"| federation_protocol | {federation or 'null (no federation)'} |",
    ]

    if issuer or response_types:
        rt_str = ", ".join(response_types) if isinstance(response_types, list) else str(response_types)
        sign_str = ", ".join(signing) if isinstance(signing, list) else str(signing)
        am_str = ", ".join(auth_methods) if isinstance(auth_methods, list) else str(auth_methods)
        lines.extend([
            f"",
            f"## Token Configuration",
            f"",
            f"| Key | Value |",
            f"|-----|-------|",
            f"| issuer | `{issuer}` |",
            f"| response_types | {rt_str} |",
            f"| implicit_grant | {'enabled' if 'token' in response_types else 'disabled'} |",
            f"| multi_refresh_token | {mrt} |",
            f"| signing_algorithms | {sign_str} |",
            f"| auth_methods | {am_str} |",
        ])

    fp_path.write_text("\n".join(lines) + "\n")
    logger.info(f"Fingerprint saved: {fp_path}")
    return fp_path


# ---------------------------------------------------------------
# RESULTS — point-in-time recon snapshot
# ---------------------------------------------------------------

def save_recon_result(domain: str, scenario: str, data: dict, summary: str = "") -> Path:
    """
    Save a recon result snapshot.
    Called after: any recon tool completion
    """
    slug = _domain_slug(domain)
    date = _today()
    result_path = RESULTS_DIR / f"{slug}_{date}_{scenario}.md"

    lines = [
        f"# Recon: {domain} -- {scenario} -- {date}",
        f"Generated: {_now()} | OPSEC: Silent-Low",
        f"",
    ]

    if summary:
        lines.extend([summary, ""])

    # Dump data as markdown-kv
    lines.extend(["## Raw Data", "", "| Key | Value |", "|-----|-------|"])
    if isinstance(data, dict):
        for k, v in data.items():
            val = str(v)[:100] + "..." if len(str(v)) > 100 else str(v)
            lines.append(f"| {k} | `{val}` |")
    elif isinstance(data, list):
        for i, item in enumerate(data):
            lines.append(f"| [{i}] | `{str(item)[:100]}` |")

    result_path.write_text("\n".join(lines) + "\n")
    logger.info(f"Result saved: {result_path}")
    return result_path


# ---------------------------------------------------------------
# BEHAVIOR — evolving attack surface profile
# ---------------------------------------------------------------

def update_attack_surface(domain: str, section: str, findings: dict) -> Path:
    """
    Update or create the attack surface profile for a target.
    Appends new findings to the appropriate section.
    Called after: each recon cycle completion
    """
    slug = _domain_slug(domain)
    behavior_path = BEHAVIOR_DIR / f"{slug}_attack_surface.md"

    # Create header if file doesn't exist
    if not behavior_path.exists():
        header = [
            f"# Attack Surface Profile: {domain}",
            f"",
            f"> Behavioral intelligence learned across recon cycles.",
            f"> Updated automatically after each recon cycle.",
            f"> Last updated: {_now()}",
            f"",
        ]
        behavior_path.write_text("\n".join(header) + "\n")

    # Append new cycle findings
    content = behavior_path.read_text()

    cycle_lines = [
        f"",
        f"## Cycle: {_now()} -- {section}",
        f"",
        f"| Key | Value |",
        f"|-----|-------|",
    ]
    for k, v in findings.items():
        cycle_lines.append(f"| {k} | {v} |")
    cycle_lines.append("")

    content += "\n".join(cycle_lines) + "\n"

    # Update the "Last updated" timestamp
    content = content.replace(
        content.split("Last updated:")[1].split("\n")[0] if "Last updated:" in content else "",
        f" {_now()}"
    ) if "Last updated:" in content else content

    behavior_path.write_text(content)
    logger.info(f"Attack surface updated: {behavior_path} [{section}]")
    return behavior_path


# ---------------------------------------------------------------
# SIGNALS — detection opportunities
# ---------------------------------------------------------------

def save_signal(tool_name: str, domain: str, signal_data: dict) -> Path:
    """
    Save a detection signal — what defenders should watch for.
    Called after: any tool with OPSEC >= medium
    """
    slug = _domain_slug(domain)
    signal_path = SIGNALS_DIR / f"{slug}_signals.md"

    if not signal_path.exists():
        header = [
            f"# Detection Signals: {domain}",
            f"",
            f"> What defenders should be watching for based on attack tooling used.",
            f"> Auto-generated from OPSEC profiles.",
            f"",
            f"| Timestamp | Tool | Noise | What to Detect |",
            f"|-----------|------|-------|----------------|",
        ]
        signal_path.write_text("\n".join(header) + "\n")

    # Append signal
    noise = signal_data.get("noise_level", "unknown")
    detection = signal_data.get("detection_risk", "unknown")
    line = f"| {_now()} | {tool_name} | {noise} | {detection[:80]} |"

    content = signal_path.read_text()
    content += line + "\n"
    signal_path.write_text(content)
    logger.info(f"Signal recorded: {tool_name} -> {signal_path}")
    return signal_path


# ---------------------------------------------------------------
# USER ENUMERATION — save validated users
# ---------------------------------------------------------------

def save_user_enum(domain: str, valid_users: list, total_tested: int, throttled: int = 0) -> Path:
    """
    Save user enumeration results to the behavior profile.
    Called after: recon_users
    """
    findings = {
        "enum_date": _now(),
        "total_tested": str(total_tested),
        "valid_count": str(len(valid_users)),
        "throttled": str(throttled),
        "valid_users": ", ".join(f"`{u}`" for u in valid_users),
    }

    # Classify users
    high = [u for u in valid_users if any(k in u.split("@")[0].lower()
            for k in ("admin", "ceo", "cfo", "cto", "ciso", "secops", "helpdesk", "it"))]
    medium = [u for u in valid_users if any(k in u.split("@")[0].lower()
              for k in ("svc", "service", "test", "dev", "hr", "finance", "shared", "sync"))]

    if high:
        findings["high_priority_targets"] = ", ".join(f"`{u}`" for u in high)
    if medium:
        findings["medium_priority_targets"] = ", ".join(f"`{u}`" for u in medium)

    return update_attack_surface(domain, "S03-UserEnum", findings)


# ---------------------------------------------------------------
# IMPLICIT GRANT — save test results
# ---------------------------------------------------------------

def save_implicit_grant_results(domain: str, results: dict) -> Path:
    """
    Save implicit grant testing results to behavior profile.
    """
    findings = {
        "test_date": _now(),
        "apps_tested": str(results.get("apps_tested", 0)),
        "apps_accepted": str(results.get("apps_accepted", 0)),
        "apps_blocked": str(results.get("apps_blocked", 0)),
        "response_type_token": results.get("token_status", "unknown"),
        "risk_level": "HIGH" if results.get("apps_blocked", 1) == 0 else "MEDIUM",
    }
    return update_attack_surface(domain, "ImplicitGrant", findings)


# ---------------------------------------------------------------
# TOKENS — per-engagement token export
# ---------------------------------------------------------------

def save_token(engagement: str, alias: str, token_data: dict) -> Path:
    """
    Export a token to the engagement-specific tokens folder.
    Called after: cred_token, cred_device_code, cred_prt_extract, persist_saml_forge, access_phishing
    """
    eng_dir = TOKENS_DIR / _domain_slug(engagement)
    eng_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    token_path = eng_dir / f"{alias}_{ts}.json"
    # Strip actual token value for the log, keep metadata
    safe_data = {k: v for k, v in token_data.items() if k != "value"}
    safe_data["exported_at"] = _now()
    token_path.write_text(json.dumps(safe_data, indent=2, default=str))
    logger.info(f"Token exported: {alias} -> {token_path}")

    # Update inventory
    _append_inventory(eng_dir / "inventory.md", "Tokens", {
        "alias": alias,
        "resource": token_data.get("resource", "unknown"),
        "obtained_via": token_data.get("obtained_via", "unknown"),
        "user": token_data.get("user_principal_name", "unknown"),
        "exported": _now(),
    })
    return token_path


# ---------------------------------------------------------------
# CREDENTIALS — captured credential material
# ---------------------------------------------------------------

def save_credential(engagement: str, cred_type: str, target: str, data: dict) -> Path:
    """
    Save captured credentials.
    Called after: cred_nthash, cred_prt_extract, cred_cookie, persist_mfa_app
    """
    eng_dir = CREDS_DIR / _domain_slug(engagement)
    eng_dir.mkdir(parents=True, exist_ok=True)
    cred_path = eng_dir / f"{cred_type}.json"

    # Load existing or create new
    existing = []
    if cred_path.exists():
        try:
            existing = json.loads(cred_path.read_text())
        except Exception:
            existing = []

    entry = {"target": target, "timestamp": _now(), **data}
    existing.append(entry)
    cred_path.write_text(json.dumps(existing, indent=2, default=str))
    logger.info(f"Credential saved: {cred_type} for {target} -> {cred_path}")

    _append_inventory(eng_dir / "inventory.md", "Credentials", {
        "type": cred_type, "target": target, "captured": _now(),
    })
    return cred_path


# ---------------------------------------------------------------
# CERTIFICATES — cryptographic material
# ---------------------------------------------------------------

def save_cert_reference(engagement: str, cert_type: str, target: str, metadata: dict) -> Path:
    """
    Log certificate creation (actual cert data stays in tool output).
    Called after: persist_federation, persist_device, persist_pta_agent
    """
    eng_dir = CERTS_DIR / _domain_slug(engagement) / cert_type
    eng_dir.mkdir(parents=True, exist_ok=True)
    ref_path = eng_dir / f"{_domain_slug(target)}_ref.md"

    lines = [
        f"# Certificate: {cert_type} -- {target}",
        f"",
        f"| Key | Value |",
        f"|-----|-------|",
        f"| type | {cert_type} |",
        f"| target | {target} |",
        f"| created | {_now()} |",
    ]
    for k, v in metadata.items():
        lines.append(f"| {k} | {v} |")

    ref_path.write_text("\n".join(lines) + "\n")
    logger.info(f"Cert reference saved: {cert_type} for {target}")
    return ref_path


# ---------------------------------------------------------------
# NOISE — actual telemetry footprint
# ---------------------------------------------------------------

def log_noise(engagement: str, tool_name: str, predicted_noise: str,
              actual_noise: str, details: str = "") -> Path:
    """
    Log actual noise generated vs OPSEC prediction.
    Called after: every tool execution
    """
    eng_dir = NOISE_DIR / _domain_slug(engagement)
    eng_dir.mkdir(parents=True, exist_ok=True)
    fp_path = eng_dir / "footprint.md"

    if not fp_path.exists():
        header = [
            f"# Noise Footprint: {engagement}",
            f"",
            f"| Timestamp | Tool | Predicted | Actual | Delta | Details |",
            f"|-----------|------|-----------|--------|-------|---------|",
        ]
        fp_path.write_text("\n".join(header) + "\n")

    delta = "MATCH" if predicted_noise.lower() == actual_noise.lower() else f"MISMATCH"
    line = f"| {_now()} | {tool_name} | {predicted_noise} | {actual_noise} | {delta} | {details[:60]} |"
    content = fp_path.read_text()
    content += line + "\n"
    fp_path.write_text(content)
    logger.info(f"Noise logged: {tool_name} predicted={predicted_noise} actual={actual_noise}")
    return fp_path


# ---------------------------------------------------------------
# PERSISTENCE — live backdoor inventory
# ---------------------------------------------------------------

def add_persistence(engagement: str, persist_type: str, target: str,
                    tool_used: str, access_method: str, cleanup_action: str) -> Path:
    """
    Register a new active backdoor in the persistence inventory.
    Called after: persist_*, access_guest_invite, privesc_role_assign, impact_config
    """
    eng_dir = PERSISTENCE_DIR / _domain_slug(engagement)
    eng_dir.mkdir(parents=True, exist_ok=True)
    inv_path = eng_dir / "inventory.md"

    if not inv_path.exists():
        header = [
            f"# Persistence Inventory: {engagement}",
            f"",
            f"> ACTIVE backdoors. ALL must be cleaned up at engagement end.",
            f"",
        ]
        inv_path.write_text("\n".join(header) + "\n")

    entry = [
        f"",
        f"### {persist_type} -- {target}",
        f"",
        f"| Key | Value |",
        f"|-----|-------|",
        f"| type | {persist_type} |",
        f"| target | {target} |",
        f"| installed | {_now()} |",
        f"| tool_used | {tool_used} |",
        f"| access_method | {access_method} |",
        f"| status | **ACTIVE** |",
        f"| cleanup_action | {cleanup_action} |",
        f"| cleanup_done | false |",
        f"",
    ]

    content = inv_path.read_text()
    content += "\n".join(entry) + "\n"
    inv_path.write_text(content)
    logger.info(f"Persistence added: {persist_type} on {target}")
    return inv_path


# ---------------------------------------------------------------
# PLAYBOOK — execution journal
# ---------------------------------------------------------------

def log_playbook_entry(engagement: str, tool_name: str, scenario: str,
                       target: str, result_summary: str,
                       opsec_predicted: str = "", opsec_actual: str = "",
                       next_action: str = "") -> Path:
    """
    Append an entry to the kill chain execution journal.
    Called after: every tool execution
    """
    eng_dir = PLAYBOOKS_DIR / _domain_slug(engagement)
    eng_dir.mkdir(parents=True, exist_ok=True)
    log_path = eng_dir / "execution_log.md"

    if not log_path.exists():
        header = [
            f"# Execution Log: {engagement}",
            f"",
            f"> Kill chain execution journal. Auto-appended after each tool call.",
            f"",
        ]
        log_path.write_text("\n".join(header) + "\n")

    entry = [
        f"### {_now()} -- {tool_name}",
        f"",
        f"| Key | Value |",
        f"|-----|-------|",
        f"| tool | {tool_name} |",
        f"| scenario | {scenario} |",
        f"| target | {target} |",
        f"| result | {result_summary} |",
    ]
    if opsec_predicted:
        entry.append(f"| opsec_predicted | {opsec_predicted} |")
    if opsec_actual:
        entry.append(f"| opsec_actual | {opsec_actual} |")
    if next_action:
        entry.append(f"| next_action | {next_action} |")
    entry.append("")

    content = log_path.read_text()
    content += "\n".join(entry) + "\n"
    log_path.write_text(content)
    logger.info(f"Playbook entry: {tool_name} on {target}")
    return log_path


# ---------------------------------------------------------------
# HELPER — inventory appender
# ---------------------------------------------------------------

def _append_inventory(inv_path: Path, title: str, entry: dict):
    """Append a markdown-kv entry to an inventory file."""
    if not inv_path.exists():
        inv_path.write_text(f"# {title} Inventory\n\n")

    lines = [f"### {_now()}", "", "| Key | Value |", "|-----|-------|"]
    for k, v in entry.items():
        lines.append(f"| {k} | {v} |")
    lines.append("")

    content = inv_path.read_text()
    content += "\n".join(lines) + "\n"
    inv_path.write_text(content)


# ---------------------------------------------------------------
# FOLDER LISTING — for MCP tool introspection
# ---------------------------------------------------------------

def get_folder_status() -> dict:
    """Return current state of all engagement folders."""
    def _count_files(d: Path) -> int:
        if not d.exists():
            return 0
        count = 0
        for f in d.rglob("*"):
            if f.is_file() and not f.name.startswith("."):
                count += 1
        return count

    def _list_files(d: Path) -> list:
        if not d.exists():
            return []
        files = []
        for f in d.rglob("*"):
            if f.is_file() and not f.name.startswith("."):
                files.append(str(f.relative_to(d)))
        return sorted(files)

    return {
        "fingerprints": {"count": _count_files(FINGERPRINTS_DIR), "files": _list_files(FINGERPRINTS_DIR)},
        "behavior": {"count": _count_files(BEHAVIOR_DIR), "files": _list_files(BEHAVIOR_DIR)},
        "results": {"count": _count_files(RESULTS_DIR), "files": _list_files(RESULTS_DIR)},
        "iocs": {"count": _count_files(BASE_DIR / "iocs"), "files": _list_files(BASE_DIR / "iocs")},
        "signals": {"count": _count_files(SIGNALS_DIR), "files": _list_files(SIGNALS_DIR)},
        "tokens": {"count": _count_files(TOKENS_DIR), "files": _list_files(TOKENS_DIR)},
        "loot": {"count": _count_files(LOOT_DIR), "files": _list_files(LOOT_DIR)},
        "creds": {"count": _count_files(CREDS_DIR), "files": _list_files(CREDS_DIR)},
        "certs": {"count": _count_files(CERTS_DIR), "files": _list_files(CERTS_DIR)},
        "noise": {"count": _count_files(NOISE_DIR), "files": _list_files(NOISE_DIR)},
        "persistence": {"count": _count_files(PERSISTENCE_DIR), "files": _list_files(PERSISTENCE_DIR)},
        "playbooks": {"count": _count_files(PLAYBOOKS_DIR), "files": _list_files(PLAYBOOKS_DIR)},
        "reports": {"count": _count_files(REPORTS_DIR), "files": _list_files(REPORTS_DIR)},
        "scenarios": {"count": _count_files(BASE_DIR / "reference" / "scenarios"), "files": _list_files(BASE_DIR / "reference" / "scenarios")},
        "app_ids": {"count": _count_files(BASE_DIR / "reference" / "app-ids"), "files": _list_files(BASE_DIR / "reference" / "app-ids")},
        "cmdlets": {"count": _count_files(BASE_DIR / "reference" / "cmdlets"), "files": _list_files(BASE_DIR / "reference" / "cmdlets")},
    }

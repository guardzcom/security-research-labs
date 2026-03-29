"""
Red team reporter — auto-generates reports, MITRE layers, evidence packages.

Features:
- Auto-report from engagement folders (reads all 15 folders)
- MITRE ATT&CK Navigator layer export (JSON)
- Evidence packaging (manifest + hashes)
- Cleanup orchestrator (reads persistence/, generates teardown checklist)
- Kill chain narrative generator (from playbooks/)
"""

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("entrareaper.reporter")

BASE_DIR = Path(__file__).parent.parent.parent.parent  # project root

# Engagement folder names (matches engagement_store.py layout)
ENGAGEMENT_FOLDERS = [
    "fingerprints", "behavior", "results", "iocs", "signals",
    "tokens", "loot", "creds", "certs", "noise",
    "persistence", "playbooks", "reports", "scenarios", "black-white",
]

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique mapping for AADInternals tools
# ---------------------------------------------------------------------------

TOOL_TO_MITRE: dict[str, list[dict[str, str]]] = {
    "recon_tenant": [
        {"technique_id": "T1589.001", "technique_name": "Gather Victim Identity Information: Credentials", "tactic": "reconnaissance"},
        {"technique_id": "T1590.001", "technique_name": "Gather Victim Network Information: Domain Properties", "tactic": "reconnaissance"},
    ],
    "recon_users": [
        {"technique_id": "T1589.002", "technique_name": "Gather Victim Identity Information: Email Addresses", "tactic": "reconnaissance"},
    ],
    "recon_domains": [
        {"technique_id": "T1590.001", "technique_name": "Gather Victim Network Information: Domain Properties", "tactic": "reconnaissance"},
    ],
    "recon_insider": [
        {"technique_id": "T1087.004", "technique_name": "Account Discovery: Cloud Account", "tactic": "discovery"},
        {"technique_id": "T1069.003", "technique_name": "Permission Groups Discovery: Cloud Groups", "tactic": "discovery"},
        {"technique_id": "T1580", "technique_name": "Cloud Infrastructure Discovery", "tactic": "discovery"},
    ],
    "cred_token": [
        {"technique_id": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts", "tactic": "credential-access"},
    ],
    "cred_device_code": [
        {"technique_id": "T1528", "technique_name": "Steal Application Access Token", "tactic": "credential-access"},
        {"technique_id": "T1566.002", "technique_name": "Phishing: Spearphishing Link", "tactic": "initial-access"},
    ],
    "cred_nthash": [
        {"technique_id": "T1003.006", "technique_name": "OS Credential Dumping: DCSync", "tactic": "credential-access"},
    ],
    "persist_federation": [
        {"technique_id": "T1484.002", "technique_name": "Domain Policy Modification: Domain Trust Modification", "tactic": "persistence"},
        {"technique_id": "T1606.002", "technique_name": "Forge Web Credentials: SAML Tokens", "tactic": "credential-access"},
    ],
    "persist_device": [
        {"technique_id": "T1098.005", "technique_name": "Account Manipulation: Device Registration", "tactic": "persistence"},
    ],
    "persist_pta_agent": [
        {"technique_id": "T1556.007", "technique_name": "Modify Authentication Process: Hybrid Identity", "tactic": "persistence"},
    ],
    "privesc_azure_admin": [
        {"technique_id": "T1078.004", "technique_name": "Valid Accounts: Cloud Accounts", "tactic": "privilege-escalation"},
        {"technique_id": "T1098.003", "technique_name": "Account Manipulation: Additional Cloud Roles", "tactic": "privilege-escalation"},
    ],
    "privesc_password": [
        {"technique_id": "T1098", "technique_name": "Account Manipulation", "tactic": "persistence"},
    ],
    "evade_audit": [
        {"technique_id": "T1562.008", "technique_name": "Impair Defenses: Disable Cloud Logs", "tactic": "defense-evasion"},
    ],
    "move_vm_exec": [
        {"technique_id": "T1021.007", "technique_name": "Remote Services: Cloud Services", "tactic": "lateral-movement"},
        {"technique_id": "T1059.001", "technique_name": "Command and Scripting Interpreter: PowerShell", "tactic": "execution"},
    ],
    "move_messaging": [
        {"technique_id": "T1534", "technique_name": "Internal Spearphishing", "tactic": "lateral-movement"},
    ],
    "collect_onedrive": [
        {"technique_id": "T1530", "technique_name": "Data from Cloud Storage", "tactic": "collection"},
        {"technique_id": "T1213.002", "technique_name": "Data from Information Repositories: SharePoint", "tactic": "collection"},
    ],
    "collect_email": [
        {"technique_id": "T1114.002", "technique_name": "Email Collection: Remote Email Collection", "tactic": "collection"},
    ],
    "impact_user_ops": [
        {"technique_id": "T1531", "technique_name": "Account Access Removal", "tactic": "impact"},
        {"technique_id": "T1136.003", "technique_name": "Create Account: Cloud Account", "tactic": "persistence"},
    ],
}

# MITRE ATT&CK tactic display order and color scheme
TACTIC_ORDER = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

TACTIC_COLORS: dict[str, str] = {
    "reconnaissance": "#7f7f7f",
    "resource-development": "#7f7f7f",
    "initial-access": "#c93c37",
    "execution": "#ff6600",
    "persistence": "#cc0000",
    "privilege-escalation": "#ff3333",
    "defense-evasion": "#ff9900",
    "credential-access": "#cc0066",
    "discovery": "#6699cc",
    "lateral-movement": "#9933cc",
    "collection": "#ffcc00",
    "command-and-control": "#666699",
    "exfiltration": "#993366",
    "impact": "#990000",
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_pretty() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _engagement_slug(engagement: str) -> str:
    return engagement.replace(".", "-").replace("@", "-").replace(" ", "-").lower()


def _sha256_file(filepath: Path) -> str:
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_file_safe(filepath: Path) -> str:
    """Read a file, returning empty string on error."""
    try:
        return filepath.read_text(errors="replace")
    except OSError:
        return ""


def _collect_engagement_files(engagement: str) -> dict[str, list[Path]]:
    """Collect all files across engagement folders."""
    slug = _engagement_slug(engagement)
    collected: dict[str, list[Path]] = {}

    for folder_name in ENGAGEMENT_FOLDERS:
        folder = BASE_DIR / folder_name
        if not folder.exists():
            collected[folder_name] = []
            continue

        files = []
        # Check for engagement-specific subfolder
        eng_subfolder = folder / slug
        if eng_subfolder.is_dir():
            for f in sorted(eng_subfolder.rglob("*")):
                if f.is_file() and not f.name.startswith("."):
                    files.append(f)
        # Also check for files named with engagement slug at folder root
        for f in sorted(folder.glob(f"{slug}*")):
            if f.is_file() and f not in files:
                files.append(f)

        collected[folder_name] = files

    return collected


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def generate_report(engagement: str) -> str:
    """
    Generate a full markdown red team report by reading all engagement folders.

    Args:
        engagement: Target engagement/domain name

    Returns:
        str: Complete markdown report
    """
    slug = _engagement_slug(engagement)
    files = _collect_engagement_files(engagement)
    total_files = sum(len(v) for v in files.values())

    lines = [
        f"# Red Team Engagement Report: {engagement}",
        f"",
        f"> Generated: {_now_pretty()}",
        f"> Engagement: {engagement}",
        f"> Total evidence files: {total_files}",
        f"",
        f"---",
        f"",
    ]

    # --- Executive Summary ---
    lines.extend([
        "## 1. Executive Summary",
        "",
    ])

    # Count findings by category
    has_creds = len(files.get("creds", [])) > 0
    has_tokens = len(files.get("tokens", [])) > 0
    has_persistence = len(files.get("persistence", [])) > 0
    has_loot = len(files.get("loot", [])) > 0
    playbook_count = len(files.get("playbooks", []))

    summary_items = []
    if has_creds:
        summary_items.append("Credentials captured")
    if has_tokens:
        summary_items.append("Access tokens obtained")
    if has_persistence:
        summary_items.append("Persistence mechanisms established")
    if has_loot:
        summary_items.append("Data exfiltrated")
    if playbook_count:
        summary_items.append(f"{playbook_count} attack phases executed")

    if summary_items:
        for item in summary_items:
            lines.append(f"- {item}")
    else:
        lines.append("- No significant findings to report (recon-only engagement)")
    lines.append("")

    # --- Target Information (from fingerprints) ---
    lines.extend(["## 2. Target Information", ""])
    fingerprint_files = files.get("fingerprints", [])
    if fingerprint_files:
        for fp_file in fingerprint_files:
            content = _read_file_safe(fp_file)
            lines.append(content)
            lines.append("")
    else:
        lines.append("No target fingerprint data collected.")
        lines.append("")

    # --- Attack Surface (from behavior) ---
    lines.extend(["## 3. Attack Surface Analysis", ""])
    behavior_files = files.get("behavior", [])
    if behavior_files:
        for bf_file in behavior_files:
            content = _read_file_safe(bf_file)
            lines.append(content)
            lines.append("")
    else:
        lines.append("No attack surface data collected.")
        lines.append("")

    # --- Kill Chain Execution (from playbooks) ---
    lines.extend(["## 4. Kill Chain Execution", ""])
    playbook_files = files.get("playbooks", [])
    if playbook_files:
        for pb_file in playbook_files:
            content = _read_file_safe(pb_file)
            lines.append(content)
            lines.append("")
    else:
        lines.append("No kill chain execution data recorded.")
        lines.append("")

    # --- Credentials & Tokens ---
    lines.extend(["## 5. Credential Access", ""])
    cred_files = files.get("creds", [])
    token_files = files.get("tokens", [])
    if cred_files or token_files:
        lines.append(f"### Credentials ({len(cred_files)} files)")
        lines.append("")
        for cf in cred_files:
            lines.append(f"- `{cf.relative_to(BASE_DIR)}`")
        lines.append("")
        lines.append(f"### Tokens ({len(token_files)} files)")
        lines.append("")
        for tf in token_files:
            lines.append(f"- `{tf.relative_to(BASE_DIR)}`")
        lines.append("")
    else:
        lines.append("No credentials or tokens captured.")
        lines.append("")

    # --- Persistence ---
    lines.extend(["## 6. Persistence Mechanisms", ""])
    persistence_files = files.get("persistence", [])
    if persistence_files:
        for pf in persistence_files:
            content = _read_file_safe(pf)
            lines.append(content)
            lines.append("")
    else:
        lines.append("No persistence mechanisms established.")
        lines.append("")

    # --- Data Collection (Loot) ---
    lines.extend(["## 7. Data Collection", ""])
    loot_files = files.get("loot", [])
    if loot_files:
        lines.append(f"| File | Size | SHA256 |")
        lines.append(f"|------|------|--------|")
        for lf in loot_files:
            size = lf.stat().st_size
            sha = _sha256_file(lf)
            lines.append(f"| `{lf.name}` | {size:,} bytes | `{sha[:16]}...` |")
        lines.append("")
    else:
        lines.append("No data collected.")
        lines.append("")

    # --- OPSEC & Noise Footprint ---
    lines.extend(["## 8. OPSEC & Noise Footprint", ""])
    noise_files = files.get("noise", [])
    if noise_files:
        for nf in noise_files:
            content = _read_file_safe(nf)
            lines.append(content)
            lines.append("")
    else:
        lines.append("No noise footprint data recorded.")
        lines.append("")

    # --- Detection Signals (Blue Team) ---
    lines.extend(["## 9. Detection Opportunities (Blue Team)", ""])
    signal_files = files.get("signals", [])
    if signal_files:
        for sf in signal_files:
            content = _read_file_safe(sf)
            lines.append(content)
            lines.append("")
    else:
        lines.append("No detection signals generated.")
        lines.append("")

    # --- IOCs ---
    lines.extend(["## 10. Indicators of Compromise", ""])
    ioc_files = files.get("iocs", [])
    if ioc_files:
        for iof in ioc_files:
            if iof.suffix == ".json":
                try:
                    ioc_data = json.loads(_read_file_safe(iof))
                    if isinstance(ioc_data, list):
                        lines.append(f"### {iof.stem} ({len(ioc_data)} IOCs)")
                        lines.append("")
                        lines.append("| Type | Value | Risk | Confidence |")
                        lines.append("|------|-------|------|------------|")
                        for ioc in ioc_data[:50]:  # cap at 50 per file
                            lines.append(
                                f"| {ioc.get('type', 'N/A')} | `{str(ioc.get('value', ''))[:60]}` "
                                f"| {ioc.get('risk', 'N/A')} | {ioc.get('confidence', 'N/A')} |"
                            )
                        lines.append("")
                except json.JSONDecodeError:
                    pass
            else:
                content = _read_file_safe(iof)
                lines.append(content)
                lines.append("")
    else:
        lines.append("No IOCs collected.")
        lines.append("")

    # --- MITRE ATT&CK Mapping ---
    lines.extend(["## 11. MITRE ATT&CK Mapping", ""])
    techniques_used = _extract_techniques_from_playbooks(playbook_files)
    if techniques_used:
        lines.append("| Tactic | Technique | Tool |")
        lines.append("|--------|-----------|------|")
        for entry in techniques_used:
            lines.append(f"| {entry['tactic']} | {entry['technique_id']} - {entry['technique_name']} | {entry['tool']} |")
        lines.append("")
    else:
        lines.append("No MITRE techniques mapped (no playbook entries found).")
        lines.append("")

    # --- Recommendations ---
    lines.extend([
        "## 12. Recommendations",
        "",
        "Based on the engagement findings, the following remediation actions are recommended:",
        "",
    ])

    if not files.get("noise", []):
        lines.append("- Deploy comprehensive audit logging across all Entra ID and M365 services")
    if has_creds:
        lines.append("- Rotate all compromised credentials immediately")
        lines.append("- Enforce phishing-resistant MFA (FIDO2/Windows Hello) for all users")
    if has_persistence:
        lines.append("- Execute cleanup checklist (see Section 6) to remove all persistence")
        lines.append("- Monitor for re-establishment of persistence mechanisms")
    if has_tokens:
        lines.append("- Revoke all active sessions and refresh tokens for compromised accounts")
    if has_loot:
        lines.append("- Assess data exposure and initiate incident response if PII/sensitive data affected")

    lines.extend([
        "- Review and harden Conditional Access policies",
        "- Implement Privileged Identity Management (PIM) for admin roles",
        "- Deploy Microsoft Defender for Cloud Apps for shadow IT detection",
        "",
    ])

    # --- Appendix: File Inventory ---
    lines.extend(["## Appendix: Evidence File Inventory", ""])
    lines.append("| Folder | Files | Details |")
    lines.append("|--------|-------|---------|")
    for folder_name in ENGAGEMENT_FOLDERS:
        folder_files = files.get(folder_name, [])
        file_names = ", ".join(f.name for f in folder_files[:5])
        if len(folder_files) > 5:
            file_names += f" (+{len(folder_files) - 5} more)"
        lines.append(f"| {folder_name} | {len(folder_files)} | {file_names} |")
    lines.append("")

    report = "\n".join(lines)

    # Save to reports folder
    report_dir = BASE_DIR / "engagement" / "delivery" / "reports" / slug
    report_dir.mkdir(parents=True, exist_ok=True)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    report_path = report_dir / f"engagement_report_{date_str}.md"
    report_path.write_text(report)
    logger.info(f"Report generated: {report_path}")

    return report


# ---------------------------------------------------------------------------
# MITRE ATT&CK Navigator Layer
# ---------------------------------------------------------------------------

def generate_mitre_layer(engagement: str) -> dict:
    """
    Generate a MITRE ATT&CK Navigator layer JSON from engagement playbook entries.

    Args:
        engagement: Target engagement/domain name

    Returns:
        dict: MITRE ATT&CK Navigator layer JSON (version 4.5 format)
    """
    files = _collect_engagement_files(engagement)
    playbook_files = files.get("playbooks", [])
    techniques_used = _extract_techniques_from_playbooks(playbook_files)

    # Deduplicate and count technique usage
    technique_scores: dict[str, dict] = {}
    for entry in techniques_used:
        tid = entry["technique_id"]
        if tid not in technique_scores:
            technique_scores[tid] = {
                "technique_id": tid,
                "technique_name": entry["technique_name"],
                "tactic": entry["tactic"],
                "tools": [],
                "count": 0,
            }
        technique_scores[tid]["tools"].append(entry["tool"])
        technique_scores[tid]["count"] += 1

    # Build Navigator layer
    techniques = []
    for tid, data in technique_scores.items():
        # Score: 1-4 based on usage count
        score = min(data["count"], 4)
        color = _score_to_color(score)

        technique_entry = {
            "techniqueID": tid,
            "tactic": data["tactic"],
            "color": color,
            "comment": f"Tools: {', '.join(set(data['tools']))}. Used {data['count']} time(s).",
            "enabled": True,
            "metadata": [],
            "links": [],
            "showSubtechniques": "." in tid,  # Show sub-techniques if it's a sub-technique ID
            "score": score,
        }
        techniques.append(technique_entry)

    layer = {
        "name": f"EntraReaper - {engagement}",
        "versions": {
            "attack": "15",
            "navigator": "4.9.5",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": f"MITRE ATT&CK techniques used during red team engagement against {engagement}. Auto-generated from playbook execution logs.",
        "filters": {
            "platforms": ["Azure AD", "Office 365", "SaaS", "Windows", "IaaS"],
        },
        "sorting": 3,  # Sort by technique name
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#66b1ff", "#ff6666"],
            "minValue": 0,
            "maxValue": 4,
        },
        "legendItems": [
            {"label": "Used once", "color": "#66b1ff"},
            {"label": "Used 2x", "color": "#ff9966"},
            {"label": "Used 3x", "color": "#ff6666"},
            {"label": "Used 4+ times", "color": "#cc0000"},
        ],
        "metadata": [
            {"name": "engagement", "value": engagement},
            {"name": "generated", "value": _now_pretty()},
            {"name": "generator", "value": "EntraReaper Reporter"},
        ],
        "links": [],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }

    # Save layer file
    slug = _engagement_slug(engagement)
    report_dir = BASE_DIR / "engagement" / "delivery" / "reports" / slug
    report_dir.mkdir(parents=True, exist_ok=True)
    layer_path = report_dir / f"mitre_layer_{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.json"
    layer_path.write_text(json.dumps(layer, indent=2))
    logger.info(f"MITRE layer generated: {layer_path} ({len(techniques)} techniques)")

    return layer


def _score_to_color(score: int) -> str:
    """Map a usage score (1-4) to a hex color."""
    colors = {1: "#66b1ff", 2: "#ff9966", 3: "#ff6666", 4: "#cc0000"}
    return colors.get(score, "#66b1ff")


def _extract_techniques_from_playbooks(playbook_files: list[Path]) -> list[dict]:
    """Extract MITRE techniques from playbook execution logs."""
    techniques: list[dict] = []

    for pb_file in playbook_files:
        content = _read_file_safe(pb_file)
        if not content:
            continue

        # Parse tool names from playbook entries (format: "### {timestamp} -- {tool_name}")
        tool_pattern = re.compile(r"###\s+[\d\-]+\s+[\d:]+\s+UTC\s+--\s+(\w+)")
        found_tools = tool_pattern.findall(content)

        for tool_name in found_tools:
            mitre_entries = TOOL_TO_MITRE.get(tool_name, [])
            for entry in mitre_entries:
                techniques.append({
                    "tool": tool_name,
                    "technique_id": entry["technique_id"],
                    "technique_name": entry["technique_name"],
                    "tactic": entry["tactic"],
                })

    return techniques


# ---------------------------------------------------------------------------
# Evidence Package
# ---------------------------------------------------------------------------

def generate_evidence_package(engagement: str) -> dict:
    """
    Create an evidence manifest with SHA256 hashes for all engagement files.

    Args:
        engagement: Target engagement/domain name

    Returns:
        dict with keys: manifest (list of file entries), stats, package_hash
    """
    files = _collect_engagement_files(engagement)
    manifest: list[dict] = []

    for folder_name, folder_files in files.items():
        for f in folder_files:
            try:
                stat = f.stat()
                entry = {
                    "folder": folder_name,
                    "filename": f.name,
                    "relative_path": str(f.relative_to(BASE_DIR)),
                    "size_bytes": stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                    "sha256": _sha256_file(f),
                }
                manifest.append(entry)
            except OSError as e:
                logger.warning(f"Could not process {f}: {e}")

    # Generate a hash of the entire manifest for integrity
    manifest_json = json.dumps(manifest, sort_keys=True)
    package_hash = hashlib.sha256(manifest_json.encode()).hexdigest()

    # Stats
    total_size = sum(e["size_bytes"] for e in manifest)
    folder_counts = {}
    for entry in manifest:
        folder = entry["folder"]
        folder_counts[folder] = folder_counts.get(folder, 0) + 1

    result = {
        "engagement": engagement,
        "generated": _now_iso(),
        "manifest": manifest,
        "stats": {
            "total_files": len(manifest),
            "total_size_bytes": total_size,
            "total_size_human": _human_size(total_size),
            "files_by_folder": folder_counts,
        },
        "package_hash": package_hash,
        "integrity_note": "SHA256 of the manifest JSON. Verify by re-hashing the manifest array with sort_keys=True.",
    }

    # Save manifest
    slug = _engagement_slug(engagement)
    report_dir = BASE_DIR / "engagement" / "delivery" / "reports" / slug
    report_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = report_dir / f"evidence_manifest_{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.json"
    manifest_path.write_text(json.dumps(result, indent=2))
    logger.info(f"Evidence package generated: {manifest_path} ({len(manifest)} files, {_human_size(total_size)})")

    return result


def _human_size(size_bytes: int) -> str:
    """Convert bytes to human-readable size."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


# ---------------------------------------------------------------------------
# Cleanup Checklist
# ---------------------------------------------------------------------------

def generate_cleanup_checklist(engagement: str) -> str:
    """
    Read persistence/ folder and generate a cleanup/teardown checklist.

    Args:
        engagement: Target engagement/domain name

    Returns:
        str: Markdown cleanup checklist
    """
    slug = _engagement_slug(engagement)
    persistence_dir = BASE_DIR / "persistence" / slug

    lines = [
        f"# Cleanup Checklist: {engagement}",
        f"",
        f"> Generated: {_now_pretty()}",
        f"> ALL items MUST be completed before engagement closeout.",
        f"",
        f"---",
        f"",
    ]

    if not persistence_dir.exists() or not any(persistence_dir.iterdir()):
        lines.append("No persistence mechanisms found. No cleanup required.")
        return "\n".join(lines)

    # Parse persistence inventory
    inventory_path = persistence_dir / "inventory.md"
    checklist_items: list[dict] = []

    if inventory_path.exists():
        content = _read_file_safe(inventory_path)

        # Parse markdown sections for each persistence entry
        # Format: ### {type} -- {target}
        sections = content.split("### ")[1:]  # skip header
        for section in sections:
            item: dict[str, str] = {}
            section_lines = section.strip().split("\n")
            if section_lines:
                item["title"] = section_lines[0].strip()

            for line in section_lines:
                if "|" in line and "Key" not in line and "---" not in line:
                    parts = [p.strip() for p in line.split("|") if p.strip()]
                    if len(parts) >= 2:
                        key = parts[0].lower()
                        value = parts[1]
                        item[key] = value

            if item.get("title"):
                checklist_items.append(item)

    if checklist_items:
        lines.append(f"## Active Persistence ({len(checklist_items)} items)")
        lines.append("")

        for i, item in enumerate(checklist_items, 1):
            status = item.get("status", "UNKNOWN")
            cleanup_action = item.get("cleanup_action", "Manual review required")
            persist_type = item.get("type", "unknown")
            target = item.get("target", "unknown")
            tool_used = item.get("tool_used", "unknown")

            lines.extend([
                f"### [{i}] {item.get('title', 'Unknown')}",
                f"",
                f"- [ ] **Cleanup action:** {cleanup_action}",
                f"- **Type:** {persist_type}",
                f"- **Target:** {target}",
                f"- **Installed via:** {tool_used}",
                f"- **Current status:** {status}",
                f"- **Installed:** {item.get('installed', 'unknown')}",
                f"",
            ])

        # Verification section
        lines.extend([
            "---",
            "",
            "## Post-Cleanup Verification",
            "",
            "- [ ] Re-run `recon_insider` to verify no residual access",
            "- [ ] Check Entra ID audit logs for the cleanup actions",
            "- [ ] Verify federation settings are restored to pre-engagement state",
            "- [ ] Confirm all registered devices are removed",
            "- [ ] Validate PTA agent list matches pre-engagement baseline",
            "- [ ] Check app registrations for residual credentials",
            "- [ ] Revoke all engagement tokens",
            "- [ ] Notify client SOC that cleanup is complete",
            "",
        ])
    else:
        # Persistence folder exists but no parseable entries
        lines.append("Persistence folder exists but no structured entries found.")
        lines.append("")
        lines.append("Manual review of the following files is required:")
        lines.append("")
        for f in sorted(persistence_dir.rglob("*")):
            if f.is_file():
                lines.append(f"- `{f.relative_to(BASE_DIR)}`")
        lines.append("")

    checklist = "\n".join(lines)

    # Save checklist
    report_dir = BASE_DIR / "engagement" / "delivery" / "reports" / slug
    report_dir.mkdir(parents=True, exist_ok=True)
    checklist_path = report_dir / f"cleanup_checklist_{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.md"
    checklist_path.write_text(checklist)
    logger.info(f"Cleanup checklist generated: {checklist_path}")

    return checklist


# ---------------------------------------------------------------------------
# Kill Chain Narrative
# ---------------------------------------------------------------------------

def generate_kill_chain_narrative(engagement: str) -> str:
    """
    Read playbooks/ execution log and generate a chronological attack narrative.

    Args:
        engagement: Target engagement/domain name

    Returns:
        str: Markdown narrative of the attack chain
    """
    slug = _engagement_slug(engagement)
    playbook_dir = BASE_DIR / "playbooks" / slug

    lines = [
        f"# Kill Chain Narrative: {engagement}",
        f"",
        f"> Generated: {_now_pretty()}",
        f"> Chronological reconstruction of the attack chain from execution logs.",
        f"",
        f"---",
        f"",
    ]

    if not playbook_dir.exists():
        lines.append("No playbook execution data found.")
        return "\n".join(lines)

    # Read execution log
    exec_log = playbook_dir / "execution_log.md"
    if not exec_log.exists():
        lines.append("No execution log found in playbooks folder.")
        return "\n".join(lines)

    content = _read_file_safe(exec_log)

    # Parse entries from the execution log
    # Format: ### {timestamp} -- {tool_name}
    entry_pattern = re.compile(
        r"###\s+([\d\-]+\s+[\d:]+\s+UTC)\s+--\s+(\w+)",
        re.MULTILINE,
    )
    entries: list[dict] = []

    # Split into sections
    sections = content.split("### ")[1:]
    for section in sections:
        section_lines = section.strip().split("\n")
        header = section_lines[0] if section_lines else ""

        match = re.match(r"([\d\-]+\s+[\d:]+\s+UTC)\s+--\s+(\w+)", header)
        if not match:
            continue

        timestamp = match.group(1)
        tool_name = match.group(2)

        # Parse key-value pairs from the table
        entry_data: dict[str, str] = {"timestamp": timestamp, "tool": tool_name}
        for line in section_lines:
            if "|" in line and "Key" not in line and "---" not in line:
                parts = [p.strip() for p in line.split("|") if p.strip()]
                if len(parts) >= 2:
                    entry_data[parts[0]] = parts[1]

        entries.append(entry_data)

    if not entries:
        lines.append("Execution log exists but no parseable entries found.")
        lines.append("")
        lines.append("Raw log content:")
        lines.append("")
        lines.append("```")
        lines.append(content[:5000])
        lines.append("```")
        return "\n".join(lines)

    # Group entries by MITRE tactic phase
    phase_order = [
        ("Reconnaissance", ["recon_tenant", "recon_users", "recon_domains", "recon_dns", "recon_openid"]),
        ("Discovery", ["recon_insider"]),
        ("Initial Access", ["cred_device_code", "access_phishing", "access_guest_invite"]),
        ("Credential Access", ["cred_token", "cred_nthash", "cred_prt_extract", "cred_cookie"]),
        ("Privilege Escalation", ["privesc_azure_admin", "privesc_password", "privesc_role_assign"]),
        ("Persistence", ["persist_federation", "persist_device", "persist_pta_agent", "persist_saml_forge", "persist_mfa_app"]),
        ("Defense Evasion", ["evade_audit"]),
        ("Lateral Movement", ["move_vm_exec", "move_messaging"]),
        ("Collection", ["collect_onedrive", "collect_email"]),
        ("Impact", ["impact_user_ops", "impact_config"]),
    ]

    # Map entries to phases
    current_phase_idx = 0
    for phase_name, phase_tools in phase_order:
        phase_entries = [e for e in entries if e.get("tool") in phase_tools]
        if not phase_entries:
            continue

        current_phase_idx += 1
        lines.extend([
            f"## Phase {current_phase_idx}: {phase_name}",
            f"",
        ])

        for entry in phase_entries:
            tool = entry.get("tool", "unknown")
            timestamp = entry.get("timestamp", "unknown")
            target = entry.get("target", "unknown")
            result = entry.get("result", "no result recorded")
            scenario = entry.get("scenario", "")
            opsec = entry.get("opsec_actual", entry.get("opsec_predicted", ""))

            # Get MITRE techniques for this tool
            mitre_entries = TOOL_TO_MITRE.get(tool, [])
            mitre_str = ", ".join(f"{m['technique_id']}" for m in mitre_entries) if mitre_entries else "N/A"

            lines.extend([
                f"**{timestamp}** -- `{tool}`",
                f"",
                f"- **Target:** {target}",
                f"- **Result:** {result}",
            ])
            if scenario:
                lines.append(f"- **Scenario:** {scenario}")
            if opsec:
                lines.append(f"- **OPSEC level:** {opsec}")
            lines.append(f"- **MITRE:** {mitre_str}")
            lines.append("")

    # Uncategorized entries (tools not in any phase)
    all_phase_tools = set()
    for _, tools in phase_order:
        all_phase_tools.update(tools)
    uncategorized = [e for e in entries if e.get("tool") not in all_phase_tools]
    if uncategorized:
        current_phase_idx += 1
        lines.extend([f"## Phase {current_phase_idx}: Other Operations", ""])
        for entry in uncategorized:
            lines.extend([
                f"**{entry.get('timestamp', 'unknown')}** -- `{entry.get('tool', 'unknown')}`",
                f"- **Target:** {entry.get('target', 'unknown')}",
                f"- **Result:** {entry.get('result', 'no result')}",
                "",
            ])

    # Summary timeline
    lines.extend([
        "---",
        "",
        "## Timeline Summary",
        "",
        "| Time | Tool | Target | Result |",
        "|------|------|--------|--------|",
    ])
    for entry in entries:
        result_short = entry.get("result", "")[:50]
        lines.append(
            f"| {entry.get('timestamp', '')} | {entry.get('tool', '')} "
            f"| {entry.get('target', '')} | {result_short} |"
        )
    lines.append("")

    narrative = "\n".join(lines)

    # Save narrative
    report_dir = BASE_DIR / "engagement" / "delivery" / "reports" / slug
    report_dir.mkdir(parents=True, exist_ok=True)
    narrative_path = report_dir / f"kill_chain_narrative_{datetime.now(timezone.utc).strftime('%Y-%m-%d')}.md"
    narrative_path.write_text(narrative)
    logger.info(f"Kill chain narrative generated: {narrative_path}")

    return narrative

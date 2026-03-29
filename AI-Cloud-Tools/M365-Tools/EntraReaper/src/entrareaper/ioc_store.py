"""
IOC store for EntraReaper.
Auto-collects and categorizes IOCs discovered during recon and attack scenarios.
Persists to JSON + generates Markdown reports per engagement.
"""

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("entrareaper.iocs")

IOC_DIR = Path(__file__).parent.parent.parent / "engagement" / "recon" / "iocs"


@dataclass
class IOC:
    """A single indicator of compromise."""
    type: str               # tenant_id, domain, user, endpoint, token, ip, url, hash, cookie, cert, app_id, protocol
    value: str              # The actual indicator value
    context: str            # How/where it was discovered
    source_scenario: str    # Which scenario produced it (e.g., "S01", "S03")
    source_tool: str        # Which MCP tool produced it (e.g., "recon_tenant")
    confidence: str         # confirmed, probable, suspected
    risk: str               # critical, high, medium, low, info
    tags: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    notes: str = ""


class IOCStore:
    """Manages IOC collection, deduplication, and export."""

    def __init__(self, engagement: str = "default"):
        self.engagement = engagement
        self.iocs: list[IOC] = []
        self._file = IOC_DIR / f"{engagement}.json"
        self._load()

    def add(self, ioc: IOC) -> bool:
        """Add an IOC. Returns False if duplicate."""
        # Deduplicate by type+value
        for existing in self.iocs:
            if existing.type == ioc.type and existing.value == ioc.value:
                # Update context if new info
                if ioc.context not in existing.context:
                    existing.context += f"; {ioc.context}"
                if ioc.source_scenario not in existing.tags:
                    existing.tags.append(ioc.source_scenario)
                self._save()
                return False
        self.iocs.append(ioc)
        self._save()
        logger.info(f"IOC added: [{ioc.type}] {ioc.value}")
        return True

    def add_bulk(self, iocs: list[IOC]) -> int:
        """Add multiple IOCs. Returns count of new (non-duplicate) entries."""
        count = sum(1 for ioc in iocs if self.add(ioc))
        return count

    def get_by_type(self, ioc_type: str) -> list[IOC]:
        """Get all IOCs of a given type."""
        return [i for i in self.iocs if i.type == ioc_type]

    def get_by_risk(self, risk: str) -> list[IOC]:
        """Get all IOCs of a given risk level."""
        return [i for i in self.iocs if i.risk == risk]

    def summary(self) -> dict:
        """Return a summary of all IOCs by type and risk."""
        by_type = {}
        by_risk = {}
        for ioc in self.iocs:
            by_type[ioc.type] = by_type.get(ioc.type, 0) + 1
            by_risk[ioc.risk] = by_risk.get(ioc.risk, 0) + 1
        return {
            "engagement": self.engagement,
            "total": len(self.iocs),
            "by_type": by_type,
            "by_risk": by_risk,
        }

    def export_markdown(self) -> str:
        """Export all IOCs as a Markdown report."""
        lines = [
            f"# IOC Report: {self.engagement}",
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            f"Total IOCs: {len(self.iocs)}",
            "",
        ]

        # Group by type
        types = sorted(set(i.type for i in self.iocs))
        for ioc_type in types:
            type_iocs = self.get_by_type(ioc_type)
            lines.append(f"## {ioc_type.replace('_', ' ').title()} ({len(type_iocs)})")
            lines.append("")
            lines.append("| Value | Risk | Confidence | Context | Source |")
            lines.append("|-------|------|------------|---------|--------|")
            for ioc in type_iocs:
                val = ioc.value[:60] + "..." if len(ioc.value) > 60 else ioc.value
                lines.append(f"| `{val}` | {ioc.risk} | {ioc.confidence} | {ioc.context[:50]} | {ioc.source_scenario} |")
            lines.append("")

        return "\n".join(lines)

    def save_markdown(self) -> Path:
        """Save Markdown report to iocs directory."""
        md_path = IOC_DIR / f"{self.engagement}_report.md"
        md_path.write_text(self.export_markdown())
        return md_path

    def clear(self) -> int:
        """Clear all IOCs. Returns count removed."""
        count = len(self.iocs)
        self.iocs.clear()
        self._save()
        return count

    def _save(self) -> None:
        IOC_DIR.mkdir(parents=True, exist_ok=True)
        data = [asdict(ioc) for ioc in self.iocs]
        self._file.write_text(json.dumps(data, indent=2))

    def _load(self) -> None:
        if not self._file.exists():
            return
        try:
            data = json.loads(self._file.read_text())
            self.iocs = [IOC(**item) for item in data]
            logger.info(f"Loaded {len(self.iocs)} IOCs for engagement '{self.engagement}'")
        except Exception as e:
            logger.warning(f"Failed to load IOC store: {e}")


def extract_iocs_from_recon(domain: str, findings: dict, scenario: str = "S01-S08") -> list[IOC]:
    """
    Auto-extract IOCs from recon findings dict.
    Called by the recon tools to populate the IOC store.
    """
    iocs = []

    # Tenant ID
    tid = findings.get('tenant_id')
    if tid and tid != 'FAILED':
        iocs.append(IOC(
            type="tenant_id", value=tid,
            context=f"Entra ID tenant for {domain}",
            source_scenario=scenario, source_tool="recon_tenant",
            confidence="confirmed", risk="info",
            tags=["recon", "identity"],
        ))

    # Domain
    iocs.append(IOC(
        type="domain", value=domain,
        context="Primary target domain",
        source_scenario=scenario, source_tool="recon_tenant",
        confidence="confirmed", risk="info",
        tags=["recon", "target"],
    ))

    # Additional domains
    for d in findings.get('domains', []):
        if isinstance(d, str) and d != domain:
            iocs.append(IOC(
                type="domain", value=d,
                context=f"Registered domain in same tenant as {domain}",
                source_scenario="S02", source_tool="recon_domains",
                confidence="confirmed", risk="info",
                tags=["recon", "domain_inventory"],
            ))

    # Confirmed users
    for user in findings.get('all_valid_users', []):
        local = user.split('@')[0] if '@' in user else user
        if local in ('admin', 'administrator', 'helpdesk', 'it', 'ceo', 'cfo', 'ciso'):
            risk = "high"
        elif local in ('test', 'dev', 'demo', 'staging'):
            risk = "medium"
        elif local in ('service', 'svc', 'sync', 'backup', 'api', 'bot'):
            risk = "medium"
        else:
            risk = "low"

        iocs.append(IOC(
            type="user", value=user,
            context=f"Confirmed via GetCredentialType API (unauthenticated)",
            source_scenario="S03", source_tool="recon_users",
            confidence="confirmed", risk=risk,
            tags=["recon", "user_enum", "credential_target"],
        ))

    # Federation endpoints
    fed = findings.get('federation', {})
    fed_url = fed.get('url', 'None')
    if fed_url and fed_url != 'None':
        iocs.append(IOC(
            type="url", value=fed_url,
            context=f"ADFS/federation active auth endpoint for {domain}",
            source_scenario="S05", source_tool="recon_dns",
            confidence="confirmed", risk="high",
            tags=["recon", "federation", "adfs", "password_spray_target"],
        ))

    fed_meta = fed.get('metadata', 'None')
    if fed_meta and fed_meta != 'None':
        iocs.append(IOC(
            type="url", value=fed_meta,
            context=f"Federation metadata URL for {domain}",
            source_scenario="S05", source_tool="recon_dns",
            confidence="confirmed", risk="medium",
            tags=["recon", "federation", "metadata"],
        ))

    # OIDC endpoints
    openid = findings.get('openid', {})
    for key in ('issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'):
        val = openid.get(key)
        if val:
            iocs.append(IOC(
                type="url", value=val,
                context=f"OpenID Connect {key} for {domain}",
                source_scenario="S06", source_tool="recon_openid",
                confidence="confirmed", risk="info",
                tags=["recon", "oidc", key],
            ))

    # Exchange protocol endpoints
    for proto in ('activesync', 'ews', 'rest'):
        url = findings.get(f'proto_{proto}')
        if url:
            risk = "medium" if proto == 'activesync' else "info"
            iocs.append(IOC(
                type="endpoint", value=url,
                context=f"Exchange {proto.upper()} protocol endpoint",
                source_scenario="S08", source_tool="raw_invoke",
                confidence="confirmed", risk=risk,
                tags=["recon", "exchange", proto, "protocol"],
            ))

    # Login info metadata
    login = findings.get('login_info', {})
    brand = login.get('Federation Brand Name', '')
    if brand and brand not in ('None', '?'):
        iocs.append(IOC(
            type="metadata", value=f"brand={brand}",
            context=f"Tenant brand name from login API",
            source_scenario="S01", source_tool="recon_tenant",
            confidence="confirmed", risk="info",
            tags=["recon", "brand"],
        ))

    acct_type = login.get('Account Type', '')
    if acct_type:
        iocs.append(IOC(
            type="metadata", value=f"auth_type={acct_type}",
            context=f"Authentication type for {domain}",
            source_scenario="S01", source_tool="recon_tenant",
            confidence="confirmed", risk="info",
            tags=["recon", "auth_config"],
        ))

    sso = login.get('Desktop Sso Enabled', 'None')
    if str(sso) == 'True':
        iocs.append(IOC(
            type="metadata", value=f"desktop_sso=enabled",
            context=f"Seamless SSO enabled. Silver Ticket attack viable.",
            source_scenario="S01", source_tool="recon_tenant",
            confidence="confirmed", risk="high",
            tags=["recon", "sso", "silver_ticket", "attack_surface"],
        ))

    region = openid.get('tenant_region_scope', '')
    if region:
        iocs.append(IOC(
            type="metadata", value=f"region={region}",
            context=f"Tenant data residency region",
            source_scenario="S06", source_tool="recon_openid",
            confidence="confirmed", risk="info",
            tags=["recon", "region"],
        ))

    return iocs

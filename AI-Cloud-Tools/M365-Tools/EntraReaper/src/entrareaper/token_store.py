"""
Token store for EntraReaper.
Maintains named token cache with metadata, expiry tracking, and persistence.
"""

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

logger = logging.getLogger("entrareaper.tokens")

# Default token store location
TOKEN_STORE_PATH = Path.home() / ".entrareaper" / "tokens.json"


@dataclass
class Token:
    """A cached access/refresh token with metadata."""
    alias: str                          # User-friendly name (e.g., "graph", "exo")
    resource: str                       # Target resource/audience
    token_type: str                     # "access", "refresh", "prt", "saml"
    value: str                          # The actual token value
    tenant_id: str = ""
    user_principal_name: str = ""
    client_id: str = ""
    scopes: list[str] = field(default_factory=list)
    expires_at: float = 0.0             # Unix timestamp
    obtained_at: float = field(default_factory=time.time)
    obtained_via: str = ""              # How it was obtained (e.g., "device_code", "credentials")
    refresh_token: str = ""             # Associated refresh token if any
    raw_response: dict = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        if self.expires_at == 0:
            return False  # No expiry info
        return time.time() > self.expires_at

    @property
    def expires_in_seconds(self) -> int:
        if self.expires_at == 0:
            return -1
        return max(0, int(self.expires_at - time.time()))

    def summary(self) -> dict:
        """Return a safe summary (no token values)."""
        return {
            "alias": self.alias,
            "resource": self.resource,
            "token_type": self.token_type,
            "tenant_id": self.tenant_id,
            "user_principal_name": self.user_principal_name,
            "client_id": self.client_id,
            "is_expired": self.is_expired,
            "expires_in_seconds": self.expires_in_seconds,
            "obtained_via": self.obtained_via,
            "has_refresh_token": bool(self.refresh_token),
        }


class TokenStore:
    """Named token cache with persistence."""

    def __init__(self, store_path: Path | None = None):
        self.store_path = store_path or TOKEN_STORE_PATH
        self._tokens: dict[str, Token] = {}
        self._load()

    def add(self, token: Token) -> None:
        """Add or update a token in the store."""
        self._tokens[token.alias] = token
        self._save()
        logger.info(f"Token stored: {token.alias} ({token.resource})")

    def get(self, alias: str) -> Token | None:
        """Get a token by alias."""
        token = self._tokens.get(alias)
        if token and token.is_expired:
            logger.warning(f"Token '{alias}' is expired")
        return token

    def get_value(self, alias: str) -> str | None:
        """Get just the token value by alias. Returns None if not found or expired."""
        token = self.get(alias)
        if token is None:
            return None
        if token.is_expired:
            logger.warning(f"Token '{alias}' is expired (expired {-token.expires_in_seconds}s ago)")
        return token.value

    def remove(self, alias: str) -> bool:
        """Remove a token by alias."""
        if alias in self._tokens:
            del self._tokens[alias]
            self._save()
            return True
        return False

    def list_tokens(self) -> list[dict]:
        """List all tokens (summaries only, no values)."""
        return [t.summary() for t in self._tokens.values()]

    def clear(self) -> int:
        """Clear all tokens. Returns count of removed tokens."""
        count = len(self._tokens)
        self._tokens.clear()
        self._save()
        return count

    def find_by_resource(self, resource: str) -> Token | None:
        """Find a non-expired token for a given resource."""
        for token in self._tokens.values():
            if token.resource == resource and not token.is_expired:
                return token
        return None

    def _save(self) -> None:
        """Persist tokens to disk."""
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        data = {alias: asdict(token) for alias, token in self._tokens.items()}
        self.store_path.write_text(json.dumps(data, indent=2, default=str))

    def _load(self) -> None:
        """Load tokens from disk."""
        if not self.store_path.exists():
            return
        try:
            data = json.loads(self.store_path.read_text())
            for alias, token_data in data.items():
                self._tokens[alias] = Token(**token_data)
            logger.info(f"Loaded {len(self._tokens)} tokens from {self.store_path}")
        except Exception as e:
            logger.warning(f"Failed to load token store: {e}")


# Resource aliases for common AADInternals targets
RESOURCE_MAP = {
    "graph": "https://graph.microsoft.com",
    "aad_graph": "https://graph.windows.net",
    "exo": "https://outlook.office365.com",
    "spo": "sharepoint",  # Tenant-specific URL
    "onedrive": "https://officeapps.live.com",
    "teams": "https://api.spaces.skype.com",
    "azure": "https://management.azure.com",
    "azure_core": "https://management.core.windows.net",
    "intune": "https://enrollment.manage.microsoft.com",
    "pta": "https://proxy.cloudwebappproxy.net/registerapp",
    "compliance": "https://compliance.microsoft.com",
    "admin": "https://admin.microsoft.com",
    "cloud_shell": "https://management.azure.com",
    "partner": "https://api.partnercenter.microsoft.com",
    "sara": "https://api.diagnostics.office.com",
    "commerce": "https://licensing.m365.microsoft.com",
}

# Map resource aliases to AADInternals token cmdlets
TOKEN_CMDLET_MAP = {
    "graph": "Get-AADIntAccessTokenForMSGraph",
    "aad_graph": "Get-AADIntAccessTokenForAADGraph",
    "exo": "Get-AADIntAccessTokenForEXO",
    "spo": "Get-AADIntAccessTokenForSPO",
    "onedrive": "Get-AADIntAccessTokenForOneDrive",
    "teams": "Get-AADIntAccessTokenForTeams",
    "azure": "Get-AADIntAccessTokenForAzureCoreManagement",
    "azure_core": "Get-AADIntAccessTokenForAzureCoreManagement",
    "intune": "Get-AADIntAccessTokenForIntuneMDM",
    "pta": "Get-AADIntAccessTokenForPTA",
    "compliance": "Get-AADIntAccessTokenForCompliance",
    "admin": "Get-AADIntAccessTokenForAdmin",
    "cloud_shell": "Get-AADIntAccessTokenForCloudShell",
    "partner": "Get-AADIntAccessTokenForMSPartner",
    "sara": "Get-AADIntAccessTokenForSARA",
    "commerce": "Get-AADIntAccessTokenForMSCommerce",
    "aad_join": "Get-AADIntAccessTokenForAADJoin",
    "office_apps": "Get-AADIntAccessTokenForOfficeApps",
    "my_signins": "Get-AADIntAccessTokenForMySignins",
    "onenote": "Get-AADIntAccessTokenForOneNote",
    "whfb": "Get-AADIntAccessTokenForWHfB",
    "iam_api": "Get-AADIntAccessTokenForAADIAMAPI",
    "azure_mgmt": "Get-AADIntAccessTokenForAzureMgmtAPI",
    "spo_migration": "Get-AADIntAccessTokenForSPOMigrationTool",
    "access_packages": "Get-AADIntAccessTokenForAccessPackages",
}

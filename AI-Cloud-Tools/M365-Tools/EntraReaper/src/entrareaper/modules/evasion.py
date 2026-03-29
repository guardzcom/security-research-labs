"""
Evasion engine — user-agent rotation, timing jitter, token audience switching.

Features:
- UA rotation: realistic user-agent strings per app context
- Timing jitter: configurable random delays between operations
- Token audience switching: when one resource blocked, try FOCI alternatives
- FOCI auto-pivot: given one token, try refreshing to all 36 family resources
"""

import logging
import random
import time
from pathlib import Path

logger = logging.getLogger("entrareaper.evasion")

BASE_DIR = Path(__file__).parent.parent.parent.parent  # project root

# ---------------------------------------------------------------------------
# User-Agent strings — realistic per application context
# Each context maps to a list of plausible UA strings observed in the wild.
# ---------------------------------------------------------------------------

USER_AGENTS: dict[str, list[str]] = {
    "outlook": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
        "Microsoft Outlook 16.0.17928.20114; Pro; Windows NT 10.0; x64",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ],
    "teams": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/24096.1400.2895.6689 Chrome/120.0.6099.291 Electron/28.3.3 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Teams/24096.1400.2895.6689 Chrome/120.0.6099.291 Electron/28.3.3 Safari/537.36",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.113 Mobile Safari/537.36 TeamsMobile-Android/1449/24114007",
    ],
    "edge": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.80",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.80",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.81",
    ],
    "azure_cli": [
        "python-requests/2.31.0",
        "AZURECLI/2.58.0 azsdk-python-core/1.30.0 Python/3.11.8 (Windows-10-10.0.22631-SP0)",
        "AZURECLI/2.58.0 azsdk-python-core/1.30.0 Python/3.11.8 (macOS-14.4-arm64-arm-64bit)",
    ],
    "powershell": [
        "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.22631; en-US) PowerShell/7.4.1",
        "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.22621.2506",
        "AzurePowershell/v12.4.0",
    ],
    "mobile": [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.113 Mobile Safari/537.36",
        "Outlook-iOS/2.0 (iPhone; iOS 17.4; Scale/3.00; 428x926; com.microsoft.Office.Outlook 4.2418.0)",
    ],
    "onedrive": [
        "OneDrive/24.071.0407.0002 (Windows; x64; 10.0.22631)",
        "OneDriveiOSApp/15.4 (com.microsoft.skydrive; iOS 17.4; Scale/3.00)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ],
    "sharepoint": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.2478.80",
        "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Word 16.0.17928; Pro)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    ],
}

# ---------------------------------------------------------------------------
# FOCI Family — all 36 Family of Client IDs members
# Tokens obtained for one app can be refreshed to obtain tokens for any other.
# ---------------------------------------------------------------------------

FOCI_FAMILY: list[dict[str, str]] = [
    {"client_id": "00b41c95-dab0-4487-9791-b9d2c32c80f2", "name": "Office 365 Management", "context": "azure_cli"},
    {"client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46", "name": "Microsoft Azure CLI", "context": "azure_cli"},
    {"client_id": "0ec893e0-5785-4de6-99da-4ed124e5296c", "name": "Office UWP PWA", "context": "outlook"},
    {"client_id": "1950a258-227b-4e31-a9cf-717495945fc2", "name": "Microsoft Azure PowerShell", "context": "powershell"},
    {"client_id": "1fec8e78-bce4-4aaf-ab1b-5451cc387264", "name": "Microsoft Teams", "context": "teams"},
    {"client_id": "22098786-6e16-43cc-a27d-191a01a1e3b5", "name": "Microsoft To-Do Client", "context": "mobile"},
    {"client_id": "26a7ee05-5602-4d76-a7ba-eae8b7b67941", "name": "Windows Search", "context": "edge"},
    {"client_id": "27922004-5251-4030-b22d-91ecd9a37ea4", "name": "Outlook Mobile", "context": "mobile"},
    {"client_id": "2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8", "name": "Microsoft Bing Search for Microsoft Edge", "context": "edge"},
    {"client_id": "4813382a-8fa7-425e-ab75-3b753aab3abb", "name": "Microsoft Authenticator App", "context": "mobile"},
    {"client_id": "4e291c71-d680-4d0e-9640-0a3358e31177", "name": "PowerApps", "context": "edge"},
    {"client_id": "57336123-6e14-4acc-8dcf-287b6088aa28", "name": "Microsoft Whiteboard Client", "context": "edge"},
    {"client_id": "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0", "name": "Microsoft Flow", "context": "edge"},
    {"client_id": "66375f6b-983f-4c2c-9701-d680650f588f", "name": "Microsoft Planner", "context": "edge"},
    {"client_id": "844cca35-0656-46ce-b636-13f48b0eecbd", "name": "Microsoft Stream Mobile Native", "context": "mobile"},
    {"client_id": "872cd9fa-d31f-45e0-9eab-6e460a02d1f1", "name": "Visual Studio", "context": "azure_cli"},
    {"client_id": "87749df4-7ccf-48f8-aa87-704bad0e0e16", "name": "Microsoft Teams Device Admin Agent", "context": "teams"},
    {"client_id": "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223", "name": "Microsoft Intune Company Portal", "context": "mobile"},
    {"client_id": "a40d7d7d-59aa-447e-a655-679a4107e548", "name": "Accounts Control UI", "context": "edge"},
    {"client_id": "a569458c-7f2b-45cb-bab9-b7dee514d112", "name": "Yammer iPhone", "context": "mobile"},
    {"client_id": "ab9b8c07-8f02-4f72-87fa-80105867a763", "name": "OneDrive SyncEngine", "context": "onedrive"},
    {"client_id": "af124e86-4e96-495a-b70a-90f90ab96707", "name": "OneDrive iOS App", "context": "mobile"},
    {"client_id": "b26aadf8-566f-4478-926f-589f601d9c74", "name": "OneDrive", "context": "onedrive"},
    {"client_id": "be1918be-3fe3-4be9-b32b-b542fc27f02e", "name": "M365 Compliance Drive Client", "context": "edge"},
    {"client_id": "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12", "name": "Microsoft Power BI", "context": "edge"},
    {"client_id": "cab96880-db5b-4e15-90a7-f3f1d62ffe39", "name": "Microsoft Defender Platform", "context": "edge"},
    {"client_id": "cf36b471-5b44-428c-9ce7-313bf84528de", "name": "Microsoft Bing Search", "context": "edge"},
    {"client_id": "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0", "name": "SharePoint", "context": "sharepoint"},
    {"client_id": "d3590ed6-52b3-4102-aeff-aad2292ab01c", "name": "Microsoft Office", "context": "outlook"},
    {"client_id": "d7b530a4-7680-4c23-a8bf-c52c121d2e87", "name": "Microsoft Edge Enterprise New Tab Page", "context": "edge"},
    {"client_id": "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3", "name": "Microsoft Defender for Mobile", "context": "mobile"},
    {"client_id": "e9b154d0-7658-433b-bb25-6b8e0a8a7c59", "name": "Outlook Lite", "context": "mobile"},
    {"client_id": "e9c51622-460d-4d3d-952d-966a5b1da34c", "name": "Microsoft Edge", "context": "edge"},
    {"client_id": "eb539595-3fe1-474e-9c1d-feb3625d1be5", "name": "Microsoft Tunnel", "context": "mobile"},
    {"client_id": "ecd6b820-32c2-49b6-98a6-444530e5a77a", "name": "Microsoft Edge", "context": "edge"},
    {"client_id": "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d", "name": "SharePoint Android", "context": "mobile"},
    {"client_id": "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34", "name": "Microsoft Edge", "context": "edge"},
]

# ---------------------------------------------------------------------------
# Resource URIs — common Microsoft Graph and service endpoints
# Used for audience switching when a specific resource is blocked
# ---------------------------------------------------------------------------

RESOURCE_AUDIENCES: dict[str, str] = {
    "graph": "https://graph.microsoft.com",
    "management": "https://management.azure.com",
    "outlook": "https://outlook.office365.com",
    "sharepoint": "https://tenant.sharepoint.com",
    "onedrive": "https://tenant-my.sharepoint.com",
    "teams": "https://api.spaces.skype.com",
    "substrate": "https://substrate.office.com",
    "office": "https://officeapps.live.com",
    "aad_graph": "https://graph.windows.net",
    "key_vault": "https://vault.azure.net",
    "storage": "https://storage.azure.com",
    "cosmos": "https://cosmos.azure.com",
    "service_bus": "https://servicebus.azure.net",
    "data_lake": "https://datalake.azure.net",
}

# ---------------------------------------------------------------------------
# Timing profiles — delays between operations
# ---------------------------------------------------------------------------

TIMING_PROFILES: dict[str, dict[str, float]] = {
    "aggressive": {"min_seconds": 2.0, "max_seconds": 5.0, "description": "Fast — acceptable for noisy recon phases"},
    "normal": {"min_seconds": 10.0, "max_seconds": 30.0, "description": "Standard — mimics casual user browsing"},
    "stealth": {"min_seconds": 60.0, "max_seconds": 300.0, "description": "Slow — mimics low-and-slow attacker or background sync"},
    "human": {"min_seconds": 3.0, "max_seconds": 15.0, "description": "Human-like — variable delays simulating user behavior"},
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_user_agent(context: str = "random") -> str:
    """
    Return a realistic user-agent string for the given application context.

    Args:
        context: One of "outlook", "teams", "edge", "azure_cli", "powershell",
                 "mobile", "onedrive", "sharepoint", or "random" (picks any).

    Returns:
        A user-agent string.
    """
    if context == "random":
        context = random.choice(list(USER_AGENTS.keys()))

    agents = USER_AGENTS.get(context)
    if not agents:
        logger.warning(f"Unknown UA context '{context}', falling back to edge")
        agents = USER_AGENTS["edge"]

    selected = random.choice(agents)
    logger.debug(f"UA selected: context={context}, ua={selected[:60]}...")
    return selected


def apply_jitter(profile: str = "normal") -> dict:
    """
    Calculate a random delay based on the timing profile. Does NOT sleep --
    returns the delay so the caller can decide whether to apply it.

    Args:
        profile: One of "aggressive", "normal", "stealth", "human"

    Returns:
        dict with keys: delay_seconds, profile, description
    """
    config = TIMING_PROFILES.get(profile)
    if not config:
        logger.warning(f"Unknown timing profile '{profile}', using normal")
        config = TIMING_PROFILES["normal"]

    if profile == "human":
        # Human-like: bimodal distribution (short pauses + occasional longer ones)
        if random.random() < 0.2:
            # 20% chance of a longer "thinking" pause
            delay = random.uniform(config["max_seconds"], config["max_seconds"] * 3)
        else:
            delay = random.uniform(config["min_seconds"], config["max_seconds"])
    else:
        delay = random.uniform(config["min_seconds"], config["max_seconds"])

    delay = round(delay, 2)
    logger.debug(f"Jitter calculated: profile={profile}, delay={delay}s")

    return {
        "delay_seconds": delay,
        "profile": profile,
        "description": config["description"],
    }


def sleep_jitter(profile: str = "normal") -> float:
    """
    Apply timing jitter by actually sleeping. Returns the actual delay.

    Args:
        profile: One of "aggressive", "normal", "stealth", "human"

    Returns:
        float: actual seconds slept
    """
    jitter = apply_jitter(profile)
    delay = jitter["delay_seconds"]
    logger.info(f"Sleeping {delay}s (profile={profile})")
    time.sleep(delay)
    return delay


def get_foci_pivot_targets() -> list[dict]:
    """
    Return all 36 FOCI family apps with client_id, name, and suggested context.

    Use case: after obtaining a token for one FOCI app, the refresh token can be
    used to obtain access tokens for ANY other FOCI app without additional consent.

    Returns:
        list of dicts with keys: client_id, name, context
    """
    return [
        {
            "client_id": app["client_id"],
            "name": app["name"],
            "context": app["context"],
            "suggested_ua": get_user_agent(app["context"]),
        }
        for app in FOCI_FAMILY
    ]


def suggest_audience_switch(blocked_resource: str) -> list[dict]:
    """
    When a resource endpoint returns 403/blocked, suggest FOCI-based alternatives
    that may grant access to the same data through a different audience.

    Args:
        blocked_resource: The resource URI or short name that was blocked
                         (e.g., "graph", "https://graph.microsoft.com", "outlook")

    Returns:
        list of dicts with keys: resource, uri, strategy, foci_apps
    """
    # Normalize input
    blocked_key = blocked_resource.lower().strip()
    for key, uri in RESOURCE_AUDIENCES.items():
        if blocked_key == key or blocked_key == uri:
            blocked_key = key
            break

    # Define pivot strategies per blocked resource
    pivot_strategies: dict[str, list[dict]] = {
        "graph": [
            {
                "resource": "outlook",
                "uri": RESOURCE_AUDIENCES["outlook"],
                "strategy": "Access mailbox via EWS/REST instead of Graph Mail API",
                "foci_apps": ["27922004-5251-4030-b22d-91ecd9a37ea4", "d3590ed6-52b3-4102-aeff-aad2292ab01c"],
            },
            {
                "resource": "aad_graph",
                "uri": RESOURCE_AUDIENCES["aad_graph"],
                "strategy": "Use legacy AAD Graph API (deprecated but often still enabled)",
                "foci_apps": ["04b07795-8ddb-461a-bbee-02f9e1bf7b46", "1950a258-227b-4e31-a9cf-717495945fc2"],
            },
            {
                "resource": "substrate",
                "uri": RESOURCE_AUDIENCES["substrate"],
                "strategy": "Access data via Office Substrate (Copilot/Search backend)",
                "foci_apps": ["d3590ed6-52b3-4102-aeff-aad2292ab01c"],
            },
        ],
        "outlook": [
            {
                "resource": "graph",
                "uri": RESOURCE_AUDIENCES["graph"],
                "strategy": "Access mail via Graph /me/messages instead of EWS",
                "foci_apps": ["d3590ed6-52b3-4102-aeff-aad2292ab01c", "04b07795-8ddb-461a-bbee-02f9e1bf7b46"],
            },
        ],
        "management": [
            {
                "resource": "graph",
                "uri": RESOURCE_AUDIENCES["graph"],
                "strategy": "Enumerate Azure resources via Graph /me/ownedObjects instead of ARM",
                "foci_apps": ["04b07795-8ddb-461a-bbee-02f9e1bf7b46", "1950a258-227b-4e31-a9cf-717495945fc2"],
            },
            {
                "resource": "key_vault",
                "uri": RESOURCE_AUDIENCES["key_vault"],
                "strategy": "Try Key Vault audience directly (separate CA policy may apply)",
                "foci_apps": ["04b07795-8ddb-461a-bbee-02f9e1bf7b46"],
            },
        ],
        "sharepoint": [
            {
                "resource": "onedrive",
                "uri": RESOURCE_AUDIENCES["onedrive"],
                "strategy": "Access files via OneDrive personal site instead of team SharePoint",
                "foci_apps": ["ab9b8c07-8f02-4f72-87fa-80105867a763", "b26aadf8-566f-4478-926f-589f601d9c74"],
            },
            {
                "resource": "graph",
                "uri": RESOURCE_AUDIENCES["graph"],
                "strategy": "Access files via Graph /drives endpoint",
                "foci_apps": ["d3590ed6-52b3-4102-aeff-aad2292ab01c"],
            },
        ],
        "teams": [
            {
                "resource": "graph",
                "uri": RESOURCE_AUDIENCES["graph"],
                "strategy": "Access Teams data via Graph /teams endpoint instead of native API",
                "foci_apps": ["1fec8e78-bce4-4aaf-ab1b-5451cc387264", "d3590ed6-52b3-4102-aeff-aad2292ab01c"],
            },
        ],
    }

    alternatives = pivot_strategies.get(blocked_key, [])

    if not alternatives:
        # Generic fallback: suggest trying Graph and management with different FOCI apps
        alternatives = [
            {
                "resource": "graph",
                "uri": RESOURCE_AUDIENCES["graph"],
                "strategy": f"Try Graph API with a different FOCI app (blocked: {blocked_resource})",
                "foci_apps": ["04b07795-8ddb-461a-bbee-02f9e1bf7b46", "d3590ed6-52b3-4102-aeff-aad2292ab01c"],
            },
            {
                "resource": "management",
                "uri": RESOURCE_AUDIENCES["management"],
                "strategy": f"Try ARM with Azure CLI client ID (blocked: {blocked_resource})",
                "foci_apps": ["04b07795-8ddb-461a-bbee-02f9e1bf7b46"],
            },
        ]
        logger.info(f"No specific pivot for '{blocked_resource}', returning generic alternatives")

    # Enrich with app names
    foci_lookup = {app["client_id"]: app["name"] for app in FOCI_FAMILY}
    for alt in alternatives:
        alt["foci_app_details"] = [
            {"client_id": cid, "name": foci_lookup.get(cid, "Unknown")}
            for cid in alt.get("foci_apps", [])
        ]

    return alternatives


def build_evasion_profile(noise_level: str) -> dict:
    """
    Build a complete evasion profile based on the target noise level.
    Combines UA, timing, and FOCI recommendations.

    Args:
        noise_level: "silent", "low", "medium", "high", "loud"

    Returns:
        dict with recommended evasion settings
    """
    level_to_timing = {
        "silent": "stealth",
        "low": "stealth",
        "medium": "normal",
        "high": "human",
        "loud": "aggressive",
    }

    level_to_ua_contexts = {
        "silent": ["edge", "outlook"],  # blend with normal traffic
        "low": ["edge", "outlook", "onedrive"],
        "medium": ["edge", "teams", "outlook"],
        "high": ["azure_cli", "powershell"],  # speed over stealth
        "loud": ["azure_cli", "powershell"],
    }

    timing_profile = level_to_timing.get(noise_level, "normal")
    ua_contexts = level_to_ua_contexts.get(noise_level, ["edge"])

    return {
        "noise_level": noise_level,
        "timing": {
            "profile": timing_profile,
            **TIMING_PROFILES[timing_profile],
        },
        "user_agent": {
            "recommended_contexts": ua_contexts,
            "sample": get_user_agent(random.choice(ua_contexts)),
        },
        "foci": {
            "enabled": noise_level in ("silent", "low", "medium"),
            "note": "Use FOCI pivoting only at medium noise or below to avoid token refresh storms.",
            "family_size": len(FOCI_FAMILY),
        },
        "recommendations": _get_evasion_recommendations(noise_level),
    }


def _get_evasion_recommendations(noise_level: str) -> list[str]:
    """Return tactical evasion recommendations based on noise level."""
    base = [
        "Rotate user-agents between operations",
        "Use FOCI token refresh instead of new auth flows when possible",
    ]

    if noise_level in ("silent", "low"):
        return base + [
            "Use stealth timing (60-300s between operations)",
            "Prefer read-only operations",
            "Avoid bulk enumeration -- sample instead",
            "Use Edge UA to blend with normal browse traffic",
            "Route through residential proxies if available",
        ]
    elif noise_level == "medium":
        return base + [
            "Use normal timing (10-30s between operations)",
            "Limit write operations to essential targets only",
            "Avoid touching audit-sensitive resources (federation, CA policies)",
            "Spread operations across multiple sessions",
        ]
    elif noise_level == "high":
        return [
            "Speed is more important than stealth at this noise level",
            "Complete objectives quickly before SOC responds",
            "Use human-like timing (3-15s) to avoid automated blocks",
            "Rotate source IPs if possible",
            "Have cleanup plan ready before execution",
        ]
    else:  # loud
        return [
            "Assume detection is inevitable",
            "Execute fastest path to objective",
            "Aggressive timing (2-5s) acceptable",
            "Document everything for the report -- you will be caught",
            "Prepare cleanup checklist before starting",
        ]

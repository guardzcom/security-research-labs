========================================================================================================================
AADInternals v0.9.8 — COMPLETE CMDLET REFERENCE
Repository: https://github.com/Gerenios/AADInternals
Author: Dr Nestori Syynimaa (@DrAzureAD), Gerenios Ltd
DefaultCommandPrefix: AADInt (all cmdlets called as e.g. Get-AADIntAccessToken)
========================================================================================================================


────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Authentication & Tokens (52 exported, 33 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [AccessToken_utils.ps1] Add-AccessTokenToCache
      Params: $AccessToken, $RefreshToken, $ShowCache
    [AccessToken_utils.ps1] Clear-Cache
    [AccessToken.ps1] Get-AccessToken
      Params: $Credentials, $PRTToken, $SAMLToken, $Resource, $ClientId, $Tenant, $KerberosTicket, $Domain, $SaveToCache, $SaveToMgCache, $IncludeRefreshToken, $ForceMFA, $ForceNGCMFA, $UseDeviceCode, $UseIMDS, $MsiResId, $MsiClientId, $MsiObjectId, $BPRT, $Certificate, $PfxFileName, $PfxPassword, $TransportKeyFileName, $OTPSecretKey, $TAP, $RedirectUri, $ESTSAUTH, $SubScope, $UseMSAL, $RefreshToken, $SessionKey, $Settings, $CAE
    [AccessToken.ps1] Get-AccessTokenForAADGraph
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $Tenant, $SaveToCache, $Resource, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForAADIAMAPI
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $SaveToCache, $Tenant, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForAADJoin
      Params: $Credentials, $PRTToken, $SAMLToken, $Device, $KerberosTicket, $Domain, $UseDeviceCode, $BPRT, $UseMSAL, $Tenant, $SaveToCache, $ForceMFA, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForAccessPackages
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $Tenant, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForAdmin
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $Tenant, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForAzureCoreManagement
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $Tenant, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForCloudShell
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $Tenant, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForCompliance
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $Tenant, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForEXO
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $Resource, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForIntuneMDM
      Params: $Credentials, $ForceMFA, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $BPRT, $SaveToCache, $Certificate, $PfxFileName, $PfxPassword, $TransportKeyFileName, $Resource, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForMSCommerce
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $Tenant, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForMSGraph
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $Tenant, $SaveToCache, $SaveToMgCache, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForMSPartner
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $Tenant, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForMySignins
      Params: $Credentials, $SaveToCache, $KerberosTicket, $Domain, $UseMSAL, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForOfficeApps
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForOneDrive
      Params: $Tenant, $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForOneNote
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $Tenant, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForPTA
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForSARA
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForSPO
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $SaveToCache, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForTeams
      Params: $Credentials, $PRTToken, $SAMLToken, $KerberosTicket, $Domain, $UseDeviceCode, $UseMSAL, $SaveToCache, $Tenant, $Resource, $OTPSecretKey, $TAP, $RefreshToken, $SessionKey, $Settings, $CAE, $ESTSAUTH
    [AccessToken.ps1] Get-AccessTokenForWHfB
      Params: $PRTToken, $Credentials, $SaveToCache, $Tenant, $OTPSecretKey, $TAP
    [AccessToken.ps1] Get-AccessTokenFromCache
      Params: $AccessToken, $ClientID, $Resource, $IncludeRefreshToken, $Force, $SubScope
    [AccessToken.ps1] Get-AccessTokenUsingIMDS
      Params: $Resource, $ClientId, $ObjectId, $AzureResourceId, $ApiVersion
    [AccessToken.ps1] Get-AccessTokenWithRefreshToken
      Params: $Resource, $ClientId, $TenantId, $RefreshToken, $SaveToCache, $IncludeRefreshToken, $SubScope, $CAE
    [CBA.ps1] Get-AdminPortalAccessTokenUsingCBA
    [AccessToken.ps1] Get-AppConsentInfo
    [AccessToken_utils.ps1] Get-Cache
    [PRT.ps1] Get-DeviceRegAuthMethods
      Params: $AccessToken, $DeviceId, $ObjectId
    [PRT.ps1] Get-DeviceTransportKey
      Params: $AccessToken, $DeviceId, $ObjectId
    [AccessToken.ps1] Get-ESTSAUTHCookie
      Params: $ESTSAUTH, $Resource, $ClientId, $Tenant, $ForceMFA, $ForceNGCMFA, $RefreshTokenCredential, $Credentials, $OTPSecretKey, $TAP, $RedirectURI, $SubScope, $Persistent
    [AccessToken_utils.ps1] Get-EndpointInstances
    [AccessToken_utils.ps1] Get-EndpointIps
    [AccessToken_utils.ps1] Get-FOCIClientIDs
      Params: $Online
    [AccessToken_utils.ps1] Get-LoginInformation
      Params: $Domain, $UserName
    [AccessToken_utils.ps1] Get-OpenIDConfiguration
    [CBA.ps1] Get-PortalAccessTokenUsingCBA
    [AccessToken_utils.ps1] Get-TenantDomains
      Params: $Domain, $SubScope
    [PRT.ps1] Get-UserPRTKeys
      Params: $Certificate, $PfxFileName, $PfxPassword, $TransportKeyFileName, $WHfBKeyFileName, $UserName, $UseDeviceCertForWHfB, $UseRefreshToken, $SAMLToken, $Credentials, $OSVersion, $IncludePartialTGT
    [PRT.ps1] Join-DeviceToAzureAD
      Params: $PfxFileName, $PfxPassword, $SID, $TenantId, $DomainName, $DomainControllerName, $Certificate, $AccessToken, $JoinType, $DeviceName, $DeviceType, $OSVersion
    [PRT.ps1] New-BulkPRTToken
      Params: $AccessToken, $Expires, $Name, $PackageId, $Force
    [PRT.ps1] New-P2PDeviceCertificate
      Params: $Certificate, $PfxFileName, $PfxPassword, $RefreshToken, $SessionKey, $Context, $Settings, $TenantId, $DeviceName, $OSVersion, $DNSNames
    [PRT.ps1] New-UserPRTToken
      Params: $RefreshToken, $SessionKey, $Context, $Settings, $KdfV2, $SubScope
    [PRT.ps1] Remove-DeviceFromAzureAD
      Params: $Certificate, $PfxFileName, $PfxPassword, $Force
    [AccessToken.ps1] Remove-UserFromEstsAuthPersistentCookie
      Params: $ESTSCookie, $Cookie, $SessionID, $UserName, $ShowContent, $SubScope
    [PRT.ps1] Set-DeviceRegAuthMethods
      Params: $AccessToken, $DeviceId, $ObjectId, $Methods
    [PRT.ps1] Set-DeviceTransportKey
      Params: $AccessToken, $DeviceId, $ObjectId, $UseBuiltInCertificate, $Certificate, $PfxFileName, $PfxPassword, $JsonFileName
    [PRT.ps1] Set-DeviceWHfBKey
      Params: $AccessToken, $Certificate, $PfxFileName, $PfxPassword
    [AccessToken.ps1] Unprotect-EstsAuthPersistentCookie
      Params: $Cookie, $SubScope

  INTERNAL FUNCTIONS (not exported):
    [AccessToken_utils.ps1] Add-RefreshTokenToCache
    [AccessToken_utils.ps1] Create-AuthorizationHeader
    [AccessToken_utils.ps1] Get-APIKeys
    [AccessToken.ps1] Get-AccessTokenForEXOPS
    [AccessToken.ps1] Get-AccessTokenUsingAADGraph
    [AccessToken.ps1] Get-AccessTokenUsingDeviceCode
    [AccessToken_utils.ps1] Get-AccessTokenUsingMSAL
    [AccessToken.ps1] Get-AccessTokenWithDeviceSAML
    [AccessToken_utils.ps1] Get-AuthRedirectUrl
    [AccessToken_utils.ps1] Get-AuthorizationCode
    [AccessToken_utils.ps1] Get-CAEClaims
    [CBA.ps1] Get-Config
    [AccessToken_utils.ps1] Get-CredentialType
    [AccessToken.ps1] Get-IdentityTokenByLiveId
    [CBA.ps1] Get-LoginParametersUsingCBA
    [AccessToken_utils.ps1] Get-MSALAzureScope
    [AccessToken_utils.ps1] Get-OAuthInfoUsingSAML
    [AccessToken_utils.ps1] Get-RSTToken
    [AccessToken.ps1] Get-RefreshTokenFromCache
    [AccessToken_utils.ps1] Get-TenantID
    [AccessToken_utils.ps1] Get-TenantLoginUrl
    [AccessToken_utils.ps1] Get-TenantSubscope
    [AccessToken_utils.ps1] Get-UserNameFromAuthHeader
    [AccessToken_utils.ps1] Get-UserRealm
    [AccessToken_utils.ps1] Get-UserRealmExtended
    [AccessToken_utils.ps1] Get-UserRealmV2
    [AccessToken_utils.ps1] Is-AccessTokenExpired
    [AccessToken_utils.ps1] Is-AccessTokenValid
    [PRT.ps1] New-SignedPRTRequest
    [AccessToken_utils.ps1] Parse-LoginMicrosoftOnlineComConfig
    [AccessToken_utils.ps1] Process-ADFSLogin
    [AccessToken_utils.ps1] Process-Login
    [AccessToken_utils.ps1] Prompt-Credentials

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## ADFS & Federation (7 exported, 5 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [FederatedIdentityTools.ps1] ConvertTo-Backdoor
      Params: $AccessToken, $DomainName, $Force
    [FederatedIdentityTools.ps1] Find-Backdoor
      Params: $AccessToken
    [ADFS.ps1] New-ADFSRefreshToken
    [FederatedIdentityTools.ps1] New-SAML2Token
      Params: $UPN, $ImmutableID, $Issuer, $InResponseTo, $NotBefore, $NotAfter, $UseBuiltInCertificate, $Certificate, $PfxFileName, $PfxPassword
    [FederatedIdentityTools.ps1] New-SAMLToken
      Params: $UPN, $ImmutableID, $Issuer, $ByPassMFA, $DeviceGUID, $SID, $NotBefore, $NotAfter, $UseBuiltInCertificate, $Certificate, $PfxFileName, $PfxPassword
    [FederatedIdentityTools.ps1] Open-Office365Portal
      Params: $UPN, $ImmutableID, $ByPassMFA, $TokenType, $NotBefore, $NotAfter, $UseBuiltInCertificate, $Issuer, $Certificate, $PfxFileName, $PfxPassword, $Browser
    [ADFS.ps1] Unprotect-ADFSRefreshToken

  INTERNAL FUNCTIONS (not exported):
    [FederatedIdentityTools.ps1] Get-ADFSIssuer
    [ADFS.ps1] New-ADFSAccessToken
    [FederatedIdentityTools.ps1] New-Backdoor
    [FederatedIdentityTools.ps1] New-SAMLPResponse
    [FederatedIdentityTools.ps1] New-WSFedResponse

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Azure AD Connect (17 exported, 7 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [AzureADConnectAPI.ps1] Get-DesktopSSO
      Params: $AccessToken
    [AzureADConnectAPI.ps1] Get-KerberosDomainSyncConfig
      Params: $AccessToken, $Recursion
    [AzureADConnectAPI.ps1] Get-SyncConfiguration
    [AzureADConnectAPI.ps1] Get-SyncDeviceConfiguration
    [AzureADConnectAPI.ps1] Get-SyncFeatures
      Params: $AccessToken
    [AzureADConnectAPI.ps1] Get-SyncObjects
      Params: $AccessToken, $Recursion, $Version, $FullSync
    [AzureADConnectAPI.ps1] Get-WindowsCredentialsSyncConfig
      Params: $AccessToken, $Recursion
    [AzureADConnectAPI.ps1] Join-OnPremDeviceToAzureAD
      Params: $AccessToken, $DeviceName, $SID, $Certificate, $DeviceId
    [AzureADConnectAPI.ps1] Remove-AzureADObject
      Params: $AccessToken, $ObjectType, $Recursion
    [AzureADConnectAPI.ps1] Reset-ServiceAccount
      Params: $AccessToken, $ServiceAccount, $Recursion
    [AzureADConnectAPI.ps1] Set-AzureADGroupMember
      Params: $AccessToken, $CloudAnchor, $SourceAnchor, $GroupSourceAnchor, $GroupCloudAnchor, $Operation, $Recursion
    [AzureADConnectAPI.ps1] Set-AzureADObject
      Params: $AccessToken, $CloudAnchor, $SourceAnchor, $ObjectType, $Operation, $Recursion
    [AzureADConnectAPI.ps1] Set-DesktopSSO
      Params: $AccessToken, $ComputerName, $DomainName, $Enable, $Password
    [AzureADConnectAPI.ps1] Set-DesktopSSOEnabled
      Params: $AccessToken, $Enable
    [AzureADConnectAPI.ps1] Set-PassThroughAuthenticationEnabled
      Params: $AccessToken, $Enable
    [AzureADConnectAPI.ps1] Set-SyncFeatures
      Params: $AccessToken, $EnableFeatures, $DisableFeatures
    [AzureADConnectAPI.ps1] Set-UserPassword
      Params: $AccessToken, $CloudAnchor, $SourceAnchor, $UserPrincipalName, $Password, $Hash, $IncludeLegacy, $ChangeDate, $Recursion, $Iterations, $PfxFileName, $PfxPassword

  INTERNAL FUNCTIONS (not exported):
    [AzureADConnectAPI.ps1] Finalize-Export
    [AzureADConnectAPI.ps1] Get-KerberosDomain
    [AzureADConnectAPI.ps1] Get-MonitoringTenantCertificate
    [AzureADConnectAPI.ps1] Get-SyncCapabilities
    [AzureADConnectAPI.ps1] Get-SyncConfiguration2
    [AzureADConnectAPI.ps1] Set-PasswordHashSyncEnabled
    [AzureADConnectAPI.ps1] Update-SyncFeatures

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Graph API (AAD) (12 exported, 3 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [GraphAPI.ps1] Add-SyncFabricServicePrincipal
      Params: $AccessToken
    [GraphAPI.ps1] Get-AzureADFeature
      Params: $AccessToken, $Feature
    [GraphAPI.ps1] Get-AzureADFeatures
      Params: $AccessToken
    [GraphAPI.ps1] Get-AzureADPolicies
    [GraphAPI.ps1] Get-ConditionalAccessPolicies
    [GraphAPI.ps1] Get-Devices
      Params: $AccessToken
    [GraphAPI.ps1] Get-DynamicAbusableGroups
      Params: $AccessToken
    [GraphAPI.ps1] Get-ServicePrincipals
      Params: $AccessToken, $ClientIds
    [GraphAPI.ps1] Get-TenantDetails
      Params: $AccessToken
    [GraphAPI.ps1] Get-UserDetails
    [GraphAPI.ps1] Set-AzureADFeature
      Params: $AccessToken, $Feature, $Enabled
    [GraphAPI.ps1] Set-AzureADPolicyDetails

  INTERNAL FUNCTIONS (not exported):
    [GraphAPI.ps1] Get-AADUsers
    [GraphAPI.ps1] Get-OAuthGrants
    [GraphAPI.ps1] Get-Settings

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## MS Graph API (15 exported, 16 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [MSGraphAPI.ps1] Add-RolloutPolicyGroups
      Params: $AccessToken, $PolicyId, $GroupIds
    [MSGraphAPI.ps1] Disable-TenantMsolAccess
      Params: $AccessToken
    [MSGraphAPI.ps1] Enable-TenantMsolAccess
      Params: $AccessToken
    [MSGraphAPI.ps1] Get-AzureAuditLog
    [MSGraphAPI.ps1] Get-AzureSignInLog
      Params: $AccessToken, $EntryId, $Export
    [MSGraphAPI.ps1] Get-B2CEncryptionKeys
      Params: $AccessToken
    [MSGraphAPI.ps1] Get-RolloutPolicies
      Params: $AccessToken
    [MSGraphAPI.ps1] Get-RolloutPolicyGroups
      Params: $AccessToken, $PolicyId
    [MSGraphAPI.ps1] Get-TenantAuthPolicy
    [MSGraphAPI.ps1] Get-TenantDomain
      Params: $AccessToken, $TenantId
    [MSGraphAPI.ps1] Get-TenantGuestAccess
      Params: $AccessToken
    [MSGraphAPI.ps1] Remove-RolloutPolicy
      Params: $AccessToken, $PolicyId
    [MSGraphAPI.ps1] Remove-RolloutPolicyGroups
      Params: $AccessToken, $PolicyId, $GroupIds
    [MSGraphAPI.ps1] Set-RolloutPolicy
      Params: $AccessToken, $PolicyId, $Enable, $Policy, $EnableToOrganization
    [MSGraphAPI.ps1] Set-TenantGuestAccess
      Params: $AccessToken, $Level

  INTERNAL FUNCTIONS (not exported):
    [MSGraphAPI.ps1] Get-AADUsers
    [MSGraphAPI.ps1] Get-MSGraphDomains
    [MSGraphAPI.ps1] Get-MSGraphGroupMembers
    [MSGraphAPI.ps1] Get-MSGraphGroupOwners
    [MSGraphAPI.ps1] Get-MSGraphRoleMembers
    [MSGraphAPI.ps1] Get-MSGraphTeams
    [MSGraphAPI.ps1] Get-MSGraphTeamsApps
    [MSGraphAPI.ps1] Get-MSGraphUser
    [MSGraphAPI.ps1] Get-MSGraphUserAppRoleAssignments
    [MSGraphAPI.ps1] Get-MSGraphUserDirectReports
    [MSGraphAPI.ps1] Get-MSGraphUserLicenseDetails
    [MSGraphAPI.ps1] Get-MSGraphUserManager
    [MSGraphAPI.ps1] Get-MSGraphUserMemberOf
    [MSGraphAPI.ps1] Get-MSGraphUserOwnedDevices
    [MSGraphAPI.ps1] Get-MSGraphUserRegisteredDevices
    [MSGraphAPI.ps1] New-UserTAP

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Provisioning & Users (16 exported, 117 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [ProvisioningAPI.ps1] Get-CompanyInformation
      Params: $AccessToken, $TenantId
    [ProvisioningAPI.ps1] Get-CompanyTags
      Params: $AccessToken
    [ProvisioningAPI.ps1] Get-GlobalAdmins
      Params: $AccessToken
    [ProvisioningAPI.ps1] Get-MSPartnerContracts
      Params: $AccessToken, $PartnerContractSearchDefinition, $PageSize, $SearchString, $SortDirection, $SortField, $DomainName, $ManagedTenantId, $SearchKey
    [ProvisioningAPI.ps1] Get-SPOServiceInformation
      Params: $AccessToken
    [ProvisioningAPI.ps1] Get-ServiceLocations
      Params: $AccessToken
    [ProvisioningAPI.ps1] Get-ServicePlans
      Params: $AccessToken
    [ProvisioningAPI.ps1] Get-Subscriptions
      Params: $AccessToken, $ReturnValue
    [ProvisioningAPI.ps1] Get-User
      Params: $AccessToken, $ObjectId, $UserPrincipalName, $LiveID, $ReturnDeletedUsers
    [ProvisioningAPI.ps1] Get-Users
      Params: $AccessToken, $UserSearchDefinition, $PageSize, $SearchString, $SortDirection, $SortField, $AccountSku, $AdministrativeUnitObjectId, $BlackberryUsersOnly, $City, $Country, $Department, $DomainName, $EnabledFilter, $HasErrorsOnly, $IncludedProperties, $IndirectLicenseFilter, $LicenseReconciliationNeededOnly, $ReturnDeletedUsers, $State, $Synchronized, $Title, $UnlicensedUsersOnly, $UsageLocation
    [ProvisioningAPI.ps1] New-Domain
      Params: $AccessToken, $ForceTakeover, $Domain, $Authentication, $Capabilities, $IsDefault, $IsInitial, $Name, $RootDomain, $Status, $VerificationMethod
    [ProvisioningAPI.ps1] New-User
      Params: $AccessToken, $LicenseOptions, $AlternateEmailAddresses, $AlternateMobilePhones, $AlternativeSecurityIds, $BlockCredential, $City, $CloudExchangeRecipientDisplayType, $Country, $Department, $DirSyncProvisioningErrors, $DisplayName, $Errors, $Fax, $FirstName, $ImmutableId, $IndirectLicenseErrors, $IsBlackberryUser, $IsLicensed, $LastDirSyncTime, $LastName, $LastPasswordChangeTimestamp, $LicenseAssignmentDetails, $LicenseReconciliationNeeded, $Licenses, $LiveId, $MSExchRecipientTypeDetails, $MSRtcSipDeploymentLocator, $MSRtcSipPrimaryUserAddress, $MobilePhone, $OathTokenMetadata, $ObjectId, $Office, $OverallProvisioningStatus, $PasswordNeverExpires, $PasswordResetNotRequiredDuringActivate, $PhoneNumber, $PortalSettings, $PostalCode, $PreferredDataLocation, $PreferredLanguage, $ProxyAddresses, $ReleaseTrack, $ServiceInformation, $SignInName, $SoftDeletionTimestamp, $State, $StreetAddress, $StrongAuthenticationMethods, $StrongAuthenticationPhoneAppDetails, $StrongAuthenticationProofupTime, $StrongAuthenticationRequirements, $StrongAuthenticationUserDetails, $StrongPasswordRequired, $StsRefreshTokensValidFrom, $Title, $UsageLocation, $UserLandingPageIdentifierForO365Shell, $UserPrincipalName, $UserThemeIdentifierForO365Shell, $UserType, $ValidationStatus, $WhenCreated, $LicenseAssignment, $DisabledServicePlans, $Error, $ReferencedObjectId, $Status, $ForceChangePassword, $Password
    [ProvisioningAPI.ps1] Remove-User
      Params: $AccessToken, $ObjectId, $UserPrincipalName, $RemoveFromRecycleBin
    [ProvisioningAPI.ps1] Set-ADSyncEnabled
      Params: $AccessToken, $EnableDirSync
    [ProvisioningAPI.ps1] Set-DomainAuthentication
      Params: $AccessToken, $Authentication, $DomainName, $ActiveLogOnUri, $DefaultInteractiveAuthenticationMethod, $FederationBrandName, $IssuerUri, $LogOffUri, $MetadataExchangeUri, $NextSigningCertificate, $OpenIdConnectDiscoveryEndpoint, $PassiveLogOnUri, $PasswordChangeUri, $PasswordResetUri, $PreferredAuthenticationProtocol, $PromptLoginBehavior, $SigningCertificate, $SigningCertificateUpdateStatus, $SupportsMfa
    [ProvisioningAPI.ps1] Set-User
      Params: $AccessToken, $AlternateEmailAddresses, $AlternateMobilePhones, $AlternativeSecurityIds, $BlockCredential, $City, $CloudExchangeRecipientDisplayType, $Country, $Department, $DirSyncProvisioningErrors, $DisplayName, $Errors, $Fax, $FirstName, $ImmutableId, $IndirectLicenseErrors, $IsBlackberryUser, $IsLicensed, $LicenseAssignmentDetails, $LicenseReconciliationNeeded, $Licenses, $LiveId, $MSExchRecipientTypeDetails, $MSRtcSipDeploymentLocator, $MSRtcSipPrimaryUserAddress, $MobilePhone, $OathTokenMetadata, $ObjectId, $Office, $OverallProvisioningStatus, $PasswordNeverExpires, $PasswordResetNotRequiredDuringActivate, $PhoneNumber, $PortalSettings, $PostalCode, $PreferredDataLocation, $PreferredLanguage, $ProxyAddresses, $ReleaseTrack, $ServiceInformation, $SignInName, $SoftDeletionTimestamp, $State, $StreetAddress, $StrongAuthenticationMethods, $StrongAuthenticationPhoneAppDetails, $StrongAuthenticationProofupTime, $StrongAuthenticationRequirements, $StrongAuthenticationUserDetails, $StrongPasswordRequired, $StsRefreshTokensValidFrom, $Title, $UsageLocation, $UserLandingPageIdentifierForO365Shell, $UserPrincipalName, $UserThemeIdentifierForO365Shell, $UserType, $ValidationStatus

  INTERNAL FUNCTIONS (not exported):
    [ProvisioningAPI.ps1] Add-AdministrativeUnit
    [ProvisioningAPI.ps1] Add-AdministrativeUnitMembers
    [ProvisioningAPI.ps1] Add-ForeignGroupToRole
    [ProvisioningAPI.ps1] Add-Group
    [ProvisioningAPI.ps1] Add-GroupMembers
    [ProvisioningAPI.ps1] Add-RoleMembers
    [ProvisioningAPI.ps1] Add-RoleMembersByRoleName
    [ProvisioningAPI.ps1] Add-RoleScopedMembers
    [ProvisioningAPI.ps1] Add-ServicePrincipal
    [ProvisioningAPI.ps1] Add-ServicePrincipalCredentials
    [ProvisioningAPI.ps1] Add-ServicePrincipalCredentialsByAppPrincipalId
    [ProvisioningAPI.ps1] Add-ServicePrincipalCredentialsBySpn
    [ProvisioningAPI.ps1] Add-WellKnownGroup
    [ProvisioningAPI.ps1] Change-UserPrincipalName
    [ProvisioningAPI.ps1] Change-UserPrincipalNameByUpn
    [ProvisioningAPI.ps1] Convert-FederatedUserToManaged
    [ProvisioningAPI.ps1] Delete-ApplicationPassword
    [ProvisioningAPI.ps1] Get-AccidentalDeletionInformation
    [ProvisioningAPI.ps1] Get-AccountSkus
    [ProvisioningAPI.ps1] Get-AdministrativeUnit
    [ProvisioningAPI.ps1] Get-AdministrativeUnitMembers
    [ProvisioningAPI.ps1] Get-AdministrativeUnits
    [ProvisioningAPI.ps1] Get-CompanyAllowedDataLocation
    [ProvisioningAPI.ps1] Get-CompanyDirSyncFeatures
    [ProvisioningAPI.ps1] Get-Contact
    [ProvisioningAPI.ps1] Get-Contacts
    [ProvisioningAPI.ps1] Get-DirSyncProvisioningErrors
    [ProvisioningAPI.ps1] Get-Domain
    [ProvisioningAPI.ps1] Get-DomainFederationSettings
    [ProvisioningAPI.ps1] Get-DomainVerificationDns
    [ProvisioningAPI.ps1] Get-Domains
    [ProvisioningAPI.ps1] Get-Group
    [ProvisioningAPI.ps1] Get-GroupMembers
    [ProvisioningAPI.ps1] Get-Groups
    [ProvisioningAPI.ps1] Get-HeaderInfo
    [ProvisioningAPI.ps1] Get-PartnerInformation
    [ProvisioningAPI.ps1] Get-PasswordPolicy
    [ProvisioningAPI.ps1] Get-Role
    [ProvisioningAPI.ps1] Get-RoleByName
    [ProvisioningAPI.ps1] Get-RoleMembers
    [ProvisioningAPI.ps1] Get-RoleScopedMembers
    [ProvisioningAPI.ps1] Get-Roles
    [ProvisioningAPI.ps1] Get-RolesForUser
    [ProvisioningAPI.ps1] Get-RolesForUserByUpn
    [ProvisioningAPI.ps1] Get-ServicePrincipal
    [ProvisioningAPI.ps1] Get-ServicePrincipalByAppPrincipalId
    [ProvisioningAPI.ps1] Get-ServicePrincipalBySpn
    [ProvisioningAPI.ps1] Get-ServicePrincipalCredentials
    [ProvisioningAPI.ps1] Get-ServicePrincipalCredentialsByAppPrincipalId
    [ProvisioningAPI.ps1] Get-ServicePrincipalCredentialsBySpn
    [ProvisioningAPI.ps1] Get-ServicePrincipals2
    [ProvisioningAPI.ps1] Get-Subscription
    [ProvisioningAPI.ps1] Get-UserByLiveId
    [ProvisioningAPI.ps1] Get-UserByObjectId
    [ProvisioningAPI.ps1] Get-UserByUpn
    [ProvisioningAPI.ps1] Get-UsersByStrongAuthentication
    [ProvisioningAPI.ps1] Has-ObjectsWithDirSyncProvisioningErrors
    [ProvisioningAPI.ps1] Has-ObjectsWithDirSyncProvisioningErrors2
    [ProvisioningAPI.ps1] Msol-Connect
    [ProvisioningAPI.ps1] Navigate-AdministrativeUnitMemberResults
    [ProvisioningAPI.ps1] Navigate-AdministrativeUnitResults
    [ProvisioningAPI.ps1] Navigate-ContactResults
    [ProvisioningAPI.ps1] Navigate-DirSyncProvisioningErrors
    [ProvisioningAPI.ps1] Navigate-GroupMemberResults
    [ProvisioningAPI.ps1] Navigate-GroupResults
    [ProvisioningAPI.ps1] Navigate-PartnerContracts
    [ProvisioningAPI.ps1] Navigate-RoleMemberResults
    [ProvisioningAPI.ps1] Navigate-RoleScopedMemberResults
    [ProvisioningAPI.ps1] Navigate-ServicePrincipalResults
    [ProvisioningAPI.ps1] Navigate-UserResults
    [ProvisioningAPI.ps1] Remove-AdministrativeUnit
    [ProvisioningAPI.ps1] Remove-AdministrativeUnitMembers
    [ProvisioningAPI.ps1] Remove-Contact
    [ProvisioningAPI.ps1] Remove-Domain
    [ProvisioningAPI.ps1] Remove-ForeignGroupFromRole
    [ProvisioningAPI.ps1] Remove-Group
    [ProvisioningAPI.ps1] Remove-GroupMembers
    [ProvisioningAPI.ps1] Remove-RoleMembers
    [ProvisioningAPI.ps1] Remove-RoleMembersByRoleName
    [ProvisioningAPI.ps1] Remove-RoleScopedMembers
    [ProvisioningAPI.ps1] Remove-ServicePrincipal
    [ProvisioningAPI.ps1] Remove-ServicePrincipalByAppPrincipalId
    [ProvisioningAPI.ps1] Remove-ServicePrincipalBySpn
    [ProvisioningAPI.ps1] Remove-ServicePrincipalCredentials
    [ProvisioningAPI.ps1] Remove-ServicePrincipalCredentialsByAppPrincipalId
    [ProvisioningAPI.ps1] Remove-ServicePrincipalCredentialsBySpn
    [ProvisioningAPI.ps1] Remove-UserByObjectId
    [ProvisioningAPI.ps1] Remove-UserByUpn
    [ProvisioningAPI.ps1] Reset-StrongAuthenticationMethodByUpn
    [ProvisioningAPI.ps1] Reset-UserPassword
    [ProvisioningAPI.ps1] Reset-UserPasswordByUpn
    [ProvisioningAPI.ps1] Restore-User
    [ProvisioningAPI.ps1] Restore-UserByUpn
    [ProvisioningAPI.ps1] Retry-ContactProvisioning
    [ProvisioningAPI.ps1] Retry-GroupProvisioning
    [ProvisioningAPI.ps1] Retry-UserProvisioning
    [ProvisioningAPI.ps1] Set-AccidentalDeletionThreshold
    [ProvisioningAPI.ps1] Set-AdministrativeUnit
    [ProvisioningAPI.ps1] Set-CompanyAllowedDataLocation
    [ProvisioningAPI.ps1] Set-CompanyContactInformation
    [ProvisioningAPI.ps1] Set-CompanyDirSyncFeature
    [ProvisioningAPI.ps1] Set-CompanyMultiNationalEnabled
    [ProvisioningAPI.ps1] Set-CompanyPasswordSyncEnabled
    [ProvisioningAPI.ps1] Set-CompanySecurityComplianceContactInformation
    [ProvisioningAPI.ps1] Set-CompanySettings
    [ProvisioningAPI.ps1] Set-Domain
    [ProvisioningAPI.ps1] Set-DomainFederationSettings
    [ProvisioningAPI.ps1] Set-Group
    [ProvisioningAPI.ps1] Set-PartnerInformation
    [ProvisioningAPI.ps1] Set-PasswordPolicy
    [ProvisioningAPI.ps1] Set-ServicePrincipal
    [ProvisioningAPI.ps1] Set-UserLicenses
    [ProvisioningAPI.ps1] Set-UserLicensesByUpn
    [ProvisioningAPI.ps1] Update-DirSyncProvisioningError
    [ProvisioningAPI.ps1] Verify-Domain
    [ProvisioningAPI.ps1] Verify-Domain2
    [ProvisioningAPI.ps1] Verify-EmailVerifiedDomain

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Kill Chain & Recon (7 exported, 0 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [KillChain.ps1] Invoke-Phishing
    [KillChain.ps1] Invoke-ReconAsGuest
    [KillChain.ps1] Invoke-ReconAsInsider
    [KillChain.ps1] Invoke-ReconAsOutsider
      Params: $DomainName, $UserName, $Single, $GetRelayingParties
    [KillChain.ps1] Invoke-UserEnumerationAsGuest
      Params: $UserName, $Groups, $GroupMembers, $Subordinates, $Manager, $Roles, $GroupId
    [KillChain.ps1] Invoke-UserEnumerationAsInsider
    [KillChain.ps1] Invoke-UserEnumerationAsOutsider
      Params: $UserName, $External, $Domain, $Method

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Teams (14 exported, 5 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [Teams.ps1] Find-TeamsExternalUser
    [Teams.ps1] Get-MyTeams
      Params: $AccessToken, $Owner, $Channels
    [Teams.ps1] Get-SkypeToken
      Params: $AccessToken
    [Teams.ps1] Get-TeamsAvailability
    [Teams.ps1] Get-TeamsExternalUserInformation
    [Teams.ps1] Get-TeamsMessages
      Params: $AccessToken
    [Teams_utils.ps1] Get-TeamsUserSettings
      Params: $AccessToken
    [Teams.ps1] Get-Translation
      Params: $AccessToken, $Text, $Language
    [Teams.ps1] Remove-TeamsMessages
      Params: $AccessToken, $MessageIDs, $DeleteType
    [Teams.ps1] Search-TeamsUser
      Params: $AccessToken, $SearchString
    [Teams.ps1] Send-TeamsMessage
      Params: $AccessToken, $Recipients, $Message, $Html, $ClientMessageId, $Thread, $External, $FakeInternal
    [Teams.ps1] Set-TeamsAvailability
      Params: $AccessToken, $Status
    [Teams.ps1] Set-TeamsMessageEmotion
      Params: $AccessToken, $MessageID, $ConversationID, $TeamsSettings, $Emotion, $Clear
    [Teams.ps1] Set-TeamsStatusMessage
      Params: $AccessToken, $Message, $Expires

  INTERNAL FUNCTIONS (not exported):
    [Teams.ps1] Add-TeamsMember
    [Teams.ps1] Get-TeamsMemberships
    [Teams.ps1] Get-TeamsMessage
    [Teams_utils.ps1] Get-TeamsRecipients
    [Teams.ps1] Remove-TeamsMember

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Exchange / ActiveSync / Outlook (8 exported, 6 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [ActiveSync.ps1] Add-EASDevice
      Params: $Credentials, $AccessToken, $DeviceId, $DeviceType, $Model, $IMEI, $FriendlyName, $OS, $OSLanguage, $PhoneNumber, $MobileOperator, $UserAgent
    [ActiveSync.ps1] Get-EASAutoDiscover
      Params: $Email, $Protocol
    [ActiveSync.ps1] Get-EASAutoDiscoverV1
      Params: $Credentials, $AccessToken
    [ActiveSync.ps1] Get-EASOptions
      Params: $Credentials, $AccessToken
    [OutlookAPI.ps1] Open-OWA
      Params: $AccessToken, $Mode
    [ActiveSync.ps1] Send-EASMessage
      Params: $Cred, $At, $Credentials, $AccessToken, $Recipient, $Subject, $Message, $DeviceId, $DeviceType, $DeviceOS
    [OutlookAPI.ps1] Send-OutlookMessage
      Params: $At, $AccessToken, $Recipient, $Subject, $Message, $SaveToSentItems
    [ActiveSync.ps1] Set-EASSettings
      Params: $Credentials, $AccessToken, $DeviceId, $DeviceType, $Model, $IMEI, $FriendlyName, $OS, $OSLanguage, $PhoneNumber, $MobileOperator, $UserAgent

  INTERNAL FUNCTIONS (not exported):
    [ActiveSync.ps1] Get-EASFolderSync
    [ActiveSync.ps1] Get-EASMails
    [ActiveSync.ps1] Get-EASSettings
    [ActiveSync.ps1] Get-EASSyncStatus
    [ActiveSync.ps1] Get-MobileOutlookSettings
    [OutlookAPI.ps1] Get-OutlookActivities

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## SharePoint Online (7 exported, 6 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [SPMT.ps1] Add-SPOSiteFiles
      Params: $Site, $FolderName, $Files, $UserName, $TimeCreated, $TimeLastModified
    [SPO.ps1] Export-SPOSiteFile
      Params: $Site, $RelativePath, $AuthHeader, $AccessToken
    [SPO.ps1] Get-SPOSiteGroups
      Params: $Site, $AccessToken
    [SPO.ps1] Get-SPOSiteUsers
      Params: $Site, $AccessToken
    [SPO.ps1] Get-SPOUserProperties
      Params: $Site, $UserName, $AccessToken
    [SPO.ps1] Set-SPOSiteMembers
      Params: $Site, $AuthHeader, $SiteName, $UserPrincipalName
    [SPMT.ps1] Update-SPOSiteFile
      Params: $Site, $File, $Id, $RelativePath, $UserName, $TimeCreated, $TimeLastModified

  INTERNAL FUNCTIONS (not exported):
    [SPO.ps1] Get-SPOSettings
    [SPO.ps1] Get-SPOSiteFile
    [SPO.ps1] Get-SPOSiteFolder
    [SPO.ps1] Get-SPOSiteUserProperties
    [SPO.ps1] Get-SPOWebId
    [SPO.ps1] Set-SPOSiteUserProperty

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## OneDrive (2 exported, 6 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [OneDrive.ps1] Get-OneDriveFiles
      Params: $OneDriveSettings, $MaxItems, $DomainGuid, $Mac, $PrintOnly, $FoldersOnly
    [OneDrive.ps1] Send-OneDriveFile

  INTERNAL FUNCTIONS (not exported):
    [OneDrive.ps1] Get-ODDefaultDocLibId
    [OneDrive.ps1] Get-ODDefaultSiteId
    [OneDrive.ps1] Get-ODDocument
    [OneDrive.ps1] Get-ODFolder
    [OneDrive.ps1] Get-ODSyncFiles
    [OneDrive.ps1] Get-ODSyncPolicy

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Azure Core Management (14 exported, 2 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [AzureCoreManagement.ps1] Get-AzureClassicAdministrators
      Params: $AccessToken, $Subscription
    [AzureCoreManagement.ps1] Get-AzureDiagnosticSettings
      Params: $AccessToken
    [AzureCoreManagement.ps1] Get-AzureDiagnosticSettingsDetails
      Params: $AccessToken, $Name
    [AzureCoreManagement.ps1] Get-AzureDirectoryActivityLog
    [AzureCoreManagement.ps1] Get-AzureResourceGroups
      Params: $AccessToken, $SubscriptionId
    [AzureCoreManagement.ps1] Get-AzureSubscriptions
      Params: $AccessToken
    [AzureCoreManagement.ps1] Get-AzureTenants
    [AzureCoreManagement.ps1] Get-AzureVMRdpSettings
      Params: $AccessToken, $SubscriptionId, $ResourceGroup, $Server
    [AzureCoreManagement.ps1] Get-AzureVMs
      Params: $AccessToken, $SubscriptionId
    [AzureCoreManagement.ps1] Grant-AzureUserAccessAdminRole
      Params: $AccessToken
    [AzureCoreManagement.ps1] Invoke-AzureVMScript
      Params: $AccessToken, $SubscriptionId, $ResourceGroup, $Server, $Script, $VMType
    [AzureCoreManagement.ps1] Remove-AzureDiagnosticSettings
      Params: $AccessToken, $Force
    [AzureCoreManagement.ps1] Set-AzureDiagnosticSettingsDetails
      Params: $AccessToken, $Logs, $Name, $Enabled, $RetentionEnabled, $RetentionDays
    [AzureCoreManagement.ps1] Set-AzureRoleAssignment
      Params: $AccessToken, $SubscriptionId, $UserName, $RoleName

  INTERNAL FUNCTIONS (not exported):
    [AzureCoreManagement.ps1] Get-AzureRoleAssignmentId
    [AzureCoreManagement.ps1] Invoke-AzureQuery

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Azure Management API (5 exported, 17 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [AzureManagementAPI.ps1] Get-AADConnectStatus
      Params: $AccessToken
    [AzureManagementAPI_utils.ps1] Get-AccessTokenForAzureMgmtAPI
      Params: $Credentials, $SaveToCache
    [AzureManagementAPI.ps1] Get-AzureInformation
    [AzureManagementAPI.ps1] New-GuestInvitation
    [AzureManagementAPI.ps1] New-MOERADomain
      Params: $AccessToken, $Domain

  INTERNAL FUNCTIONS (not exported):
    [AzureManagementAPI_utils.ps1] Call-AzureAADIAMAPI
    [AzureManagementAPI_utils.ps1] Call-AzureManagementAPI
    [AzureManagementAPI_utils.ps1] Create-WebSession
    [AzureManagementAPI_utils.ps1] Create-WebSession2
    [AzureManagementAPI_utils.ps1] Get-AccessTokenForAADIAMAPI2
    [AzureManagementAPI.ps1] Get-AzureActivityLog
    [AzureManagementAPI.ps1] Get-AzureManagementUsers
    [AzureManagementAPI_utils.ps1] Get-DelegationToken
    [AzureManagementAPI.ps1] Get-TenantApplications
    [AzureManagementAPI.ps1] Get-TenantAuthenticationMethods
    [AzureManagementAPI.ps1] Get-UserTenants
    [AzureManagementAPI.ps1] Is-ExternalUserUnique
    [AzureManagementAPI.ps1] New-AzureManagementUser
    [AzureManagementAPI_utils.ps1] Prompt-AzureADCredentials
    [AzureManagementAPI.ps1] Remove-AzureManagementUser
    [AzureManagementAPI.ps1] Remove-AzureManagementUsers
    [AzureManagementAPI.ps1] Set-AzureManagementAdminRole

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## MDM / Intune (4 exported, 1 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [MDM.ps1] Get-DeviceCompliance
      Params: $AccessToken, $DeviceId, $ObjectId, $All, $My
    [MDM.ps1] Join-DeviceToIntune
      Params: $AccessToken, $DeviceName, $ZtdCorrelationId
    [MDM.ps1] Set-DeviceCompliant
      Params: $AccessToken, $DeviceId, $ObjectId, $Compliant, $Managed, $Intune
    [MDM.ps1] Start-DeviceIntuneCallback
      Params: $Certificate, $PfxFileName, $PfxPassword, $DeviceName, $Scope, $SessionId

  INTERNAL FUNCTIONS (not exported):
    [MDM.ps1] Remove-DeviceFromIntune

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## MFA (7 exported, 1 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [MFA.ps1] Get-UserMFA
      Params: $AccessToken, $UserPrincipalName
    [MFA.ps1] Get-UserMFAApps
      Params: $AccessToken, $UserPrincipalName
    [MFA.ps1] New-OTP
      Params: $SecretKey, $Clipboard
    [MFA.ps1] New-OTPSecret
      Params: $Clipboard
    [MFA.ps1] Register-MFAApp
      Params: $AccessToken, $DeviceToken, $DeviceName, $Type
    [MFA.ps1] Set-UserMFA
      Params: $AccessToken, $UserPrincipalName, $State, $DefaultMethod, $StartTime, $PhoneNumber, $AlternativePhoneNumber, $Email
    [MFA.ps1] Set-UserMFAApps
      Params: $AccessToken, $UserPrincipalName, $Id, $AuthenticationType, $DeviceName, $DeviceTag, $DeviceToken, $NotificationType, $OathTokenTimeDrift, $OathSecretKey, $PhoneAppVersion, $TimeInterval

  INTERNAL FUNCTIONS (not exported):
    [MFA.ps1] Get-UserMFA2

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Kerberos (0 exported, 5 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  INTERNAL FUNCTIONS (not exported):
    [Kerberos.ps1] Get-Authenticator
    [Kerberos.ps1] Get-PAC
    [Kerberos.ps1] Get-SessionKeyFromPAC
    [Kerberos.ps1] Parse-Authenticator
    [Kerberos.ps1] Parse-PAC

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## PTA (Pass-Through Auth) (1 exported, 0 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [PTA.ps1] Register-PTAAgent
      Params: $AccessToken, $MachineName, $FileName, $UpdateTrust, $Bootstrap, $PfxFileName, $PfxPassword

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## MS App Proxy (3 exported, 3 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [MSAppProxy.ps1] Export-ProxyAgentBootstraps
      Params: $Certificates
    [MSAppProxy.ps1] Get-ProxyAgentGroups
      Params: $AccessToken
    [MSAppProxy.ps1] Get-ProxyAgents

  INTERNAL FUNCTIONS (not exported):
    [MSAppProxy.ps1] Add-ProxyAgentToGroup
    [MSAppProxy.ps1] New-ProxyAgentGroup
    [MSAppProxy.ps1] Register-ProxyAgent

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Hybrid Health Services (10 exported, 5 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [HybridHealthServices.ps1] Get-HybridHealthServiceMembers
      Params: $AccessToken, $ServiceName
    [HybridHealthServices.ps1] Get-HybridHealthServiceMonitoringPolicies
    [HybridHealthServices.ps1] Get-HybridHealthServices
      Params: $AccessToken, $Service
    [HybridHealthServices_utils.ps1] New-HybridHealtServiceEvent
      Params: $MFAAuthenticationType, $UniqueID, $Server, $EventType, $PrimaryAuthentication, $RequiredAuthType, $RelyingParty, $RelyingPartyName, $Result, $DeviceAuthentication, $URL, $User, $UserId, $UserIdType, $UPN, $Timestamp, $Protocol, $NetworkLocationType, $AppTokenFailureType, $IPAddress, $ClaimsProvider, $OAuthClientID, $OAuthTokenRetrievalMethod, $MFA, $MFAProviderErrorCode, $ProxyServer, $Endpoint, $UserAgent, $DeviceID, $ErrorHitCount, $X509CertificateType, $ActivityId, $ActivityIdAutoGenerated, $PrimarySid, $ImmutableId
    [HybridHealthServices.ps1] New-HybridHealthService
      Params: $AccessToken, $Type, $DisplayName, $Signature
    [HybridHealthServices.ps1] New-HybridHealthServiceMember
      Params: $AccessToken, $ServiceName, $MachineId, $MachineName, $MachineRole
    [HybridHealthServices.ps1] Register-HybridHealthServiceAgent
      Params: $AccessToken, $ServiceName, $MachineName, $MachineRole, $Status
    [HybridHealthServices.ps1] Remove-HybridHealthService
      Params: $AccessToken, $ServiceName
    [HybridHealthServices.ps1] Remove-HybridHealthServiceMember
      Params: $AccessToken, $ServiceName, $ServiceMemberId
    [HybridHealthServices.ps1] Send-HybridHealthServiceEvents
      Params: $AgentKey, $MachineId, $TenantId, $ServiceId, $Events, $AgentInfo

  INTERNAL FUNCTIONS (not exported):
    [HybridHealthServices_utils.ps1] Get-HybridHealthServiceAccessToken
    [HybridHealthServices_utils.ps1] Get-HybridHealthServiceBlobUploadKey
    [HybridHealthServices_utils.ps1] Get-HybridHealthServiceEventHubPublisherKey
    [HybridHealthServices_utils.ps1] Get-HybridHealthServiceMemberCredentials
    [HybridHealthServices_utils.ps1] Send-ADFSServiceBusMessage

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Compliance API (1 exported, 0 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [ComplianceAPI.ps1] Search-UnifiedAuditLog
      Params: $AccessToken, $Start, $End, $All, $IpAddresses, $Target, $Operations, $Users

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## MS Commerce (2 exported, 0 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [MSCommerce.ps1] Get-SelfServicePurchaseProducts
      Params: $AccessToken
    [MSCommerce.ps1] Set-SelfServicePurchaseProduct
      Params: $AccessToken, $Id, $Enabled

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## MS Partner (4 exported, 4 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [MSPartner.ps1] Find-MSPartners
    [MSPartner.ps1] Get-MSPartnerOrganizations
    [MSPartner.ps1] Get-MSPartnerRoleMembers
    [MSPartner.ps1] New-MSPartnerDelegatedAdminRequest
      Params: $TenantId, $Domain

  INTERNAL FUNCTIONS (not exported):
    [MSPartner.ps1] Get-MSPartnerOffers
    [MSPartner.ps1] Get-MSPartnerPublishers
    [MSPartner.ps1] Get-MSPartnerRoles
    [MSPartner.ps1] New-MSPartnerTrialOffer

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Admin API (5 exported, 0 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [AdminAPI.ps1] Approve-MSPartnerDelegatedAdminRequest
      Params: $TenantId, $Domain, $AccessToken
    [AdminAPI.ps1] Get-AccessTokenUsingAdminAPI
      Params: $TokenType, $Resource, $AccessToken, $WebSession, $SaveToCache
    [AdminAPI.ps1] Get-MSPartners
      Params: $AccessToken
    [AdminAPI.ps1] Get-TenantOrganisationInformation
      Params: $AccessToken, $Domain, $TenantId
    [AdminAPI.ps1] Remove-MSPartnerDelegatedAdminRoles
      Params: $TenantId, $Domain, $AccessToken

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## SARA (Support & Recovery) (4 exported, 1 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [SARA.ps1] Get-SARATenantInfo
      Params: $AccessToken, $UserName, $Tests
    [SARA.ps1] Get-SARAUserInfo
      Params: $AccessToken, $UserName, $ExecutionEnvironment
    [SARA.ps1] Resolve-SARAHost
      Params: $AccessToken, $Host
    [SARA.ps1] Test-SARAPort
      Params: $AccessToken, $Host, $Port

  INTERNAL FUNCTIONS (not exported):
    [SARA.ps1] Get-SARAFreeBusyInformation

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Cloud Shell (1 exported, 0 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [CloudShell.ps1] Start-CloudShell
      Params: $AccessToken, $Shell, $SubscriptionId, $ResourceGroup, $StorageAccount, $FileShareName

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Configuration & Utils (11 exported, 37 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [CommonUtils.ps1] Convert-ObjectIDtoSID
      Params: $ObjectID
    [CommonUtils.ps1] Convert-SIDtoObjectID
      Params: $SID
    [Configuration.ps1] Get-Configuration
    [CommonUtils.ps1] Get-Configuration
    [Configuration.ps1] Read-Configuration
    [CommonUtils.ps1] Read-Configuration
    [Configuration.ps1] Save-Configuration
    [CommonUtils.ps1] Save-Configuration
    [Configuration.ps1] Set-Setting
      Params: $Setting, $Value
    [CommonUtils.ps1] Set-Setting
      Params: $Setting, $Value
    [CommonUtils.ps1] Set-UserAgent
      Params: $Device

  INTERNAL FUNCTIONS (not exported):
    [CommonUtils.ps1] Check-ContinuationBit
    [CommonUtils.ps1] Convert-BytesToOid
    [CommonUtils.ps1] Convert-OidToBytes
    [CommonUtils.ps1] Decode-MultiByteInteger
    [CommonUtils.ps1] Encode-Asn1
    [CommonUtils.ps1] Encode-MultiByteInteger
    [CommonUtils.ps1] Get-BinaryContent
    [CommonUtils.ps1] Get-CompressedByteArray
    [CommonUtils.ps1] Get-DeDeflatedByteArray
    [CommonUtils.ps1] Get-DecompressedByteArray
    [CommonUtils.ps1] Get-DeflatedByteArray
    [CommonUtils.ps1] Get-Digest
    [CommonUtils.ps1] Get-MD4
    [CommonUtils.ps1] Get-OidRawValue
    [CommonUtils.ps1] Get-RC4
    [CommonUtils.ps1] Get-RandomBytes
    [Configuration.ps1] Get-Setting
    [CommonUtils.ps1] Get-Setting
    [CommonUtils.ps1] Get-StringBetween
    [CommonUtils.ps1] Get-Thumbprint
    [CommonUtils.ps1] Get-UserAgent
    [CommonUtils.ps1] Get-XmlDictionary
    [CommonUtils.ps1] Load-Certificate
    [CommonUtils.ps1] Load-PrivateKey
    [CommonUtils.ps1] New-Certificate
    [CommonUtils.ps1] New-JWT
    [CommonUtils.ps1] New-RandomIPv4
    [CommonUtils.ps1] New-RandomSID
    [CommonUtils.ps1] Parse-Asn1
    [CommonUtils.ps1] Parse-CertificateOIDs
    [CommonUtils.ps1] Read-Accesstoken
    [CommonUtils.ps1] Remove-BOM
    [CommonUtils.ps1] Remove-Bytes
    [CommonUtils.ps1] Set-BinaryContent
    [CommonUtils.ps1] Sign-JWT
    [CommonUtils.ps1] Split-String
    [CommonUtils.ps1] Unload-PrivateKey

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## DCaaS (1 exported, 0 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [DCaaS.ps1] Get-UserNTHash
      Params: $ClientPfxFileName, $ClientPassword, $ClientPfxPassword, $PfxFileName, $PfxPassword, $TenantId, $ClientId, $UserPrincipalName, $UseBuiltInCertificate

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Access Packages (3 exported, 0 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [AccessPackages.ps1] Get-AccessPackageAdmins
      Params: $AccessToken
    [AccessPackages.ps1] Get-AccessPackageCatalogs
      Params: $AccessToken
    [AccessPackages.ps1] Get-AccessPackages
      Params: $AccessToken

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## OneNote (1 exported, 0 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [OneNote.ps1] Start-Speech
      Params: $AccessToken, $Text, $Language, $PreferredVoice

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Office Apps (0 exported, 3 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  INTERNAL FUNCTIONS (not exported):
    [OfficeApps.ps1] Get-RecentLocations
    [OfficeApps.ps1] Get-SharedWithUser
    [OfficeApps.ps1] Get-UserConnections

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
## Sync Agent (1 exported, 0 internal)
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

  EXPORTED FUNCTIONS:
    [SyncAgent.ps1] Register-SyncAgent
      Params: $AccessToken, $MachineName, $FileName, $UpdateTrust, $PfxFileName, $PfxPassword

========================================================================================================================
TOTALS: 235 exported functions, 283 internal functions, 518 total
Exported count from .psd1 manifest: 244
========================================================================================================================

EXPORTED BUT NOT FOUND IN PARSED SOURCE (may be in _utils files or dynamic):
  - Get-AccessTokenForSPOMigrationTool
  - Get-ComplianceAPICookies
  - Get-Error
  - Get-ImmutableID
  - Get-MobileDevices
  - Get-TenantId
  - Get-UnifiedAuditLogSettings
  - New-B2CAuthorizationCode
  - New-B2CRefreshToken
  - New-KerberosTicket
  - New-OneDriveSettings
  - Read-AccessToken
  - Set-UnifiedAuditLogSettings

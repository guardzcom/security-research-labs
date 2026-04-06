# Full Password + MFA Status Check for a Specific User in Entra ID
# Checks: password profile flags, MFA registration, enrolled auth methods
#
# Required scopes: User.Read.All, UserAuthenticationMethod.Read.All, AuditLog.Read.All
# Usage: Change "kevin@domain.com" to the target UPN

Connect-MgGraph -Scopes "User.Read.All","UserAuthenticationMethod.Read.All","AuditLog.Read.All" -NoWelcome

$targetUPN = "kevin@domain.com"

# Check password profile
$user = Get-MgUser -UserId $targetUPN -Property `
    displayName, userPrincipalName, accountEnabled, `
    passwordProfile, onPremisesSyncEnabled, `
    onPremisesImmutableId, lastPasswordChangeDateTime

Write-Host "=== Password Status ==="
Write-Host "  forceChangePasswordNextSignIn:        $($user.PasswordProfile.ForceChangePasswordNextSignIn)"
Write-Host "  forceChangePasswordNextSignInWithMfa:  $($user.PasswordProfile.ForceChangePasswordNextSignInWithMfa)"
Write-Host "  lastPasswordChangeDateTime:            $($user.LastPasswordChangeDateTime)"
Write-Host "  onPremisesSyncEnabled:                 $($user.OnPremisesSyncEnabled)"

# Check MFA registration
$mfa = Get-MgReportAuthenticationMethodUserRegistrationDetail `
  -Filter "userPrincipalName eq '$targetUPN'"

Write-Host "`n=== MFA Status ==="
Write-Host "  isMfaRegistered:      $($mfa.IsMfaRegistered)"
Write-Host "  isMfaCapable:         $($mfa.IsMfaCapable)"
Write-Host "  methodsRegistered:    $($mfa.MethodsRegistered -join ', ')"
Write-Host "  defaultMfaMethod:     $($mfa.DefaultMfaMethod)"

# List actual auth methods
$methods = Get-MgUserAuthenticationMethod -UserId $targetUPN
Write-Host "`n=== Registered Auth Methods ==="
foreach ($m in $methods) {
    Write-Host "  $($m.AdditionalProperties['@odata.type']) - ID: $($m.Id)"
}

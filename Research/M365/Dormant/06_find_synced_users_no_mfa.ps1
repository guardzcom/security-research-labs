# Find Synced Users Without MFA — Full Entra + AD Cross-Check
# Combines Entra MFA registration report with on-prem sync status
# Every user in the output is a synced identity with password but no MFA
#
# Required scopes: User.Read.All, UserAuthenticationMethod.Read.All, AuditLog.Read.All

Connect-MgGraph -Scopes "User.Read.All","UserAuthenticationMethod.Read.All","AuditLog.Read.All" -NoWelcome

$noMfa = Get-MgReportAuthenticationMethodUserRegistrationDetail -Filter "isMfaRegistered eq false" |
  Where-Object { $_.UserType -eq 'member' }

foreach ($user in $noMfa) {
    $entraUser = Get-MgUser -UserId $user.UserPrincipalName `
      -Property "onPremisesSyncEnabled,onPremisesImmutableId,onPremisesSamAccountName"

    if ($entraUser.OnPremisesSyncEnabled -eq $true) {
        [PSCustomObject]@{
            UPN              = $user.UserPrincipalName
            DisplayName      = $user.UserDisplayName
            MfaRegistered    = $user.IsMfaRegistered
            MfaCapable       = $user.IsMfaCapable
            MethodsRegistered = ($user.MethodsRegistered -join ', ')
            SyncEnabled      = $entraUser.OnPremisesSyncEnabled
            ImmutableId      = $entraUser.OnPremisesImmutableId
            OnPremSAM        = $entraUser.OnPremisesSamAccountName
        }
    }
}

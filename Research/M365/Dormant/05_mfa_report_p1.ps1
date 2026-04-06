# MFA Registration Report — Requires Entra ID P1 License
# Uses the pre-computed userRegistrationDetails report (faster for large tenants)
# Note: Report may take up to 24 hours to populate after P1 license activation
#
# Required scopes: AuditLog.Read.All, UserAuthenticationMethod.Read.All

Connect-MgGraph -Scopes "AuditLog.Read.All","UserAuthenticationMethod.Read.All" -NoWelcome

Get-MgReportAuthenticationMethodUserRegistrationDetail -Filter "isMfaRegistered eq false" |
  Where-Object { $_.UserType -eq 'member' } |
  Select-Object UserPrincipalName, UserDisplayName, IsMfaRegistered, IsMfaCapable,
                IsPasswordlessCapable, MethodsRegistered, DefaultMfaMethod |
  Export-Csv -Path "users_no_mfa.csv" -NoTypeInformation

Write-Host "Exported to: users_no_mfa.csv"

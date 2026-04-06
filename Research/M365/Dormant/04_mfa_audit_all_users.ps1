# MFA Audit — Check All Entra ID Users for MFA Registration
# Works on all license tiers (queries each user individually)
# Outputs: table + CSV export
#
# Required scopes: User.Read.All, UserAuthenticationMethod.Read.All

Connect-MgGraph -Scopes "User.Read.All","UserAuthenticationMethod.Read.All" -NoWelcome
$users = Get-MgUser -All -Property DisplayName, UserPrincipalName, Id, OnPremisesSyncEnabled, AccountEnabled

$results = foreach ($user in $users) {
    $methods = Get-MgUserAuthenticationMethod -UserId $user.Id
    $types = $methods | ForEach-Object { $_.AdditionalProperties["@odata.type"] }
    $nonPwd = $types | Where-Object { $_ -ne "#microsoft.graph.passwordAuthenticationMethod" }
    $hasMfa = $nonPwd.Count -gt 0
    $methodStr = ($types -replace "#microsoft.graph.", "" -replace "AuthenticationMethod", "") -join ", "

    [PSCustomObject]@{
        UPN     = $user.UserPrincipalName
        Name    = $user.DisplayName
        Synced  = if ($user.OnPremisesSyncEnabled) { "Yes" } else { "No" }
        Enabled = $user.AccountEnabled
        HasMFA  = $hasMfa
        Methods = $methodStr
    }
}

$results | Format-Table -AutoSize
Write-Host "`nTotal: $($results.Count) | MFA: $(($results | Where-Object HasMFA -eq $true).Count) | No MFA: $(($results | Where-Object HasMFA -eq $false).Count)"
$results | Export-Csv -Path "mfa_audit.csv" -NoTypeInformation
Write-Host "Exported to: mfa_audit.csv"

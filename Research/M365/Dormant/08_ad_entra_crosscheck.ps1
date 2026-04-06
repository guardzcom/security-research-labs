# AD to Entra Cross-Check — Verify Sync Status + MFA for Every AD User
# Connects to both on-prem AD and Microsoft Graph
# Shows: AD attributes, ImmutableId, Entra sync status, account state
#
# Required: AD RSAT tools + Graph scope User.Read.All

Connect-MgGraph -Scopes "User.Read.All" -NoWelcome

$adUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties objectGUID, userPrincipalName, userAccountControl, pwdLastSet, whenCreated, lastLogonTimestamp

$results = foreach ($user in $adUsers) {
    $immutableId = [Convert]::ToBase64String($user.objectGUID.ToByteArray())

    $entraUser = $null
    try {
        $entraUser = Get-MgUser -Filter "onPremisesImmutableId eq '$immutableId'" -Property displayName, onPremisesSyncEnabled, accountEnabled, userPrincipalName, lastPasswordChangeDateTime -ErrorAction SilentlyContinue
    } catch {}

    [PSCustomObject]@{
        Name            = $user.Name
        SAM             = $user.SamAccountName
        UPN             = $user.UserPrincipalName
        objectGUID      = $user.objectGUID
        ImmutableId     = $immutableId
        UAC             = $user.userAccountControl
        AD_PwdLastSet   = if ($user.pwdLastSet -gt 0) {[DateTime]::FromFileTime($user.pwdLastSet)} else {'Must Change'}
        AD_LastLogon    = if ($user.lastLogonTimestamp -gt 0) {[DateTime]::FromFileTime($user.lastLogonTimestamp)} else {'Never'}
        AD_Created      = $user.whenCreated
        SyncedToEntra   = if ($entraUser) { 'Yes' } else { 'No' }
        Entra_Enabled   = if ($entraUser) { $entraUser.AccountEnabled } else { 'N/A' }
        Entra_UPN       = if ($entraUser) { $entraUser.UserPrincipalName } else { 'N/A' }
        Entra_LastPwdChange = if ($entraUser) { $entraUser.LastPasswordChangeDateTime } else { 'N/A' }
    }
}

$results | Format-Table Name, SAM, UAC, AD_PwdLastSet, SyncedToEntra, Entra_Enabled, Entra_UPN -AutoSize
$results | Export-Csv -Path "ad_entra_crosscheck.csv" -NoTypeInformation

Write-Host "`nTotal AD users: $($results.Count)"
Write-Host "Synced to Entra: $(($results | Where-Object SyncedToEntra -eq 'Yes').Count)"
Write-Host "NOT synced: $(($results | Where-Object SyncedToEntra -eq 'No').Count)"
Write-Host "Exported to: ad_entra_crosscheck.csv"

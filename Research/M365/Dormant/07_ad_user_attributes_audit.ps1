# AD User Attributes Audit — Query Critical Hybrid Identity Attributes
# Run on Domain Controller or machine with RSAT AD tools
# Shows UAC flags, password status, group count, and last change time

Get-ADUser -Filter {Enabled -eq $true} -Properties userAccountControl, pwdLastSet, userPrincipalName, accountExpires, mail, proxyAddresses, memberOf, whenChanged |
  Select-Object Name, SamAccountName,
    @{N='UAC';E={$_.userAccountControl}},
    @{N='Disabled';E={[bool]($_.userAccountControl -band 2)}},
    @{N='PwdNeverExpires';E={[bool]($_.userAccountControl -band 65536)}},
    @{N='PwdNotReqd';E={[bool]($_.userAccountControl -band 32)}},
    @{N='PwdLastSet';E={if ($_.pwdLastSet -gt 0) {[DateTime]::FromFileTime($_.pwdLastSet)} else {'MUST CHANGE'}}},
    @{N='AcctExpires';E={if ($_.accountExpires -gt 0 -and $_.accountExpires -lt [long]::MaxValue) {[DateTime]::FromFileTime($_.accountExpires)} else {'Never'}}},
    @{N='GroupCount';E={$_.memberOf.Count}},
    @{N='LastChanged';E={$_.whenChanged}} |
  Format-Table -AutoSize

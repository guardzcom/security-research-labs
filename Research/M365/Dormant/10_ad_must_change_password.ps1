# Find Users Who Must Change Password at Next Logon
# Run on Domain Controller or machine with RSAT AD tools
# pwdLastSet = 0 means force change, syncs to Entra as forceChangePasswordNextSignIn = true

Get-ADUser -Filter {pwdLastSet -eq 0 -and Enabled -eq $true} -Properties pwdLastSet, userAccountControl |
  Select-Object Name, SamAccountName,
    @{N='pwdLastSet';E={$_.pwdLastSet}},
    @{N='UAC';E={$_.userAccountControl}}

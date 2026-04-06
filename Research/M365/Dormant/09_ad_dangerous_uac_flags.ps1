# Hunt Dangerous UAC Flags — Find Accounts with Risky Configurations
# Run on Domain Controller or machine with RSAT AD tools
# Detects: PASSWD_NOTREQD, delegation flags, password never expires

Get-ADUser -Filter {Enabled -eq $true} -Properties userAccountControl |
  Where-Object {
    ($_.userAccountControl -band 32) -or       # PASSWD_NOTREQD
    ($_.userAccountControl -band 1048576) -or   # TRUSTED_FOR_DELEGATION
    ($_.userAccountControl -band 16777216) -or  # TRUSTED_TO_AUTH_FOR_DELEGATION
    ($_.userAccountControl -band 65536)         # DONT_EXPIRE_PASSWD
  } |
  Select-Object Name, SamAccountName,
    @{N='UAC';E={$_.userAccountControl}},
    @{N='PASSWD_NOTREQD';E={[bool]($_.userAccountControl -band 32)}},
    @{N='DELEGATION';E={[bool]($_.userAccountControl -band 1048576)}},
    @{N='CONSTRAINED_DELEG';E={[bool]($_.userAccountControl -band 16777216)}},
    @{N='PWD_NEVER_EXPIRES';E={[bool]($_.userAccountControl -band 65536)}} |
  Format-Table -AutoSize

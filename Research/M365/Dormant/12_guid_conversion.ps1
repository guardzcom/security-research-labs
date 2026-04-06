# GUID / ImmutableId Conversion Utilities
# Convert between on-prem objectGUID and Entra ImmutableId (Base64)
# Use during forensic investigations to correlate AD ↔ Entra evidence

# --- objectGUID to ImmutableId ---
$adUser = Get-ADUser -Identity "kevin" -Properties objectGUID
$immutableId = [Convert]::ToBase64String($adUser.objectGUID.ToByteArray())
Write-Host "AD objectGUID:    $($adUser.objectGUID)"
Write-Host "Entra ImmutableId: $immutableId"

# --- ImmutableId to objectGUID ---
# $immutableId = "1eLWKGhjWk22cdUrMBcmgA=="
$guid = [Guid]([Convert]::FromBase64String($immutableId))
Write-Host "Reverse GUID:     $guid"

# --- Find user in Entra by ImmutableId ---
# Get-MgUser -Filter "onPremisesImmutableId eq '$immutableId'"

# --- Find user in AD by LDAP escaped hex ---
# Get-ADUser -LDAPFilter "(msDS-ConsistencyGuid=\d5\e2\d6\28\68\63\5a\4d\b6\71\d5\2b\30\17\26\80)"

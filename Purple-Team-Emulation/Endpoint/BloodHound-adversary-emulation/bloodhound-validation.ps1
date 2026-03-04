<#
.SYNOPSIS
    BloodHound adversary emulation for EDR detection validation.
    No real AD enumeration performed.
.NOTES
    MITRE: T1087.002, T1069.002, T1482, T1059.001
#>

$artifact = "$env:TEMP\bh_emulation_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$harmless = "echo benign > `"$artifact`""

$bhCmd = "Invoke-BloodHound -CollectionMethod All -Domain CONTOSO.LOCAL; Get-BloodHoundData; $harmless"

Start-Process -FilePath "powershell.exe" `
    -ArgumentList "-Command $bhCmd" `
    -WindowStyle Hidden `
    -Wait

Write-Host "BloodHound execution emulation completed safely."
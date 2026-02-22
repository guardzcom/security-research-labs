<#
.SYNOPSIS
  Office macro-security tampering emulation for EDR/AV/SIEM detection testing (purple team).
.DESCRIPTION
  Creates registry keys and values under a sandbox path (SecurityTestEmu) that mimic
  Office macro-security tampering (AccessVBOM, VbaWarnings, etc.) without changing
  real Office behavior. Use only in authorized test environments.
#>

# Office versions to simulate
$versions = "14.0", "15.0", "16.0"

foreach ($v in $versions) {

    # Sandbox path that LOOKS like the real Office path
    $p = "HKCU:\Software\Microsoft\Office\$v\SecurityTestEmu"

    # Ensure key exists
    if (!(Test-Path $p)) { New-Item -Path $p -Force | Out-Null }

    # Create noise to mimic AccessVBOM tampering
    New-ItemProperty -Path $p -Name "AccessVBOM"   -Value 1 -PropertyType DWORD -Force | Out-Null

    # Create noise to mimic VbaWarnings tampering
    New-ItemProperty -Path $p -Name "VbaWarnings"  -Value 1 -PropertyType DWORD -Force | Out-Null

    # Additional noise keys to resemble malware / macro weaponization
    New-ItemProperty -Path $p -Name "MacroPolicyOverride" -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $p -Name "VBEBypassFlag"       -Value 1 -PropertyType DWORD -Force | Out-Null
}

Write-Host "Office macro-security tampering emulation completed."

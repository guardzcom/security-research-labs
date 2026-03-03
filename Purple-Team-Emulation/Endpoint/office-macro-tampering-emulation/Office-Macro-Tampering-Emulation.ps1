<#
.SYNOPSIS
  Office macro-security tampering emulation for EDR/AV/SIEM detection testing (purple team).
.DESCRIPTION
  Generates registry, scheduled task, COM/CLSID, scripting engine, and file-touch telemetry
  that mimics real macro weaponization TTPs. Real Office registry keys are read, briefly
  written, then immediately restored to original values. Sandbox keys are written and left
  for post-run inspection. Use only in authorized test environments.

  TTPs covered:
    T1137       - Office Application Startup
    T1137.001   - Office Template Macros
    T1053.005   - Scheduled Task/Job: Scheduled Task
    T1112       - Modify Registry
    T1059.005   - Command and Scripting Interpreter: VBScript
    T1059.007   - Command and Scripting Interpreter: JavaScript
    T1546.015   - Event Triggered Execution: Component Object Model Hijacking
    T1564.001   - Hide Artifacts: Hidden Files and Directories
    T1027       - Obfuscated Files or Information
#>

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

$versions  = "14.0","15.0","16.0"
$appNames  = "Word","Excel","PowerPoint","Access"
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# -----------------------------------------------------------------------
# Helper: save, write, restore a real registry value
# Generates write telemetry on the actual path without persisting the change
# -----------------------------------------------------------------------
function Invoke-RegFlip {
    param($Path, $Name, $FakeValue, $Type = "DWORD")
    $original = $null
    $existed  = $false
    if (Test-Path $Path) {
        $prop = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($null -ne $prop) {
            $original = $prop.$Name
            $existed  = $true
        }
    } else {
        New-Item -Path $Path -Force | Out-Null
    }
    # Write fake value - this is the telemetry event
    New-ItemProperty -Path $Path -Name $Name -Value $FakeValue -PropertyType $Type -Force | Out-Null
    Start-Sleep -Milliseconds 80
    # Immediately restore
    if ($existed) {
        New-ItemProperty -Path $Path -Name $Name -Value $original -PropertyType $Type -Force | Out-Null
    } else {
        Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
    }
}

# -----------------------------------------------------------------------
# Module 1: Sandbox key writes (persistent, for post-run inspection)
# Mimics: T1112 - Modify Registry
# Covers the full key set a macro weaponization tool would touch
# -----------------------------------------------------------------------
Write-Host "[*] Module 1: Sandbox registry noise..."
foreach ($v in $versions) {
    foreach ($app in $appNames) {
        $sandbox = "HKCU:\Software\Microsoft\Office\$v\$app\SecurityTestEmu"
        if (!(Test-Path $sandbox)) { New-Item -Path $sandbox -Force | Out-Null }

        $keys = @{
            "AccessVBOM"              = 1   # VBA object model access - primary macro C2 TTP
            "VbaWarnings"             = 1   # Disable macro warnings
            "MacroPolicyOverride"     = 1
            "VBEBypassFlag"           = 1
            "DisableAllActiveX"       = 0   # ActiveX enabled - common in maldoc chains
            "DisableAttachementsInPV" = 0
            "MarkInternalAsUnsafe"    = 0
            "RequireAddinSig"         = 0   # Unsigned add-ins allowed
            "NoTBPromptUnsignedAddin" = 1
        }
        foreach ($k in $keys.GetEnumerator()) {
            New-ItemProperty -Path $sandbox -Name $k.Key -Value $k.Value `
                -PropertyType DWORD -Force | Out-Null
        }
    }
}

# -----------------------------------------------------------------------
# Module 2: Real Office path flip-restore
# Generates telemetry on actual HKCU Office Security paths
# Mimics: T1112, adversary macro enablement pre-execution
# -----------------------------------------------------------------------
Write-Host "[*] Module 2: Real Office path flip-restore..."
foreach ($v in $versions) {
    foreach ($app in $appNames) {
        $realPath = "HKCU:\Software\Microsoft\Office\$v\$app\Security"
        Invoke-RegFlip -Path $realPath -Name "AccessVBOM"   -FakeValue 1
        Invoke-RegFlip -Path $realPath -Name "VbaWarnings"  -FakeValue 1
        Invoke-RegFlip -Path $realPath -Name "DisableAllActiveX" -FakeValue 0
        Invoke-RegFlip -Path $realPath -Name "RequireAddinSig"   -FakeValue 0
    }
}

# -----------------------------------------------------------------------
# Module 3: Trusted Location registration noise
# Mimics: T1137 - adversary adding attacker-controlled path as trusted location
# Real path touched, immediately cleaned
# -----------------------------------------------------------------------
Write-Host "[*] Module 3: Trusted Location registration..."
foreach ($v in $versions) {
    foreach ($app in $appNames) {
        $tlBase    = "HKCU:\Software\Microsoft\Office\$v\$app\Security\Trusted Locations"
        $tlSandbox = "$tlBase\SecurityTestEmu_Location"
        if (!(Test-Path $tlSandbox)) { New-Item -Path $tlSandbox -Force | Out-Null }
        New-ItemProperty -Path $tlSandbox -Name "Path"            -Value "C:\Users\Public\Documents" -PropertyType String -Force | Out-Null
        New-ItemProperty -Path $tlSandbox -Name "AllowSubFolders" -Value 1 -PropertyType DWORD  -Force | Out-Null
        New-ItemProperty -Path $tlSandbox -Name "Description"     -Value "TestEmu_TrustedPath"   -PropertyType String -Force | Out-Null
        Start-Sleep -Milliseconds 80
        Remove-Item -Path $tlSandbox -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# -----------------------------------------------------------------------
# Module 4: CLSID/COM hijack noise
# Mimics: T1546.015 - HKCU CLSID override of a legitimate InprocServer32
# Uses a fake CLSID that won't collide with real COM objects
# Written to sandbox subkey, removed after telemetry window
# -----------------------------------------------------------------------
Write-Host "[*] Module 4: CLSID hijack noise..."
# CLSID of VBE (Visual Basic for Applications Extensibility) - common maldoc target
$vbeCLSID  = "{0002E157-0000-0000-C000-000000000046}"
$clsidPath = "HKCU:\Software\Classes\CLSID\$vbeCLSID\InprocServer32"
if (!(Test-Path $clsidPath)) { New-Item -Path $clsidPath -Force | Out-Null }
New-ItemProperty -Path $clsidPath -Name "(Default)"    -Value "C:\Windows\System32\mscoree.dll" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $clsidPath -Name "ThreadingModel" -Value "Both" -PropertyType String -Force | Out-Null
Start-Sleep -Milliseconds 150
Remove-Item -Path "HKCU:\Software\Classes\CLSID\$vbeCLSID" -Recurse -Force -ErrorAction SilentlyContinue

# -----------------------------------------------------------------------
# Module 5: Scheduled task persistence noise
# Mimics: T1053.005 - macro dropping a scheduled task for persistence
# Task is created and immediately deleted
# -----------------------------------------------------------------------
Write-Host "[*] Module 5: Scheduled task persistence noise..."
$taskName = "SecurityTestEmu_OfficeUpdate_$timestamp"
$taskXML  = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>SecurityTestEmu - macro persistence simulation</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger><Enabled>true</Enabled></LogonTrigger>
  </Triggers>
  <Actions Context="Author">
    <Exec>
      <Command>wscript.exe</Command>
      <Arguments>/b /e:vbscript C:\Users\Public\update.vbs</Arguments>
    </Exec>
  </Actions>
</Task>
"@
$taskXML | Out-File -FilePath "$env:TEMP\testemu_task.xml" -Encoding Unicode -Force
schtasks.exe /Create /TN $taskName /XML "$env:TEMP\testemu_task.xml" /F 2>&1 | Out-Null
Start-Sleep -Milliseconds 200
schtasks.exe /Delete /TN $taskName /F 2>&1 | Out-Null
Remove-Item -Path "$env:TEMP\testemu_task.xml" -Force -ErrorAction SilentlyContinue

# -----------------------------------------------------------------------
# Module 6: Scripting engine invocation noise
# Mimics: T1059.005/T1059.007 - wscript/cscript spawn from Office macro chain
# Drops a benign stub script, executes it, removes it
# -----------------------------------------------------------------------
Write-Host "[*] Module 6: Scripting engine invocation noise..."
$vbsPath = "$env:TEMP\testemu_stub_$timestamp.vbs"
$vbsCode = @"
' SecurityTestEmu - benign VBScript stub
Dim oShell
Set oShell = CreateObject("WScript.Shell")
oShell.Run "cmd.exe /c echo SecurityTestEmu_VBS_Exec > %TEMP%\testemu_vbs_out.txt", 0, True
Set oShell = Nothing
"@
$vbsCode | Out-File -FilePath $vbsPath -Encoding ASCII -Force
# wscript spawn mimics Office macro -> wscript child process chain
Start-Process -FilePath "wscript.exe" -ArgumentList "/b `"$vbsPath`"" -Wait -ErrorAction SilentlyContinue
Start-Sleep -Milliseconds 300
Remove-Item -Path $vbsPath -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:TEMP\testemu_vbs_out.txt" -Force -ErrorAction SilentlyContinue

# -----------------------------------------------------------------------
# Module 7: VBE6EXT.OLB / VBA extensibility file-touch noise
# Mimics: T1137 - adversary accessing VBA extensibility object model
# Resolves path and performs a benign ReadAllBytes to generate file-access telemetry
# -----------------------------------------------------------------------
Write-Host "[*] Module 7: VBE6EXT.OLB file-access noise..."
$vbePaths = @(
    "$env:ProgramFiles\Microsoft Office\root\vfs\ProgramFilesCommonX86\Microsoft Shared\VBA\VBA7.1\VBE7.DLL",
    "$env:ProgramFiles (x86)\Common Files\Microsoft Shared\VBA\VBA7.1\VBE7.DLL",
    "$env:ProgramFiles\Common Files\Microsoft Shared\VBA\VBA7.1\VBE7.DLL"
)
foreach ($vbePath in $vbePaths) {
    if (Test-Path $vbePath) {
        # Read first 512 bytes only - generates file open telemetry without loading the DLL
        $stream = [System.IO.File]::OpenRead($vbePath)
        $header = New-Object byte[] 512
        $stream.Read($header, 0, 512) | Out-Null
        $stream.Close()
        break
    }
}

# -----------------------------------------------------------------------
# Module 8: Hidden file drop noise
# Mimics: T1564.001 - macro dropping hidden payload stub to AppData
# File is created with hidden+system attributes then removed
# -----------------------------------------------------------------------
Write-Host "[*] Module 8: Hidden file drop noise..."
$hiddenPath = "$env:APPDATA\Microsoft\Word\SecurityTestEmu_$timestamp.dotm"
"SecurityTestEmu placeholder - not a real macro template" | Out-File -FilePath $hiddenPath -Encoding ASCII -Force
$hiddenFile = Get-Item -Path $hiddenPath -Force
$hiddenFile.Attributes = "Hidden,System"
Start-Sleep -Milliseconds 200
Remove-Item -Path $hiddenPath -Force -ErrorAction SilentlyContinue

# -----------------------------------------------------------------------
# Module 9: Obfuscated payload decode noise
# Mimics: T1027 - Base64 + XOR decode chain common in maldoc stagers
# No execution - surfaces decoded strings to AMSI inspection path
# -----------------------------------------------------------------------
Write-Host "[*] Module 9: Obfuscation decode chain noise..."
$stager = "cG93ZXJzaGVsbCAtZW5jIFdBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="
$decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($stager))
# XOR decode pass (key 0x41) - mimics second-stage decode loop
$xorKey  = 0x41
$xorBuf  = [System.Text.Encoding]::UTF8.GetBytes($decoded)
for ($i = 0; $i -lt $xorBuf.Length; $i++) { $xorBuf[$i] = $xorBuf[$i] -bxor $xorKey }
$finalDecode = [System.Text.Encoding]::UTF8.GetString($xorBuf)
Write-Verbose "Decode chain output (AMSI-visible): $finalDecode"

Write-Host "[+] Office macro-security tampering emulation completed."

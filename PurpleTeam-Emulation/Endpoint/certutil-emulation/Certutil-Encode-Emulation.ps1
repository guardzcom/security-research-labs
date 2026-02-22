<#
.SYNOPSIS
  Certutil encode emulation for detection testing (purple team).
.DESCRIPTION
  Launches certutil.exe -encode with a fake input file. Output is written ONLY to
  %TEMP%. Does not read or write C:\Windows\System32\config. Run only in authorized
  test environments; do not run as Administrator.
#>

# Safety: refuse to run if elevated (optional; remove if you run in a controlled non-admin context)
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Warning "Refusing to run as Administrator to avoid any risk to system files. Run as normal user for detection testing."
    exit 1
}

$fakeIn = "$env:TEMP\fake_dump.bin"
$safeOutDir = "$env:TEMP\certutil_emulation_out"
if (-not (Test-Path $safeOutDir)) { New-Item -ItemType Directory -Path $safeOutDir -Force | Out-Null }

"xyz" | Out-File $fakeIn -Encoding ASCII -Force

# Sensitive-looking names for EDR visibility; output goes ONLY to %TEMP%
$h = "SAM", "SYSTEM", "SECURITY"
$runCount = 0

foreach ($item in $h) {
    1..3 | ForEach-Object {
        $outFile = Join-Path $safeOutDir "encoded_$item`_$_.b64"
        Start-Process "cmd.exe" -ArgumentList "/c certutil.exe -encode `"$fakeIn`" `"$outFile`"" -WindowStyle Hidden
        $runCount++
    }
}

Write-Host "Concurrent certutil encode emulation launched ($runCount processes). Output only in: $safeOutDir"

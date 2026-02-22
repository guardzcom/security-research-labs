<#
.SYNOPSIS
  EDR Telemetry Simulator  - generates controlled API telemetry for detection validation (purple team).
.DESCRIPTION
  Invokes Windows APIs and patterns commonly associated with keyloggers, process access,
  and network checks in a harmless way (no hooks, no real access, no exfil). Use only
  in authorized test environments to validate EDR/AV/SIEM detection rules.
#>

# Generate unique class names to avoid Add-Type collisions
$KL = "KeySim_{0}" -f ([Guid]::NewGuid().ToString("N"))
$PS = "ProcSim_{0}" -f ([Guid]::NewGuid().ToString("N"))
$NM = "NetSim_{0}" -f ([Guid]::NewGuid().ToString("N"))

# ----------------------------
# Module 1: Keylogging Telemetry Noise
# ----------------------------
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class $KL {
    [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern IntPtr SetWindowsHookExA(int idHook, IntPtr lpfn, IntPtr hMod, uint threadId);
}
"@

[$KL]::GetAsyncKeyState(0) | Out-Null
[$KL]::GetForegroundWindow() | Out-Null

$buf = New-Object System.Text.StringBuilder 128
[$KL]::GetWindowText([IntPtr]::Zero, $buf, $buf.Capacity) | Out-Null

# ----------------------------
# Module 2: Process Access Noise Signature
# ----------------------------
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class $PS {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualQuery(IntPtr lpAddress, IntPtr buffer, IntPtr size);
}
"@

# harmless call (no access granted)
[$PS]::OpenProcess(0x0, $false, 0) | Out-Null

# ----------------------------
# Module 3: Network API Noise (classic malware scaffold pattern)
# ----------------------------
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class $NM {
    [DllImport("wininet.dll")] public static extern bool InternetCheckConnection(string lpszUrl, int dwFlags, int dwReserved);
}
"@

[$NM]::InternetCheckConnection("http://example.com", 1, 0) | Out-Null

# ----------------------------
# Module 4: Obfuscation Noise Block
# ----------------------------
$fake = "GetAsyncKeyState;SetWindowsHookExA;NtUserGetAsyncKeyState;GetWindowTextA;WM_KEYBOARD_LL"
$encodedNoise = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($fake))
$encodedNoise | Out-Null

# ----------------------------
# Module 5: Random Loop Noise (mimics polling structure)
# ----------------------------
for ($i=0; $i -lt 3; $i++) {
    Start-Sleep -Milliseconds 120
    [void][$KL]::GetAsyncKeyState($i)
}

Write-Host "EDR Telemetry Simulator completed."
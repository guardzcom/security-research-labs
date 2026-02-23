<#
.SYNOPSIS
  EDR Telemetry Simulator - generates controlled API telemetry for detection validation (purple team).
.DESCRIPTION
  Invokes Windows APIs and patterns commonly associated with keyloggers, process access,
  and network exfiltration simulation. All network activity is loopback-only (127.0.0.1).
  No external connectivity, no real data exfiltration.
  Use only in authorized test environments to validate EDR/AV/SIEM detection rules.
#>

# Generate unique suffix - N format produces hyphen-free GUID safe for class names
$suffix = [Guid]::NewGuid().ToString("N")
$KL = "KeySim_$suffix"
$PS = "ProcSim_$suffix"
$NM = "NetSim_$suffix"

# ----------------------------
# Module 1: Keylogging Telemetry Noise
# Exercises: GetAsyncKeyState polling, GetForegroundWindow, GetWindowText, SetWindowsHookExA syscall
# MITRE: T1056.001 (Keylogging)
# ----------------------------
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class $KL {
    [DllImport("user32.dll")] public static extern short GetAsyncKeyState(int vKey);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int GetWindowText(IntPtr hWnd, System.Text.StringBuilder text, int count);
    [DllImport("user32.dll")] public static extern IntPtr SetWindowsHookExA(int idHook, IntPtr lpfn, IntPtr hMod, uint dwThreadId);
    [DllImport("user32.dll")] public static extern bool UnhookWindowsHookEx(IntPtr hhk);
}
"@

# Resolve type via reflection - avoids the dynamic variable-in-brackets parse error
$klType = [AppDomain]::CurrentDomain.GetAssemblies() |
    ForEach-Object { $_.GetType($KL) } |
    Where-Object { $_ -ne $null } |
    Select-Object -First 1

$klType::GetAsyncKeyState(0) | Out-Null
$klType::GetForegroundWindow() | Out-Null
$buf = New-Object System.Text.StringBuilder 128
$klType::GetWindowText([IntPtr]::Zero, $buf, $buf.Capacity) | Out-Null

# WH_KEYBOARD_LL = 13; null callback will fail but syscall telemetry is generated
$hookHandle = $klType::SetWindowsHookExA(13, [IntPtr]::Zero, [IntPtr]::Zero, 0)
if ($hookHandle -ne [IntPtr]::Zero) {
    $klType::UnhookWindowsHookEx($hookHandle) | Out-Null
}

# ----------------------------
# Module 2: Process Access Noise Signature
# Exercises: OpenProcess with PROCESS_VM_READ | PROCESS_QUERY_INFORMATION (0x410)
# MITRE: T1003.001 (LSASS Memory)
# ----------------------------
Add-Type @"
using System;
using System.Runtime.InteropServices;
public class $PS {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll")] public static extern IntPtr VirtualQuery(IntPtr lpAddress, IntPtr buffer, IntPtr size);
}
"@

$psType = [AppDomain]::CurrentDomain.GetAssemblies() |
    ForEach-Object { $_.GetType($PS) } |
    Where-Object { $_ -ne $null } |
    Select-Object -First 1

$hProc = $psType::OpenProcess(0x0410, $false, 0)
if ($hProc -ne [IntPtr]::Zero) {
    $psType::CloseHandle($hProc) | Out-Null
}

# ----------------------------
# Module 3: Simulated Exfiltration over Loopback
# Mimics encode -> connect -> send -> close exfil scaffold.
# No listener required - connection refused still generates Sysmon EID 3 / ETW Winsock telemetry.
# MITRE: T1041 (Exfiltration Over C2 Channel), T1071.001
# ----------------------------
Add-Type @"
using System;
using System.Net.Sockets;
using System.Text;
public class $NM {
    public static void SimulateExfil(string host, int port, string payload) {
        try {
            using (var client = new TcpClient()) {
                var result = client.BeginConnect(host, port, null, null);
                result.AsyncWaitHandle.WaitOne(500);
                if (client.Connected) {
                    var stream = client.GetStream();
                    var data = Encoding.UTF8.GetBytes(payload);
                    stream.Write(data, 0, data.Length);
                    stream.Flush();
                }
                client.Close();
            }
        } catch { }
    }
}
"@

$nmType = [AppDomain]::CurrentDomain.GetAssemblies() |
    ForEach-Object { $_.GetType($NM) } |
    Where-Object { $_ -ne $null } |
    Select-Object -First 1

$fakeCapture  = "user=testbox\admin;keys=SecurePass1!;window=cmd.exe"
$exfilPayload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($fakeCapture))

# Port 4444 - Metasploit default reverse shell signature
$nmType::SimulateExfil("127.0.0.1", 4444, $exfilPayload)

# ----------------------------
# Module 4: AMSI-Visible Obfuscation Noise
# Decoded string surfaces known keylogger API names to AMSI inspection path.
# MITRE: T1027, T1140
# ----------------------------
$fake = "GetAsyncKeyState;SetWindowsHookExA;NtUserGetAsyncKeyState;GetWindowTextA;WM_KEYBOARD_LL"
$encodedNoise = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($fake))
$decodedNoise = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedNoise))
Write-Verbose "Decoded noise (AMSI-visible): $decodedNoise"

# ----------------------------
# Module 5: Polling Loop Noise
# Timed GetAsyncKeyState polling - primary behavioral keylogger signature.
# MITRE: T1056.001
# ----------------------------
for ($i = 0; $i -lt 3; $i++) {
    Start-Sleep -Milliseconds 120
    $klType::GetAsyncKeyState($i) | Out-Null
}

Write-Host "EDR Telemetry Simulator completed."

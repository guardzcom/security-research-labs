# EDR Telemetry Simulator

**Purpose:** Purple-team detection validation  - generates **controlled API telemetry** commonly associated with keyloggers, process access, and network checks, without performing any malicious action. Use to validate that EDR, AV, or SIEM rules alert on these patterns.

**Authorized use only.** Run only in test environments or with explicit approval.

---

## What it does

The script invokes Windows APIs and patterns in a **harmless way** (no hooks installed, no real process access, no data exfiltrated):

| Module | APIs / pattern | Intent |
|--------|----------------|--------|
| **1. Keylogging telemetry** | `GetAsyncKeyState`, `GetForegroundWindow`, `GetWindowText`, `SetWindowsHookExA` (referenced) | Simulate keylogger-related API usage so telemetry shows these calls. No hook is installed; no keys are logged. |
| **2. Process access** | `OpenProcess(0, false, 0)`, `VirtualQuery` (referenced) | Simulate process-handle / memory-style API usage. No real access is granted (request is no-access on PID 0). |
| **3. Network API** | `InternetCheckConnection("http://example.com", ...)` | Simulate a “check before C2” style call often seen in beacons. |
| **4. Obfuscation noise** | Base64-encoded string of common keylogger/malware API names | Creates a string that may trigger static or memory-based “suspicious encoded string” rules. |
| **5. Polling loop** | Short loop with `Start-Sleep` and `GetAsyncKeyState($i)` | Mimics the **structure** of keylogger polling without logging anything. |

Unique class names (GUID-based) are used so `Add-Type` does not collide when the script is run multiple times in the same session.

---

## Usage

```powershell
# From this folder; Windows only
.\EDR-Telemetry-Simulator.ps1
```

---

## Requirements

- **Windows** (uses user32, kernel32, wininet P/Invoke).
- **PowerShell 5.1+** (Windows PowerShell or PowerShell Core on Windows).

---

## What this script does not do

- Does **not** install hooks or log keystrokes.
- Does **not** open or read other processes’ memory.
- Does **not** exfiltrate data or contact a C2.
- Only **invokes APIs and patterns** so your detection stack can be tested.

---

## License

See [../../../LICENSE](../../../LICENSE).

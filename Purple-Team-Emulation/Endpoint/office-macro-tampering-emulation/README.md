# Office Macro-Security Tampering Emulation (Detection Test)

**Purpose:** Purple-team detection validation - generates **registry activity** that mimics Office macro-security tampering (AccessVBOM, VbaWarnings, macro-policy bypass) without changing real Office behavior. Use to validate that EDR, AV, or SIEM rules alert on this pattern.

**Authorized use only.** Run only in test environments or with explicit approval.

---

## What it does

- For Office versions **14.0**, **15.0**, **16.0** (Office 2010, 2013, 2016/365), creates a **sandbox** registry key:
  - `HKCU:\Software\Microsoft\Office\<version>\SecurityTestEmu`
- Writes DWORD values that match names commonly used in macro-weaponization and detection rules:

| Value               | Set to | Meaning (if it were the real key) |
|---------------------|--------|------------------------------------|
| **AccessVBOM**      | 1      | Trust access to the VBA project object model (often abused by macro malware). |
| **VbaWarnings**     | 1      | Can reduce or bypass macro/VBA security warnings. |
| **MacroPolicyOverride** | 1  | Suggests bypassing macro policy. |
| **VBEBypassFlag**   | 1      | Suggests bypassing VBA Editor-related restrictions. |

Real Office does **not** read `SecurityTestEmu`; the real security keys live under paths like `...\Excel\Security` or `...\Word\Security`. So Office macro security is **not** changed - only registry telemetry is generated for detection testing.

---

## Usage

```powershell
# From this folder; Windows only
.\Office-Macro-Tampering-Emulation.ps1
```

---

## Requirements

- **Windows** (registry access).
- **PowerShell 5.1+** (Windows PowerShell or PowerShell Core on Windows).
- No elevation required (writes under HKCU).

---

## What this script does not do

- Does **not** modify real Office security keys (Excel/Word/etc. Security subkeys).
- Does **not** enable macros or VBA project access for actual Office apps.
- Only creates keys under `...\SecurityTestEmu` so detection rules can be validated safely.

---

## License

See [../../../LICENSE](../../../LICENSE).

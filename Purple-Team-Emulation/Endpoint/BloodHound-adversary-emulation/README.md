# BloodHound Adversary Emulation (Detection Test)

**Purpose:** Purple-team / detection test: emulate BloodHound-style process and command-line activity to validate EDR/SIEM alerts for AD enumeration and data-collection patterns. Uses a benign domain and writes only to `%TEMP%`; no real Active Directory enumeration is performed.

**Authorized use only.** Run only in test environments or with explicit approval.

---

## What it does

- Launches PowerShell with BloodHound-style commands (`Invoke-BloodHound`, `Get-BloodHoundData`) against a fake domain (`CONTOSO.LOCAL`) to generate process/command-line telemetry.
- Writes a harmless artifact to `%TEMP%` so EDR can see the execution pattern without performing real AD collection.
- **MITRE:** T1087.002 (Domain Account), T1069.002 (Domain Groups), T1482 (Domain Trust), T1059.001 (PowerShell).

---

## Usage

```powershell
# From this folder
.\bloodhound-validation.ps1
```

---

## Requirements

- **Windows.** PowerShell 5.1+.
- BloodHound / SharpHound modules are **not** required for the emulation; the script triggers command patterns that EDR may flag. If you have BloodHound installed, ensure you run only in an approved test environment.

---

## License

See [../../../../LICENSE](../../../../LICENSE).

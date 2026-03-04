# Nmap Scanning Emulation (Detection Test)

**Purpose:** Purple-team / detection test: simulate **nmap-style process creation and command-line patterns** to validate EDR/SIEM rules (e.g. SentinelOne) that alert on network scanning. Does **not** perform real network scanning—uses a benign stub executable and scan-like arguments only.

**Authorized use only.** Run only in test environments or with explicit approval.

---

## What it does

- Creates a harmless .NET console app compiled as `nmap.exe` in `%TEMP%`.
- Launches it with command-line arguments that mimic common nmap scan flags (e.g. `-sS`, `-sV`, `-oN`, `-sU`, `-p`, `-iL`) so EDR can see “nmap.exe” with scan-like args.
- Runs several test cases: SYN scan sim, OS detection sim, output-to-file sim, aggressive scan sim, UDP scan sim, and a “no trigger” case (`--help`).
- Ensures the run is **not** as SYSTEM (script exits if so), to match typical rule exclusions.
- Prints a SentinelOne Deep Visibility–style query for verifying detections; then cleans up temp artifacts.

---

## Usage

```powershell
# From this folder. Run as a standard user (not SYSTEM).
.\Namp-scanning.ps1
```

---

## Requirements

- **Windows.** PowerShell 5.1+ (script compiles a small .NET stub).
- Run as a **normal / standard user**. The script aborts if run as SYSTEM (or equivalent) so detection validation matches the rule’s excluded context.

---

## License

See [../../../../LICENSE](../../../../LICENSE).

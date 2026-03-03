# Certutil Encode Emulation (Detection Test)

**Purpose:** Purple-team / detection test: emulate `certutil.exe -encode` with sensitive-looking paths to validate EDR/SIEM alerts. Does **not** read or write real registry hives; uses a fake input and writes only to `%TEMP%`.

**Authorized use only.** Run only in test environments or with explicit approval. Do not run as Administrator.

---

## What it does

- Creates a small fake file in `%TEMP%`.
- Launches multiple hidden `cmd.exe` processes that run:
  - `certutil.exe -encode <fake_file> <output_in_temp>`
  - Output files are written only under `%TEMP%\certutil_emulation_out\` so EDR can see the process/command-line pattern without touching `C:\Windows\System32\config\`.

---

## Usage

```powershell
# From this folder, no elevation
.\Certutil-Encode-Emulation.ps1
```

---

## Requirements

- Windows (certutil.exe available).
- **Do not run as Administrator**  - script aborts if elevated.

---

## License

See [../../../LICENSE](../../../LICENSE).

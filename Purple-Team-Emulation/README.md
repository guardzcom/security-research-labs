# Purple Team Emulation

Scripts and tools for **purple team** detection testing: emulate attacker behaviors (e.g. living-off-the-land) in a safe, controlled way to validate EDR, SIEM, and detection rules. Tools are grouped by area (e.g. Endpoint); each tool lives in its own dedicated folder with a README.

> **Authorized use only.** Run only in test environments or with explicit approval. Do not run as Administrator unless the tool documentation explicitly allows it.

**Note:** Some scripts are **soft emulation** (lightweight, safe signals) to verify EDR/SIEM detection, while others can be **stronger** (more realistic or invasive). Check each tool’s README for scope and run only in approved test environments.

---

## Tools (dedicated folders)

| Tool | Folder | Description |
|------|--------|-------------|
| **Certutil Encode Emulation** | [Endpoint/certutil-emulation/](Endpoint/certutil-emulation/) | `Certutil-Encode-Emulation.ps1`  - Emulate certutil.exe -encode for EDR/SIEM detection testing; output only to %TEMP%, refuses to run as admin. |
| **EDR Telemetry Simulator** | [Endpoint/edr-telemetry-simulator/](Endpoint/edr-telemetry-simulator/) | `EDR-Telemetry-Simulator.ps1`  - Generates controlled API telemetry (keylogger/process/network patterns) for EDR/AV/SIEM detection validation; harmless API calls only. |
| **Office Macro-Security Tampering Emulation** | [Endpoint/office-macro-tampering-emulation/](Endpoint/office-macro-tampering-emulation/) | `Office-Macro-Tampering-Emulation.ps1`  - Registry activity mimicking AccessVBOM/VbaWarnings/macro-policy tampering under sandbox path for detection testing. |

---

## Requirements

- **Windows** (scripts use Windows binaries, e.g. certutil.exe).
- Run as **normal user** unless a tool’s README states otherwise.

---

## License

Same as the root repository  - see [../LICENSE](../LICENSE).

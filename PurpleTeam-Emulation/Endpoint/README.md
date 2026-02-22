# Endpoint (Purple Team Emulation)

Endpoint-level detection testing: emulate living-off-the-land and API patterns in a safe way to validate EDR, AV, and SIEM rules. Each tool has its own folder with a README.

---

## Tools

| Tool | Folder | Description |
|------|--------|-------------|
| **Certutil Encode Emulation** | [certutil-emulation/](certutil-emulation/) | `Certutil-Encode-Emulation.ps1`  - Emulate certutil.exe -encode for detection testing; output only to %TEMP%, refuses admin. |
| **EDR Telemetry Simulator** | [edr-telemetry-simulator/](edr-telemetry-simulator/) | `EDR-Telemetry-Simulator.ps1`  - Controlled API telemetry (keylogger/process/network patterns) for EDR/AV/SIEM validation. |
| **Office Macro-Security Tampering Emulation** | [office-macro-tampering-emulation/](office-macro-tampering-emulation/) | `Office-Macro-Tampering-Emulation.ps1`  - Registry noise mimicking Office macro-security tampering (sandbox path only). |

---

## Requirements

- **Windows.** Run as normal user unless a tool’s README states otherwise.

---

## License

Same as the root repository  - see [../../LICENSE](../../LICENSE).

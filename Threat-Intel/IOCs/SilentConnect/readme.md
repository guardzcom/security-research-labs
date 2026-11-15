# SilentConnect - Indicators of Compromise

## Incident context

The indicators below are associated with a rogue ScreenConnect client (`25.2.4.9229`) and its supporting scripts and persistence mechanisms. Correlate indicators with host and network telemetry before taking action; some names and paths may also occur in legitimate environments.

## Network and infrastructure

| Type | Value (defanged) | Context |
|------|------------------|---------|
| Domain | `transactonly[.]com` | Relay server communicating with the existing ScreenConnect client (`25.2.4.9229`). |
| Domain | `relay[.]vigatu[.]top` | Secondary C2 relay server used by the rogue client. |
| Domain | `downloads[.]ps1cloud[.]com` | Payload delivery domain hosting PowerShell scripts. |
| GitHub account / Gist | `bradleymadden` (`gistfile1.txt`, executed as `gistfile1.ps1`) | Auxiliary script delivery via a public GitHub Gist. |

## Host-based artifacts

### Directories and paths

| Value | Context |
|-------|---------|
| `C:\Program Files (x86)\Microsoft Toolset\` | Directory mimicking IT tooling where the rogue client was spawned. |
| `C:\WINDOWS\SystemTemp\ScreenConnect\25.2.4.9229\` | ScreenConnect file staging directory. |
| `C:\WINDOWS\TEMP\` | Used to stage stealth `.msi` installers. |

### Files and payloads

| Value | Context |
|-------|---------|
| `myne.ps1` | PowerShell payload retrieved from `downloads[.]ps1cloud[.]com`. |
| `psvigatu.ps1` | PowerShell persistence payload retrieved from `downloads[.]ps1cloud[.]com`. |
| `gistfile1.txt` / `gistfile1.ps1` | Script delivered via the public GitHub Gist listed above. |
| Decoy `.msi` files | Installer files mimicking unrelated vendors, such as DocuSign. |

## Persistence

| Type | Value | Context |
|------|-------|---------|
| Windows service | `User_Data_Storage` | Custom malicious service. |
| Scheduled task | `MicrosoftUpdateTools` | Masqueraded scheduled task. |

## Client parameters

| Value | Context |
|-------|---------|
| `t=stole` | Client tag parameter on the rogue ScreenConnect instance. |
| `h=` | Relay parameter pointing to external or unauthorized infrastructure; the specific parameter value is not provided here. |

## Defensive notes

- Search endpoint and network telemetry for the listed paths, filenames, service, task, and domains; correlate findings with ScreenConnect client version `25.2.4.9229`.
- Review the associated process command lines and client configuration for `t=stole` and unauthorized relay values supplied through `h=`.
- Treat generic artifacts such as `.msi` files, Windows temporary paths, and individual filenames as contextual indicators. Validate ownership and execution history before containment or removal.

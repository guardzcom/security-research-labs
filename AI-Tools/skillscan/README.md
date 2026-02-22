# SkillScan

CLI and web tool to **scan skill definition files and URLs** for malicious patterns. Detects prompt injection, malware delivery, code execution, suspicious URLs, encoded or obfuscated content, and suspicious skill metadata. Designed for AI agent skills (e.g. OpenClaw, Cursor, or other SKILL.md-style definitions).

**Authorized use only.** Use on skills and URLs you own or are permitted to assess.

---

## What it does

- **Scan local files** - One or more skill files (e.g. `SKILL.md`, `*.md`).
- **Scan URLs** - Fetch and scan skill content from a URL (optional `--strip-html`).
- **Scan directories** - Recursive scan with optional pattern (e.g. `--pattern "*.md"`).
- **List rules** - Run `skillscan rules` to see detection rule names and descriptions.

**Detection categories** (examples): suspicious URLs (shorteners, tunnels, paste sites, raw GitHub, exfil endpoints, C2-like links), prompt injection patterns, code execution and malware delivery, encoded/obfuscated content, suspicious skill metadata.

---

## Requirements

- **Python 3** (core scanner is `skillscan.py`).
- Optional: PowerShell or Windows batch for wrapper scripts; web UI uses `skillscan_web.html` (and optional server components).

---

## Usage

**Python (direct):**

```bash
python skillscan.py scan file skill.md [skill2.md ...]
python skillscan.py scan url https://example.com/skill [--strip-html]
python skillscan.py scan dir ./skills/ [--pattern "*.md"]
python skillscan.py rules
```

**PowerShell wrapper:**

```powershell
.\skillscan.ps1 scan file skill.md
.\skillscan.ps1 scan url https://playbooks.com/skills/openclaw/skills/reddit-trends --strip-html
.\skillscan.ps1 scan dir .\skills\ --pattern "*.md"
.\skillscan.ps1 rules
```

**Batch (Windows):** `skillscan.bat` forwards arguments to `skillscan.py`.

---

## Files

| File | Purpose |
|------|---------|
| `skillscan.py` | Core scanner (Python). |
| `skillscan.ps1` | PowerShell wrapper; finds Python and invokes `skillscan.py`. |
| `skillscan.bat` | Batch wrapper for Windows. |
| `skillscan_web.html` | Web UI for browser-based scanning. |
| `skillscan_server.py` / `skillscan_server.ps1` | Optional server components for web UI. |

---

## License

Same as the root repository - see [../../LICENSE](../../LICENSE).

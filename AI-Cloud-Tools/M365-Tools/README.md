# M365 Tools

**Goal:** Microsoft 365 / Entra ID defensive, detection, and **authorized** red team tooling: OAuth IOC scanning, MCP-driven Entra ID engagement automation, and related checks. Each tool has its own folder with a README.

**Authorized use only.** Use only on tenants you own or have explicit permission to test.

---

## Contents

| Tool | Folder | Description |
|------|--------|-------------|
| **OAuth IOCs Check** | [IOCs-Check/](IOCs-Check/) | `Check-OAuthIOCs.ps1` — Scan your Entra ID tenant for malicious OAuth app IOCs (service principals, permission grants, sign-in/audit logs). |
| **Shadow AI Audit** | [Shadow-OAuth-AI/](Shadow-OAuth-AI/) | `ShadowAIAudit.ps1` — 10-check read-only audit of AI agents, LLM copilots, and OAuth AI tools in your tenant. Scores each AI-named service principal on Graph scopes, app-only permissions, tenant-wide consent, directory roles, risky redirect URIs, multiple credentials, and more; outputs a self-contained HTML dashboard plus per-check CSVs. See [Shadow-OAuth-AI/README.md](Shadow-OAuth-AI/README.md). |
| **EntraReaper** | [EntraReaper/](EntraReaper/) | MCP server that exposes AADInternals-style operations as tools for **authorized** Entra ID / M365 red team and purple team work: governance, scenarios, kill chains, engagement folders, and reporting. See [EntraReaper/README.md](EntraReaper/README.md). |

**See also:** [Research/M365/Dormant/](../../Research/M365/Dormant/) — hybrid AD / Entra MFA registration gap scripts and Graph samples (reference artifacts, not part of this tools tree).

---

## License

Same as the root repository — see [../../LICENSE](../../LICENSE).

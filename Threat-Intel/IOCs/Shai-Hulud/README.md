# IOC Package: Shai-Hulud (compromised npm / PyPI supply chain)

**Purpose:** Indicators of compromise for a supply-chain campaign involving hijacked or malicious packages, associated payloads, C2, persistence, and campaign markers. Use for threat intelligence, log review, EDR/SIEM rules, and dependency auditing.

**Authorized use only.** Handle per your classification and sharing policies. Verify indicators against your environment and official vendor advisories before taking action.

---

## Malicious or compromised packages

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `@tanstack/router` | npm package | Compromised pkg | Versions **1.169.5**, **1.169.8** - initial entry point via CI/CD hijack |
| `@tanstack/react-router` | npm package | Compromised pkg | Versions **1.169.5**, **1.169.8** - high distribution (millions of weekly downloads) |
| `@tanstack/router-core` | npm package | Compromised pkg | Version **1.169.5+** - shared core across TanStack suite |
| `@tanstack/setup` | npm package | Malicious pkg | **Not** a legitimate TanStack org package - presence alone is an IOC |
| `@mistralai/mistral*` | npm + PyPI | Compromised pkg | Both registries affected; registry crossover confirmed |
| UiPath (suite) | npm package | Compromised pkg | Multiple UiPath automation packages; worm propagation reported |
| `guardrails-ai` | npm package | Compromised pkg | AI safety tooling; collateral via stolen maintainer tokens |
| `opensearch-js` | npm package | Compromised pkg | OpenSearch JavaScript client |
| `transformers.pyz` | PyPI package | Compromised pkg | PyPI payload; delivered via **git-tanstack.com** C2 |

---

## File hashes (SHA-256)

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `router_init.js` | SHA-256 | Malicious file | `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c` - ~2.3 MB obfuscated JS stealer; main payload |
| `tanstack_runner.js` | SHA-256 | Malicious file | `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96` - loader; executes from malicious Git commit |
| `@tanstack/setup` `package.json` | SHA-256 | Malicious file | `7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b` |

---

## C2 and exfiltration domains

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `filev2.getsession.org` | Domain | Exfil / C2 | Session Protocol CDN; encrypted credential upload endpoint |
| `seed1.getsession.org` | Domain | C2 | TLS-pinned C2 verification endpoint |
| `git-tanstack.com` | Domain | Exfil / C2 | PyPI-related exfil; delivers **transformers.pyz** payload |
| `api.masscan.cloud` | Domain | C2 | Secondary C2 endpoint |

---

## Network targets (credential harvest)

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `169.254.169.254` | IP / endpoint | Credential harvest | AWS IMDS metadata service |
| `169.254.170.2` | IP / endpoint | Credential harvest | AWS ECS task metadata endpoint |
| `127.0.0.1:8200` | IP / endpoint | Credential harvest | HashiCorp Vault local API; token extraction |

*Note: These endpoints are legitimate cloud and local services; context (unexpected callers, non-cloud hosts, npm install / CI processes) matters for detection.*

---

## Persistence artifacts

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `gh-token-monitor` | Service name | Persistence | systemd unit (Linux) / LaunchAgent (macOS); reported to run destructive command on token revoke |
| `.claude/settings.json` | File path | Persistence | IDE hook; also drops `.claude/router_runtime.js` |
| `.vscode/tasks.json` | File path | Persistence | VS Code task hook; also drops `.vscode/setup.mjs` |
| `.github/workflows/codeql_analysis.yml` | File path | Persistence | Injected workflow disguised as legitimate CodeQL automation |

---

## Campaign markers

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `github:tanstack/router#79ac49ee...` | Git ref | IOC | Malicious orphan commit (reporter: **voicproducoes**); used in `optionalDependencies` |
| `claude@users.noreply.github.com` | Git identity | IOC | Commit author on GitHub dead-drop repos; message: `chore: update dependencies` |
| `dependabot/github_actions/format/{dune-term}` | Branch pattern | IOC | Related naming; branches such as **fremen**, **sardaukar**, **siridar-ghola-*** used as dead-drops |
| `A Mini Shai-Hulud has Appeared` | Repo description | IOC | GitHub repos carrying stolen data |
| `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner` | npm token description | IOC | Token description string used as ransom/threat marker |
| `bun run tanstack_runner.js && exit 1` | prepare script | IOC | Exact string in compromised `package.json` **prepare** field |

---

## Defensive notes (operational)

- **Dependencies:** Pin or lockfile-audit `@tanstack/*` and other listed packages; remove `@tanstack/setup` if present; compare install scripts and `prepare`/`postinstall` to known-good baselines.
- **CI/CD:** Review recent pipeline changes, `optionalDependencies` that pull Git SHAs, and any CodeQL or Dependabot workflow files that do not match repository history.
- **Network:** Correlate outbound connections to listed domains and IMDS/Vault access from developer machines, CI runners, or containers running `npm`/`bun`/`node`.
- **Endpoints:** Treat unexpected access to IMDS, ECS metadata, or `127.0.0.1:8200` from build or package-related processes as high priority for investigation.

---

## License

Same as the root repository - see [../../../LICENSE](../../../LICENSE).

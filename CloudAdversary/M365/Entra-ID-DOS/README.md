# Entra ID Smart Lockout Validator (Entra-ID-DOS)

Validates **Microsoft Entra ID Smart Lockout** policy in cloud-only and hybrid (Password Hash Sync / Pass-through Authentication) environments. The script uses the **modern browser login flow** (OAuth2 authorize + form POST) to send controlled authentication requests with random incorrect passwords. It monitors for **AADSTS50053** (account locked) to confirm Smart Lockout activates at or below your configured threshold.

Unlike ROPC-only approaches, this flow:

- **Bypasses ROPC blocks** — Works when Conditional Access or Security Defaults block legacy auth.
- **Works without legacy auth** — No dependency on ROPC being enabled in the tenant.
- **Uses the same pipeline as a real browser** — Credentials are submitted via the standard login form.
- **Detects MFA** — If the password is correct but MFA is required, the script detects the challenge and stops (no need for a non-MFA test account when using wrong passwords).

If modern auth initialization fails, the script **falls back to ROPC** automatically.

Use only on tenants and accounts you **own** or have **explicit written authorization** to test. This tool intentionally triggers account lockout and generates sign-in failures.

---

## What it does

| Feature | Description |
|--------|--------------|
| **Smart Lockout test** | Sends bad-password attempts via **browser login flow** (GET /authorize → POST /login); falls back to ROPC if init fails. Validates threshold and duration; detects lockout (50053), bad password (50126), and MFA (password correct). |
| **Deployment auto-detect** | Uses User Realm Discovery, OpenID config, and a probe auth (hash-tracking test) to infer **CloudOnly**, **PHS**, **PTA**, or **Federated**. |
| **PHS** | Runs a **hash-tracking** test: same bad password sent multiple times should *not* increment the lockout counter (last 3 hashes tracked in cloud). |
| **PTA** | Validates Microsoft-recommended hybrid config: Entra threshold &lt; AD DS threshold (2–3× recommended), Entra duration &gt; AD DS duration. |
| **Federated** | Tests cloud-side lockout only; advises on AD FS Extranet Smart Lockout for on-prem coverage. |
| **Compliance pre-flight** | Before the main test, checks PTA/PHS/Cloud configuration and reports PASS/FAIL/WARN. |
| **Output** | Writes a timestamped `.log` and `.csv` of all attempts to the output directory. |

---

## How it works (per attempt)

1. **GET /authorize** — Obtain login context (flow token, sCtx).
2. **POST /login** — Submit credentials via form POST.
3. **Parse response** — 50126 (bad password), 50053 (locked), or MFA (password correct, script stops).

If the modern auth flow cannot be initialized, the script uses **ROPC** (token endpoint) for that attempt or the rest of the run.

---

## Requirements

- **PowerShell 5.1+** (Windows, macOS, or Linux with PowerShell Core)
- A **test user** (UPN) in the target tenant. The browser flow works with tenants that block ROPC or have legacy auth disabled; for lockout testing with wrong passwords, MFA on the account is not an issue (script stops if it detects “password correct, MFA required”).
- **Authorization:** Only run against tenants where you have explicit permission for security testing

---

## Parameters (summary)

| Parameter | Required | Description |
|-----------|----------|-------------|
| `TenantId` | Yes | Entra ID tenant ID (GUID) or domain (e.g. `contoso.onmicrosoft.com`) |
| `UserEmail` | Yes | UPN of the test user (e.g. `testuser@contoso.com`) |
| `DeploymentType` | No | `Auto` (default), `CloudOnly`, `PHS`, `PTA`, or `Federated` |
| `LockoutThreshold` | No | Expected Entra Smart Lockout threshold (default: 10) |
| `LockoutDurationSec` | No | Expected lockout duration in seconds (default: 60) |
| `ADLockoutThreshold` | PTA | On-prem AD DS account lockout threshold |
| `ADLockoutDurationMin` | PTA | On-prem “Reset account lockout counter after” (minutes) |
| `MaxAttempts` | No | Max auth attempts before stopping (default: 150) |
| `DelaySec` | No | Delay between attempts in seconds (default: 2) |
| `ClientId` | No | OAuth2 public client ID used for ROPC fallback (default: Azure AD PowerShell client) |
| `OutputPath` | No | Directory for `.log` and `.csv` (default: current directory) |

For full parameter details and validation rules, see the script’s comment-based help:  
`Get-Help .\Entra-ID-DOS.ps1 -Full`

The script supports **-WhatIf**: use `-WhatIf` to see what would run without sending attempts.

---

## Examples

**Auto-detect deployment and run with defaults (threshold 10, max 150 attempts):**

```powershell
.\Entra-ID-DOS.ps1 -TenantId "contoso.onmicrosoft.com" -UserEmail "testuser@contoso.com"
```

**Force PHS mode (includes hash-tracking replay test):**

```powershell
.\Entra-ID-DOS.ps1 -TenantId "contoso.onmicrosoft.com" -UserEmail "testuser@contoso.com" -DeploymentType PHS
```

**Force PTA and validate against AD DS policy (Entra 10, AD 20, Entra 120s &gt; AD 60s):**

```powershell
.\Entra-ID-DOS.ps1 -TenantId "contoso.onmicrosoft.com" -UserEmail "testuser@contoso.com" -DeploymentType PTA -ADLockoutThreshold 20 -ADLockoutDurationMin 1 -LockoutDurationSec 120
```

**Auto-detect with optional AD DS values for PTA compliance:**

```powershell
.\Entra-ID-DOS.ps1 -TenantId "contoso.onmicrosoft.com" -UserEmail "testuser@contoso.com" -DeploymentType Auto -ADLockoutThreshold 20 -ADLockoutDurationMin 1
```

---

## Entra ID error codes (reference)

| Code | Meaning |
|------|--------|
| AADSTS50126 | Invalid credentials (expected during testing) |
| AADSTS50053 | Account locked by Smart Lockout (target signal) |
| AADSTS50057 | Account disabled |
| AADSTS50074 | Password correct, MFA needed (script stops) |
| AADSTS50076 | MFA required (Conditional Access; script stops) |
| AADSTS50079 | MFA registration required |

The script also detects MFA from the login page (redirect or MFA challenge) and reports `mfa_required` / `mfa_redirect` when the password was correct and the user is sent to MFA.

---

## Output and sensitive data

The script writes:

- **Log file:** `Entra-ID-DOS_yyyyMMdd_HHmmss.log` — timestamped events and PASS/FAIL/WARN.
- **CSV file:** `Entra-ID-DOS_yyyyMMdd_HHmmss.csv` — per-attempt results. Each row includes timestamps, HTTP status, error codes, trace/correlation IDs, **AuthMethod** (`modern` or `ropc-fallback`), and **Phase** (e.g. `lockout-test`, `hash-tracking`, `probe`).

During auto-detection, the script reports **Probe Method** (modern vs ropc-fallback) so you can see which auth path was used for the PTA/PHS probe.

Treat these as sensitive; they document authentication attempts and tenant/account context. Store and retain per your data handling policies.

---

## References

- [Microsoft: Smart Lockout in Entra ID](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-password-smart-lockout)

---

## File layout

```
Entra-ID-DOS/
├── README.md           (this file)
└── Entra-ID-DOS.ps1    (main script)
```

---

## License

Same as the root repository — see [../../LICENSE](../../LICENSE).

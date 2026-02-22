# DeviceStrike  - Device Code Flow for Microsoft Graph

OAuth2 device-code authentication for Microsoft Graph with optional automatic token refresh. Use with Entra ID (Azure AD) tenants and apps you control.

> **Authorized use only.** Use this script only with apps and tenants you own or have explicit permission to test. Storing tokens on disk increases risk -use encrypted storage and restrict permissions if you enable caching.

---

## What it does

- Performs **device-code flow** against Entra ID (`common` or a specific tenant) using a client ID.
- Prompts you to open a verification URL and enter the user code; then retrieves access and refresh tokens.
- Optionally refreshes access tokens automatically before expiry and exposes the access token to the calling session.
- For production, consider MSAL libraries with PKCE instead of this helper.

---

## Requirements

- **PowerShell 5.1+** (Windows, macOS, or Linux with PowerShell Core)
- An Entra ID app registration (or use the built-in client ID for testing; for production use your own app)

---

## Usage

1. Open PowerShell in this folder.
2. Run the script:
   ```powershell
   .\DeviceStrike.ps1
   ```
3. Follow the prompt: open the verification URL in a browser and enter the code shown.
4. The script prints the access token and, in the loop, refreshes it periodically.

**Security notes:**

- If you enable token caching, store the cache on an encrypted disk and restrict filesystem permissions.
- Prefer environment variables or secure input for secrets; avoid hardcoding tokens in files.

---

## File

| File | Description |
|------|-------------|
| `DeviceStrike.ps1` | Device-code flow + optional refresh loop; tokens printed to console. |

---

## License

Same as the root repository  - see [../../LICENSE](../../LICENSE).

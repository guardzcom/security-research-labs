# Credentials

Captured credential material. Handle with care — contains sensitive authentication data.

## Structure

```
creds/{engagement}/
  nthashes.json           — NT hashes from cred_nthash (cloud DCSync)
  mfa_secrets.json        — MFA TOTP secrets from persist_mfa_app
  prt_keys.json           — PRT keys from cred_prt_extract
  cookies.json            — ESTSAUTH cookies from cred_cookie
  passwords.json          — Validated credentials from cred_token (credentials method)
  inventory.md            — Summary: what creds, for whom, how obtained
```

## Auto-populated by

| Tool | What Gets Saved |
|------|----------------|
| `cred_nthash` | NT hashes (cloud DCSync) |
| `cred_prt_extract` | PRT keys + tokens |
| `cred_cookie` | ESTSAUTH cookies |
| `cred_mfa_read` | MFA method details (not secrets — read-only) |
| `persist_mfa_app` | MFA TOTP secret (rogue authenticator) |
| `cred_token` (credentials) | Validated username + password confirmation |

## CLEANUP REQUIRED

All credential material MUST be securely deleted at engagement end.
Cross-reference with `cleanup/` folder for wipe checklist.

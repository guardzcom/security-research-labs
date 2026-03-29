# Tokens

Per-engagement exported token dumps. Separated from the global `~/.entrareaper/tokens.json` cache.

## Structure

```
tokens/{engagement}/
  {alias}_{timestamp}.json    — Full token export (JWT, refresh, PRT, SAML)
  inventory.md                — Live token inventory (alias, resource, expiry, obtained_via)
```

## Auto-populated by

| Tool | What Gets Saved |
|------|----------------|
| `cred_token` | Access + refresh token with metadata |
| `cred_device_code` | Phished token with victim UPN |
| `cred_prt_extract` | PRT keys/token |
| `persist_saml_forge` | Forged SAML token |
| `kerberos_ticket` | Silver Ticket |
| `access_phishing` | Captured phishing token |

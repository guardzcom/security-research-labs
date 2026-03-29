# Certificates

Cryptographic material for persistent access. HIGH sensitivity.

## Structure

```
certs/{engagement}/
  federation/
    backdoor.pfx          — Golden SAML signing cert from persist_federation
    issuer_uri.txt        — Backdoor issuer URI
  devices/
    {device_name}.pfx     — Device cert from persist_device (AAD Join)
    {device_name}.pem     — Device cert (Intune enrollment)
  pta/
    pta_agent.pfx         — PTA agent cert from persist_pta_agent
```

## Auto-populated by

| Tool | What Gets Saved |
|------|----------------|
| `persist_federation` (install) | Golden SAML signing certificate |
| `persist_device` | Device certificate + private key |
| `persist_pta_agent` | PTA agent certificate |

## CLEANUP CRITICAL

Certificates left behind = active backdoors in production.
ALWAYS cross-reference with `persistence/` and `cleanup/` at engagement end.

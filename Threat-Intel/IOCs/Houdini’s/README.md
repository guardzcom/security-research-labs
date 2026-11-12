# Houdini’s Indicators of Compromise

**Goal:** Network, host, and URL-pattern indicators provided for defensive threat hunting and detection.

**Authorized use only.** Handle per your classification and sharing policies.

## Network indicators

| Type | Value |
|------|-------|
| Defanged IPv4 | `104[.]164.46.131` |
| Defanged IPv4 | `153[.]52.162.234` |
| Defanged domain | `blackbox[.]workplacelawyers.online` |
| Defanged domain | `nexoratip[.]com` |
| Defanged domain | `rmm[.]houdini.supportsign.site` |
| Defanged IPv4 and port | `45[.]153.34.178:443` |

## URL indicators

| Defanged URL |
|--------------|
| `https://rmm[.]houdini.supportsign.site/pay?t=RxkhKVYZDLjWd8yR` |
| `http://45[.]153.34.178/panel/` |

## Host indicators

| Type | Value |
|------|-------|
| SHA1 | `f8d674ec766b3a08c115a3e535a992e8ecab636d` |
| File path | `C:\WINDOWS\TEMP\sc.msi` |
| File path | `C:\WINDOWS\TEMP\ScreenConnect.ClientSetup.msi` |

## URL pattern

```text
/Bin/ScreenConnect.ClientSetup.msi?e=Access&y=Guest
```

## License

Same as the root repository — see [../../../LICENSE](../../../LICENSE).

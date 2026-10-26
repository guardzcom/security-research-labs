# ConnectWise Cloud Service Abuse — Indicators

## Incident context

ConnectWise reported unauthorized activity involving its cloud services. The IP address below was used for a password spray on October 13–14 and app authentications on October 15. The application credentials were abused; the application IDs themselves belong to legitimate ConnectWise services.

## Network indicator

| Type | Value (defanged) | Context |
|------|-------------------|---------|
| IP address | `144[.]172.64.128` | Infrastructure hosted by RouterHosting (AS14956); observed in the October 13–14 password spray and October 15 app authentications. |

## User agents

| Value | Context and fidelity |
|-------|----------------------|
| `curl/7.88.1` | Seen during the password spray. Low fidelity by itself; more useful when correlated with the IP address above. |
| `Python-urllib/3.12` | Reported by ConnectWise in suspicious authentication activity and used in the credential changes described in the incident. Common and low fidelity on its own. |
| `python-requests/2.31` | Reported by ConnectWise in suspicious authentication activity. Common and low fidelity on its own. |

## Application and tenant identifiers

| Type | ID | Service / context | Defensive handling |
|------|----|-------------------|--------------------|
| Application ID | `506e08f9-6e9a-4da4-942b-a099a03644ae` | ConnectWise Cloud Backup (formerly SkyKick Backup). Its credential was abused. | Legitimate application; do not block the ID. Disable its service principal in your tenant if unused or as part of incident response. |
| Application ID | `24205314-2b89-4e07-a2a4-579e898a5640` | ConnectWise Cloud Management - MS Teams (formerly SkyKick Cloud Manager - MS Teams). In one tenant it assigned itself Global Administrator and modified other applications. | Legitimate application; do not block the ID. Disable its service principal in your tenant if unused or as part of incident response. |
| Tenant ID | `3f9cd7a0-127a-4ed4-bf06-2f830d5616b7` | Application owner tenant ID observed on the app's service principal events; this is the vendor's tenant. | Use to identify and correlate the vendor-owned service principal events. It is not the affected customer tenant ID. |

## Defensive notes

- Hunt for the IP and correlate it with authentication, password-spray, app-authentication, and credential-change events around October 13–15.
- Treat the user agents as supporting context, not standalone block indicators.
- Review the listed service principals and their credentials, consent, assigned roles, and changes to other applications. Disable the service principal in your tenant where appropriate; do not block the legitimate application IDs tenant-wide.

## Sources

- [ConnectWise Trust Advisories](https://www.connectwise.com/company/trust/advisories)
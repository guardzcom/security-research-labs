# Storm-0940 Indicators of Compromise

**Goal:** Network and HTTP user-agent indicators associated with Storm-0940 activity, for threat hunting and defensive detection.

**Authorized use only.** Handle per your classification and sharing policies.

## Network IP indicators

| IP address | Reported context |
|------------|-----------------|
| `144.172.64.99` | Primary password spray and ConnectWise authentication origin |
| `144.172.64.60` | ConnectWise application sign-in and Graph API activity |
| `144.172.64.128` | ConnectWise application sign-in and Graph API activity |
| `187.15.88.186` | Transient VPN IP; Graph API access context |
| `187.15.90.217` | Transient VPN IP; Graph API access context |
| `187.15.89.186` | Transient VPN IP; Graph API access context |

## HTTP user-agent strings

| User-agent | Reported context |
|------------|-----------------|
| `Python-urllib/3.12` | Observed HTTP user-agent |
| `python-requests/2.31.0` | Observed HTTP user-agent |
| `python-requests/2.34.2` | Observed HTTP user-agent |
| `curl/7.88.1` | Observed HTTP user-agent |
| `azure-toolkit/1.0` | Observed HTTP user-agent |

## Defensive notes

- Hunt for the IP addresses in authentication, ConnectWise application sign-in, and Graph API logs, correlating with the activity context above.
- Treat user-agent strings as supporting indicators rather than standalone proof of compromise; common tools may appear in legitimate activity.
- Validate the observed time range and tenant context before blocking IPs, particularly those identified as transient VPN addresses.

## License

Same as the root repository — see [../../../LICENSE](../../../LICENSE).

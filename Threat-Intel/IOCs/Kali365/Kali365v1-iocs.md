# IOC Package: Kali365 v1

**Purpose:** Network indicators associated with Kali365 v1 infrastructure. Use for threat intelligence enrichment, log review, detection engineering, and defensive blocking where policy allows.

**Authorized use only.** Validate indicators against local telemetry and sharing policy before enforcement.

---

## 1. Package Metadata


| Field                     | Value                                                                                                                        |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Campaign / infrastructure | Kali365 v1                                                                                                                   |
| Indicator classes         | Domains, FQDNs, IPv4 addresses                                                                                               |
| Last updated              | 2026-06-2                                                                                                                   |
| Coverage note             | This package preserves confirmed indicators from the Kali365 v1 IOC list and groups them by provider or infrastructure role. |
| Tracking note             | We are continuing to track Kali365, and more IOCs will be added.                                                             |


---

## 2. Network Indicators - Domains


| Indicator                  | Type            | Category        |
| -------------------------- | --------------- | --------------- |
| `*abt90.org`               | Wildcard domain | Root domain     |
| `*cecyani.xyz`             | Wildcard domain | Root domain     |
| `*democrakidsradio.org`    | Wildcard domain | Root domain     |
| `*duemineral.uk`           | Wildcard domain | Root domain     |
| `*kali365.xyz`             | Wildcard domain | Campaign domain |
| `*loadingdocuments.uk`     | Wildcard domain | Root domain     |
| `*mediaplanung.biz`        | Wildcard domain | Root domain     |
| `*nikadent.icu`            | Wildcard domain | Root domain     |
| `*nysexams.com`            | Wildcard domain | Root domain     |
| `*pohlusa.co`              | Wildcard domain | Root domain     |
| `*stpaulscathedralokc.org` | Wildcard domain | Root domain     |
| `*trulites.com`            | Wildcard domain | Root domain     |
| `*walter-software.com`     | Wildcard domain | Root domain     |


---

## 3. Network Indicators - Subdomains


| Indicator                    | Type | Category                           | Notes                     |
| ---------------------------- | ---- | ---------------------------------- | ------------------------- |
| `*.duemineral.uk`            | FQDN | Campaign subdomain                 |                           |
| `*.loadingdocuments.uk`      | FQDN | Campaign subdomain                 |                           |
| `*.sharepoint-msviewer.com`  | FQDN | Lookalike Microsoft infrastructure |                           |
| `*.userfriendlyinterface.de` | FQDN | Campaign subdomain                 |                           |
| `*.hostlab.net.tr`           | FQDN | Campaign subdomain                 | Many subdomains involved. |


---

## 4. Network Indicators - Cloudflare Pages


| Indicator                | Type | Category         | Notes |
| ------------------------ | ---- | ---------------- | ----- |
| `sharepoint-*.pages.dev` | FQDN | Cloudflare Pages |       |


---

## 5. Network Indicators - Cloudflare Workers

**Note:** These are specific worker hostnames. Avoid broad blocking of shared provider domains such as `workers.dev` unless explicitly approved.


| Indicator       | Type | Category           | Notes |
| --------------- | ---- | ------------------ | ----- |
| `*.workers.dev` | FQDN | Cloudflare Workers |       |


---

## 6. Network Indicators - IP Addresses


| Indicator         | Type | Category               | Notes |
| ----------------- | ---- | ---------------------- | ----- |
| `216.203.20.95`   | IPv4 | Network infrastructure |       |
| `199.91.220.111`  | IPv4 | Network infrastructure |       |
| `162.243.166.119` | IPv4 | Network infrastructure |       |
| `157.230.53.233`  | IPv4 | Network infrastructure |       |
| `5.182.32.166`    | IPv4 | Network infrastructure |       |
| `2.58.56.248`     | IPv4 | Network infrastructure |       |
| `102.89.22.100`   | IPv4 | Network infrastructure |       |
| `167.99.0.116`    | IPv4 | Network infrastructure |       |
| `159.203.163.96`  | IPv4 | Network infrastructure |       |
| `66.179.30.87`    | IPv4 | Network infrastructure |       |
| `103.216.220.117` | IPv4 | Network infrastructure |       |
| `59.11.162.114`   | IPv4 | Network infrastructure |       |
| `18.117.247.159`  | IPv4 | Network infrastructure |       |
| `104.21.32.229`   | IPv4 | Network infrastructure |       |
| `172.67.156.83`   | IPv4 | Network infrastructure |       |
| `104.21.86.181`   | IPv4 | Network infrastructure |       |
| `104.16.80.73`    | IPv4 | Network infrastructure |       |
| `172.67.223.123`  | IPv4 | Network infrastructure |       |
| `45.158.14.18`    | IPv4 | Network infrastructure |       |
| `31.141.216.143`  | IPv4 | Network infrastructure |       |
| `94.154.32.45`    | IPv4 | Network infrastructure |       |
| `45.174.242.246`  | IPv4 | Network infrastructure |       |


## 7. User Agents


| Indicator              | Type               | Category                | Notes                                                    |
| ---------------------- | ------------------ | ----------------------- | -------------------------------------------------------- |
| `Go-http-client`       | User agent         | Go HTTP client          | Generic Go HTTP client user-agent fragment.              |
| `kali365-live/`*       | User agent         | Kali365 client          | Campaign-specific user agent.                            |
| `python-httpx`         | User agent         | Python HTTP client      | HTTPX user-agent fragment.                               |
| `python-requests`      | User agent         | Python HTTP client      | Requests library user-agent fragment.                    |
| `python-requests/*`    | User agent         | Python HTTP client      | Versioned Requests library user agent.                   |
| `Rotating browser UAs` | User agent pattern | Browser client rotation | Rotating browser-style user agents observed or expected. |


---

## License

Same as the root repository - see [../../../LICENSE](../../../LICENSE).

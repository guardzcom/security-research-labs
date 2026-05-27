# IOC Package: Kali365 v1

**Purpose:** Network indicators associated with Kali365 v1 infrastructure. Use for threat intelligence enrichment, log review, detection engineering, and defensive blocking where policy allows.

**Authorized use only.** Validate indicators against local telemetry and sharing policy before enforcement.

---

## 1. Package Metadata

| Field | Value |
|-------|-------|
| Campaign / infrastructure | Kali365 v1 |
| Indicator classes | Domains, FQDNs, IPv4 addresses |
| Last updated | 2026-05-27 |
| Coverage note | This package preserves confirmed indicators from the Kali365 v1 IOC list and groups them by provider or infrastructure role. |

---

## 2. Network Indicators - Domains

| Indicator | Type | Category |
|-----------|------|----------|
| `*abt90.org` | Wildcard domain | Root domain |
| `*cecyani.xyz` | Wildcard domain | Root domain |
| `*democrakidsradio.org` | Wildcard domain | Root domain |
| `*duemineral.uk` | Wildcard domain | Root domain |
| `*kali365.xyz` | Wildcard domain | Campaign domain |
| `*loadingdocuments.uk` | Wildcard domain | Root domain |
| `*mediaplanung.biz` | Wildcard domain | Root domain |
| `*nikadent.icu` | Wildcard domain | Root domain |
| `*nysexams.com` | Wildcard domain | Root domain |
| `*pohlusa.co` | Wildcard domain | Root domain |
| `*stpaulscathedralokc.org` | Wildcard domain | Root domain |
| `*trulites.com` | Wildcard domain | Root domain |
| `*walter-software.com` | Wildcard domain | Root domain |

---

## 3. Network Indicators - Subdomains

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `*.duemineral.uk` | FQDN | Campaign subdomain | |
| `*.loadingdocuments.uk` | FQDN | Campaign subdomain | 
| `*.sharepoint-msviewer.com` | FQDN | Lookalike Microsoft infrastructure | |

---

## 4. Network Indicators - Cloudflare Pages

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `sharepoint-*.pages.dev` | FQDN | Cloudflare Pages | |

---

## 5. Network Indicators - Cloudflare Workers

**Note:** These are specific worker hostnames. Avoid broad blocking of shared provider domains such as `workers.dev` unless explicitly approved.

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `*.workers.dev` | FQDN | Cloudflare Workers | |

---

## 6. Network Indicators - IP Addresses

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `216.203.20.95` | IPv4 | Network infrastructure | |
| `199.91.220.111` | IPv4 | Network infrastructure | |
| `162.243.166.119` | IPv4 | Network infrastructure | |
| `157.230.53.233` | IPv4 | Network infrastructure | |
| `5.182.32.166` | IPv4 | Network infrastructure | |
| `102.89.22.100` | IPv4 | Network infrastructure | |
| `167.99.0.116` | IPv4 | Network infrastructure | |
| `159.203.163.96` | IPv4 | Network infrastructure | |


## 7. User Agents

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `Go-http-client` | User agent | Go HTTP client | Generic Go HTTP client user-agent fragment. |
| `kali365-live/*` | User agent | Kali365 client | Campaign-specific user agent. |
| `python-httpx` | User agent | Python HTTP client | HTTPX user-agent fragment. |
| `python-requests` | User agent | Python HTTP client | Requests library user-agent fragment. |
| `python-requests/*` | User agent | Python HTTP client | Versioned Requests library user agent. |
| `Rotating browser UAs` | User agent pattern | Browser client rotation | Rotating browser-style user agents observed or expected. |

---


## License

Same as the root repository - see [../../../LICENSE](../../../LICENSE).

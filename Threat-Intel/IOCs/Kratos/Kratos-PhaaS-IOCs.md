# IOC Package: Kratos PhaaS

**Purpose:** Indicators and behavioral context for the Kratos phishing-as-a-service (PhaaS) kit, including asset fingerprints, exfiltration endpoints, domains, hashes, and detection-focused observations.

**Authorized use only.** Handle per your classification and sharing policies.

---

## 1. Threat summary

- **Threat:** Kratos PhaaS / phishing kit infrastructure
- **Observed behaviors:** Fake Microsoft authentication-themed phishing pages, browser-side asset loading, and exfiltration to PHP endpoints.
- **Additional context:** Cloudflare Turnstile, DOMPurify 3.2.6, and a browser tab titled “Authentication” were observed as part of the experience.
- **Behavioral fingerprinting:** The actor appears to use multiple or rotating User-Agent strings within the same attack flow, which can help distinguish automation and browser-based phishing activity from simpler single-visit traffic.
- **Temporal fingerprinting:** In some cases, the same campaign or infrastructure can resume or remain active again after a few days, so short-gap reappearance should be treated as related activity rather than a fresh, isolated event.

---

## 2. Campaign context 

- It was first observed Kratos activity in its sandbox in January 2026, and operator-side OSINT indicated the admin panel had been active since September 2025.
- The article describes V0, V1, and V2 as belonging to the same Kratos service rather than three unrelated actors.
- Shared infrastructure and content across generations were noted in the report: `razen[.]online`, `theoceanac[.]online`, `jumpast[.]es`, and `enerdizerandtron[.]de` were reused across V1/V2; the `lg.svg` file used in V1 was byte-for-byte identical to the `dsa.svg` file in V2; and the shared `styles.css` hash `c447e75f1029ed7a5882add16bcd13ad44be3bd47c93c830ff39185e23d25ebb` was observed across 636 tasks.
- Victimology from the article points to Microsoft 365 as the primary impersonation theme, with 1,365 sandbox tasks reaching `login.live.com` or `microsoftonline.com`, 412 cases classified as “Fake Microsoft Authentication Page,” and 148 suspected victim organizations, with a strong concentration in Spain and Southern Europe.
- The report also notes that many phishing emails passed through corporate email filters or secure email gateways before reaching the sandbox, often using lures around shared documents, DocuSign, or invoices.

## 3. Primary asset fingerprints (detection)

| Variant | Fingerprint | Notes |
|--------|-------------|-------|
| **V1** | `*/assets/img/barr.svg` + `*/assets/img/lg.svg` | Loaded together in the same session |
| **V2** | `*dsa.svg` + `*sid.gif` + `*imag.jpg` | Same session |

---

## 4. Asset content hashes (SHA-256)

| Asset | Hash |
|------|------|
| `lg.svg` | `cd231b895bbcd7154b81df1e065bf02f1ec667b920c8b6d23308cd509833b5ea` |
| `barr.svg` | `949895df17148c5ea29f190d2619a14b3ec648425b9cc3c5a1423553c16f3898` |
| `ani.gif` | `9d1a1a5e3b5e5de8a6c76ded7a01fa01709d426232b0048c9ee6ba0c5c1b8b42` |
| `styles.css` | `c447e75f1029ed7a5882add16bcd13ad44be3bd47c93c830ff39185e23d25ebb` |

> `styles.css` is associated with a shared footprint across V1 and V2 and was observed connecting 636 tasks.

---

## 5. Exfiltration endpoints

| Variant | Endpoint |
|--------|----------|
| **V0** | `*/PTT/SOft/mini.php` (also referenced as `*/SOft/mini.php`) |
| **V1** | `*/next.php`, `*/nex.php`, `*/n3xt.php`, `*/officers*eur.php` |
| **V2** | `*/save.php` |

---

## 6. Domains / hosting infrastructure

| Domain | Notes |
|--------|-------|
| `dwbud.vilaribit.com` | Early V0 domain; `/PTT/SOft` path |
| `razen[.]online` | — |
| `theoceanac[.]online` | — |
| `jumpast[.]es` | — |
| `enerdizerandtron[.]de` | — |
| `abal[.]my` | — |
| `starwellmedia[.]com` | — |
| `aabiz[.]de` | — |
| `aspireglobal[.]ltd` | — |
| `buenne[.]de` | — |
| `dufllot[.]sbs` | — |
| `espaciocf[.]de` | — |
| `ihrsupportcenter[.]de` | — |
| `ilersls[.]org` | — |
| `aaalen[.]de` | — |
| `rundwasser[.]de` | — |
| `smartcontrolengineer[.]com` | — |
| `sonnenbrillenspot[.]de` | — |
| `trisrnareprjdocz[.]com` | — |
| `crm-technik[.]de` | Shared parent; review before blocking |
| `klenpare[.]com` | Wildcard/shared parent |
| `uvarnix[.]cfd` | Wildcard/shared parent |
| `xavon[.]sbs` | Wildcard |

---

## 7. IP address

| Type | Value |
|------|-------|
| **Operator IP** | `41.128.0.x/24` |

> Reported as an operator IP in Egypt.

---

## 8. Engine signatures

- Kratos exfil activity observed — `/next.php`
- Kratos exfil HTTP activity observed — `/SOft/mini.php`
- Xbit setter activity for `barr.svg`, `lg.svg`, `ani.gif`, and `bg.png`
- Generic phishkit-related URL chain observed (`/assets/img/*`)
- Generic phishkit exfil activity observed (`/next.php`)
- Domain chain identified as phishing (challengepoint)

---

## 9. Behavioral indicators

- Cloudflare Turnstile identified as **challengepoint**
- **DOMPurify 3.2.6** observed in the page stack
- Browser tab titled **Authentication**
- “Fake Microsoft Authentication Page” incident narrative
- Animated envelope with “Loading in progress…” over a blurred invoice
- `Einvoice Beta` footer
- WebSocket activity observed as a risk indicator (not proof of AiTM)
- `submitData()` function sending `di` and `pr` parameters
- Multiple or rotating User-Agent strings observed across the same attack flow; useful as a supporting fingerprint when combined with asset and exfiltration patterns
- Delayed reactivation or continued operation after a few days, suggesting short-term dormancy or staged campaign activity

---

## 10. URL path tokens (affiliate fingerprints)

- `factura`
- `dgt`
- `Clbsrus`
- `Svgclur`
- `Suclers`
- `paidoffice`
- `yhwh`
- `elroi`

---

## Footer — source

**Source note:** Intelligence provided as a structured IOC package for defensive use, supplemented with campaign context from the ANY.RUN analysis article on Kratos PhaaS account takeover activity.

**Related:** [Guardz Security Research Labs (GitHub)](https://github.com/guardzcom/security-research-labs)

---

## License

Same as the root repository — see [../../../LICENSE](../../../LICENSE).

---

Supplemental intelligence reference: this IOC package incorporates selected campaign observations from the ANY.RUN analysis article on Kratos PhaaS account takeover activity — https://any.run/cybersecurity-blog/kratos-phaas-account-takeover/

Additional reference: Guardz ITDR research and related threat context on Kratos PhaaS activity 

# IOC Package: OnForge - Tech Support Scam Campaign

**Purpose:** Indicators of compromise for a browser-based tech-support scam campaign using fake Microsoft security alerts, phone numbers, live chat (Tawk.to), and assets hosted under `on-forge.com` and related redirect domains. Intended for CTI, detection engineering, and defensive blocking where policy allows.

---

## 1. Package metadata

| Field | Value |
|--------|--------|
| **Campaign / infrastructure** | OnForge (`on-forge.com` subdomains and related artifacts) |
| **Classification** | Fraud / tech-support scam (scareware-style browser lock) |
| **Source** | SentinelOne Deep Visibility |
| **Last updated** | 2026-04-14 |
| **Coverage note** | Broader campaign telemetry referenced as 96+ domains, 18+ phones, 4 IPs, 2 Tawk.to accounts; this file lists confirmed samples and patterns at time of publication. |

---

## 2. Campaign summary

The activity clusters on **`*.on-forge.com`**, where short-lived subdomains serve HTML and static assets that mimic Microsoft security messaging, inject callback **phone numbers**, and use aggressive browser behavior (fullscreen overlay, keyboard focus traps, looping audio) to pressure victims into calling operators. **Tawk.to** account identifiers appear in the same operational context as the scam pages.

Subdomains often align with **query-parameter variants** used in landing URLs (for example `ph0ne=`, `Anph=`, `bcda=`, `Kuph=`). Additional naming styles include long random-looking labels with an embedded hash segment, and **`usa-monday-admin-<8 chars>`** style hosts. Some hosts return **HTTP 522** (previously live scam pages, torn down). **Redirect entry points** on unrelated TLDs funnel traffic toward the on-forge infrastructure.

---

## 3. Network indicators - domains

**Note:** Research surfaced **dozens of domains** across **dozens of campaigns**, every hostname we classified in this set still **relies on the same OnForge** (`on-forge.com`) **platform**. The **Category** column in the table below is our label for **each domain’s type** (variant, lifecycle, or role).

**Recommendation:** Where policy permits, a **wildcard DNS or proxy deny** for `*.on-forge.com` reduces exposure to newly generated subdomains. Validate for collateral impact before enforcing at the perimeter.

| FQDN | Category | Notes |
|------|----------|--------|
| `*.on-forge.com` | Wildcard block (recommended) | Catches ephemeral subdomains |
| `ikdnknskgjnsnflsjnfljsdlsjd-uynmyovf.on-forge.com` | Confirmed scam subdomain | |
| `kjhgfdfghjklkjfj.on-forge.com` | Confirmed scam subdomain | |
| `kasdjfkasjd8uawkjnmzmnvmdsfhj27jajak03.on-forge.com` | Confirmed scam (variant A: `ph0ne=`) | |
| `nbvcxcghjmmn.on-forge.com` | Confirmed scam (variant B: `Anph=`) | |
| `usa-monday-admin-4wq5elwf.on-forge.com` | Confirmed scam (variant C: `bcda=`) | |
| `exorepusvir-osgfaw8g.on-forge.com` | Confirmed scam (variant D: `Kuph=`) | |
| `nvcvbnnvghvbj.on-forge.com` | Dead / torn down (522; former scam page) | |
| `blajdlajndlakjdlajdla-gpw2vpji.on-forge.com` | Keyboard mash + Forge hash (type B) | |
| `nequi-allianze-tramites.on-forge.com` | Other scam on same infrastructure | |
| `segurosn.lat` | Redirect entry point | |
| `dhjanask.online` | Redirect entry point | Third-party context: [VirusTotal domain report](https://www.virustotal.com/gui/domain/dhjanask.online/details) |

---

## 4. Network indicators — IP addresses

| Type | Value | Notes |
|------|--------|--------|
| IPv4 | `104.18.10.251` | Validate context before blocking; may reflect shared or CDN-fronted infrastructure. |
| IPv4 | `104.18.11.251` | Same as above. |
| IPv4 | `15.204.43.250` | |
| IPv4 | `104.45.153.136` | |

---

## 5. Phone numbers

| Region / type | Number |
|----------------|--------|
| UK freephone | `08085310436` |
| UK freephone | `080008xxxxx` |
| US toll-free | `1833926xxxx` |
| US toll-free | `57436xxxxx`  |

---

## 6. Tawk.to account identifiers

| Account ID |
|------------|
| `69cd421fb8aa781c3b30ed16` |
| `68d549cbc6b9a0194dd28338` |

---

## 7. File hashes - scam page assets (SHA256)

| SHA256 | File | Type | Purpose / description |
|--------|------|------|------------------------|
| `298deae4484ebe1f2cf64669197a880d08f1c25852317d16e0feb9880a7b83fb` | `custom.js` | JavaScript | Scam engine: fullscreen hijack, keyboard lock, audio trap |
| `e5a7faad39c23549b61051a5e50dc7d1a8bc63411b825619d1301334529687c2` | `index.html` | HTML | Main scam page: fake Microsoft Security alert, phone injection |
| `915cbddff7dab2554948e6cd382450219f0e71c7a9facb1f4f362d37a1cf880d` | `bg.png` | PNG | Explicit adult content (scareware shock image) |
| `948b1331677d0f9991d50376bfba436033c5a9cc5919cf9f74c03424b6f3e342` | `back.jpg` | JPEG | Fake Microsoft Support page screenshot |
| `7497f3d08e577650f4a8f8e835c9cb8369f84693385530733c4269e2636bd997` | `custom.css` | CSS | Hidden cursor, pulsing animation, fullscreen overlay styling |
| `316e6a6737bd296ab30aca2ef7fa36f119d15786a2432d01e31fdc130272f15c` | `defend.png` | PNG | Windows Defender shield icon |
| `ee4bc5fe81fa7c1e8497d79c9c8a96485df217092d334e9b48fa8840fed11d03` | `ms.png` | PNG | Microsoft four-square logo |
| `3b531d403dc8ce7cbb0efb1a0c307cfb2bbaaf21feaff9f3546f13bebda71887` | `v.jpg` | JPEG | Two laptops with shield (scan illustration) |
| `3821ef20f5904fdb993e34d87ff8fb9c5786a382efb0eeee8b4f00c91428b701` | `x.png` | PNG | Warning / close icon |
| `0589be7715d2320e559eae6bd26f3528e97450c70293da2e1e8ce45f77f99ab1` | `beep1.mp3` | MP3 | Alarm beep (loops) |

---

## 8. URL patterns and detection regex

### 8.1 Query parameter tokens (blocking / hunting)

Block or alert on request URIs containing these substrings when paired with suspicious referrers or the on-forge host class:

- `ph0ne=`
- `Anph=`
- `bcda=`
- `Kuph=`

### 8.2 Broad pattern — on-forge.com with phone-style parameters

```regex
https?://[a-z0-9\-]{5,60}\.on-forge\.com/.+\?(ph0ne|Anph|bcda|Kuph)=
```

### 8.3 Type B subdomains (keyboard mash + Forge hash segment)

```regex
[a-z]{15,30}-[a-z0-9]{8}\.on-forge\.com
```

### 8.4 Type C subdomains (`usa-monday-admin`)

```regex
usa-monday-admin-[a-z0-9]{8}\.on-forge\.com
```

---

## 9. Operational and defensive notes

- **DNS / HTTP blocking:** Wildcard denial of `on-forge.com` is effective against rotation but requires change control; document exceptions if any legitimate use appears (unlikely for this campaign class).
- **IP blocking:** Several listed IPv4 addresses may be shared CDN or hosting; prefer **domain and URL** controls and **hash** blocks on proxies and endpoints where possible.
- **User education:** Tech-support scams that cite “Microsoft Security” and demand a phone call remain a high-volume fraud pattern; reinforce official support channels and browser reset procedures.
- **Reporting:** Route confirmed fraud URLs and phone numbers through your national fraud reporting and telecom abuse workflows as applicable.

---

## Footer - source

**Primary reference:** SentinelOne Deep Visibility research, consolidated **2026-04-14** (Guardz Security Research Labs).

**Related:** [Guardz Security Research Labs (GitHub)](https://github.com/guardzcom/security-research-labs)

---

## License

Same as the root repository — see [../../../LICENSE](../../../LICENSE).

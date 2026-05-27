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

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `*abt90.org` | Wildcard domain | Root domain | |
| `*cecyani.xyz` | Wildcard domain | Root domain | |
| `*democrakidsradio.org` | Wildcard domain | Root domain | |
| `*duemineral.uk` | Wildcard domain | Root domain | |
| `*kali365.xyz` | Wildcard domain | Campaign domain | Wildcard-style indicator as provided. |
| `*loadingdocuments.uk` | Wildcard domain | Root domain | |
| `*mediaplanung.biz` | Wildcard domain | Root domain | |
| `*nikadent.icu` | Wildcard domain | Root domain | |
| `*nysexams.com` | Wildcard domain | Root domain | |
| `*pohlusa.co` | Wildcard domain | Root domain | |
| `*stpaulscathedralokc.org` | Wildcard domain | Root domain | |
| `*trulites.com` | Wildcard domain | Root domain | |
| `*walter-software.com` | Wildcard domain | Root domain | |

---

## 3. Network Indicators - Subdomains

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `api.duemineral.uk` | FQDN | Campaign subdomain | |
| `v2.duemineral.uk` | FQDN | Campaign subdomain | |
| `auth.loadingdocuments.uk` | FQDN | Campaign subdomain | |
| `panel.loadingdocuments.uk` | FQDN | Campaign subdomain | |
| `login.sharepoint-msviewer.com` | FQDN | Lookalike Microsoft / SharePoint infrastructure | |
| `ls.sharepoint-msviewer.com` | FQDN | Lookalike Microsoft / SharePoint infrastructure | |

---

## 4. Network Indicators - Cloudflare Pages

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `sharepoint-63m.pages.dev` | FQDN | Cloudflare Pages | |
| `sharepoint-81c.pages.dev` | FQDN | Cloudflare Pages | |
| `tryingdocusign.pages.dev` | FQDN | Cloudflare Pages | |

---

## 5. Network Indicators - Cloudflare Workers

**Note:** These are specific worker hostnames. Avoid broad blocking of shared provider domains such as `workers.dev` unless explicitly approved.

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `access-base-yz6o.p-uhv4e1ee.workers.dev` | FQDN | Cloudflare Workers | |
| `access-file-z1or.steve-c57.workers.dev` | FQDN | Cloudflare Workers | |
| `acqxx-nikg-5cub.p-8kehah0a.workers.dev` | FQDN | Cloudflare Workers | |
| `app-edge-8bqf.p-j65j3f1q.workers.dev` | FQDN | Cloudflare Workers | |
| `base-flow-38xb.p-l3bhkqec.workers.dev` | FQDN | Cloudflare Workers | |
| `base-mail-w7v5.p-onnw7z7w.workers.dev` | FQDN | Cloudflare Workers | |
| `box-note-1qu3.p-xqs8hnkj.workers.dev` | FQDN | Cloudflare Workers | |
| `chrji-fhav-oz04.p-qtlv10l7.workers.dev` | FQDN | Cloudflare Workers | |
| `cloud-access-03pv.bdeda974c99320a3040456b8.workers.dev` | FQDN | Cloudflare Workers | |
| `cloud-access-uc53.p-vy4za09n.workers.dev` | FQDN | Cloudflare Workers | |
| `cloud-link-j46j.p-zltii3tp.workers.dev` | FQDN | Cloudflare Workers | |
| `cloud-view-hb2b.boom-book.workers.dev` | FQDN | Cloudflare Workers | |
| `core-box-iz5s.reckagrace.workers.dev` | FQDN | Cloudflare Workers | |
| `core-flow-0np5.pdfonlinedocsdocs-outlook-com-s-account.workers.dev` | FQDN | Cloudflare Workers | |
| `core-mail-etk1.p-b8eaz6oe.workers.dev` | FQDN | Cloudflare Workers | |
| `core-portal-g1cv.ran04don.workers.dev` | FQDN | Cloudflare Workers | |
| `data-doc-sfym.p-50ds7vs5.workers.dev` | FQDN | Cloudflare Workers | |
| `data-drive-bd71.p-4bpdi3hp.workers.dev` | FQDN | Cloudflare Workers | |
| `data-form-f5at.p-lvqyivvk.workers.dev` | FQDN | Cloudflare Workers | |
| `doc-note-82oj.p-ll66wpsr.workers.dev` | FQDN | Cloudflare Workers | |
| `doc-open-z062.p-4510rez0.workers.dev` | FQDN | Cloudflare Workers | |
| `drive-edge-lzl0.p-8pd549l5.workers.dev` | FQDN | Cloudflare Workers | |
| `drive-mail-wmou.pwyv30sj.workers.dev` | FQDN | Cloudflare Workers | |
| `egvmu-ejrp-8rmc.royalbase3.workers.dev` | FQDN | Cloudflare Workers | |
| `file-base-ggoa.p-yxcqepyg.workers.dev` | FQDN | Cloudflare Workers | |
| `file-doc-uhug.p-ao3eomo9.workers.dev` | FQDN | Cloudflare Workers | |
| `file-drive-g180.p-lmilwl5o.workers.dev` | FQDN | Cloudflare Workers | |
| `file-share-9p2m.papastrious.workers.dev` | FQDN | Cloudflare Workers | |
| `file-sync-tczr.p-77iqt3w6.workers.dev` | FQDN | Cloudflare Workers | |
| `flow-open-7ff0.p-ygj98iy2.workers.dev` | FQDN | Cloudflare Workers | |
| `flow-store-gyoz.p-o9vztksz.workers.dev` | FQDN | Cloudflare Workers | |
| `form-cloud-t655.p-oejdzrsz.workers.dev` | FQDN | Cloudflare Workers | |
| `form-doc-wyiy.p-xqs8hnkj.workers.dev` | FQDN | Cloudflare Workers | |
| `form-hub-lfct.p-utpgo2kb.workers.dev` | FQDN | Cloudflare Workers | |
| `gmkcb-bdxh-03l9.c-cmd509g3.workers.dev` | FQDN | Cloudflare Workers | |
| `hub-app-8ee1.p-kegps6il.workers.dev` | FQDN | Cloudflare Workers | |
| `hub-flow-2qs3.p-qn7zcudl.workers.dev` | FQDN | Cloudflare Workers | |
| `link-app-jhzt.p-ux0nzmb5.workers.dev` | FQDN | Cloudflare Workers | |
| `mail-link-zkfq.p-qjt4uz2n.workers.dev` | FQDN | Cloudflare Workers | |
| `net-open-55eu.p-r3k6zulh.workers.dev` | FQDN | Cloudflare Workers | |
| `net-web-qo53.p-2f5hwpkd.workers.dev` | FQDN | Cloudflare Workers | |
| `net-web-wnqd.p-8r4315uz.workers.dev` | FQDN | Cloudflare Workers | |
| `note-access-nj2w.rob-c2d.workers.dev` | FQDN | Cloudflare Workers | |
| `open-share-njlb.p-l4yg6fjb.workers.dev` | FQDN | Cloudflare Workers | |
| `oynfe-roik-zlpe.c-qtkfck53.workers.dev` | FQDN | Cloudflare Workers | |
| `page-core-sv2l.p-anmh2mbc.workers.dev` | FQDN | Cloudflare Workers | |
| `page-mail-vm24.p-8xzcvt1x.workers.dev` | FQDN | Cloudflare Workers | |
| `page-sync-4pib.p-qtlv10l7.workers.dev` | FQDN | Cloudflare Workers | |
| `pgfqi-epwc-d1t6.p-1razygxw.workers.dev` | FQDN | Cloudflare Workers | |
| `portal-cloud-cs2c.p-ewgaj1gg.workers.dev` | FQDN | Cloudflare Workers | |
| `portal-share-tj8e.p-50ds7vs5.workers.dev` | FQDN | Cloudflare Workers | |
| `pwjss-npaw-3soj.mary-3fb.workers.dev` | FQDN | Cloudflare Workers | |
| `rwlha-qilv-ic1v.p-rrw76os2.workers.dev` | FQDN | Cloudflare Workers | |
| `secure-link-ek3t.c-kzevzz5a.workers.dev` | FQDN | Cloudflare Workers | |
| `share-portal-r6le.p-deum4gog.workers.dev` | FQDN | Cloudflare Workers | |
| `store-open-rc2p.p-ko5g87h5.workers.dev` | FQDN | Cloudflare Workers | |
| `sync-link-z79k.bartlett-pamela.workers.dev` | FQDN | Cloudflare Workers | |
| `sync-page-pwra.p-rrw76os2.workers.dev` | FQDN | Cloudflare Workers | |
| `sync-portal-jumn.p-ajmeubmp.workers.dev` | FQDN | Cloudflare Workers | |
| `sync-store-ur85.p-lboid22u.workers.dev` | FQDN | Cloudflare Workers | |
| `sync-vault-lpwq.p-zhge84gd.workers.dev` | FQDN | Cloudflare Workers | |
| `tiny-water-f307.eggzhan.workers.dev` | FQDN | Cloudflare Workers | |
| `vault-access-pg0o.misty-pine-60bb.workers.dev` | FQDN | Cloudflare Workers | |
| `vault-cloud-maou.p-afw8621d.workers.dev` | FQDN | Cloudflare Workers | |
| `vault-web-s3ue.p-y10utwre.workers.dev` | FQDN | Cloudflare Workers | |
| `view-base-5vpr.3mdcy99f8511wpsebllpbkjizyg3run6.workers.dev` | FQDN | Cloudflare Workers | |
| `view-open-jiif.bryanray1104.workers.dev` | FQDN | Cloudflare Workers | |
| `view-portal-exuw.b875e3d068d947ba88099fe9.workers.dev` | FQDN | Cloudflare Workers | |
| `view-sync-9r5b.p-y9fhvs2p.workers.dev` | FQDN | Cloudflare Workers | |

---

## 6. Network Indicators - IP Addresses

| Indicator | Type | Category | Notes |
|-----------|------|----------|-------|
| `216.203.20.95` | IPv4 | Network infrastructure | |
| `199.91.220.111` | IPv4 | Network infrastructure | |
| `167.99.0.116` | IPv4 | Network infrastructure | |
| `162.243.166.119` | IPv4 | Network infrastructure | |
| `157.230.53.233` | IPv4 | Network infrastructure | |
| `102.89.22.100` | IPv4 | Network infrastructure | |
| `159.203.163.96` | IPv4 | Network infrastructure | |

---

## 7. Defensive Notes

- Prefer exact FQDN blocking for shared-hosting indicators such as Cloudflare Workers and Cloudflare Pages.
- Treat the IP addresses as infrastructure indicators; validate ownership and hosting context before perimeter blocking.
- Use the lookalike Microsoft / SharePoint domains for phishing and credential-harvesting hunts.

---

## License

Same as the root repository - see [../../../LICENSE](../../../LICENSE).

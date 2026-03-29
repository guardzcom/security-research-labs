# IOC Package: Akira Ransomware — Case Notes (“Seven Seconds to Stop Akira”)

**Purpose:** Indicators and incident context from a single defended-environment engagement, formatted for CTI and detection use. **Malware sample is a per-victim build** and may not match public corpus hashes.

---

## 1. Source intelligence

| Field | Value |
|--------|--------|
| **Report title** | Seven Seconds to Stop Akira |
| **Publisher** | Guardz |
| **Author** | Elli Shlomo |
| **Publication date** | 2026-03-29 |
| **Threat** | Akira ransomware (RaaS) |
| **MITRE group** | [G1024 — Akira](https://attack.mitre.org/groups/G1024/) |

---

## 2. Incident summary (narrative)

- **Deployment:** Akira executed **T1021.002** (SMB) lateral deployment across **20 endpoints** from a single **unmanaged internal host** (no EDR agent, no managed inventory record) at **11:43:39 UTC**.
- **Detection:** Behavioral EDR (**SentinelOne**) fired at **T+7 seconds** on execution patterns (not file hash): ransomware file write (multiple threat IDs), ransomware file rename, known ransomware extensions; parallel **kill → quarantine → remediate → rollback** per endpoint.
- **Primary payload:** Terminated at **T+7 seconds**; **VSS destruction (T1490)** occurred; **215 of 220 files** recovered via EDR snapshot rollback (**~97.7%** over 9 rollback operations).
- **Ransom note:** `akira_readme.txt` appeared **~119 minutes 55 seconds** after initial block (**13:43:34 UTC** per article timeline), from a **secondary process** / lineage attributed in the article to **SentinelOne Storyline Group `4B9AC41CB65366EA`** and **Process UID `005DDBECDAEFF636`** (active lateral-capable thread post-containment window per forensic narrative).
- **Static IOCs:** Per-victim binary **did not match** [CISA Advisory AA24-109A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a) known corpus as of **2026-03-26** (per article).

---

## 3. File hashes (malware sample)

| Type | Value | Notes |
|------|--------|--------|
| **SHA256** | `c9062a3b3036d3006a3505ed2e916622c4ddc580f6785a94e3f91165adcd0483` | Per-victim build; not in AA24-109A set (per article) |
| **SHA1** | `43b76ecca62da78153fc3a99406a99397f731b47` | Same sample |
| **MD5** | `88c31bc7893def6ba5817fdefed13361` | Same sample |

---

## 4. Ransom note

| Attribute | Value |
|-----------|--------|
| **Filename** | `akira_readme.txt` |
| **SHA1** | `eb2e4058d9575f989725164fcf544f05c2bc2e86` |

*(Article states portions of the note were written to disk long after the primary payload was blocked.)*

---

## 5. File system indicators

| Indicator | Value |
|-----------|--------|
| **Encrypted extensions** | `.akira` (primary); `.arika` observed in **2** instances (per article) |
| **Ransom note** | `akira_readme.txt` |
| **Extension types targeted (listed)** | `.docx` `.doc` `.txt` `.pdf` `.xlsx` `.xls` `.ps1` `.db` `.sqlite` `.url` |

### SentinelOne (tenant-specific correlation)

| Artifact | Value |
|----------|--------|
| **Process UID** | `005DDBECDAEFF636` |
| **Storyline Group** | `4B9AC41CB65366EA` |

---

## 6. Network indicators

| Type | Value (defanged) |
|------|-------------------|
| **Tor (C2, per article)** | `akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id[.]onion` |
| **Tor (leak site, per article)** | `akira1iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad[.]onion` |
| **Internal origin (class)** | RFC1918 **/24** segment; unmanaged host; **no EDR** (per article—exact subnet not published) |

---

## 7. MITRE ATT&CK mapping (from article)

| ID | Technique | Context in article |
|----|-----------|---------------------|
| T1021.002 | SMB/Windows Admin Shares | Lateral deployment to 20 endpoints |
| T1490 | Inhibit System Recovery | VSS destruction |
| T1562 | Impair Defenses | Hypothesis: EDR removal on patient zero (*Probable* in coverage) |

---

## 8. Threat actor profile (open source, per article)

- Ransomware-as-a-service; article cites **~$244M** extortion revenue and **250+** victims since **March 2023** (figures as stated in blog).
- **Double extortion:** exfiltration precedes encryption in confirmed engagements; note references **`.arika`** / **`.akira`**, pre-encryption theft, leak-site pressure, test decryption, insurance/finance-aware wording.

---

## 9. Defensive notes (high level)

- **Coverage gap:** Unmanaged asset vs RMM inventory vs EDR enrollment delta cited as patient-zero root cause; reconciliation and SLA remediation recommended.
- **Lateral movement:** Article recommends **default-deny inbound** on workstations with **explicit SMB allowlists** (e.g. file servers only) and **segmentation** (workstation / server / unmanaged VLANs).

---

## Footer — source

**Primary reference:** [Seven Seconds to Stop Akira](https://guardz.com/blog/seven-seconds-to-stop-akira/) — Guardz blog, 2026-03-29.

**Related:** [Guardz Security Research Labs (GitHub)](https://github.com/guardzcom/security-research-labs)

---

## License

Same as the root repository — see [../../../LICENSE](../../../LICENSE).

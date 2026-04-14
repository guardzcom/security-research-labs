# IOCs (Indicators of Compromise)

**Goal:** Indicators of compromise—hashes, domains, IPs, URLs, file names, or other artifacts from research and investigations—for threat intelligence, detection rules, and sample sets. Each collection lives in its own subfolder with a README.

**Authorized use only.** Do not add IOCs from ongoing investigations without proper authorization. Handle per your classification and sharing policies.

---

## Contents

| Folder | Description |
|--------|-------------|
| [Akira/](Akira/) | Akira ransomware IOCs and case notes from Guardz “Seven Seconds to Stop Akira” (hashes, ransom note, filesystem and Tor indicators, SentinelOne storyline artifacts, MITRE G1024 context). |
| [OAuth-abuse/](OAuth-abuse/) | OAuth consent phishing and token-theft IOCs: malicious app IDs, redirect URLs, file/behavior indicators, hunting signals (Microsoft-Intel-OAuth.md). |
| [OnForge/](OnForge/) | on-forge.com tech-support scam IOCs: domains, IPs, phones, Tawk.to IDs, file hashes, URL parameters, detection regex (OnForge-IOCs.md; SentinelOne Deep Visibility). |

---

## License

Same as the root repository — see [../../LICENSE](../../LICENSE).

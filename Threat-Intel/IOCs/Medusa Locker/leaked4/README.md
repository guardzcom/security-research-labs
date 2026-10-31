# Medusa Locker `.leaked4` Indicators of Compromise

**Goal:** Record file, network, and behavioral indicators associated with the Medusa Locker `.leaked4` variant for defensive research and detection.

**Authorized use only.** Handle these indicators according to your classification and sharing policies. Network indicators are defanged for safe handling.

## Indicators

| Indicator | Value |
|-----------|-------|
| Ransom note | `RANSOM_NOTE.html` — 3,902 bytes; SHA-1: `e9cd16b812ce052939448df36001e013710c3cd0` |
| Encrypted-file extension | `.leaked4` |
| Instruction file named in the ransom note | `HOW_TO_RECOVER_DATA.html` |
| Tor negotiation portal | `723pt5dc2plfexrfvudhdhzvesgesqbcl4yivijjubptnogukxxv3hqd[.]onion` |
| Tor leak blog | `hxxps://5tqdhriujqb7tb3cw3i3ffwaamjtnph6wsijdbecscyqhii3jbjz2rqd[.]onion/` |
| Contact addresses | `derckader2026[@]gmail[.]com`; `derckader2026[@]outlook[.]com` |
| Credential dump pattern | `C:\Windows\Temp\` followed by 8 random letters and `.tmp`; 32 KB; written by a remote session after Remote Registry starts |
| Guardz EDR alerts | Security Hive Save; Syskey Query |

## License

Same as the root repository — see [../../../../LICENSE](../../../../LICENSE).

---
name: New Attack Scenario
about: Submit a new attack scenario for inclusion in EntraReaper
title: "[SCENARIO] S__: "
labels: scenario
assignees: ''
---

## Scenario Overview

- **Name:** (e.g., "OAuth Consent Phishing via Custom App")
- **Category:** (e.g., Credential Access, Persistence, Lateral Movement)
- **Hat:** WHITE / GRAY / BLACK
- **Perspective:** EXTERNAL / EXTERNAL+CRED / INTERNAL / PARTNER / PRIVILEGED
- **OPSEC Level:** Silent / Low / Medium / HIGH / LOUD
- **Difficulty:** Easy / Medium / Hard

## MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic |
|-------------|----------------|--------|
| T1234 | Technique Name | Tactic |
| T1234.001 | Sub-technique | Tactic |

## Tools Used

List the EntraReaper tools this scenario requires:

- `tool_name_1` -- purpose in this scenario
- `tool_name_2` -- purpose in this scenario

## Step-by-Step

```
# Phase 1: Description
tool_a(param="value")

# Phase 2: Description
tool_b(param="value")

# Phase 3: Description
tool_c(param="value")
```

## Use Cases

**White hat use:** How this is used in authorized penetration testing or security audits.

**Gray hat use:** How this applies to red team engagements or bug bounty research.

**Black hat use:** How a real-world adversary would execute this technique (for threat modeling).

## Key Insight

What is the important takeaway from this scenario? Why does it matter?

## Kill Chain Integration

Does this scenario fit into an existing kill chain (A-M)? If so, where?

- [ ] Extends Chain ___: Insert between S__ and S__
- [ ] Enables a new kill chain (describe below)
- [ ] Standalone -- does not fit existing chains

## Prerequisites

- What access level is required to start?
- What tokens or credentials are needed?
- Are there specific tenant configurations required?

## Detection Opportunities

What should blue teams look for to detect this technique?

- Log source:
- Indicator:
- Detection logic:

## References

- Link to relevant research, blog post, or CVE
- Link to AADInternals documentation for the cmdlets used
- Link to MITRE ATT&CK technique page

## Checklist

- [ ] All tools referenced exist in EntraReaper (or I am also submitting a tool PR)
- [ ] MITRE ATT&CK mapping is accurate
- [ ] OPSEC level reflects realistic detection risk
- [ ] Three use cases (white/gray/black) are documented
- [ ] Detection opportunities are documented for blue team

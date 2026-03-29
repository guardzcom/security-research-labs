# Reports

Engagement deliverables — executive summary, technical findings, remediation.

## Structure

```
reports/{engagement}/
  executive_summary.md    — C-level overview: scope, impact, risk rating
  technical_findings.md   — Detailed findings with evidence + MITRE mapping
  remediation.md          — Prioritized fix recommendations
  evidence_appendix.md    — Supporting evidence: screenshots, queries, IOCs
  timeline.md             — Chronological attack narrative (links to timeline/)
```

## Generated from

Aggregates data across all other folders:
- `fingerprints/` — target identity for report header
- `behavior/` — attack surface summary
- `iocs/` — indicators appendix
- `playbooks/` — kill chain narrative
- `loot/` — evidence of impact
- `noise/` — OPSEC assessment
- `persistence/` + `cleanup/` — remediation urgency

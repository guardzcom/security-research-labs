---
name: Feature Request
about: Suggest a new feature or improvement for EntraReaper
title: "[FEATURE] "
labels: enhancement
assignees: ''
---

## Summary

One-sentence description of the feature.

## Motivation

Why is this feature needed? What problem does it solve? What use case does it enable?

## Proposed Solution

Describe your proposed implementation. For new MCP tools, include:

### Tool Definition

- **Tool name:** (e.g., `recon_new_tool`)
- **Category:** (e.g., Recon, Credential Access, Persistence, etc.)
- **Parameters:** List of input parameters
- **AADInternals cmdlet(s):** Which cmdlet(s) does it wrap?
- **OPSEC level:** Silent / Low / Medium / HIGH / LOUD
- **MITRE ATT&CK:** Technique ID(s)

### Expected Output

```json
{
  "status": "success",
  "tool": "recon_new_tool",
  "data": { "example": "output" }
}
```

## Alternatives Considered

Describe alternative approaches you considered and why you prefer the proposed solution.

## Integration

- [ ] This requires changes to `server.py` (new tool)
- [ ] This requires changes to `opsec.py` (new OPSEC profile)
- [ ] This requires changes to `engagement_store.py` (new save hook)
- [ ] This requires changes to `evasion.py` (new evasion capability)
- [ ] This requires changes to `analyzer.py` (new analysis capability)
- [ ] This requires changes to `reporter.py` (new report section)
- [ ] This requires changes to `bridge.py` (new PowerShell interaction)
- [ ] This requires a new AADInternals cmdlet (upstream dependency)

## Additional Context

Any additional information, screenshots, or references.

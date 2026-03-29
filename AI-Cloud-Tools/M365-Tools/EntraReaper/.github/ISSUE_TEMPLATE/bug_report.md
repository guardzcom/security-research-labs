---
name: Bug Report
about: Report a bug in EntraReaper
title: "[BUG] "
labels: bug
assignees: ''
---

## Describe the Bug

A clear and concise description of what the bug is.

## Environment

- **OS:** (e.g., macOS 14.5, Ubuntu 24.04)
- **Python version:** (e.g., 3.12.3)
- **PowerShell version:** (e.g., 7.4.1)
- **AADInternals version:** (e.g., 0.9.4)
- **EntraReaper version:** (e.g., 2.1.0)
- **MCP client:** (e.g., Claude Code 1.0.12)

## Steps to Reproduce

1. Run `...`
2. Call tool `...` with parameters `...`
3. See error

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened. Include error messages, JSON output, or logs.

## Tool Output

```json
Paste the JSON response from the failing tool here.
```

## PowerShell Diagnostics

Output of `pwsh scripts/setup.ps1`:

```
Paste setup.ps1 output here.
```

## Additional Context

- Is this reproducible? (always / sometimes / once)
- Does it work with a different tenant?
- Any relevant OPSEC budget state?

## Checklist

- [ ] I have verified that PowerShell 7 and AADInternals are installed correctly
- [ ] I have run `pwsh scripts/setup.ps1` and it passes
- [ ] I have checked that this is not an AADInternals upstream issue
- [ ] I have searched existing issues for duplicates

# Playbooks

Kill chain execution journal — what was run, when, in what order, what happened.

## Structure

```
playbooks/{engagement}/
  execution_log.md        — Chronological tool calls with results (auto-appended)
  kill_chain.md           — Which chain (A-K) was followed + deviations
  decision_log.md         — Why we pivoted, what branching decisions were made
```

## Entry Format (markdown-kv)

Each tool execution appends:

```
| Key | Value |
|-----|-------|
| timestamp | 2026-03-26 16:08:26 UTC |
| tool | recon_users |
| scenario | S03 |
| target | microsoft.com |
| result | 18 valid / 185 tested |
| opsec_actual | Low (33 throttled — rate limiting triggered) |
| opsec_predicted | Low |
| next_action | S17 device code phish targeting satya@microsoft.com |
| decision | Prioritize C-suite over IT accounts — higher impact for report |
```

## Auto-populated by

Every tool call appends to the execution log.
Decision entries are manual (red team operator documents reasoning).

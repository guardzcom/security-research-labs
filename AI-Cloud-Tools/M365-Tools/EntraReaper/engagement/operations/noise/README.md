# Noise

Actual telemetry footprint — what logs and alerts our actions generated.
Compares OPSEC profile predictions vs reality.

## Structure

```
noise/{engagement}/
  footprint.md            — Per-tool noise log (auto-appended)
  opsec_delta.md          — Predicted vs actual noise comparison
  rate_limits.md          — Throttling events with timestamps
```

## Entry Format (markdown-kv)

| Key | Value |
|-----|-------|
| timestamp | 2026-03-26 16:01:37 UTC |
| tool | recon_users |
| target | m.grdz.org |
| predicted_noise | Low |
| actual_noise | Low + THROTTLED (26 requests rate-limited after 80) |
| logs_expected | None (GetCredentialType) |
| logs_actual | Possible rate-limit alert on Microsoft side |
| delta | Rate limiting was NOT in OPSEC profile — update opsec.py |

## Why This Matters

- OPSEC profiles are theoretical. Noise logs capture reality.
- Rate limiting = Microsoft saw unusual volume. May trigger alerts.
- Debrief accuracy depends on knowing what you actually left behind.
- Feed deltas back into opsec.py to improve future predictions.

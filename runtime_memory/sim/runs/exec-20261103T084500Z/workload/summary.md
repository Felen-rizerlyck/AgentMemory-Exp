# Offline workload: recovery time vs retry window

seeds per config: 30; down time uniform 0..1800s; retry interval 60s; horizon 3600s.

| config | success | calls | failures | blocked | would_block | false_block_rate | mean TTS | p95 TTS |
|---|---|---|---|---|---|---|---|---|
| baseline | 1.0 | 16.9 | 15.9 | 0 | 0 | 0.0 | 954 | 1740 |
| shadow_60 | 1.0 | 16.9 | 15.9 | 0 | 12.9 | 0.078 | 954 | 1740 |
| enforce_60 | 0.0 | 4 | 4 | 57 | 0 | 0.0 | None | None |
| shadow_300 | 1.0 | 16.9 | 15.9 | 0 | 15.9 | 0.063 | 954 | 1740 |
| enforce_300 | 0.467 | 3.5 | 3.033 | 24.9 | 0 | 0.0 | 578.6 | 900 |
| shadow_900 | 1.0 | 16.9 | 15.9 | 0 | 15.9 | 0.063 | 954 | 1740 |
| enforce_900 | 1.0 | 2.533 | 1.533 | 1.533 | 0 | 0.0 | 1380 | 1800 |
| shadow_1800 | 1.0 | 16.9 | 15.9 | 0 | 15.9 | 0.063 | 954 | 1740 |
| enforce_1800 | 1.0 | 2 | 1 | 1 | 0 | 0.0 | 1800 | 1800 |

Notes:
- baseline has no memory: call every 60s.
- shadow records decisions but always calls.
- enforce skips blocked calls and waits for next_retry_at.
- false_block_rate = false_blocks / would_block in shadow.
- mean_blocked counts block decisions/preflights, not distinct calls; a long outage can produce repeated blocked preflights.
- per-seed raw rows: runs.jsonl; per-config metrics: metrics.json.

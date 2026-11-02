# Edge-case test report

Date: 2026-11-02  
Command: `cd runtime_memory && python -m unittest discover -s tests`  
Result: **77 tests OK** (includes `tests/test_edge_cases.py` and `tests/test_store_edge.py`).

## Cases exercised

| # | Edge case | Expected | Result |
|---|---|---|---|
| E1 | Shadow says `block`, then the real call succeeds | count as `false_block`, not a confirmed block | PASS |
| E2 | `auth` issue stays open; after `expires_at` → `stale`; probe succeeds | probe, then `resolved`, then `allow` | PASS |
| E3 | `Retry-After: 7200` but class TTL is 3600 | expiry must not precede the retry window; block at 1h, probe at 2h | PASS (bug found + fixed) |
| E4 | Issue stuck in `probing` with no `probe_started_at` | recover to `open`/`stale`, do not block forever | PASS (bug found + fixed) |
| E5 | Another preflight while a probe is actually in flight | block with `probe already in flight` | PASS |
| E6 | Per-run budget exhausted | block with `run budget`, no issue id required | PASS |
| E7 | `invalid_args` on query A | block A, allow sibling query B | PASS |
| E8 | Same target in another `environment_id` / `scope` | no cross-environment/session block | PASS |
| E9 | Model adds a note | status / `next_retry_at` unchanged | PASS |
| E10 | `preflight(record=False)` for inspection | no decision row, no probing transition | PASS |
| E11 | Unknown error class | falls back to `scope` + `unknown` policy | PASS |
| E12 | Issue expired (`expires_at` passed) then probe succeeds | `stale` → probe → `resolved` | PASS |
| E13 | Malformed `decisions.jsonl` | `check` reports a journal problem, does not crash | PASS |
| E14 | Old event file / old resolved issue | `gc` dry-run keeps; apply removes only eligible data | PASS |
| E15 | Duplicate issues with the same key | `find_issue` prefers the live one over the resolved one | PASS |

## Bugs found and fixed

1. **`expires_at` could be earlier than a server `Retry-After` window.**
   A rate-limit issue with `Retry-After=7200` and class TTL=3600 would become
   `stale` after 1 hour, allowing a probe before the server's 2-hour window.
   Fixed by `RuntimeMemory._expires_at`: expiry is `max(class TTL, next_retry_at)`.

2. **A `probing` issue with a missing `probe_started_at` could stick forever.**
   Crash/partial-write recovery only handled a parseable timestamp.
   Fixed in `_refresh_issues`: missing `probe_started_at` is treated as an
   abandoned probe and recovered to `open`/`stale`.

## Residual, documented

- `issue.attempts` can be `max_attempts + 1` because `max_attempts` counts
  retries after the initial failure (3 failures + 1 successful probe = 4).
- `count` is failure observations; `attempts` is all calls.
- `data/policy.json` reflects the last phase; `policies.json` holds all phases.
- `records.md` samples the first successful event; the 1/2/3/4 attempt sequence
  is visible in `data/events/*.jsonl`.

# AGENT_NOTES — `sim-2026-11-02-agent-v2`

Independent rerun of the runtime-memory prototype after the four data-quality fixes.
Read-only outside this run directory; no source code, demo data, `runtime_memory/data`,
or the previous `sim-2026-11-02-agent/` run was modified (old-run artifact hashes match
the first run). This is the only file written here.

## 1. Command and exit code

Working directory: `F:\AI_Learning\AgentMemory\runtime_memory`

```powershell
python sim/scenario.py --run-id sim-2026-11-02-agent-v2
```

- Python: 3.14.0
- **Exit code: 0** (success)
- Output: `F:\AI_Learning\AgentMemory\runtime_memory\sim\runs\sim-2026-11-02-agent-v2`
- Final stdout: `actual calls=13 blocked=3 failures=8` /
  `shadow would_block=2 false_blocks=0 duplicate_attempts=3`
- New artifact present: `policies.json` (23 lines / 3 phases)

## 2. Fix verification

**(1) `event.attempt` now follows the issue counter — CONFIRMED.** The MCP failure
streak in phase A is now `attempt = 1, 2, 3`:

| event_id | ts | attempt | outcome | decision_id |
|---|---|---|---|---|
| OP-20261102T060000-BD528E | 06:00:00Z | 1 | fail | — |
| OP-20261102T060100-FA7799 | 06:01:00Z | 2 | fail | DEC-20261102T060100-424E24 |
| OP-20261102T060200-1E66B1 | 06:02:00Z | 3 | fail | DEC-20261102T060200-6E132F |

The SIEM streak is `1, 2`; pcap/shell/model first calls are `1`. Residual nuance:
the success path still records `attempt=1` (it increments only via the issue counter),
so successful probes/retries are `1` even when they are a later call for that
fingerprint — e.g. the model retry `OP-20261102T060831-370630` (2nd call, ok) and the
MCP probe `OP-20261102T062332-0D9E93` (after 3 failures, ok) both carry `attempt=1`.
That is understandable (no issue counter increments on success) but `attempt` is still
not a monotonic per-fingerprint call number for OK events.

**(2) IDs and `report.generated_at` use the injected fake clock — CONFIRMED.**
All 27 IDs (13 events + 9 decisions + 5 issues) encode fake-clock time
`2026-11-02T06:xx`:

```
OP-20261102T060000-BD528E … OP-20261102T062533-EAD6F1
DEC-20261102T060100-424E24 … DEC-20261102T062533-A8CA26
ISS-20261102T060000-847592 … ISS-20261102T060800-7C07A2
```

`report.json.generated_at = "2026-11-02T06:25:33Z"`, which equals the fake clock's
final timestamp — no real wall-clock `07:52` values remain. The ID timestamp and its
record `ts` now agree (e.g. issue `ISS-20261102T060500-...` ↔ `first_seen
2026-11-02T06:05:00Z`).

**(3) `policies.json` shows shadow then enforce — CONFIRMED.**

```json
{"phases": [
  {"phase": 1, "enforce": false, "policy_version": "2026-11-02.1", "at": "2026-11-02T06:00:00+00:00"},
  {"phase": 2, "enforce": true,  "policy_version": "2026-11-02.1", "at": "2026-11-02T06:08:31+00:00"},
  {"phase": 3, "enforce": true,  "policy_version": "2026-11-02.1", "at": "2026-11-02T06:25:33+00:00"}
]}
```

Phase 1 (shadow, `enforce=false`), phase 2 (enforce), phase 3 (new session, enforce).
`data/policy.json` still ends with `enforce: true` (last phase), as documented.

**(4) Inspection-only phase C decisions excluded — CONFIRMED.** `decisions.jsonl` has
exactly 9 records, all with `run_id` `sim-2026-11-02-agent-v2` (4 shadow) or
`...-v2-b` (5 enforce) — no `-c` records. The six phase-C inspection preflights are
visible only in `narrative.log` and get no `decision_id`. `report.decisions.total`
stays `9` with `shadow_total=4`, `enforce_total=5`.

## 3. Key numbers (unchanged from the v1 run, as expected)

| Metric | Value |
|---|---|
| actual calls (executed) | **13** |
| blocked calls (skipped by enforce gate) | **3** |
| failures (executed, outcome=fail) | **8** |
| shadow `would_block` | **2** |
| shadow `false_blocks` | **0** (confirmed_blocks = 2) |
| `duplicate_attempts` | **3** |
| probes | attempts **4**, success **3**, success_rate **0.75** |
| issues | total **5** → resolved **3**, open **2** (stale_rate 0.0) |
| events | total 13 → ok 5, fail 8 |
| decisions | total 9 → block 5, probe 4, hint 0 (shadow 4 / enforce 5) |
| enforce blocked_calls | 3 |

- All 8 failures are in shadow phase A (mcp ×3, siem ×2, pcap case-001, shell, model);
  all 3 executed enforce-phase calls succeeded.
- Issues by status:
  - resolved 3: `ISS-20261102T060000-847592` (mcp `unreachable`, scope, count 3),
    `ISS-20261102T060300-F29C32` (siem `rate_limit`, scope, count 2),
    `ISS-20261102T060800-7C07A2` (model `timeout`, call, count 1)
  - open 2: `ISS-20261102T060500-F396AE` (pcap `schema`, **call**-level),
    `ISS-20261102T060700-7A1FA9` (shell `permission`, scope)
- The two shadow blocks (mcp attempts 2–3) are confirmed by real failures:
  `would_block=2`, `false_blocks=0`.

## 4. Record-shape observations

**Events** (`data/events/2026-11.jsonl`, 13 JSONL lines; one per executed call). Each
line has the 16-hex `event_id`, fake-clock `ts`, operation identity, `outcome`,
`duration_ms`, the aggregated key (`fingerprint`, `key_level`), and preflight linkage
(`decision_id`, `would_block`). Example call-level fingerprint from the failing pcap
event `OP-20261102T060500-1DCDB3`:

```
fingerprint = "lab-a|call|parser|pcap.parse|parse|/data|args:sha256:47da44f5d0cc848b"
key_level   = "call"
```

Targets are normalized inside the fingerprint (`/data/pcap` → `/data`; URL
`.../hunt/sse` → `.../hunt`), so fingerprints intentionally differ from the literal
`target` field. A resolving success event (`OP-20261102T062332-0D9E93`) has
`decision_id=DEC-20261102T062332-40418E, would_block=false, outcome=ok` and is later
cited in the issue's `resolved_basis`.

**Issues** (`data/issues.json` → `{schema_version, issues:[...]}`, 5 records). An
issue keeps the fingerprint family of its `key_level` and adds lifecycle fields:
`status`, `count`/`attempts`, `first_seen`/`last_seen`, `retry_policy` (mode,
base_s/max_s, next_retry_at, ttl_s), `next_retry_at`, `expires_at`, `workaround`,
`confidence`, `source_event_ids`, `diagnosis`, `resolution`/`resolved_at`/
`resolved_basis`. Example resolved issue `ISS-20261102T060000-847592`:

```
fingerprint   = "lab-a|scope|mcp|hunt.query|search|http://10.7.194.120:22196/hunt"
count/attempts = 3 / 3
retry_policy  = {mode:"fixed", base_s:900, max_s:1800, max_attempts:3,
                 next_retry_at:"2026-11-02T06:17:00Z"}
workaround    = "use local pcap or cached hunt results until endpoint is restored"
resolution    = "fixed"; resolved_basis = "success event OP-20261102T062332-0D9E93"
source_event_ids = 4 ids (3 phase-A failures + the successful probe)
```

Open example: `ISS-20261102T060500-F396AE` (call-level `schema`,
`retry_policy.mode="none"`, `next_retry_at=null`). `expires_at` follows the
per-class `ttl_s` (86400 s for unreachable/schema/permission, 3600 s for
rate_limit/timeout).

**Decisions** (`data/decisions.jsonl`, 9 lines). Only non-`allow` outcomes are
persisted; each carries both fingerprints, `decision`, `reason`, `issue_id`,
`blocked_until`, `attempts_left`, `alternatives`, `shadow`. Shadow example
`DEC-20261102T060100-424E24` (`shadow:true, decision:"block", attempts_left:3,
blocked_until:"2026-11-02T06:15:00Z", alternatives:[]`). Its enforce twin
`DEC-20261102T060831-68561E` has `shadow:false` and carries the phase-A workaround as
`alternatives: ["use local pcap or cached hunt results until endpoint is restored"]`.
These now align with the event `attempt` numbers (mcp events attempt 2/3 reference
`DEC-...060100`/`DEC-...060200`).

## 5. Do the three behaviours still hold?

**(a) Shadow decisions not blocking — YES.** Phase A recorded 4 shadow
`block`/`probe` decisions but executed all 10 calls (`blocked=0`); the 2 shadow blocks
were followed by real failures and are counted `would_block=2`, `confirmed_blocks=2`,
`false_blocks=0`. See `narrative.log` "mcp hunt attempt 2: preflight=block ... executed
-> fail".

**(b) Enforce blocking — YES.** `enforce=true` skipped 3 calls: mcp blocked until its
retry window (workaround surfaced as `alternatives`), pcap `case-001` blocked as
non-retryable `schema` at call level, shell blocked as non-retryable `permission`. The
sibling pcap `case-002` was allowed; after the 901 s advance the mcp probe succeeded
(issue resolved) and the siem probe also succeeded (issue resolved).

**(c) Memory persisting into a new run — YES.** Phase C is a fresh runtime with new
run id `...-v2-c` and `enforce=true`: mcp/siem/model → `allow` (resolved issues),
pcap `case-001` → `block` (`ISS-...F396AE` open), shell → `block` (`ISS-...7A1FA9`
open), pcap `case-002` → `allow`. Phase B also crosses the `-v2-b` run boundary
(per-run budget reset; issue-level retry window still applies).

## 6. Remaining anomalies / confusing fields

1. **`event.attempt` for successful calls is still `1`** (model retry with outcome ok,
   all probe successes), because the counter is only aligned with the issue counter on
   failure. The MCP failure streak is now correct (`1,2,3`), but an OK event does not
   reveal whether it was the 2nd/5th attempt for that fingerprint.
2. **`data/policy.json` still reflects only the last phase** (`enforce: true`); it is
   no longer the sole policy record (`policies.json` has all phases), but anyone reading
   only `data/policy.json` would still miss phase A's shadow mode.
3. **Cosmetic timestamp format mismatch:** `policies.json` uses
   `"...+00:00"` for `at`, while event/issue/decision `ts` use `"...Z"` for the same
   instants. Harmless but easy to mis-parse with a naive string comparison.
4. **`records.md` samples only the first event** (`attempt: 1`); the fixed
   `1,2,3` attempt sequence is only visible by reading `data/events/2026-11.jsonl`
   (or the `narrative.log` issue counts), not the sample record.
5. `report.decisions.total=9` intentionally excludes the 6 phase-C inspection
   preflights (fix #4); it also excludes all `allow` outcomes by design, so it should
   not be compared directly to the 44-line `narrative.log`.

No functional failure; all expected artifacts exist: `summary.md`, `report.json`,
`records.md`, `narrative.log`, `policies.json`, `data/issues.json`,
`data/decisions.jsonl`, `data/events/2026-11.jsonl`, `data/policy.json`,
`data/playbook.md`, and an empty `data/overrides.jsonl` (no overrides exercised).

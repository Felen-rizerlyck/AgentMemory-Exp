# AGENT_NOTES — `sim-2026-11-02-agent-final`

Final independent run of the runtime-memory prototype after the last data-quality fix
(success/probe events use the next attempt number; `records.md` samples first failure /
retry failure / success; `policies.json` timestamps use `Z`). Read-only outside this
directory; no source code, demo data, `runtime_memory/data`, or the earlier
`sim-2026-11-02-agent` / `sim-2026-11-02-agent-v2` runs were modified (v1 artifact
hashes still match the first run; v2 still contains its pre-fix `1,2,3,1` MCP
attempts). This is the only file written here.

## 1. Command and exit code

Working directory: `F:\AI_Learning\AgentMemory\runtime_memory`

```powershell
python sim/scenario.py --run-id sim-2026-11-02-agent-final
```

- Python: 3.14.0
- **Exit code: 0** (success)
- Output: `F:\AI_Learning\AgentMemory\runtime_memory\sim\runs\sim-2026-11-02-agent-final`
- Final stdout: `actual calls=13 blocked=3 failures=8` /
  `shadow would_block=2 false_blocks=0 duplicate_attempts=3`

## 2. Fix verification

**(1) Success/probe events use the next attempt number — CONFIRMED.**
MCP event attempts are now **1, 2, 3, 4** (the phase-B probe after three failures is
attempt 4):

| event_id | ts | attempt | outcome | note |
|---|---|---|---|---|
| OP-20261102T060000-BD315D | 06:00:00Z | 1 | fail | first failure |
| OP-20261102T060100-372292 | 06:01:00Z | 2 | fail | retry failure, `would_block=true` |
| OP-20261102T060200-AE2D86 | 06:02:00Z | 3 | fail | third failure |
| OP-20261102T062332-220158 | 06:23:32Z | **4** | **ok** | enforce probe succeeds, `run_id=...-final-b` |

- **Model retry attempt = 2** — `OP-20261102T060831-DF1A67` (06:08:31Z, ok) follows the
  failed `OP-20261102T060800-96D152` (attempt 1). Model sequence `1, 2`.
- **SIEM probe attempt = 3** — `OP-20261102T062533-10ABC0` (06:25:33Z, ok,
  `run_id=...-final-b`) follows failures at attempt 1 and 2. SIEM sequence `1, 2, 3`.

The issue records now agree: MCP `attempts=4` (`count=3`), SIEM `attempts=3`
(`count=2`), model `attempts=2` (`count=1`). `issue.attempts` = all attempts (failures
plus the successful probe/retry), `issue.count` = failures only.

**(2) `records.md` sample names — CONFIRMED.** Headings are exactly:

```
## event_first_failure   attempt=1  OP-20261102T060000-BD315D (mcp, fail)
## event_retry_failure   attempt=2  OP-20261102T060100-372292 (mcp, fail,
                                    decision_id=DEC-20261102T060100-2C7774, would_block=true)
## event_success         attempt=1  OP-20261102T060600-4306CF (pcap case-002, ok)
## issue_open            ISS-20261102T060500-2800C7 (pcap schema, call-level)
## issue_resolved        ISS-20261102T060000-C23EA3 (mcp unreachable, attempts=4)
## decision_block        DEC-20261102T060100-2C7774 (shadow=true)
## decision_probe        DEC-20261102T060400-558898 (shadow=true)
```

**(3) `policies.json` timestamps use `Z` — CONFIRMED.**

```json
{"schema_version": 1, "phases": [
  {"phase": 1, "enforce": false, "policy_version": "2026-11-02.1", "at": "2026-11-02T06:00:00Z"},
  {"phase": 2, "enforce": true,  "policy_version": "2026-11-02.1", "at": "2026-11-02T06:08:31Z"},
  {"phase": 3, "enforce": true,  "policy_version": "2026-11-02.1", "at": "2026-11-02T06:25:33Z"}
]}
```

Phase 1 shadow, phases 2–3 enforce; `data/policy.json` still ends `enforce: true`
(last phase), as documented.

Earlier fixes remain in place: all IDs use the fake clock
(`...20261102T060000`…`06:25:33`), `report.generated_at = "2026-11-02T06:25:33Z"`,
and phase C's `preflight(record=False)` inspections still add no
`decisions.jsonl` records (9 lines, run ids only `...-final` and `...-final-b`).

## 3. Key numbers

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
  - resolved 3: `ISS-20261102T060000-C23EA3` (mcp `unreachable`, scope, count 3,
    attempts 4), `ISS-20261102T060300-5D5CAC` (siem `rate_limit`, scope, count 2,
    attempts 3), `ISS-20261102T060800-7DD10C` (model `timeout`, call, count 1,
    attempts 2)
  - open 2: `ISS-20261102T060500-2800C7` (pcap `schema`, **call**-level),
    `ISS-20261102T060700-B434E1` (shell `permission`, scope)
- The two shadow blocks (mcp attempts 2–3) were followed by real failures:
  `would_block=2`, `confirmed_blocks=2`, `false_blocks=0`.

## 4. Record-shape observations

**Events** (`data/events/2026-11.jsonl`, 13 JSONL lines). One line per executed call
with 16-hex `event_id`, fake-clock `ts`, operation identity, `outcome`, `duration_ms`,
the aggregated key (`fingerprint`, `key_level`), preflight linkage
(`decision_id`, `would_block`) — and now a meaningful `attempt` for both failures and
successes. Example fingerprint from the open pcap issue:

```
fingerprint = "lab-a|call|parser|pcap.parse|parse|/data|args:sha256:47da44f5d0cc848b"
key_level   = "call"
```

Targets are normalized inside fingerprints (`/data/pcap` → `/data`, URL `.../hunt/sse`
→ `.../hunt`), so the fingerprint differs from the literal `target` field.

**Issues** (`data/issues.json` → `{schema_version, issues:[...]}`, 5 records). Keys are
scope- or call-level plus lifecycle fields (`status`, `count`, `attempts`,
`retry_policy`, `next_retry_at`, `expires_at`, `workaround`, `source_event_ids`,
`diagnosis`, `resolution`/`resolved_at`/`resolved_basis`). Example `ISS-20261102T060000-C23EA3`:

```
fingerprint    = "lab-a|scope|mcp|hunt.query|search|http://10.7.194.120:22196/hunt"
count/attempts = 3 / 4
retry_policy   = {mode:"fixed", base_s:900, max_s:1800, max_attempts:3,
                  next_retry_at:"2026-11-02T06:17:00Z"}
workaround     = "use local pcap or cached hunt results until endpoint is restored"
resolved_basis = "success event OP-20261102T062332-220158"  (attempt 4 probe)
source_event_ids = [3 phase-A failures + the successful probe]
```

**Decisions** (`data/decisions.jsonl`, 9 lines). Only non-`allow` outcomes, with both
fingerprints, `decision`, `reason`, `blocked_until`, `attempts_left`, `alternatives`,
`shadow`. Example shadow block `DEC-20261102T060100-2C7774` (`ts 06:01:00Z`,
`shadow:true`, `blocked_until 06:15:00Z`); its enforce twin
`DEC-20261102T060831-FC9AC5` carries the phase-A workaround in `alternatives`.

## 5. Behaviours

- **(a) Shadow non-blocking — YES.** Phase A recorded 4 shadow block/probe decisions
  and still executed all 10 calls (`blocked=0`); the 2 shadow blocks were confirmed by
  real failures (`would_block=2`, `false_blocks=0`).
- **(b) Enforce blocking — YES.** 3 calls skipped (mcp until retry window, pcap
  case-001 call-level schema, shell permission); sibling pcap case-002 allowed; mcp
  probe (attempt 4) and siem probe (attempt 3) resolved their issues.
- **(c) Cross-run memory — YES.** Fresh run `...-final-c` allowed resolved
  mcp/siem/model and blocked open pcap case-001 / shell. Phase B also crosses the
  `-final-b` run boundary.

## 6. Residual anomalies / confusing fields

1. **`records.md.event_success` is a first-attempt success** — it samples the earliest
   ok event, pcap `case-002` with `attempt=1`, so the sample page does not showcase the
   new success-attempt numbering (mcp attempt 4, siem attempt 3, model attempt 2 are
   only in `data/events/2026-11.jsonl`). The sample names are correct, but the success
   example is the least interesting one for this fix.
2. **`issue.attempts` can exceed `retry_policy.max_attempts`** — resolved mcp issue has
   `attempts=4` with `max_attempts=3` (the `+1` retry-window semantics make 4 legal),
   and `count` (failures) now differs from `attempts` (all calls). Correct but easy to
   misread as an off-by-one if you treat `max_attempts` as a hard call cap.
3. **`data/policy.json` still reflects only the last phase** (`enforce: true`);
   `policies.json` is now the complete record, but reading the old file alone still
   hides phase A's shadow mode.
4. `report.json` / `summary.md` still do not surface per-event `attempt`, so the fixed
   numbering must be read from the events JSONL (or `narrative.log` only shows issue
   `count`, not attempt numbers).

No functional failure; all expected artifacts exist: `summary.md`, `report.json`,
`records.md`, `narrative.log`, `policies.json`, `data/issues.json`,
`data/decisions.jsonl`, `data/events/2026-11.jsonl`, `data/policy.json`,
`data/playbook.md`, and an empty `data/overrides.jsonl` (no overrides exercised).

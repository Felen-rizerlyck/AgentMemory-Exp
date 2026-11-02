# AGENT_NOTES — `sim-2026-11-02-agent`

Independent simulation run of the runtime-memory prototype. Read-only outside this
run directory; no source code, demo data, or `runtime_memory/data` was modified.
`runtime_memory/sim/runs/` is the only new path (untracked in git).

## 1. Command and exit code

Working directory: `F:\AI_Learning\AgentMemory\runtime_memory`

```powershell
python sim/scenario.py --run-id sim-2026-11-02-agent
```

- Python: 3.14.0
- **Exit code: 0** (success)
- Output written to: `F:\AI_Learning\AgentMemory\runtime_memory\sim\runs\sim-2026-11-02-agent`
- Final stdout line: `actual calls=13 blocked=3 failures=8` /
  `shadow would_block=2 false_blocks=0 duplicate_attempts=3`

## 2. Key numbers

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
| decisions | total 9 → block 5, probe 4, hint 0 (shadow_total 4, enforce_total 5) |
| enforce blocked_calls | 3 |

Breakdown worth knowing:

- All **8** failures happened in phase A (shadow): mcp ×3, siem ×2, pcap case-001,
  shell, model. All **3** executed enforce-phase calls (mcp probe, siem probe,
  pcap case-002) succeeded.
- Phase A: 10 executed / 0 blocked. Phase B: 3 executed / 3 blocked (5 steps).
- Open issues (both unresolved → still blocking in phase C):
  - `ISS-20261102T075227-89D0D5` — pcap `schema`, key_level **call**
  - `ISS-20261102T075227-889210` — shell `permission`, key_level **scope**

## 3. Record-shape observations

**Events** (`data/events/2026-11.jsonl`, one JSON object per executed call, 13 lines).
The line carries a 16-hex `event_id`, the fake-clock `ts`, the operation identity
(`component`/`tool`/`action`/`target`), `outcome`, redacted message, `duration_ms`,
the aggregated key (`fingerprint`, `key_level`), and the preflight linkage
(`decision_id`, `would_block`). Example event `OP-20261102T075227-E29C3D` (failing
pcap case-001):

```
fingerprint = "lab-a|call|parser|pcap.parse|parse|/data|args:sha256:47da44f5d0cc848b"
key_level   = "call"
```

Note the fingerprint target is *normalized* away from the literal `target`
(`/data/pcap` → `/data`, i.e. parent directory; URLs keep only scheme/host/port plus
the first path segment, so `.../hunt/sse` → `.../hunt`). A scope-level sample is
`lab-a|scope|mcp|hunt.query|search|http://10.7.194.120:22196/hunt`. When preflight
returned `allow` the `decision_id` is `""` and `would_block` is `false`; when shadow
preflight returned `block` the call still executed but recorded the decision id and
`would_block: true` (events 2–3 of the mcp run). The call-level fingerprint is what
lets the bad pcap stay blocked while `case-002` (`args` differ → different
`args:sha256:...`) is allowed.

**Issues** (`data/issues.json`: `{schema_version, issues:[...]}`, 5 records). An
aggregated issue keeps both fingerprint families (`fingerprint` at its `key_level`)
and adds lifecycle data: `status`, `count`/`attempts`, `first_seen`/`last_seen`,
`retry_policy` (key_level, retryable, mode, base_s/max_s, next_retry_at, ttl_s),
`next_retry_at`, `expires_at`, `workaround`, `confidence`, `source_event_ids`,
`diagnosis`, `resolution`/`resolved_at`/`resolved_basis`. Example resolved issue
`ISS-20261102T075226-67B882` (mcp unreachable, scope-level, resolved):

```
fingerprint   = "lab-a|scope|mcp|hunt.query|search|http://10.7.194.120:22196/hunt"
count/attempts = 3 / 3
retry_policy  = {mode: "fixed", base_s: 900, max_s: 1800, max_attempts: 3,
                 next_retry_at: "2026-11-02T06:17:00Z"}
workaround    = "use local pcap or cached hunt results until endpoint is restored"
resolution    = "fixed"; resolved_basis = "success event OP-20261102T075227-014064"
source_event_ids = [4 ids, including the successful probe]
```

`expires_at` follows the per-error-class `ttl_s` (unreachable/schema/permission
86400s, rate_limit/timeout 3600s), not a global TTL. Open example:
`ISS-20261102T075227-89D0D5` (call-level, `retry_policy.mode="none"`,
`next_retry_at=null`, `attempts_left`/`max_attempts` 0).

**Decisions** (`data/decisions.jsonl`, 9 lines). Only non-`allow` preflight outcomes
(`block`/`probe`) are persisted, both fingerprint families are stored, plus
`decision`, `reason`, `issue_id`, `blocked_until`, `attempts_left`, `alternatives`,
`confidence`, `expires_at`, `shadow`, `override`. Example shadow decision
`DEC-20261102T075226-2AB85E`:

```
decision      = "block"; shadow = true
reason        = "blocked until retry window: unreachable @ .../hunt/sse (1 failure(s))"
blocked_until = "2026-11-02T06:15:00Z"; attempts_left = 3; alternatives = []
```

The matching enforce decision `DEC-20261102T075227-DF79AC` has `shadow: false` and
carries `alternatives: ["use local pcap or cached hunt results until endpoint is
restored"]` — so the phase-A workaround is surfaced exactly when the enforce gate
blocks. Phase C preflights were run with `record=False` and therefore appear only in
`narrative.log`, not in `decisions.jsonl`.

## 4. Does the scenario demonstrate the three behaviours?

**(a) Shadow decisions not blocking — YES.** Phase A produced 4 preflight
`block`/`probe` decisions (2 block + 2 probe) with `shadow: true`, yet `blocked=0`
and all 10 calls executed. The two shadow blocks were followed by real failures and
are counted as `would_block=2`, `confirmed_blocks=2`, `false_blocks=0`. Ground truth
is visible in `narrative.log`, e.g. `mcp hunt attempt 2: preflight=block ... executed
-> fail`.

**(b) Enforce blocking — YES.** Phase B (`enforce=true`) skipped 3 calls:
mcp `hunt.query` blocked until its retry window (alternatives shown), pcap
`case-001` blocked as non-retryable `schema` at call level, shell `run` blocked as
non-retryable `permission`. The sibling pcap `case-002` was allowed (call-level key
isolates only the bad args). After the 901 s clock advance the mcp probe ran and
succeeded (issue resolved), and the siem probe also succeeded (issue resolved).

**(c) Memory persisting into a new run — YES.** Phase C is a fresh `RuntimeMemory`
instance with new run id `sim-2026-11-02-agent-c` and `enforce=true`, reading only
the on-disk store. Its preflights: mcp/siem/model → `allow` (their issues are
resolved), pcap `case-001` → `block` (`ISS-...89D0D5` still open), shell → `block`
(`ISS-...889210` still open), pcap `case-002` → `allow`. Phase B additionally shows
memory crossing the `-b` run-id boundary (the phase-A issue blocks it while the
per-run attempt budget is reset).

## 5. Anomalies / confusing fields

1. **Event `attempt` is always `1`** in all 13 events — including the 2nd/3rd mcp
   attempts (record ts 06:01, 06:02), the 2nd siem attempt, and the model retry.
   Repetition is only visible on the issue (`count`/`attempts` reach 3 and 2). The
   field looks unpopulated/misleading for per-run retries.
2. **ID timestamps vs record timestamps use different clocks.**
   `event_id`/`issue_id`/`decision_id` embeds real wall-clock time
   (`...20261102T075226/075227...`) and `report.json.generated_at` is
   `2026-11-02T07:52:27.63Z`, while every record `ts`/`first_seen`/`last_seen` uses
   the injected fake clock (06:00:00–06:25:33Z). The scenario is therefore not
   byte-reproducible across reruns (README does warn IDs vary), but the ~1.5 h
   offset between an ID's timestamp and the record it names can confuse correlation.
3. **`data/policy.json` ends as `enforce: true`** because each phase rewrites it and
   phase C is the last writer; reading the single policy snapshot misrepresents the
   phase-A shadow mode. Likewise `report.decisions.total=9` counts only the 9
   persisted non-allow decisions (4 shadow + 5 enforce) and excludes the 6 phase-C
   fresh preflights and all `allow`s, while `summary.md`'s "Execution" block omits
   `duplicate_attempts`/probe metrics even though `report.json` contains them.

No functional failure was observed; the run completed and all expected artifacts
exist: `summary.md`, `report.json`, `records.md`, `narrative.log`,
`data/issues.json`, `data/decisions.jsonl`, `data/events/2026-11.jsonl`,
`data/policy.json`, `data/playbook.md`, and an empty `data/overrides.jsonl`
(no overrides were exercised).

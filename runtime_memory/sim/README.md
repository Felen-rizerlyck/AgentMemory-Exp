# Simulated restricted-lab scenario

A deterministic, offline scenario for the runtime-memory prototype. It does not
call any real tool; it simulates one analyst/agent session against a restricted
lab and records the runtime-memory artifacts.

## Scenario

Environment: `lab-a`, one virtual `session_id`, three virtual `run_id` phases.

| Phase | Mode | What happens |
|---|---|---|
| A | shadow (`enforce=false`) | MCP hunt endpoint unreachable (3 attempts), SIEM rate-limited (2), one malformed pcap, shell permission denied, model timeout then retry |
| B | enforce (`enforce=true`) | MCP is blocked until its retry window, then one probe succeeds; the bad pcap is blocked while a different pcap path is allowed; the shell permission issue is blocked |
| C | enforce, new run | memory persists: resolved issues allow, unresolved parser/shell issues still block |

A workaround is recorded on the MCP issue during phase A. It is surfaced as an
`alternative` when the enforce phase blocks the call.

## Run

From `runtime_memory/`:

```powershell
python sim/scenario.py --run-id sim-2026-11-02
```

By default this writes to `sim/runs/sim-2026-11-02/`. Use `--out` to choose a
different directory, and `--force` to overwrite an existing one.

## Outputs

```text
sim/runs/<run-id>/
├── data/
│   ├── policy.json
│   ├── events/2026-11.jsonl   # one line per actual call
│   ├── decisions.jsonl        # block/probe/hint decisions
│   ├── overrides.jsonl
│   └── issues.json            # aggregated issues
├── narrative.log              # timestamped story
├── summary.md                 # execution counts + report JSON
├── records.md                 # sample event/issue/decision records
└── report.json                # machine-readable metrics
```

The scenario is intentionally deterministic in time (fake clock), but event and
issue IDs contain a timestamp and random suffix.

## Offline Monte-Carlo workload

`sim/workload.py` simulates many endpoints with random outage durations and
compares no-memory, shadow, and enforce under different retry windows:

```powershell
python sim/workload.py --seeds 30 --run-id workload-2026-11-03-b30
```

Outputs `summary.md`, `metrics.json`, `table.csv`, and per-seed `runs.jsonl`
under `sim/runs/<run-id>/`. The current example is
`sim/runs/workload-2026-11-03-b30/`.

## Scale probe

`sim/scale.py` writes 1k / 5k / 20k synthetic events and measures preflight
(with/without a run_id), report and check latency:

```powershell
python sim/scale.py
```

Output: `sim/runs/scale-2026-11-03/summary.md` + `metrics.json`.
The `with run_id` measurement includes the per-run budget scan over all events,
so it grows linearly with event count.

## Edge cases

`sim/EDGE_CASES.md` lists the additional edge tests (false block, stale recovery,
Retry-After > TTL, abandoned probing, per-run budget, environment/scope
isolation, malformed journals, gc). Run them with the normal test command.

## Deep mode/behaviour matrix (2026-11-03)

`sim/deep_test.py` is a deterministic 59-check matrix added for issue #3.  It
covers shadow/enforce, probe and manual paths, the state machine and budgets,
scope isolation, fingerprints, classification, redaction, concurrent stores,
report metrics and audit traceability.  It uses a fake clock and temporary
directories, never writes `runtime_memory/data`, and does not modify the
algorithm.

```powershell
python sim/deep_test.py --force
```

Outputs `sim/runs/deep-2026-11-03/report.json` (machine-readable) and
`summary.md` (all checks plus evidence).  The analysis is in
`sim/FINDINGS_2026-11-03.md`.

> The issue referenced `docs/RUNTIME_MEMORY_TEST_PLAN.md`, but that file is not
> present in the working tree, any branch or the git history.  The matrix is
> therefore derived from `docs/RUNTIME_MEMORY_DESIGN.md` §16/§9.5/§15 and the
> runtime-memory READMEs.

## What to inspect

- `data/events/*.jsonl`: the trace shape (`fingerprint`, `error_class`,
  `would_block`, `decision_id`).
- `data/issues.json`: `scope` vs `call` fingerprints, `retry_policy`,
  `next_retry_at`, `expires_at`, `workaround`, `source_event_ids`.
- `data/decisions.jsonl`: shadow vs enforce decisions.
- `summary.md`: actual calls, blocked calls, shadow would-block, duplicate
  attempts, resolved/open issues.
- `records.md`: a compact sample of each record type.

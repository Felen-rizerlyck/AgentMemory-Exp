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

## Edge cases

`sim/EDGE_CASES.md` lists the additional edge tests (false block, stale recovery,
Retry-After > TTL, abandoned probing, per-run budget, environment/scope
isolation, malformed journals, gc). Run them with the normal test command.

## What to inspect

- `data/events/*.jsonl`: the trace shape (`fingerprint`, `error_class`,
  `would_block`, `decision_id`).
- `data/issues.json`: `scope` vs `call` fingerprints, `retry_policy`,
  `next_retry_at`, `expires_at`, `workaround`, `source_event_ids`.
- `data/decisions.jsonl`: shadow vs enforce decisions.
- `summary.md`: actual calls, blocked calls, shadow would-block, duplicate
  attempts, resolved/open issues.
- `records.md`: a compact sample of each record type.

# Runtime Memory

An independent prototype for **operational memory**: recording tool/environment
failures, aggregating them into retryable issues, and deciding before a tool call
whether to **allow**, **probe**, or **block** it.

This directory is deliberately separate from [`demo/`](../demo/README.md). It does
not import `demo/src/attack_memory`, does not write `demo/data`, and does not
participate in the case-memory `catalog validate` / `audit` / `state` / `retention`
flows.

- Design document: [`docs/RUNTIME_MEMORY_DESIGN.md`](../docs/RUNTIME_MEMORY_DESIGN.md)
- Chinese README: [`README_CN.md`](README_CN.md)

## Why a second memory

| Memory | Question | Store |
|---|---|---|
| Case memory (`demo/`) | What does this attack look like? | `attack_patterns`, links, chains |
| **Runtime memory (this dir)** | What is broken, when may I retry, what else can I use? | `data/events`, `data/issues.json` |

`ops_journal.jsonl`, `corrections.json`, and `link_exceptions.json` in `demo/`
are *not* runtime memory: they are a write-transaction WAL, domain negative
memory, and audit exceptions respectively.

## What is implemented

- Append-only operation traces (`data/events/YYYY-MM.jsonl`)
- Issue aggregation with two key levels:
  - `scope`: endpoint/service-level failures (`unreachable`, `auth`, `rate_limit`)
  - `call`: argument/data-level failures (`schema`, `invalid_args`, `not_found`, `timeout`)
- A state machine: `cooldown → open → probing → resolved/stale`
- Per-error-class retry policy (`data/policy.json`)
- `preflight` / `postflight` library API and a small CLI
- **Shadow mode by default**: decisions are recorded, but calls still run
- Enforce mode: `block` prevents the call
- Redaction of bearer tokens, passwords, cookies and private keys
- JSONL store with a small cross-platform file lock; `issues.json` is atomic
- `report --since 7d` with shadow false-block, duplicate-attempt and probe metrics
- 77 stdlib `unittest` tests, including `tests/test_edge_cases.py` and
  `tests/test_store_edge.py`, plus a read-only verification script

## Quick start

All commands run from `runtime_memory/`.

```powershell
# 1) validate the store
python src/manage_runtime_memory.py check
python src/manage_runtime_memory.py state

# 2) end-to-end demo (temporary data dir, no repo writes)
python src/run_runtime_demo.py --shadow     # default: observe only
python src/run_runtime_demo.py --enforce    # block the repeated calls

# 3) tests + verification matrix
python -m unittest discover -s tests
python scripts/verify_runtime_memory.py
```

Python 3.11+; standard library only.

## Shadow vs enforce

```python
from runtime_memory import OperationRequest, RuntimeMemory

runtime = RuntimeMemory("data")  # policy defaults to data/policy.json (enforce=false)
req = OperationRequest(
    component="mcp", tool="hunt.query", action="search",
    target="10.7.194.120:22196", args={"q": "dns tunnel"},
    scope="global", environment_id="lab-a",
)

decision = runtime.preflight(req)
if decision.action == "block":
    # In shadow mode this is a recommendation; in enforce mode the caller must
    # skip the tool call and return decision to the model.
    ...

runtime.postflight(req, "fail", error=ConnectionRefusedError("refused"),
                   decision=decision)
```

Set `"enforce": true` in `data/policy.json` to make `block` authoritative.
The demo defaults to a temporary data directory so it never touches the
checked-in store.

## CLI

```powershell
# Inspect
python src/manage_runtime_memory.py check
python src/manage_runtime_memory.py state --json
python src/manage_runtime_memory.py issues --active
python src/manage_runtime_memory.py issue ISS-...

# Ask before a call
python src/manage_runtime_memory.py preflight \
  --component mcp --tool hunt.query --action search \
  --target 10.7.194.120:22196 --args '{"q":"dns tunnel"}' --json

# Record an outcome (usually done by a gateway, not by the model)
python src/manage_runtime_memory.py record \
  --component mcp --tool hunt.query --action search \
  --target 10.7.194.120:22196 --outcome fail \
  --error-class unreachable --message "connect refused"

# Operate
python src/manage_runtime_memory.py resolve ISS-... --basis "endpoint restored"
python src/manage_runtime_memory.py ignore ISS-... --basis "false alarm"
python src/manage_runtime_memory.py note ISS-... --text "checked again" --author analyst

# Report / cleanup
python src/manage_runtime_memory.py report --since 7d
python src/manage_runtime_memory.py gc --dry-run
```

`preflight --probe --basis "..."` records an explicit override; it is still
audited in `data/overrides.jsonl`.

## Data layout

```text
runtime_memory/
├── data/
│   ├── policy.json          # error class -> retry policy; enforce=false by default
│   ├── issues.json          # aggregated issue snapshot
│   ├── events/YYYY-MM.jsonl # append-only operation traces
│   ├── decisions.jsonl      # preflight decisions (block/probe/hint)
│   ├── overrides.jsonl      # explicit probes
│   └── playbook.md          # curated, human-reviewed notes
├── src/runtime_memory/      # models, fingerprint, policy, store, runtime, report, cli
├── src/manage_runtime_memory.py
├── src/run_runtime_demo.py
├── tests/
├── scripts/verify_runtime_memory.py
└── skills/runtime-memory/SKILL.md
```

No event log is committed. The `data/` seed is intentionally small; a real
harness should point `--root` at its own writable directory.

Record-reading notes:

- `count` = number of failure observations; `attempts` = all calls including a
  successful probe/retry.
- `max_attempts` means retries **after** the initial failure, so a resolved
  issue can legitimately have `attempts = max_attempts + 1` (for example
  3 failures + one successful probe = 4).
- `decisions.jsonl` stores only non-allow decisions (`block` / `probe` /
  `allow_with_hint`); `allow` calls appear only as events.

## Commonality with `demo/`

The layout mirrors the case-memory prototype so both can later live under one
harness:

- `src/<package>/` package + thin CLI entry point
- `data/` file store with JSON schemas and `schema_version`
- `tests/` stdlib `unittest`
- `scripts/verify_*.py` read-only matrix
- `skills/<name>/SKILL.md` runtime rules
- English + Chinese README

It deliberately does **not** share code or data with `demo/`; the two stores
have different lifecycles and audit semantics.

## Simulated run

`sim/scenario.py` is a deterministic restricted-lab scenario: shadow phase →
enforce phase → new session with persistent memory.

```powershell
python sim/scenario.py --run-id sim-2026-11-02-agent
```

It writes `sim/runs/<run-id>/` with:

- `data/events/*.jsonl`, `data/issues.json`, `data/decisions.jsonl`
- `narrative.log` (timestamped story)
- `summary.md` / `report.json`
- `records.md` (sample event / issue / decision)
- `policies.json` (shadow vs enforce phase policies)

The final example run is under
`sim/runs/sim-2026-11-02-agent-final/`, with `AGENT_NOTES.md` from the
independent runner. Earlier runs are kept for comparison.

## Relationship to a tool dependency graph

This prototype touches the **runtime health layer** of a tool dependency graph,
but it is not a dependency graph implementation.

- It knows nodes by `(environment, component, tool, target)` and records health,
  failure counts, retry windows, and workarounds.
- A `workaround` is an `alternative_to` edge in spirit, but it is stored as text.
- It does not model static `depends_on` direction, topology, planning order,
  blast radius, or graph queries.

If a graph is needed later, export a projection from this store:

```text
node: (environment, component, tool, target)
edge: calls | depends_on | alternative_to | co_fails_with
attr: status, error_class, next_retry_at, confidence
```

Do not build a graph database before the flat issue store proves useful.

## Limits

- Single-writer prototype; the lock prevents interleaved JSONL lines, not
  multi-process transactions.
- Shadow decisions are advisory until `enforce=true`; the caller must honor
  `block` in enforce mode.
- No automatic issue resolution from an external health check; a successful
  probe or a human resolve is required.
- No playbook auto-generation; `playbook.md` is curated.
- No cross-agent coordination beyond `scope` / `environment_id`.
- Default TTLs and backoffs are deliberate starting points, not calibrated
  production values.
- `preflight` with a non-empty `run_id` scans events for the per-run budget;
  in the scale probe this was ~156ms at 20k events (vs ~1ms without `run_id`).
  Add an index/cache before high-volume use, or leave `run_id` empty if the
  gateway already enforces a per-run attempt cap.
- A short backoff plus a small `max_attempts` can exhaust the issue budget
  before a long outage recovers; the 30-seed workload showed `enforce_60`
  reaching 0% success, while `enforce_900` reached 100%. Tune backoff and
  `max_attempts` together, not separately.

## Further reading

- [Design document](../docs/RUNTIME_MEMORY_DESIGN.md)
- [Executable offline test plan](../docs/RUNTIME_MEMORY_TEST_PLAN.md)
- [Chinese README](README_CN.md)
- [Demo case memory](../demo/README.md)
- [Memory/skill self-iteration survey](../docs/agent-memory-skill-self-iteration-survey-2026-10.md)

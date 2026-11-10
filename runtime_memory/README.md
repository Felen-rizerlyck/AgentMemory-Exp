# Runtime Memory

Runtime Memory is a small operational-memory prototype for tool and service
calls. It records outcomes, groups repeated failures into issues, and returns a
preflight decision: `allow`, `allow_with_hint`, `probe`, or `block`.

It is separate from [`demo/`](../demo/README.md), which stores reviewed attack
cases. Runtime Memory records tool health and retry experience; it does not
store attack cases or decide whether an alert is malicious.

## Current shape

- Append-only call events, issue snapshots, preflight decisions, and operator overrides.
- Per-error retry policy with a retry window and slow probes after the normal attempt budget.
- Retryable failures become `open` only after evidence from distinct `run_id`s; repeated failures in one run alone do not count as independent evidence.
- `shadow` is the default: the decision is advisory and the caller still invokes the tool. `enforce` blocks only when the calling gateway honors the decision.
- The local tool layer in [`tool_layer/`](tool_layer/README.md) exercises the real HTTP call boundary against a controllable localhost service. It is not an MCP server or a production gateway.
- JSONL and JSON files keep the prototype inspectable. Cross-process locking and consistency checks exist, but this is not a transactional database.

## Quick start

Commands below run from `runtime_memory/`:

```powershell
# Inspect the default store and compact active issue cards
python src/manage_runtime_memory.py check
python src/manage_runtime_memory.py state --json
python src/manage_runtime_memory.py brief

# Run the deterministic runtime-memory demonstration
python src/run_runtime_demo.py --shadow
python src/run_runtime_demo.py --enforce

# Run the local tool-layer integration demo from the repository root instead
cd ..
python runtime_memory/tool_layer/run_demo.py
```

The demos use temporary stores by default. To retain data, the tool-layer demo
accepts `--data-root <path>`; keep this separate from `runtime_memory/data/`
and `demo/data/` while experimenting. Python 3.11+; the local tool layer uses
the standard library.

## How a caller uses it

The memory library does not intercept arbitrary tool calls. A gateway must
call `preflight`, skip a non-shadow `block`, call the tool for other decisions,
and call `postflight` with the outcome and original decision:

```python
from runtime_memory import OperationRequest, RuntimeMemory

memory = RuntimeMemory("runtime-data")
request = OperationRequest(
    component="mcp", tool="search", action="search",
    target="local-service", args={"query": "health"},
    scope="session", session_id="session-1", run_id="run-1",
)
decision = memory.preflight(request)

def invoke(call_tool, request, decision):
    if decision.action == "block" and not decision.shadow:
        return {"blocked": True, "decision": decision.to_dict()}
    try:
        result = call_tool(request)
    except Exception as error:
        memory.postflight(request, "fail", error=error, decision=decision)
        raise
    memory.postflight(request, "ok", decision=decision)
    return result

result = invoke(call_tool, request, decision)
```

Always record outcomes from the harness/tool adapter, not from a model's
unverified claim. Keep `enforce` off until the gateway behavior has been
observed in shadow on representative calls.

## CLI reference

The global `--root` option comes before the subcommand. It lets a caller use a
dedicated writable store:

```powershell
python src/manage_runtime_memory.py --root ..\tmp\runtime-data check
python src/manage_runtime_memory.py --root ..\tmp\runtime-data preflight `
  --component mcp --tool search --action search --target local-service `
  --args '{"query":"health"}' --run-id run-1 --json
python src/manage_runtime_memory.py --root ..\tmp\runtime-data record `
  --component mcp --tool search --action search --target local-service `
  --outcome fail --error-class unreachable --run-id run-1
python src/manage_runtime_memory.py --root ..\tmp\runtime-data report --json
```

Other useful commands: `issues --active`, `issue <ISS-ID>`, `brief --json`,
`resolve`, `ignore`, `note`, `workaround`, and `gc` (dry-run by default).
`preflight --probe --basis ...` is an operator override and is audited.

## Layout

```text
runtime_memory/
├── src/runtime_memory/       # library: models, policy, store, runtime, report, CLI
├── src/manage_runtime_memory.py
├── src/run_runtime_demo.py
├── tool_layer/               # local HTTP tool server, memory gateway, end-to-end demo
├── data/                     # default policy/store seed; don't use for throwaway tests
├── tests/                    # unit/edge/security regression tests
├── scripts/                  # verification helpers
├── sim/                      # scenarios, workload probes, and saved run artifacts
└── skills/runtime-memory/    # agent operating guidance
```

Store files include `policy.json`, `issues.json`, `events/YYYY-MM.jsonl`,
`decisions.jsonl`, `overrides.jsonl`, and a curated `playbook.md`. Directories
under `sim/runs/` are experiment outputs, not the live default store.

## Validation and guides

From `runtime_memory/`:

```powershell
python -m unittest discover -s tests
python scripts/verify_runtime_memory.py
```

Related documents:

- [Chinese README](README_CN.md)
- [Design](../docs/RUNTIME_MEMORY_DESIGN.md)
- [Simple algorithm test guide](../docs/RUNTIME_MEMORY_SIMPLE_TEST_GUIDE_2026-11-10.md)
- [Fix and concurrency retest plan](../docs/RUNTIME_MEMORY_FIX_AND_RETEST_PLAN_2026-11-10.md)
- [Tool-layer test plan](../docs/RUNTIME_MEMORY_TOOL_LAYER_TEST_PLAN_2026-11-10.md)

## Limits

- Shadow mode does not prevent calls; the caller must honor enforce decisions to stop retries.
- The local harness tests localhost HTTP integration and controlled failures, not MCP protocol compatibility, production traffic, or real failure distributions.
- JSONL plus file locks are suitable for a small prototype, not a high-throughput multi-agent service. `preflight` with a `run_id` scans events for run-budget accounting.
- A crash between event append and issue update can leave an orphan event; `check` reports this inconsistency but does not automatically repair it.
- Backoff values are starting defaults, not production-calibrated settings.

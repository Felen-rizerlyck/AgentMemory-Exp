# Gateway Call Lifecycle

Runtime Memory is a library and policy decision point. It does not wrap tools
automatically. The harness or gateway that actually invokes a tool owns the
whole lifecycle:

```text
build stable OperationRequest
        │
        ▼
preflight(request)
   ├─ enforce + block ──► return blocked result; do not call tool
   └─ allow / hint / probe / shadow decision
                          │
                          ▼
                    call tool once
                          │
                          ▼
          postflight(request, actual outcome, decision)
```

## 1. Build the request consistently

Use the same request identity before and after the call. Set:

- `component`, `tool`, `action`, and `target` to stable identifiers;
- `environment_id` to distinguish isolated environments;
- `scope` and identity (`session_id` or `agent_id`) to control visibility;
- `run_id` when the caller has a stable run identifier and wants per-run budgets/evidence;
- `args` to the arguments used for this invocation. The runtime fingerprints normalized arguments and redacts stored values.

Avoid putting credentials in `target`, `args`, or error text. Redaction is a
fallback, not a reason to pass secrets into logs.

## 2. Interpret the preflight decision

| Decision | Shadow mode | Enforce mode |
|---|---|---|
| `allow` | Call tool | Call tool |
| `allow_with_hint` | Call tool and consider the workaround | Call tool and consider the workaround |
| `probe` | Make one probe call | Make one probe call |
| `block` | Advisory only: caller still executes and must record the actual result | Do not call the tool; return the block decision to the caller/model |

Do not turn a `block` into an unrecorded retry. An operator may issue an
audited override with a basis; model-facing logic must not impersonate an
operator override.

## 3. Record the actual outcome

For a call that ran, pass the original `Decision` to `postflight`. This links
the event to the preflight decision. Record the actual success/failure in a
`finally`-safe adapter so exceptions and cancellation paths do not disappear.
Do not call `postflight` as if a blocked enforce-mode call ran.

```python
decision = memory.preflight(request)
if decision.action == "block" and not decision.shadow:
    return {"blocked": True, "decision": decision.to_dict()}

try:
    result = tool_client.call(request)
except ToolError as error:
    memory.postflight(request, "fail", error=error, decision=decision)
    raise
else:
    memory.postflight(request, "ok", decision=decision)
    return result
```

Adapt outcome to the real failure: `timeout` for a timeout, `denied` for a
permission denial when appropriate, and `fail` for other failures. Supply
`error_class` explicitly when the tool protocol provides a reliable status
code that the generic exception classifier cannot see.

### CLI-only/manual linkage

When exercising the CLI manually, capture `decision_id` from
`preflight --json`, then pass it to `record --decision-id <id>`. Without this
ID, reports cannot reliably join a preflight decision to its outcome. For an
integrated gateway, pass `decision=decision` directly to `postflight`.

## 4. Rollout

1. Point the adapter at a dedicated writable `--root`/store; do not mix it
   with case memory in `demo/data`.
2. Start with `enforce=false`. Shadow records what would be blocked but still
   makes the call, so it measures decisions without protecting the tool.
3. Inspect `report`, false-block examples, and issue classifications.
4. Enable enforce for one low-risk component only after the gateway has been
   shown to skip blocked calls and always record calls that did run.

The local HTTP harness in `runtime_memory/tool_layer/` demonstrates this
boundary. It is not an MCP adapter; a real MCP client needs its own gateway
adapter that preserves the same lifecycle.

# Runtime Memory Tool Layer

An isolated local tool harness for exercising the real call boundary around
`RuntimeMemory`. It lives outside `src/` and `tests/` and uses only Python's
standard library beyond the existing runtime-memory package.

## What it contains

- `server.py`: a real local HTTP service with a searchable tool and controlled
  modes (`success`, `unavailable`, `timeout`, `rate_limit`, `auth`).
- `gateway.py`: calls `preflight`, invokes the HTTP tool when allowed (or in
  shadow), and records success/failure using `postflight` with the same
  decision ID.
- `run_demo.py`: one command that demonstrates healthy call, repeated outage,
  same-run vs cross-run evidence, enforce blocking, and recovery probing.

This is a local HTTP integration harness, not an MCP server. It tests actual
process/network calls and the memory gateway behavior without requiring an
external account, cloud service, or MCP SDK. An MCP client can later replace
the HTTP transport inside `gateway.py` while retaining the same request and
preflight/postflight pattern.

## Run

From the repository root:

```powershell
python runtime_memory/tool_layer/run_demo.py
```

By default, data is written to a temporary directory and removed at exit. To
retain the generated events/issues/decisions in a dedicated path:

```powershell
python runtime_memory/tool_layer/run_demo.py --data-root runtime_memory/tool_layer/runs/local-demo
```

Do not point `--data-root` at `runtime_memory/data` or `demo/data`.

## Expected observations

The JSON output should show:

1. `healthy_call` returns a local result.
2. Three simulated 503 calls are recorded as `unreachable`; two share `run-A`
   and one uses `run-B`.
3. The issue has two distinct evidence run IDs and status `open`.
4. With enforce enabled, a blocked call does not increment the backend call
   counter.
5. After the short retry interval, changing the tool to `success` allows a
   probe; the issue resolves and subsequent calls are allowed.
6. `check` returns an empty problem list.

The server's `timeout`, `rate_limit`, and `auth` modes can be selected by
posting `{"mode":"timeout"}` etc. to `/admin/mode`. Their calls are recorded
under the corresponding error class; auth is intentionally non-retryable.

## Scope and limits

This validates the end-to-end shape of a real local tool call, not production
MCP integration or production reliability. The local modes are deterministic
failure injection. Keep runtime memory in shadow for real tools until a
separate gateway adapter has been connected and observed on representative
traffic.

---
name: runtime-memory
description: Use before and after a tool call to check known operational issues, respect retry windows, record failures, and use a workaround instead of repeating a broken call.
---

# Runtime Memory Skill

Use this skill when a harness tool call (MCP, shell, file/parser, model API,
sandbox, web) may fail for **operational** reasons. It is separate from the
case-memory skill in `demo/`.

## Operating rules

1. **Before a tool call, run preflight.** Never call a tool that the runtime
   memory reports as `block` in enforce mode.
2. **Respect the action.**
   - `block`: do not call; use an `alternative` if present; report the issue id.
   - `probe`: at most one call; record the outcome.
   - `allow_with_hint`: call normally, but mention the known workaround.
   - `allow`: call normally.
3. **After every call, record the outcome.** Use `postflight` (library) or the
   gateway; do not hand-write issue status.
4. **Never mark an issue as broken by yourself.** Models may add `notes`, not
   change `status`, `next_retry_at`, or `workaround`.
5. **Override only with a basis.** `preflight --probe --basis "..."` is logged in
   `data/overrides.jsonl`; a silent retry is not allowed.
6. **Do not put runtime issues into `demo/data`.** The case-memory audit,
   retention and version semantics do not apply here.
7. **A stale issue is not a permanent block.** After `expires_at`, allow one
   probe; if it succeeds, the issue resolves.
8. **Distinguish failure layers.** `invalid_args` means the model used the tool
   wrongly; do not record it as `unreachable` or the whole endpoint will be
   blocked for the wrong reason.

## Commands

```powershell
cd runtime_memory

# Ask before a call
python src/manage_runtime_memory.py preflight \
  --component mcp --tool hunt.query --action search \
  --target 10.7.194.120:22196 --args '{"q":"dns tunnel"}' --json

# Inspect
python src/manage_runtime_memory.py issues --active
python src/manage_runtime_memory.py brief
python src/manage_runtime_memory.py issue ISS-...
python src/manage_runtime_memory.py report --since 7d

# Operate (human/operator)
python src/manage_runtime_memory.py resolve ISS-... --basis "endpoint restored"
python src/manage_runtime_memory.py ignore ISS-... --basis "false alarm"
```

## Recall policy

| decision | what to do |
|---|---|
| `block` + alternatives | use an alternative; do not retry the same call |
| `block`, no alternatives | stop and report; wait for retry window or human |
| `probe` | one attempt; then record the outcome |
| `allow_with_hint` | proceed; mention the workaround |
| `allow` | proceed |

A runtime issue is **not** evidence about the attack. It only explains why a
component is unavailable; keep case conclusions separate.

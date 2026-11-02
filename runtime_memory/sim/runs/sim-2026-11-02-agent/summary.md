# Simulated restricted-lab run

- run_id: `sim-2026-11-02-agent`
- phase A: shadow (calls execute, decisions recorded)
- phase B: enforce (blocked calls skipped)
- phase C: new session (memory persists)

## Execution

- actual calls: 13
- blocked calls: 3
- failures: 8

## Report

```text
{
  "generated_at": "2026-11-02T07:52:27.634681Z",
  "since": null,
  "events": {
    "total": 13,
    "ok": 5,
    "failures": 8,
    "by_outcome": {
      "fail": 8,
      "ok": 5
    }
  },
  "decisions": {
    "total": 9,
    "block": 5,
    "shadow_block": 2,
    "probe": 4,
    "hint": 0,
    "shadow_total": 4,
    "enforce_total": 5
  },
  "shadow": {
    "would_block": 2,
    "false_blocks": 0,
    "confirmed_blocks": 2
  },
  "enforce": {
    "blocked_calls": 3
  },
  "probes": {
    "attempts": 4,
    "success": 3,
    "success_rate": 0.75
  },
  "duplicate_attempts": 3,
  "issues": {
    "total": 5,
    "by_status": {
      "resolved": 3,
      "open": 2
    },
    "stale_rate": 0.0,
    "open": 2
  },
  "top_open_issues": [
    {
      "issue_id": "ISS-20261102T075227-889210",
      "status": "open",
      "error_class": "permission",
      "component": "shell",
      "tool": "run",
      "target": "host-01",
      "count": 1,
      "next_retry_at": null,
      "workaround": ""
    },
    {
      "issue_id": "ISS-20261102T075227-89D0D5",
      "status": "open",
      "error_class": "schema",
      "component": "parser",
      "tool": "pcap.parse",
      "target": "/data/pcap",
      "count": 1,
      "next_retry_at": null,
      "workaround": ""
    }
  ]
}
```

## What to look at

- `data/events/*.jsonl`: one line per actual tool call, with `fingerprint`, `error_class`, `would_block` and `decision_id`.
- `data/issues.json`: aggregated issues; note `scope` vs `call` fingerprints and the `workaround` / `next_retry_at` fields.
- `data/decisions.jsonl`: every block/probe decision, including shadow decisions.
- `records.md`: a small sample of each record type.
- `narrative.log`: the story with timestamps.
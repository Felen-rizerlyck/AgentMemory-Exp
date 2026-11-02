# Sample runtime-memory records

These are actual records produced by `sim/scenario.py`.

## event

```json
{
  "event_id": "OP-20261102T060000-BD528E",
  "ts": "2026-11-02T06:00:00Z",
  "component": "mcp",
  "tool": "hunt.query",
  "action": "search",
  "target": "http://10.7.194.120:22196/hunt/sse",
  "outcome": "fail",
  "scope": "global",
  "environment_id": "lab-a",
  "session_id": "sim-session-01",
  "run_id": "sim-2026-11-02-agent-v2",
  "error_class": "unreachable",
  "error_code": "",
  "message_redacted": "connect refused",
  "duration_ms": 30012,
  "attempt": 1,
  "retryable": true,
  "fingerprint": "lab-a|scope|mcp|hunt.query|search|http://10.7.194.120:22196/hunt",
  "key_level": "scope",
  "decision_id": "",
  "would_block": false,
  "evidence_ref": "",
  "author": "harness",
  "policy_version": "2026-11-02.1",
  "schema_version": 1
}
```

## issue_open

```json
{
  "issue_id": "ISS-20261102T060500-F396AE",
  "fingerprint": "lab-a|call|parser|pcap.parse|parse|/data|args:sha256:47da44f5d0cc848b",
  "key_level": "call",
  "scope": "global",
  "environment_id": "lab-a",
  "component": "parser",
  "tool": "pcap.parse",
  "action": "parse",
  "target": "/data/pcap",
  "error_class": "schema",
  "status": "open",
  "first_seen": "2026-11-02T06:05:00Z",
  "last_seen": "2026-11-02T06:05:00Z",
  "count": 1,
  "attempts": 1,
  "retry_policy": {
    "key_level": "call",
    "retryable": false,
    "mode": "none",
    "base_s": 0,
    "max_s": 0,
    "max_attempts": 0,
    "max_attempts_per_run": 1,
    "ttl_s": 86400,
    "next_retry_at": null
  },
  "next_retry_at": null,
  "expires_at": "2026-11-03T06:05:00Z",
  "workaround": "",
  "confidence": 0.6,
  "source_event_ids": [
    "OP-20261102T060500-1DCDB3"
  ],
  "last_probe_event_id": null,
  "probe_started_at": null,
  "diagnosis": "model_usage",
  "resolution": "",
  "resolved_at": null,
  "resolved_basis": "",
  "reviewer": "",
  "notes": [],
  "related_incident_id": null,
  "related_case_id": null,
  "schema_version": 1
}
```

## issue_resolved

```json
{
  "issue_id": "ISS-20261102T060000-847592",
  "fingerprint": "lab-a|scope|mcp|hunt.query|search|http://10.7.194.120:22196/hunt",
  "key_level": "scope",
  "scope": "global",
  "environment_id": "lab-a",
  "component": "mcp",
  "tool": "hunt.query",
  "action": "search",
  "target": "http://10.7.194.120:22196/hunt/sse",
  "error_class": "unreachable",
  "status": "resolved",
  "first_seen": "2026-11-02T06:00:00Z",
  "last_seen": "2026-11-02T06:02:00Z",
  "count": 3,
  "attempts": 3,
  "retry_policy": {
    "key_level": "scope",
    "retryable": true,
    "mode": "fixed",
    "base_s": 900,
    "max_s": 1800,
    "max_attempts": 3,
    "max_attempts_per_run": 1,
    "ttl_s": 86400,
    "next_retry_at": "2026-11-02T06:17:00Z"
  },
  "next_retry_at": "2026-11-02T06:17:00Z",
  "expires_at": "2026-11-03T06:02:00Z",
  "workaround": "use local pcap or cached hunt results until endpoint is restored",
  "confidence": 0.95,
  "source_event_ids": [
    "OP-20261102T060000-BD528E",
    "OP-20261102T060100-FA7799",
    "OP-20261102T060200-1E66B1",
    "OP-20261102T062332-0D9E93"
  ],
  "last_probe_event_id": "OP-20261102T062332-0D9E93",
  "probe_started_at": "2026-11-02T06:23:32Z",
  "diagnosis": "environment",
  "resolution": "fixed",
  "resolved_at": "2026-11-02T06:23:32Z",
  "resolved_basis": "success event OP-20261102T062332-0D9E93",
  "reviewer": "",
  "notes": [],
  "related_incident_id": null,
  "related_case_id": null,
  "schema_version": 1,
  "workaround_by": "analyst",
  "workaround_at": "2026-11-02T06:03:00Z"
}
```

## decision_block

```json
{
  "schema_version": 1,
  "decision_id": "DEC-20261102T060100-424E24",
  "ts": "2026-11-02T06:01:00Z",
  "component": "mcp",
  "tool": "hunt.query",
  "action": "block",
  "target": "http://10.7.194.120:22196/hunt/sse",
  "scope": "global",
  "environment_id": "lab-a",
  "session_id": "sim-session-01",
  "run_id": "sim-2026-11-02-agent-v2",
  "scope_fingerprint": "lab-a|scope|mcp|hunt.query|search|http://10.7.194.120:22196/hunt",
  "call_fingerprint": "lab-a|call|mcp|hunt.query|search|http://10.7.194.120:22196/hunt|args:sha256:8c9348a0f809ffe2",
  "decision": "block",
  "issue_id": "ISS-20261102T060000-847592",
  "reason": "blocked until retry window: unreachable @ http://10.7.194.120:22196/hunt/sse (1 failure(s))",
  "blocked_until": "2026-11-02T06:15:00Z",
  "attempts_left": 3,
  "alternatives": [],
  "confidence": 0.6,
  "expires_at": "2026-11-03T06:00:00Z",
  "policy_version": "2026-11-02.1",
  "shadow": true,
  "override": false,
  "override_basis": ""
}
```

## decision_probe

```json
{
  "schema_version": 1,
  "decision_id": "DEC-20261102T060400-149128",
  "ts": "2026-11-02T06:04:00Z",
  "component": "siem",
  "tool": "search",
  "action": "probe",
  "target": "http://siem.lab-a:9200",
  "scope": "global",
  "environment_id": "lab-a",
  "session_id": "sim-session-01",
  "run_id": "sim-2026-11-02-agent-v2",
  "scope_fingerprint": "lab-a|scope|siem|search|query|http://siem.lab-a:9200",
  "call_fingerprint": "lab-a|call|siem|search|query|http://siem.lab-a:9200|args:sha256:310364d1dca25cfd",
  "decision": "probe",
  "issue_id": "ISS-20261102T060300-F29C32",
  "reason": "retry window open: rate_limit @ http://siem.lab-a:9200 (1 failure(s))",
  "blocked_until": null,
  "attempts_left": 3,
  "alternatives": [],
  "confidence": 0.6,
  "expires_at": "2026-11-02T07:03:00Z",
  "policy_version": "2026-11-02.1",
  "shadow": true,
  "override": false,
  "override_basis": ""
}
```

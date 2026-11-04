# Runtime memory deep test matrix

- generated: 2026-11-04T02:23:26+00:00
- harness: `sim/deep_test.py`
- out: `runtime_memory/sim/runs/deep-2026-11-03`
- checks: 59
- status: CRASH=2, FINDING=16, GAP=9, PASS=32

> The requested plan `RUNTIME_MEMORY_TEST_PLAN.md` exists; this matrix is
> derived from `docs/RUNTIME_MEMORY_DESIGN.md` §16 (test plan),
> §9.5 (interception matrix) and §15 (metrics), plus additional
> robustness checks. Cross-check the two if their scopes differ.

## Checks

| # | id | category | status | severity | title |
|---|---|---|---|---|---|
| 1 | `mode.shadow` | mode | **PASS** | info | shadow records block but still executes the call |
| 2 | `mode.enforce` | mode | **PASS** | info | enforce mode refuses postflight for a blocked call |
| 3 | `mode.probe_in_flight` | mode | **PASS** | info | a second preflight while a probe is in flight blocks |
| 4 | `mode.policy_load` | mode | **PASS** | info | enforce mode is loaded from data/policy.json |
| 5 | `mode.note` | mode | **PASS** | info | a model note never changes status or next_retry_at |
| 6 | `mode.probe_ok` | mode | **PASS** | info | a successful probe resolves the issue |
| 7 | `mode.probe_fail` | mode | **PASS** | info | a failed probe reopens the issue and increments the backoff |
| 8 | `mode.manual` | mode | **PASS** | info | resolve allows the call and a new failure reopens the issue |
| 9 | `mode.mitigated` | mode | **PASS** | info | a mitigated issue yields allow_with_hint and the workaround |
| 10 | `mode.workaround_only` | mode | **FINDING** | low | recording a workaround transitions to mitigated |
| 11 | `mode.override_auth` | mode | **FINDING** | high | model override bypasses a non-retryable auth block |
| 12 | `mode.override_budget` | mode | **FINDING** | high | model override bypasses the per-run hard budget |
| 13 | `mode.override_audit` | mode | **PASS** | info | every override is recorded in overrides.jsonl |
| 14 | `state.cooldown_open` | state | **PASS** | info | the first failure creates cooldown, the second opens the issue |
| 15 | `state.retry_window` | state | **PASS** | info | preflight blocks before next_retry_at and probes after it |
| 16 | `state.schema` | state | **PASS** | info | schema failures block only the bad call and are not retried |
| 17 | `state.invalid_args` | state | **PASS** | info | invalid_args failures block only the bad call and are not retried |
| 18 | `state.retry_after` | state | **PASS** | info | Retry-After wins over the class backoff and extends expiry |
| 19 | `state.auth_stale` | state | **PASS** | info | non-retryable auth blocks until TTL, then allows one probe |
| 20 | `state.abandoned_probe` | state | **PASS** | info | an abandoned probe without probe_started_at recovers |
| 21 | `state.attempt_budget` | state | **PASS** | info | the issue-level attempt budget eventually blocks |
| 22 | `state.per_class_run_budget` | state | **GAP** | medium | the class-level max_attempts_per_run is not enforced |
| 23 | `state.probe_after_expiry` | state | **GAP** | low | probe_after_expiry=false is ignored |
| 24 | `state.defaults` | state | **GAP** | low | policy.defaults is not used for cooldown/TTL |
| 25 | `state.read_only` | state | **PASS** | info | record=False writes no decision and does not probe |
| 26 | `state.mitigated_expired` | state | **FINDING** | medium | mitigating an already-expired issue is immediately undone |
| 27 | `state.jitter` | state | **GAP** | low | exponential backoff has no jitter |
| 28 | `scope.environment` | scope | **PASS** | info | environment_id isolates issues |
| 29 | `scope.session` | scope | **FINDING** | high | a session-scope issue blocks every other session |
| 30 | `scope.agent` | scope | **FINDING** | high | an agent-scope issue blocks every other agent |
| 31 | `scope.global_resolution` | scope | **FINDING** | medium | a successful session call cannot resolve a global issue |
| 32 | `scope.mixed` | scope | **FINDING** | medium | a session failure updates the global issue record |
| 33 | `scope.cross_env_mitigation` | scope | **GAP** | low | another environment's success does not mitigate the issue |
| 34 | `identity.normalise` | identity | **PASS** | info | target and argument normalisation is stable |
| 35 | `identity.key_level` | identity | **PASS** | info | call-level failures only block the same arguments |
| 36 | `identity.bad_port` | identity | **CRASH** | medium | a malformed URL port does not crash preflight |
| 37 | `identity.non_json_args` | identity | **CRASH** | medium | non-JSON argument values do not crash preflight |
| 38 | `classify.known` | classify | **PASS** | info | known exception types map to the documented class |
| 39 | `classify.server_errors` | classify | **FINDING** | medium | 5xx and errno-based network errors fall back to unknown |
| 40 | `classify.invalid_args` | classify | **GAP** | medium | postflight cannot pass the argument context to the classifier |
| 41 | `security.redaction` | security | **PASS** | info | header, URL, password and private-key redaction works |
| 42 | `security.redaction_json` | security | **FINDING** | high | JSON-formatted secrets are not redacted |
| 43 | `security.target_credentials` | security | **FINDING** | high | URL userinfo credentials leak through the raw target field |
| 44 | `security.message_limit` | security | **PASS** | info | message_redacted is truncated |
| 45 | `store.multiprocess` | store | **FINDING** | high | concurrent record() calls crash on the file lock and/or lose counts |
| 46 | `store.lock_contention` | store | **FINDING** | high | the JSONL file lock can raise an uncaught PermissionError on Windows |
| 47 | `store.atomic_json` | store | **PASS** | info | issues.json remains a complete JSON document |
| 48 | `store.corrupt_events` | store | **FINDING** | medium | a corrupt event journal raises from report and budgeted preflight |
| 49 | `audit.expires_at` | audit | **FINDING** | low | check() does not enforce the expires_at invariant |
| 50 | `store.find_live` | store | **PASS** | info | find_issue prefers the live duplicate |
| 51 | `store.gc` | store | **PASS** | info | gc deletes old events/resolved issues and keeps audit logs |
| 52 | `report.link` | report | **FINDING** | medium | shadow false blocks require the caller to pass the decision |
| 53 | `report.rate` | report | **GAP** | low | report exposes counts but not false_block_rate |
| 54 | `report.probe_rate` | report | **PASS** | info | probe success rate is reported |
| 55 | `report.duplicate_scope` | report | **GAP** | low | duplicate_attempts is not scoped to a run |
| 56 | `audit.block_issue` | audit | **PASS** | info | a per-run budget block is explicit and may lack an issue_id |
| 57 | `audit.override` | audit | **PASS** | info | overrides are audited |
| 58 | `audit.reopen` | audit | **PASS** | info | a resolved issue can be reopened by a new failure |
| 59 | `audit.rebuild` | audit | **GAP** | info | rebuild_issues is not implemented |

## Categories

| category | pass | finding | gap | crash |
|---|---|---|---|---|
| audit | 3 | 1 | 1 | 0 |
| classify | 1 | 1 | 1 | 0 |
| identity | 2 | 0 | 0 | 2 |
| mode | 10 | 3 | 0 | 0 |
| report | 1 | 1 | 2 | 0 |
| scope | 1 | 4 | 1 | 0 |
| security | 2 | 2 | 0 | 0 |
| state | 9 | 1 | 4 | 0 |
| store | 3 | 3 | 0 | 0 |

## Non-pass detail

### mode.workaround_only (FINDING, low)

**recording a workaround transitions to mitigated**

- expected: set_workaround should make the issue mitigated (design §7.2 / README_CN §3.3) and preflight should return allow_with_hint
- observed: {'status': 'cooldown', 'decision': 'block', 'alternatives': ['use local pcap']}

```json
{
  "status": "cooldown",
  "decision": "block",
  "alternatives": [
    "use local pcap"
  ]
}
```

### mode.override_auth (FINDING, high)

**model override bypasses a non-retryable auth block**

- expected: auth is non-retryable and should require a human/operator decision (design §7.3, §9.3); a model override should not be enough
- observed: {'blocked': 'block', 'override': 'probe', 'override_reason': 'override: model wants to retry', 'issue_status': 'probing', 'overrides': 1}

```json
{
  "blocked": "block",
  "override": "probe",
  "override_reason": "override: model wants to retry",
  "issue_status": "probing",
  "overrides": 1
}
```

### mode.override_budget (FINDING, high)

**model override bypasses the per-run hard budget**

- expected: the per-run budget is described as a hard guard; an override should not turn its block into a probe
- observed: {'blocked': 'block', 'blocked_reason': 'run budget exhausted: 1 failure(s) for this operation in budget-run', 'blocked_issue_id': '', 'override': 'probe', 'override_reason': 'override: try anyway', 'override_issue_id': ''}

```json
{
  "blocked": "block",
  "blocked_reason": "run budget exhausted: 1 failure(s) for this operation in budget-run",
  "blocked_issue_id": "",
  "override": "probe",
  "override_reason": "override: try anyway",
  "override_issue_id": ""
}
```

### state.per_class_run_budget (GAP, medium)

**the class-level max_attempts_per_run is not enforced**

- expected: policy.classes.unreachable.max_attempts_per_run=1 should cap failures in one run
- observed: {'class_max_attempts_per_run': 1, 'failures_in_single_run': 4, 'issue_attempts': 4}

```json
{
  "class_max_attempts_per_run": 1,
  "failures_in_single_run": 4,
  "issue_attempts": 4
}
```

### state.probe_after_expiry (GAP, low)

**probe_after_expiry=false is ignored**

- expected: policy.defaults.probe_after_expiry should be honoured
- observed: {'configured_probe_after_expiry': False, 'decision': 'probe', 'reason': 'stale issue; one probe allowed: auth @ http://10.7.194.120:22196/hunt/sse (1 failure(s))'}

```json
{
  "configured_probe_after_expiry": false,
  "decision": "probe",
  "reason": "stale issue; one probe allowed: auth @ http://10.7.194.120:22196/hunt/sse (1 failure(s))"
}
```

### state.defaults (GAP, low)

**policy.defaults is not used for cooldown/TTL**

- expected: policy.defaults.cooldown_s and issue_ttl_s should affect the default backoff/TTL; the class values win and the defaults keys are dead configuration
- observed: {'defaults': {'cooldown_s': 1, 'issue_ttl_s': 1}, 'next_retry_delta_s': 900, 'expires_delta_s': 86400}

```json
{
  "defaults": {
    "cooldown_s": 1,
    "issue_ttl_s": 1
  },
  "next_retry_delta_s": 900,
  "expires_delta_s": 86400
}
```

### state.mitigated_expired (FINDING, medium)

**mitigating an already-expired issue is immediately undone**

- expected: resolve(..., resolution='mitigated') should remain mitigated until it is re-checked or a new failure occurs
- observed: {'status_after_resolve': 'mitigated', 'expires_at': '2026-11-03T06:00:00Z', 'next_decision': 'probe', 'status_after_next_preflight': 'stale'}

```json
{
  "status_after_resolve": "mitigated",
  "expires_at": "2026-11-03T06:00:00Z",
  "next_decision": "probe",
  "status_after_next_preflight": "stale"
}
```

### state.jitter (GAP, low)

**exponential backoff has no jitter**

- expected: design §10.2 calls for ±20% jitter to avoid synchronised retries
- observed: {'delays_s': [30, 60, 120], 'expected_without_jitter': [30, 60, 120]}

```json
{
  "delays_s": [
    30,
    60,
    120
  ],
  "expected_without_jitter": [
    30,
    60,
    120
  ]
}
```

### scope.session (FINDING, high)

**a session-scope issue blocks every other session**

- expected: design §13: 'session 只在本 run 生效'; session-a must not block session-b
- observed: {'failure_session': 'session-a', 'other_session': 'session-b', 'decision': 'block', 'reason': 'blocked until retry window: unreachable @ http://10.7.194.120:22196/hunt/sse (1 failure(s))'}

```json
{
  "failure_session": "session-a",
  "other_session": "session-b",
  "decision": "block",
  "reason": "blocked until retry window: unreachable @ http://10.7.194.120:22196/hunt/sse (1 failure(s))"
}
```

### scope.agent (FINDING, high)

**an agent-scope issue blocks every other agent**

- expected: design §13: 'agent' means one Agent; agent-a must not block agent-b
- observed: {'decision': 'block', 'reason': 'blocked until retry window: unreachable @ http://10.7.194.120:22196/hunt/sse (1 failure(s))'}

```json
{
  "decision": "block",
  "reason": "blocked until retry window: unreachable @ http://10.7.194.120:22196/hunt/sse (1 failure(s))"
}
```

### scope.global_resolution (FINDING, medium)

**a successful session call cannot resolve a global issue**

- expected: design §7.3: another scope's success may mitigate; at minimum a genuine success must not leave the issue stuck in probing
- observed: {'probe': 'probe', 'issue_scope': 'global', 'status_after_session_success': 'probing'}

```json
{
  "probe": "probe",
  "issue_scope": "global",
  "status_after_session_success": "probing"
}
```

### scope.mixed (FINDING, medium)

**a session failure updates the global issue record**

- expected: scope is part of issue ownership; the same operation failing in session s2 should not increment the global issue
- observed: {'issue_count': 1, 'scopes': ['global'], 'counts': [2]}

```json
{
  "issue_count": 1,
  "scopes": [
    "global"
  ],
  "counts": [
    2
  ]
}
```

### scope.cross_env_mitigation (GAP, low)

**another environment's success does not mitigate the issue**

- expected: design §7.2: 'open --other environment success--> mitigated'
- observed: {'lab_a_issue_status': 'cooldown'}

```json
{
  "lab_a_issue_status": "cooldown"
}
```

### identity.bad_port (CRASH, medium)

**a malformed URL port does not crash preflight**

- expected: preflight returns a decision (or a documented validation error), never an uncaught exception
- observed: ValueError: Port out of range 0-65535

```json
{
  "exception": "ValueError",
  "message": "Port out of range 0-65535"
}
```

### identity.non_json_args (CRASH, medium)

**non-JSON argument values do not crash preflight**

- expected: preflight returns a decision (or a documented validation error), never an uncaught exception
- observed: TypeError: Object of type bytes is not JSON serializable

```json
{
  "exception": "TypeError",
  "message": "Object of type bytes is not JSON serializable"
}
```

### classify.server_errors (FINDING, medium)

**5xx and errno-based network errors fall back to unknown**

- expected: design §8.5: 5xx -> internal; OSError(errno=101/111) -> unreachable
- observed: {'HTTP 500': 'unknown', 'HTTP 503': 'unknown', 'OSError(errno=101)': 'unknown', 'OSError(errno=111)': 'unknown'}

```json
{
  "HTTP 500": "unknown",
  "HTTP 503": "unknown",
  "OSError(errno=101)": "unknown",
  "OSError(errno=111)": "unknown"
}
```

### classify.invalid_args (GAP, medium)

**postflight cannot pass the argument context to the classifier**

- expected: the classifier supports context['source']='args' -> invalid_args, but postflight has no context parameter, so a plain ValueError becomes unknown
- observed: {'context_parameter': False, 'ValueError_without_context': 'unknown', 'ValueError_with_args_context': 'invalid_args'}

```json
{
  "context_parameter": false,
  "ValueError_without_context": "unknown",
  "ValueError_with_args_context": "invalid_args"
}
```

### security.redaction_json (FINDING, high)

**JSON-formatted secrets are not redacted**

- expected: error messages often contain JSON; password/token/api_key and quoted Authorization values must be redacted before storage
- observed: {'{"password": "hunter2", "token": "tok-abc", "api_key": "AK-123"}': '{"password": "hunter2", "token": "tok-abc", "api_key": "AK-123"}', '{"Authorization": "Bearer abc123"}': '{"Authorization": "Bearer abc123"}'}

```json
{
  "{\"password\": \"hunter2\", \"token\": \"tok-abc\", \"api_key\": \"AK-123\"}": "{\"password\": \"hunter2\", \"token\": \"tok-abc\", \"api_key\": \"AK-123\"}",
  "{\"Authorization\": \"Bearer abc123\"}": "{\"Authorization\": \"Bearer abc123\"}"
}
```

### security.target_credentials (FINDING, high)

**URL userinfo credentials leak through the raw target field**

- expected: credentials must not appear in issue.target, decision.reason or report.top_open_issues
- observed: {'issue_target': 'https://user:hunter2@10.0.0.1/hunt', 'decision_reason': 'blocked until retry window: unreachable @ https://user:hunter2@10.0.0.1/hunt (1 failure(s))', 'report_target': 'https://user:hunter2@10.0.0.1/hunt'}

```json
{
  "issue_target": "https://user:hunter2@10.0.0.1/hunt",
  "decision_reason": "blocked until retry window: unreachable @ https://user:hunter2@10.0.0.1/hunt (1 failure(s))",
  "report_target": "https://user:hunter2@10.0.0.1/hunt"
}
```

### store.multiprocess (FINDING, high)

**concurrent record() calls crash on the file lock and/or lose counts**

- expected: 4 events -> 1 issue, count=4; the README calls the JSONL lock cross-platform and the lock should wait, not raise an uncaught OSError
- observed: [{'round': 0, 'errors': [], 'events': 4, 'issue_records': 3, 'issue_counts': [1, 1, 1], 'issue_attempts': [1, 1, 1], 'sum_counts': 3}, {'round': 1, 'errors': [{'type': 'PermissionError', 'message': "[WinError 5] 拒绝访问。: 'C:\\\\Users\\\\cui-home\\\\AppData\\\\Local\\\\Temp\\\\rtmem-deep-mp-nih8wl8x\\\\tmpiscfhiqe.tmp' -> 'C:\\\\Users\\\\cui-home\\\\AppData\\\\Local\\\\Temp\\\\rtmem-deep-mp-nih8wl8x\\\\issues.json'"}], 'events': 4, 'issue_records': 3, 'issue_counts': [1, 1, 1], 'issue_attempts': [1, 1, 1], 'sum_counts': 3}, {'round': 2, 'errors': [], 'events': 4, 'issue_records': 3, 'issue_counts': [1, 1, 1], 'issue_attempts': [1, 1, 1], 'sum_counts': 3}]

```json
[
  {
    "round": 0,
    "errors": [],
    "events": 4,
    "issue_records": 3,
    "issue_counts": [
      1,
      1,
      1
    ],
    "issue_attempts": [
      1,
      1,
      1
    ],
    "sum_counts": 3
  },
  {
    "round": 1,
    "errors": [
      {
        "type": "PermissionError",
        "message": "[WinError 5] 拒绝访问。: 'C:\\\\Users\\\\cui-home\\\\AppData\\\\Local\\\\Temp\\\\rtmem-deep-mp-nih8wl8x\\\\tmpiscfhiqe.tmp' -> 'C:\\\\Users\\\\cui-home\\\\AppData\\\\Local\\\\Temp\\\\rtmem-deep-mp-nih8wl8x\\\\issues.json'"
      }
    ],
    "events": 4,
    "issue_records": 3,
    "issue_counts": [
      1,
      1,
      1
    ],
    "issue_attempts": [
      1,
      1,
      1
    ],
    "sum_counts": 3
  },
  {
    "round": 2,
    "errors": [],
    "events": 4,
    "issue_records": 3,
    "issue_counts": [
      1,
      1,
      1
    ],
    "issue_attempts": [
      1,
      1,
      1
    ],
    "sum_counts": 3
  }
]
```

### store.lock_contention (FINDING, high)

**the JSONL file lock can raise an uncaught PermissionError on Windows**

- expected: file_lock should treat Access Denied / FileExists as contention and retry until its timeout; a thread must not crash
- observed: errors=[{'round': 4, 'type': 'PermissionError', 'message': "[Errno 13] Permission denied: 'C:\\\\Users\\\\cui-home\\\\AppData\\\\Local\\\\Temp\\\\rtmem-deep-lock-onn6u81z\\\\events.jsonl.lock'"}]; rounds=[{'round': 0, 'lines': 80, 'expected': 80}, {'round': 1, 'lines': 80, 'expected': 80}, {'round': 2, 'lines': 80, 'expected': 80}, {'round': 3, 'lines': 80, 'expected': 80}, {'round': 4, 'lines': 72, 'expected': 80}]

```json
{
  "errors": [
    {
      "round": 4,
      "type": "PermissionError",
      "message": "[Errno 13] Permission denied: 'C:\\\\Users\\\\cui-home\\\\AppData\\\\Local\\\\Temp\\\\rtmem-deep-lock-onn6u81z\\\\events.jsonl.lock'"
    }
  ],
  "rounds": [
    {
      "round": 0,
      "lines": 80,
      "expected": 80
    },
    {
      "round": 1,
      "lines": 80,
      "expected": 80
    },
    {
      "round": 2,
      "lines": 80,
      "expected": 80
    },
    {
      "round": 3,
      "lines": 80,
      "expected": 80
    },
    {
      "round": 4,
      "lines": 72,
      "expected": 80
    }
  ]
}
```

### store.corrupt_events (FINDING, medium)

**a corrupt event journal raises from report and budgeted preflight**

- expected: check() reports the journal problem; report/preflight should return a controlled error instead of an uncaught ValueError
- observed: {'report': 'ValueError: 2026-11.jsonl line 1: Expecting value: line 1 column 1 (char 0)', 'preflight_with_run': 'ValueError: 2026-11.jsonl line 1: Expecting value: line 1 column 1 (char 0)', 'preflight_without_run': 'allow', 'check': ['journal: 2026-11.jsonl line 1: Expecting value: line 1 column 1 (char 0)']}

```json
{
  "report": "ValueError: 2026-11.jsonl line 1: Expecting value: line 1 column 1 (char 0)",
  "preflight_with_run": "ValueError: 2026-11.jsonl line 1: Expecting value: line 1 column 1 (char 0)",
  "preflight_without_run": "allow",
  "check": [
    "journal: 2026-11.jsonl line 1: Expecting value: line 1 column 1 (char 0)"
  ]
}
```

### audit.expires_at (FINDING, low)

**check() does not enforce the expires_at invariant**

- expected: design §16.3 invariant 4: expires_at always exists; check() should report an issue without it
- observed: []

```json
[]
```

### report.link (FINDING, medium)

**shadow false blocks require the caller to pass the decision**

- expected: a shadow block followed by a successful call should count as a false block even when the caller only records the outcome
- observed: {'decision': 'block', 'would_block': 1, 'false_blocks': 0, 'false_block_rate_present': False}

```json
{
  "decision": "block",
  "would_block": 1,
  "false_blocks": 0,
  "false_block_rate_present": false
}
```

### report.rate (GAP, low)

**report exposes counts but not false_block_rate**

- expected: design §15.1 defines false_block_rate; the report has would_block/false_blocks but no rate
- observed: {'decision': 'block', 'would_block': 1, 'false_blocks': 0, 'false_block_rate_present': False}

```json
{
  "decision": "block",
  "would_block": 1,
  "false_blocks": 0,
  "false_block_rate_present": false
}
```

### report.duplicate_scope (GAP, low)

**duplicate_attempts is not scoped to a run**

- expected: design §15.1 defines duplicate_attempts 'in run'; the report counts repeats across all runs
- observed: {'duplicate_attempts': 1, 'note': 'two failures in distinct runs'}

```json
{
  "duplicate_attempts": 1,
  "note": "two failures in distinct runs"
}
```

### audit.rebuild (GAP, info)

**rebuild_issues is not implemented**

- expected: design §11.6 proposes rebuilding issues from events; the prototype has no rebuild method
- observed: method absent

```json
"absent"
```

## Reproduce

```powershell
cd runtime_memory
python sim/deep_test.py --force
```

The harness uses fake clocks and temporary data directories; it does
not write to `runtime_memory/data` and does not modify the algorithm.

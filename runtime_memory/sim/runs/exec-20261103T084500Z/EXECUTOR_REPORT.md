# Executor report — exec-20261103T084500Z

## Environment

- python: 3.14.0
- commit: 5b1dcfe
- git status: M runtime_memory/sim/deep_test.py
?? runtime_memory/sim/concurrency.py
?? runtime_memory/sim/multitool.py
?? runtime_memory/sim/policy_grid.py
?? runtime_memory/sim/redaction_fuzz.py
?? runtime_memory/sim/retention.py
?? runtime_memory/sim/run_plan.py
?? runtime_memory/sim/scale_multi.py
- started: 2026-11-03T08:45:16+00:00
- finished: 2026-11-03T08:53:45+00:00
- data/issues.json: `{"schema_version": 1, "issues": []}`

## Baseline

| check | command | exit | status | seconds |
|---|---|---|---|---|
| T0.1 | `C:\Python314\python.exe -m unittest discover -s tests` | 0 | **PASS** | 6.84 |
| T0.2 | `C:\Python314\python.exe scripts/verify_runtime_memory.py` | 0 | **PASS** | 9.7 |
| T0.3 | `C:\Python314\python.exe src/manage_runtime_memory.py check` | 0 | **PASS** | 0.61 |

## Results

| ID | purpose | command | exit | status | seconds | notes |
|---|---|---|---|---|---|---|
| T0.1 | baseline unit tests | `C:\Python314\python.exe -m unittest discover -s tests` | 0 | **PASS** | 6.84 | ............................................................................. / ---------------------------------------------------------------------- / Ran 77 tests in 6.088s /  / OK |
| T0.2 | verification matrix | `C:\Python314\python.exe scripts/verify_runtime_memory.py` | 0 | **PASS** | 9.7 | simulate operator fix: resolve ISS-20261102T060000-FD7E49 / preflight after resolve -> allow / OK: enforce demo /  / Runtime memory verification: PASS |
| T0.3 | store check | `C:\Python314\python.exe src/manage_runtime_memory.py check` | 0 | **PASS** | 0.61 | Runtime memory check clean. |
| T1.1 | edge cases | `C:\Python314\python.exe -m unittest discover -s tests -p test_edge_cases.py -v` | 0 | **PASS** | 1.97 |  / ---------------------------------------------------------------------- / Ran 13 tests in 1.274s /  / OK |
| T1.2 | store edge cases | `C:\Python314\python.exe -m unittest discover -s tests -p test_store_edge.py -v` | 0 | **PASS** | 0.86 |  / ---------------------------------------------------------------------- / Ran 7 tests in 0.172s /  / OK |
| T1.3 | 59-check deep matrix | `C:\Python314\python.exe sim/deep_test.py --out F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\deep --force` | 0 | **PASS** | 11.82 | checks=59 CRASH=2 FINDING=16 GAP=9 PASS=32 / wrote F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\deep |
| T2 | Monte-Carlo workload | `C:\Python314\python.exe sim/workload.py --seeds 30 --run-id exec-20261103T084500Z-workload --out F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\workload` | 0 | **PASS** | 166.21 | enforce_900: {'runs': 30, 'success_rate': 1.0, 'mean_calls': 2.533, 'mean_failures': 1.533, 'mean_blocked': 1.533, 'mean_would_block': 0, 'mean_false_blocks': 0, 'false_block_rate': 0.0, 'mean_time_to_success_s': 1380, 'p95_time_to_success_s': 1800, 'mean_duplicate_failures': 0.533} / shadow_1800: {'runs': 30, 'success_rate': 1.0, 'mean_calls': 16.9, 'mean_failures': 15.9, 'mean_blocked': 0, 'mean_would_block': 15.9, 'mean_false_blocks': 1, 'false_block_rate': 0.063, 'mean_time_to_success_s': 954, 'p95_time_to_success_s': 1740, 'mean_duplicate_failures': 14.9} / enforce_1800: {'runs': 30, 'success_rate': 1.0, 'mean_calls': 2, 'mean_failures': 1, 'mean_blocked': 1, 'mean_would_block': 0, 'mean_false_blocks': 0, 'false_block_rate': 0.0, 'mean_time_to_success_s': 1800, 'p95_time_to_success_s': 1800, 'mean_duplicate_failures': 0.0} /  / wrote F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\workload |
| T3 | policy grid | `C:\Python314\python.exe sim/policy_grid.py --seeds 10 --run-id exec-20261103T084500Z-policy-grid --out F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\policy-grid` | 0 | **PASS** | 140.12 | enforce_b1800_m5_ttl86400: success=1.0 calls=2 blocked=1 / enforce_b1800_m10_ttl3600: success=1.0 calls=2 blocked=1 / enforce_b1800_m10_ttl86400: success=1.0 calls=2 blocked=1 /  / wrote F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\policy-grid |
| T4 | multi-tool / alternatives | `C:\Python314\python.exe sim/multitool.py --seeds 30 --run-id exec-20261103T084500Z-multitool --out F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\multitool` | 0 | **PASS** | 142.59 | shadow: {'runs': 30, 'task_success_rate': 0.233, 'mean_calls': 44.1, 'mean_failures': 27.667, 'mean_blocked': 26.633, 'mean_would_block': 26.633, 'mean_false_blocks': 1.467, 'mean_tts_s': 565.714, 'mean_duplicate_failures': 26.667} / enforce_obedient: {'runs': 30, 'task_success_rate': 1.0, 'mean_calls': 4.233, 'mean_failures': 2.5, 'mean_blocked': 6.867, 'mean_would_block': 0, 'mean_false_blocks': 0, 'mean_tts_s': 162, 'mean_duplicate_failures': 1.5} / enforce_naive: {'runs': 30, 'task_success_rate': 0.233, 'mean_calls': 13, 'mean_failures': 3.533, 'mean_blocked': 35, 'mean_would_block': 0, 'mean_false_blocks': 0, 'mean_tts_s': 900, 'mean_duplicate_failures': 2.533} /  / wrote F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\multitool |
| T5a | scale 1k/5k/20k | `C:\Python314\python.exe sim/scale.py --sizes 1000,5000,20000 --run-id exec-20261103T084500Z-scale --out F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\scale` | 0 | **PASS** | 2.49 | / 5000 / 0.9 ms / 44.68 ms / 37.99 ms / 39.46 ms / / / 20000 / 0.75 ms / 162.01 ms / 155.98 ms / 161.09 ms / /  /  / wrote F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\scale |
| T5b | multi-issue scale | `C:\Python314\python.exe sim/scale_multi.py --issues 100 --events 5000 --run-id exec-20261103T084500Z-scale-multi --out F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\scale-multi` | 0 | **PASS** | 5.8 | / 100 / 5000 / 8.06 ms / 110.56 ms / 127.37 ms / 108.07 ms / 120628 B / 1688890 B / /  / check problems: none /  / wrote F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\scale-multi |
| T5c | scale 100k | `C:\Python314\python.exe sim/scale.py --sizes 100000 --run-id exec-20261103T084500Z-scale-100k --out F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\scale-100k` | 0 | **PASS** | 12.07 | / 100000 / 0.91 ms / 1375.74 ms / 1860.91 ms / 1870.67 ms / /  / `preflight with run_id` includes the per-run budget scan over all events; `preflight no run_id` skips it. /  / wrote F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\scale-100k |
| T6 | concurrency / crash | `C:\Python314\python.exe sim/concurrency.py --run-id exec-20261103T084500Z-concurrency --out F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\concurrency` | 0 | **FAIL** | 3.53 | concurrency checks failed / - `concurrent_postflight`: 2 processes record the same failure. / - `partial_write_event_without_issue`: check() visibility. / - `terminate_between_event_and_issue`: simulated crash after the event append, before the issue update. /  / wrote F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\concurrency |
| T7 | retention / gc | `C:\Python314\python.exe sim/retention.py --days 90 --run-id exec-20261103T084500Z-retention --out F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\retention` | 0 | **PASS** | 1.21 | old_resolved_deleted: True / recent_resolved_kept: True / check: clean /  / wrote F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\retention |
| T8 | redaction fuzz | `C:\Python314\python.exe sim/redaction_fuzz.py --messages 1000 --run-id exec-20261103T084500Z-redaction --out F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\redaction` | 0 | **FAIL** | 1.89 | plan-pattern leaks=0; json leaks=300; target leaks=2 / normal text preserved: True /  / Note: the plan lists header/password/token/cookie/private-key patterns; JSON-formatted secrets and URL userinfo are included as realistic additional variants. /  / wrote F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\redaction |

## Metrics

### T2 workload

| config | success | calls | failures | blocked | false_rate | mean TTS |
|---|---|---|---|---|---|---|
| baseline | 1.0 | 16.9 | 15.9 | 0 | 0.0 | 954 |
| shadow_60 | 1.0 | 16.9 | 15.9 | 0 | 0.078 | 954 |
| enforce_60 | 0.0 | 4 | 4 | 57 | 0.0 | None |
| shadow_300 | 1.0 | 16.9 | 15.9 | 0 | 0.063 | 954 |
| enforce_300 | 0.467 | 3.5 | 3.033 | 24.9 | 0.0 | 578.6 |
| shadow_900 | 1.0 | 16.9 | 15.9 | 0 | 0.063 | 954 |
| enforce_900 | 1.0 | 2.533 | 1.533 | 1.533 | 0.0 | 1380 |
| shadow_1800 | 1.0 | 16.9 | 15.9 | 0 | 0.063 | 954 |
| enforce_1800 | 1.0 | 2 | 1 | 1 | 0.0 | 1800 |

### T3 policy grid (summary)

32 cells; raw `grid.csv` in `F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e\runtime_memory\sim\runs\exec-20261103T084500Z\policy-grid`.

- best: `enforce_b300_m10_ttl3600` success=1.0
- worst: `enforce_b60_m1_ttl3600` success=0.0

### T4 multi-tool

```json
{
  "schema_version": 1,
  "parameters": {
    "seeds": 30,
    "interval_s": 60,
    "horizon_s": 900,
    "alternative_p": 0.7
  },
  "configs": {
    "baseline": {
      "runs": 30,
      "task_success_rate": 0.233,
      "mean_calls": 44.1,
      "mean_failures": 27.667,
      "mean_blocked": 0,
      "mean_would_block": 0,
      "mean_false_blocks": 0,
      "mean_tts_s": 565.714,
      "mean_duplicate_failures": 26.667
    },
    "shadow": {
      "runs": 30,
      "task_success_rate": 0.233,
      "mean_calls": 44.1,
      "mean_failures": 27.667,
      "mean_blocked": 26.633,
      "mean_would_block": 26.633,
      "mean_false_blocks": 1.467,
      "mean_tts_s": 565.714,
      "mean_duplicate_failures": 26.667
    },
    "enforce_obedient": {
      "runs": 30,
      "task_success_rate": 1.0,
      "mean_calls": 4.233,
      "mean_failures": 2.5,
      "mean_blocked": 6.867,
      "mean_would_block": 0,
      "mean_false_blocks": 0,
      "mean_tts_s": 162,
      "mean_duplicate_failures": 1.5
    },
    "enforce_naive": {
      "runs": 30,
      "task_success_rate": 0.233,
      "mean_calls": 13,
      "mean_failures": 3.533,
      "mean_blocked": 35,
      "mean_would_block": 0,
      "mean_false_blocks": 0,
      "mean_tts_s": 900,
      "mean_duplicate_failures": 2.533
    },
    "cross_tool_checks": {
      "checks": {
        "unrelated_tool_allowed": true,
        "same_scope_blocked": true,
        "call_level_args_isolated": true,
        "workaround_in_alternatives": true,
        "same_component_other_tool_allowed": true
      },
      "all_pass": true
    },
    "comparisons": {
      "obedient_not_below_baseline": true,
      "naive_worse_than_obedient": true
    }
  }
}
```

### T5 scale

```json
{
  "schema_version": 1,
  "rows": [
    {
      "size": 1000,
      "preflight_no_run_ms": 0.77,
      "preflight_with_run_ms": 15.82,
      "report_ms": 10.5,
      "check_ms": 30.35
    },
    {
      "size": 5000,
      "preflight_no_run_ms": 0.9,
      "preflight_with_run_ms": 44.68,
      "report_ms": 37.99,
      "check_ms": 39.46
    },
    {
      "size": 20000,
      "preflight_no_run_ms": 0.75,
      "preflight_with_run_ms": 162.01,
      "report_ms": 155.98,
      "check_ms": 161.09
    }
  ]
}
```

### T5 multi-issue

```json
{
  "schema_version": 1,
  "rows": [
    {
      "issues": 100,
      "events": 5000,
      "preflight_no_run_ms": 8.06,
      "preflight_with_run_ms": 110.56,
      "report_ms": 127.37,
      "check_ms": 108.07,
      "issues_json_bytes": 120628,
      "events_bytes": 1688890,
      "check_problems": []
    }
  ]
}
```

### T6 concurrency

```json
{
  "schema_version": 1,
  "checks": [
    {
      "test": "concurrent_append",
      "expected_lines": 200,
      "actual_lines": 165,
      "bad_lines": 0,
      "errors": [
        {
          "type": "PermissionError",
          "message": "[Errno 13] Permission denied: 'C:\\\\Users\\\\cui-home\\\\AppData\\\\Local\\\\Temp\\\\rtmem-conc-append-n87fgl2d\\\\events\\\\2026-11.jsonl.lock'"
        }
      ],
      "status": "FAIL"
    },
    {
      "test": "concurrent_postflight",
      "expected_issue_count": 2,
      "issue_records": 2,
      "issue_counts": [
        1,
        1
      ],
      "events": 2,
      "errors": [],
      "status": "FAIL"
    },
    {
      "test": "partial_write_event_without_issue",
      "check_problems": [],
      "detected": false,
      "status": "GAP",
      "note": "plan T6: not detecting event-without-issue is a gap"
    },
    {
      "test": "terminate_between_event_and_issue",
      "marker_seen": true,
      "check_problems": [],
      "corrupt_event_lines": 0,
      "event_count": 1,
      "issue_count": 0,
      "status": "PASS"
    }
  ]
}
```

### T7 retention

```json
{
  "schema_version": 1,
  "days": 90,
  "per_day": 100,
  "before": {
    "event_files": 4,
    "event_bytes": 2154600,
    "event_lines": 9000,
    "issues": 4,
    "issue_ids": [
      "ISS-old-resolved",
      "ISS-old-open",
      "ISS-recent-resolved",
      "ISS-recent-open"
    ],
    "issues_json_bytes": 4390
  },
  "dry_run": {
    "event_files": 2,
    "events": 5600,
    "issues": 1,
    "dry_run": 1
  },
  "after_dry_run": {
    "event_files": 4,
    "event_bytes": 2154600,
    "event_lines": 9000,
    "issues": 4,
    "issue_ids": [
      "ISS-old-resolved",
      "ISS-old-open",
      "ISS-recent-resolved",
      "ISS-recent-open"
    ],
    "issues_json_bytes": 4390
  },
  "apply": {
    "event_files": 2,
    "events": 5600,
    "issues": 1,
    "dry_run": 0
  },
  "after_apply": {
    "event_files": 2,
    "event_bytes": 813960,
    "event_lines": 3400,
    "issues": 3,
    "issue_ids": [
      "ISS-old-open",
      "ISS-recent-resolved",
      "ISS-recent-open"
    ],
    "issues_json_bytes": 3281
  },
  "dry_run_deleted_nothing": true,
  "open_issues_kept": true,
  "old_resolved_deleted": true,
  "recent_resolved_kept": true,
  "check_problems": []
}
```

### T8 redaction

```json
{
  "schema_version": 1,
  "messages": 1000,
  "stored_messages": 40,
  "by_pattern": {
    "authorization": {
      "checked": 100,
      "leaks": 0
    },
    "password": {
      "checked": 100,
      "leaks": 0
    },
    "token": {
      "checked": 100,
      "leaks": 0
    },
    "api_key": {
      "checked": 100,
      "leaks": 0
    },
    "cookie": {
      "checked": 100,
      "leaks": 0
    },
    "private_key": {
      "checked": 100,
      "leaks": 0
    },
    "json_password": {
      "checked": 100,
      "leaks": 100
    },
    "json_token": {
      "checked": 100,
      "leaks": 100
    },
    "json_authorization": {
      "checked": 100,
      "leaks": 100
    },
    "normal": {
      "checked": 100,
      "leaks": 0
    }
  },
  "plan_pattern_leaks": 0,
  "json_pattern_leaks": 300,
  "redaction_leak_samples": [
    {
      "pattern": "json_password",
      "index": 6,
      "secret": "SEC-JSON_PASSWORD-0006-82597552",
      "redacted": "{\"password\": \"SEC-JSON_PASSWORD-0006-82597552\", \"ok\": false}"
    },
    {
      "pattern": "json_token",
      "index": 7,
      "secret": "SEC-JSON_TOKEN-0007-17930905",
      "redacted": "{\"token\": \"SEC-JSON_TOKEN-0007-17930905\", \"error\": \"expired\"}"
    },
    {
      "pattern": "json_authorization",
      "index": 8,
      "secret": "SEC-JSON_AUTHORIZATION-0008-07339937",
      "redacted": "{\"Authorization\": \"Bearer SEC-JSON_AUTHORIZATION-0008-07339937\"}"
    },
    {
      "pattern": "json_password",
      "index": 16,
      "secret": "SEC-JSON_PASSWORD-0016-15359867",
      "redacted": "{\"password\": \"SEC-JSON_PASSWORD-0016-15359867\", \"ok\": false}"
    },
    {
      "pattern": "json_token",
      "index": 17,
      "secret": "SEC-JSON_TOKEN-0017-23933272",
      "redacted": "{\"token\": \"SEC-JSON_TOKEN-0017-23933272\", \"error\": \"expired\"}"
    },
    {
      "pattern": "json_authorization",
      "index": 18,
      "secret": "SEC-JSON_AUTHORIZATION-0018-60773253",
      "redacted": "{\"Authorization\": \"Bearer SEC-JSON_AUTHORIZATION-0018-60773253\"}"
    },
    {
      "pattern": "json_password",
      "index": 26,
      "secret": "SEC-JSON_PASSWORD-0026-61052324",
      "redacted": "{\"password\": \"SEC-JSON_PASSWORD-0026-61052324\", \"ok\": false}"
    },
    {
      "pattern": "json_token",
      "index": 27,
      "secret": "SEC-JSON_TOKEN-0027-99550129",
      "redacted": "{\"token\": \"SEC-JSON_TOKEN-0027-99550129\", \"error\": \"expired\"}"
    },
    {
      "pattern": "json_authorization",
      "index": 28,
      "secret": "SEC-JSON_AUTHORIZATION-0028-45612283",
      "redacted": "{\"Authorization\": \"Bearer SEC-JSON_AUTHORIZATION-0028-45612283\"}"
    },
    {
      "pattern": "json_password",
      "index": 36,
      "secret": "SEC-JSON_PASSWORD-0036-41810591",
      "redacted": "{\"password\": \"SEC-JSON_PASSWORD-0036-41810591\", \"ok\": false}"
    }
  ],
  "stored_leaks": [
    {
      "file": "issues.json",
      "secret": "SEC-TARGET-0001-99999999",
      "pattern": "target_userinfo"
    },
    {
      "file": "events\\2026-11.jsonl",
      "secret": "SEC-JSON_PASSWORD-0006-82597552",
      "pattern": "stored_message"
    },
    {
      "file": "events\\2026-11.jsonl",
      "secret": "SEC-JSON_AUTHORIZATION-0008-07339937",
      "pattern": "stored_message"
    },
    {
      "file": "events\\2026-11.jsonl",
      "secret": "SEC-JSON_PASSWORD-0016-15359867",
      "pattern": "stored_message"
    },
    {
      "file": "events\\2026-11.jsonl",
      "secret": "SEC-JSON_PASSWORD-0036-41810591",
      "pattern": "stored_message"
    },
    {
      "file": "events\\2026-11.jsonl",
      "secret": "SEC-JSON_AUTHORIZATION-0018-60773253",
      "pattern": "stored_message"
    },
    {
      "file": "events\\2026-11.jsonl",
      "secret": "SEC-JSON_AUTHORIZATION-0038-70165056",
      "pattern": "stored_message"
    },
    {
      "file": "events\\2026-11.jsonl",
      "secret": "SEC-JSON_TOKEN-0007-17930905",
      "pattern": "stored_message"
    },
    {
      "file": "events\\2026-11.jsonl",
      "secret": "SEC-JSON_TOKEN-0027-99550129",
      "pattern": "stored_message"
    },
    {
      "file": "events\\2026-11.jsonl",
      "secret": "SEC-JSON_PASSWORD-0026-61052324",
      "pattern": "stored_message"
    },
    {
      "file": "events\\2026-11.jsonl",
      "secret": "SEC-JSON_AUTHORIZATION-0028-45612283",
      "pattern": "stored_message"
    },
    {
      "file": "events\\2026-11.jsonl",
      "secret": "SEC-JSON_TOKEN-0037-29250236",
      "pattern": "stored_message"
    },
    {
      "file": "events\\2026-11.jsonl",
      "secret": "SEC-JSON_TOKEN-0017-23933272",
      "pattern": "stored_message"
    },
    {
      "file": "events\\2026-11.jsonl",
      "secret": "SEC-TARGET-0001-99999999",
      "pattern": "target_userinfo"
    }
  ],
  "storage_message_leaks": 12,
  "target_userinfo_leaks": 2,
  "normal_text_preserved": true
}
```

## Anomalies

| severity | test | file | description | evidence |
|---|---|---|---|---|
| P0 | T8 | runtime_memory/src/runtime_memory/redact.py | JSON-formatted secrets are not redacted | `json_pattern_leaks=300; storage_message_leaks=12` |
| P0 | T8 | runtime_memory/src/runtime_memory/runtime.py | URL userinfo credentials are persisted in issue.target / report | `target_userinfo_leaks=2` |
| P0 | T6 | runtime_memory/src/runtime_memory/store.py | concurrent_append failed under concurrency | `{"expected_lines": 200, "actual_lines": 165, "bad_lines": 0, "errors": [{"type": "PermissionError", "message": "[Errno 13] Permission denied: 'C:\\\\Users\\\\cui-home\\\\AppData\\\\Local\\\\Temp\\\\rtmem-conc-append-n87fgl2d\\\\events\\\\2026-11.jsonl.lock'"}]}` |
| P0 | T6 | runtime_memory/src/runtime_memory/store.py | concurrent_postflight failed under concurrency | `{"expected_issue_count": 2, "issue_records": 2, "issue_counts": [1, 1], "events": 2, "errors": []}` |
| P2 | T6 | runtime_memory/src/runtime_memory/store.py | partial_write_event_without_issue is not detected by check() | `{"check_problems": [], "detected": false, "note": "plan T6: not detecting event-without-issue is a gap"}` |
| P2 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | mode.workaround_only: recording a workaround transitions to mitigated | `{'status': 'cooldown', 'decision': 'block', 'alternatives': ['use local pcap']}` |
| P0 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | mode.override_auth: model override bypasses a non-retryable auth block | `{'blocked': 'block', 'override': 'probe', 'override_reason': 'override: model wants to retry', 'issue_status': 'probing', 'overrides': 1}` |
| P0 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | mode.override_budget: model override bypasses the per-run hard budget | `{'blocked': 'block', 'blocked_reason': 'run budget exhausted: 1 failure(s) for this operation in budget-run', 'blocked_issue_id': '', 'override': 'probe', 'override_reason': 'override: try anyway', 'override_issue_id': ''}` |
| P1 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | state.mitigated_expired: mitigating an already-expired issue is immediately undone | `{'status_after_resolve': 'mitigated', 'expires_at': '2026-11-03T06:00:00Z', 'next_decision': 'probe', 'status_after_next_preflight': 'stale'}` |
| P0 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | scope.session: a session-scope issue blocks every other session | `{'failure_session': 'session-a', 'other_session': 'session-b', 'decision': 'block', 'reason': 'blocked until retry window: unreachable @ http://10.7.194.120:22196/hunt/sse (1 failure(s))'}` |
| P0 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | scope.agent: an agent-scope issue blocks every other agent | `{'decision': 'block', 'reason': 'blocked until retry window: unreachable @ http://10.7.194.120:22196/hunt/sse (1 failure(s))'}` |
| P1 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | scope.global_resolution: a successful session call cannot resolve a global issue | `{'probe': 'probe', 'issue_scope': 'global', 'status_after_session_success': 'probing'}` |
| P1 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | scope.mixed: a session failure updates the global issue record | `{'issue_count': 1, 'scopes': ['global'], 'counts': [2]}` |
| P1 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | identity.bad_port: a malformed URL port does not crash preflight | `ValueError: Port out of range 0-65535` |
| P1 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | identity.non_json_args: non-JSON argument values do not crash preflight | `TypeError: Object of type bytes is not JSON serializable` |
| P1 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | classify.server_errors: 5xx and errno-based network errors fall back to unknown | `{'HTTP 500': 'unknown', 'HTTP 503': 'unknown', 'OSError(errno=101)': 'unknown', 'OSError(errno=111)': 'unknown'}` |
| P0 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | security.redaction_json: JSON-formatted secrets are not redacted | `{'{"password": "hunter2", "token": "tok-abc", "api_key": "AK-123"}': '{"password": "hunter2", "token": "tok-abc", "api_key": "AK-123"}', '{"Authorization": "Bearer abc123"}': '{"Authorization": "Bearer abc123"}'}` |
| P0 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | security.target_credentials: URL userinfo credentials leak through the raw target field | `{'issue_target': 'https://user:hunter2@10.0.0.1/hunt', 'decision_reason': 'blocked until retry window: unreachable @ https://user:hunter2@10.0.0.1/hunt (1 failure(s))', 'report_target': 'https://user:hunter2@10.0.0.1/hunt'}` |
| P1 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | store.multiprocess: concurrent record() calls create duplicate live issues | `[{'round': 0, 'errors': [], 'events': 4, 'issue_records': 4, 'issue_counts': [1, 1, 1, 1], 'issue_attempts': [1, 1, 1, 1], 'sum_counts': 4}, {'round': 1, 'errors': [], 'events': 4, 'issue_records': 3, 'issue_counts': [1, 1, 1], 'issue_attempts': [1, 1, 1], 'sum_counts': 3}, {'round': 2, 'errors': []` |
| P0 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | store.lock_contention: the JSONL file lock can raise an uncaught PermissionError on Windows | `errors=[{'round': 1, 'type': 'PermissionError', 'message': "[Errno 13] Permission denied: 'C:\\\\Users\\\\cui-home\\\\AppData\\\\Local\\\\Temp\\\\rtmem-deep-lock-s1xwgppt\\\\events.jsonl.lock'"}]; rounds=[{'round': 0, 'lines': 80, 'expected': 80}, {'round': 1, 'lines': 70, 'expected': 80}]` |
| P1 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | store.corrupt_events: a corrupt event journal raises from report and budgeted preflight | `{'report': 'ValueError: 2026-11.jsonl line 1: Expecting value: line 1 column 1 (char 0)', 'preflight_with_run': 'ValueError: 2026-11.jsonl line 1: Expecting value: line 1 column 1 (char 0)', 'preflight_without_run': 'allow', 'check': ['journal: 2026-11.jsonl line 1: Expecting value: line 1 column 1 ` |
| P2 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | audit.expires_at: check() does not enforce the expires_at invariant | `[]` |
| P1 | T1.3 | runtime_memory/src/runtime_memory/runtime.py | report.link: shadow false blocks require the caller to pass the decision | `{'decision': 'block', 'would_block': 1, 'false_blocks': 0, 'false_block_rate_present': False}` |

## Not run

| ID | reason |
|---|---|
| T9 | optional; T4 already runs scripted obedient and naive agents |
| T10 | optional ablation; not run in this pass |

## Verdict

- T0/T1 baseline and edge tests: see table.
- T2-T8: see per-test status and metrics above.
- Any FAIL/TIMEOUT is a finding, not something this runner fixes.
- T9 is covered by T4's scripted obedient/naive agents; T10 is optional and not run.
- No core source, tests or data were modified by the runner.

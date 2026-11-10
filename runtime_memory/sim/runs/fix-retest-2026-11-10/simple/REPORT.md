# Runtime Memory 简单效果测试报告（2026-11-10）

- 执行日期：2026-11-10T03:18:42+00:00
- Python：3.14.0
- commit：2b933ce
- 测试目录（已清理/保留见备注）：`C:\Users\cui-home\AppData\Local\Temp\runtime-memory-simple-check-bgf5nryq`
- 临时 policy：`policy.json`（enforce=false，unreachable base=2s/max=3s/max_attempts=1/ttl=60s）

## 汇总

| ID | 结果 | 观察 | 证据 |
|---|---|---|---|
| T0 | **PASS** | {'check': 'Runtime memory check clean.', 'brief': 'No active tool issues.', 'state': {'root': 'C:\\Users\\cui-home\\AppData\\Local\\Temp\\runtime-memory-simple-check-bgf5nryq', 'enforce': False, 'events': 0, 'decisions': 0, 'overrides': 0, 'issues': 0, 'issues_by_status': {'cooldown': 0, 'open': 0,  | `evidence/commands.jsonl` / `data/` |
| T1 | **PASS** | {'issue_id': 'ISS-20261110T031845-6F1B91', 'status': 'cooldown', 'count': 1, 'evidence_run_ids': ['run-A'], 'next_retry_at': '2026-11-10T03:18:47.494440Z'} | `evidence/commands.jsonl` / `data/` |
| T2 | **PASS** | {'status': 'cooldown', 'count': 3, 'evidence_run_ids': ['run-A'], 'next_retry_at': '2026-11-10T03:18:50.428683Z'} | `evidence/commands.jsonl` / `data/` |
| T3 | **PASS** | {'status': 'open', 'count': 4, 'evidence_run_ids': ['run-A', 'run-B'], 'next_retry_at': '2026-11-10T03:18:51.760772Z'} | `evidence/commands.jsonl` / `data/` |
| T4 | **PASS** | {'action': 'block', 'fingerprint': 'test|scope|mcp|demo.query|search|case-cooldown', 'issue_id': 'ISS-20261110T031850-D1817B', 'reason': 'blocked until retry window: unreachable @ case-cooldown (1 failure(s))', 'blocked_until': '2026-11-10T03:18:52.151076Z', 'attempts_left': 1, 'alternatives': [], ' | `evidence/commands.jsonl` / `data/` |
| T5 | **PASS** | {'action': 'probe', 'fingerprint': 'test|scope|mcp|demo.query|search|case-one', 'issue_id': 'ISS-20261110T031845-6F1B91', 'reason': 'slow recovery probe: unreachable @ case-one (4 failure(s))', 'blocked_until': None, 'attempts_left': 0, 'alternatives': [], 'confidence': 0.95, 'expires_at': '2026-11- | `evidence/commands.jsonl` / `data/` |
| T6 | **PASS** | {'issue': {'status': 'resolved', 'next_retry_at': None, 'probe_started_at': None}, 'next_preflight': {'action': 'allow', 'fingerprint': 'test|scope|mcp|demo.query|search|case-one', 'issue_id': '', 'reason': '', 'blocked_until': None, 'attempts_left': 0, 'alternatives': [], 'confidence': 0.0, 'expire | `evidence/commands.jsonl` / `data/` |
| T7 | **PASS** | {'text': '- mcp/demo.query @ case-brief: cooldown / unreachable (1 independent run(s)); retry=2026-11-10T03:18:57.425831Z\n- mcp/demo.query @ case-cooldown: cooldown / unreachable (1 independent run(s)); retry=2026-11-10T03:18:52.151076Z', 'json': {'issues': [{'issue_id': 'ISS-20261110T031855-06113E | `evidence/commands.jsonl` / `data/` |
| T8 | **PASS** | {'check': 'Runtime memory check clean.', 'report': {'events': {'total': 7, 'ok': 1, 'failures': 6, 'by_outcome': {'fail': 6, 'ok': 1}}, 'decisions': {'total': 2, 'block': 1, 'shadow_block': 1, 'probe': 1, 'hint': 0, 'shadow_total': 2, 'enforce_total': 0}, 'issues': {'total': 3, 'by_status': {'cooldo | `evidence/commands.jsonl` / `data/` |

## 说明

- 按 guide 使用临时 `--root`，未读写 `runtime_memory/data`、`sim/runs` 或 demo 数据。
- 所有 outcome 由 CLI `record` 模拟，未调用真实工具/网络。
- 测试结果是小样本功能检查，不代表生产效果。


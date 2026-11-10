# Runtime Memory 简单效果测试报告（2026-11-10）

- 执行日期：2026-11-10T02:50:42+00:00
- Python：3.14.0
- commit：3462004
- 测试目录（已清理/保留见备注）：`C:\Users\cui-home\AppData\Local\Temp\runtime-memory-simple-check-jo71akpm`
- 临时 policy：`policy.json`（enforce=false，unreachable base=2s/max=3s/max_attempts=1/ttl=60s）

## 汇总

| ID | 结果 | 观察 | 证据 |
|---|---|---|---|
| T0 | **PASS** | {'check': 'Runtime memory check clean.', 'brief': 'No active tool issues.', 'state': {'root': 'C:\\Users\\cui-home\\AppData\\Local\\Temp\\runtime-memory-simple-check-jo71akpm', 'enforce': False, 'events': 0, 'decisions': 0, 'overrides': 0, 'issues': 0, 'issues_by_status': {'cooldown': 0, 'open': 0,  | `evidence/commands.jsonl` / `data/` |
| T1 | **PASS** | {'issue_id': 'ISS-20261110T025044-EDBCD4', 'status': 'cooldown', 'count': 1, 'evidence_run_ids': ['run-A'], 'next_retry_at': '2026-11-10T02:50:46.962778Z'} | `evidence/commands.jsonl` / `data/` |
| T2 | **PASS** | {'status': 'cooldown', 'count': 3, 'evidence_run_ids': ['run-A'], 'next_retry_at': '2026-11-10T02:50:49.995157Z'} | `evidence/commands.jsonl` / `data/` |
| T3 | **PASS** | {'status': 'open', 'count': 4, 'evidence_run_ids': ['run-A', 'run-B'], 'next_retry_at': '2026-11-10T02:50:51.323867Z'} | `evidence/commands.jsonl` / `data/` |
| T4 | **PASS** | {'action': 'block', 'fingerprint': 'test|scope|mcp|demo.query|search|case-cooldown', 'issue_id': 'ISS-20261110T025049-B1E784', 'reason': 'blocked until retry window: unreachable @ case-cooldown (1 failure(s))', 'blocked_until': '2026-11-10T02:50:51.597500Z', 'attempts_left': 1, 'alternatives': [], ' | `evidence/commands.jsonl` / `data/` |
| T5 | **PASS** | {'action': 'probe', 'fingerprint': 'test|scope|mcp|demo.query|search|case-one', 'issue_id': 'ISS-20261110T025044-EDBCD4', 'reason': 'slow recovery probe: unreachable @ case-one (4 failure(s))', 'blocked_until': None, 'attempts_left': 0, 'alternatives': [], 'confidence': 0.95, 'expires_at': '2026-11- | `evidence/commands.jsonl` / `data/` |
| T6 | **PASS** | {'issue': {'status': 'resolved', 'next_retry_at': None, 'probe_started_at': None}, 'next_preflight': {'action': 'allow', 'fingerprint': 'test|scope|mcp|demo.query|search|case-one', 'issue_id': '', 'reason': '', 'blocked_until': None, 'attempts_left': 0, 'alternatives': [], 'confidence': 0.0, 'expire | `evidence/commands.jsonl` / `data/` |
| T7 | **PASS** | {'text': '- mcp/demo.query @ case-brief: cooldown / unreachable (1 independent run(s)); retry=2026-11-10T02:50:56.744210Z\n- mcp/demo.query @ case-cooldown: cooldown / unreachable (1 independent run(s)); retry=2026-11-10T02:50:51.597500Z', 'json': {'issues': [{'issue_id': 'ISS-20261110T025054-BF3A80 | `evidence/commands.jsonl` / `data/` |
| T8 | **PASS** | {'check': 'Runtime memory check clean.', 'report': {'events': {'total': 7, 'ok': 1, 'failures': 6, 'by_outcome': {'fail': 6, 'ok': 1}}, 'decisions': {'total': 2, 'block': 1, 'shadow_block': 1, 'probe': 1, 'hint': 0, 'shadow_total': 2, 'enforce_total': 0}, 'issues': {'total': 3, 'by_status': {'resolv | `evidence/commands.jsonl` / `data/` |

## 说明

- 按 guide 使用临时 `--root`，未读写 `runtime_memory/data`、`sim/runs` 或 demo 数据。
- 所有 outcome 由 CLI `record` 模拟，未调用真实工具/网络。
- 测试结果是小样本功能检查，不代表生产效果。


## 补充观察：现有 unittest 未同步

- `python -m unittest discover -s tests`：**90 tests，3 failures / 1 error**。
- 失败项：`test_second_failure_opens_issue`、`test_failed_probe_reopens_issue`、`test_attempt_budget_allows_one_probe_then_blocks`、`test_duplicate_attempts_are_reported`。
- 解释：这些测试仍按旧语义断言“同一 run 第二次失败即 open / 预算耗尽后 block”；新的 2026-11-09 语义改为“同一 run 不升级 / 预算耗尽后 slow probe”，与指南 T2/T3/T5 一致。`by_status['open']` 的 KeyError 是同一原因（issue 仍为 cooldown）。按指南未修改测试/源代码。
- 原始输出：`evidence/unittest.log`；结构化记录：`baseline_tests.json`。

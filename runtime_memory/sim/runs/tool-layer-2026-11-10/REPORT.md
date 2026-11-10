# Tool Layer 测试总结（tool-layer-2026-11-10）

- commit：`3147fae6`（tool_layer 由 main 下载；src 与 2b933ce 一致）
- Python：3.14.0
- 临时 root：全部在 `%TEMP%`；未写入 runtime_memory/data 或 demo/data
- 数据隔离：`True`

| ID | PASS/FAIL | 实际值 | 证据 |
|---|---|---|---|
| A1 | **PASS** | {'exit_code': 0, 'stderr': ''} | `results.json` |
| A2 | **PASS** | {'exit_code': 0, 'backend': {'mode': 'success', 'calls': 5}, 'check': []} | `demo.json` |
| A3 | **PASS** | {'bind': '127.0.0.1', 'external_calls': 0} | `server.py binds 127.0.0.1; gateway uses base_url from the local server` |
| B1 | **PASS** | {'status': 200, 'body': {'query': 'b1', 'results': ['local-result:b1'], 'source': 'local-test-tool'}, 'calls_delta': 1} | `results.json` |
| B2 | **PASS** | {'status': 503, 'body': {'error': 'service_unavailable', 'retryable': True}, 'calls_delta': 1} | `results.json` |
| B3 | **PASS** | {'result': {'status': None, 'body': None, 'error': 'timeout', 'message': 'timed out', 'duration_s': 0.51}, 'calls_delta': 1} | `results.json` |
| B4 | **PASS** | {'status': 429, 'body': {'error': 'rate_limited', 'retry_after_s': 1}, 'calls_delta': 1} | `results.json` |
| B5 | **PASS** | {'status': 401, 'body': {'error': 'unauthorized'}, 'calls_delta': 1} | `results.json` |
| B6 | **PASS** | {'invalid_mode': {'status': 400, 'body': {'error': 'unsupported mode: bogus'}, 'duration_s': 0.028}, 'unknown_path': {'status': 404, 'body': {'error': 'not_found'}, 'duration_s': 0.013}, 'invalid_json': {'status': 400, 'body': {'error': 'invalid_json'}, 'duration_s': 0.008}, 'cal | `results.json` |
| C1 | **PASS** | {'result': {'query': 'baseline', 'results': ['local-result:baseline'], 'source': 'local-test-tool'}, 'events': 1, 'active_issues': 0, 'target': 'http://127.0.0.1:35605'} | `results.json` |
| C2 | **PASS** | {'error_class': 'unreachable', 'status': 'cooldown', 'calls_delta': 1} | `results.json` |
| C3 | **PASS** | {'decision': {'schema_version': 1, 'decision_id': 'DEC-20261110T073348-C18BD8', 'ts': '2026-11-10T07:33:48.571913Z', 'component': 'local_http', 'tool': 'search', 'requested_action': 'search', 'target': 'http://127.0.0.1:35605', 'scope': 'session', 'scope_id': 'local-test-session' | `results.json` |
| C4 | **PASS** | {'after_same_run': {'status': 'cooldown', 'evidence': ['run-C2']}, 'after_new_run': {'status': 'open', 'evidence': ['run-C2', 'run-C4']}} | `results.json` |
| C5 | **PASS** | {'blocked': True, 'decision': {'action': 'block', 'fingerprint': 'local-test|scope|local_http|search|search|http://127.0.0.1:35605', 'issue_id': 'ISS-20261110T073348-7E152F', 'reason': 'blocked until retry window: unreachable @ http://127.0.0.1:35605 (4 failure(s))', 'blocked_unt | `results.json` |
| C6 | **PASS** | {'decision': {'action': 'probe', 'fingerprint': 'local-test|scope|local_http|search|search|http://127.0.0.1:35605', 'issue_id': 'ISS-20261110T073348-7E152F', 'reason': 'slow recovery probe: unreachable @ http://127.0.0.1:35605 (4 failure(s))', 'blocked_until': None, 'attempts_lef | `results.json` |
| C7 | **PASS** | {'decision': {'action': 'allow', 'fingerprint': 'local-test|scope|local_http|search|search|http://127.0.0.1:35605', 'issue_id': '', 'reason': '', 'blocked_until': None, 'attempts_left': 0, 'alternatives': [], 'confidence': 0.0, 'expires_at': None, 'policy_version': '2026-11-02.1' | `results.json` |
| C8 | **PASS** | {'c3_event_linked': True, 'c5_decision': 'DEC-20261110T073349-A8A700', 'c5_event_found': False, 'c6_event_linked': True} | `results.json` |
| C9 | **PASS** | {'check': [], 'events': {'total': 7, 'ok': 3, 'failures': 4, 'by_outcome': {'ok': 3, 'fail': 4}}, 'decisions': {'total': 5, 'block': 4, 'shadow_block': 3, 'probe': 1, 'hint': 0, 'shadow_total': 3, 'enforce_total': 2}, 'issues': {'total': 1, 'by_status': {'cooldown': 0, 'open': 0, | `results.json` |
| D1 | **PASS** | {'error_class': 'unreachable', 'issue': {'status': 'cooldown', 'error_class': 'unreachable', 'retry_policy': {'key_level': 'scope', 'retryable': True, 'mode': 'fixed', 'base_s': 1, 'max_s': 1, 'max_attempts': 1, 'ttl_s': 30, 'next_retry_at': '2026-11-10T07:33:55.998620Z'}}} | `results.json` |
| D2 | **PASS** | {'error_class': 'timeout', 'hit': 'timeout'} | `results.json` |
| D3 | **PASS** | {'error_class': 'rate_limit', 'issue': 'rate_limit', 'next_retry_delta_s': 0.937254} | `results.json` |
| D4 | **PASS** | {'error_class': 'auth', 'issue': {'status': 'open', 'error_class': 'auth', 'next_retry_at': None}, 'blocked': 'block', 'still_blocked': 'block'} | `results.json` |
| D5 | **SKIP** | {'error_class': 'timeout', 'closed_port': 12149, 'message': '<urlopen error timed out>'} | `results.json` |
| D6 | **PASS** | {'decision': {'action': 'probe', 'fingerprint': 'local-test|scope|local_http|search|search|http://127.0.0.1:60050', 'issue_id': 'ISS-20261110T073354-04E978', 'reason': 'retry window open: unreachable @ http://127.0.0.1:60050 (1 failure(s))', 'blocked_until': None, 'attempts_left' | `results.json` |
| E | **PASS** | {'healthy': {'query': 'baseline', 'results': ['local-result:baseline'], 'source': 'local-test-tool'}, 'outages': [('run-A', 'unreachable'), ('run-A', 'unreachable'), ('run-B', 'unreachable')], 'evidence_gate': {'step': 'evidence_gate', 'status': 'open', 'evidence_run_ids': ['run- | `demo.json` |
| A4 | **PASS** | {'before': {'runtime_memory/data': '3b6ff3e63452314c5c8cf124bf3d45d16c444787690c46601e003755f45d2015', 'demo/data': '1d03cd051e93fdae22f14ab3aaad650ff251cbde809e9800870bd37054957bac'}, 'after': {'runtime_memory/data': '3b6ff3e63452314c5c8cf124bf3d45d16c444787690c46601e003755f45d2 | `data_isolation.json` |

## 结论

- 本地 HTTP 工具层初步可用：是
- D5 为可选网络边界；SKIP 表示本机未复现连接拒绝分支。
- 尚未验证：MCP 协议适配、真实远端工具流量、生产并发/负载。

## 运行观察

- runner 退出码：**0**（`cmd /c` 实测；stdout/stderr 见 `runner.stdout.txt`、`b3_server_stderr.log`）。
- B3：客户端 0.5s 超时后，服务端延迟响应写回时记录一次 `ConnectionAbortedError`；这是测试服务的线程日志，runner 未崩溃，B3 PASS。原始输出见 `b3_server_stderr.log`。
- D5：可选网络边界。本机对关闭的本地端口返回超时而非快速连接拒绝，因此该分支未触发，标记 SKIP；D1–D4、D6 已覆盖错误分类与恢复。
- `attempts/attempt1/`：首版 harness 的 C3 断言读错 decision 字段（记录字段是 `decision`，不是 `action`），D5 使用 port 1 导致超时；保留现场用于审计，最终重跑已修正 harness，未修改工具层实现。

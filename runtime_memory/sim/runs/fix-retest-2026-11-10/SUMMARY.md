# Runtime Memory 修复与复测总结（fix-retest-2026-11-10）

- checkout / commit：`2b933ce`（父提交 `f00b1de`）
- Python 版本：3.14.0
- 原始工作区修改：clean
- 本次修改文件：仅新增 `runtime_memory/sim/runs/fix-retest-2026-11-10/` 测试产物；未改 `src/`、`tests/`、`data/`

## 修复摘要

代码修复已在 `2b933ce` 完成，本轮只做复测：

| 问题 | 根因证据 | 修复 | 对应复测 |
|---|---|---|---|
| Windows 锁文件打开 `PermissionError` | 旧并发 probe：165/200 行，lock 打开失败 | `file_lock` 对有界超时内的 Windows error 32/33 重试 | R2 |
| 并发同 key issue 重复 | 旧 probe：2 events → 2 issue（各 count=1） | writer lock + 合并 `evidence_run_ids`/`dropped_event_count` | R3 |
| 孤立失败 event | 旧 `check()` 不报 event-without-issue | `check()` 在 writer lock 快照下校验失败 event 的 fingerprint/class/scope | R4 |
| 报表缺省 status 键 | 旧测试 `by_status["open"]` KeyError | `by_status` 固定输出 6 个状态（含 0） | R1/R6 |
| 旧测试语义 | 3 failures / 1 error | 更新为同 run 不升级、独立 run 升级、预算耗尽后 slow probe；新增独立 run 与 orphan 用例 | R1 |
| 并发探针退出/诊断 | 旧 probe 即使 FAIL 也 exit 0 | 修正 expected 字段、orphan 检测、FAIL 非零退出 | R2/R3/R4 |

## 复测结果

| 项 | 结果 | 数值与退出码 | 证据 |
|---|---|---|---|
| R1 单元测试 | **PASS** | 92 tests，exit 0 | `step0/unittest.log`、`step0/unittest.exit` |
| R2 并发 append ×10 | **PASS** | 10/10 每次 200/200 行、0 bad line、无 error、exit 0 | `probe-01..10/metrics.json`、`probes/summary.json` |
| R3 并发 postflight ×10 | **PASS** | 10/10 每次 2 events / 1 issue / count=2、无 error | 同上 |
| R4 partial/crash | **PASS** | 10/10 orphan 被 check 检出；crash 日志 0 corrupt | `probe-01..10/metrics.json` |
| R5 简单功能 T0–T8 | **PASS** | T0–T8 全部 PASS；临时 root + shadow | `simple/REPORT.md`、`simple/results.json` |
| R6 CLI check/report/brief | **PASS** | check clean；report events=1、false_block_rate=null；brief 1 card；state 全状态计数 | `step6/` |
| R7 diff/status | **PASS** | `git diff --check` 无输出（exit 0）；status 仅新增本 run 目录 | `step7/` |

## 关键 metrics

- R2/R3：10 次 probe 全部满足 200 行、2 events、1 issue、count=2；无 worker error。
- R4：partial-write event 被 `check()` 报为 `failure has no matching issue`；crash 注入后 event 保留、issue 为空、日志合法且 orphan 被检出。
- R6：单条失败记录后 `check` clean；`report.issues.by_status` 输出全部 6 个状态；`false_block_rate=null`（无 shadow block）；`brief` 输出 1 条 cooldown 卡片。
- R1：从 90 tests 增加到 92 tests，全部通过。

## 已知限制

- 离线、临时目录、两次进程/10 次重复；不是生产并发压测。
- 未接真实 MCP/SIEM/shell/LLM；T0–T8 只是小样本功能检查。
- 未验证 SQLite/多 Agent/真实网络故障分布。

## 是否允许进入下一阶段

R1–R7 均通过，10 次并发/崩溃 probe 未出现静默丢行、重复 issue 或未检测 orphan。按计划完成门槛，可以进入真实工具 gateway 的 shadow 接入；仍建议先 shadow 观察，不直接开 enforce。

# BASELINE — fix-retest-2026-11-10

- 仓库根目录：`F:\DeepSeekHarness\data\state\superagent\work\runtime-memory-tests-64464fdaa11e`
- 执行 commit：`2b933ce`（runtime_memory: 修复版本冲突与复测）
- 对应父提交：`f00b1de`（merge PR #5）
- Python：3.14.0
- 执行日期：2026-11-10（UTC）
- 单元测试工作目录：`runtime_memory/`
- 初始 `git status --short`：clean（本轮只新增 `sim/runs/fix-retest-2026-11-10/` 测试产物）
- 本轮未修改 `runtime_memory/src/`、`tests/`、`data/`、`demo/`、`docs/`

## 代码修复已包含在 2b933ce

| 区域 | 修复 |
|---|---|
| store 文件锁 | Windows 短暂 `PermissionError` 在超时内重试 |
| issue 并发合并 | 合并重复 issue 时保留 `evidence_run_ids` / `dropped_event_count` |
| `check()` | writer lock 快照；失败 event 无匹配 issue 时报告 |
| 报表 | `issues.by_status` 对所有状态显式输出（含 0） |
| 旧测试 | 同步同 run 不升级、独立 run 升级、预算耗尽后 slow probe |
| 并发探针 | 修正 expected 字段、orphan 检测、FAIL 非零退出 |

本轮只复测，不重复实现这些修复。

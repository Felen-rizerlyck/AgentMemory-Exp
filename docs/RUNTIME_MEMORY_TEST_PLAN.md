# 运行记忆（Runtime Memory）离线测试计划

> **版本**：2026-11-03  
> **状态**：可执行（供后台模型/执行器使用）  
> **范围**：`runtime_memory/` 的离线、确定性测试；不接真实工具，不改 `demo/`，不改 `runtime_memory/src/`。  
> **目标读者**：另一个在后台执行测试的 LLM/Agent。  
> **相关文档**：[项目说明](../runtime_memory/README_CN.md) · [设计文档](RUNTIME_MEMORY_DESIGN.md) · [边缘测试报告](../runtime_memory/sim/EDGE_CASES.md)

---

## 0. 给执行模型的 60 秒摘要

工作目录：

```text
F:\AI_Learning\AgentMemory\runtime_memory
```

**先做（必须）**：

```powershell
cd F:\AI_Learning\AgentMemory\runtime_memory

python -m unittest discover -s tests
python scripts/verify_runtime_memory.py
python src/manage_runtime_memory.py check
python sim/scenario.py --run-id exec-<UTC>-scenario
python sim/workload.py --seeds 30 --run-id exec-<UTC>-workload
python sim/scale.py --sizes 1000,5000,20000 --run-id exec-<UTC>-scale
```

**再做（推荐，按时间选）**：T3 策略网格、T4 多工具负载、T5 100k 规模、T6 崩溃/并发、T7 保留/gc、T8 脱敏 fuzz。  
**可选**：T9 Agent 合规性、T10 消融。  
**不允许**：修改 `runtime_memory/src/`、`runtime_memory/data/`、`demo/`、已有 run 目录；不要调用真实工具/网络/LLM；不要 `git commit`。  
**产出**：在 `runtime_memory/sim/runs/exec-<UTC>/` 下写 `EXECUTOR_REPORT.md`、`results.json`、原始命令输出；所有数字必须来自实际运行，不能编造。

把 `<UTC>` 换成一个唯一时间戳，例如 `20261103T150000Z`。不要复用已有 run id。

---

## 1. 硬约束（执行前先读）

| 编号 | 约束 | 说明 |
|---|---|---|
| C1 | **只读核心** | 不修改 `runtime_memory/src/`、`runtime_memory/tests/`、`runtime_memory/data/`、`demo/`、`docs/` |
| C2 | **只写自己的 run 目录 / 新实验脚本** | 允许写 `runtime_memory/sim/runs/exec-<UTC>/`；新实验脚本直接放 `runtime_memory/sim/`（与 `workload.py` 同级，便于 `ROOT = parents[1]`） |
| C3 | **唯一 run id** | 每个实验用不同 run id；`--force` 只用于自己新建的目录 |
| C4 | **不碰真实环境** | 不调用真实 MCP/shell/SIEM/LLM；只跑本地 Python 仿真 |
| C5 | **不修 bug** | 发现失败/异常只记录，不改代码；把 `file:line`、复现命令、原始输出写进报告 |
| C6 | **不编造** | 没跑就写 `NOT_RUN`；失败就写 `FAIL`；不要用“应该”代替输出 |
| C7 | **保留原始输出** | 每个命令记录 `exit code`、stdout/stderr 摘要、耗时 |
| C8 | **超时即停** | 单命令超过 10 分钟未结束：停止、记录、继续下一个；不要无限等待 |
| C9 | **编码** | 读写 UTF-8；不要用 `cat`/`type` 处理中文，用 Python 或编辑器 |
| C10 | **不提交** | 不执行 `git add` / `git commit` / `git reset` |

---

## 2. 环境与当前基线

### 2.1 环境

```powershell
cd F:\AI_Learning\AgentMemory\runtime_memory
python --version
git rev-parse --short HEAD
git status --short
```

记录 Python 版本、当前 commit、工作区是否有未提交改动。当前预期：Python 3.11+（实测 3.14.0），只依赖标准库。

### 2.2 基线命令与预期

```powershell
python -m unittest discover -s tests
python scripts/verify_runtime_memory.py
python src/manage_runtime_memory.py check
```

当前基线（2026-11-03 实测）：

| 检查 | 预期 |
|---|---|
| 单元测试 | `Ran 90 tests ... OK`（约 5–8s） |
| 验证矩阵 | `Runtime memory verification: PASS` |
| `check` | `Runtime memory check clean.` |
| `runtime_memory/data/issues.json` | `{"schema_version": 1, "issues": []}` |

如果基线不一致：记录实际值、环境差异；**不要**修改代码来“修好”基线；继续执行时在报告中说明偏差。

### 2.3 已有实验数据（不要覆盖）

```text
runtime_memory/sim/runs/
├── sim-2026-11-02-agent/          # 早期 run
├── sim-2026-11-02-agent-v2/       # 修复前对照
├── sim-2026-11-02-agent-final/    # 最终主场景
├── workload-2026-11-03-b30/       # 30-seed Monte Carlo
└── scale-2026-11-03/              # 1k/5k/20k scale
```

新实验一律用新的 `exec-<UTC>-*` 目录。

---

## 3. 测试矩阵

| ID | 优先级 | 目的 | 执行方式 | 预计 | 状态 |
|---|---|---|---|---|---|
| T0 | P0 | 确认基线可跑 | 三条基线命令 | 1 分钟 | 已实测 |
| T1 | P0 | 边界行为正确性 | `tests/test_edge_cases.py` + `test_store_edge.py` | 2 分钟 | 已实测 |
| T2 | P0 | 恢复时间 vs 重试窗口 | `sim/workload.py` | 5 分钟 | 已实测 |
| T3 | P1 | 退避 × 重试次数 × TTL 的 tradeoff | 新脚本 `policy_grid.py` | 10 分钟 | 待做 |
| T4 | P1 | 多工具/替代路径/跨工具干扰 | 新脚本 `multitool.py` | 10 分钟 | 待做 |
| T5 | P1 | 规模与 per-run 预算扫描 | `sim/scale.py` + 多 issue 变体 | 10–15 分钟 | 20k 已实测 |
| T6 | P2 | 并发写/崩溃/锁/部分写 | `sim/concurrency.py` | 3 分钟 | 已修/可跑 |
| T7 | P2 | 保留/gc 与陈旧数据 | 现有测试 + 90 天仿真 | 5 分钟 | 部分已实测 |
| T8 | P2 | 脱敏 fuzz | `tests/test_redaction_security.py` | 1 分钟 | 已修/可跑 |
| T9 | P3 | Agent 是否遵守 block/alternative | 脚本化 agent（无 LLM） | 10 分钟 | 可选 |
| T10 | P3 | 去掉 workaround/scope/call 的消融 | 改 workload 配置 | 10 分钟 | 可选 |

**执行顺序建议**：T0 → T1 → T2 → T3 → T4 → T5 → T6 → T7 → T8。  
时间不够就停在 T5，T6–T8 标记 `NOT_RUN`。

---

## 4. 测试详情

### T0. 基线自检

**目的**：确认代码、数据、测试在当前环境可运行，给后续实验一个可信起点。

**步骤**

```powershell
cd F:\AI_Learning\AgentMemory\runtime_memory
python -m unittest discover -s tests
python scripts/verify_runtime_memory.py
python src/manage_runtime_memory.py check
```

**记录**

- 每条命令的 exit code、耗时、最后 5 行输出。
- `git rev-parse --short HEAD` 和 `git status --short`。
- `data/issues.json` 内容。

**判定**

- PASS：测试 `OK`、验证 `PASS`、check `clean`、data 为空。
- FAIL：任一条非零退出，或数字与基线不一致；记录原始输出，不修。

---

### T1. 边界测试

**目的**：验证 false block、stale 恢复、Retry-After、probing 崩溃、预算、环境/scope 隔离、损坏 journal、gc 等边界行为。

**步骤**

```powershell
python -m unittest discover -s tests -p "test_edge_cases.py" -v
python -m unittest discover -s tests -p "test_store_edge.py" -v
```

也可以直接跑全量 `python -m unittest discover -s tests`。

**关键用例（应全部通过）**

| 用例 | 期望 |
|---|---|
| shadow block 后实际成功 | 计入 `false_block`，不是 confirmed |
| `auth` 过期后 stale | probe 成功 → resolved |
| `Retry-After: 7200` > TTL 3600 | expiry 不早于 retry 窗口 |
| `probing` 缺 `probe_started_at` | 恢复为 open/stale，不永久 block |
| probe 进行中再次 preflight | block，reason 含 `probe` |
| per-run 预算耗尽 | block，reason 含 `run budget`，可无 issue_id |
| `invalid_args` 命中 query A | A 拦，sibling B 放行 |
| 同 target 不同 environment/scope | 互不影响 |
| 模型 note | status/next_retry 不变 |
| `record=False` | 不写 decision、不改 probing |
| 未知 error class | 回退 scope + unknown |
| 损坏 `decisions.jsonl` | `check` 报 journal 问题，不崩 |
| 旧 event/旧 resolved issue | `gc` dry-run 保留，apply 只删 eligible |
| 同 key 重复 issue | `find_issue` 优先 live |

**判定**：全部 PASS；失败时记录用例名、期望、实际、traceback。

---

### T2. Monte-Carlo 负载（恢复时间 vs 重试窗口）

**目的**：量化 shadow 的 false block、enforce 的时间代价，以及不同退避参数的影响。

**脚本**：[`sim/workload.py`](../runtime_memory/sim/workload.py)

**步骤**

```powershell
python sim/workload.py --seeds 30 --run-id exec-<UTC>-workload
```

参数含义：端点随机 down `0..1800s`，agent 每 `60s` 调用一次，horizon `3600s`，每个配置 30 个 seed。  
输出：`sim/runs/exec-<UTC>-workload/{summary.md,metrics.json,table.csv,runs.jsonl}`。

**当前基线（30 seeds，可直接对照）**

| config | success | calls | failures | blocked | would_block | false_rate | mean TTS |
|---|---|---|---|---|---|---|---|
| baseline | 1.0 | 16.9 | 15.9 | 0 | 0 | 0.0 | 954 |
| shadow_900 | 1.0 | 16.9 | 15.9 | 0 | 15.9 | 0.063 | 954 |
| enforce_60 | 0.0 | 4 | 4 | 57 | 0 | 0.0 | None |
| enforce_300 | 0.467 | 3.5 | 3.0 | 24.9 | 0 | 0.0 | 579 |
| enforce_900 | 1.0 | 2.5 | 1.5 | 1.5 | 0 | 0.0 | 1380 |
| enforce_1800 | 1.0 | 2.0 | 1.0 | 1.0 | 0 | 0.0 | 1800 |

**必须记录**

- 实际 configs 表（不要只复制上面，跑自己的）。
- `false_block_rate`、`mean_false_blocks`、`mean_duplicate_failures`、`mean_time_to_success_s`。
- 与基线差异；如果 seed 数不同，注明。

**解读（报告里要写）**

- `false_block_rate = false_blocks / would_block`，但每个 run 平均约 1 次 false block；两个指标都要报。
- `blocked` 是 block 决策/preflight 次数，不是“不同调用数”。
- `enforce_60` 的 0% 不是崩溃，是“短退避 + max_attempts=3 在恢复前耗尽预算”。

**判定**：exit 0；三个输出文件存在；表格数字可复述；无异常堆栈。  
**可选**：用 `--seeds 100` 重跑，但可能 >5 分钟；不要阻塞后续测试。

---

### T3. 策略网格（base_s × max_attempts × TTL）

**目的**：找到“少失败”和“不误伤”的折中，解释为什么 `enforce_60` 失败、`enforce_900` 成功。

**方法**：复制 [workload.py](../runtime_memory/sim/workload.py) 为 `sim/policy_grid.py`，只改实验参数，不改核心库。

**网格**

```text
base_s:       60, 300, 900, 1800
max_attempts: 1, 3, 5, 10
TTL:          3600, 86400
seeds:        30（时间允许再 100）
```

**实现要点**

1. `policy_for(base_s, max_attempts, enforce, ttl_s)` 中设置：
   - `classes.unreachable.base_s = base_s`
   - `classes.unreachable.max_attempts = max_attempts`
   - `classes.unreachable.ttl_s = ttl_s`
2. 复用 `run_once` / `summarize`，把结果写成 `grid.csv`：
   `base_s,max_attempts,ttl_s,success_rate,mean_calls,mean_failures,mean_blocked,mean_false_blocks,mean_tts_s,mean_duplicate_failures`
3. 每个配置只写新 run 目录：`sim/runs/exec-<UTC>-policy-grid/`。
4. 不要修改 `workload.py` 原始文件；不要改 `src/`。

**运行示例**

```powershell
python sim/policy_grid.py --seeds 30 --run-id exec-<UTC>-policy-grid
```

**验收**

- 网格全部跑完，`grid.csv` 行数 = 4×4×2（或实际配置数）。
- 能复现：`base=60,max=3` 成功率低/0；`base=900,max=3` 成功率高。
- 报告里给出 2–3 条可执行建议（例如“不要把 base 降到 60 而不提高 max_attempts”）。

**判定**：exit 0；CSV 完整；无核心改动。  
**超时**：10 分钟；超时则跑子集（base 60/300/900 × max 3/5），标记未完成。

---

### T4. 多工具负载与替代路径

**目的**：验证多个工具/组件同时存在时，issue 不会误伤无关工具；替代路径是否真的降低失败。

**实现**：新建 `sim/multitool.py`，不修改核心。

**场景建议**

- 3 个 component：`mcp`、`siem`、`parser`。
- 10 个 tool/action 组合；其中：
  - `mcp.hunt.query` 端点 down 0–30 分钟；
  - `siem.search` 限流；
  - `parser.pcap.parse` 对一个文件 schema 失败，另一个文件正常；
  - 每个 tool 有一个 `alternative`（成功概率 0.7）。
- 一个“任务”需要 3 个 tool；task success = 3 个都成功。
- 30 seeds（时间允许再 100）；模式：baseline / shadow / enforce；agent 策略：
  - naive：block 后仍重试；
  - obedient：block 后用 alternative。
- 指标：task success、calls、failures、blocked、false_blocks、duplicate、time-to-task-success。

**必须验证**

- 不相关的 tool 不会被另一个 tool 的 issue 拦；
- 同 target/scope 的 tool 共享 issue；
- 同 target 不同 args（call-level）不互相拦；
- alternative 被返回在 `Decision.alternatives` 中；
- enforce + obedient 的 task success 不低于 baseline；enforce + naive 明显更差。

**输出**：`sim/runs/exec-<UTC>-multitool/{summary.md,metrics.json,runs.jsonl}`。

**判定**：无跨工具误拦；数据完整；报告说明替代路径效果。  
**超时**：10 分钟。

---

### T5. 规模与 per-run 预算扫描

**目的**：找 JSONL 的性能边界，量化 `run_id` 预算扫描的 O(n) 成本。

**脚本**：[`sim/scale.py`](../runtime_memory/sim/scale.py)

**步骤**

```powershell
python sim/scale.py --sizes 1000,5000,20000 --run-id exec-<UTC>-scale
# 时间允许再做：
python sim/scale.py --sizes 100000 --run-id exec-<UTC>-scale-100k
```

**当前基线（1k/5k/20k）**

| events | preflight no run_id | preflight with run_id | report | check |
|---|---|---|---|---|
| 1k | 0.97ms | 15.5ms | 10.1ms | 11.1ms |
| 5k | 0.82ms | 46.9ms | 38.0ms | 38.9ms |
| 20k | 0.90ms | 155.9ms | 150.2ms | 146.0ms |

**多 issue 变体（建议）**

- 在 `sim/scale_multi.py` 生成 100 个 issue（不同 tool/target），重复测量；
- 记录 `issues.json` 大小、`events` 文件大小、进程 RSS（可选）。

**判定**

- 无崩溃；文件可读；`check` 不报错；
- `preflight with run_id` 随 N 近似线性（这是已知实现代价，不是 bug）；
- 报告给出“何时需要索引/缓存/SQLite”的建议，但**不要**在测试中改存储。

**超时**：10 分钟；100k 若超时，保留 20k 结果并标记。

---

### T6. 并发写、崩溃与部分写

**目的**：验证 JSONL 锁、原子 `issues.json`、以及“event 已写、issue 未写”这类部分状态是否可发现。

**实现**：已有 [`sim/concurrency.py`](../runtime_memory/sim/concurrency.py)；不要改核心。

**步骤**

```powershell
python sim/concurrency.py
```

**测试**

1. **并发追加**：4 个子进程各追加 200 条合法 JSON 行；
   - 期望：800 行、每行可解析、无 `PermissionError`。
2. **并发 issue 更新**：两个进程各 `postflight` 同一 issue 10 次；
   - 期望：1 条 live issue，`count=20`，无重复 issue。
3. **部分写**：手动 append 一条 event 但不写 issue；`check` 是否发现？
   - 当前 `check` 不校验 event→issue 反向引用；预期是“不会发现”，记录为 **gap**，不是 FAIL。
4. **崩溃恢复**：用 `subprocess` 在 `postflight` 中途 `terminate()`；再跑 `check`；
   - 期望：不出现损坏 JSON；可能留下 event 无 issue 或 issue 无 event；记录。

**判定**：输出 `append_ok=true`、`issue_ok=true` = PASS；部分状态未检测 = 记录 gap，不要求修复。

**超时**：5 分钟。

---

### T7. 保留 / gc / 陈旧数据

**目的**：验证 `gc` 只删除 eligible 数据，陈旧 issue 不会无限积累。

**步骤**

1. 现有测试：`tests/test_store_edge.py` 中的 `gc` 用例。
2. 仿真脚本（可选）：生成 90 天、每天 100 events + 若干 issue；运行：
   ```powershell
   python sim/retention.py --days 90 --run-id exec-<UTC>-retention
   ```
   - `gc(dry_run=True)` 与 `gc(dry_run=False)` 各一次；
   - 记录删除前后文件数、字节数、issue 数。
3. 检查 `issues.json` 中 `resolved` 旧 issue 被删、open 保留；event 文件按月份删除。

**判定**：dry-run 不删；apply 只删 eligible；无损坏；报告给出 30/90 天数据量。

---

### T8. 脱敏 fuzz

**目的**：确保错误消息/参数中的 token、密码、cookie、私钥不会进入 events/issues/decisions。

**实现**：已有 [`tests/test_redaction_security.py`](../runtime_memory/tests/test_redaction_security.py)；也可扩展 `sim/redaction_fuzz.py` 做更大规模 fuzz。

**快速验证**

```powershell
python -m unittest discover -s tests -p "test_redaction_security.py" -v
```

**步骤**

1. 生成 1000 条消息，随机包含：
   - `Authorization: Bearer <random>`
   - `password=...`、`token=...`、`api_key=...`
   - JSON 形式 `{"password":"...","token":"..."}`
   - URL userinfo `https://user:pass@host/...` 和 `?token=...`
   - `Cookie: session=...`
   - 私钥块
   - 正常文本作为对照
2. 调用 `redact()` / `redact_target()`，再跑几次 `postflight`，检查 `events/*.jsonl`、`issues.json`、`decisions.jsonl`、`overrides.jsonl`。
3. 断言：每个 secret 字符串都不出现在任何落盘文件中；正常文本保留。

**判定**：0 泄漏 = PASS；任何泄漏 = P0，记录具体文件和模式。

---

### T9. Agent 合规性（可选）

**目的**：验证“模型/agent 是否真的遵守 block”，而不是只验证 gate。

**方法（无 LLM）**：脚本化两种 agent：

- `obedient`：`block` 时用 `alternatives`，不再调用原工具；
- `naive`：忽略 `block`，继续调用（enforce 下应被 gateway 拦）。

**指标**：blocked calls、alternative success、task success、duplicate attempts。  
**判定**：enforce 下 naive 也不能绕过（调用次数受控）；obedient 的 task success 更高。  
**注意**：这是模拟 agent，不是真实 LLM；报告中写清楚。

---

### T10. 消融（可选）

**目的**：知道哪个特性真正有用。

**变体**：

- 去掉 `workaround`/`alternatives`；
- 关掉 scope 隔离（所有 issue 共享）；
- 关掉 call 隔离（所有 args 共享）；
- shadow vs enforce。

**方法**：基于 `workload.py` 的参数化，不修改核心；每个变体输出 success/false/duplicate/TTS。  
**判定**：数据完整；报告说明哪个特性贡献最大，不要过度推断。

---

## 5. 结果格式

### 5.1 `results.json`

```json
{
  "schema_version": 1,
  "run_id": "exec-20261103T150000Z",
  "commit": "fe36f34",
  "python": "3.14.0",
  "started_at": "2026-11-03T15:00:00Z",
  "finished_at": "2026-11-03T15:20:00Z",
  "tests": [
    {"id": "T0", "command": "python -m unittest discover -s tests",
     "exit_code": 0, "duration_s": 6.2, "status": "PASS", "notes": "90 tests"}
  ],
  "metrics": {
    "workload": {"run_dir": "...", "table": "..."},
    "scale": {"run_dir": "...", "table": "..."}
  },
  "anomalies": [
    {"severity": "P1", "test": "T5", "file": "runtime_memory/src/runtime_memory/runtime.py",
     "description": "preflight with run_id is O(events)", "evidence": "155.9ms at 20k"}
  ],
  "not_run": [
    {"id": "T9", "reason": "optional; no model available"}
  ]
}
```

### 5.2 `EXECUTOR_REPORT.md`

```markdown
# Executor report — exec-<UTC>

## Environment
- python:
- commit:
- git status:

## Baseline
| check | expected | actual | status |

## Results
| ID | purpose | command | exit | status | notes |

## Metrics
### T2 workload
（贴 summary 表）

### T5 scale
（贴 summary 表）

## Anomalies
| severity | test | file:line | description | evidence |

## Not run
| ID | reason |

## Verdict
- 哪些通过
- 哪些失败/未跑
- 下一步建议（不要修代码）
```

**Severity**：

- `P0`：数据损坏、秘密泄漏、测试基线失败、真实功能错误；
- `P1`：性能/语义与设计不符、指标异常；
- `P2`：文档/可读性/小问题；
- `INFO`：观察，不是问题。

---

## 6. 解读规则（避免误读）

1. **false_block_rate 的分母是 block 决策**；每个 run 的 false block 次数要单独看。当前 30-seed 数据里两者都重要。
2. **`blocked` 是 block 决策/preflight 次数**，不是“不同工具调用数”。enforce_60 的 57 次是重复 preflight，不是 57 个不同调用。
3. **`attempts` = 所有调用次数（含成功 probe）**；`count` = 失败次数；`max_attempts` 是“首次失败后的允许重试次数”，所以 `attempts` 可以 = `max_attempts + 1`。
4. **合成数据不是生产效果**：down time 是 uniform 0–30 分钟；真实环境分布不同，不能直接外推。
5. **`enforce_60` 0% 是参数/预算问题，不是崩溃**；`enforce_900` 100% 也不是“最优”，只是这组分布下可用。
6. **scale 的 O(n) 是已知实现代价**：`preflight` 带 `run_id` 会扫描 events；不要在测试中改核心，先记录。
7. **T6 的部分状态可能“check 不报”**：这是缺失的不变量，记为 gap，不要假装修好了。

---

## 7. 可直接粘贴给执行模型的 Prompt

```text
You are the background test executor for F:\AI_Learning\AgentMemory\runtime_memory.

Read docs/RUNTIME_MEMORY_TEST_PLAN.md first and follow it exactly.
Run T0, T1, T2 (mandatory), then T3, T4, T5 (recommended), then T6, T7, T8 if time.
Use a unique run id exec-<UTC> and write all outputs under runtime_memory/sim/runs/exec-<UTC>/.

Hard rules:
- Do not modify runtime_memory/src/, runtime_memory/tests/, runtime_memory/data/, demo/, or docs/.
- Do not use real tools, network, or an LLM.
- Do not fix bugs; report them with file:line and raw output.
- Do not fabricate numbers. Mark NOT_RUN for anything not executed.
- Capture exit codes, durations, stdout/stderr; keep raw JSONL/CSV outputs.

Deliver:
1. runtime_memory/sim/runs/exec-<UTC>/EXECUTOR_REPORT.md
2. runtime_memory/sim/runs/exec-<UTC>/results.json
3. raw command outputs and experiment directories.

At the end, send the Lead a concise summary: PASS/FAIL per test, key metrics, anomalies, not-run.
```

---

## 8. 附录

### 8.1 文件索引

| 内容 | 路径 |
|---|---|
| 主场景 | [`runtime_memory/sim/scenario.py`](../runtime_memory/sim/scenario.py) |
| Monte Carlo | [`runtime_memory/sim/workload.py`](../runtime_memory/sim/workload.py) |
| 规模探针 | [`runtime_memory/sim/scale.py`](../runtime_memory/sim/scale.py) |
| 边缘测试报告 | [`runtime_memory/sim/EDGE_CASES.md`](../runtime_memory/sim/EDGE_CASES.md) |
| 单元测试 | `runtime_memory/tests/` |
| 验证矩阵 | [`runtime_memory/scripts/verify_runtime_memory.py`](../runtime_memory/scripts/verify_runtime_memory.py) |
| 运行说明 | [`runtime_memory/README_CN.md`](../runtime_memory/README_CN.md) |
| 设计文档 | [`docs/RUNTIME_MEMORY_DESIGN.md`](RUNTIME_MEMORY_DESIGN.md) |

### 8.2 当前已实测结果（2026-11-03）

```text
unit tests: 90 OK
verify: PASS
check: clean
workload: sim/runs/workload-2026-11-03-b30/
scale:    sim/runs/scale-2026-11-03/
main sim: sim/runs/sim-2026-11-02-agent-final/
```

### 8.3 术语

| 术语 | 含义 |
|---|---|
| event | 一次实际工具调用 |
| issue | 聚合后的问题 |
| decision | preflight 的 block/probe/hint |
| fingerprint | 问题身份；scope/call 两级 |
| false block | shadow 判 block 但实际调用成功 |
| TTS | time to success |
| `run_id` | 一次运行；per-run 预算用它 |
| `scope` | global/session/agent，影响 issue 可见性 |

---

> **执行结束条件**：T0–T2 至少完成；T3–T5 能跑则跑；所有结果写入 `exec-<UTC>`；报告注明 PASS/FAIL/NOT_RUN。不要为了“全绿”修改代码或数据。

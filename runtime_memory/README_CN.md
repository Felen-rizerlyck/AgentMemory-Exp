# 运行记忆（Runtime Memory）· 初版

一个**独立**的运行记忆原型：记录工具/环境/操作层面的失败，聚合成可重试的 issue，在工具调用前决定 **allow / probe / block**。

它和 [`demo/`](../demo/README.md) 的案例记忆是两类东西：

- `demo/` 回答“**攻击长什么样**”；
- 本目录回答“**这个工具/端点/环境为什么失败、什么时候能再试、有没有替代路径**”。

本目录**不 import** `demo/src/attack_memory`，**不写** `demo/data`，也不参与 demo 的 `catalog validate` / `audit` / `state` / `retention`。

- 设计文档：[`docs/RUNTIME_MEMORY_DESIGN.md`](../docs/RUNTIME_MEMORY_DESIGN.md)
- English README：[`README.md`](README.md)

---

## 0. 一句话

**记录“发生了什么问题”，聚合成“下次该怎么处理”，并在调用前真正拦住重复的无用尝试。**

默认是 **shadow 模式**：preflight 会算出 `block/probe`，但调用仍然执行，只记录“如果拦截会怎样”。确认误拦率可接受后，再把 `policy.json` 的 `enforce` 改为 `true`。

---

## 1. 它不是什么

先划清三个容易混淆的 demo 账本：

| 现有物 | 它是什么 | 为什么不是运行记忆 |
|---|---|---|
| `demo/data/ops_journal.jsonl` | demo 写事务的两阶段 WAL | 记录文件写入事务，不记录工具失败 |
| `demo/data/corrections.json` | 案例负记忆 | 记录“这个 incident 不是这个 case” |
| `demo/data/link_exceptions.json` | 审计例外 | 记录 regex 不匹配的已复核链接 |

运行记忆是第四类：**harness 层的操作/环境问题记忆**，有自己的 schema、TTL、脱敏和审计。

---

## 2. 快速开始

所有命令在 `runtime_memory/` 下执行：

```powershell
# 1) 体检
python src/manage_runtime_memory.py check
python src/manage_runtime_memory.py state

# 2) 端到端演示（默认使用临时目录，不写仓库 data/）
python src/run_runtime_demo.py --shadow     # 只观察，不拦截
python src/run_runtime_demo.py --enforce    # 拦截重复调用

# 3) 测试与验证矩阵
python -m unittest discover -s tests
python scripts/verify_runtime_memory.py
```

Python 3.11+，只用标准库。

`--keep` 会把演示写入 `runtime_memory/data`；默认不加，避免污染仓库。

---

## 3. 它做了什么

### 3.1 三层数据

```text
events/*.jsonl        一次工具调用一行，append-only；给复盘/指标/事后蒸馏
        │ 聚合
        ▼
issues.json           按 fingerprint 聚合的问题；preflight 读取；短 TTL
        │ 人审
        ▼
playbook.md           这一类问题以后怎么处理；长期、人工维护
```

你举的“某部件遇到问题，或许半小时后重试”，落在 **issue 的 `next_retry_at`**，不是 event 里的一行文本。

### 3.2 两级 fingerprint

| 级别 | 适用 | 组成 |
|---|---|---|
| `scope` | 端点/服务/认证级问题 | `environment + component + tool + action + target` |
| `call` | 参数/数据级问题 | scope + 规范化参数的 hash |

**error class 不进入 fingerprint**：preflight 在调用前并不知道下一次会报什么错；issue 把 `error_class` 存成属性。这样“同一个端点不可达”不会被每个 query 拆成不同 issue。

### 3.3 状态机

```text
(no issue) --fail--> cooldown --same fail--> open
                         │                    │
                         │ success            │ next_retry_at 到点
                         ▼                    ▼
                     resolved              probing
                                              │
                                    success ──┼── fail
                                              ▼      ▼
                                          resolved   open
open/cooldown --expires_at--> stale --probe--> resolved / open
open --workaround 人工--> mitigated（allow_with_hint）
```

- 第一次失败默认只建 `cooldown`，不把工具封死；
- `auth` / `permission` / `schema` / `invalid_args` 这类“重试无用”的错误第一次就建 `open`；
- `stale` 允许一次 probe，不是永久封禁；
- `probing` 带 `probe_started_at`，进程崩溃后可以被恢复。

### 3.4 重试策略

`data/policy.json` 按 `error_class` 配置：

| error_class | 级别 | 重试 | 默认退避 |
|---|---|---|---|
| `unreachable` | scope | 是 | 900s 固定 |
| `timeout` | call | 是 | 30s 指数到 300s |
| `rate_limit` | scope | 是 | 60s 指数到 300s |
| `auth` / `permission` | scope | 否 | — |
| `schema` / `invalid_args` | call | 否 | — |
| `not_found` | call | 否 | — |
| `internal` / `unknown` | scope | 谨慎 | 60s，最多 1 次 |

`preflight` 在 `next_retry_at` 之前返回 `block`，到点返回 `probe`；`attempts` 超过 `max_attempts` 后即使到点也 block（`reason=attempt budget exhausted`）。

### 3.5 Shadow 与 enforce

**Shadow（默认）**

- `preflight` 仍返回 `block` / `probe`；
- 调用方**照常执行**工具；
- event 记录 `would_block=true`；
- `report` 给出 `shadow.would_block`、`shadow.false_blocks`、`shadow.confirmed_blocks`。

**Enforce**

- `policy.json` 的 `"enforce": true`；
- `block` 时调用方必须跳过工具调用，把 Decision 作为工具结果返回；
- `report.enforce.blocked_calls` 统计真正被拦下的调用。

`preflight --probe --basis "..."` 可以记录一次显式 override，落在 `data/overrides.jsonl`，不会被静默绕过。

---

## 4. 数据文件

```text
runtime_memory/data/
├── policy.json          # error_class -> retry policy；enforce=false 默认
├── issues.json          # 聚合问题快照（原子写）
├── events/YYYY-MM.jsonl # 操作轨迹（append-only；仓库不提交）
├── decisions.jsonl      # preflight 的 block/probe/hint 决策
├── overrides.jsonl      # 显式 probe 的 override 记录
└── playbook.md          # 人审后的处理经验
```

- `events` 按 UTC 月份分文件；
- `issues.json` 用临时文件 + `replace` 原子写；
- JSONL 追加有跨平台文件锁（单写者原型，不是多进程事务）；
- 错误消息先脱敏（Bearer、password、cookie、私钥等）再落盘；
- `--root` 可以指向 harness 自己的可写目录，不必用仓库里的 `data/`。

读记录时注意：

- `count` 是失败次数；`attempts` 是所有调用次数（包含成功的 probe/retry）；
- `max_attempts` 指“首次失败之后的允许重试次数”，所以已解决的 issue 可以是
  `attempts = max_attempts + 1`（例如 3 次失败 + 1 次成功 probe = 4）；
- `decisions.jsonl` 只存非 `allow` 的决策（block/probe/allow_with_hint）；
  `allow` 调用只在 events 里。

---

## 5. CLI

```powershell
# 查看
python src/manage_runtime_memory.py check
python src/manage_runtime_memory.py state --json
python src/manage_runtime_memory.py issues --active
python src/manage_runtime_memory.py issue ISS-...

# 调用前问一句
python src/manage_runtime_memory.py preflight \
  --component mcp --tool hunt.query --action search \
  --target 10.7.194.120:22196 --args '{"q":"dns tunnel"}' --json

# 记录结果（通常由 gateway 自动做，不是模型手写）
python src/manage_runtime_memory.py record \
  --component mcp --tool hunt.query --action search \
  --target 10.7.194.120:22196 --outcome fail \
  --error-class unreachable --message "connect refused"

# 人工处理
python src/manage_runtime_memory.py resolve ISS-... --basis "endpoint restored"
python src/manage_runtime_memory.py ignore ISS-... --basis "false alarm"
python src/manage_runtime_memory.py note ISS-... --text "checked again" --author analyst

# 报表 / 清理
python src/manage_runtime_memory.py report --since 7d
python src/manage_runtime_memory.py gc --dry-run
```

---

## 6. 库 API

```python
from runtime_memory import OperationRequest, RuntimeMemory

runtime = RuntimeMemory("data")  # 默认读取 data/policy.json
req = OperationRequest(
    component="mcp", tool="hunt.query", action="search",
    target="10.7.194.120:22196", args={"q": "dns tunnel"},
    scope="global", environment_id="lab-a", run_id="run-1",
)

decision = runtime.preflight(req)
if decision.action == "block":
    # shadow 模式下这是建议；enforce 模式下调用方必须跳过调用
    return {"blocked": True, "decision": decision.to_dict()}

try:
    result = call_tool(req)          # 你的真实工具
except Exception as exc:
    runtime.postflight(req, "fail", error=exc, decision=decision)
    raise
else:
    runtime.postflight(req, "ok", decision=decision)
    return result
```

**职责边界**：事实由 harness/gateway 写；模型只能加 `notes`，不能直接把 issue 设成“永久坏”。

---

## 7. 与 demo 的共通性

为了以后能收进同一个 harness，本目录刻意沿用 demo 的结构：

| 维度 | demo | runtime_memory |
|---|---|---|
| 代码布局 | `src/attack_memory/` + 薄 CLI | `src/runtime_memory/` + 薄 CLI |
| 数据 | `data/*.json|csv` | `data/*.json|jsonl` |
| schema | 顶层 `schema_version` | 顶层 `schema_version` |
| 测试 | stdlib `unittest` | stdlib `unittest` |
| 验证 | `scripts/verify_demo.py` | `scripts/verify_runtime_memory.py` |
| Agent 规则 | `skills/attack-memory/SKILL.md` | `skills/runtime-memory/SKILL.md` |
| 文档 | `README.md` + `README_CN.md` | `README.md` + `README_CN.md` |

但**代码和数据完全分开**：两套 store 的生命周期、审计语义、权限边界不同，不应混在一个 `data/` 里。

---

## 8. 仿真场景与数据

`sim/scenario.py` 是一个确定性的“受限实验环境”场景：

- A 阶段 shadow：MCP 不可达 3 次、SIEM 限流 2 次、一个坏 pcap、shell 权限拒绝、模型超时后重试；调用仍执行，决策照记。
- B 阶段 enforce：MCP 被拦到重试窗口，之后一次 probe 成功；坏 pcap 被拦，另一个 pcap 路径允许；shell 权限问题被拦。
- C 阶段新 run：记忆仍生效，已解决 issue 放行，未解决的 pcap/shell 继续拦。

```powershell
python sim/scenario.py --run-id sim-2026-11-02-agent
```

输出在 `sim/runs/<run-id>/`：
`data/events/*.jsonl`（每次实际调用一行）、`data/issues.json`（聚合问题）、`data/decisions.jsonl`（block/probe/hint 决策）、`narrative.log`、`summary.md`、`report.json`、`records.md`、`policies.json`。

独立执行者跑出的最终示例：`sim/runs/sim-2026-11-02-agent-final/`，其中 `AGENT_NOTES.md` 记录了它的观察和异常；更早的 `sim-2026-11-02-agent/`、`-v2/` 保留作对照。

## 9. 与“工具依赖图”的关系

结论：**触及了工具依赖图的运行时健康层，但不是完整的依赖图实现。**

它已经有的：

- 节点坐标 `environment / component / tool / target`；
- 节点健康 `status / error_class / count / next_retry_at / confidence`；
- `workaround` 作为 `alternative_to` 边的雏形；
- co-failure 的原始事件（同一 run/session 的失败序列）。

它还没有的：

- 静态 `depends_on` 方向、数据流；
- 拓扑排序/规划；
- 影响面/爆炸半径；
- 替代路径的自动发现与验证；
- 图查询/图数据库。

所以现在不要上图数据库。等扁平 issue store 证明能减少重复尝试后，再导出投影：

```text
node: (environment, component, tool, target)
edge: calls | depends_on | alternative_to | co_fails_with
attr: status, error_class, next_retry_at, confidence
```

## 10. 当前边界

- 单写者原型；文件锁只保证 JSONL 不交错，不是多进程事务；
- shadow 决策是建议，调用方必须自己遵守 `block`（enforce 模式）；
- 没有外部健康检查自动 resolve；需要 probe 成功或人工 resolve；
- 没有 playbook 自动生成；
- 没有跨 Agent 协调，只有 `scope` / `environment_id`；
- 默认 TTL/退避是起点，不是生产校准值；
- `preflight` 带 `run_id` 时会扫描 events 做 per-run 预算；规模探针在 2 万事件时约 **156ms**（不带 run_id 约 1ms）。高吞吐前要加索引/缓存，或者由 gateway 自己维护 per-run 计数；
- “短退避 + 小 max_attempts”可能在长故障恢复前就把 issue 预算耗尽：30 seed 的负载实验里 `enforce_60` 成功率 0%，`enforce_900` 为 100%。退避和 `max_attempts` 要一起调，不能分开看；
- 不写 `demo/data`，不 import demo。

---

## 11. 测试与验证

```powershell
python -m unittest discover -s tests
python scripts/verify_runtime_memory.py
```

当前：**77 个测试**，覆盖 fingerprint、redaction、policy、状态机、shadow/enforce、override、report、CLI，以及边缘用例（false block、stale 恢复、Retry-After、probing 崩溃、预算、环境隔离、损坏 journal、gc）。

`scripts/verify_runtime_memory.py` 会跑：

1. `compileall src`
2. `unittest discover`
3. `manage_runtime_memory.py check`
4. `run_runtime_demo.py --shadow`
5. `run_runtime_demo.py --enforce`

全部使用临时数据目录，不修改 `data/`。

---

## 12. 下一步

1. 把 gateway 接到一个真实组件（例如 MCP hunt）上，先 shadow 1 周；
2. 看 `false_blocks` / `would_block` / `duplicate_attempts`；
3. 对单个组件开 `enforce=true`；
4. 再考虑 SQLite / 多 Agent / playbook / 图投影。

设计细节、开放问题和排期见 [`docs/RUNTIME_MEMORY_DESIGN.md`](../docs/RUNTIME_MEMORY_DESIGN.md)。

离线测试的方法、步骤、预期和结果模板见 [`docs/RUNTIME_MEMORY_TEST_PLAN.md`](../docs/RUNTIME_MEMORY_TEST_PLAN.md)，可直接交给后台模型执行。

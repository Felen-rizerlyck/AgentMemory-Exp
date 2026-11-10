# Runtime Memory Tool Layer 测试计划

**状态**：待后台模型执行  
**对象**：`runtime_memory/tool_layer/`（`server.py`、`gateway.py`、`run_demo.py`）  
**目标**：验证本地 HTTP 工具调用、preflight gate、postflight 记录和故障分类形成真实闭环；不评估生产并发或真实 MCP 接入。

## 执行规则

1. 从仓库根目录执行；记录当前 commit、Python 版本和 `git status --short`。
2. 服务只绑定 `127.0.0.1`，不得改为 `0.0.0.0` 或暴露到局域网/公网。
3. 所有测试均使用本地测试服务，不访问互联网、不调用生产工具、不使用真实凭据。
4. `RuntimeMemory` 使用临时目录或 `runtime_memory/tool_layer/runs/<唯一run-id>`；绝不指向 `runtime_memory/data` 或 `demo/data`。
5. 保留命令、stdout/stderr、退出码、`check()` 输出和 JSON 摘要。若失败，先保留现场与证据，不在同一轮临时修改实现以追求 PASS。
6. 这是测试计划，不代表测试已经执行。工具层为 HTTP harness，不应把结果描述为 MCP 互通或生产可用性证明。

## 组件与预期调用链

```text
scenario / caller
      │
      ▼
MemoryGateway.call_search
      ├─ RuntimeMemory.preflight
      ├─ enforce block? ── yes ──► ToolBlocked（不发送 HTTP 请求）
      └─ no / shadow ────────────► POST /tools/search
                                     │
                    ┌────────────────┼─────────────────┐
                    ▼                ▼                 ▼
                 HTTP 200          HTTP error       timeout/network error
                    └────────────────┼─────────────────┘
                                     ▼
                      RuntimeMemory.postflight(decision_id)
```

服务接口：`GET /health`、`GET /admin/state`、`POST /admin/mode`、`POST /tools/search`。模式由 `/admin/mode` 设置为 `success`、`unavailable`、`timeout`、`rate_limit` 或 `auth`。

## 阶段 A：运行入口与服务边界

| ID | 检查 | 操作 | 预期 | 证据 |
|---|---|---|---|---|
| A1 | 语法与导入 | `python -m py_compile runtime_memory/tool_layer/server.py runtime_memory/tool_layer/gateway.py runtime_memory/tool_layer/run_demo.py` | 退出码 0；没有语法/导入错误 | 命令日志 |
| A2 | 端到端演示 | `python runtime_memory/tool_layer/run_demo.py` | 退出码 0，输出合法 JSON，最后 `check` 为空 | stdout JSON、退出码 |
| A3 | 无外部依赖 | 观察测试期间网络请求 | 除 `127.0.0.1` 外无网络访问；无需 MCP SDK、账号或凭据 | 执行记录/人工确认 |
| A4 | 数据隔离 | 运行演示前后检查 `runtime_memory/data`、`demo/data` 的状态/哈希（只读） | 两处默认数据没有测试写入 | 比较结果 |

## 阶段 B：本地服务模式

对每种 mode 分别执行：启动 `make_server()`，向 `/admin/mode` 发送设置请求，然后调用 `/tools/search`。可以使用 `run_demo.py` 所在目录的 Python 模块，也可写一个临时 runner；不得修改 `src/` 或正式工具层文件来绕过接口。

| ID | 服务模式 | 预期 HTTP/客户端行为 | 是否增加 backend call 计数 |
|---|---|---|---|
| B1 | `success` | HTTP 200，JSON 包含 query、一个 local result、source 标识 | 是，+1 |
| B2 | `unavailable` | HTTP 503，响应包含 `service_unavailable` | 是，+1 |
| B3 | `timeout` | 服务延迟响应；gateway 超时（默认客户端 0.5 秒）并报告 `timeout` | 是，+1；服务端之后完成/写回失败不应让测试 runner 崩溃 |
| B4 | `rate_limit` | HTTP 429；gateway 记录 `rate_limit`，带 1 秒 retry-after | 是，+1 |
| B5 | `auth` | HTTP 401；gateway 记录 `auth`，不得作为可重试的网络故障 | 是，+1 |
| B6 | 未知模式/路径/JSON | 管理端未知模式返回 400；未知路径 404；无效 JSON 返回 400 | 工具调用计数不因无效管理请求变化 |

`/admin/state` 的 `calls` 只统计 `/tools/search`，不统计 health 或管理请求。核对时以该定义为准。

## 阶段 C：Gateway 与记忆闭环

每个场景使用新的临时 root，除非该行明确要求复用 issue。优先通过 gateway API 驱动，检查 `issues.json`、`events/*.jsonl` 和 `decisions.jsonl`。

| ID | 场景 | 操作 | 预期 |
|---|---|---|---|
| C1 | 初始健康调用 | mode=`success`，调用 `call_search(query, run_id="run-ok")` | 返回工具 JSON；新增 ok event；无活动 issue；event target 为本地服务地址 |
| C2 | Shadow 失败仍执行 | `enforce=false`、mode=`unavailable`，调用一次 | gateway 收到工具失败，event outcome=`fail`、error_class=`unreachable`；issue 创建为 `cooldown`；实际 HTTP call 计数 +1 |
| C3 | Shadow block 仍执行 | 同一 target 在 retry window 内再次调用，保持 `enforce=false` | preflight 可以是 `block` 且 `shadow=true`；调用仍实际发出，backend call +1；结果 event 的 `decision_id` 与 decision journal 对应 |
| C4 | 两个 run 的证据 | 复用 C2/C3 issue；在相同 run 再失败后，再用不同 run_id 失败 | 同一 run 不增加 distinct evidence；第二个不同 run 后 issue 升为 `open`，run ID 集合仅包含不同 run |
| C5 | Enforce 真拦截 | issue 未到重试时间时设 `enforce=true`，发起新 run 调用 | 抛出 `ToolBlocked`，decision=`block`；backend call 计数不变；不得写一条伪造的工具结果 event |
| C6 | retry 后恢复探测 | 等待 issue 的 `next_retry_at`，设服务为 `success`，以新 run 调用 | preflight 返回 `probe`；实际 HTTP 请求 +1；postflight 记录 ok 并 resolve issue；`next_retry_at`、`probe_started_at` 为空 |
| C7 | 成功后的后续调用 | C6 成功后再次调用同 target | preflight `allow`，工具返回成功；issue 保持 resolved |
| C8 | 决策关联 | 对 C3/C5/C6 的决策和结果按 ID 关联 | 有实际调用结果的 event 带对应 decision ID；enforce 拦截没有工具 event 是正确行为 |
| C9 | 数据审计 | 对每个 root 执行 `memory.store.check()`，并读取 `memory.report()` | 正常完成的场景 check clean；events、decisions、issues 与实际调用数吻合 |

## 阶段 D：错误分类与恢复矩阵

对每种故障模式使用独立 root；读取 Gateway `ToolCallError.error_class` 和持久化 event/issue 的类别，核对一致性。

| ID | mode / 实际故障 | 预期类别 | Retry 预期 |
|---|---|---|---|
| D1 | 503 `unavailable` | `unreachable` | retryable；冷却期后可以 probe |
| D2 | 客户端等待超时 | `timeout` | retryable；按 timeout policy 更新窗口 |
| D3 | HTTP 429 | `rate_limit` | retryable；Retry-After 至少 1 秒，不应被 TTL 提前覆盖 |
| D4 | HTTP 401 | `auth` | non-retryable；preflight block，不能因到达 retry window 自动 probe |
| D5 | 服务未启动/连接拒绝（可选） | `unreachable` | 捕获 URLError 的连接拒绝原因后正确分类；不泄露异常中的敏感信息 |
| D6 | 503 后切换 success | `unreachable` → 成功 probe → resolved | 一次成功结果解除活动阻塞，之后 allow |

测试 D5 时可用不同端口创建 gateway，不要停止其他本机服务。若错误被包装成不同异常类型，应记录异常类型与分类结果，不要把预期写死后吞掉真实错误。

## 阶段 E：端到端脚本验收

运行：

```powershell
python runtime_memory/tool_layer/run_demo.py
```

JSON 输出中依次核对：

1. `healthy_call` 成功且有本地结果；
2. 三次 outage 均以 `unreachable` 记录，前两次 run ID 相同，第三次不同；
3. `evidence_gate` 状态为 `open`，包含两个 distinct run ID；
4. `enforce_gate.outcome` 是 `blocked_before_tool`，调用前后 backend call 数相同；
5. `recovery_probe.decision.action` 是 `probe`，成功后 `final_issue.issue.status` 为 `resolved`；
6. `final_report` event/decision/issue 计数符合该执行轨迹；
7. 最终 `check` 为 `[]`。

## 判定与失败处理

- A1、A2、B1–B5、C1–C9、D1–D4、E 的强制项全部通过，才判为“本地 HTTP 工具层初步可用”。D5 为可选网络边界用例。
- 若 B 模式通过但 C/E 失败，问题位于 gateway 与 RuntimeMemory 的调用/记录集成，不能判为工具层通过。
- 若 C5 backend call 仍增加，属于 enforce gate 未生效的阻断级失败；停止后续可能造成重复调用的场景并保留输出。
- 若失败 event 没有 issue 或 decision link 错误，记录 event、issue、decision 三份原始 JSON 和 request 参数（脱敏）。
- 不要把本地注入的 503/timeout 称为真实生产故障分布；该计划验证的是调用控制与故障闭环。

## 最终报告格式

```text
# Tool Layer 测试总结
- commit / Python：
- 执行命令与退出码：
- 临时 root / 数据隔离确认：

| ID | PASS/FAIL/SKIP | 实际值 | 证据路径 |

## 主要问题
- 复现步骤：
- 预期与实际：
- stdout/stderr 或 JSON 证据：

## 结论
- 本地 HTTP 工具层初步可用：是/否
- 尚未验证：MCP 协议适配、真实远端工具流量、生产并发/负载。
```

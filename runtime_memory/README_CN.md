# 运行记忆（Runtime Memory）

运行记忆是一个面向工具与服务调用的轻量原型：记录调用结果，把重复故障聚合成 issue，并在调用前给出 `allow`、`allow_with_hint`、`probe` 或 `block` 决策。

它与 [`demo/`](../demo/README.md) 的案例记忆分开：案例记忆回答“攻击是什么”，运行记忆回答“工具/服务当前有什么问题、何时可以重试”。两者的代码、数据和生命周期都不共享。

## 当前实现

- 追加式事件日志、issue 快照、调用前决策和人工 override 审计。
- 按错误类型配置退避；重试预算耗尽后仍允许慢速探测。
- retryable 错误只有在不同 `run_id` 中出现，才累计为独立证据；同一 run 的重试不会单独升级为长期 `open`。
- 默认 `shadow`：记录决策但仍执行调用。只有调用方接入 gateway 并遵守 `enforce` 决策，`block` 才会真正阻止工具调用。
- [`tool_layer/`](tool_layer/README.md) 是本机 HTTP 测试工具层：真实发起 localhost 请求并注入可控故障；它不是 MCP server，也不是生产 gateway。
- 存储使用可读的 JSON/JSONL 文件和跨进程锁，适合小规模原型；它不是事务型数据库。

## 快速开始

以下命令在 `runtime_memory/` 目录执行：

```powershell
# 检查默认 store，查看状态和简短记忆卡片
python src/manage_runtime_memory.py check
python src/manage_runtime_memory.py state --json
python src/manage_runtime_memory.py brief

# 确定性运行记忆演示
python src/run_runtime_demo.py --shadow
python src/run_runtime_demo.py --enforce
```

本地 HTTP 工具层演示从仓库根目录执行：

```powershell
python runtime_memory/tool_layer/run_demo.py
```

演示默认使用临时数据目录。工具层支持 `--data-root <路径>` 保留产物；实验时请与 `runtime_memory/data/`、`demo/data/` 分开。要求 Python 3.11+；本地工具层仅使用标准库。

## 调用方如何接入

运行记忆库不会自动拦截任意工具调用。调用方/gateway 需要在调用前执行 `preflight`，在 enforce 模式下跳过 `block`，其它允许的决策才调用工具，并把实际结果连同原始 decision 传给 `postflight`：

```python
from runtime_memory import OperationRequest, RuntimeMemory

memory = RuntimeMemory("runtime-data")
request = OperationRequest(
    component="mcp", tool="search", action="search",
    target="local-service", args={"query": "health"},
    scope="session", session_id="session-1", run_id="run-1",
)
decision = memory.preflight(request)

def invoke(call_tool, request, decision):
    if decision.action == "block" and not decision.shadow:
        return {"blocked": True, "decision": decision.to_dict()}
    try:
        result = call_tool(request)
    except Exception as error:
        memory.postflight(request, "fail", error=error, decision=decision)
        raise
    memory.postflight(request, "ok", decision=decision)
    return result

result = invoke(call_tool, request, decision)
```

调用结果应由 harness/tool adapter 写入，不能只依赖模型自报成功。真实调用接入时先观察 shadow 数据，再考虑开启 enforce。

## CLI

全局参数 `--root` 放在子命令前，可把记忆写入独立目录：

```powershell
python src/manage_runtime_memory.py --root ..\tmp\runtime-data check
python src/manage_runtime_memory.py --root ..\tmp\runtime-data preflight `
  --component mcp --tool search --action search --target local-service `
  --args '{"query":"health"}' --run-id run-1 --json
python src/manage_runtime_memory.py --root ..\tmp\runtime-data record `
  --component mcp --tool search --action search --target local-service `
  --outcome fail --error-class unreachable --run-id run-1
python src/manage_runtime_memory.py --root ..\tmp\runtime-data report --json
```

其它常用命令：`issues --active`、`issue <ISS-ID>`、`brief --json`、`resolve`、`ignore`、`note`、`workaround` 和默认 dry-run 的 `gc`。`preflight --probe --basis ...` 是会留下审计记录的操作员 override。

## 目录结构

```text
runtime_memory/
├── src/runtime_memory/       # library：模型、策略、store、运行时、报表、CLI
├── src/manage_runtime_memory.py
├── src/run_runtime_demo.py
├── tool_layer/               # 本地 HTTP 工具服务、memory gateway、端到端演示
├── data/                     # 默认策略与 store 种子；临时测试不要写这里
├── tests/                    # 单元、边缘和安全回归
├── scripts/                  # 验证辅助脚本
├── sim/                      # 场景、负载探针和已保存的实验结果
└── skills/runtime-memory/    # Agent 使用规则
```

store 文件包括 `policy.json`、`issues.json`、`events/YYYY-MM.jsonl`、`decisions.jsonl`、`overrides.jsonl` 和人工维护的 `playbook.md`。`sim/runs/` 是实验产物，不是默认实时记忆目录。

## 测试与文档

在 `runtime_memory/` 下：

```powershell
python -m unittest discover -s tests
python scripts/verify_runtime_memory.py
```

- [English README](README.md)
- [设计文档](../docs/RUNTIME_MEMORY_DESIGN.md)
- [算法简单测试指南](../docs/RUNTIME_MEMORY_SIMPLE_TEST_GUIDE_2026-11-10.md)
- [修复与并发复测计划](../docs/RUNTIME_MEMORY_FIX_AND_RETEST_PLAN_2026-11-10.md)
- [工具层测试计划](../docs/RUNTIME_MEMORY_TOOL_LAYER_TEST_PLAN_2026-11-10.md)

## 边界

- Shadow 只给建议，不会阻止调用；要减少重复调用，调用方必须接入并遵守 enforce 决策。
- 本地工具层验证 localhost HTTP 调用和受控故障，不验证 MCP 协议、生产流量或真实故障分布。
- JSONL 加文件锁适合小型原型，不适合高吞吐多 Agent 服务；带 `run_id` 的 preflight 会扫描事件计算 run 预算。
- event 已追加但 issue 尚未更新时若进程崩溃，可能留下孤立 event；`check` 会报告，但不会自动修复。
- 默认退避参数是起点，尚非生产环境校准值。

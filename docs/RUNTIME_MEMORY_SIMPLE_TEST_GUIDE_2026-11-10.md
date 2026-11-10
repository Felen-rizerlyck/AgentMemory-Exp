# Runtime Memory 简单效果测试指南

**用途**：交给执行模型，在隔离数据目录中验证近期算法修改是否符合预期。  
**范围**：只做小规模、可解释的功能检查，不做性能压测，也不据此判断生产可用性。  
**实现对象**：`runtime_memory/` 当前 CLI 和运行时实现。

## 执行要求

1. 只使用临时目录作为 `--root`，不要读写 `runtime_memory/data`、`sim/runs` 或 demo 数据。
2. 不改源代码和现有测试；仅准备临时 policy 和测试数据。结束后保留测试输出/报告，清理临时目录。
3. 默认保持 `enforce: false`（shadow）。测试期间不调用真实工具；所有 outcome 都由测试者通过 `record` 模拟。
4. 每一步记录命令、输出、测试目录、最终 `issues.json` 和 `report --json`。失败时保留目录，便于复现。
5. PowerShell 命令从仓库根目录执行。可先运行 `python runtime_memory/src/manage_runtime_memory.py --help` 确认入口可用。

## 临时环境

```powershell
$testRoot = Join-Path $env:TEMP "runtime-memory-simple-check"
New-Item -ItemType Directory -Force -Path $testRoot | Out-Null
Copy-Item runtime_memory/data/policy.json (Join-Path $testRoot "policy.json")
```

编辑临时目录中的 `policy.json`，对 `unreachable` 规则设置短间隔，便于不等待太久：

```json
"enforce": false,
"classes": {
  "unreachable": {
    "key_level": "scope",
    "retryable": true,
    "mode": "exponential",
    "base_s": 2,
    "max_s": 3,
    "max_attempts": 1,
    "ttl_s": 60
  }
}
```

保留 `policy.json` 中其它 error class 配置。每个 CLI 命令均在子命令前传入 `--root $testRoot`。下面用 `$script` 保存 CLI 脚本路径：

```powershell
$script = "runtime_memory/src/manage_runtime_memory.py"
python $script --root $testRoot check
```

如执行环境不是 PowerShell，将 `$testRoot` 换成操作系统临时目录，并用等价的 CLI 调用。测试结束前不要复用旧的测试目录；需要重跑时先换一个新目录名。

## 测试用例

统一请求参数：`--component mcp --tool demo.query --action search --target test-endpoint --scope global --environment test --args '{"q":"health"}'`。每个 case 使用不同 `--target`，避免 fingerprint 相互影响。记录失败时使用 `--outcome fail --error-class unreachable --message "simulated connection failure"`。

| ID | 验证点 | 操作 | 预期结果 |
|---|---|---|---|
| T0 | 隔离与初始状态 | 在新 `$testRoot` 执行 `check`、`brief`、`state --json` | check clean；brief 显示没有活动问题；事件和 issue 数为 0。仓库默认 data 未改变 |
| T1 | 首次失败可记忆 | 对 target `case-one` 执行一次 `record`，`run-id run-A` | 创建一个 `cooldown` issue，`count=1`，记录 `evidence_run_ids=[run-A]`，并有 `next_retry_at` |
| T2 | 同一 run 的重试不升级 | 对 `case-one` 再执行两次失败记录，仍传 `run-id run-A` | issue 保持 `cooldown`，`count` 增加；独立运行证据仍只有 1 个。不能仅因同一 run 重试而变为 `open` |
| T3 | 跨 run 的重复故障升级 | 对 `case-one` 再记一次失败，传 `run-id run-B` | `evidence_run_ids` 包含两个不同 run；issue 升为 `open`。`issues --active --json` 可见状态和证据数 |
| T4 | 冷却期内拦截建议 | 对新 target `case-cooldown` 记录一次失败，然后立即执行 `preflight ... --run-id check-T4 --json`，不加 `--probe` | retry 时间未到时返回 `block`，原因包含等待重试窗口。因 policy 是 shadow，决策带 `shadow: true`；此步骤不调用真实工具 |
| T5 | 预算耗尽后仍可探测 | T3 后等待到 issue 的 `next_retry_at`（短 policy 下最长约 3 秒），用新的 `--run-id check-T5` 执行 `preflight` | 返回 `probe`，原因可标为慢速恢复探测；不能因为 `attempts > max_attempts` 永久 block。新 run 用于避开单 run 的调用预算。若读取到 `next_retry_at`，按其时间等待，不要固定假设延时 |
| T6 | 探测成功自动解除 | 将 T5 返回的 `decision_id` 传给 `record --outcome ok --run-id run-C --decision-id <id>` | issue 变为 `resolved`；顶层 `next_retry_at` 和 `probe_started_at` 应为空。之后相同请求 preflight 返回 `allow` |
| T7 | 精简记忆卡片 | 在另一个新 target 上记录一次失败，执行 `brief` 和 `brief --json` | 输出活动问题的工具/目标、状态、错误类型、独立 run 数、重试时间；存在 workaround 时显示 workaround；不输出完整事件历史 |
| T8 | 结构与审计自检 | 执行 `check`、`report --json`，保存 `issues.json`、events、decisions | check clean；report 有本次模拟事件和决策。日志中的请求工具动作与决策结果可区分；通过 `decision_id` 可以把记录和结果关联起来 |

## 命令参考

以下模板中的公共参数可复制到各命令后：

```powershell
$common = @('--component','mcp','--tool','demo.query','--action','search',
  '--target','case-one','--scope','global','--environment','test',
  '--args','{"q":"health"}')
python $script --root $testRoot record @common --run-id run-A --outcome fail `
  --error-class unreachable --message 'simulated connection failure'
python $script --root $testRoot issues --active --json
python $script --root $testRoot preflight @common --run-id check-T5 --json
python $script --root $testRoot brief --json
python $script --root $testRoot report --json
```

注意：`--root` 是全局参数，放在子命令之前。T2/T3 重复记录时复用相同 `$common`，仅替换 `--run-id`。T5 等待 `issues --active --json` 中该 issue 的 `next_retry_at` 到时后再调用 preflight。T6 使用 T5 输出的 decision ID 记录成功结果。

## 汇总记录模板

执行模型完成后，请输出下面这张表，并附上命令输出或文件路径：

| ID | 结果（通过/失败/未执行） | 观察到的值/行为 | 证据（命令输出或文件） | 备注 |
|---|---|---|---|---|
| T0 |  |  |  |  |
| T1 |  |  |  |  |
| T2 |  |  |  |  |
| T3 |  |  |  |  |
| T4 |  |  |  |  |
| T5 |  |  |  |  |
| T6 |  |  |  |  |
| T7 |  |  |  |  |
| T8 |  |  |  |  |

另附：Python 版本、执行日期、policy 实际内容、测试目录、`check` 输出、`report --json`。不要把一次小样本测试描述成总体效果或生产验证。

## 判定标准与问题报告

- T2 未升为 `open` 且 T3 升为 `open`：证据独立性行为符合预期。
- T5 在退避时间到达后返回 `probe`，T6 成功后变为 `allow`：慢速恢复和解除闭环符合预期。
- T8 `check` clean，decision 和 event 能按 ID 关联：本轮基础记录闭环成立。
- 任一结果不符时，保留临时目录，不要直接修改源代码“修好测试”。报告实际命令、完整 JSON 输出、当前 issue 内容、预期与实际差异。
- 若 CLI 参数形式或字段名与本文不同，先记录版本/差异并停止该 case，不要猜测参数或对默认数据目录试跑。

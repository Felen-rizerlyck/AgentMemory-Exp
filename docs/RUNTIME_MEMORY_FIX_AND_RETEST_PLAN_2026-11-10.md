# Runtime Memory 并发与回归修复、复测计划

**状态**：代码修复已完成，等待后台模型复测  
**用途**：交给后台模型按阶段修复并复测 `runtime_memory`。  
**依据**：`runtime_memory/sim/simple-guide-2026-11-10/REPORT.md`、`runtime_memory/sim/runs/exec-20261103T084500Z/EXECUTOR_REPORT.md` 与 `runtime_memory/sim/concurrency.py`。  
**目标**：修复并发写入/聚合问题和审计缺口；同步过时测试；形成可复现的通过/失败证据。

## 已完成的代码修复

本轮已按下述问题完成代码修改，后台模型接下来负责复测和报告；不要重复实现这些改动：

| 区域 | 已完成修改 | 仍需由复测确认 |
|---|---|---|
| `store.py` 文件锁 | Windows 锁文件短暂 `PermissionError` 时在有界超时内重试；postflight 已有的全操作 writer lock 保留 | 并发 append 与并发 postflight 是否连续稳定通过 |
| issue 合并 | 合并并发创建的同 key issue 时合并 `evidence_run_ids` 和 `dropped_event_count` | 两进程竞争是否只留下一个 issue、计数和 event 引用完整 |
| `Store.check()` | 在一致的 writer lock 快照下校验；报告无匹配 issue 的失败 event | 手工 orphan 和 crash 注入能否被发现；现有保留/GC数据有无误报 |
| 报表 | `issues.by_status` 对所有状态输出显式计数（包括 0） | 旧消费者/单测及 JSON 报表是否正常 |
| 旧测试语义 | 更新旧断言以匹配同 run 不升级、独立 run 升级、预算耗尽后慢 probe；增加对应的独立 run 和 orphan-event 用例 | 所有单元测试是否通过 |
| 并发探针 | 清理重复导入、修正 expected 字段；孤立 event 不再伪报 PASS；FAIL 返回非零退出码 | 新 probe 的实际退出码、metrics 与汇总是否一致 |

以上属于待复测的实现，不代表已验证修复。若 R1–R5 暴露失败，后台模型应提交失败证据和根因，不要修改结果来使其通过。

## 执行边界

1. 开始前记录仓库根目录、当前 commit、Python 版本和 `git status --short`。工作区已有修改不得覆盖、还原或清理。
2. 当前代码修复已完成。直接执行下方回归，不要在复测途中先改代码；如发现问题，保留失败产物并单独报告。复测使用新建的临时输出目录，不覆盖已有 `sim/runs/*` 产物。
3. 修复必须保持运行记忆数据与 `demo/data` 隔离；并发和崩溃测试只使用临时目录。
4. 不通过放宽断言、跳过失败用例或只把状态改成 `PASS` 来消除失败。每个失败都要有代码原因、针对性回归和原始输出。
5. 每阶段完成后记录文件、变更摘要、命令、退出码和结果。遇到无法解释的基线差异，停止依赖该结果的修复并报告差异。

## 已知基线

简单功能测试 T0–T8 为 PASS，涵盖同 run 不升级、跨 run 升级、预算耗尽后 probe、成功解除和 brief 输出。该结果是小样本行为验证，不是并发或生产验证。

已有并发探针报告记录：

| 检查 | 已观察结果 | 初步含义 |
|---|---|---|
| 并发 JSONL append | 165/200 行；一个进程创建/打开 `.lock` 文件时报 `PermissionError` | 文件锁文件的跨进程打开/生命周期仍有问题；需在当前 checkout 复现后定位，不能假定根因 |
| 并发 postflight | 2 events，却写成 2 条 issue、每条 count=1 | 相同 fingerprint 的并发创建未稳定聚合 |
| event 无对应 issue | `check()` 未报问题 | 检查器尚未识别孤立 event |
| event 写入后进程终止 | 1 event、0 issues，`check()` clean | 部分写入可留下静默不一致 |
| 旧单测 | 90 项中 3 failures / 1 error | 部分测试仍断言旧的升级/预算行为；报表对缺省 status 键也不够稳健 |

上表来自既有报告。执行者应以当前 checkout 的新基线为准，并在报告中注明是否复现。并发脚本的输出/退出码诊断已做整理，但实际锁和一致性缺陷尚未因此修复。

## 阶段 0：冻结基线与确认执行对象

| 步骤 | 操作 | 验收 |
|---|---|---|
| 0.1 | 记录当前 commit、`git status --short`、Python 版本和测试命令工作目录 | 结果写入本次 run 的 `BASELINE.md`；既有改动清单可追溯 |
| 0.2 | 记录本次修复后测试基线：从 `runtime_memory/` 执行 `python -m unittest discover -s tests` | 完整保存 stdout/stderr、退出码、测试总数、失败名和 traceback |
| 0.3 | 运行并发 probe：从 `runtime_memory/` 执行 `python sim/concurrency.py --run-id <唯一run-id> --out <临时目录>` | 保存 `metrics.json`、`summary.md` 和退出码；确认 `--out` 不位于既有 run 目录 |
| 0.4 | 检查目标源码与报告所指版本是否一致 | 记录差异；不得把旧 checkout 的失败直接宣称为当前代码的失败 |

## 阶段 1：修复并发文件锁与 append

### 目标

多进程向同一 JSONL 追加时，每条记录完整、无丢行、无互斥锁文件打开错误；锁等待超时要被清楚报告。

### 工作项

1. 检查 `store.py` 的 `file_lock`、OS 锁获取/释放、锁文件创建和 `append_jsonl`。重点分析 Windows `PermissionError` 的实际 traceback/文件句柄生命周期；不可仅凭报告推断具体根因。
2. 确认所有进程锁定同一规范化路径，锁文件不会在仍有进程依赖时被删除或替换；进程被终止时 OS 锁可释放。
3. 检查线程内重入逻辑是否只避免同线程重复获取，且不会错误地把其他线程当作持锁者。
4. 如要改变锁策略，说明 Windows 与 POSIX 分支的行为、超时策略和锁文件保留策略。

### 验收

- 至少连续运行 10 次并发 append 检查，每次 2 个进程各写 100 条；每次都恰有 200 行、200 行均可解析为 JSON、无重复/丢失、无 worker error。
- 锁等待超时测试（若实现有超时）应稳定返回明确异常，不产生截断 JSONL。
- 不允许只因 `metrics` 状态逻辑改变而通过；计数和逐行解析必须通过。

## 阶段 2：修复 issue 并发聚合

### 目标

两个进程同时为同一 fingerprint/error_class 记录失败时，最终只存在一个活动 issue，事件和失败次数完整。

### 工作项

1. 从 `RuntimeMemory.postflight`、`_write_locked`、`Store.writer_lock`、`find_issue`、`upsert_issue` 追踪一次失败从读到写的完整临界区。
2. 找到并修复“锁保护了单次 upsert，但 issue 查找/创建/更新并非一个原子临界区”或其他已由复测证明的竞态。
3. 如果继续采用 JSON 文件，保证进程级锁覆盖读-改-写的完整事务；避免用两个各自原子的操作假装整体原子。
4. 检查并发成功/失败交错时不会把 resolved issue 重新覆盖为旧状态，也不会丢 source event 引用/运行证据。

### 验收

- 同一 fingerprint 的 2 个并发失败最终为 2 events、1 个活动 issue、`count=2`、source event IDs 包含两条 event。
- 至少运行 10 次并发 postflight 检查，均满足以上条件，无重复 issue、无丢计数。
- 再做不同 fingerprint 并发写入，结果分别聚合，不互相合并。
- 所有参与写入的进程以成功退出或提供可诊断错误；不得静默吞错。

## 阶段 3：检查器识别孤立 event 与崩溃窗口

### 目标

若 event 已落盘、issue 尚未落盘，`check()` 能发现可识别的不一致；报告不把它标为 clean/PASS。

### 工作项

1. 定义最低限度可检查的不变量：失败 event 应能匹配到 fingerprint/error_class/scope/scope_id 对应 issue；成功 event 可以引用已存在 issue 或不对应任何 issue。
2. 按当前数据模型实现一致性检查，并考虑 resolved issue、GC 删除旧事件、保留期和旧 schema，避免对合法历史数据误报。
3. 更新 `sim/concurrency.py`：crash 场景须检查 orphan event 是否被报告；未检测到应是 `GAP` 或 `FAIL`，不能 `PASS`。脚本遇 `FAIL` 返回非零退出码。
4. 检查修复/重建功能是否属于本轮必要范围。若不实现自动修复，`check` 输出需给出 event ID 和 issue key 等可定位信息。

### 验收

- 手工构造“失败 event 有、issue 无”的隔离 store，`check()` 返回清晰问题。
- 正常 `postflight` 产生的 event/issue 数据通过 `check()`。
- crash 注入在 event append 与 issue 更新之间终止进程后：日志不损坏，孤立 event 被明确检测，不报 clean。
- 对应 check 输出和 crash probe 的 metrics 互相一致。

## 阶段 4：同步策略测试与报表边界

### 策略语义（新预期）

| 场景 | 预期 |
|---|---|
| 同一 `run_id` 内同 issue 重复失败 | 失败计数增加，证据运行数不增加；retryable 错误不因同一 run 的重试直接升为 `open` |
| 出现第二个独立 `run_id` 的失败 | 达到独立证据门槛后升为 `open` |
| 无 `run_id` 的重复失败 | 不伪造独立 run 证据；仍能按 retry/backoff 规则工作 |
| retryable 错误超过 `max_attempts` | 到期后慢速 `probe`，而非永久 block |
| probe 成功 | issue resolved，顶层 `next_retry_at` 与 `probe_started_at` 清空；后续 preflight allow |
| 不可重试类别 | 按对应策略 block/提示，不强套 retryable 路径 |

### 工作项与验收

1. 更新旧测试中的预期行为，保留用例覆盖目的，不删除断言来规避失败。
2. 为不同 run、同一 run、无 run_id、预算耗尽、probe 成功/失败补足清晰测试；测试时间通过固定时钟或短 policy 控制，不依赖长 `sleep`。
3. 报表的 `by_status` 对所有支持状态稳定输出（计数为 0 时也可访问），或明确规定消费者必须用 `.get`；为 CLI/JSON 使用者选择一致契约。
4. 失败/重复尝试指标的分组口径保持原定义，确保 `duplicate_attempts` 测试不会受 issue 状态改变影响。
5. 单元测试全绿；报告中列出执行总数、退出码和实际覆盖范围。

## 阶段 5：回归与结果归档

按以下顺序复测，全部使用唯一 run ID 和临时输出目录：

| 顺序 | 命令/动作 | 通过标准 |
|---|---|---|
| R1 | `python -m unittest discover -s tests`（cwd=`runtime_memory/`） | 全部通过，退出码 0 |
| R2 | 并发 append probe，连续 10 次 | 每次 200/200 行、JSON 有效、无错误 |
| R3 | 并发 postflight probe，连续 10 次 | 每次 2 events / 1 active issue / count 2 |
| R4 | partial-write 与 crash probe | orphan 被 check 检出；日志合法；状态为 GAP/FAIL 时不能伪报 PASS |
| R5 | 已有简单功能测试 T0–T8 | 全部通过，shadow 模式、临时 root、无真实工具调用 |
| R6 | `python src/manage_runtime_memory.py --root <临时root> check`、`report --json`、`brief --json` | check clean；输出 schema/状态计数合理；数据来源可追溯 |
| R7 | `git diff --check` 与 `git status --short` | 无空白错误；改动范围与计划一致，原有用户改动保留 |

在 `runtime_memory/sim/runs/<unique-run-id>/` 或明确的临时输出目录保存 `BASELINE.md`、命令日志、各 probe metrics 和最终 `SUMMARY.md`。若输出目录需清理，先确认路径只包含本次执行产物；不要清理共享或历史目录。

## 最终报告模板

```text
# Runtime Memory 修复与复测总结
- checkout / commit：
- Python 版本：
- 原始工作区修改：
- 本次修改文件：

## 修复摘要
| 问题 | 根因证据 | 修复 | 对应复测 |

## 复测结果
| R1-R7 | PASS/FAIL/GAP/未执行 | 数值与退出码 | 证据路径 |

## 已知限制
- 未解决问题：
- 是否允许进入下一阶段：是/否，理由：
```

## 完成门槛

只有当 R1–R7 均通过，且并发/崩溃检查没有静默数据丢失或孤立记录时，才建议进入真实工具 gateway 的 shadow 接入。任一并发项仍失败时，不要开启 enforce；报告失败及其复现证据，等待下一轮修复。

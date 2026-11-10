# 运行记忆（Runtime Memory）内容评审与优化路线

> **状态**：只读评审，未改动任何代码/数据/产物
> **日期**：2026-11-09
> **范围**：`runtime_memory/`（原型 + 数据产物 + 仿真实验 + 设计文档）
> **方法**：3 路独立只读评审（设计-实现差距 / 代码正确性-性能-安全 / 记忆内容-数据质量）+ Lead 复核；未重跑测试套件（原因见 §6）
> **一句话结论**：这套运行记忆的**底座是真实可跑的**，问题不在"有没有实现"，而在"**记忆内容是否可信、拦截行为是否正确、收益是否可证**"——三件事目前都只完成了一半。

**阅读导航**：现状盘点看 §1；已经做对的不要推翻看 §2；你感觉到的"优化空间"被归为五类看 §3；**从何下手看 §4（先做 D 组、再做 B 组、最后 G/C 组）**；如果只做三件事看 §4.5；不建议现在做的看 §5。

---

## 0. 一句话版本

现在的运行记忆 = **原始操作轨迹 + 按 fingerprint 聚合的失败计数 + 一套重试策略**。它已经能"记录 → 聚合 → 在调用前给 allow/probe/block"，但：

1. **内容自相矛盾**：`decisions.jsonl` 里工具动作被自己覆盖（`"action"` 写了两次），`issues.json` 里已解决 issue 仍留着过期的 `next_retry_at`，`confidence` 只是失败次数，`count/attempts/max_attempts` 三个计数互相打架；
2. **行为上有两个反向风险**：该硬的时候不硬（同一个 run 里重试两次就把 issue 升级成 `open`），不该硬的时候硬（attempt 预算用尽后对可重试故障硬封到 24h TTL，`enforce_60` 仿真成功率 0% 就是证据）；
3. **闭环有断点**：CLI 路径拿不到 `decision_id`，shadow 的 false-block 根本回算不出来，enforce 上线的 go/no-go 证据不成立；`playbook`、`notes`、`related_*`、`overrides` 全是空壳；per-component enforce 不存在，设计里的 Phase 2 无法执行。

**从何下手**：先做 §4.1 的"内容自洽 + 可度量"（半天，零风险），再做 §4.2 的"行为正确性"（2–3 天），然后才是 §4.3 的"接真实网关 + 性能"（3–5 天）。**不要**先调退避参数、不要先上向量库/图数据库、不要先做 playbook 自动生成。

---

## 1. 你现在到底存了什么（内容盘点）

### 1.1 仓库内的存储是"空壳"，这是设计使然

| 文件 | 现状 | 说明 |
|---|---|---|
| `runtime_memory/data/issues.json` | `{"schema_version":1,"issues":[]}` | 空；默认 demo 用临时目录，不落仓库 |
| `runtime_memory/data/decisions.jsonl` | 空文件 | 同上 |
| `runtime_memory/data/overrides.jsonl` | 空文件 | 从未产生 override |
| `runtime_memory/data/events/` | 只有 `README.md` | 轨迹不提交 |
| `runtime_memory/data/playbook.md` | 规则 + 1 条"Example (not active)" | 人审资产，当前 0 条有效条目 |

所以"看一下 runtime memory 的内容"，**仓库里能看到的只有策略和占位符**；真正的记忆内容在仿真产物里。

### 1.2 唯一一份真实内容：`sim/runs/sim-2026-11-02-agent-final/`

这是 shadow → enforce → 新 run 三个阶段的完整产物（确定性模拟，假时钟）：

| 产物 | 数量 / 内容 |
|---|---|
| `data/events/2026-11.jsonl` | **13** 条调用（ok 5 / fail 8） |
| `data/issues.json` | **5** 条 issue（resolved 3 / open 2） |
| `data/decisions.jsonl` | **9** 条决策（block 5 / probe 4；shadow 4 / enforce 5） |
| `report.json`/`summary.md` | blocked calls 3、would_block 2、false_blocks 0、duplicate_attempts 3 |
| `records.md` | 7 个手工抽样记录 |
| `narrative.log` | 带时间戳的故事线 |
| `policies.json` | 3 个阶段的 enforce 开关记录 |

另有 `sim/runs/workload-2026-11-03-b30/`（30 seed × 11 配置的蒙特卡洛）和 `sim/runs/scale-2026-11-03/`（1k/5k/20k 事件性能探针）。

### 1.3 记录的"内容密度"很低

| 记录 | 字段数 | 其中真正有信息量的 |
|---|---|---|
| event | ~25（identity/trace/redaction 派生字段占多数） | 时间、op 身份、outcome、error_class、message、duration、attempt |
| issue | 32–34（含 6 个从未填过的字段） | fingerprint、status、count/attempts、next_retry_at、workaround、source_event_ids |
| decision | ~25（≈80% 可从 issue+event 派生） | decision、reason、shadow、override*、issue_id |

把 13 条事件压成"人/模型真正需要读的内容"，实际只有：

- **5 条错误消息**：`connect refused`、`429 Too Many Requests`、`truncated pcap header`、`denied`、`upstream timeout`；
- **2 个重试窗口**（MCP 06:17、SIEM 06:06）；
- **1 条 workaround**（MCP 用本地 pcap/缓存）；
- **2 条仍未解决的 issue**（pcap call-level schema、shell permission）。

同时：`playbook` 0 条、`notes` 0 条、`related_incident_id/related_case_id` 全 null、`overrides` 0 条、`allow_with_hint`/`mitigated`/`stale` 状态从未出现、`error_code`/`evidence_ref`/`agent_id` 从未填过。

**结论**：今天的"记忆内容"= 原始轨迹 + 聚合计数；**还没有"结论/经验/摘要"这一层**。这正是工作记忆最该优化的地方之一。

---

## 2. 已经做对的部分（优化时不要推翻）

1. **三层模型是真的**：trace（append-only JSONL）→ issue（按 scope/call 两级 fingerprint 聚合）→ preflight（allow/probe/block/hint），不是只存不拦的日志。
2. **shadow/enforce 双模式 + 安全阀**：stale 允许一次 probe、非重试错误首次即 open、人工 resolve/ignore/override 有入口；E1–E15 边界用例已有测试覆盖。
3. **身份与隔离**：`environment_id` 进 fingerprint；`global/session/agent` + `scope_id` 的可见性规则；重试窗口不会被小 TTL 提前击穿（Retry-After > TTL 的修复）。
4. **脱敏有基础**：Bearer/JSON secret/query/private key 都有规则，且写入 `args` 前会先脱敏再 hash。
5. **证据链完整度比一般原型好**：90 个测试、`verify_runtime_memory.py` 验证矩阵、scenario/workload/scale 三类仿真、`AGENT_NOTES.md` 记录了独立执行者的复核。
6. **设计文档质量高**：`docs/RUNTIME_MEMORY_DESIGN.md` 把边界、威胁模型、反模式都写清楚了——问题主要是**实现没跟上文档**，而不是缺想法。

下面的优化是在这个骨架上补内容层、修行为、补闭环，不是重写。

---

## 3. 你感觉到的"优化空间"，具体是这五类

### 3.1 内容形状：宽、重复、关键字段相互覆盖

| ID | 问题 | 证据 | 影响 |
|---|---|---|---|
| C1 | **决策记录里工具动作被覆盖**：`_decision_record` 先写 `"action": request.action`，随后又写 `"action": decision.action`，后写覆盖前写 | `runtime_memory/src/runtime_memory/runtime.py:276` vs `:287`；产物 `data/decisions.jsonl:1` 里 `"action":"block","decision":"block"` | `"search"` 这类工具动作从决策日志中消失；只能靠 fingerprint 反推；`check()` 按 `action ∈ ACTIONS` 校验，永远查不出来 |
| C2 | **决策 80% 字段是派生的**：`blocked_until/expires_at/confidence/alternatives` 都能从引用 issue 得到；identity 字段与 event 重复 | `decisions.jsonl` vs `issues.json` 对照 | 记录变宽、写放大、且派生字段会漂移（下面 C3） |
| C3 | **issue 记录自相矛盾**：已 resolved 的 issue 仍保留过期的 `next_retry_at`；`probe_started_at` 在 shadow probe 时为 null、enforce probe 时才有值；`last_probe_event_id` 既写失败 probe 也写成功 probe；`workaround_by/at` 不在 dataclass 里，下次更新即丢 | `runtime.py:456-483`（resolve 不清 next_retry）；`:260-265`（probing 仅 enforce）；`:449-450` / `:476`；`models.py:79-121` | 读记录的人/模型无法判断"这条 issue 现在到底该不该试"；审计字段会静默丢失 |
| C4 | **`confidence` 只是失败次数**：`min(0.95, 0.4 + 0.2*count)`，不衰减、不随反证下降，却被打印给 agent、被用作排序 tiebreaker | `runtime.py:419,447`；`cli.py:61,76` | 名字叫"置信度"，实际是"重复计数"；会诱导模型过度相信记忆 |
| C5 | **`count / attempts / max_attempts` 三重语义**：`count`=失败次数、`attempts`=全部调用、`max_attempts`=首次失败后的重试数（所以 `attempts = max_attempts+1`） | `README_CN.md:163-169`、`AGENT_NOTES.md §2/§6.2`、`EDGE_CASES.md:41-42` | 同一个 issue 上出现 `count=3, attempts=4, max_attempts=3`，每个读记录的人都要先学一遍语义 |
| C6 | **`source_event_ids` 静默截断到 20**，没有丢弃计数；resolved 后复发会把 count/attempts 重置为 1，慢性问题读起来像新问题 | `runtime.py:452-453`、`:431-436` | 审计不可追溯；记忆"失忆" |
| C7 | **没有摘要/渲染层**：给 agent 的是 Decision 的 `reason` 字符串 + JSON；给运维的是 counts + 10 条"最新"issue（不是最严重） | `report.py:124-137`、`cli.py:48-86` | "记忆内容"从未被压缩成可复用的一句话结论；上下文注入靠调用方自己拼 |

### 3.2 证据与信任：一次重试风暴就能"硬化"一条 issue

| ID | 问题 | 证据 | 影响 |
|---|---|---|---|
| T1 | **没有证据独立性**：同一 fingerprint 第二次失败就 `cooldown → open`（硬拦级别），不区分是不是同一个 run/session 的重试风暴；issue 不存 distinct run/session 计数 | `runtime.py:438-447` | 一次参数错误重试 2 次就能把工具封住；这是"记忆污染"的最小复现路径 |
| T2 | **拦截/解决/白名单全是无鉴权的**：`record --outcome ok` 的"自报成功"会直接 resolve issue；`resolve/ignore` 的 `--reviewer` 默认 `"human"`；CLI 把 `--probe` 直接映射成 `human_override=True`；store 就是 agent 可写目录 | `runtime.py:355-370,486-507`；`cli.py:148-158,231-233`；`store.py:137-146` | "模型不能自己解封/绕过"目前只是约定，不是机制；SKILL/README 的安全声明与实现不符 |
| T3 | **覆盖审计可被跳过**：`record=False` 时 override 不写 `overrides.jsonl`；resolve/workaround 只改 issue 可变字段，没有 append-only 审计 | `runtime.py:223,486-521` | 无法回答"是谁、凭什么解除了这个 block" |
| T4 | **脱敏有缺口**：只匹配 Bearer，不匹配 Basic；签名类 query 参数（`X-Amz-Signature`/`sig`/`credential`）会原样落盘；URL fragment 不扫；非 URL 的 `user:pass@host`、`AWS_SECRET_ACCESS_KEY=...` 漏网；`error_class/component/tool` 等模型侧字符串不脱敏 | `redact.py:13-34,55-71`；`runtime.py:318-342,530-534` | 凭据可能进入长期日志 |
| T5 | **"成功"没有 provenance**：event 的 `author` 硬编码为 `"harness"`，不校验调用方身份 | `runtime.py:352` | 无法区分"工具真成功"和"模型自报成功" |

### 3.3 生命周期：该退不退，该放不放

| ID | 问题 | 证据 | 影响 |
|---|---|---|---|
| L1 | **预算耗尽 = 长期硬封**：`attempts > max_attempts` 时永远 `block`，直到 `expires_at`（`unreachable` 是 24h）；而 `stale` 只在 TTL 到期后才出现 | `runtime.py:100-114`；`policy.py:24-28` | 网络抖动 3 分钟后恢复，记忆仍可能封 24 小时；**记忆把短故障变成长故障** |
| L2 | **workload 已经在报警**：`enforce_60` 成功率 0%（预算在恢复前耗尽）、`enforce_300` 46.7%、`enforce_900` 100%、`enforce_1800` 100%——成功率只由"重试窗口是否长于故障时长"决定 | `sim/runs/workload-2026-11-03-b30/metrics.json:30-127` | 当前默认参数在真实故障分布下不可信；README 已诚实记录，但没有给出修复方向 |
| L3 | **stale 不退休**：`stale` 是 ACTIVE 状态，`probe_after_expiry=false` 时永久 block；`gc` 只删 `resolved` issue 和整月旧事件文件，open/stale 永不清理，decisions/overrides 更是无保留期 | `models.py:12`；`runtime.py:93-99`；`store.py:413-443` | 陈旧记忆无限积累；`issues.json` 每次全量重读，越来越慢 |
| L4 | **`mitigated` 永远不会自动获得**：设计说"其它环境/其它 agent 成功 → mitigated"，实现只有同 key 成功 → resolved；alternative 只是文本，成功使用替代路径不会回写记忆 | `runtime.py:456-483`；设计 §7.2/§13 | 记忆学不到"绕路成功"的经验，workaround 永远是死文本 |
| L5 | **resolved 后复发重置**：count/attempts 清零，缺 lifetime 计数 | `runtime.py:431-436` | 慢性依赖问题被读成一次性问题 |

### 3.4 闭环：decision → event → issue → playbook 链上有断点

| ID | 问题 | 证据 | 影响 |
|---|---|---|---|
| F1 | **CLI 路径拿不到 decision_id**：`preflight` 文本输出不打印 `decision_id`，`record` 也没有 `--decision-id`；而 `report` 靠 decision↔event 的 `decision_id` join 计算 false-block 和 probe 成功率 | `cli.py:48-68,127-146,239-250`；`report.py:41-68` | 按文档推荐的 agent 用法（CLI preflight→tool→record），shadow 指标恒为 0——enforce 上线的 go/no-go 证据无法产生 |
| F2 | **false_block_rate 既没输出、口径也有问题**：`report` 只输出计数；workload 里 `false_block_rate = false_blocks / would_block`，分母把同一 outage 内每次重复 preflight 都算进去，所以 `enforce_*` 行 0.0 是 0/0 的假零 | `report.py:102-109`；`workload.py:160-162`；metrics.json 各 enforce 行 | 设计写的"<5%"门槛无法被验证；仿真出的 6.3%/7.8% 也不能直接判超标——**先改口径再谈门槛** |
| F3 | **playbook 闭环不存在**：只有占位文件；没有 `report --propose-playbook`、没有 issue↔playbook 链接、没有复核/失效条件字段 | `store.py:162-168`；`models.py:79-121` | 设计里的 L1"人审蒸馏"环目前是零；记忆停在学习的第一步 |
| F4 | **指标覆盖不全/定义含糊**：缺 false_block_rate、time_to_workaround、tokens_saved、override_rate；`duplicate_attempts` 是全局计数不是 per-run；TTS 只对成功 run 取均值（幸存者偏差），`enforce_300` 的 578s 只覆盖 46.7% 的 run | `report.py:110-116`；`workload.py:151,163` | 无法回答"这份记忆到底省了多少、晚了多少"——而这正是调参的目标函数 |
| F5 | **override 从不进入报表**；`time_to_workaround` 没有可计算的时间点 | `report.py` 未读 overrides | 人工介入成本和收益不可见 |

### 3.5 系统层：现在还接不了真实网关

| ID | 问题 | 证据 | 影响 |
|---|---|---|---|
| S1 | **热路径 = 写锁 + O(events) 扫描**：`preflight` 全程持写锁，带 `run_id` 时还要 `read_events()` 全量扫描；20k 事件 155.9ms，无 run_id 0.9ms | `runtime.py:162-197`；`store.py:186-197`；`sim/runs/scale-2026-11-03/summary.md` | 每个工具调用都做一次这种 preflight 不现实；多 agent 会在同一把 OS 锁上串行（约 6 次/秒） |
| S2 | **report/check/state 也全量扫描**，且不先刷新过期状态 | `report.py:37-39`；`store.py:382-401`；20k 下 150ms/146ms | 运维视图慢且 `stale_rate` 可能算错 |
| S3 | **per-component enforce 不存在**：只有全局 `enforce` bool | `policy.py:103-104`；`runtime.py:76-78,137` | 设计 Phase 2"单组件硬拦→扩展"无法执行 |
| S4 | **部分写不可恢复**：成功时先 append event 再改 issue，失败时先 append 再 upsert；崩溃窗口会留下"有成功事件但 issue 仍 block"或"计数漏记"；`check` 不校验 event↔issue 关联，`rebuild_issues` 也不存在 | `runtime.py:368-383`；`store.py:350-392`；设计 §11.6 | 审计一致性只是概率性的 |
| S5 | **证据不可复现**：`sim-2026-11-02-agent-final` 里的 `data/policy.json`/`issues.json` 含 `defaults{...}`、`max_attempts_per_run`、`max_blocked_calls_per_run` 等 HEAD 代码已不产生的字段；`EDGE_CASES.md` 写 77 tests，README 写 90 | `sim/runs/sim-2026-11-02-agent-final/data/policy.json:6-16` vs `policy.py:13-75`；`EDGE_CASES.md:5` vs `README_CN.md:319` | 复核时的"实际产物"和当前代码对不上；CI 只做 exit-code 烟测 |
| S6 | **跨会话没有被真正验证**：phase C"新 session"只换了 `run_id`，`session_id` 仍是 `sim-session-01` | `sim/scenario.py:97-101,250-255` | G2"新会话首次调用就有记忆"没有真正测到 |
| S7 | **关键行为测试缺位**：budget 耗尽后的恢复、stale 退休、run 预算 component 上限、并发/崩溃、报告 `--since`、Basic auth/fragment 脱敏等路径无测试；`sim/concurrency.py` 不在验证矩阵里 | `tests/` 90 个测试的分布；`scripts/verify_runtime_memory.py:35-44` | 上面这些问题改起来没有安全网 |

---

## 4. 从何下手：三档路线（按"先修可信度，再修行为，最后做规模化"排序）

> 原则：**先让记忆说的每句话是真的、可度量的（D），再让它别害人（B），最后才让它跑得快、接得进（G），内容层增强（C）放在有真实数据之后。**
> 每一项都给了验收标准，便于直接当任务单执行。

### 4.1 D 组：先做（半天，零风险）——让内容自洽、可度量

| # | 改动 | 位置 | 验收 |
|---|---|---|---|
| D1 | 修 `_decision_record` 的重复 `action`：改成 `requested_action`（工具动作）+ `decision`（决策结果），删除派生字段或明确标注 derived | `src/runtime_memory/runtime.py:268-300`；`report.py:46-51` 同步 | `grep '"action":"block","decision":"block"'` 不再出现在新产物；`check()` 增加重复 key/枚举校验 |
| D2 | 打通 decision 身份链：`preflight` 文本输出打印 `decision_id`；`record` 增加 `--decision-id`（以及 `--retry-after-s`/`--evidence-ref`）；`report` 输出 `shadow.false_block_rate`（分母 0 时输出 `null` 而不是 0.0） | `cli.py:48-68,127-146,239-250`；`report.py:102-116` | 用 CLI 走一遍 shadow：preflight(block)→record(ok)→report 能看到 `false_blocks=1, false_block_rate=1.0`（该次） |
| D3 | 清 issue 自相矛盾：resolve 时清空 `next_retry_at`；`probe_started_at` 只在 `probing` 状态有值；`workaround_by/at` 进 dataclass（或删除）；`source_event_ids` 截断时记 `dropped_event_count`；`retry_policy.next_retry_at` 与顶层只留一处 | `runtime.py:456-483,509-521`；`models.py:79-121`；`store.py` | 新增单测覆盖；`issues.json` 中不再出现 `resolved` + 未来/过期 `next_retry_at` 组合 |
| D4 | 修指标口径：`false_block_rate` 输出 N/A 语义；`mean_blocked` 改名 `mean_blocked_preflights`（或同时输出 distinct 调用数）；TTS 同时输出 `n_success/total`；把 workload 的注意事项写进 `metrics.json` 而不是只在 summary.md | `report.py`；`sim/workload.py:139-237` | 重跑 workload，表格不再出现"enforce 行 false_block_rate=0.0"这种假零 |
| D5 | 用 HEAD 重新生成 `sim-2026-11-02-agent-final`，`check` 增加结构/不变量校验（event↔issue 反向引用、`expires_at >= next_retry_at`、decision 有 issue 或 budget 引用）；`verify_runtime_memory.py` 增加产物 schema 校验 | `scripts/verify_runtime_memory.py`；`store.check()` | 产物与代码一致；`EDGE_CASES.md`/README 测试数同步为 90；CI 里能重放 |

**验收总纲**：`python -m unittest discover -s tests` 全绿（新增 ≥5 个测试）；重跑 scenario/workload；README/AGENT_NOTES 不再需要解释"这个字段为什么矛盾"。

### 4.2 B 组：本周（2–3 天）——把"记忆害人"的行为改掉

| # | 改动 | 要点 | 验收 |
|---|---|---|---|
| B1 | **预算耗尽改为慢探测**（修 L1/L2） | retryable class 在 attempts 用尽后不要 `block` 到 `expires_at`；改为按 `slow_probe_s`（如 `max_s`）周期允许一次 probe，或用新证据/人工唤醒；TTL 与 `max_attempts` 一起定，不能分开调 | 新增单测：3 次失败 + 预算耗尽 + 目标恢复 → 能在 max_s 量级内 probe 成功；workload 增加 `enforce_adaptive` 配置，成功率 ≥ baseline 且 calls 显著下降 |
| B2 | **stale 退休 + gc 扩展**（修 L3） | policy 增加 `max_stale_age_s`：stale 超期自动 `resolved(ignored)`；`gc` 覆盖 stale/open 长期未确认、decisions/overrides 保留期；`check` 报告 dangling | 单测：stale 超期后 allow；gc dry-run/apply 只删 eligible；issues.json 不再无限增长 |
| B3 | **证据独立性**（修 T1） | issue 记录 `distinct_runs`/`distinct_sessions`；`open`（硬拦级别）要求 ≥2 个独立 run；同一 run 内最多 `cooldown`；`confidence` 改成按独立证据计算，或改名 `evidence_strength` 并停止打印给 agent | 单测：同 run 重试 3 次仍 cooldown/block 但不升级为高置信硬拦；跨 run 第 2 次失败才 open |
| B4 | **per-component enforce**（修 S3） | `policy.enforce` 支持 bool 或 `{component: bool}`；`Decision.shadow` 按组件计算 | 单测：mcp enforce + siem shadow 同时生效 |
| B5 | （可选，二选一）§9.5 拦截强度矩阵 | `cooldown` 用短 TTL、`open + count>=2 + 高证据` 才 hard block、低证据用 hint/probe | 若时间不够，先只做 `block/probe/hint` 三档，别做全套 |

**验收总纲**：`enforce_60` 不再是 0% 成功率；预算耗尽/陈旧 issue 都有退出路径；`enforce_adaptive` 的调用数明显低于 baseline 失败数；新增测试覆盖上述 4 类行为。

### 4.3 G 组：下周（3–5 天）——让记忆第一次真正"拦"

| # | 改动 | 要点 | 验收 |
|---|---|---|---|
| G1 | **per-run budget ledger**（修 S1） | `postflight` 时更新 `data/run_budgets.json`（run_id→call key/component 计数）；`preflight` O(1) 读取；只读 preflight 不拿写锁；issue 按 fingerprint 建内存索引/缓存 | 20k 事件下 preflight p95 < 5ms；多进程并发压测无锁等待 |
| G2 | **接真实工具边界** | harness 的 before/after hook（设计 §12.2 方式 C）或 gateway 包装：preflight→block 时不调用、enforce 时执行；after 在 finally 里 postflight；Decision 作为工具结果返回 | shadow 跑一周：`false_blocks`/`would_block`/`duplicate_attempts` 有真实数据；每周报告可解释每次 block |
| G3 | **审计与权限**（修 T2/T3/T5） | operator 能力（token/进程边界）才能 override/resolve/record-success；resolve/ignore/workaround 写 append-only 审计；禁止 `record=False + override`；成功 event 带 decision_id/nonce | 越权测试全部被拒；每次 block 都能追溯到 issue_id + policy_version + source events |

**验收总纲**：真实环境 shadow 一周，报告里有可回算的 false-block 与节省的失败调用数；enforce 只在单组件打开，误拦率不超过校准值。

### 4.4 C 组：之后（约 1 周）——让记忆可读、可复用

| # | 改动 | 价值 |
|---|---|---|
| C1 | **`brief` 记忆摘要渲染器**：按 component 分组输出"现在什么坏了 / 何时可再试 / 替代路径 / 证据数"，≤10 行；`SKILL.md` 改用 brief 而不是裸 JSON | 这是真正进入模型上下文的"工作记忆卡片"，直接解决"宽记录不可读" |
| C2 | **issue 时间线**：events+decisions+overrides 按时间合并成一条 issue 的故事（首次/复发/探测/解决/人审） | 运维审阅、复盘、审计三合一 |
| C3 | **playbook 蒸馏闭环**：`report --propose-playbook` 跨 run 聚合同 fingerprint 的复现问题，生成候选条目（症状/环境/处理/失效条件/依据 issue），人审 accept 后才写入；复用 demo 的 propose/accept 门禁模式 | 设计里的 L1 环第一次有机制；避免"单次失败自动生成"的反模式 |
| C4 | **incident/rollup 层**：component+error_class+时间窗聚合成 incident 摘要；gc 删原始事件后保留 rollup；`related_incident_id` 有写入口 | 解决"删事件就失忆"和"operator 只看到孤立的 issue" |
| C5 | **评测补齐**：T3 策略网格、T4 多工具+替代路径、T9 agent 合规性（obedient vs naive）、T10 消融；用 ≥100 seeds 重跑 | 让"记忆有用"从演示变成可复现实验；T9 是当前 G1 论证最缺的一环 |

### 4.4b 补充：报表与文档

- 统一指标字典（一个 `METRICS.md` 或 report 顶部说明）：每个指标的定义、分母、已知偏差（false_block 只在 shadow 可测、blocked 是决策数不是调用数、`duplicate_attempts` 是全局计数）。
- 设计文档 §5/§7/§9/§15 与实现的差异清单（见附录 B）要么实现、要么明确降级为"未来工作"，不要让文档继续承诺不存在的能力。

### 4.5 如果只能做三件事

1. **D1 + D2（半天）**：修 decision 记录的身份和链路。理由：后面所有指标、调参、enforce go/no-go 都建立在"决策能关联到调用结果"上；这是最便宜、收益最大的一步。
2. **B1 + B2（1–2 天）**：预算耗尽慢探测 + stale 退休。理由：这两条是"记忆把短故障变成长故障/永久阻塞"的唯一来源；先保证记忆不害人，再谈拦截强度。B3（证据独立性）建议同批做，成本很低。
3. **G1 + G2（2–3 天）**：per-run ledger + 真实 gateway shadow。理由：设计自己说"最关键的不是存储，是 gate"；没有真实 shadow 数据，后面的策略调参和内容优化都是盲调。

### 4.6 明确不建议现在做（避免过度设计）

- **向量库/图数据库**：当前内容量与结构化 fingerprint 都不需要；设计 §6.4/§22 已给出理由。
- **自动生成 playbook / 模型直接改 issue 状态**：污染风险大于收益；保持人审或 harness 写事实。
- **扩展 error taxonomy 到几十类**：先用现有 10 类跑出真实分布，再看要不要细分。
- **在没有真实网关数据前精调退避参数**：workload 的 uniform outage 分布不代表生产；先接 shadow 拿分布。
- **把 `confidence` 做成"看起来科学"的概率**：没有校准数据前，改名 `evidence_strength` 或直接删掉展示更安全。

---

## 5. 附录 A：关键证据索引

| 问题 | 文件:行 |
|---|---|
| decision `action` 被覆盖 | `runtime_memory/src/runtime_memory/runtime.py:276,287`；产物 `sim/runs/sim-2026-11-02-agent-final/data/decisions.jsonl:1` |
| decision↔event 关联只靠 decision_id；CLI 无此参数 | `report.py:41-68`；`cli.py:127-146,239-250` |
| 预算耗尽硬封 | `runtime.py:100-114`；`policy.py:24-28`；workload `metrics.json:30-41` |
| stale 不退休 / gc 只删 resolved | `models.py:12`；`runtime.py:93-99`；`store.py:413-443` |
| 同 run 重试即 open / confidence 公式 | `runtime.py:438-447` |
| 越权路径（record/resolve/override） | `runtime.py:355-370,486-507,217-241`；`cli.py:148-158,231-233` |
| `record=False` 跳过 override 审计 | `runtime.py:223` |
| 脱敏缺口 | `redact.py:13-34,55-71` |
| preflight 热路径 | `runtime.py:161-197`；`store.py:186-197`；`sim/runs/scale-2026-11-03/summary.md` |
| 部分写/无 rebuild/check 盲区 | `runtime.py:368-383`；`store.py:350-392`；设计 §11.6 |
| 产物与 HEAD 不一致 | `sim/runs/sim-2026-11-02-agent-final/data/policy.json:6-16` vs `policy.py:13-75`；`EDGE_CASES.md:5` vs `README_CN.md:319` |
| phase C 未换 session_id | `sim/scenario.py:97-101,250-255` |
| 设计承诺清单（未实现） | 见附录 B |

## 6. 附录 B：设计承诺与实现差距速查（可当 design 文档 TODO）

| 设计承诺 | 实现现状 |
|---|---|
| §5.1 event `args_fingerprint` 字段 | 未实现（只进 fingerprint 字符串） |
| §5.3 Decision `max_attempts` | 未实现（只有 attempts_left） |
| §7.1 `probing` 时 preflight=allow | 实现为 block（"probe already in flight"，且有测试）——文档语义需改 |
| §7.2 其它环境成功 → mitigated | 未实现 |
| §8.3 成功采样 1/100、解决必记 | 未实现（每次成功都写 event） |
| §9.5 拦截强度矩阵 | 未实现（所有 block 同一强度） |
| §10.2 指数退避 ±20% jitter、自动解析 Retry-After | 未实现（Retry-After 只能调用方传入） |
| §11.1 `schema.md` | 仓库中不存在 |
| §11.6 `rebuild_issues` / §12.3 `rebuild-issues` CLI | 未实现 |
| §12.4 MCP 工具 `query`/`note` | 未实现 |
| §12.5 harness hook 契约 | 仓库内无适配器（设计自述"未接 harness"） |
| §15.1 false_block_rate / time_to_workaround / tokens_saved / override_rate | 未实现或不可计算 |
| §16.3 不变量 1–6 | 部分被违反（预算 block 无 issue；decision 无 source events；resolve 非 append-only） |
| §18 Q1–Q10 | 未见决策记录；Q3（per-component enforce）、Q5（采样）、Q7（软引用）、Q10（resolve 权限）与实现不符 |
| §19 Phase 2 单组件 enforce | 不可执行（全局 enforce） |

---

## 7. 评审方法与未验证项（诚实声明）

- 本评审为**静态只读**：3 路独立评审分别负责设计-实现差距、代码正确性/性能/安全、记忆内容/数据质量；所有结论均有 `file:line` 或产物证据，未修改任何文件。
- **未重跑测试/仿真**：本机 DSH 沙箱在该 workspace 执行 shell 时报 Windows ACL 错误（`SetNamedSecurityInfoW ... grantWrite(F:\AI_Learning\AgentMemory)`），`pwsh`/`terminal` 不可用。因此"90 tests OK / verify PASS / check clean"沿用仓库记录，并用 `grep` 静态核对到 90 个 `def test_`；建议在可写环境按 §4.1 D5 重跑一次验收。
- 引用行号对应 **2026-11-09** 的工作区 HEAD；如代码已变化以实际为准。

# 运行记忆（Runtime Memory）设计文档

> **状态**：Draft，供实现方案讨论  
> **日期**：2026-11-02  
> **范围**：攻击检测 harness 层的“工具/环境/操作问题”记忆；不修改 `demo/` 的案例记忆  
> **相关文档**：[demo 中文说明](../demo/README_CN.md) · [记忆与 Skill 自我迭代调研](agent-memory-skill-self-iteration-survey-2026-10.md) · [demo 项目介绍](DEMO_OVERVIEW.md) · [demo 优化建议](DEMO_IMPROVEMENT_BACKLOG.md)  
> **一句话**：记录“这个环境/工具最近出了什么问题、下次何时能再试、有没有替代路径”，并在工具调用前**真正拦住**重复的无用尝试；它和案例记忆分开存储、分开生命周期、分开审计。

**阅读导航**：方案对比看 §3；推荐架构看 §4；数据/接口/存储看 §5–§12；风险看 §14；指标与测试看 §15–§16；需要决策的问题看 §18；排期看 §19。

---

## 0. 摘要：需要先定的 6 件事

1. **它不是案例记忆。** 案例记忆回答“攻击长什么样”；运行记忆回答“这个工具/端点/环境为什么失败、何时重试、怎么绕开”。不要写进 `demo/data`。
2. **它不是 `ops_journal`。** [demo 的 `ops_journal.jsonl`](../demo/src/attack_memory/storage.py#L352) 是写事务的两阶段 WAL（`txn_id/status/files/sha256`），记录“文件写没写成功”，不是“工具为什么失败”。
3. **它不是 `corrections`。** [corrections.json](../demo/src/attack_memory/corrections.py) 是案例负记忆（“这个 incident 为什么不是这个 case”），不是运行错误。
4. **它需要三层，而不是一张表**：操作轨迹（trace）→ 问题记忆（issue）→ 经验/playbook。你举的“半小时后重试”属于 issue 的 `next_retry_at`。
5. **真正防重复尝试的是 preflight gate，不是存储本身。** 只存不拦，模型会继续试；只拦不存，跨会话又会重犯。
6. **建议先做 shadow 模式**：记录 + 计算“本该拦哪些”，但不真正拦截；用历史/在线数据测误拦率，再对单个组件开启强制拦截。

**建议方案**：§3 的方案 B（trace + issue + preflight）+ §19 的 Phase 0/1/2。

---

## 1. 问题、目标与非目标

### 1.1 问题

攻击检测 harness 里有大量会失败的操作：

- MCP / hunt 端点不可达、超时、限流；
- SIEM 查询超时、返回 schema 变化；
- shell 命令因权限、路径、编码失败；
- 日志解析器遇到截断、缺字段、坏 pcap/evtx；
- 模型 API 超时、上下文超限、工具参数格式错误；
- 沙箱/文件系统权限拒绝。

当前的问题是：

1. **失败经验不持久**：下一次会话/下一个 Agent 从零开始，重复踩同一个坑。
2. **失败经验不共享**：一个组件知道端点坏了，另一个组件还在重试。
3. **模型没有“停手”机制**：它可能连续尝试同一工具，消耗 token/时间，甚至把一次参数错误误判成“工具不可用”。
4. **失败原因不可归类**：工具坏了、参数错了、数据坏了、模型用错了，四类问题混在一起，导致错误的修复动作。
5. **缺少“何时再试”的策略**：要么立刻重试（可能仍然失败），要么永久放弃（可能环境已恢复）。

### 1.2 目标

| ID | 目标 | 可验证标准 |
|---|---|---|
| G1 | 减少同一 fingerprint 的重复失败尝试 | 同一 run 内重复失败次数下降 ≥30%（相对 shadow 基线） |
| G2 | 跨会话复用“环境问题” | 新会话首次调用就能拿到已知 issue/替代路径 |
| G3 | 可解释、可审计 | 每次 block 都能追溯到 issue + source events + policy |
| G4 | 不污染案例记忆 | `demo/data` 哈希不变；`catalog state`/`audit` 不受影响 |
| G5 | 安全 | 错误消息脱敏；模型不能单方面把工具标成“永久坏”；issue 可过期/可探测 |
| G6 | 可度量 | 有 duplicate attempts / blocked / false-block / time-to-workaround 指标 |

### 1.3 非目标

- 不做通用聊天日志/全量会话转录；
- 不做语义记忆/向量检索（第一版）；
- 不自动生成 skill/playbook（第一版只做人审后的 playbook）；
- 不替代 demo 的案例记忆、负记忆、证据链；
- 不让模型直接写 issue 状态（模型只能注解）；
- 不做跨组织的全局共享记忆。

---

## 2. 定位：它在记忆体系里的位置

### 2.1 四类记忆

| 记忆 | 回答的问题 | 载体 | 写入方式 | 生命周期 | 读取时机 |
|---|---|---|---|---|---|
| 案例记忆（demo） | 攻击长什么样、可复用吗 | `attack_patterns` / `families` | 人审 + 门禁 | 长 | 分析时检索 |
| 证据记忆（demo） | 这次发生了什么 | `raw_logs` / `links` / `chains` | 复核 | 中 | 复盘/召回 |
| **运行记忆（新）** | 工具/环境出了什么问题、何时再试 | `runtime_memory/` | **harness 自动** | 短 | **调用前 preflight** |
| 技能/playbook（新，可选） | 这类问题以后怎么做 | `playbook.md` / skill | 人审 | 长 | 任务前/培训 |

### 2.2 与调研里的“四个时钟”对齐

[记忆与 Skill 自我迭代调研](agent-memory-skill-self-iteration-survey-2026-10.md) 把更新时机分成 L0–L3：

- **L0 任务内**：单步失败、工具报错 → 适合“小步记忆 + 重试 + 局部纠错”，风险是“污染上下文、错误累积”。运行记忆的主战场在这里。
- **L1 任务后**：完整轨迹 + 成败 → 适合把重复问题蒸馏成 issue/workaround/playbook。
- **L2 空闲/周期**：去重、衰减、归档、报表。
- **L3 跨代/元**：改 harness/架构；不是本文范围。

运行记忆的设计原则是：**L0 自动捕获，L1 人审蒸馏，L2 定期收敛；不要让 L0 直接改 L3。**

### 2.3 与现有 demo 账本的边界

| 现有物 | 它是什么 | 为什么不是运行记忆 |
|---|---|---|
| `ops_journal.jsonl` | demo 写事务的两阶段 WAL | 记录文件写入事务，不记录工具失败 |
| `corrections.json` | 案例负记忆 | 记录“这个 incident 不是这个 case” |
| `link_exceptions.json` | 审计例外 | 记录 regex 不匹配的已复核链接 |
| `repair_log.json` | 派生状态修复 | 运维修复记录 |
| `pattern_versions/` | 案例版本快照 | 案例历史，不涉及工具/环境 |
| **`runtime_memory/`** | **工具/环境问题记忆** | **新的、独立的生命周期与读取路径** |

**硬边界**：

- 运行记忆不 import `demo/src/attack_memory`；
- 不写入 `demo/data`；
- 不参与 `catalog validate` / `audit` / `state` / `retention` / `freeze`；
- 如需关联，只存 `related_incident_id` / `related_case_id` 这种**软引用**，不做外键。

---

## 3. 设计选项

### 选项 A：只记录操作轨迹（trace-only）

- 每次工具调用写一行 JSONL；失败/成功都记。
- 提供查询/报表，但不拦截。
- **优点**：最简单，1 天可出原型；可复盘、可统计。
- **缺点**：**不能防止重复尝试**；模型不读就不会变；容易变成“没人看的日志”。
- **适用**：先验证“问题是否高频”，或作为 B 的第一步。

### 选项 B：trace + issue + preflight（推荐）

- trace 自动记录；
- 同 fingerprint 聚合为 issue；
- 调用前 preflight：block / probe / allow-with-hint；
- 调用后 postflight：更新状态、重试时间、解决/过期。
- **优点**：真正减少无用尝试；跨会话；可解释；实现量可控（3–5 天 MVP）。
- **缺点**：需要接工具边界；需要处理误拦/陈旧记忆；需要状态机与策略。
- **适用**：目标就是“防止模型过多无用尝试”。

### 选项 C：完整运行记忆平台

- B + SQLite/WAL + 多 Agent scope + playbook + 报表 + 自动蒸馏 + 与 skill 系统打通。
- **优点**：可扩展、可共享、可运营。
- **缺点**：成本高；在 B 没验证前容易过度设计；自动蒸馏有污染风险。
- **适用**：B 在 1–2 个组件上证明有效之后。

### 对比

| 能力 | A | B | C |
|---|---|---|---|
| 复盘/统计 | ✅ | ✅ | ✅ |
| 跨会话避免重复 | ❌ | ✅ | ✅ |
| 调用前拦截 | ❌ | ✅ | ✅ |
| 多 Agent 共享 | ❌ | 有限 | ✅ |
| 误拦治理 | — | 需要 | 需要 |
| 实现成本 | 0.5–1 天 | 3–5 天 | 2–3 周 |
| 主要风险 | 没人看 | 误拦/陈旧 | 过度设计 |

**建议：先 B，且先 shadow。** 不要从 C 开始。

---

## 4. 推荐架构：三层 + 两个环

### 4.1 三层

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. 操作轨迹（trace）                                         │
│    events/YYYY-MM.jsonl：一次调用一行，append-only           │
│    用途：复盘、指标、事后蒸馏；不直接进 prompt               │
└─────────────────────────────────────────────────────────────┘
                 │ 聚合（同 fingerprint）
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. 问题记忆（issue）                                         │
│    issues.json：状态、重试策略、next_retry_at、workaround    │
│    用途：preflight 读取；跨会话；短 TTL                      │
└─────────────────────────────────────────────────────────────┘
                 │ 人审/多次验证
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. 经验/playbook（可选）                                     │
│    playbook.md：这一类问题怎么处理；稳定、长期、人审         │
│    用途：培训/提示/未来 skill；不从单次失败自动生成          │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 两个环

**执行环（L0，每次工具调用）**

```text
调用前 preflight
  ├─ block：不调用，返回卡片（until/reason/alternatives）
  ├─ probe：允许一次探测
  └─ allow / allow-with-hint：正常调用

调用后 postflight
  ├─ 成功：resolve / mitigate
  └─ 失败：更新 count / next_retry_at / status
```

**巩固环（L1/L2，任务后/周期）**

```text
events + issues
  → 诊断：工具/环境 vs 模型用法 vs 数据质量 vs 编排
  → 提议：workaround / playbook / harness 修复
  → 人审
  → 写入 playbook 或转给开发
```

### 4.3 组件图

```text
┌──────────────┐     preflight      ┌──────────────────┐
│ Tool Gateway │ ─────────────────► │ Runtime Memory   │
│ (MCP/shell/  │ ◄───────────────── │  issues.json     │
│  file/model) │   Decision         │  policy.json     │
└──────┬───────┘                    └────────┬─────────┘
       │                                     │
       │ 实际调用                             │ postflight
       ▼                                     ▼
┌──────────────┐                    ┌──────────────────┐
│ 外部工具/环境 │                    │ events/*.jsonl   │
└──────────────┘                    └──────────────────┘
```

---

## 5. 数据模型

### 5.1 操作事件（Operation Event）

一行一个事件，append-only。成功可采样，失败全记。

```jsonc
{
  "schema_version": 1,
  "event_id": "OP-20261102T113657-0001",
  "ts": "2026-11-02T11:36:57+08:00",
  "session_id": "S-...",
  "run_id": "R-...",
  "scope": "global | session | agent",
  "environment_id": "lab-a",
  "component": "mcp | shell | file | model | parser | sandbox | web",
  "tool": "hunt.query",
  "action": "search",
  "target": "10.7.194.120:22196",
  "args_fingerprint": "sha256:...",
  "outcome": "ok | fail | timeout | denied",
  "error_class": "unreachable | timeout | auth | rate_limit | schema | not_found | invalid_args | internal | unknown",
  "error_code": "ECONNREFUSED",
  "message_redacted": "connect ECONNREFUSED 10.7.194.120:22196",
  "duration_ms": 30012,
  "attempt": 1,
  "retryable": true,
  "evidence_ref": "logs/run-.../mcp.log#L42",
  "author": "harness",
  "policy_version": "2026-11-02.1"
}
```

字段说明：

| 字段 | 必填 | 说明 |
|---|---|---|
| `event_id` | 是 | 唯一；建议 `OP-<ts>-<seq>` |
| `ts` | 是 | UTC 或带时区 ISO 8601 |
| `session_id` / `run_id` | 建议 | 用于 per-run 预算和复盘 |
| `scope` | 是 | `global`（共享环境）/`session`（本次运行）/`agent`（单 Agent） |
| `environment_id` | 是 | 手工配置的环境标识，防止跨环境误伤 |
| `component` / `tool` / `action` | 是 | 指纹的组成部分 |
| `target` | 是 | 端点/主机/路径前缀；规范化后存储 |
| `args_fingerprint` | 条件 | call 级指纹需要；scope 级可为空 |
| `outcome` | 是 | ok/fail/timeout/denied |
| `error_class` | 失败必填 | 决定重试策略 |
| `error_code` | 可选 | 原始错误码，便于细分类 |
| `message_redacted` | 可选 | 脱敏后的短消息；不存完整堆栈 |
| `duration_ms` / `attempt` | 建议 | 指标与退避 |
| `retryable` | 建议 | 策略计算的结果，不是模型判断 |
| `evidence_ref` | 可选 | 指向原始日志/文件，便于复核 |
| `author` | 是 | `harness` / `model` / `human`；事实默认 harness |

### 5.2 问题记录（Issue）

按 fingerprint 聚合，`issues.json` 整体原子写。

```jsonc
{
  "schema_version": 1,
  "issue_id": "ISS-20261102T113657-0001",
  "fingerprint": "lab-a|scope|mcp|hunt.query|search|10.7.194.120:22196",
  "key_level": "scope",
  "scope": "global",
  "environment_id": "lab-a",
  "component": "mcp",
  "tool": "hunt.query",
  "action": "search",
  "target": "10.7.194.120:22196",
  "error_class": "unreachable",
  "diagnosis": "tool | environment | model_usage | data | orchestration | permission",
  "status": "cooldown | open | probing | mitigated | resolved | stale",
  "first_seen": "2026-11-02T11:36:57+08:00",
  "last_seen": "2026-11-02T11:40:12+08:00",
  "count": 3,
  "attempts": 3,
  "retry_policy": {
    "mode": "exponential",
    "base_s": 900,
    "max_s": 1800,
    "max_attempts": 3,
    "max_attempts_per_run": 1
  },
  "next_retry_at": "2026-11-02T12:10:12+08:00",
  "expires_at": "2026-11-03T11:40:12+08:00",
  "workaround": "该网段不可达；改用本地 pcap 或备用端点",
  "confidence": 0.8,
  "source_event_ids": ["OP-...-0001", "OP-...-0002"],
  "last_probe_event_id": null,
  "related_incident_id": null,
  "related_case_id": null,
  "notes": []
}
```

字段说明：

- `fingerprint`：见 §6；`key_level` 表示 `scope` 还是 `call`。
- `diagnosis`：失败归因层（工具/环境/模型用法/数据/编排/权限）；它决定“怎么修”，不决定“等多久”。
- `status`：状态机见 §7。
- `count`：同 fingerprint 的失败次数（窗口内/全量由策略定义）。
- `attempts`：实际尝试次数（含 probe）。
- `retry_policy`：由 `policy.json` 计算并固化，便于审计。
- `next_retry_at`：在此之前 preflight 应 block；到点后允许 probe。
- `expires_at`：超过此时间未再确认 → `stale`；stale 允许一次 probe，而不是永久 block。**必须不早于 `next_retry_at`**：服务端 `Retry-After` 超过 class TTL 时，TTL 要延长到 retry 窗口之后，否则会在服务端仍要求等待时提前 probe。
- `workaround`：可执行替代方案；没有就留空，不要编。
- `confidence`：0–1；由证据量/复现次数决定，不当作概率展示。
- `source_event_ids`：审计用；不要求全量，保留最近 N 条。
- `related_incident_id` / `related_case_id`：软引用，可为空；不要反向写 demo。
- `notes`：模型/人追加的注解，**不改变 status**。

### 5.3 调用前决策（Decision）

```jsonc
{
  "action": "allow | allow_with_hint | probe | block",
  "issue_id": "ISS-...",
  "fingerprint": "...",
  "blocked_until": "2026-11-02T12:10:12+08:00",
  "reason": "endpoint unreachable (3 attempts)",
  "attempts_left": 0,
  "max_attempts": 3,
  "alternatives": ["use local pcap", "try backup endpoint"],
  "confidence": 0.8,
  "expires_at": "2026-11-03T11:40:12+08:00",
  "policy_version": "2026-11-02.1"
}
```

语义：

- `block`：**不要调用**；把 Decision 作为工具结果返回给模型；
- `probe`：允许**一次**调用，调用后必须更新 issue；
- `allow_with_hint`：允许调用，但附带 workaround/已知问题提示；
- `allow`：正常调用。

### 5.4 策略（Policy）

`policy.json` 按 `error_class` 配置默认行为，可被环境覆盖。

```jsonc
{
  "schema_version": 1,
  "policy_version": "2026-11-02.1",
  "defaults": {
    "cooldown_s": 300,
    "issue_ttl_s": 86400,
    "max_attempts_per_run": 3,
    "probe_after_expiry": true
  },
  "budgets": {
    "max_attempts_per_call_key_per_run": 3,
    "max_failures_per_component_per_run": 10,
    "max_blocked_calls_per_run": 50
  },
  "classes": {
    "unreachable": {
      "key_level": "scope",
      "retryable": true,
      "mode": "fixed",
      "base_s": 900,
      "max_s": 1800,
      "max_attempts": 3,
      "max_attempts_per_run": 1,
      "ttl_s": 86400
    },
    "timeout": {
      "key_level": "call",
      "retryable": true,
      "mode": "exponential",
      "base_s": 30,
      "max_s": 300,
      "max_attempts": 3,
      "max_attempts_per_run": 3,
      "ttl_s": 3600
    },
    "auth": {
      "key_level": "scope",
      "retryable": false,
      "mode": "none",
      "max_attempts": 0,
      "ttl_s": 86400
    },
    "schema": {
      "key_level": "call",
      "retryable": false,
      "mode": "none",
      "max_attempts": 0,
      "ttl_s": 86400
    }
  }
}
```

### 5.5 Playbook（可选）

`playbook.md` 是人审后的“这类问题怎么处理”，不是自动生成：

```markdown
## MCP hunt 端点不可达

- 症状：`hunt.query` 返回 ECONNREFUSED / 超时；目标 10.7.194.120:22196。
- 适用环境：lab-a 内网。
- 处理：优先使用本地 pcap；30 分钟后再探测一次；不要连续重试。
- 依据：ISS-...（3 次失败），2026-11-02 复核。
- 失效条件：网络策略变更 / 端点迁移。
```

---

## 6. 指纹（Fingerprint）规范

### 6.1 两级指纹

同一类错误可能有两种粒度：

| 级别 | 适用 | 组成 | 例子 |
|---|---|---|---|
| **scope 级** | 传输/认证/服务级问题 | `environment|scope|component|tool|action|target` | 端点不可达、认证失败、限流 |
| **call 级** | 参数/数据级问题 | `environment|call|component|tool|action|target|args:<hash>` | 某条查询 schema 错误、某路径 not_found |

**为什么 error_class 不进入 fingerprint**：preflight 在调用前并不知道下一次会报什么错。如果 key 里带 `error_class`，调用前就查不到 issue。因此 `error_class` 是 issue 的属性，不是 key 的一部分；同一个 operation key 下可以并存多个不同 `error_class` 的 issue。

**为什么需要两级**：

- 端点不可达时，所有查询都失败，应该共享一个 issue，而不是每个 query 一个；
- 某条查询参数错误时，不应该把整个工具/端点标成坏，只拦这条调用；
- preflight 同时查 scope key 和 call key，取其中最严格的动作（block > probe > hint > allow）。

建议默认：

| error_class | key_level |
|---|---|
| `unreachable` / `auth` / `rate_limit` | scope |
| `timeout` | call（如果是大查询）或 scope（如果是端点） |
| `schema` / `not_found` / `invalid_args` | call |
| `internal` / `unknown` | scope |

### 6.2 规范化规则

- `environment_id`：手工配置（如 `lab-a`），不要用 hostname 自动猜；
- `component` / `tool` / `action`：小写、去空格；
- `target`：
  - URL → 保留 `scheme://host:port` + 第一段路径（如 `http://10.7.194.120:22196/hunt`），去掉 query/fragment；
  - 文件 → 保留目录前缀（如 `C:/data/pcap`），不保留文件名；
  - shell → 主机名/目标串；命令类别由 `action` 表达，不把完整命令塞进 target；
- `args_fingerprint`：
  - 只对 call 级用；
  - 规范化 JSON（排序 key、去空白、去时间戳/随机数）；
  - 对敏感字段先脱敏再 hash；
  - 不存原参数，只存 hash + 可选摘要。

### 6.3 示例

```text
scope: lab-a|scope|mcp|hunt.query|search|10.7.194.120:22196
call:  lab-a|call|mcp|hunt.query|search|10.7.194.120:22196|args:ab12...
```

同一个 scope key 下可以同时有：

```text
ISS-A  fingerprint=<scope>  error_class=unreachable
ISS-B  fingerprint=<scope>  error_class=auth
```

preflight 会查到两条，按“block > probe > hint > allow”取最严格的一条。

### 6.4 为什么不用自由文本/向量

- 这里的键是结构化的；用 embedding 会把“同一个端点”拆成多个相似 issue；
- 指纹可解释、可去重、可精确匹配；
- 语义相似检索可以作为**第二级**（“相似错误消息”），但不能做第一层。

---

## 7. Issue 状态机

### 7.1 状态

| 状态 | 含义 | preflight 行为 |
|---|---|---|
| `cooldown` | 单次失败，短期冷却 | block 到 `next_retry_at` |
| `open` | 重复失败/确认问题 | block 到 `next_retry_at`，或给替代路径 |
| `probing` | 已放行一次探测 | 本次 allow；探测后更新 |
| `mitigated` | 有 workaround | allow_with_hint |
| `resolved` | 已成功/已修复 | allow |
| `stale` | 过期未确认 | 允许一次 probe |

### 7.2 转移

```text
(no issue)
   │ fail
   ▼
cooldown ──same fail──► open
   │                      │
   │ success              │ next_retry_at reached
   ▼                      ▼
resolved                probing
                           │
                 success ──┼── fail
                           ▼      ▼
                       resolved   open（重新计算退避）
open/cooldown ──expires_at──► stale
stale ──probe success──► resolved
stale ──probe fail─────► open
open ──other environment success──► mitigated
任何状态 ──人工──► resolved / ignored（记 audit）
```

### 7.3 规则

1. **第一次失败默认只建 `cooldown`，不建全局 `open`**：避免一次偶然故障把工具封死。**例外**：`auth` / `permission` / `schema` / `invalid_args` 这类“重试无用”的 class 第一次就建 `open`（`retryable=false`），因为等待不会让问题消失。
2. **同一 fingerprint + `error_class` 的第二次失败升级 `open`**：与 demo 的“单样本 vs 重复证据”同构。
3. **`next_retry_at` 只在真实尝试后设置**：不要根据传闻/模型自述设置。
4. **过期必须允许 probe**：`stale` 不是永久封禁；一次探测成功即 `resolved`。
5. **成功可以来自另一个 scope/environment**：标记 `mitigated`，不要全局 `resolved`，除非同环境成功。
6. **人工可以强制 resolve/ignore**：必须写 basis，进 audit。
7. **`probing` 必须可恢复**：记录 `probe_started_at`；进程崩溃/超时后，启动时把超过 `probe_timeout_s` 的 `probing` 回退为 `open` 或 `stale`。**`probe_started_at` 缺失也视为 abandoned probe**，同样回退，避免脏数据永久卡在探测中。

---

## 8. 写入路径

### 8.1 谁写

| 写入者 | 能写什么 | 不能写什么 |
|---|---|---|
| **harness / tool gateway** | event、issue 状态、next_retry_at、resolve | — |
| **模型** | `notes`（注解）、`related_*` 软引用 | 不能写 status、不能把工具标成永久坏 |
| **人工** | resolve/ignore、workaround、playbook、policy 覆盖 | 不能删除 event 历史 |

### 8.2 捕获点

在工具边界统一包装，而不是每个调用点手写：

```python
@runtime.guard(component="mcp", tool="hunt.query", action="search")
def hunt_query(target, query):
    ...
```

或显式 gateway：

```python
def call_tool(req: OperationRequest, fn):
    decision = runtime.preflight(req)
    if decision.action == "block":
        return BlockedResult(decision)
    try:
        result = fn()
    except Exception as exc:
        runtime.postflight(req, error=exc)
        raise
    runtime.postflight(req, ok=True)
    return result
```

### 8.3 记录策略

- **失败全记**：fail/timeout/denied；
- **成功采样**：默认 1/100 或只在“解决 open issue”时记；
- **不记全量堆栈**：只存 `error_class` + 短消息 + `evidence_ref`；
- **脱敏**：token、cookie、password、Authorization、内网凭据；
- **去重**：同 fingerprint 在窗口内只更新 `last_seen/count`；
- **预算**：每个 run 每个 call key 最多 3 次；每个 component 最多 10 次失败；超过返回 `block`，`reason=budget_exhausted`（预算不是 issue 状态，是决策原因）。

### 8.4 失败分类

写 issue 前先判断“是哪一层的问题”：

| 分类 | 例子 | 修复动作 |
|---|---|---|
| 工具/环境 | 端点不可达、限流、服务 5xx | 退避/换端点/等 |
| 模型用法 | 参数格式错、选了不存在的工具 | 改 prompt/参数，**不要**标工具坏 |
| 数据质量 | pcap 截断、evtx 坏、字段缺失 | 修数据/解析器，**不要**重试 |
| 编排 | 顺序错、依赖未就绪 | 改流程，**不要**重试 |
| 权限 | 403/401 | 提权/换凭据，**不要**重试 |

**诊断错层会导致错误的更新对象**（调研 §7.2 的原话）。所以 event 里保留 `component` 与 `error_class`，issue 里保留 `diagnosis` 字段（可选）。

### 8.5 从异常到 error_class 的映射

分类应基于**异常类型 + HTTP 状态 + 上下文**，不要只凭错误消息关键词：

| 异常/状态 | error_class | 备注 |
|---|---|---|
| `ConnectionRefusedError` / DNS 解析失败 / `OSError(errno=101/111)` | `unreachable` | 端点/网络问题 |
| `TimeoutError` / `asyncio.TimeoutError` / 读取超时 | `timeout` | 是否可重试取决于查询规模 |
| HTTP 401/403 / `PermissionError` | `auth` / `permission` | 不重试 |
| HTTP 429 / `Retry-After` | `rate_limit` | 服从服务端 |
| HTTP 404 / `FileNotFoundError` | `not_found` | 先核对 ID/路径 |
| `JSONDecodeError` / schema 校验失败 | `schema` | 修 parser/schema |
| 参数校验 `TypeError`/`ValueError`（来自工具入参） | `invalid_args` | 模型用法问题 |
| 沙箱拒绝 / `PermissionError`（文件/网络） | `permission` | 改权限，不重试 |
| 其他未分类 | `internal` / `unknown` | 记 issue，默认只 probe 一次 |

实现上建议：

```python
def classify(exc: BaseException, context: dict) -> str:
    if isinstance(exc, (ConnectionRefusedError, socket.gaierror)):
        return "unreachable"
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return "timeout"
    status = getattr(exc, "status", None) or context.get("http_status")
    if status in (401, 403):
        return "auth"
    if status == 429:
        return "rate_limit"
    if status == 404:
        return "not_found"
    if isinstance(exc, (json.JSONDecodeError, SchemaError)):
        return "schema"
    if isinstance(exc, (TypeError, ValueError)) and context.get("source") == "args":
        return "invalid_args"
    return "unknown"
```

**不要把 `invalid_args` 记成 `unreachable`**：否则整个工具/端点会被错误封禁。

---

## 9. 读取路径与拦截

### 9.1 Preflight 算法

```python
def preflight(req: OperationRequest) -> Decision:
    now = utcnow()
    scope_key = scope_fingerprint(req)
    call_key = call_fingerprint(req)
    issues = store.find_issues([scope_key, call_key], statuses=ACTIVE_STATUSES)
    if not issues:
        return Decision.allow()

    ranked = []
    for issue in issues:
        if issue.status == "mitigated":
            ranked.append((1, issue, "workaround available"))
        elif issue.status == "stale":
            ranked.append((2, issue, "stale; one probe allowed"))
        elif not issue.retry_policy.retryable:
            ranked.append((3, issue, "non-retryable"))
        elif issue.attempts >= issue.retry_policy.max_attempts:
            ranked.append((3, issue, "attempt budget exhausted"))
        elif issue.next_retry_at is None or now >= issue.next_retry_at:
            ranked.append((2, issue, "retry window open"))
        else:
            ranked.append((3, issue, "blocked until retry window"))

    rank, issue, reason = max(ranked, key=lambda item: (item[0], item[1].confidence))
    action = {1: "allow_with_hint", 2: "probe", 3: "block"}[rank]
    return Decision(action=action, issue=issue, reason=reason)
```

### 9.2 返回给模型

- `block`：**不调用工具**，把 Decision 作为工具结果返回；
- `probe`：允许调用，但本次结果必须回写；
- `allow_with_hint`：正常调用，附带 workaround；
- 卡片只包含必要字段，避免上下文污染：

```text
[BLOCKED] hunt.query @ 10.7.194.120:22196
reason: endpoint unreachable (3 attempts)
retry after: 2026-11-02 12:10 (+08:00)
alternatives: use local pcap; try backup endpoint
issue: ISS-...
```

### 9.3 模型 override

- 模型可以请求 `probe=true` + `basis`；
- gate 只在以下情况允许：
  - `now >= next_retry_at`，或
  - `issue.status == stale`，或
  - 人工/策略显式允许；
- 每次 override 记录 `override_by` / `override_basis` / 结果；
- **不能静默绕过**；如果模型直接调用底层工具，网关仍然拦截。

### 9.4 Shadow 模式

`enforce=false` 时：

- preflight 仍计算 `block/probe`；
- 网关**照常调用**；
- 记录 `shadow_would_block=true` 与实际结果；
- 报表对比“如果拦截，会避免多少次失败/误拦多少次成功”。

这是上线前的关键一步。

### 9.5 拦截强度矩阵

不是所有 issue 都该硬拦。建议按“证据强度 + 错误类型”分级：

| 条件 | 建议动作 | 理由 |
|---|---|---|
| `cooldown`（单次失败） | block，短 TTL（5–15 分钟） | 给瞬时故障让路，但不过度升级 |
| `open` + `count >= 2` + `confidence >= 0.7` | **hard block** | 重复证据，值得拦 |
| `open` + `confidence < 0.7` | `allow_with_hint` 或 block + 允许 override | 证据不足，避免误拦 |
| `auth` / `schema` / `permission` | block 到人工处理 | 重试无用，越早停越好 |
| `rate_limit` / `timeout` | block 到 `next_retry_at`，到点 probe | 时间敏感 |
| `stale` | 允许一次 probe | 环境可能已恢复 |
| `mitigated` | `allow_with_hint` | 有替代路径，不阻塞 |
| `resolved` | allow | 已验证恢复 |

**原则**：硬拦只用于“重复 + 高置信 + 重试无用”的组合；其余用提示/probe，避免误拦。

---

## 10. 重试策略

### 10.1 默认矩阵

| error_class | key_level | 重试 | 退避 | 最大次数 | TTL | 备注 |
|---|---|---|---|---|---|---|
| `unreachable` | scope | 是 | 900s 固定 | 3 / 每 run 1 | 24h | 先检查端点/网络 |
| `timeout` | call/scope | 是 | 30s 指数到 300s | 3 | 1h | 大查询可换分页 |
| `rate_limit` | scope | 是 | `Retry-After` 或 60s | 3 | 1h | 尊重服务端 |
| `auth` / `permission` | scope | 否 | — | 0 | 24h | 提权/换凭据 |
| `schema` / `parse` | call | 否 | — | 0 | 24h | 修 parser/schema |
| `not_found` | call | 否 | — | 0 | 1h | 核对 ID/路径 |
| `invalid_args` | call | 否 | — | 0 | 1h | 模型用法问题 |
| `internal` / `unknown` | scope | 谨慎 | 60s 固定 | 1 | 1h | 记 issue，转人工 |

### 10.2 退避

- `fixed` / `exponential` / `none`；
- exponential 加 jitter（±20%），避免多 Agent 同时重试；
- `Retry-After` 优先于本地策略；
- 一个 issue 的 `max_attempts` 用完后，即使 `next_retry_at` 过期也 block，直到人工/新证据。

### 10.3 “半小时后重试”怎么表达

不要写死 30 分钟：

```jsonc
"retry_policy": {"mode": "fixed", "base_s": 1800, "max_attempts": 3}
"next_retry_at": "2026-11-02T12:06:57+08:00"
```

- 由 `error_class` 决定 base；
- 由 `attempt` 决定是否指数；
- 由 `expires_at` 决定何时变 `stale`；
- 由 `max_attempts` 决定何时彻底停。

---

## 11. 存储与目录

### 11.1 目录布局（推荐）

```text
runtime_memory/                     # 与 demo/ 平级；harness 层
├── README.md
├── schema.md
├── policy.json                     # error_class -> retry policy
├── events/
│   └── 2026-11.jsonl               # append-only，按月
├── issues.json                     # 聚合问题，原子写
├── playbook.md                     # 可选，人审
├── overrides.jsonl                 # 人工/模型 override 记录（append-only）
└── tests/
```

如果 harness 在另一个仓库，就把这个目录放在 harness 侧；本仓库只保留 schema/设计/最小实现。

### 11.2 存储选型

| 方案 | 适用 | 优点 | 缺点 |
|---|---|---|---|
| JSONL + `issues.json` | 单写者、MVP | 零依赖、可读、可 diff、可重建 | 无索引、并发弱 |
| SQLite WAL | 多 Agent/并发 | 索引、事务、查询 | 多一个文件/迁移 |
| 混合 | 大规模 | JSONL 原始 + SQLite 物化 | 复杂度高 |

**建议**：MVP 用 JSONL；当出现“多 Agent 同时写”或“issues > 1k / 查询变慢”时再上 SQLite。**不要先上向量库。**

### 11.3 保留与清理

| 数据 | 保留 | 说明 |
|---|---|---|
| `events/*.jsonl` | 7–30 天 | 原始轨迹；可压缩/归档 |
| `issues.json` | 7–90 天（按 class） | `resolved` 保留一段时间用于审计 |
| `playbook.md` | 长期 | 人审资产 |
| `overrides.jsonl` | 90 天 | 审计 override |

`gc` 只删除过期 events/issues，不删除 playbook/override 审计记录。

### 11.4 并发

- JSONL：单写者 + 文件锁；`issues.json` 用 temp + replace 原子写；
- SQLite：WAL；`events` 追加、`issues` upsert；
- 多 Agent：`scope` + `environment_id` 隔离；冲突用“最近成功/更高 confidence/人工”解决。

### 11.5 脱敏

- 正则：`Authorization: Bearer ...`、`password=...`、`token=...`、`Cookie: ...`、私钥块；
- 对 `target` 是否脱敏由配置决定（内网 IP 可能需要保留，否则无法定位）；
- `message_redacted` 只保留前 200–500 字符；完整内容放 `evidence_ref`，权限更高。

### 11.6 Python 包结构（建议）

```text
runtime_memory/
├── __init__.py
├── models.py          # OperationRequest / OperationEvent / Issue / Decision
├── fingerprint.py     # scope/call key 规范化
├── policy.py          # error_class -> retry policy / budgets
├── store.py           # JSONL append + issues.json 原子读写；可选 SQLite 后端
├── runtime.py         # preflight / postflight / resolve / override
├── redact.py          # 脱敏
├── report.py          # shadow / metrics / issues 报表
├── cli.py             # python -m runtime_memory ...
└── tests/
    ├── test_fingerprint.py
    ├── test_policy.py
    ├── test_state_machine.py
    ├── test_preflight.py
    ├── test_redact.py
    └── test_store.py
```

核心接口：

```python
class RuntimeMemory:
    def __init__(self, root: Path, policy: Policy, clock=utcnow): ...
    def preflight(self, req: OperationRequest) -> Decision: ...
    def postflight(self, req: OperationRequest, outcome: Outcome) -> Issue: ...
    def resolve(self, issue_id: str, basis: str, reviewer: str) -> Issue: ...
    def ignore(self, issue_id: str, basis: str, reviewer: str) -> Issue: ...
    def report(self, since: timedelta, shadow: bool = False) -> Report: ...
    def rebuild_issues(self) -> int: ...
```

### 11.7 SQLite 表（可选后端）

```sql
CREATE TABLE events (
  event_id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  session_id TEXT,
  run_id TEXT,
  scope TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  component TEXT NOT NULL,
  tool TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  args_fingerprint TEXT,
  outcome TEXT NOT NULL,
  error_class TEXT,
  error_code TEXT,
  message_redacted TEXT,
  duration_ms INTEGER,
  attempt INTEGER,
  retryable INTEGER,
  evidence_ref TEXT,
  author TEXT,
  policy_version TEXT
);

CREATE TABLE issues (
  issue_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  key_level TEXT NOT NULL,
  scope TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  component TEXT NOT NULL,
  tool TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  error_class TEXT NOT NULL,
  status TEXT NOT NULL,
  first_seen TEXT NOT NULL,
  last_seen TEXT NOT NULL,
  count INTEGER NOT NULL,
  attempts INTEGER NOT NULL,
  retry_policy_json TEXT NOT NULL,
  next_retry_at TEXT,
  expires_at TEXT,
  workaround TEXT,
  confidence REAL,
  related_incident_id TEXT,
  related_case_id TEXT
);

CREATE INDEX idx_issues_lookup
  ON issues(fingerprint, scope, environment_id, status);
CREATE INDEX idx_issues_retry
  ON issues(status, next_retry_at);
```

JSONL 仍然是原始层；SQLite 只是物化层，`rebuild_issues` 可从 events 重建。

---

## 12. 集成方式

### 12.1 组件清单

| 组件 | 例子 | 失败类型 |
|---|---|---|
| MCP / hunt | `hunt.query` | unreachable、timeout、rate_limit、schema |
| SIEM/日志查询 | ES/SQL | timeout、auth、schema |
| shell | 本地命令 | permission、not_found、timeout |
| 文件/解析 | pcap、evtx、csv | schema、parse、not_found |
| 模型 API | LLM 调用 | timeout、rate_limit、context_overflow、invalid_tool_call |
| 沙箱 | 文件/网络权限 | denied、permission |
| Web | 抓取 | timeout、403、DNS |

### 12.2 接入方式

**方式 A：装饰器（最小侵入）**

```python
@runtime.guard(component="mcp", tool="hunt.query", action="search")
def query(target, q):
    ...
```

**方式 B：显式 gateway（更可控）**

```python
def call_tool(req, fn):
    decision = runtime.preflight(req)
    if decision.action == "block":
        return BlockedResult(decision)
    ...
```

**方式 C：harness 的 before/after hook**

如果 harness 有工具调用生命周期钩子，在 `before_tool_call` 做 preflight，在 `after_tool_call` 做 postflight；这是最干净的方式。

### 12.3 CLI

```powershell
# 调用前查询（调试/人工）
python -m runtime_memory preflight --component mcp --tool hunt.query \
  --action search --target 10.7.194.120:22196 --args '{"q":"..."}'

# 查看问题
python -m runtime_memory issues --status open
python -m runtime_memory issue ISS-...

# 人工解决/忽略
python -m runtime_memory resolve ISS-... --basis "endpoint restored"
python -m runtime_memory ignore ISS-... --basis "false alarm"

# 报表/清理
python -m runtime_memory report --since 7d
python -m runtime_memory rebuild-issues
python -m runtime_memory gc --dry-run
```

### 12.4 可选 MCP 工具

- `runtime_memory.query`：只读，给模型查已知问题；
- `runtime_memory.note`：只写 `notes`，不写 status；
- 真正的拦截仍在 gateway，不能依赖模型主动查询。

### 12.5 Harness hook 契约（如果 harness 支持中间件）

```python
# before: 返回 Decision；harness 必须按 action 执行
def before_tool_call(ctx: ToolCallContext) -> Decision:
    req = OperationRequest(
        component=ctx.component, tool=ctx.tool, action=ctx.action,
        target=normalize_target(ctx.target), args=ctx.args,
        scope=ctx.scope, environment_id=ctx.environment_id,
        session_id=ctx.session_id, run_id=ctx.run_id,
    )
    return runtime.preflight(req)

# after: 成功或失败都要调用；用于更新 issue
def after_tool_call(ctx: ToolCallContext, result=None, error=None) -> None:
    runtime.postflight(req_from_ctx(ctx), outcome_from(result, error))
```

要求：

- `before_tool_call` 的 `block` 必须阻止实际调用，而不是只给模型提示；
- `after_tool_call` 必须在 `finally` 中执行，避免异常路径漏记；
- `ctx` 必须带 `run_id`/`session_id`/`environment_id`，否则无法做 per-run 预算和跨环境隔离；
- 如果 harness 没有 hook，就在工具 client 外包一层 gateway，不要在每个调用点手写。

---

## 13. 多 Agent / Scope

| scope | 共享范围 | 例子 |
|---|---|---|
| `global` | 整个环境/所有 Agent | MCP 端点不可达、网络策略 |
| `session` | 单次运行 | 本次 run 的临时限流、上下文超限 |
| `agent` | 单 Agent | 某模型/某 Agent 的参数格式问题 |

规则：

- `environment_id` 必须参与 fingerprint；否则 lab-a 的问题会污染 lab-b；
- `global` issue 可以被所有 Agent 读取；`session` 只在本 run 生效；
- 一个 Agent 的成功可以 `mitigated` 另一个 Agent 的 issue，但不要直接 `resolved` 全局；
- 多写者用 SQLite WAL 或单写者队列；JSONL + 文件锁只适合低并发。

---

## 14. 安全、风险与反模式

### 14.1 威胁模型

| 风险 | 机制 | 缓解 |
|---|---|---|
| **模型自我封锁** | 模型写“工具坏了”以避免使用 | 只有 harness 写 status；模型只能 notes |
| **陈旧记忆永久阻塞** | issue 不过期 | `expires_at` + stale 允许 probe + 人工 resolve |
| **跨环境污染** | 一个环境的故障传到另一个 | `environment_id` + scope |
| **错误归因** | 参数错误被记成工具坏 | `error_class=invalid_args`；诊断分层 |
| **秘密泄漏** | 错误消息含 token/密码 | 脱敏 + 只存摘要 + 权限 |
| **上下文污染** | 把完整 issue 历史塞进 prompt | 只注入 preflight 卡片 |
| **记忆中毒** | 外部内容写入 issue | 写入只来自 harness；内容扫描 |
| **过度拦截** | 误拦导致任务失败 | shadow 测误拦率；短 TTL；override |
| **审计缺失** | 无法解释为什么没调用 | 每次 block 记 issue_id + policy_version + source events |

### 14.2 反模式

1. **只存不拦**：变成“没人看的日志”。
2. **只拦不存**：跨会话重犯。
3. **让模型写 issue 状态**：自我实现。
4. **永久 block**：一次故障封死工具。
5. **所有错误都等 30 分钟**：auth/schema 等再久也没用。
6. **把参数错误记成工具坏**：错误的更新对象。
7. **把完整堆栈塞进 prompt**：上下文污染。
8. **先上向量库**：结构化键不需要。
9. **把运行记忆写进 `demo/data`**：污染案例审计/状态/实验冻结。
10. **自动从单次失败生成 playbook**：过度泛化。

---

## 15. 观测与评测

### 15.1 指标

| 指标 | 定义 | 目标 |
|---|---|---|
| `duplicate_attempts` | 同 fingerprint 在 run 内的重复失败次数 | 相对 shadow 基线 ↓≥30% |
| `blocked_calls` | 被 block 的调用数 | 可解释、非零 |
| `false_block_rate` | 被 block 但实际会成功的比例 | <5% |
| `probe_success_rate` | probe 成功/总 probe | 用来调 TTL |
| `time_to_workaround` | 首次失败 → 有 workaround | 越短越好 |
| `stale_issue_rate` | 过期未确认 issue 比例 | <20% |
| `tokens_saved` | 估算避免的调用成本 | 正收益 |
| `override_rate` | 人工/模型 override 比例 | 低且可解释 |

### 15.2 Shadow 评估

1. 记录 1–2 周真实失败（或回放历史 trace）；
2. 计算“如果拦截，会 block 多少次”；
3. 对比实际结果：block 的调用里有多少会成功（误拦）；
4. 调整 TTL/阈值；
5. 只在误拦率可接受时开启强制。

### 15.3 报表

```text
runtime_memory report --since 7d

open issues: 3
  ISS-... mcp hunt.query unreachable  count=3  next_retry=...
  ISS-... parser evtx schema          count=2  workaround=...
blocked calls: 17
false blocks: 0 (shadow)
duplicate attempts saved: 12
stale issues: 1
```

---

## 16. 测试计划

### 16.1 单元测试

- 指纹规范化（URL/路径/shell/参数 hash）；
- `key_level` 选择；
- 策略计算（fixed/exponential/Retry-After/max attempts）；
- 状态机转移（cooldown→open→probing→resolved/stale）；
- TTL/expiry；
- 脱敏；
- 指纹去重/聚合。

### 16.2 集成测试

- 假工具第一次失败 → cooldown；第二次 → open；preflight block；
- `next_retry_at` 到期 → probe；成功 → resolved；
- stale → probe；失败 → open；
- 另一环境成功 → mitigated；
- shadow 模式：block 决策但实际调用，记录 `would_block`；
- 并发写（JSONL 锁 / SQLite WAL）；
- **demo 数据哈希不变**（运行记忆不碰 demo）。

### 16.3 不变量

1. 没有 event 的 issue 不存在；
2. 没有 issue 的 block 不存在；
3. 每个 block 都能追溯到 `issue_id` + `policy_version` + source events；
4. `expires_at` 一定存在；
5. `resolved` 后不是永久 allow：新失败可以重新打开；
6. 模型不能写 status。

### 16.4 具体用例

| # | 场景 | 期望 |
|---|---|---|
| T1 | 首次 `unreachable` | 建 `cooldown`，preflight block 到 `next_retry_at` |
| T2 | 同一 issue（fingerprint + error_class）第二次失败 | 升级 `open`，`count=2`，退避更新 |
| T3 | `next_retry_at` 到期 | preflight 返回 `probe`，允许一次调用 |
| T4 | probe 成功 | issue → `resolved`；后续 allow |
| T5 | probe 失败 | 回 `open`，退避加倍，`attempts+1` |
| T6 | `expires_at` 过期未确认 | issue → `stale`；preflight 允许一次 probe |
| T7 | shadow 模式 | 记录 `would_block=true`，但实际调用仍执行 |
| T8 | 模型写 notes | notes 增加，`status`/`next_retry_at` 不变 |
| T9 | `auth` 失败 | 不重试；block 到人工 resolve |
| T10 | 同 target 不同 `environment_id` | 两个独立 issue，不互相影响 |
| T11 | 错误消息含 `Bearer ...` | 存储中不出现 token |
| T12 | 两个进程同时写 events | 无丢行；issues 不出现半写 |
| T13 | 解析器 `schema` 失败 | 不重试；提示修 schema，而不是“等半小时” |
| T14 | `invalid_args` 来自模型 | 不封工具；提示改参数 |

---

## 17. 与 demo 的兼容

- **不 import** `demo/src/attack_memory`；
- **不写** `demo/data`；
- **不影响** `catalog validate` / `audit` / `state` / `retention` / `freeze`；
- 如需关联，event/issue 里存 `related_incident_id` / `related_case_id` 软引用；
- 如果要做联合报表，用只读脚本拼两份数据，不要合并存储；
- `runtime_memory/` 可以有自己的 `.gitignore`（events/issues 不入库），但 `schema.md`/`policy.json`/`README.md` 入库。

---

## 18. 开放问题（需要你决策）

| ID | 问题 | 选项 | 建议 |
|---|---|---|---|
| Q1 | 存储放哪 | 本仓库 `runtime_memory/` / harness 仓库 | 先在 harness 侧；本仓库放设计与最小实现 |
| Q2 | 共享粒度 | global / session / agent | 环境问题 global，模型问题 agent |
| Q3 | 拦截强度 | 硬拦截 / 软提示 / shadow | shadow → 单组件硬拦截 → 扩展 |
| Q4 | TTL 默认 | 按 class / 统一 | 按 class（见 §10） |
| Q5 | 成功是否记录 | 全记 / 采样 / 只记解决 | 采样 1/100 + 解决必记 |
| Q6 | 模型能否写 notes | 能 / 不能 | 能，但不改 status |
| Q7 | 是否关联 incident/case | 软引用 / 无 | 软引用，可为空 |
| Q8 | 何时上 SQLite | 现在 / 多 Agent 时 | 多 Agent 或 >1k issues |
| Q9 | playbook 是否自动生成 | 自动 / 人审 | 人审；单次失败不生成 |
| Q10 | 谁有权限 resolve/ignore | 模型 / 人 / 运维 | 人/运维；模型只能 probe 申请 |

---

## 19. 实施路线

### Phase 0：Trace + Shadow（2 天）

- `runtime_memory/` 包 + `events.jsonl`；
- `policy.json` 初版；
- `preflight` 计算但不拦截（shadow）；
- `report --shadow` 输出 would-block / false-block；
- 不接生产 gate，先看数据。

**退出标准**：能对 1 个组件（MCP）记录失败并算出“如果拦截会怎样”。

### Phase 1：Issue + 策略（3 天）

- `issues.json` 聚合 + 状态机；
- TTL/next_retry_at/expiry；
- per-run 预算；
- 单元/集成测试。

**退出标准**：shadow 报表能给出 duplicate attempts / false-block 估算。

### Phase 2：单组件强制（2 天）

- 对 MCP hunt 开启 `enforce=true`；
- block/probe/override；
- 记录 `blocked_calls`、`probe_success_rate`；
- 观察 1 周。

**退出标准**：重复失败下降 ≥30%，误拦 <5%。

### Phase 3：扩展（3–5 天）

- SQLite/WAL（如需要）；
- 多 Agent scope；
- playbook 人审流程；
- 报表/告警；
- 与 harness hook 集成。

**总投入**：约 2 周（不含长期调参）。

---

## 20. 附录

### 20.1 调用序列

```text
Agent
  │ call hunt.query
  ▼
Gateway ──preflight──► Runtime Memory
  │                      │
  │◄──── Decision ───────┘
  │
  ├─ block → return BlockedResult（不调用）
  ├─ probe → call tool once
  └─ allow → call tool
  │
  ▼
Tool/Environment
  │ result/error
  ▼
Gateway ──postflight──► Runtime Memory（event + issue update）
  │
  ▼
Agent
```

### 20.2 伪代码

```python
@dataclass
class OperationRequest:
    component: str
    tool: str
    action: str
    target: str
    args: dict
    scope: str = "session"
    environment_id: str = "default"
    session_id: str = ""
    run_id: str = ""

class RuntimeMemory:
    def preflight(self, req: OperationRequest) -> Decision:
        scope_key = scope_fingerprint(req)
        call_key = call_fingerprint(req)
        issues = self.store.find_issues([scope_key, call_key],
                                        statuses=ACTIVE_STATUSES)
        if not issues:
            return Decision.allow()
        # choose the most restrictive action across scope/call issues
        return self.decide(issues)

    def postflight(self, req, error=None):
        event = OperationEvent.from_request(req, error)
        self.store.append_event(event)
        if error is None:
            self.resolve_matching(scope_fingerprint(req), call_fingerprint(req))
            return None
        error_class = classify_exception(error)
        level = self.policy.key_level(error_class)
        key = scope_fingerprint(req) if level == "scope" else call_fingerprint(req)
        issue = self.store.get_or_create(key, error_class, req)
        issue.record_failure(event, self.policy)
```

### 20.3 示例记录

```jsonc
// events/2026-11.jsonl
{"schema_version":1,"event_id":"OP-20261102T113657-0001","ts":"2026-11-02T11:36:57+08:00","scope":"global","environment_id":"lab-a","component":"mcp","tool":"hunt.query","action":"search","target":"10.7.194.120:22196","outcome":"fail","error_class":"unreachable","error_code":"ECONNREFUSED","message_redacted":"connect ECONNREFUSED","duration_ms":30012,"attempt":1,"retryable":true,"author":"harness"}
```

```jsonc
// issues.json
{"schema_version":1,"issues":[{"issue_id":"ISS-...","fingerprint":"lab-a|scope|mcp|hunt.query|search|10.7.194.120:22196","key_level":"scope","error_class":"unreachable","status":"open","count":3,"attempts":3,"retry_policy":{"mode":"fixed","base_s":900,"max_s":1800,"max_attempts":3,"max_attempts_per_run":1},"next_retry_at":"2026-11-02T12:10:12+08:00","expires_at":"2026-11-03T11:40:12+08:00","workaround":"use local pcap","confidence":0.8}]}
```

### 20.4 术语

| 术语 | 含义 |
|---|---|
| trace | 原始操作轨迹，append-only |
| issue | 聚合后的问题记忆，preflight 读取 |
| fingerprint | 问题身份；scope/call 两级 |
| cooldown | 单次失败后的短期冷却 |
| open | 重复失败/确认问题 |
| probing | 已放行一次探测 |
| mitigated | 有 workaround，不阻塞 |
| stale | 过期未确认，允许 probe |
| preflight | 调用前决策 |
| postflight | 调用后更新 |
| shadow | 只计算不拦截 |
| override | 人工/模型请求绕过（记审计） |

---

## 21. 结论

- **值得做**：它解决的是“重复踩坑 + 模型不停试”，和案例记忆互补，不是替代。
- **必须分开**：`runtime_memory/` 独立于 `demo/data`；不要复用 `ops_journal`/`corrections`/`link_exceptions`。
- **先做 B + shadow**：trace + issue + preflight；先测误拦，再强制。
- **最关键的不是存储，是 gate**：没有 preflight，记忆不会改变行为。
- **最关键的安全阀是过期 + probe**：不要让一条陈旧 issue 永久封死工具。

> 下一步：如果这份设计的方向 OK，我可以按 Phase 0 起一个最小 `runtime_memory/` 原型（schema + JSONL store + preflight + shadow report + tests），或者先把它拆成更细的接口/任务清单。

---

## 22. 与“工具依赖图”的关系

结论：**触及了工具依赖图的运行时健康层，但不是完整的依赖图实现。**

### 22.1 它已经提供的图要素

- **节点坐标**：`environment / component / tool / target` 可以直接作为依赖图节点键；
- **节点健康**：`status / error_class / count / next_retry_at / confidence` 是节点属性；
- **替代路径的雏形**：`workaround` 实际上是一条 `alternative_to` 边，只是目前是文本，不是一等图边；
- **失败传播原料**：events 里有 `session_id / run_id / component / ts`，可以统计 co-failure、同 run 连锁失败。

### 22.2 它还没有的图能力

- 静态 `depends_on` 方向：谁依赖谁、数据从哪来、调用顺序；
- 拓扑排序/规划：先调 A 还是 B；
- 影响面/爆炸半径：一个节点挂了会影响哪些任务；
- 替代路径的自动发现与验证；
- 图查询/图数据库/可视化。

### 22.3 推荐做法

**先不要上图数据库。** 等扁平的 issue store 证明能减少重复尝试后，再导出一个投影：

```text
node: (environment, component, tool, target)
edge: calls | depends_on | alternative_to | co_fails_with
attr: status, error_class, next_retry_at, confidence
```

这样运行记忆是**证据层**，依赖图是**规划层**；两者不要混在一个存储里。前者高频、短 TTL、自动写入；后者低频、需要人工确认、用于规划和影响分析。

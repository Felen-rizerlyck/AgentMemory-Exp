# Attack Memory Demo · 中文说明

> 本文是 [README.md](README.md) 的中文导读，回答三个问题：**一次分析请求怎么走完**、**`data/` 里每个文件是干什么的**、**每条命令归谁用、背后调用什么函数**。
> 英文 README 保持为权威项目说明（设计原则、状态块、性能与验证明细）；字段级 schema 见
> [memory-schema.md](skills/attack-memory/references/memory-schema.md)，运行规则见 [SKILL.md](skills/attack-memory/SKILL.md)。
> 本文只讲“设定上的作用”，不写当前数据规模/统计数字——那些由 `catalog state` 动态生成。

---

## 0. 一句话定位

一套**规则化、可审计、可回滚的案例记忆**：确定性召回 + 结构化证据包 + Agent 裁决 + 受控写回 + 不可变版本。
它不是向量检索 demo，也没有 HTTP 服务——“一次分析请求”= 一个 CSV 日志批次 + 一组命令行操作；
最终分析结论由 Agent/分析师依据证据包给出，demo 的职责是保证**任何结论都有证据、任何记忆变更都过门控、任何历史都能回滚**。

---

## 1. 快速开始

```powershell
cd demo

# 1) 体检
python src/manage_memory.py catalog validate
python src/manage_memory.py audit
python src/manage_memory.py catalog state

# 2) 用现有语料跑一次检索
python src/run_demo.py --input data/raw_logs.csv --min-tier medium

# 3) 测试与一键验证矩阵
python -m unittest discover -s tests
python scripts/verify_demo.py
```

所有命令都在 `demo/` 下执行，命令行里给的路径一律相对 `demo/`；只依赖 Python 标准库。
`scripts/verify_demo.py` 会跑 compileall、测试、validate、audit、state 同步、检索/回看样例、
JSON 契约、repair dry-run、corrections，并对 `demo/data` 做写前/写后哈希守卫。

---

## 2. 角色模型：谁在做什么

| 角色 | 负责 | 约束 |
|---|---|---|
| **模型 / Agent（运行时）** | 接收日志、检索候选、解释证据、记录候选/关系/纠正、发演进提案 | 只能“提议”；写操作必须过确定性门控；不能自动成为最终裁决者 |
| **人工分析师** | 确认关系、标注阶段、复核新案例、接受/拒绝提案、案例合并/退役、审阅负记忆 | 提交权留给人；`--force`、`--auto`、破坏类变更尤其应由人执行 |
| **确定性 harness（代码）** | regex 校验、support 覆盖门控、held-out 回归、审计、事务 journal、版本快照 | 用规则而不是模型判断“能不能写” |
| **运维 / CI** | validate / audit / state --check / repair / snapshot / retention | 周期性巩固与修复，不改变语义 |

> 这就是调研里反复强调的 **“模型提议、harness 裁决”**：demo 里没有“模型直接覆盖生产记忆”的路径；
> 实验模式（本 demo）允许模型通过 CLI 写，但每条写入都留 admission/audit 痕迹；部署模式应由使用方把提交权收到人。

---

## 3. 完整运行流程

### 3.0 一次“请求”的输入

一个 CSV 批次，必需列 `timestamp`、`source`、`log_id`、`content`；可选 `event_id`、`incident_id`、
`case_id`、`batch_id`。它代表“收到了这些日志”，不代表“这些日志已经是一个 incident”。

### 3.1 接收（Capture）

```powershell
python src/ingest_logs.py --input <batch.csv>
```

- 只追加到 `raw_logs.csv`，不覆盖历史；自动补 `event_id` 与 `batch_id`；
- 输入里自带的 `incident_id` 默认被**扣留**（“你说是同一 incident”不是证据），除非显式 `--allow-incident-id`；
- `case_id` 一律置空，`source` 统一小写；重复 `event_id` 直接拒绝。

### 3.2 召回（Retrieve）

```powershell
python src/run_demo.py --input <batch.csv> --min-tier weak [--json] [--incident-id INC-...]
```

内部顺序：

1. **划分 scope**：有 `incident_id` 的行按 incident 整体分析；未标注行先按 `batch_id`，再从内容里抽 `host=` 再拆开——
   避免把不同主机的行硬拼成一条从未存在的攻击链。每个 scope 都会标注“候选 scope，不是 incident 证明”。
2. **动作检测**：用 case 的 `action_id/action_regex` 对每行做匹配，并做 source 感知（`expected_sources` 支持 `any`）。
3. **时序对齐**：按时间做 LCS 式对齐，一个动作最多支撑一个 step；时间戳缺失则顺序记为 `unassessable`。
4. **分档**：只看 required 骨架——全部 required 命中且顺序成立 → `strong`；足够多的非 generic 命中 → `medium`；
   其余细分为 `weak: prefix / tail / generic_only / mismatch_only / unaligned_only`；纯词法命中只算 `keyword_only`（不是候选）。
5. **证据包**：每个候选输出 matched 与 detected 的区别、每个 step 的证据事件与来源、未对齐检测、
   顺序评估、source fit、未观测步骤（required/optional 分开）、缺失的前缀/缺口、下一步假设，
   以及 pattern 自己的 caveat/provenance/negative evidence。

在证据包之上，本版还附加三样“记忆辅助”：

- `historical_precision`：该 case 的 step 在历史语料上“命中且被复核链接”的比例；
- `evidence_confidence`：required 覆盖率 × 历史精度的证据比（明确标注**不是概率**，不改变 tier 排序）；
- `prior_rejections`：负记忆里针对该 case（可到 incident）的历史拒绝原因。

`--json` 输出带顶层 `schema_version`，字段契约稳定，供脚本/子 Agent 消费。

### 3.3 解释与裁决（Agent / 分析师）

这是“结合召回结果做分析”真正发生的环节，规则见 [SKILL.md](skills/attack-memory/SKILL.md) 的 Recall policy：

| 召回结果 | 能否当先例 | 用法 |
|---|---|---|
| `strong` / `medium` | 可以 | 引用具体步骤作为正例 |
| `weak: prefix` | 只能当假设 | 攻击可能刚开始，需要证伪而不是确认 |
| `weak: tail` | 只作“这一步长什么样” | 不能代表整条链 |
| `weak: generic_only` | 不能 | 只是共享检测器 |
| `weak: mismatch_only` | 不能 | 是传感器预期问题 |
| `keyword_only` | 不能 | 不是候选 |

选定候选后，用 `lookup_case_logs.py` 拉历史证据再下结论：

- `--exclude-incident <正在判断的 incident>` **必须**：否则会泄露该 incident 自己的复核标签（答案泄漏）；
- fixture 默认隐藏，related 需显式包含；merged case 自动跟随 alias，证据计入 target 且不双计；
- 输出应包含：支持点、冲突点（source 不匹配 / 顺序异常）、未观测项（unknown ≠ absent）、
  传感器可用性、置信度提示、建议动作（确认链接 / 关联 / 记纠正 / 新候选 / 演进提案）。

### 3.4 写回（把这次分析变成记忆）

按分析结论选择动作；所有写操作都过 `storage.commit()` 事务并记入 journal：

| 分析结论 | 命令 | 落盘 |
|---|---|---|
| 已复核的确定关系 | `review link --status confirmed` | `event_pattern_links.csv`（追加）+ `raw_logs.csv` 标签列 + journal |
| 变体但不确定 | `review associate`（写 related，不改标签） | links + journal |
| regex 不匹配但人工确认例外 | `review link --force --basis "..."` | links + `link_exceptions.json` + journal |
| 现有 case 解释不了的行为 | `review stage`（独立阶段标注） | `incident_chains.json` 注解 |
| 新手法（还没到建 case） | `catalog stage` | `case_candidates.json` + journal |
| 判定为误报/不匹配 | `catalog correction add` | `corrections.json` + journal |
| 有足够证据的新案例 | `catalog add --supporting-incident-ids ...` / `--from-candidate` | `attack_patterns.json` + `case_admissions.json` + `pattern_versions/<case>/v001.json` + journal |
| 现有案例补步/加来源 | `evolve propose` → `evolve accept` | `pattern_proposals.json` + `pattern_versions/<case>/vNNN.json` + `attack_patterns.json` + journal |

### 3.5 门禁：写完必须自证

```powershell
python src/manage_memory.py audit                 # 交叉检查全部账本；不干净 exit 1
python src/manage_memory.py catalog state --check README.md   # 文档状态块是否与 store 一致
python src/manage_memory.py catalog repair        # dry-run：派生状态能否自愈
```

`audit` 检查的类别包括：links 与标签一致、force 例外是否真实存在、版本快照连续、
提案与快照一致、候选状态/归属、家族与目录一致、迁移与快照/家族一致、准入与 marker 一致、
链/阶段引用、生命周期、归档、负记忆引用、事务 journal 未完成项与机器本地路径泄漏。

### 3.6 巩固（Consolidate，空闲/周期）

```powershell
python src/manage_memory.py catalog chains --rebuild      # 从 raw+links 重建链，保留人工注解
python src/manage_memory.py catalog snapshot --all        # 补缺失的版本基线
python src/manage_memory.py catalog repair --apply        # 应用安全修复（派生状态）
python src/manage_memory.py catalog retention             # TTL 报告；--apply 才归档
python src/manage_memory.py catalog review-case --case-id CASE-... --basis "..."  # 人审解除 unreviewed
```

巩固只处理**派生状态**和**归档**：不删除 raw logs / links / cases / candidates / proposals；
retention 归档会写 gzip 月度段、manifest 与 tombstone，归档数据仍可审计。

### 3.7 演进（案例记忆的自我迭代）

```powershell
python src/manage_memory.py evolve propose --input data/proposals/<file>.json
python src/manage_memory.py evolve list
python src/manage_memory.py evolve accept PROP-... --basis "..." [--auto]
python src/manage_memory.py evolve reject PROP-... --basis "..."
python src/manage_memory.py evolve rollback --case-id CASE-... --to N --basis "..."
```

- 提案是“证据 + 小补丁”，支持 `add_step / extend_step / add_source / set_required / reorder_steps`；
- `add_step` 默认 optional；门控会拒绝：证据不足、stale base_version、跨案例污染、shadow top-1 变化、
  strong 数下降、required 覆盖率下降、held-out（非 support）confirmed incident 回归；
- `--auto` 只给门控判定合格的小步补全类操作；降级、收紧、重排必须显式接受；
- 接受时同时快照旧版本与新版本；回滚用快照恢复，不改写历史。

### 3.8 流程示意

```
新日志 CSV
  │ ingest_logs.py（只追加，扣留输入标签）
  ▼
raw_logs.csv ──review link/associate──> event_pattern_links.csv ──派生──> 标签 / incident_chains
  │                                                                          │
  │  run_demo.py：scope → 动作检测 → 时序对齐 → tier → 证据包               │
  ▼                                                                          ▼
候选证据（文本 / JSON）                                             case_candidates（stage）
  │                                                                          │
  ▼                                                                          ▼
Agent/分析师裁决 ──lookup_case_logs──> 历史证据                    attack_patterns（add/promote）
  │                                                                          │
  ├── 确认关系/阶段/纠正 ──> links / chains / corrections                    │
  ├── 新案例 ─────────────> patterns + admissions + v001 快照               │
  └── 演进提案 ───────────> proposals ──gate──> accept ──> 新版本快照        │
                                                                             ▼
                                               audit / state --check / repair / retention
```

---

## 4. `data/` 目录：每个文件设定上的作用

### 4.1 先分六层

| 层 | 回答的问题 | 文件 |
|---|---|---|
| **证据层（episodic）** | 发生了什么？ | `raw_logs.csv`、`event_pattern_links.csv`、`incident_chains.json`、`link_exceptions.json`（按需） |
| **语义层（semantic）** | 什么是真的、可复用的？ | `attack_patterns.json`、`families.json`、`pattern_versions/`、`pattern_migrations.json`、`case_admissions.json` |
| **候选与演化层** | 什么还没成为 case？怎么演进？ | `case_candidates.json`、`signature_lexicon.json`、`pattern_proposals.json`、`case_lifecycle.json` |
| **负记忆与运行账本** | 什么是错的？写入本身可靠吗？ | `corrections.json`、`ops_journal.jsonl`、`repair_log.json`（按需） |
| **归档层（consolidate）** | 哪些数据被移出活跃区但仍可审计？ | `retention_tombstones.json`、`archive/<month>/` |
| **输入素材（非运行时）** | 示例/配置/格式说明 | `promoted/`、`proposals/README.md`、`validation_batches/` |

### 4.2 证据层

| 文件 | 设定作用 | 写入者 | 读取者 | 性质 |
|---|---|---|---|---|
| `raw_logs.csv` | 原始事件行。`case_id`/`incident_id` 是**分析标签**，不是原始日志字段 | `ingest_logs.py` 追加；`review link` 改标签列；retention 归档移除 | 检索、lookup、chains、candidates、retention | 事件正文权威、只追加；**标签是派生缓存**（audit 校验，repair 可重建） |
| `event_pattern_links.csv` | 已复核的“事件 → incident/case/step”关系，append-only；同一事件多条时按时间与文件顺序“最新者生效” | `review link` / `review associate` | 检索的 reviewed 状态、chain 构建、成熟度/派生计数、audit、lookup | **权威、append-only**，历史不覆盖 |
| `link_exceptions.json` | `--force` 链接的例外账本（键=事件+incident+case+step，附 basis/reviewer/时间） | `review link --force`（首次使用时创建） | `audit` 精确放行并计数 | 负向豁免；孤儿/重复/无 basis 会被 audit 报错 |
| `incident_chains.json` | incident 级有序链：每条事件带 `stage/stage_kind/label/stage_order/stage_basis`，`unclassified` 保留“解释不了”的行为 | `review stage` 写注解；`catalog chains --rebuild` 重建（保留注解） | chains 命令、audit、retention、state | **半派生**：结构可从 raw+links 重建，但注解是主数据 |

### 4.3 语义层

| 文件 | 设定作用 | 写入者 | 读取者 | 性质 |
|---|---|---|---|---|
| `attack_patterns.json` | 可复用攻击链目录：case、step（动作定义/regex/来源/required/generic）、family、版本、review marker、provenance | `catalog add`、`evolve accept/rollback`、`review-case`、retire/merge/split | 全部：检索、门控、audit、state | **权威目录**，不可手改；同一 `action_id` 全库只能有一个 regex |
| `families.json` | 分类学：family → case 集合，可带 broad 的 family step（只作为上下文，不做第二套判定） | reviewed migration（脚本/人工） | 检索的 family context、families 命令、chain 构建、audit | 分类配置；family step 只能 related，永不 confirmed，不改 tier |
| `pattern_versions/<CASE>/vNNN.json` | 每个版本的**不可变快照**：建案例时写 v001，接受提案时写新版本；seed case 的早期版本可能是 backfill 基线 | `catalog add`、`evolve accept/rollback`、`catalog snapshot` | `evolve rollback`、版本审计 | 不可变审计资产；快照剔除 review 行政字段，避免 rollback 复活旧 marker |
| `pattern_migrations.json` | 已审“结构迁移”账本（例如把一个 step 从 case 移入 family 并升版本） | reviewed migration | 迁移审计、validate | append-only、已审；必须与快照和 family step 一致 |
| `case_admissions.json` | 新案例准入账本：来源、basis、review 状态、support coverage/single_sample；`admission_id` 永久保留 | `catalog add`（自动）、`review-case`（人工） | audit、validate、run_demo 的 `UNREVIEWED` 标记、state | 准入/复核账本；marker 不会自动消失 |

### 4.4 候选与演化层

| 文件 | 设定作用 | 写入者 | 读取者 | 性质 |
|---|---|---|---|---|
| `case_candidates.json` | 还没成为 case 的技术候选：事件证据、签名特征、状态（provisional/promotable/promoted/rejected/merged）、别名关系、pending links | `catalog stage/merge/split`、`add --from-candidate` | candidates/families 命令、audit、retention、state | 候选账本；**不会自动建 case**；无判别词的候选进 `ungrouped` |
| `signature_lexicon.json` | 候选签名抽取用的产品/动作词表（外置，可扩展；加载失败回退内置） | 人工维护（只读配置） | `signatures.extract_features`（stage/promote 时） | 纯配置，不参与检索 |
| `pattern_proposals.json` | 演进提案账本：操作、base/new version、support 证据、门控 metrics、决定与理由 | `evolve propose/accept/reject` | `evolve list`、audit、retention、state | **模型提议**的账本；accepted 才写新版本快照 |
| `case_lifecycle.json` | case 级生命周期事件（merge/split/retire/reactivate），append-only | `catalog merge-case/split-case/retire/reactivate`（merge/split 与 patterns+candidates 同一事务） | lifecycle 命令、audit、lookup alias 解析 | 生命周期账本；retired 保留历史但检索跳过；merged 可跟随 alias |

### 4.5 负记忆与运行账本

| 文件 | 设定作用 | 写入者 | 读取者 | 性质 |
|---|---|---|---|---|
| `corrections.json` | 负记忆：某 incident 为什么**不是**某 case（决定/原因码/证据/依据/复核人） | `catalog correction add` | `run_demo` 的 `prior_rejections`、corrections 命令、audit | append-only 的“已测边界”，不是先例 |
| `ops_journal.jsonl` | 两阶段提交账本：每笔写入先 pending（含目标文件 SHA-256）后 done；崩溃窗口可检测 | 所有 mutating 命令的 `storage.commit()` | audit（未完成/路径泄漏）、state（事务计数）、repair | 运行账本；正常状态下是成对记录 |
| `repair_log.json` | 派生状态修复记录：修了什么、before/after、依据；与修复写在同一事务 | `catalog repair --apply`（首次使用时创建） | repair 审计 | append-only；只修派生状态，绝不删资产 |

### 4.6 归档层

| 路径 | 设定作用 | 写入者 | 读取者 | 性质 |
|---|---|---|---|---|
| `archive/<YYYY-MM>/` | 月度归档 gzip 段（raw links chains candidates）+ 每次运行的 manifest（归档了哪些 incident/事件、TTL 参数） | `catalog retention --apply`（唯一归档命令） | 归档审计/清理 | 按“月”追加段，不按 incident 拆文件 |
| `retention_tombstones.json` | 归档运行的墓碑/清单：incident 摘要、事件数、内容 hash 根、仍被活跃数据引用的 tombstone | `retention --apply` | retention 审计、state | 让“被移出活跃区”的数据仍可审计 |

### 4.7 输入素材（不参与运行时）

| 路径 | 作用 |
|---|---|
| `promoted/CASE-009.json` | 当年用 `catalog add --from-candidate` 晋升案例时的**作者手写 pattern 输入文件**；对应目录里的 CASE-009。运行时不会自动读它。 |
| `proposals/README.md` | 提案 JSON 的格式说明和示例（文档，不是数据）。 |
| `validation_batches/CASE-008_similar_synthetic.csv` | 隔离的合成验证批次，供 eval/消融实验使用；**不要随手 ingest**，否则会变成真实 raw 行。 |

### 4.8 事实源 / 派生 / append-only 一览

| 类别 | 文件 | 说明 |
|---|---|---|
| **权威事实源** | raw_logs 的正文/批次/时间、event_pattern_links、attack_patterns、families、case_admissions、pattern_proposals、pattern_migrations、case_lifecycle、corrections、pattern_versions | 只能通过对应命令写，不要手改 |
| **派生缓存** | raw_logs 的 case/incident 标签、成熟度与派生计数、state 块、audit 聚合 | 可由 links/patterns 重建；`catalog repair` / `catalog state` 重算 |
| **半派生** | incident_chains.json | 结构可重建，但人工注解是主数据 |
| **append-only 账本** | links、versions、proposals、migrations、lifecycle、corrections、exceptions、journal、repair_log、archive | 追加或快照只读 |
| **按需出现** | link_exceptions.json、repair_log.json | 首次使用才创建；**现在没有是正常状态** |
| **不参与运行时** | promoted/、validation_batches/、proposals/README.md | 输入素材/文档/配置 |

### 4.9 文件之间的关系（一句话版）

- `raw_logs` 的事件 + `event_pattern_links` 的复核决定 → 派生出标签和 `incident_chains`；
- 检索只读 `attack_patterns`/`families`/`raw_logs`/`links`，并把结果与 `corrections` 对照；
- 新手法先进 `case_candidates`，积累证据后晋升为 `attack_patterns` 的 case（同时产生 admission 和 v001 快照）；
- 对现有 case 的修改只能通过 `pattern_proposals` → 门控 → `pattern_versions` 新快照；
- 结构性变化走 `pattern_migrations`；案例合并/退役走 `case_lifecycle`；
- 所有写入都经过 `ops_journal`；派生状态坏了用 `repair`（留 `repair_log`）；
- 过期数据由 `retention` 移入 `archive/`，并在 `retention_tombstones` 留下可审计的墓碑。

---

## 5. 指令手册

### 5.1 通用约定

- 所有命令在 `demo/` 下执行；路径参数相对 `demo/`，不允许绝对路径或跳出 demo。
- 写命令的落盘方式：需要同时改多个文件的命令经 `storage.commit()` 事务化（渲染全部文件成功后才替换，失败不留半写状态，journal 记 pending/done）；单文件账本用原子写；`ingest_logs` 是纯追加。
- `--json` 契约：`run_demo` 与 `lookup_case_logs` 的 JSON 顶层带 `schema_version: 1`；
  `audit --json`、`catalog state --json`、`catalog retention --json`、`catalog repair --json` 的字段结构由测试固定，
  当前不带 `schema_version`，做破坏性变更时需同步测试与文档。
- 退出码：`audit`/`catalog validate`/`catalog state --check` 发现问题返回 1；`manage_memory.py` 的业务校验错误由 `main`
  捕获后打印 `ERROR:` 并返回 2（`run_demo`/`lookup`/`ingest` 的参数错误由 argparse 返回 2，业务错误会抛异常）。
- `--force`、`--auto`、`--apply`、`accept`、`review-case` 属于高权限动作：实验模式可用，部署模式应收归人工。

### 5.2 检索与召回（模型/Agent 主要入口）

| 命令 | 用途 / 关键参数 | 背后函数 | 读写 | 使用角色 |
|---|---|---|---|---|
| `python src/run_demo.py --input <csv> [--json] [--top N] [--min-tier T] [--incident-id INC]` | 对批次做召回：scope 划分、动作检测、时序对齐、tier、证据包、family 上下文、历史精度、负记忆提示 | `retrieval.retrieve/build_action_index/match_pattern`、`diagnostics.step_statistics`、`corrections.for_case`、`families.family_evidence`、`run_demo.main` | 读 patterns/raw/families/links/corrections；不写 | 模型/Agent（只读） |
| `python src/lookup_case_logs.py --case-id CASE... [--incident-id ...] [--step-id ...] [--exclude-incident ...] [--status ...] [--include-related] [--include-fixtures] [--json]` | 按 case/incident/step 回看历史证据；merged case 跟随 alias（`alias_of`/`resolved_case_id`）；fixtures 默认隐藏 | `lookup_case_logs.select_observations`、`catalog.maturity/pattern_version`、`links.derived_observations`、`storage.resolve_case` | 读 raw/links/patterns；不写 | 模型/Agent（只读） |

### 5.3 接收

| 命令 | 用途 / 关键参数 | 背后函数 | 读写 | 使用角色 |
|---|---|---|---|---|
| `python src/ingest_logs.py --input <csv> [--allow-incident-id]` | 把新批次标准化后追加到 raw 日志；默认扣留输入 incident_id | `ingest.ingest`（`storage.append_csv`） | 写 `raw_logs.csv`（追加）；无 journal（纯追加，不入多文件事务） | 模型/Agent 或运维 |

### 5.4 catalog 查询与报告命令（默认只读）

| 命令 | 用途 | 背后函数 |
|---|---|---|
| `catalog validate` | 结构校验：目录、家族、迁移、准入、链、生命周期、归档、版本、例外、alias | `audit.run_validation` |
| `catalog state [--json] [--check README.md]` | 输出/校验由 store 生成的状态块；`--check` 不一致即 exit 1 | `state.memory_state / render_state_block / check_state_block` |
| `catalog families` | 列出 family 与 case/候选统计 | `families.counts` |
| `catalog candidates [--status S] [--family F] [--by-group]` | 列候选；`--by-group` 按确定性签名分组，无判别词的进 `ungrouped` | `candidates.list_candidates`、`signatures.group_candidates` |
| `catalog chains [--rebuild]` / `catalog chain --incident-id INC [--summarize]` | 查看/重建 incident 链，汇总未解释阶段 | `chains.build_chains / summarize_chain` |
| `catalog migrations` / `catalog admissions` / `catalog lifecycle` / `catalog corrections [--case-id] [--incident-id]` | 查看各账本 | 对应模块的 `load_*` / `list_*` |
| `catalog retention [--as-of D] [参数...] [--json]` | 只读 TTL 报告（`--apply` 才会归档） | `retention.build_report / format_lines` |
| `catalog snapshot --all` / `--case-id CASE` | 补齐缺失的版本快照基线（幂等） | `catalog.backfill_snapshots` |
| `catalog repair`（默认 dry-run） | 规划/报告派生状态修复 | `repair.repair_plan` |
| `audit [--verbose] [--case-id CASE] [--json]` | 全量交叉审计；不干净 exit 1 | `audit.run_audit / format_audit_lines`、`diagnostics.diagnostic_lines` |

> 例外（虽然列在本节，但会写文件）：`catalog chains --rebuild` 重建链、`catalog snapshot` 写缺失快照；
> `catalog retention --apply`、`catalog repair --apply` 见 5.5。

### 5.5 catalog 写命令（受门控）

| 命令 | 用途 / 门控 | 背后函数 | 读写 | 建议角色 |
|---|---|---|---|---|
| `catalog stage --signature S --incident-id INC --event-ids E1,E2 [--family-id F] [--label L]` | 记录一个未成 case 的技术候选；同签名第二个 incident → `promotable` | `candidates.upsert_candidate`（`signatures.extract_features`） | 写 candidates + journal；校验事件存在/归属 | 模型/Agent |
| `catalog merge --primary P --alias A --basis "..." [--allow-ungrouped]` | 合并同家族同签名候选；`--allow-ungrouped` 才允许无判别词候选 | `candidates.merge_candidates` | 写 candidates + journal | 人工（复核） |
| `catalog split --primary P --alias A --basis "..."` | 撤销候选合并（仅非 promoted 簇） | `candidates.split_candidate` | 写 candidates + journal | 人工 |
| `catalog add --input pattern.json --supporting-incident-ids A,B [--force]` / `catalog add --from-candidate CAND --input pattern.json [--force]` | 新增案例：≥2 独立 incident、required 步并集覆盖、至少一个 incident 达 strong/medium；`--force` 仅限已复核单样本并记录 `single_sample` | `catalog.add_pattern / add_pattern_from_candidate`、`pattern_support_report`、`admissions.build/insert`、`write_version_snapshot` | 写 patterns + admissions + v001 + journal | 模型可提议，人工复核；`review-case` 后部署可信 |
| `catalog review-case --case-id CASE --basis "..." [--reviewer]` | 人工复核后清除 `unreviewed` marker（admission 保留） | `catalog.review_case`、`admissions.review_admission` | 写 patterns + admissions + journal | 人工 |
| `catalog merge-case --source S --target T --basis "..."` / `catalog split-case --case-id C --basis "..."` | 保守别名合并/撤销：source 退休、`merged_into` 指向 target，links/steps 不重写 | `catalog.merge_case / split_case`、`lifecycle.build_record` | 写 patterns + candidates + lifecycle（同一事务） | 人工 |
| `catalog retire --case-id C --basis "..."` / `catalog reactivate --case-id C --basis "..."` | 退役/恢复案例（保留历史，检索跳过 retired） | `catalog.retire_case / reactivate_case`、`lifecycle.record` | 写 patterns + lifecycle | 人工 |
| `catalog correction add --incident-id INC --case-id CASE --reason-code R --event-ids ... --basis "..." [--decision] [--reviewer]` | 记录负记忆：这次为什么不是这个 case（原因码、证据、依据） | `corrections.add_correction` | 写 corrections + journal | 模型/Agent 或人工（复核） |
| `catalog repair --apply [--json]` | 应用安全修复：标签从 links 派生、补缺失快照、清孤儿 admission；同事务写 repair_log | `repair.repair`、`repair.load_repair_log` | 写 raw/exceptions/snapshots/admissions + repair_log + journal | 运维/人工 |
| `catalog retention --apply [--max-active-bytes ...] [--archive-max-days ...]` | 归档过期 incident：写 gzip 段、manifest、tombstone | `retention.apply_report / audit_archives` | 写 archive/、tombstones、活跃文件 | 运维（显式决策） |

### 5.6 review 命令（复核写入）

| 命令 | 用途 / 门控 | 背后函数 | 读写 | 建议角色 |
|---|---|---|---|---|
| `review link --event-ids E... --incident-id INC --case-id CASE --step-id S --status confirmed|related|rejected|fixture|candidate --basis "..." [--force]` | 记录复核关系；regex 不匹配默认拒绝；`--force` 需 basis 且写例外账本；仅 confirmed/rejected 改标签 | `links.append_links`（`storage.commit`、`apply_label_changes`） | 写 links + raw 标签（+ exceptions）+ journal | 模型可写、人工确认（部署） |
| `review associate --event-ids E... --incident-id INC --case-id CASE [--step-id S] --basis "..."` | 变体关联：写 related，不改 case 标签，family step 只能 related | `links.append_links` | 写 links + journal | 模型/Agent |
| `review stage --incident-id INC --event-id E --stage NAME [--label L] [--order N] --basis "..."` | 独立阶段注解（不属于任何 case 的行为），用于保留 unclassified | `chains.review_stage` | 写 `incident_chains.json` | 模型/Agent 或人工 |

### 5.7 evolve 命令（案例演进）

| 命令 | 用途 / 门控 | 背后函数 | 读写 | 建议角色 |
|---|---|---|---|---|
| `evolve propose --input data/proposals/x.json` | 提交提案并立即跑确定性门控，记录 metrics/blockers；不会自动改目录 | `evolution.create_proposal / evaluate_proposal`、`retrieval.retrieve` | 写 proposals + journal | 模型/Agent（提议） |
| `evolve list [--case-id] [--status]` | 列提案 | `evolution.load_proposals` | 只读 | 全部 |
| `evolve accept PROP --basis "..." [--auto]` | 重新跑门控后接受：写旧/新版本快照 + 新目录；`--auto` 只给门控判定合格的小步补全类 | `evolution.accept_proposal`、`write_version_snapshot` | 写 versions + patterns + proposals + journal | 人工（`--auto` 视部署策略） |
| `evolve reject PROP --basis "..."` | 拒绝提案 | `evolution.reject_proposal` | 写 proposals | 人工 |
| `evolve rollback --case-id CASE --to N --basis "..."` | 用快照恢复历史版本并保留历史 | `evolution.rollback_pattern` | 写 patterns + versions + journal | 人工 |

### 5.8 测试与验证

| 命令 | 用途 | 背后函数/组成 |
|---|---|---|
| `python -m unittest discover -s tests` | 全量测试（含门控反例、不变量、JSON 契约、性能门控默认跳过） | `tests/test_memory.py`、`test_gates.py`、`test_memory_ops.py`、`test_retrieval_contract.py`、`test_invariants.py`、`test_perf.py`（`RUN_PERF=1` 时跑） |
| `python scripts/verify_demo.py [--group baseline|new|all] [--real-unittest] [--json] [--no-data-guard]` | 一键只读矩阵：编译、测试、validate、audit、state 同步、检索/回看样例、JSON 契约、repair dry-run、corrections、journal 卫生、数据哈希守卫 | `scripts/verify_demo.py` |

### 5.9 命令到读写文件的速查

| 命令 | 主要写 | 主要读 |
|---|---|---|
| `ingest_logs` | raw_logs | — |
| `run_demo` | — | patterns、raw_logs、families、links、corrections |
| `lookup_case_logs` | — | raw_logs、links、patterns |
| `review link/associate` | links、raw 标签、exceptions | patterns、raw、links、families |
| `review stage` | chains | patterns、raw、families |
| `catalog stage/merge/split` | candidates | raw、links、signatures/lexicon |
| `catalog add` / `review-case` | patterns、admissions、versions | raw、links、candidates |
| `catalog merge-case/split-case/retire/reactivate` | patterns、candidates、lifecycle | patterns、candidates、lifecycle |
| `evolve propose/accept/reject/rollback` | proposals、versions、patterns | patterns、raw、links |
| `catalog correction add` | corrections | patterns、raw、links |
| `catalog chains --rebuild` | chains | raw、links、patterns、families |
| `catalog snapshot` | versions | patterns |
| `catalog repair --apply` | raw 标签、versions、admissions、repair_log | raw、links、patterns、admissions |
| `catalog retention --apply` | archive/、tombstones、活跃文件 | patterns、raw、links、candidates、proposals、chains |
| `catalog state` / `audit` | — | 全部 |

---

## 6. 常见拒绝语义（为什么会“不让写”）

| 操作 | 会被拒绝的典型情况 |
|---|---|
| `ingest_logs` | 缺必需列 / 行缺字段 / 重复 `event_id` |
| `review link` | 未知 case/step/event；非 related 却缺 step；事件内容不匹配 step regex（除 `--force`+basis）；事件标签已属于别的 case；family step 被 confirmed |
| `catalog add` | case_id 重复；支持 incident 少于两个（非 `--force`）；required 步并集未覆盖；没有任何 support incident 达 strong/medium；action_id 与既有定义冲突 |
| `evolve propose` | 未知 case、stale base_version、支持证据不属于该 case、独立 incident 不足、support 事件不匹配新 step、跨案例污染、shadow top-1 变化、strong/required coverage 下降、held-out 回归、收紧（narrowing） |
| `evolve accept --auto` | 提案不是门控判定合格的小步补全类 |
| `catalog correction add` | case/incident/event 不存在或归属不符；reason_code/decision 非法；basis 为空；完全重复 |
| `catalog stage` | 事件不存在或归属别的 incident；同一候选状态迁移非法 |
| `catalog merge` | 不同 family/签名；primary 已 promoted/merged；ungrouped 未显式允许 |
| `audit` | 任意账本不一致（links/标签、例外、版本、提案、候选、家族、迁移、准入、链、生命周期、归档、负记忆、journal） |
| `catalog state --check` | README 状态块与 store 不一致（说明有人改了数字或忘了重新生成） |

---

## 7. 典型场景脚本

### 7.1 分析一个新批次

```powershell
python src/ingest_logs.py --input .tmp/batch.csv
python src/run_demo.py --input .tmp/batch.csv --min-tier medium --json
python src/lookup_case_logs.py --case-id CASE-005 --exclude-incident INC-...
```

### 7.2 判定为误报（负记忆）

```powershell
python src/manage_memory.py review link --event-ids EVT-... --incident-id INC-... \
  --case-id CASE-005 --status rejected --basis "only a shared whoami probe"
python src/manage_memory.py catalog correction add --incident-id INC-... --case-id CASE-005 \
  --reason-code generic_only --basis "only a shared whoami probe; no case step"
```

### 7.3 发现新手法（候选 → 案例）

```powershell
python src/manage_memory.py catalog stage --signature "F1::NewTechnique" --family-id web-exploit \
  --incident-id INC-A --event-ids EVT-1,EVT-2
# 第二个独立 incident 出现后
python src/manage_memory.py catalog add --from-candidate CAND-00xx --input data/promoted/new.json
python src/manage_memory.py audit
```

### 7.4 给现有案例补一个阶段

```powershell
python src/manage_memory.py evolve propose --input data/proposals/CASE-x_add_step.json
python src/manage_memory.py evolve accept PROP-... --basis "two incidents continued into the new stage"
python src/manage_memory.py review link --event-ids EVT-... --incident-id INC-... \
  --case-id CASE-x --step-id Sx --status confirmed --basis "..."
python src/manage_memory.py audit
```

### 7.5 巡检/修复/归档

```powershell
python src/manage_memory.py catalog validate
python src/manage_memory.py audit
python src/manage_memory.py catalog state --check README.md
python src/manage_memory.py catalog repair            # dry-run
python src/manage_memory.py catalog retention         # 只读报告
python src/manage_memory.py catalog retention --apply # 归档（显式决策）
```

---

## 8. 概念与边界（最容易混淆的点）

1. **event ≠ incident ≠ case**：一条原始事件、一组相关事件、一条可复用攻击链；三者不要混用。
2. `raw_logs.csv` 里的 `case_id/incident_id` 是**分析标签**，真正判断历史在 `event_pattern_links.csv`（append-only、最新者生效）。
3. **tier 是确定性证据档位，不是概率**；`evidence_confidence` 也是证据比，不是概率。
4. **scope 是候选 scope，不是 incident 证明**；一个 host 或一个 generic 动作不足以证明有关联。
5. **没有召回 ≠ 良性**：只说明规则里没有受支持的案例；应保留为 unclassified 证据并复核。
6. **v001 可能是基线**：seed case 的早期快照是 backfill 的当前内容基线，不是历史还原；只有 accept/migration 产生的版本是真实历史。
7. **fixtures 是合成验证数据**，默认隐藏，不能当真实观测汇报。
8. **merged alias 只部分合并**：lookup 跟随 alias 并把证据计入 target，但检索只对 active case 打分，不把 source 的历史证据折进 target 评分。
9. **ungrouped 候选只告警**：无判别词的候选需要人工显式 merge，不自动成组/晋升。
10. **单写者原型**：CSV/JSON 便于手工检查，不是并发数据库；journal 能检测中断事务，但不提供锁或隔离。
11. **retention 的 TTL 是实验默认值**；`--apply` 是显式运维决策，归档数据仍可通过 manifest/tombstone 审计。
12. **skill 是说明不是强制**：部署方需要自己把 `unreviewed` 复核、提交权、权限边界做成策略。

---

## 9. 相关文档

- [英文项目说明 README.md](README.md)
- [运行时规则 SKILL.md](skills/attack-memory/SKILL.md)
- [记忆 schema / 账本字段](skills/attack-memory/references/memory-schema.md)
- [案例写入规范](skills/attack-memory/references/case-write-spec.md)
- [运行时命令 playbook](skills/attack-memory/references/runtime-playbook.md)
- [项目介绍与汇报材料](../docs/DEMO_OVERVIEW.md)
- [优化项与修改方案](../docs/DEMO_IMPROVEMENT_BACKLOG.md)
- [记忆自我迭代调研](../docs/agent-memory-skill-self-iteration-survey-2026-10.md)

# 记忆框架可用性与检索通道消融 · 测试大纲 v1.5

> 日期：2026-10-22 · 受测系统：**`demo/` 原型**（D1 已确认）· 状态：可执行草案（v1.5：补充无记忆配对对照与通道消融修订）
> 变更：v1 → v1.1 依 D1~D4 确认结果重写（受测系统改为 demo、链层消融改为 `incident_id` 分区消融）；v1.1 → v1.2 按「每类第 1 个 unit 入库」更新测试库状态与对照设计；v1.5 增补 §17，明确 M0 无记忆比较口径并修订后续通道消融。§15–§16 已完成实验及结果原样保留，本增补不回写既有数据或结论。
> 前置：**demo 数据已按「每类第 1 个多行 unit 入库」完成重整**——8 个案例（CASE-001~007 新增 + 原 CASE-029 改号 CASE-008）/ **45 行观测 / 每案例 ≥3 步**（单行的 1041、1101 已分别换成 1042 schtasks、1102 BloodHound），映射见 `eval/usability_ablation/case_id_map.json`；第 3 节验收条件已逐条通过。

---

## 0. 结论先行（4 个会改变结论的设计问题）

| # | 问题 | 后果 | 本版做法 |
|---|---|---|---|
| 1 | 原 demo 只有 1 个 pattern（CASE-029）、17 行数据 → 多类别记忆无法检验 | "新家族"在两组都会判新，无区分力 | **已重整为 8 个案例 / 8 个家族 / 41 行**（每类第 1 个 unit 入库），并把 "完全一致单元" 作为对照（§4.4） |
| 2 | **GT 不能"想当然"**：实测主库 1001-1080 里只有 3/80 个 unit 与已有案例明显对应 | 正例若选错，有无记忆都判"新"，结论变成"记忆无用" | 正例从案例库**派生变体**，并用 demo 自身跑一遍确认"动作全命中 + strong"才纳入 |
| 3 | **"有记忆/无记忆"混了两件事**：知识存在 vs 检索找对 | M1 若被允许直接读 `attack_patterns.json`，等于 oracle，测不出检索价值 | 三档 M0 / M1 / M2，且 M1 **禁止直读 pattern 库**（只给 CLI） |
| 4 | **删日志只测"变差多少"，没测"该补什么"** | 记忆在缺证据场景的核心价值是补全/预测下一步 | 残缺实验主指标加 `predict_next` 命中率与"是否指出缺失阶段" |

---

## 1. 研究问题与假设

| RQ | 问题 | 假设（可被推翻） |
|---|---|---|
| RQ1 | 记忆是否提升判定？ | H1：M1 的链级判定正确率 > M0；T2（新家族）上 M1 的误匹配率 < M0 |
| RQ2 | 检索机制本身贡献多少？ | H2：M1 ≈ M2 → 检索够用；M1 < M2 → 检索是瓶颈；M1 > M2 → 检索式记忆更抗噪 |
| RQ3 | 证据不完整时是否仍有用？ | H3a：M1 退化幅度 < M0；H3b：M1 能指出缺失阶段/预测下一步，M0 不能 |
| RQ4 | 三个关键词子通道是否必要、贡献多大？ | H4：动作通道是主渠道；关键词主要作用于**并列排序**与**动作零命中时的兜底**；probes(×4) 贡献最大，mitre(×2) 最小 |
| RQ5（可选） | 判定是否跟随检索？ | H5：一致率高 → 记忆通过检索生效；不一致时逐案分析是"agent 纠错"还是"检索误导" |

---

## 2. 受测系统与条件

### 2.1 受测系统：`demo/`

- 入口：`python src/run_demo.py --input <batch.csv> [--json]`（候选检索）、`python src/lookup_case_logs.py --case-id …`（取历史观测）。
- 判定单元：demo 自身按 **`incident_id`** 分区；无 `incident_id` 的行落 `unassigned batch` 单 scope。**测试批次里每个 unit 必须带独立 `incident_id`**（否则一个批次会被当成一个 scope）。
- 匹配语义：steps 的 `action_regex` → 动作索引 → LCS 时序对齐（source 兼容为硬闸）→ 档位 `strong/medium/weak/keyword_only/none`。
- 排序：档位 → 非通用命中步数 → 命中步数 → source_fit_ratio → keyword_score → case_id。

### 2.2 记忆条件（受测 agent 可见的世界）

| 条件 | 可见 | 可调用 | 用途 |
|---|---|---|---|
| **M0** | 仅本批日志 CSV（中性文件名） | 无 | 模型先验基线 |
| **M1** | 同上 + `demo/src/run_demo.py`、`lookup_case_logs.py`、`demo/skills/attack-memory/`（工作流说明） | 检索 CLI（**不得直读 `data/attack_patterns.json`**；沙箱里该文件权限不可读或用 wrapper 代理） | 真实部署形态 |
| **M2** | 同上 + `memory_summary.md`（由 pattern 库生成的**摘要**：case_id / name / summary / 各步 label / mitre；**不含** steps 的 action_id、正则、顺序细节与任何排序） | 无检索 | 拆分"知识存在"与"检索机制" |

> 三条件共用同一 prompt 骨架，只替换"可用知识/工具"段；角色、输出 schema、禁止项逐字相同。

---

## 3. demo 数据重整的验收条件（你做数据面，我按此校验）

不满足任一条，实验结论不可用；我会写 `build_testset.py --check` 自动验收。

1. **pattern 数与家族数 ≥8，且每个案例 ≥3 步**（当前：8 个案例 / 8 个家族 / 45 行；单步案例档位恒为 strong、无区分度，已全部替换）。
2. **每个 pattern ≥1 个非通用步骤**（`generic:false`）—— 否则 demo 的档位闸门永远拿不到 `strong`（已知缺陷 6），正例 GT 不成立。
3. **`action_id` 全局唯一**（形如 `case039_s1_xxx`）。已知缺陷 2：同名 `action_id` 的正则会跨案例并集 → 不同案例互相误命中，消融结果会被污染。
4. **每个 pattern 的 `retrieval` 至少含 2 个 keywords 与 1 个 pattern_probes**，且 probes 能匹配其自身证据行（否则该 pattern 在 K 通道上恒为零，消融会低估 K）。
5. **每个 pattern 的 `expected_sources` 与其证据行来源一致**（source 兼容是硬闸，写错会让步骤永远不命中）。
6. **每个 incident 的 CSV 行**：`event_id` 唯一、`timestamp` 可解析（ISO8601）、`content` 非空、列数齐全（已知缺陷 7：短行会崩）。
7. **`case_id` 列只用于留档**：测试批的 CSV 必须**留空 `case_id`**（否则等于把答案喂进去）；`incident_id` 保留（demo 需要它分区）。
8. **fixture 与真实观测分开**：新建的变体行用独立 `batch_id`，关系表状态用 `fixture`，否则 `lookup_case_logs` 会把它们计成真实观测（已知缺陷 4）。

---

## 4. 测试集构造（D4 已确认：我建、你抽检 20%）

### 4.1 T1 正例：案例派生变体（10 个）

- 选 10 个**步骤数 ≥3** 的案例（覆盖 Web 入口 / 主机侧 / DNS 混合），排除只有单一通用探针的案例。
- 变异规则：**替换表层 token**（IP、域名、主机编号、路径段、参数名、账号、UA、端口），**保留**所有被 `action_regex` 命中的子串形态（如 `X-BEResource=`、`/ecp/<id>/ecp.aspx` 的形态）。
- **纳入闸门**：变体必须通过 `run_demo.py --json` 自检 —— 该 case 的 `matched_steps == total_steps`、`tier == strong`、`order_ok == true`；否则重生成（最多 3 次）。
- GT：`match(CASE-xxx)` + `expected_stages` + `expected_next_step`。

### 4.2 T2 负例：新家族（10 个）

- 来源：`dataset/data-1081-1100/1101-1120/1121-1140.txt`（勒索 / 域身份 / 供应链；与 29 案例相似度最高 0.31，实测全部应为 NEW）。
- 转成 demo CSV（每 unit 一个 `incident_id`，`case_id` 留空）。
- GT：`new`；次级信号 = 是否说出正确家族（勒索/AD/供应链），仅作质量描述。

### 4.3 T3 无关负例（可选，4 个）

- 正常 DNS 解析、`systemctl restart nginx`、健康检查等；GT=`irrelevant`。用于测"记忆是否制造虚假关联"。

### 4.4 T0 精确重复对照（不进主样本，只做正确性校验）

- 7 个入库 unit（1001/1021/1042/1061/1081/1102/1121）的**原始行原样**再作为未标注批次跑一次检索：期望 top1 = 对应案例、`strong`、`matched_steps == total_steps`、`order_ok == true`。
- 这是**检索正确性对照**（sanity check），不是"记忆有效性"证据：它证明"完全一致的案例能被完整召回"，用来给后续变体/残缺实验提供上界。
- 实测（已跑）：7/7 全部 `strong` 且全覆盖（3/3、4/4、3/3、4/4、3/3、3/3、3/3），order 可判且一致。

### 4.5 T4 回顾性对照（不进 agent 实验）

- `demo/data/raw_logs.csv` 里的 CASE-008 原始 8 行 + fixture 8 行：只跑检索层指标（已入库 = 训练集，喂 agent 会泄漏）。

### 4.5 GT 表与复核

`gt_units.json`：`unit → {kind, case_id, family, expected_stages, expected_next_step, variant_of}`。
我全量自检 + 你抽检 20%（建议抽 T1 的 4 个 + T2 的 4 个）。

---

## 5. 实验 A：可用性（RQ1/RQ2）· 20 unit × 3 条件 = 60 次

- 抽样：10 正例 + 10 负例（T2）；T3 4 条并入 M1 作为附加观察（不占主样本）。
- 每 unit 在 M0/M1/M2 各跑 1 次；unit 顺序、条件顺序随机化（固定 seed）；**每次运行独立子代理、独立上下文**。
- 输入：`batch_<n>.txt|csv`（只含该 unit 的行，文件名/内容不含 unit 号、家族名、`CASE-` 字样）。
- 输出 schema（强制）：

```json
{"verdict":"match|new|irrelevant","case_id":"CASE-0xx|null",
 "stages_observed":["..."],"expected_next_step":"...","confidence":1-5,
 "evidence_event_ids":["..."],"why":"<=120字"}
```

**指标**：Verdict Acc（主）、FalseMatch（T2 上给出 match 的比例）、Stage F1、NextStep Hit、Schema OK（门禁）、耗时/token。
**统计**：同一 unit 的 M0 vs M1 用 McNemar 精确检验；差值 + bootstrap 95% CI（按 unit 重抽 10000 次）；M1 vs M2 同法。分层报告（正例/负例）。

---

## 6. 实验 B：不完整证据（RQ3）· 12 unit × 2 版本 × 2 条件 = 48 次

| 版本 | 删除内容 | 期望观察 |
|---|---|---|
| B1 删中间步 | 时间序中间一条非通用行 | demo 应给 `gap_steps` + `predict_next`；agent 应指出缺口 |
| B2 删末步 | 最后一条 | `predict_next` 应等于被删步；agent 应预测下一步 |

（B3 删 rasp 行、B4 删 2 行作为扩展，各 +24 次，可选）

**指标**：Verdict Acc、Stage F1、**NextStep Hit（主）**、**过度自信率**（错但 confidence≥4）、以及检索层：档位变化（strong→medium/weak）、`predict_next.step_id` 是否等于被删步、`gap_steps` 是否命中。
**条件**：M0 / M1 各 1 次/版本。

---

## 7. 实验 C：通道消融（RQ4）· 纯离线，不调用 LLM

**demo 的真实通道**（按 `demo/src/attack_memory/retrieval.py`）：

| 代号 | 通道 | 权重/作用 | 实现位置 |
|---|---|---|---|
| A | 动作通道：`action_regex` 命中 → LCS 对齐 → 档位 | 主渠道；source 兼容为硬闸 | `extract_log_actions` / `_align_sequence` |
| A-gate | 动作的 source 兼容闸（`expected_sources`） | 决定某动作能否支撑该步 | `_align_sequence.compatible` |
| A-order | 时序检查（`order_ok`） | 只影响能否 `strong` | `match_pattern` |
| K1 | `retrieval.keywords` 语义关键词 | +3/个（去重） | `_keyword_score` |
| K2 | `mitre` 标签 | +2/个（词边界） | `_keyword_score` |
| K3 | `retrieval.pattern_probes` 正则探针 | +4/个 | `_keyword_score` |
| C | `incident_id` 分区（demo 的"链层"） | 决定 scope：按事件分组 vs 整批一个 scope | `run_demo.partition_logs` |

> 注意：**demo 的关键词通道只有 3 个子通道**（没有主线的 indicators/signature）；链层消融改为 `incident_id` 分区消融。

**条件矩阵**（对 T1+T2+T4 全量跑，秒级）：

1. `{A,K1,K2,K3,C}` 基线
2. `{K1,K2,K3}`（关动作通道 → 只剩 keyword_only 兜底）
3. `{A}`（关全部关键词）
4. `{A,K2,K3}`、`{A,K1,K3}`、`{A,K1,K2}`（逐个子通道关闭）
5. `{A,K1,K2,K3}` 但 **关 A-order**（测时序检查对 strong 的影响）
6. `{A,K1,K2,K3}` 但 **关 source 闸**（`compatible` 恒真，测来源约束的价值）
7. 关 C：把批次里所有 `incident_id` 清空（整批一个 scope），对比链归属正确率/碎片率

**指标**：
- `Recall@1/@3`、`MRR`（T1）
- `FalseMatchRate`（T2：给出 `strong`/`match` 的比例）——安全场景最关键
- `keyword_only` 兜底区的单独表现（K 是否只在"动作零命中"时有用）
- `PredictUsable`（能给出 `predict_next` 的比例）
- 关 C 时：链归属正确率、碎片率（同 unit 被拆）、跨 unit 误并率

**判读规则（先写死）**：
- 通道"必要"：关闭后 Recall@1 或 FalseMatchRate 恶化 ≥5pp 且 bootstrap CI 不跨 0。
- 通道"贡献"：ΔRecall@1 / ΔMRR + **唯一命中数**（仅该通道能找对的 unit 数）。
- 若关 K1/K2/K3 后 Recall@1 降 <2pp 且 FalseMatch 不变 → 判"对检索非必要"，但仍报告其在 keyword_only 子集的作用。
- 若 `A-order` 关闭后 `strong` 比例大幅上升而 Recall 不变 → 说明时序检查只是"档位收紧"，不是"候选筛选"。

**预期（允许被推翻）**：A 主导；K3（probes×4）> K1（keywords×3）> K2（mitre×2）；K 主要在并列排序与 `keyword_only` 兜底起作用；A-order 只影响档位不影响候选；source 闸影响"跨源同请求"的判定；C 影响链归属而非 case 匹配。

---

## 8. 实验 D（可选）：检索-判定一致性（RQ5）

对 M1 的每一次运行，比对 agent 的 `case_id` 与 `run_demo` 的 top1：
- 一致且正确 → 记忆经检索生效；不一致且 agent 正确 → agent 纠错（记 retrieval miss）；不一致且 agent 错 → **检索误导**（单独统计发生率，这是最需要警惕的失败模式）。

---

## 9. 执行协议（可复现性）

1. **沙箱**：每次 run 用独立只读副本 `eval/usability/sandbox/run_<id>/`；**禁止**读 `dataset/`、`eval/results/`、`history/`、`data/memory_store.json`、`data/batches/`。
2. **M1 防直读**：沙箱中不提供 `data/attack_patterns.json`（或用 0600 + wrapper）；只允许通过 `python src/run_demo.py` 检索。
3. **中性化**：批次文件名 `batch_<seq>.csv`；`case_id` 列留空；日志内容不含 `CASE-`、家族名、unit 号。
4. **独立上下文**：每 run 一个新子代理（deepseek-flash 钉定）；同一 run 只判一个 unit。
5. **只读校验**：run 前后对 `demo/data/*.csv`、`attack_patterns.json` 取 sha256，必须一致。
6. **记录**：`eval/usability/runs.jsonl`：`run_id, unit, condition, version, model, prompt_sha, started_at, duration_s, tokens, raw_output, parsed, retrieval_topk`。
7. **盲判**：判分脚本不读 `condition` 字段；先机械判分（verdict/case_id/next_step），阶段与理由按 rubric 由我打、你抽 20% 复核。
8. **重复**：主实验每条件 1 次；若条件间差异 <5pp，再抽 8 个 unit 各跑 2 次估方差。

---

## 10. 交付物

```
eval/usability_ablation/
├── build_testset.py        # T1 变体生成（含 strong 自检闸）+ T2/T3 转换 + 残缺版本
├── check_demo_data.py      # 第 3 节 8 条验收条件自动检查
├── gt_units.json           # GT 表
├── ablate_channels.py      # 7 类消融（含 A-gate / A-order / C）
├── harness/{run_protocol.md, run_one.py, score.py}
├── runs.jsonl              # 运行记录（含 prompt hash / token / 原始输出）
└── results/{report_usability.md, report_ablation.md, *.csv}
```

---

## 11. 里程碑

| 里程碑 | 内容 | 依赖 |
|---|---|---|
| M0 | 大纲定稿（本文件） | ✅ |
| M1 | demo 数据重整 + 8 条验收通过 | 你整理数据，我跑 `check_demo_data.py` |
| M2 | T1 变体 + T2/T3 转换 + GT 表（你抽检 20%） | M1 |
| M3 | 实验 C 消融全量 + 报告草稿 | M2 |
| M4 | 实验 A（60 次）+ 实验 B（48 次） | M3 |
| M5 | 汇总报告（统计、失败案例、局限） | M4 |

---

## 12. 效度威胁

1. **demo 数据由你重整、变体由我生成** → GT 是"设计出来的"，结论是"对该测试集的可用性"，不等于真实告警分布。
2. **子代理可能猜到是测试**（用户画像/环境痕迹）→ 尽力隔离，报告中声明。
3. **单模型、单次运行** → 不能外推到强模型或其它 agent。
4. **已入库样本 = 训练集** → 只做检索层回顾，不喂 agent。
5. **档位不可跨案例比较**：`strong` 要求"全覆盖 + 顺序一致 + 有非通用步"，步骤数不同的 pattern 之间 `strong` 的严格程度不同 → 报告里按案例分层，不混算。
6. **demo 已知缺陷会影响读数**（详见 `references/demo-audit.md`）：①对齐会吞掉同一步的第二条证据 → 阶段召回不能用 `evidence` 计数，要用 `unobserved_steps`/`gap_steps` + 原始批次；②同名 action_id 会跨案例并集 → 验收条件 3 必须满足；⑥全通用步骤拿不到 strong → 验收条件 2；⑦短行崩溃 → 输入 CSV 列校验。
7. **判定对 ≠ 分析对**：verdict 对但理由错要单列（用 `why` 抽样复核）。

---

## 附录 A：demo 里可直接复用的资产

| 资产 | 位置 | 用途 |
|---|---|---|
| pattern schema | `demo/data/attack_patterns.json`（CASE-029） | 数据重整的模板 |
| CSV schema | `demo/data/raw_logs.csv`（`event_id,batch_id,incident_id,case_id,timestamp,source,log_id,content`） | 测试批与 GT 表格式 |
| 检索/档位实现 | `demo/src/attack_memory/retrieval.py` | 消融挂点（A / A-gate / A-order / K1 / K2 / K3） |
| 分区逻辑 | `demo/src/run_demo.py::partition_logs` | C 消融挂点 |
| 历史观测查询 | `demo/src/lookup_case_logs.py` | M1 的"取历史证据"能力 |
| 工作流说明 | `demo/skills/attack-memory/SKILL.md` + `references/*` | M1 的 agent 指南（需检查是否泄漏答案） |
| 29 个案例原文 | `data/memory_store.json` | 重整 pattern 库的素材源 |
| 新家族负例 | `dataset/data-1081-1140.txt` | T2 |
| 既有审计结论 | skill `references/demo-audit.md` | 已知缺陷与判读口径 |

## 附录 B：指标与统计

- **Recall@k**：GT case 出现在排序前 k 的 unit 比例。
- **FalseMatchRate**：T2/T3 上给出 `match`（或 `strong`）的 unit 比例。
- **MRR**：`1/rank(GT)` 均值；未出现记 0。
- **McNemar**：只看不一致对（b=M0 错 M1 对，c=M0 对 M1 错），p = 2·P(X≤min(b,c))，X~Bin(b+c, 0.5)。
- **Bootstrap CI**：按 unit 重抽 10000 次，报告 Δ 的 95% 区间；不跨 0 才判有差异。
- **唯一命中数**：仅该通道命中、其余通道静默的 unit 数（不可替代性）。

---

## 13. 模型因子与天花板探测（v1.3 新增）

### 13.1 为什么不能只换小模型

"记忆是否有用"在**案例归属**上不是可争辩的问题：M0 没有案例库，不可能报出 `CASE-xxx`，天然 0 分；真正会被强模型压平的是**语义识别**（这是 Log4Shell 吗），而那恰恰不是记忆的价值所在。因此处理顺序是：先改指标/任务形态 → 再谈换模型。

| 指标 | M0 天花板风险 | 处置 |
|---|---|---|
| 攻击类型识别 | 高（强模型接近满分） | 降为背景指标，不进主结论 |
| 案例归属（CASE-00x） | 无（M0 必 0） | 主指标，但要防止"抄检索输出"：M1 的检索结果**抹掉 case_id/name**，只给 evidence/steps/tier |
| 新家族误匹配 / 弃权 | 中 | 主指标（记忆最该证明的价值） |
| 阶段补全 / 下一步预测 / 删行退化 | 低 | 主指标 |

### 13.2 新增两条臂

- **M1p（注入检索，不用工具）**：把 `run_demo --json` 的结果（去掉 case_id/name）直接放进 prompt，单轮判定。用于：① 拆开"工具调用能力"与"记忆使用能力"；② 弱模型可公平参与；③ 可用单轮 API/本地推理批量跑（秒级）。
- **R 基线（rule-agent，无 LLM）**：直接取检索 top1 作为判定。给出"记忆本身能拿多少分"的参照：若 M1p ≈ R，说明模型没加分；若弱臂 ≪ R，说明瓶颈在模型而非记忆。

### 13.3 模型可选（本机实测）

| 模型 | 位置 | 单次判定耗时 | 协议遵循 | 备注 |
|---|---|---|---|---|
| deepseek-flash（API） | Hermes 默认 provider | 5~15 min（子代理）/ 秒级（单轮） | 好 | 主臂 |
| deepseek-r1:14b | `F:\AI_Tools\models`（独立 Ollama 存储，需 `OLLAMA_MODELS` + 独立端口，如 11435） | ~31 s（CoT 进 `reasoning` 字段，`max_tokens` 需 ≥800） | 中（答案裹在 ```json 代码块里，需提取） | 弱臂候选，但推理能力不弱，可能仍天花板 |
| qwen2.5:14b | 同上 | ~17 s | **好**（直接输出合法 JSON） | 弱臂首选（协议噪声小） |
| gemma-2-9b | 默认 Ollama 实例 | ~3 s | 差（实测中文指令直接跑偏） | 仅作"极弱/协议失败"对照，不进主矩阵 |

硬件：RTX 4090 Laptop 16GB → 14B Q4 舒适；32B 放不下。注意 C 盘仅剩 ~7GB，模型目录须在 F 盘。

### 13.4 天花板探测（先跑这个，再决定换不换）

- 样本：8 个 unit（4 个近邻正例：同族但缺/换一个阶段；4 个新家族负例）。
- 条件：M0 与 M1p；模型：deepseek-flash 与 qwen2.5:14b（各 16 次，共 32 次单轮）。
- **调用方式（关键）**：M0/M1p/M2 一律用**直接模型调用**（单条 messages、无工具、无历史、temperature=0），不要用子代理——子代理有 shell 权限，可能读到 `data/memory_store.json` 或 `dataset/parsed_*.json` 里的标签，M0 会被污染。flash 需要 `DEEPSEEK_API_KEY`（本机未配置）；本地臂直接用 Ollama（11435）。
- 只有 **M1（要调检索工具）** 才用子代理，且必须在 `%LOCALAPPDATA%\Temp\` 下的**沙箱副本**里跑（见 §14）。
- 判据：M0 语义识别 ≥7/8 → 任务太简单，先加难度（近邻干扰 / 抹掉 case 标签 / 强制弃权）；M0 ≤5/8 → 天花板不存在，主实验用 flash，弱臂只做对照。
- 同时记录 R 基线分数，作为"记忆本身"的参照。

---

## 14. 不变性保证：实验期间不得产生新记忆

### 14.1 冻结清单（开工前记录 sha256，之后每轮与收尾各校验一次）

```
demo/data/attack_patterns.json      # 案例库（记忆本体）
demo/data/raw_logs.csv              # 观测（含 case_id 标签列）
demo/data/event_pattern_links.csv   # 关系表
eval/usability_ablation/case_id_map.json
```

写入 `eval/usability_ablation/freeze.json`。任一文件 hash 变化 → 立即停止，判该轮作废并记录原因。

### 14.2 运行沙箱（只放读路径，写入口从物理上不提供）

```
%LOCALAPPDATA%\Temp\usability\run_<id>\
├── src/run_demo.py                  # 检索（只读）
├── src/lookup_case_logs.py          # 取历史观测（只读）
├── src/attack_memory/__init__.py
├── src/attack_memory/retrieval.py
├── src/attack_memory/storage.py     # 含写函数但无调用入口
├── data/{attack_patterns.json,raw_logs.csv,event_pattern_links.csv}   # 设只读
├── skills/attack-memory/            # 工作流说明（示例 id 已中性化）
└── batch/batch_<id>.csv             # 本轮测试批次（case_id 留空）
```

- **不放**：`src/ingest_logs.py`、`src/manage_memory.py`、`attack_memory/ingest.py`、`attack_memory/manage.py`（实测 `run_demo`/`lookup_case_logs` 只 import `retrieval` + `storage`，因此删掉写入口不影响检索）。
- 只读加固：`icacls <sandbox>\data /deny "%USERNAME%":(W)`；跑完再 `icacls /remove:d` 清理。
- 每轮用独立目录，跑完即弃；不复制 `dataset/`、`eval/results/`、`history/`、`data/memory_store.json`。

### 14.3 每轮独立会话

| 条件 | 会话形态 | 上下文 |
|---|---|---|
| M0 / M1p / M2（直接调用） | 单条 `messages`（system+user），无历史 | 每轮新建，同一 unit 的三种条件互不可见 |
| M1（子代理） | 每次 `delegate_task` 新建会话 | 不跨 unit、不跨轮；子代理只看到沙箱 |
| R 基线 | 纯脚本 | 无模型 |

### 14.4 输出与记忆分离

- 判定的唯一落点是 `eval/usability_ablation/runs.jsonl`（`run_id/unit/condition/model/prompt_sha/raw_output/parsed`），**不进** `raw_logs.csv`、**不进** `attack_patterns.json`、**不进** `event_pattern_links.csv`。
- 不调用 `ingest_logs.py` / `manage_memory.py add-pattern` / `link-events`（沙箱里根本没有这些入口）。
- M2 的"oracle 记忆"只以 prompt 文本注入，不写任何文件。

### 14.5 违规判据（任一命中即该轮作废）

1. `freeze.json` 中任一 hash 变化；
2. `raw_logs.csv` 出现新 `event_id` 或行数变化；
3. `attack_patterns.json` 的 pattern 数 ≠ 8（或 case_id 集合变化）；
4. `event_pattern_links.csv` 行数变化；
5. 子代理输出里出现沙箱外路径（如 `F:/AI_Learning/AgentMemory/...`）的操作痕迹。

## 15. Stage 2 实测结果（2026-10-21，60 unit × 2 模型 × 2.5 条件 = 300 次单轮）

数据：`eval/usability_ablation/results/`（runs.jsonl / runs_summary.csv / report_stage2.md / stage2_sample_60.csv）。
样本分层：7 精确重复 + 29 同族变体 + 14 有弱候选新家族 + 10 无候选新家族。

| 条件 | 模型 | 归属正确 | 精确重复 | 变体/新案例过度确认 | 锚定率 | 平均置信 |
|---|---|---|---|---|---|---|
| assisted（带"非 strong 不得 match"提示） | qwen2.5:14b | 60/60 | 7/7 | 0/53 | 100% | 2.95 |
| assisted_free（无提示） | qwen2.5:14b | 43/60 | 7/7 | 17/53 | 100% | 2.98 |
| assisted_free（无提示） | deepseek-r1:14b | 33/60 | 7/7 | 27/53 | 68% | 2.68 |
| direct（无记忆） | qwen2.5:14b | 家族 19/34 | — | 编造编号 0/60 | — | 3.00 |
| direct（无记忆） | deepseek-r1:14b | 家族 25/34 | — | 编造编号 27/60 | — | 4.43 |

**结论（可直接引用的四条）**：
1. `strong` 档检索是确定答案：两模型在 7 个精确重复上全部正确归属。
2. 主要失败模式是**弱证据被当成确认**：qwen 32%、r1 51% 的"应变 new"案例被判 match，集中在勒索家族（CASE-005，共 8 例）与"同族不同向量"（JNDI/Exchange/Laravel 端点变体）。
3. **锚定率 100%（qwen）**：模型从不改选检索 top1，只做接受/拒绝 → 检索质量直接决定判断，模型不会纠错。r1 的 68% 里多数是"无候选时凭先验补位"（10 例在空检索上判 match），属更危险的行为。
4. **无候选时 qwen 10/10 保守**，说明"记忆不出现"比"给弱候选"更安全；给 weak 候选反而诱导误判。

**方法论教训**：
- 不要在消融 prompt 里写"档位非 strong 不得 match"——任务会退化成"读档位"，qwen 直接 60/60 满分（天花板）。必须同时跑无提示版本。
- 必须记录**锚定率**（case_id 是否等于检索 top1），否则会把"检索对了"误读成"模型判断对了"。
- `deepseek-r1:14b` 在无案例清单时会编造案例编号（`Ransomeware-2023-002`、`12345`、`XXXX-0001`），且置信度更高（4.43 vs 3.00）——弱模型不等于更保守。

## 16. 实验二：catalog（只给案例摘要、无检索）与 next-step GT（2026-10-22）

目录：`eval/usability_ablation/results/exp1_memory_vs_retrieval/`（实验一，300 次）、`results/exp2_catalog/`（实验二，120 次）；结构见 `eval/usability_ablation/README.md`。

**归属正确（严格 GT）**：

| 模型 | catalog（无检索） | assisted_free（有检索） | 配对不一致 | McNemar 精确 p |
|---|---|---|---|---|
| qwen2.5:14b | 45/60（宽松 53） | 43/60（宽松 55） | 仅 catalog 对 8 / 仅检索对 6 | 0.79（不显著） |
| deepseek-r1:14b | 24/60（宽松 47） | 33/60（宽松 53） | 仅 catalog 对 1 / 仅检索对 10 | **0.012** |

结论：**检索的增益依赖模型**——对 r1 有实质帮助（+9，p=0.012），对 qwen 无增益（−2，n.s.），且在变体层把 qwen 的判 match 从 10 条推到 14 条（锚定导致的过度确认）。两个模型在 catalog 下都是 7/7 精确重复——**完整一致的案例不靠检索也能归属**。

**next-step（GT：`gt_next_phase_60.json`，60 条 × 2 个可接受阶段，关键词近似映射）**：

| 条件 | qwen 平均分 / 单点 | r1 平均分 / 单点 |
|---|---|---|
| direct（无记忆） | 0.65 / 13 | 0.71 / 13 |
| catalog | 0.66 / 19 | 0.68 / 19 |
| assisted（带提示） | 0.66 / 20 | — |
| assisted_free | 0.58 / 16 | 0.64 / 17 |

结论：**粗粒度的"下一阶段"预测没有从记忆中获益**（direct 已经 0.65~0.71）。原因是 GT 只到杀伤链阶段，靠通用常识即可作答。要测"记忆补全缺失步骤"的价值，必须做**步骤级 GT**（哪些 step 被覆盖、缺哪一条、下一步应出现哪个来源），而不是阶段级。

## 17. v1.5 后续补充：无记忆配对对照与通道消融

本节只规定后续分析和新增实验；§15 的 Stage 2 与 §16 的 catalog/next-phase 结果、原始输出和既有口径均保留，不要求重跑或改写。现有 `direct` 已包含“只给攻击日志”的模型运行，但它与 assisted 的主要输出目标不同，因此此前的家族命中/案例归属数字不能直接回答“记忆是否改善模型判断”。优先复用现有日志计算共同指标；只有输出或 GT 不足时才另开一轮，放入独立结果目录并标注为补充实验。

### 17.1 比较条件与问题拆分

| 条件 | 提供给模型 | 能回答的问题 |
|---|---|---|
| **M0 / direct** | 仅本 unit 的攻击日志；不提供案例库、检索结果或案例编号 | 无记忆时模型对攻击家族、已观察阶段和下一步的基线判断 |
| **M2 / catalog** | 同一日志 + 未排序的案例摘要；不提供检索结果 | 加入案例知识本身是否改善共同分析指标 |
| **M1p / assisted-free** | 同一日志 + 案例摘要 + 预计算的检索证据；不提供工具调用 | 在已有案例知识上，检索证据是否带来增量 |
| **M1-tool（可选）** | 同一日志 + 只读检索 CLI | 实际工具调用与预计算证据之间的差异 |

现有 §15–§16 的 `assisted_free` 是**预计算检索证据注入**，按条件应称 M1p；不能将其当成 agent 自主调用检索工具的 M1。既有结果保留原名称以便追溯。分析时分别比较 M0↔M2（记忆知识增量）、M2↔M1p（检索增量）、M0↔M1p（整套记忆路径的总增量）。M1-tool 作为独立后续问题，不与前三个条件混算。

### 17.2 共同任务、指标与判定

- 同一模型、同一 unit 在各条件下使用相同的日志、提示骨架与 JSON 字段；每轮独立上下文、`temperature=0`。共同字段至少包括 `family`、`stages_observed`、`next_step`、`confidence`。M1p/M1-tool/M2 可额外输出 `verdict` 和 `case_id`；**M0 不要求猜测或填写不存在于其上下文中的案例编号**。
- **主要共同指标**：步骤级下一步命中（由 §17.3 冻结的 GT 判定）；**次要指标**：观察阶段 F1、攻击家族归一化准确率、证据是否支持结论、错误 match/过度确认率。案例归属准确率只比较 M2、M1p、M1-tool，不能把 M0 的“没有可选案例编号”记作错误。
- 先用同一批 unit 做配对比较，按 unit 报告差值与 95% bootstrap 区间；二元准确率同时报告配对 McNemar 精确检验。模型分别报告，不跨模型合并。多项指标/多通道的推断性检验使用 Holm 校正；未校正结果标为探索性。
- 只有共同指标上的配对提升支持“记忆改善模型分析”；仅案例编号命中提升支持“记忆提供了案例归属能力”，不能替代共同指标。提升还需与误匹配率、置信度错配和分层结果并报。
- 现有 `direct` 输出曾包含 `known_case` 字段，虽然没有提供案例库，会诱发无依据的编号填写。既有原始结果不改；未来 M0 提示删除此字段，历史 `claims_case` 只作为该提示设计下的探索性观察，不计入无记忆主指标。

### 17.3 GT 复核与 next-step 口径

- 在看模型输出前，由两名复核者独立把 `family_variant` 拆分为 **same-pattern variant**（同一可复用模式，GT 为 match/对应 case）与 **novel pattern / same-family**（仅家族相近，GT 为 new）；不一致时先仲裁。无法确定的标为 `ambiguous`，不计入案例归属主指标，但仍可参与有明确步骤 GT 的阶段与下一步比较。
- `next_phase` 的文本关键词近似映射和 `needs_review` 标签只保留为探索性背景结果。正式判断记忆是否改善下一步推断，应使用已有 `gt_step_level_60.json` 中逐 unit 的观察步骤、缺失步骤、下一步步骤及可接受来源；模型输出在揭盲前按冻结的同义词/动作映射表评分。GT 文件及评分映射保存版本号与 hash。
- 报告分层给出 exact、same-pattern variant、novel same-family、novel other-family、无候选；同时给 n 和区间，避免 7 个 exact 对总分产生过度影响。

### 17.4 通道消融修订

- A/K1/K2/K3 的消融仍为纯离线配对实验：固定同一测试 unit、记忆库、scope 与排序规则，每次只改变指定通道。至少报告 T1 的 Recall@1/@3、MRR，以及 novel 样本上的 strong/medium 误匹配；同时报告弱候选率、keyword-only 命中与各分层结果。K1/K2/K3 的 leave-one-out 用于估计边际影响；“仅该通道唯一命中”作为补充，不单独等同于因果贡献。
- **A-order 与 A-gate 不能只看 tier。**时序和来源闸会改变候选档位，而档位参与候选排序，因此两项消融都要同时报告 tier 分布、Recall@k/MRR 和误匹配，不能预设其“只改变档位、不改变候选排序”。
- 通道是多个同一批 unit 上的配对比较；按 unit 做 bootstrap，预先指定主指标，多个通道检验做 Holm 校正。若样本量不足以支持稳定区间，报告效应量与区间并称探索性，不用单个阈值宣称通道“必要/非必要”。
- **C（`incident_id` 分区）单列为 scope/事件切分压力测试，不当作检索通道。**输入必须是包含多个已知独立 incident 的混合批次，所有事件共用同一 `batch_id`、各自保留不同 `incident_id`；对照组只清空 `incident_id`，不得拆成“一文件一个 unit”。测量跨 incident 误并率、事件分区准确率及混合后 case 检索变化。单 unit 文件上清空 `incident_id` 不产生有效对照，应标为不可测。

### 17.5 执行顺序

1. 先用现有 M0/direct、M2/catalog、M1p/assisted-free 原始输出，对共同字段做盲评重算；保留现有报告，新增版本化的配对分析表。明确标注当前 next-phase GT 的关键词映射限制。
2. 先冻结并复核 same-pattern 与 novel-family GT、步骤级 next-step 同义映射；如历史输出不能按统一口径评分，再只补跑缺失条件，不覆盖既有 runs。
3. 再执行 A/K 消融；C 另用多事件混合批次执行。完成后报告各自适用的结论，不把 scope 测试与检索排序消融合并。

## 17. 实验三：残缺日志上的补全与下一步来源（2026-10-22，qwen2.5:14b，282 次）

GT：`gt_step_level_60.json`（步骤划分机械生成，7 个入库案例步数 3/4/3/4/3/3/3 与库内一致；del1=删中间步、del2=删中间+末步）。
口径：`下一步来源(覆盖)` = GT 来源 ⊆ 模型所给；`全等` = 完全一致；gap 判对 = 是否报告缺口且与 GT 一致。

| 条件 | del1 n=54 gap / 覆盖 | del2 n=40 gap / 覆盖 |
|---|---|---|
| direct（无记忆） | 51 / 33（61%） | 38 / 30（75%） |
| catalog（摘要无检索） | 47 / **43（80%）** | 37 / **34（85%）** |
| assisted（摘要+检索） | 49 / 40（74%） | 36 / 33（83%） |

**结论**：
1. **"有没有缺口"不需要记忆**：direct 已 94~95% 判对，加记忆反而略降（87~91%）——模型会因案例模板而倾向于认为链路完整。
2. **"缺的是哪一步、下一步该出现哪个来源"需要记忆**：catalog 比 direct 高 19pp（del1）和 10pp（del2），这是目前唯一测到的记忆正向作用。
3. 检索证据在这一点上仍然无增益（74% < 80%），与实验二的结论一致（锚定）。
4. 来源"全等"几乎为 0：模型总是多报 1~2 个可能来源，说明该项应按"覆盖"而非"全等"计分。

**家族层判断准确率（36 个有 GT 家族的 unit，同一口径）**：

| 条件 | qwen2.5:14b | deepseek-r1:14b |
|---|---|---|
| direct（只给日志，无任何参考） | 19/34 = 56% | 25/34 = 74% |
| +8 条案例摘要 | **33/34 = 97%** | 30/34 = 88% |
| +摘要+召回 | 32/34 = 94% | 30/34 = 88% |

→ 这正是"加一套辅助参考是否提升判断准确率"的答案：**提升很大（qwen +41pp，r1 +14pp），但增益来自案例摘要而不是检索**。

# 动作匹配检索器指南（v2.1：动作匹配 + 攻击链层）— 攻击检测 Agent 记忆机制验证

> 本文件是当前**最新版方法流程指南**。旧版（关键词双通道打分 v1；链层前的 v2）已归档至 `history/`（`old_` 前缀），保留可运行作对照，不再作为现行方法。
> **运行手册（每次分析日志都要走）**：skill `security-log-case-memory` 的 `references/runtime-playbook.md`（检索输出读法 / 判定决策表 / 已知边界 / 速查命令）；写案例见同 skill 的 `references/case-write-spec.md`；开发与升级见 `references/upgrade-playbook.md`。
> 设计依据：`docs/ACTION_SEQUENCE_MATCHING.md`、实体模型两篇（`docs/ENTITY_EXTRACTION_RETRIEVAL.md`、`docs/ENTITY_VS_CASE_GRAPH.md`）、链层方案与实现记录 `docs/MULTI_LOG_CHAIN_DESIGN.md`（§12）。

---

## 一、机制总览

**核心设想**：每个攻击以**形式化的动作链**存储（攻击链阶段序列细化为"去变量的动作指令"），检索时以**动作序列匹配为主 + 关键词匹配为辅**，并在 v2.1 把判定单元从"单行"升级为"批内攻击链"。

| 层 | 角色 | 内容 |
|---|---|---|
| **动作通道**（主，v2） | 结构化匹配 | 动作库正则识别日志行中的动作 → 反向索引取候选案例 → 案例动作序列位置对齐 → 完整/前缀/中段/缺口四类匹配 + **下一步动作预测** + **分叉相似案例** |
| **关键词通道**（辅，v1 保留） | 兜底 + 并列排序 | `retrieval_keys`(×3) / `mitre`(×2) / `indicators`(×2) / `signature`(×1) + `pattern_probes`(×4)，跨通道 token 去重 |
| **链层**（v2.1，判定单元） | 多日志关联 | 批内行 → 候选链（组装：会话/实体/同请求跨源并发/载荷模板 + 时间窗 + 阶段校验）→ **链整体匹配**（复用行级对齐 + 来源槽位校验 + 顺序一致性）→ 链级判定与预测 |

**判定单元 = 链**：`python src/retrieve.py --chain <批次>` 给最终判定；`--batch` 的行级结果降级为**分诊提示**（两者在链级输出里并列）。组装只做**候选生成**（机械、确定性），链归属由 Agent 确认（可拆可并）。详见 **§九**。

关键设计（源自可行性分析结论）：

1. **动作 = 去变量的指令/行为模板**：`wmic /node:<ip> process call create`、`ssh -i <keyfile>`、`DGA 随机子域查询`。变量（IP、文件名、域名）不参与匹配，基础设施更名后仍可召回（如 DGA 换域）。
2. **案例仍为完整单元，以动作为索引**：案例不拆散，`action_sequence` 按攻击链顺序引用动作库中的动作 id。检索时现建反向索引（动作 → 案例），零外部依赖。
3. **停止条件 = 最长可观察重合**：不"匹配到最短重合就停"，而是返回命中路径上的所有案例 + 标注匹配深度，前缀案例不被完整案例遮蔽，未观察的下一步动作变成**预测**（链级还带**预期来源**）。
4. **单行日志 = 单链片段**：一条日志行通常只暴露攻击链的一段（WAF 行见入口、HIDS 行见主机侧），动作对齐天然表达"链中段/缺口"视角，不要求每行完整命中。
5. **缺失/跳步不扣分**：`matched` 只数"命中且来源可接受"的位置；`完整` 是唯一通向强档的形态，缺口（如 2/4）仍为中档 —— 档位是**置信度刻度**，不是分数。

## 二、记忆结构（`data/memory_store.json`）

```jsonc
{
  "cases": [ /* 案例实例，schema 见下 */ ],
  "action_library": { /* 动作 id -> {label, regex, generic, stage} */ },
  "activity_patterns": [ /* 跨案例活动模式【实验性子层】，观察级置信度 */ ]
}
```

**案例字段**：

| 字段 | 说明 |
|---|---|
| `id` / `source` / `attack_type` / `kill_chain` / `mitre` / `indicators` / `signature` / `reasoning` | 人工写（Agent 产出）；`reasoning` 记录判定链条与"证据从严"声明 |
| `retrieval_keys` / `pattern_probes` | 供**关键词通道**使用（判别性红线：系统路径 `/etc/*`、`/bin/*`、`/var/spool/*`、`/dev/tcp` 不作键） |
| `action_sequence` | **v2 新增**：按攻击链顺序的动作 id 列表 —— **由脚本注入**（`scripts/build_action_index.py` 的 `SEQUENCES`），Agent 不手写 |
| `action_sources` | **v2.1 新增**：每个动作步的**观测来源**（`["waf","web"]` / `"hids"` / `"any"`）→ 供链级**来源槽位校验**（观测层不符 → `◐`，不计入匹配计数）；**由脚本注入**（`SOURCES`，证据推导见 `scripts/derive_action_sources.py`） |

**动作库条目**：`action_id -> {"label": 去变量后的动作名, "regex": 结构正则, "generic": 是否通用探针, "stage": 杀伤链阶段}`

- 共享动作（`cmd=id` 探针、`echo;id`、`java 序列化魔数 rO0AB` 等）跨案例复用——复用本身即案例间相似性的来源（分叉参考）。
- `generic=true` 标记通用探针（whoami / cmd=id / echo;id / id;hostname 等）：**不参与**链层模板/并发并链信号，单发命中仅作弱参照，不单独支撑结论。判别性由**序列位置**提供，不由单动作提供。
- `stage` 取值域：`recon / initial_access / execution / privilege / persistence / lateral / c2 / exfil`，供组装层**阶段校验**（回退 ≥2 档且实体不同 → 切链）。
- 数据红线：`action_sources` 与 `stage` 两列**只由脚本写入**（derive → build）；手改会被下次运行覆盖。

## 三、检索协议（每批日志标准流程第一步）

```bash
# 单条检索（行级）
python src/retrieve.py "ssh -i /tmp/.key -o StrictHostKeyChecking=no root@10.20.8.183 \"id; hostname\""

# 批量检索（逐行；分诊）
python src/retrieve.py --batch data/incoming_logs.txt

# 链级检索（判定单元；组装 + 链整体匹配 + 行级分诊并列）
python src/retrieve.py --chain data/incoming_logs.txt
```

### 动作通道匹配形态（对齐算法）

对一条日志行：① 动作库正则识别出现的动作（按行内位置排序）；② 反向索引取候选案例；③ 每个候选案例做**位置对齐**——观察到的动作落在案例序列的哪些位置：

| 形态 | 定义 | 档位 | 附加输出 |
|---|---|---|---|
| **完整匹配** | 序列所有位置连续全命中（n/n） | 强 | — |
| **前缀匹配** | 从链头连续命中，未到链尾 | 中（命中≥2）/ 弱（命中 1） | **预测下一步**：链上未观察的第一个动作 |
| **中段匹配** | 连续命中但未含链头 | 同上 | 前段未观察动作列表 + 预测下一步 |
| **缺口匹配** | 命中位置不连续 | 同上 | 缺口（未观察的中间动作）列表 |

- **候选数量**：行级会把动作通道命中的案例**全部列出**（无上限），只关键词命中的另列"关键词兜底区"；每条候选附最多 **3 个分叉参考**（同一行还命中哪几条案例）。链级算法算全部候选，`show_chain` 默认**打印前 3 条**。
- **分叉参考**：命中案例之外，与本次观察共享动作的其他案例；列出但不并入结论。
- 排序键：档位 → 命中数 → 关键词分 → 覆盖度 → 案例号（关键词分优先于覆盖度，防短链案例在弱档并列时压过长链正确案例）。

### 判读规则

- 动作通道：完整 = 强档（含 1/1 单动作案例，如 DGA）；命中 ≥2 = 中档；命中 1 = 弱参照（按噪声处理，尤其 `generic` 动作单发）。
- 关键词通道兜底：强 ≥6 / 中 4–5 / 弱 ≤3（弱按噪声处理）。**关键词强分但动作通道为空 ≠ 匹配**（该通道只做兜底分诊）。
- 字段重叠**不重复计分**：`keyword_score` 用 `seen` 集合逐通道扣减（keys/mitre/ind/sig 之间去重）；唯一真重复是 `pattern_probes` 不参与去重。实测边际价值：动作通道在任何关键词变体下不变（123/123 · 强档 60），关键词通道整体只值 **3 行**兜底排序（`signature` 1 行、`probes` 权重档 0 行）→ **不要为"重复"删字段**（详见 §五 与 skill `upgrade-playbook.md` §3.1）。
- **弱档模板再现 ≠ 新案例**：当批次行只共享一个通用探针、且该探针正是既有案例序列第 1 步时，按"弱档模板再现 / 待观察"处理；不因"候选链未闭合"就新建案例（实例见 `eval/results/report_unseen_unit10_blind_test.md`）。
- 无动作命中且无实质关键词命中 → 【新案例】。
- 分析结论对检索支撑显式标注 `[检索: CASE-xxx]`，无实质命中标【新案例】。

### 输出示例

```
== 查询: wmic /node:10.20.6.179 process call create "cmd.exe /c whoami"
   [动作] 识别: WMIC 远程进程创建 (wmic /node:<ip>) → whoami 侦察探针
   [动作] [CASE-001] 前缀匹配 2/4（中）横向移动 / 远程命令执行 (WMIC)（载荷演进：侦察 → 持久化）
        - 链: ●1.WMIC 远程进程创建  ●2.whoami 侦察探针  ○3.创建后门账户  ○4.账户加入本地组；预测下一步: 创建后门账户 (net user /add)
        - 关键词: score=17(强) keys×3: wmic,whoami,process call create; probe×4: wmic\s+/node:
```

## 四、提取流程（每批日志：落盘 → 检索 → 判断 → 提取 → 验证）

0. **核对批次来源（先做）**：按 `log_id` 精确搜 `dataset/parsed_*.json` 与 `dataset/*.txt` —— 该批次可能就是某个**已标注单元**的复现/变体（此时应比对人工期望，而非当成新形态）；来自前瞻批的期望在 `history/old_eval/run_recall_unseen.py`。
1. **落盘**：日志原文逐行写入 `data/incoming_logs.txt`（保留截断原样）。
2. **检索**：`--batch`（分诊）+ `--chain`（判定），判读见 §三与 §九。
3. **判断**：**以链级为最终单元**标注 `[检索: CASE-xxx]` / 【新链案例】/ 无关；行级只作提示。弱档（尤其通用探针单发）按噪声处理。
4. **提取**（严格按 skill `references/case-write-spec.md` 的**五处写入 + 顺序**）：
   - ① 案例本体 → ② `ACTIONS` → ③ `STAGES` → ④ `SEQUENCES` → ⑤ 在 `scripts/derive_action_sources.py` 的 `BATCH_EVIDENCE` 登记「批次文件 + 该批 log_id→案例」→ 跑 `python scripts/derive_action_sources.py`（生成 `SOURCES`）→ 跑 `python scripts/build_action_index.py`（注入 + 校验，幂等）。
   - 合并 vs 新建：同路径/同指纹/同工具链 → **合并强化**（追加 targets/domains/IPs、观测次数、差异标注）；同链不完整观测（前缀）→ 并入原案例为观测条目；技术不同（即使同家族）、后续动作不同（分叉）→ **新建**。
5. **动作入库门禁**（沿用判别性红线）：
   - 动作正则只锚定特有结构（技术指纹/编码形态/完整路径模板），禁止通用命令与通用路径（`;id`、`/etc/passwd`、`/bin/sh`）单独作动作；
   - 正向：命中该案例所有已知观测行（**在其自身证据行上必须命中**）；反向：不命中负样本、**通用样板行、前瞻 GENERIC/NOVEL 行**；改后跑 `python eval/run_action_recall.py` 回归。
   - 实测反例（勿重蹈）：HIDS 进程链格式（`cat /etc/passwd … <== /bin/sh -c … <== <父进程名>`、`/bin/(dash|sh|bash) -c`）已存在 **20 条同格式通用行**（dataset 10 + 921-930 GENERIC 10），按门禁**不可作动作**。
6. **批次留档**：判定为入库后，把该批复制到 `data/batches/<日期>_<主题>.txt` 并在 `BATCH_EVIDENCE` 登记**该副本路径**（`incoming_logs.txt` 会被下一批覆盖，直接指它会让已入库案例的来源证据失效）；`data/batches/README.md` 说明各文件与用法。
7. **验证**：`python eval/run_action_recall.py` + `python tests/test_chain_assembly.py` + `python tests/test_chain_integration.py`（动过库/脚本/代码才跑），基线数字必须不变；一把梭用 `python skills/security-log-case-memory/scripts/check_gates.py`。
8. **证据从严**：只记录日志可见内容，不夸大（如"仅见 LFI 阶段，无后续载荷证据"）。

## 五、评测与回归

```bash
python eval/run_action_recall.py                          # v2 全量召回审计（重放 + 前瞻）→ eval/results/report_action_recall.md
python skills/security-log-case-memory/scripts/check_gates.py   # 门禁一把梭（行级 + 链级 + 乱序 + 解析完整性）
python history/old_eval/run_recall_full.py                # v1 旧评测框架（归档对照用，仍可运行）
```

**当前成绩（行级 v2 口径，2026-10-15 复核）**：

| 口径 | 成绩 |
|---|---|
| 已入库重放（133 行 = 特征行 123 + 通用样板行 10，回顾性） | 组合 Top-1 **122/123（99%）** · Top-3 123/123 · 动作通道命中 **123/123（100%）** · 动作强档（完整匹配）60/123 |
| 档位×召回（特征行） | 强 60/60 · 中 36/36 · 弱 26/27（唯一非 Top-1 即下条歧义行） |
| 形态分布（特征行） | 完整 60 · 前缀 41 · 中段 13 · 缺口 9 |
| 前瞻批 data-921-930（未入库，40 行） | KNOWN 21：Top-1 21/21 · 动作通道 21/21；SHARED 6/6 相关案例进入动作通道；NOVEL 3 行：动作通道 0 中/强档；GENERIC 10 行：动作误命中 0/10 |
| 负样本 9 条（v1 留档） | 动作通道 9/9 静默 |

- 唯一非 Top-1：`911-920-3-3` F5 rasp 行——截断后仅剩共享探针 `cmd=127.0.0.1;id`，CASE-010 排第 1、CASE-011 排第 2（v1 同行的已知歧义，目标仍在 Top-3）；**接受现状，勿调分**。
- 说明：动作强档 49% 属预期——单源日志行天然只暴露链片段（WAF 行=前缀、HIDS 行=中段），完整匹配主要出现在多阶段同行的批次。
- 关键词通道边际（变体实测）：去 `signature` 通道 → Top-1 121；`pattern_probes` 不计分 / 权重 4→2 → 122 不变；关键词通道整体关闭 → 119。动作通道在所有变体下不变。

**链级口径（v2.1 实测）**：见 §9.5。

**报告留档**：`eval/results/report_action_recall.md`（行级召回审计）· `report_deployment_agent_test.md`（部署场景测试：Flash 子代理判定 12/12）· `report_unseen_unit10_blind_test.md`（前瞻单元复核 + 盲测对照 + 新动作门禁实测）。

## 六、已知边界（诚实标注）

1. **严格顺序假设**：`action_sequence` 为严格先后；真实攻击中侦察/发现可能交错，届时升级为子序列/序列对齐匹配。
2. **单行单片段假设**（行级）：每行只做一次动作识别+对齐；跨行时序关联在 v2.1 由链层承担，跨批次仍不串链。
3. **分叉建模近似**：案例内多写法（如 CASE-021 的 sed/echo 两写法）以线性序列近似表达，检索时以"中段匹配+前段未观察"呈现；Trie 真分叉（独立案例）由提取准则保证。
4. **动作库覆盖率**：动作库由案例证据归纳，库外动作无法识别——NOVEL 行依赖关键词通道兜底（弱档）与人工判断，这正是"前瞻测试"的检验对象。
5. **链层组装是批内的 + 抗粘连优先**：同秒/同 URI/同参数的三层观测，若**唯一共享动作是 generic**，组装**不会**并链（信号 2.5 要求至少一侧有非通用动作）→ 退化为多条 singleton，链归属交 Agent 人工确认。实测案例与"暂不放宽"的取舍见设计文档 §12 未修复项 4。
6. **弱档模板再现不算新案例**：只共享一个入口通用探针、判别性后续阶段全缺时，按"模板再现 / 待观察"处理（纪律已写入 skill；反面实例见 §五 报告）。
7. **新增案例/动作会反向影响前瞻基准**：若新动作使某前瞻 KNOWN 行改判到新案例，须同步更新 `history/old_eval/run_recall_unseen.py` 的期望标注，否则前瞻指标失真——新增前先用沙箱对照量化影响面。

## 七、目录结构

| 路径 | 说明 |
|---|---|
| `GUIDE.md` | 本指南（现行方法） |
| `README.md` | 项目总览与快速开始（成绩数字以此处与 GUIDE 为准，两处同步） |
| `src/retrieve.py` | 动作匹配检索器（行级：动作通道 + 关键词通道；链级：`chain_match()` + `--chain`） |
| `src/chain_assembly.py` | **链组装层**（键聚类/并发/模板/窗口/阶段校验，确定性候选生成；参数在文件顶部常量） |
| `scripts/build_action_index.py` | 动作库（`ACTIONS`，含 `STAGES`）/序列（`SEQUENCES`）/来源（`SOURCES`）注入与校验（幂等） |
| `scripts/derive_action_sources.py` | `action_sources` 标注的证据推导（dataset 期望行 + `BATCH_EVIDENCE` 批次登记 + `OVERRIDES` 覆盖） |
| `data/memory_store.json` | 案例库（cases + action_library + activity_patterns） |
| `data/incoming_logs.txt` · `data/batches/` | 批次落盘位；`data/batches/` = 已入库批次留档 + 参考样例（`CASE-029_ProxyLogon_原样本.txt`）+ 说明 `README.md` |
| `eval/run_action_recall.py` | v2 召回审计（重放 + 前瞻）→ `eval/results/` |
| `eval/fixtures/` | 链级 fixture（数据集扁平化）与生成脚本 `gen_chain_fixtures.py` |
| `tests/` | 单测/集成测试（stdlib unittest：组装层 43 条 + 链级集成 14 条） |
| `skills/security-log-case-memory/` | skill 仓库内副本：`SKILL.md` + `references/`（运行手册 · 写规 · 升级手册 · 生产适配）+ `scripts/`（门禁） |
| `docs/` | 设计文档：`MULTI_LOG_CHAIN_DESIGN.md`（链层方案 + §12 实现记录/偏差/边界）、`ACTION_SEQUENCE_MATCHING.md`、`ENTITY_*.md`、`LOG_SCHEMA_ADAPTATION.md` |
| `history/` | **归档区**：v1 实现 `old_retrieve.py`、v1 文档 `old_*.md`、v1 评测框架 `old_eval/`（补丁后仍可运行）、链层前留档 `old_GUIDE.md`/`old_retrieve_v2_linelevel.py`/`old_build_action_index_v2.py`/`old_memory_store_pre_chain.json` |
| `dataset/` | 原始日志批次（data-901-910 ~ data-921-930）+ 解析存档 |
| `log-schema/` · `Agent记忆产品落地-调研/` | 生产字段字典（gitignore）、产品落地调研（独立于本流程） |

## 八、从 v1 / v2 迁移的说明

- 案例数据（**29 案例**全部字段）原样保留，仅新增 `action_sequence`（v2）与 `action_sources`、动作库 `stage`（v2.1）。
- v1 打分逻辑整体保留为关键词通道，跨通道去重版（#4）、结构化组件（#2）、B2 字段设计等修复成果全部继承。
- v1 遗留待议事项（关系图决策、gold 复核、`indicators` 字段拆分）见 `history/old_PENDING.md`、`history/old_GRAPH_DECISION.md`，未在本版处理。
- 链层前留档（`old_GUIDE.md` 等）仅供对照；现行流程以本文件 + skill 运行手册为准。

## 九、链级检索（多日志攻击链层）

> 状态：**已实现并作为判定单元**——`--chain` 给最终判定，行级 `--batch` 为分诊提示。设计文档 `docs/MULTI_LOG_CHAIN_DESIGN.md`（实现记录、偏差与边界见其 §12；审查修复见 §12.7）。

### 9.1 机制

现实攻击 = 一次攻击多条日志（WAF 见入侵、RASP 见执行、HIDS 见提权/持久化、DNS 见 C2），行级"独立事件"是实验期理想化。链层在既有行级检索之上**加一层**（行级函数一行未改）：

```
日志行
 ├─ 行级动作抽取（复用 match_actions）
 │    ├─ 行级检索 retrieve()  → 【降级为分诊提示】
 │    └─ 链组装 assemble_chains()【新】→ 候选链
 │         └─ 链级匹配 chain_match()【新：复用 align_case + 来源槽位校验 + 顺序一致性】
 │              └─ 链级判定：完整/前缀/中段/缺口 + 预测(动作+来源) + 证据行
```

组装只做**候选生成**（机械、确定性），链归属最终由 Agent 确认（可拆可并）。

### 9.2 组装信号（可靠性排序）

| 优先级 | 信号 | 判定 |
|---|---|---|
| 1 | 会话/关联 ID | 相同 `session_id` 等键 → 确定性同簇 |
| 2 | 实体连续性 | 共享端点（IP / 完整主机名，去通用清单）→ 同簇 |
| 2.5 | **同请求跨源并发** | 不同来源 + Δt≤30s（**窗内滑窗两两配对**，不要求相邻）+ 共享动作 **或** 同 URI 路径（规范化后相等） + **至少一侧有非通用动作** + 实体不冲突 → 中置信候选（补"某层载荷被截断只剩通用探针"的碎片） |
| 3 | 载荷模板跨层一致 | 仅**非 generic** 动作：**跨源用 3600s 宽窗、同源仅 300s 紧邻窗**（同源模板重叠属弱证据，防同源噪声粘连） |
| 4 | 阶段校验 | 杀伤链阶段回退 ≥2 档且相邻行实体不同 → 切链；实体相同/会话键分组 → 只标"待确认" |
| 5 | 时间窗 | 默认 3600s，仅宽松过滤，**不作主信号** |

参数默认值集中写在 `src/chain_assembly.py` 顶部（`WINDOW_S` / `CONCURRENT_S` / `CONCURRENT_LINK_S` / `TEMPLATE_LINK_S` / `TEMPLATE_SAME_SRC_S` / `STAGE_TOLERANCE`，待真实数据校准）。

### 9.3 命令与输出

```bash
python src/retrieve.py --chain data/incoming_logs.txt   # 链级：组装 + 链级匹配 + 行级分诊并列
python src/chain_assembly.py data/incoming_logs.txt     # 只看组装（调试视图）
```

输出要点：每条链给 行证据列表 / `已重合`（`●`命中 `◐`来源不符 `○`未观察，带观测来源与预期来源）/ `预测下一步 [预期来源]` / 证据行 / 链内关键词合计 / 行级分诊；前缀·中段链标 `⚠ 链未闭合 → 攻击进行中` 并提示"按预测来源补证据"；顺序倒置标 `⚠ 顺序异常（已降档）`；`⚑` 提示低置信拼接。

### 9.4 判读规则（链层）

| 检索输出 | 含义 | Agent 动作 |
|---|---|---|
| 完整（强） | 链闭合、与案例吻合 | 判 `[检索: CASE-xxx]`，按案例链序复述攻击叙事 + 处置要点 |
| 前缀/中段（未闭合） | 攻击**进行中** | 按「预测下一步[预期来源]」主动等/拉取该源证据；事件按"进行中"升级 |
| 缺口 | 期望的中间步骤未观察到 | 两种解释（该源未采集 / 换手法）→ **定点核查该阶段** |
| 弱档 / 通用探针单发 | 噪声 | 不作判定依据 |
| 关键词兜底强分（动作通道空） | 词面像、行为不像 | 不判案例；标【疑似/待观察】，并考虑动作库是否漏了该形态 |
| `◐ 来源不符` | 动作对、观测层不对 | 疑似另一台/另一次攻击 → 不并入本案 |
| `⚑ 低置信拼接/顺序异常` | 组装可疑 | 先拆/并链再判定 |
| 候选为空 | 技术不在库中 | 【新链案例】→ 走提取流程 |
| 多候选并列 | 分叉 | 按"档位→命中数→关键词分"取主判，结论里写明次选与分叉 |

- **链级 = 最终判定单元**；链级与行级分诊不一致时**以链级为准**并说明理由（例：9101-9110 首个链，CASE-016 中段 2/4 中档胜过 CASE-003 的 1/4 弱档）。
- 完整匹配 → 链确认 → 合并强化（追加证据行/新阶段/新目标，并补 `action_sources` 观测）。
- 前缀/中段（链未闭合）→ **攻击进行中**：按"预测下一步[预期来源]"主动等/拉取对应源证据。

### 9.5 实测与边界

- 行级回归**零扰动**（123 特征行 · Top-1 122 · 动作命中 123 · 强档 60）；组装 35/35 正确并链、**0 碎片、0 误并**；链级 57/58 Top-1 与行级人工期望一致（1 条混合载荷歧义见设计文档 §12.4）。
- 链级档位×召回（58 链）：强 32 / 中 15 / 弱 11；形态 完整 35（Top-1 35/35）· 前缀 14（13/14）· 中段 5（5/5）· 缺口 4（4/4）→ **未闭合不影响判定，失分集中在唯独的前缀歧义**。
- 消融实测：关闭来源槽位校验 / 取消 `order_ok` 降档 / 链级排序去掉关键词分 → Top-1 均不变（57/58，含 1 条已知例外）→ **来源槽位与顺序校验是"压误判"而非"提召回"**；关键词分在链级仅作同档并列的稳定 tie-break。
- 已通过 **3 个 deepseek-flash 子代理并行审查**（组装/匹配/注入三层），全部发现逐条修复（含 3 处非确定性、1 处 O(n²) 拆簇、5 处信号缺陷、1 处崩溃），修复记录见设计文档 **§12.7**；修复后单测 43 条 + 集成 14 条全绿。
- 性能：5000 行 0.50s / 20000 行 2.00s / 50000 行 4.95s（等距 1s 场景，线性近似）；乱序输入结果一致（200 次 0 不一致）。
- 已知边界：组装是**批内**的（跨批次链会断；生产可用 `session_id` 兜底）；层间载荷形态与 URI 路径都不重合时仍可能碎片化；同源模板重叠 > 300s 不并链（可调 `TEMPLATE_SAME_SRC_S`）；"唯一共享动作是 generic 时同秒同 URI 也不并链"（见 §六-5）。
- 回归与验证入口：`python tests/test_chain_assembly.py`、`python tests/test_chain_integration.py`（fixture 见 `eval/fixtures/`）。

### 9.6 参考样例（拿来即可复现一条完整链）

`data/batches/CASE-029_ProxyLogon_原样本.txt` —— ProxyLogon 风格完整链：SSRF 入口(`X-BEResource`) → IIS 工作进程执行(`w3wp→cmd.exe`) → ASPX webshell(`aspnet_client`) → 提权(`PrintSpoofer`) → 持久化(`sc create`) → DNS TXT 长标签外传（8 行 / 5 源 / 24 分钟）。

```bash
python src/retrieve.py --chain "data/batches/CASE-029_ProxyLogon_原样本.txt"
# → 1 条候选链（8 行，waf→web→hids→rasp→dns；entity/高）· [CASE-029] 完整匹配 6/6（强）
```

文件用途与预期输出见 `data/batches/README.md`；该批同时是 CASE-029 的 `action_sources` 推导证据。

### 9.7 运行手册（skill）

skill `security-log-case-memory` 按"运行 / 写案例 / 开发升级"分层：

| 何时读 | 文件 |
|---|---|
| 每次分析日志（输出读法、判定决策表、边界、速查命令） | `references/runtime-playbook.md` |
| 写案例（五处写入 + 顺序 + 门禁） | `references/case-write-spec.md` |
| 改管线（⚠ 仅开发/升级阶段） | `references/upgrade-playbook.md` |
| 接生产日志前（schema 适配 + 接入现状） | `references/production-log-schema.md` |
| 门禁一把梭 / 组装质量 | `scripts/check_gates.py` · `scripts/measure_assembly_quality.py` |

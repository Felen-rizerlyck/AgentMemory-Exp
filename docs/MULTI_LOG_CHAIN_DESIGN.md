# 多日志攻击链（Chain）设计与实现方案

> 状态：**已实现（M1-M5 完成并通过验证；M6 文档同步完成）。实现记录与对本文的偏差见 §12（含实测数据）。**
> 目标：**只增加一层，不改 v2 行级检索核心**（行级 `retrieve()/align_case()/keyword_score()` 一行未改，回归数字零扰动）。
> 背景：现实攻击 = 一次攻击多条日志（WAF 见入侵、RASP 见执行、HIDS 见提权/持久化、DNS 见 C2），行级"独立事件"设定是实验期的理想化；记忆单元应从"行"升级为"链"。
> 共识取舍：①两层架构 ②组装信号 ③流式链匹配 ④存储改造 ⑤提取单元改链 = 本方案主体（全量详述）；⑥边界问题 ⑦测试数据/评测 = 低优先（§10，本轮未做）。

---

## 0. 术语

| 词 | 含义 |
|---|---|
| 行 line | 单条日志 = 证据片段（现有检索单位） |
| 链 chain | 同一次攻击的跨源多行证据集合（有序），即"事件/incident" |
| 组装 assembly | 把行聚成候选链（分组依据见 §2） |
| 链匹配 chain matching | 对链整体做案例对齐打分（复用现有 `align_case`） |
| 分诊 triage | 行级检索的弱/中档候选提示（保留，不作最终判定） |

## 1. 目标与边界

- **目标**：把"多日志混杂的单一攻击"识别为一条链，对链整体做案例匹配、预测与提取。
- **约束**：
  1. v2 行级检索（`src/retrieve.py` 的 `retrieve()/align_case()/keyword_score()`）**一行不改**，仍作分诊；
  2. 新能力全部以"新模块 + 新增字段"实现（加层不加改）；
  3. 组装只做**候选生成**（机械、确定性），链归属最终由 Agent 确认——与关系图"候选+人工确认"同哲学；
  4. 组装参数（时间窗等）先给默认值并标注"待真实数据校准"，不阻塞开工。

## 2. 组装信号（回答：这不是评分，是分组依据）

组装回答的问题是"哪些行属于同一次攻击"，**先于**匹配。它与打分无关；打分仍走现有对齐逻辑（§6）。五类信号按可靠性排序：

| 优先级 | 信号 | 依据 | 实现方式 |
|---|---|---|---|
| 1（最强） | 会话/关联 ID | 生产 schema：`session_id`（主会话连接ID）、alarm_event 的"关联告警 ID 集合"、"告警归并规则 ID" | 行解析出会话键，相同键直接进同链（确定性分组） |
| 2（强） | 实体连续性 | 源→目标 IP 对、主机/资产名 | 键 = **(src, dst) 对**（不是单 src——同一 NAT 出口并发打两个目标会误并链）；链内实体键需连续一致 |
| 3（中） | 载荷模版跨层一致 | 同一去变量模版在多个源的行中重复出现 | 用 `match_actions()` 抽取行内动作 id，跨行动作 id 交集参与分组评分 |
| 4（中） | 阶段顺序无倒置 | 杀伤链阶段（侦察→初始访问→执行→提权→持久化→C2） | 组装后校验阶段排序；倒置 = 切链信号 |
| 5（低） | 时间窗 | 行时间戳接近 | 仅作**宽松窗口过滤**（默认 3600s，待校准）；**不可作主信号**——现有数据的 88-90s 固定节奏是合成模板规律，真实数据不存在 |

一句话：**2 是匹配的上游输入（拼链），匹配本身 = "分权重合分检索的攻击链版本"（复用 align_case，§6）**。

## 3. 两层架构与模块布局

```
日志行
 ├─ 行级动作抽取 match_actions()          【复用，不改】
 │    ├─ 行级检索 retrieve()               【复用，不改】→ 分诊提示（弱/中档候选）
 │    └─ 组装 chain_assembly()             【新模块】
 │         └─ 候选链列表 [{chain_id, lines, ordered_actions, sources, entities}]
 │              └─ 链匹配 chain_match()    【新函数，内部复用 align_case + 来源槽位校验】
 │                   └─ 链级判定: 完整/前缀/中段/缺口 + 预测(动作+来源) + 证据行列表
 │                        └─ Agent 确认 → 合并强化 / 新建（链为单元）
```

- **新文件** `src/chain_assembly.py`：组装算法（§5）。
- **新函数** `src/retrieve.py` 内追加 `chain_match()` + CLI `--chain` 入口（追加，不改 `score_case/align_case/keyword_score/main` 既有路径）。
- **数据字段**：案例新增 `action_sources`（§4）；`activity_patterns` 扶正为链级模式层（§4.3）。

## 4. 存储改造（最小增量）

### 4.1 案例新增 `action_sources`（与 `action_sequence` 平行）

```jsonc
"action_sequence": ["sqli_tautology", "mass_assignment_admin", "ssh_landed_key"],
"action_sources":  ["waf",             "rasp",                   "hids"]
```

- 取值：`waf / rasp / hids / dns / any`；**缺省 = `any`**（向后兼容，现有 28 案例不动也成立）。
- 含义：链匹配时每个被匹配动作的"观察来源"须与预期来源一致，`any` 跳过校验（§6.2）。
- 注入方式：`scripts/build_action_index.py` 的 `SEQUENCES` 旁**平行新增** `SOURCES` 字典（`"CASE-0NN": ["waf", ...]`），幂等注入 `action_sources`；无条目的案例注入全 `any`。现有 22 个案例的 `action_sources` 由人工标注（一次性的小标注任务，可开工时按案例 reasoning 里的"WAF 见 X、HIDS 见 Y"补）。

### 4.2 案例观测条目（低优先，可选）

- 现状用 `reasoning` 追加"新增观测"段落。可选升级：`observations: [{date, line_ids, stages_observed}]` 结构化记录链级证据行。**本轮可不做**，不影响链匹配主流程。

### 4.3 `activity_patterns` 扶正（语义，不改结构）

- 现状 PAT-001 是"跨案例时间节奏"（90s）。扶正后定位：**链模板 = 结构（action 序列）+ 来源（action_sources）+ 时间（PAT 式节奏，观察级）**。
- 本方案不迁移 PAT-001 数据，只在新文档/新案例中按新语义使用；旧条目原样保留。

## 5. 组装算法 `chain_assembly()`（实现步骤）

输入：批内行列表（已含时间戳/来源/ID/内容）。输出：候选链列表。

```
Step 1 行解析：每行 → {ts, source, line_id, session_key, entity_key=(src_ip,dst_ip)|asset, actions=match_actions(line)}
Step 2 键聚类（按优先级顺序尝试，先高后低）：
   a. session_key 相同 → 同簇（确定性）
   b. entity_key 相同且时间段内连续 → 同簇
   c. 无以上键：载荷模版交集（actions 重叠数 ≥1）且时间窗内 → 候选同簇（低置信，标记待确认）
Step 3 窗口过滤：簇内行时间跨度 > 默认 3600s（可配）→ 拆簇
Step 4 排序：每簇按时间升序；ordered_actions = 逐行 actions 拼接（保留行来源映射）
Step 5 阶段校验：若行序列出现阶段倒置（如持久化先于初始访问）且实体键不同 → 在该处切链；若实体键相同 → 不切但标记"顺序异常，待确认"
```

- 输出链对象：`{chain_id, lines[], ordered_actions[], sources[], entities[], confidence, flags[]}`。
- 确定性保证：同输入同输出（无随机）；候选+确认制，Agent 可拆可并。

## 6. 链匹配 `chain_match()`（复用 align_case）

### 6.1 对齐（复用）

- 链查询 = `ordered_actions`（含每个动作的观察来源）。
- 对每个案例：`align_case(case, chain_action_ids)`（**复用现有函数**，集合位置交集 + 连续性判定）→ 完整/前缀/中段/缺口 + tier + 预测动作。
- 排序键沿用：档位→命中数→关键词分→覆盖度→案例号（关键词分可用链内行级分数的合计或最大）。

### 6.2 来源槽位校验（新增，唯一新逻辑）

- 对每个匹配动作：`observed_source vs action_sources[i]`：
  - 一致或 `any` → 通过；
  - 不一致 → 该动作降为"来源不符"标注，不参与匹配计数（或按配置降档），提示"该阶段疑似非本案证据"。
- 链缺阶段（案例有动作未出现在链中）→ 缺口/预测语义（现有）；**预测输出升级为带来源**："预测下一步: 创建后门账户 (net user /add) [预期来源: hids]"。

### 6.3 伪代码

```python
def chain_match(chain, cases, lib):
    ids = [a for a, _ in chain["ordered_actions"]]
    for case in cases:
        al = align_case(case, ids)              # 复用
        if al is None: continue
        # 来源槽位校验
        for pos in al["positions"]:
            want = (case.get("action_sources") or ["any"]*len(case["action_sequence"]))[pos]
            got = chain["sources"][chain_action_pos]   # 该动作的观察来源
            al["source_ok"] = al.get("source_ok", True) and (want == "any" or want == got)
        # 预测带来源
        al["predict_source"] = (case.get("action_sources") or [])[al["predict_pos"]] if al["predict"] else None
        yield case, al
```

### 6.4 输出格式（链级，中文）

```
== 链 CHAIN-01（4 行证据，waf→rasp→hids）:
   [链] [CASE-009] 前缀匹配 2/3（中）SQLi 认证绕过 + 批量赋值提权
        - 已重合: ●SQLi 恒真绕过[waf] ●批量赋值 admin=true[rasp] ○SSH 横向[预期 hids]
        - 预测下一步: SSH 横向移动 [预期来源: hids]
        - 证据行: WAF0303110, RASP0303220
```

## 7. 流式/进行中语义

- 前缀/中段链 = **攻击进行中**：输出预警 + 带来源预测（Agent 可据此主动等/拉取特定源证据）。
- 完整匹配 = 链确认 → 触发提取（合并强化：追加证据行/新阶段/新目标）。
- 无命中新链 = 按 case-write-spec 新建（链为单元，`source` 字段可写多源 `WAF+RASP+HIDS`，`kill_chain` 按链阶段写全）。
- 单行单阶段观测仍可建案，但必须标"仅见 X 阶段，无后续证据"（证据从严规则不变）。

## 8. 提取流程变更（判定单元 = 链）

- 行级判定降级为**分诊提示**（输出里标"分诊"而非最终判定）。
- 链级判定为最终结论：`[检索: CASE-xxx]` / 【新链案例】/ 无关。
- 判据复用："同链不完整观测 = 前缀 → 合并"（落到链级：同一案例的链，阶段更全 → 合并强化原案例并补 `action_sources` 观测）。
- `case-write-spec.md` 需小增补：新建链级案例时的 `action_sources` 标注要求（写规 §三 加一行即可）。

## 9. 实现顺序（可直接开工的里程碑）

| 里程碑 | 内容 | 验收标准 |
|---|---|---|
| **M1** | `src/chain_assembly.py`：行解析 + 键聚类 + 窗口 + 阶段校验 | 对合成批输出确定性候选链；单测覆盖 Step1-5 |
| **M2** | `build_action_index.py` 平行加 `SOURCES` + 注入 `action_sources`（缺省 any）；22 案例人工标注 sources | build 校验通过；store 内所有案例有 `action_sources` |
| **M3** | `retrieve.py` 追加 `chain_match()` + `--chain` 入口（不动既有函数） | 行级回归三件套数字不变 |
| **M4** | 链级输出格式（§6.4）+ 预测带来源 + 进行中预警文案 | 手工样例链输出符合格式 |
| **M5** | 最小链级场景（自造 1-2 条跨源链）手工验证 | 前缀链正确预测带来源；完整链正确命中；行级检索不受影响 |

每步合入前跑 `python eval/run_action_recall.py`（行级回归必须零扰动）。

## 10. 低优先（后续再做）

### 10.1 边界问题（交错攻击切分）

- 细化切链规则：阶段倒置 + 载荷模版分叉 + 实体键不同 → 切；全满足才切，单信号只标记"待确认"。
- 同 (src,dst) 但时间上两次独立攻击（同载体重复利用）→ 靠"链已完成"（完整匹配闭合）后新起链。

### 10.2 测试数据与评测（链级）

- 场景：五阶段跨源完整链（SQLi→RCE→提权→持久化→C2）、双攻击窗口交错（边界测试）、未完成链（仅前 2 阶段，预测测试）。
- 链级 gold：`{lines: [..], expect_case / new_chain, expect_stage_count}`；指标：整链召回、阶段精度、交错误并率。
- 合成数据注意：**不要再埋固定节奏**；时间只做宽松窗口。

## 11. 开放问题（不阻塞开工）

1. 时间窗默认值（3600s 待真实数据校准）；
2. 同 src 不同 dst 并发攻击的分组（已用 (src,dst) 对缓解）；
3. 跨波次战役（多窗口同模版）的归属——现有 `activity_patterns` 层职责，链级不处理；
4. ~~`action_sources` 的 22 案例人工标注口径（按 reasoning 证据补，不臆造）~~ → 已由 §12.2-6 的数据推导脚本解决（28 案例全量标注，可重跑复核）。

---

## 12. 实现记录（M1-M5 完成；本节记录交付物、对上方方案的偏差、实测数据与已知边界）

### 12.1 交付物

| 文件 | 内容 |
|---|---|
| `src/chain_assembly.py`（新） | 组装层：行解析 → 键聚类（会话/实体/并发/模板）→ 窗口过滤 → 排序 → 阶段校验；确定性 |
| `src/retrieve.py`（追加） | 链级匹配 `chain_match()` + 渲染 `show_chain()` + `--chain` 入口；**既有行级函数一行未改** |
| `scripts/build_action_index.py`（追加） | `STAGES`（77 动作阶段）+ `SOURCES`（28 案例动作观测来源）平行字典，`validate()` 加对齐校验，注入 `stage` / `action_sources` |
| `scripts/derive_action_sources.py`（新） | `action_sources` 的证据推导脚本（可审计、可重跑），写入 build 脚本的标记块 |
| `tests/test_chain_assembly.py`（新） | 组装层单测 43 条（Step1-5 + 信号 2.5 + 确定性 + 边界 + 审查修复回归，hermetic 自造动作库） |
| `tests/test_chain_integration.py`（新） | 链级集成 14 条（真实案例库 + 数据集 fixture：并链质量/链级 Top-1/演示批/匹配修复回归/行级不受影响） |
| `eval/fixtures/`（新） | `gen_chain_fixtures.py` + 3 个数据集扁平化 fixture + 演示批（完整跨源链/前缀链/噪声/DNS 链） |

### 12.2 对本文方案的偏差（每条都刻意、可回滚；理由与数据列后）

1. **`action_sources` 值域加 `web`**，且值支持"单值或列表"（`["waf","web","rasp"]` = 任一来源即通过）。原因：数据里 `web` 源 29 行、案例 `source` 字段也含 `WEB`；同一请求被 waf+web+rasp 三层同时捕获时，单值标注会把合法匹配误判"来源不符"。
2. **新增链级顺序一致性检查 `order_ok`**（补 §6 匹配期的空档）：`align_case()` 是**集合语义**（不看顺序），链级按"案例位置升序 ↔ 链内时间序须单调不减"判定，反向则**降一档**并标注"顺序异常待确认"；`align_case()` 未改。
3. **动作库新增 `stage` 字段**（77 动作，`STAGES` 平行字典注入），支撑 §5 Step5 阶段校验与链级展示。配套口径：行阶段 = 行内**最深**阶段（非"最后一个动作"）；`recon`（侦察/发现）不参与顺序判定；倒置阈值 `STAGE_TOLERANCE=2` 档；相邻行间隔 ≤ `CONCURRENT_S=300s` 视为**同一事件的多源观测**，跳过倒置判定（否则同请求多层行会因"各层看到的侧面不同"被误判倒置）。
4. **新增信号 2.5「同请求跨源并发」**（超出 §2 的五信号，**可一键关闭**：`CONCURRENT_LINK_S=0`）：不同来源 + Δt ≤ 30s + 共享动作 id **或** URI 路径相关 + 至少一侧含非通用动作 + 实体不冲突 → **中置信**候选。理由：某一层的载荷常被日志截断而只剩通用探针 token，此时信号 3 失效 → 链碎片化；实测三数据集 35 组同案例多行：碎片 **5 → 0**，误并保持 **0**。
5. **信号 3 只用非 `generic` 动作**且限窗内相邻（防整批共享探针把无关行粘连成巨链）。
6. **`action_sources` 由 `scripts/derive_action_sources.py` 依数据推导**（非纯手工标注）：动作在 dataset 期望行被命中 → 取该行来源；未命中（载荷被截断/正则形态不覆盖）→ 取"该案例证据行来源 ∩ 案例 `source` 层"；不在数据集的 CASE-023~028 → 按部署测试批 `log_id` 映射；`generic` 探针 → `any`（约束探针只会制造假告警）。
7. **单测用 stdlib `unittest`**（仓库零外部依赖、环境无 pytest），新增 `tests/` 目录，`python tests/<file>.py` 直接可跑。

### 12.3 实现参数（待真实数据校准，覆盖 §11-1）

| 参数 | 默认 | 含义 |
|---|---|---|
| `WINDOW_S` | 3600 | 宽松时间窗：簇跨度超此值 → 拆簇（会话键分量除外） |
| `CONCURRENT_S` | 300 | 同事件多源观测窗（阶段倒置判定以其跳过） |
| `CONCURRENT_LINK_S` | 30 | 信号 2.5 并链窗（0 = 关闭） |
| `TEMPLATE_LINK_S` | 3600 | 信号 3 **跨源**并链窗（与拆簇窗解耦） |
| `TEMPLATE_SAME_SRC_S` | 300 | 信号 3 **同源**并链窗（同源模板重叠属弱证据，只在紧邻时间内承认） |
| `STAGE_TOLERANCE` | 2 | 阶段回退 ≥2 档才算倒置（回退 1 档视为自然交错） |

### 12.4 验证数据（本轮实测）

- **行级回归（铁律）**：特征行 123 · Top-1 **122** · Top-3 123 · 动作通道命中 **123** · 强档 60 · 样板行 10 —— 与链层合入前**完全一致**（`eval/run_action_recall.py`）。
- **组装**：三个入库数据集（30 单元）中 35 组"同案例多行" → **35/35 正确并链、0 碎片、0 跨案例误并**（信号 2.5 关闭时：30/35，碎片 5）。
- **链级匹配**：58 条链中 **57 条 Top-1 == 行级人工期望**；1 条差异（9101-9110 首个链：该单元 waf/web/rasp 行同时携带 CASE-003 与 CASE-016 载荷且 rasp 行被截断，链级把 cache_key+smuggle 并成 CASE-016 中段 2/4 中档 → Top-1 归 CASE-016，期望案例仍在 Top-3），已写成 `tests/test_chain_integration.py` 的显式例外表并注明原因。
- **演示批**（`eval/fixtures/chain_demo_cross_source.txt`）：完整跨源链 3 行 → `CASE-010 完整 2/2 强`；前缀链 2 行 → `CASE-009 前缀 2/3 中` + 预测 `mysql_load_file [预期来源: waf|rasp]`；噪声单例 → 无命中；DNS 信标链 3 行 → `CASE-002 完整`。

### 12.5 命令

```bash
python src/retrieve.py --chain data/incoming_logs.txt   # 链级：组装 + 链级匹配 + 行级分诊并列
python src/chain_assembly.py data/incoming_logs.txt     # 只看组装（调试视图）
python tests/test_chain_assembly.py                     # 组装层单测（31 条）
python tests/test_chain_integration.py                  # 链级集成（真实库 + fixture，8 条）
python eval/run_action_recall.py                        # 行级回归（数字必须不变）
python eval/fixtures/gen_chain_fixtures.py              # 重导出链级 fixture
python scripts/derive_action_sources.py --dry-run       # 复核 action_sources 标注推导
```

### 12.6 已知边界（本轮未做；§10 仍未动）

- 组装是**批内**的：跨批次的链（前段在上一批）会断开——生产可用 `session_id`（信号 1）兜底，本数据无该字段。
- 理论上仍可能碎片化：某层载荷形态完全不同**且** URI 路径也不重合时（本数据 0 例）。
- §10.1 交错攻击切分细化、§10.2 链级评测体系（整链召回 / 阶段精度 / 交错误并率）未做。

### 12.7 子代理审查与修复记录（3 个 deepseek-flash 子代理并行审查，本轮全部处理）

审查结论：组装层【不通过】（3 处非确定性 + 性能劣化 + 5 处信号缺陷 + 1 处崩溃 + 6 处低危）、匹配层【有条件通过】（1 中 + 3 低 + 1 信息）、注入层【有条件通过】（2 中 + 3 低 + 2 信息）。**发现已逐条复核并修复**；修复后：单测 **43 条** + 集成 **14 条**全绿、行级回归零扰动、组装 **35/35 · 0 碎片 · 0 误并**、链级 Top-1 **57/58**（1 条混合载荷歧义不变）。

| # | 审查发现 | 修复 |
|---|---|---|
| A1-A2 高 | 排序键用行下标作 tie-break → 乱序输入并链结果/链内动作序不同 | 全面改用与输入无关的完备键 `(ts, source, log_id, content)`；真实批 + "同刻且无 log_id"并列键场景各 200 次乱序 **0 不一致** |
| A3 高 | `_split_by_window` 等距大簇退化为逐行剥离（n=5000 2.56s、n=20000 98.6s） | 重写为**单趟线性扫描**闭块；实测 5000 行 0.50s、20000 行 2.00s、50000 行 4.95s，行数守恒、块跨度 ≤ 窗 |
| A4 中 | `clusters.sort` 取"最小输入下标行"（笔误）→ 链序错乱 | 改为按簇内最早行的完备键排序 |
| A5 中 | 信号 2.5 只看全局相邻行，中间夹一行噪声即失效 | 改为**窗内滑窗两两配对**（含回归用例） |
| A6 中 | 阶段倒置的"并发跳过"不看来源，同源对也被豁免 | 追加"来源不同"条件，并以**最高阶段来源行**作时间基准（flag 文案同步） |
| A7 中 | 会话键簇被时间窗无条件拆散，碎片仍报"高置信会话链" | 会话分量**不拆**（确定性分组），跨窗时保留并标记"会话键分量跨窗" |
| A8 中 | `session_linked` 按整分量豁免切链，误放行经实体连入的非会话行 | 改为**仅当切点两侧同一会话键直连**时豁免 |
| A9 中 | 信号 3 允许同源模板重叠（真实批曾把两条 hids WMIC 行按 24 分钟粘连） | 信号 3 跨源用宽窗、**同源仅紧邻窗**（`TEMPLATE_SAME_SRC_S=300`） |
| A10 中 | `window_s` 兼作拆簇窗与模板并链窗（CLI `--window` 连带改并链） | 拆成独立参数（`TEMPLATE_LINK_S` / `TEMPLATE_SAME_SRC_S`），`--window` 只影响拆簇 |
| A11 中 | 动作库 `stage` 非字符串时崩溃 | 类型守卫；未知取值改为链级 flag（不静默忽略） |
| A12-A18 低 | flags 复制给所有子链；单行碎片继承高置信；方括号 log_id/空 source 不支持；会话键 <3 字符静默丢弃；flag 文案硬编码阈值；`_ACTION_RES` 缓存键仅按动作 id；路径后缀判定过宽 + 系统路径前缀误排除 + 主机名 TLD 过窄 | 逐条修复：flag 只挂触发行所在子链；单行链 → singleton/低 + 原分量依据 flag；解析支持 `[log_id]`/空 `[]`（source 记 unknown、markdown 行显式跳过）；会话键下限 2 字符 + 右边界；文案用运行阈值；缓存键含 regex；路径改**规范化后相等**（去 URL 残留主机名段）、系统路径按**路径段**判定、TLD 清单扩到内网后缀 |
| B1 中 | 案例序列含重复动作 id 时，链级按 id 重对齐会把"来源不符"位置捞回（现库无重复，属潜伏） | 新增 `_classify_positions()` 按位置复算形态/档位/预测（`align_case` 保持不动）；按审查口径复现验证：缺口 3/4、`mismatch=[2]` |
| B2-B5 低 | 来源列表含 `any` 应跳过；`action_sources` 裸串按下标取字符；`--window` 缺参/非法裸 traceback；无预测时预警文案写 `[any]` | 逐条修复 + 回归用例 |
| C1 中 | `derive_action_sources.py` 漏 data-921-930 → CASE-006/009 两条标注回退成 `[waf,rasp]`，web 层观测会被整链拒掉 | 新增 **OVERRIDES 人工覆盖 4 条**（逐条注明依据）：`com_sun_gadget=rasp`、`gcp_metadata_ssrf=[waf,web]`、`mysql_load_file=[waf,web]`、`spel_type_ref=[waf,web]`；标注块头部自动写入分支构成（直接观测 71 / generic→any 12 / 人工覆盖 4 / 回退推断 0——其中"回退推断 1→0"即由 C4 修复带来） |
| C2 低 | 6 条标注越出案例 `source` 字段 | CASE-003 / CASE-005 的 `source` 补 `WEB`（数据集同单元确有 [web] 行），reasoning 注明 |
| C3 信息 | `re.sub` replacement 未按字面量处理 | 改为 `lambda _m: new_block` |
| C4 中 | **三个动作正则在其自身证据行上 0 命中**（`com\.sun\.` vs 截断文本 `com.sun`、`T(java.lang.Runtime` vs 实际 `java.lang.Runtime.getRuntime()`、`/tmp/\.svc` vs 转义形态 `\/tmp\/.svc`）→ 动作永不触发，来源标注只能靠回退推断 | 修正为 `com\.sun` / `java\.lang\.Runtime` / `tmp\\?/\.svc`（覆盖 `/tmp/.svc` 与 `\/tmp\/.svc` 两种载体形态）。**先在沙箱实测影响再改**：全部行级口径零扰动（Top-1 122 · 动作命中 123 · 强档 60 · 样板行 0 误命中 · NOVEL 0 中/强档）、链级不变（35/35 · 0 碎片 · 0 误并 · Top-1 57/58）；三个动作已**正向验证**命中各自证据行（CASE-021 的链级匹配随之从 1/4 升到 2/4） |

**未修复项（记录在案，待决策）**：

1. **CASE-014 序列末位 `shebang_cmd_inject`（execution=2）相对前位 c2(6) 回退 4 档**（潜伏）：实测因"同请求多源并发豁免"不触发切链，仅提示"同请求跨源并发拼接"。可选修法（移到序列首位 / 引入"标记类动作"豁免）都会改动行级序列语义，待决策。
2. **同源模板重叠 > 300s 不再并链**（行为变更）：真实批两条 hids WMIC 行相隔 24 分钟现各自成链（一条前缀 2/4 中 + 一条完整 4/4 强）。取"宁可切开让 Agent 合并、不要粘连让 Agent 拆开"；如需恢复并链，调大 `TEMPLATE_SAME_SRC_S`。
3. `_action_regex` 缓存键改动是**对既有行级代码的唯一触碰**（原键仅动作 id，换库不失效）；已跑全量回归确认数字不变。
4. **同秒 / 同 URI / 同参数的三层观测，在"唯一共享动作是 generic"时不并链**（已知边界，2026-10-15 决定暂不放宽）：实测 921-930 unit 10 的 waf/web/rasp 三行（路径归一化后同为 `/api/v1/ping`、参数同为 `cmd=127.0.0.1;id`、Δt=1s）仍是 3 条 singleton —— 因为信号 2.5 要求"至少一侧有非通用动作"。取舍：抗粘连优先，链归属交 Agent 人工确认；放宽方案（同 URI + 同参数键值 + Δt≤5s 时豁免 generic）留待需要时再评估。同批还固化了一条判定纪律（已写入 skill）：**弱档模板再现 ≠ 新案例** —— 当批次行只共享一个通用探针、且该探针正是既有案例序列第 1 步时，按"弱档模板再现 / 待观察"处理，不因"链未闭合"新建案例；单独出现的主机进程链样板行不构成新证据。复核与盲测对照全文见 `eval/results/report_unseen_unit10_blind_test.md`。

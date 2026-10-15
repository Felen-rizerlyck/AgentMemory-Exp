---
name: security-log-case-memory
description: "Use when analyzing attack-detection log batches into case memory (检索→判定→提取); 开发/升级走 references/upgrade-playbook.md。"
---

# 安全日志案例记忆 · 运行流程（攻击检测 Agent 验证）

**触发**：在 `F:\AI_Learning\AgentMemory` 处理一批安全日志（`时间 [来源] 编号 内容`，来源 waf·web·rasp·hids·dns），要分析攻击链 + 把案例提取为记忆。
**硬约束**：案例记忆**只写该目录** `data/memory_store.json`，**不写真实 Hermes 记忆**（用户明确要求）。
**分工**：本文件 = 每次都要遵守的常读版；运行细节看 `references/runtime-playbook.md`；**开发/升级/加层/测试另走 `references/upgrade-playbook.md`（仅开发阶段）**。

## 每批固定 6 步（细节见 `references/runtime-playbook.md`）

1. **落盘**：原文逐行写 `data/incoming_logs.txt`（保留截断原样）。
2. **行级分诊**：`python src/retrieve.py --batch data/incoming_logs.txt`
3. **链级判定**：`python src/retrieve.py --chain data/incoming_logs.txt`
4. **判定**：逐链下结论 → `[检索: CASE-xxx]` / 【新案例】/ 无关（**链级为准**，行级只作提示；候选为空 → 【新链案例】）。
5. **提取**：读 `references/case-write-spec.md` → 五处写入 → `python scripts/derive_action_sources.py` → `python scripts/build_action_index.py`。
6. **验证**：`python eval/run_action_recall.py` + `python tests/test_chain_assembly.py` + `python tests/test_chain_integration.py`（动过库/脚本/代码才跑），数字必须不变。

## 判定纪律（速查五条）

1. **链级 = 最终判定单元**，行级是分诊；冲突时以链级为准并写出理由。
2. **档位是置信度**：动作通道 `完整`=强 / `命中≥2`=中 / `命中=1`=弱；**弱档（尤其通用探针单发）按噪声**处理。
3. **关键词通道只兜底**：关键词强分（≥6）但动作通道为空 ≠ 匹配；主区永远压过兜底区。
4. `◐ 来源不符` = 该阶段疑似非本案证据（**不计入匹配计数**）；`⚑ 低置信拼接/顺序异常` = 先拆并再判；`⚠ 链未闭合` = 攻击进行中 → 按「预测下一步[预期来源]」主动等/拉取证据。
5. **候选为空 → 【新链案例】**（走提取流程，不要硬套最相近案例）；多候选并列时按「档位→命中数→关键词分」取舍并写明分叉。

## 输出习惯（用户已习惯的格式）

检索结果（表）→ 判定（带 `[检索: CASE-xxx]` 标注 + 理由，含缺失阶段/进行中提示）→ 提取变更（表）→ 每批末尾简述新观察；中文、简洁、证据从严。

- 长任务**分段交付**：单条回复过长会被平台截断（用户提过）→ 按里程碑逐段给「完成了什么 + 一行状态」，别把多个阶段挤进一条。
- **讲解机制/演示能力**：用一条真实场景链**实跑全流程**并贴**真实输出**、注明调用的函数与命令（落盘 → `--batch` → `--chain` → 判定 → 五处写入 → 门禁四件套）。现成素材 `data/batches/CASE-029_ProxyLogon_原样本.txt`（ProxyLogon 风格 8 行 5 源 → CASE-029；说明与预期输出见 `data/batches/README.md`）。
- **讲解 `action_sequence`**：同一案例造四条片段各跑一次并贴输出 —— 全指纹塞进一行（`完整 6/6 强`）· 只给中间一步（`中段 1/6 弱` + 预测下一步）· 跳步（`缺口 2/6 中` + `缺口(未观察): …`）· 只给末步（前段全列、无预测）。**解释字段**用「一匹配 + 一不匹配」两例实跑（不匹配的两种形状：只有关键词命中而动作通道空、动作命中但来源槽位不符 `◐`）。
- 用户决策风格：架构类变更先出「机制确认」材料再进入决策；标准可冻结、细则延后但必须记入待议文档；结论要有评测数据支撑；会主动提方案让你评估可行性。

## 陷阱速查（完整清单见 `references/`）

- 编码载荷**先解码再判断**：`%%32%65`→`%2e`→`.`；`%26`→`&`。
- **改动作正则前先正向验证**：正则必须在其自身证据行上 `re.search` 命中，否则动作永不触发；覆盖同一 token 在 waf/web/rasp 的多种载体形态（JSON 转义引号、冒号-引号键值、截断无尾缀）。三类翻车形态：日志截断、正则与文本形态不符、路径被转义。
- **含反斜杠的内容别手打反斜杠**（heredoc/patch 会多层解析，`\u` 直接抛错）→ 用 `write_file` 写脚本或用 `chr(92)` 拼串；落地后 `ast.parse()` + `repr()` 逐字对比 + 正向命中验证。
- 案例 `action_sources` **不要手改 `SOURCES` 块**（derive 会整块重写）：在 `scripts/derive_action_sources.py` 的 `BATCH_EVIDENCE` 登记「批次文件 + 该批 log_id→案例」→ 跑 derive → 跑 build 注入；漏登记会被 build 拦住。
- 排序键 = 档位→命中数→关键词分→覆盖度→案例号（关键词分优先于覆盖度）。**已知歧义行**（911-920-3-3 F5 rasp 截断行：CASE-010 第 1、CASE-011 第 2）接受现状、**勿调分**。
- **不要为「关键词字段重复」删字段**：跨字段 token 去重已生效（`seen` 集合逐通道扣减），实测关键词通道整体只值 3 行兜底排序、动作通道在所有变体下不变；真重复仅 `pattern_probes` 字面型正则，代价是分诊噪声，靠纪律兜住。
- 新增案例后重跑检索是**回顾性**打分（证明可召回），不得当作事前检出；`dataset/data-921-930` 保持未入库（前瞻性）。
- 链层旋钮只在 `src/chain_assembly.py` 顶部常量（`WINDOW_S`/`CONCURRENT_S`/`CONCURRENT_LINK_S`/`TEMPLATE_LINK_S`/`TEMPLATE_SAME_SRC_S`/`STAGE_TOLERANCE`）；组装只做候选生成，链归属 Agent 确认；**不要去改行级打分**。
- 收到一批日志**先按 `log_id` 精确核对 `dataset/`**（`dataset/parsed_*.json`、`dataset/*.txt`）：用户给的批次很可能就是某个已标注单元的复现/变体；核对要精确匹配，**别用被 `head` 截断的 grep 输出下"不在数据集里"的结论**（踩过：把已标注的 921-930 unit 10 误判为新形态）。
- 批次顺序 ≠ 时间顺序（日期可乱序）；时序规律入库要统一锚点 + 标「观察级」+ n=1 标「待验证」+ 注明来源覆盖限制。
- 勿混淆：真实 Hermes 记忆 = `MEMORY.md`/`USER.md`（纯文本、无检索）；本验证 = JSON 案例库 + 检索协议（为案例级召回设计）。

## 文件与参考（按需读）

| 何时读 | 文件 |
|---|---|
| **每批分析时**（输出读法、判定决策表、边界、速查命令） | `references/runtime-playbook.md` |
| **写案例时**（五处写入 + 顺序 + 门禁） | `references/case-write-spec.md` |
| **改管线时**（⚠ 仅开发/升级阶段，非运行流程） | `references/upgrade-playbook.md` |
| 接生产日志前 | `references/production-log-schema.md` |
| 门禁一把梭 / 组装质量 | `scripts/check_gates.py` · `scripts/measure_assembly_quality.py` |
| 方法指南 / 链层方案 | `GUIDE.md`（§九 = 链层）· `docs/MULTI_LOG_CHAIN_DESIGN.md`（§12 = 实现记录/偏差/审查修复） |
| 代码 | `src/retrieve.py`（行级 + `chain_match()`/`--chain`）· `src/chain_assembly.py`（组装层）· `scripts/build_action_index.py`（注入+校验，幂等）· `scripts/derive_action_sources.py`（来源推导） |
| 数据 | `data/memory_store.json`（cases + action_library + activity_patterns）· `data/batches/`（已入库批次留档 + 参考样例，含 `CASE-029_ProxyLogon_原样本.txt`）· `dataset/`（901-910 / 911-920 / 9101-9110 已入库；`dataset/data-921-930.txt` 未入库前瞻批） |
| 评测与测试 | `eval/run_action_recall.py` → `eval/results/*.md` · `eval/fixtures/` · `tests/` |

**生产数据接入（未接入主流程）**：`log-schema/`（本地、gitignore）= 生产日志字段字典；hunt MCP 端点 `http://10.7.194.120:22196/hunt/sse` 已配进 `config.yaml`，当前内网不可达——详见 `references/production-log-schema.md` §六。

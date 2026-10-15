# 攻击检测 Agent 记忆机制验证（v2.1：动作匹配 + 攻击链层）

验证一个安全检测 Agent 如何把经手的攻击**提取为结构化实例记忆**（形式化攻击链 + 去变量的动作序列 + 观测来源/阶段），存入本地案例库（`data/memory_store.json`），供后续遇到相似攻击时**检索辅助攻击链分析**与**下一步推断**。

> **数据说明**：日志为清洗/模拟数据（使用文档 IP 段 `203.0.113.x` / `192.0.2.x` / `198.51.100.x`），仅用于记忆机制验证，非真实生产告警。
> **方法说明**：现行方法 = **v2 动作匹配 + v2.1 攻击链层**，完整指南见 **[GUIDE.md](GUIDE.md)**（§一~§八 行级；**§九 链层**）。
> **判定单元**：链层已实现并在并行验证（默认流程暂未切换）——**链级判定为最终单元**（完整/前缀/中段/缺口 + 预测带来源），**行级结果降级为分诊提示**，两者在 `--chain` 输出里并列给出。
> **版本**：v1（关键词双通道打分）与链层前的 v2 均已归档至 `history/`（`old_` 前缀，保留可运行作对照）。

## 目录结构

| 路径 | 说明 |
|---|---|
| `src/retrieve.py` | 检索器主模块。行级：动作通道（动作库识别 → 反向索引 → 序列对齐/预测/分叉）+ 关键词通道兜底；链级：`chain_match()`（复用 `align_case` + 来源槽位校验 + 顺序一致性）、`show_chain()`、`--chain` 入口 |
| `src/chain_assembly.py` | **链组装层**：行解析 → 信号聚类（会话 ID / 实体连续性 / 同请求跨源并发 / 载荷模板）→ 时间窗过滤 → 排序 → 阶段校验；确定性候选生成（输入乱序结果一致） |
| `scripts/build_action_index.py` | 动作库（`ACTIONS`，含 `STAGES` 阶段）/ 案例动作序列（`SEQUENCES`）/ 观测来源（`SOURCES`）注入与校验（幂等） |
| `scripts/derive_action_sources.py` | `action_sources` 标注的**证据推导**脚本（dataset 期望行 + 批次证据登记 + 人工覆盖，可审计、可重跑） |
| `data/memory_store.json` | 案例库（`cases` + `action_library` + `activity_patterns`） |
| `data/incoming_logs.txt` · `data/batches/` | 批次落盘位；`data/batches/` = **已入库批次留档 + 参考样例**（`CASE-029_ProxyLogon_原样本.txt`：ProxyLogon 风格 8 行 5 源完整链；`deploy_test_2026-10-14.txt`）与说明 `README.md` |
| `eval/run_action_recall.py` | 行级召回审计（已入库重放 + data-921-930 前瞻）→ `eval/results/report_action_recall.md` |
| `eval/fixtures/` | 链级 fixture（三个数据集扁平化 + 演示批）与生成脚本 `gen_chain_fixtures.py` |
| `tests/` | 单测 / 集成测试（stdlib unittest，零依赖：组装层 43 条 + 链级集成 14 条） |
| `docs/` | 设计文档：`MULTI_LOG_CHAIN_DESIGN.md`（链层方案 + **§12 实现记录/偏差/审查修复**）、`ACTION_SEQUENCE_MATCHING.md`、`ENTITY_*.md`、`LOG_SCHEMA_ADAPTATION.md` |
| `history/` | 归档区：v1（`old_retrieve.py`、`old_*.md`、`old_eval/`）、链层前快照（`old_GUIDE.md`、`old_retrieve_v2_linelevel.py`、`old_build_action_index_v2.py`、`old_memory_store_pre_chain.json`） |
| `skills/` | `security-log-case-memory` skill 的仓库内副本：`SKILL.md`（运行流程常读版）+ `references/`（`runtime-playbook.md` **运行手册** · `case-write-spec.md` 写规 · `upgrade-playbook.md` 开发/升级〔⚠ 仅开发阶段〕· `production-log-schema.md` 生产适配）+ `scripts/`（`check_gates.py` 门禁一把梭 · `measure_assembly_quality.py` 组装质量） |
| `dataset/` | 原始日志批次（`data-901-910` ~ `data-921-930`）+ 解析存档 |
| `Agent记忆产品落地-调研/` | 产品落地调研（独立于本验证流程） |

## 快速开始

> 所有命令在**项目根目录**执行。

```bash
# ── 单条 / 行级批量检索（分诊） ──
python src/retrieve.py "wmic /node:10.20.6.179 process call create"
python src/retrieve.py --batch data/incoming_logs.txt

# ── 链级检索（组装候选链 + 链整体匹配 + 行级分诊并列）──
python src/retrieve.py --chain data/incoming_logs.txt
python src/retrieve.py --chain "data/batches/CASE-029_ProxyLogon_原样本.txt"   # 参考样例：完整链（见下）

# ── 只看组装（调试视图）──
python src/chain_assembly.py data/incoming_logs.txt

# ── 提取入库两步（新案例/新观测后）──
python scripts/derive_action_sources.py      # ① 依批次证据推导 action_sources（写入 build 脚本）
python scripts/build_action_index.py         # ② 注入动作/序列/阶段/来源 + 门禁校验（幂等）

# ── 回归与验证（改任何东西后必跑）──
python eval/run_action_recall.py                                    # 行级数字必须不变
python tests/test_chain_assembly.py && python tests/test_chain_integration.py

# ── 其它 ──
python eval/fixtures/gen_chain_fixtures.py   # 重导出链级 fixture（字节可复现）
python history/old_eval/run_recall_full.py   # v1 归档框架（对照用，仍可运行）
```

**全流程示例（链层）**：`data/batches/CASE-029_ProxyLogon_原样本.txt` 是一条 ProxyLogon 风格完整链（SSRF → IIS 进程执行 → ASPX webshell → PrintSpoofer 提权 → sc create 持久化 → DNS TXT 外传，8 行 / 5 源 / 24 分钟），也是 CASE-029 的来源批次与 `action_sources` 推导证据；文件说明与预期输出见 `data/batches/README.md`。
`--batch` 看行级分诊（多为「无相似案例命中」或通用探针弱档）→ `--chain` 看链级判定（组装为 1 条链 → 入库后 `[CASE-029] 完整匹配 6/6（强）`）。

## 核心流程（每批：落盘 → 检索 → 判断 → 提取）

1. **落盘**：日志原文逐行写入 `data/incoming_logs.txt`（格式 `ts [source] log_id content`；保留截断原样）。
2. **检索**：
   - 行级 `--batch`：动作序列对齐（完整/前缀/中段/缺口 + 预测下一步 + 分叉参考）+ 关键词兜底 → **分诊提示**；
   - 链级 `--chain`：批内组装候选链（机械确定性，链归属由 Agent 确认）→ 链整体匹配 → **最终判定**：`完整/前缀/中段/缺口` + `预测下一步[预期来源]` + 证据行；链未闭合时输出「⚠ 攻击进行中」。
3. **判断**：以**链级**为最终单元标注 `[检索: CASE-xxx]` / 【新链案例】/ 无关；行级弱档（尤其通用探针单发）按噪声处理。跨批次不串链（组装是批内的；生产可用 `session_id` 兜底）。
4. **提取**：高度相似 → 合并强化（追证据行/新阶段/新目标）；技术不同 → 新建案例。**按 `skills/security-log-case-memory/references/case-write-spec.md` 的五处写入 + 顺序执行**（案例本体 → `ACTIONS` → `STAGES` → `SEQUENCES` → 批次证据登记 → `derive` → `build`），过完门禁四件套（行级重检 / 链级重检 / 全量回归 / tests）才算入库完成。

> **运行细节**（检索输出读法、判定决策表、边界与速查命令）见 `skills/security-log-case-memory/references/runtime-playbook.md`；**开发/升级/回归**见同目录 `upgrade-playbook.md`（⚠ 仅开发阶段）。

## 当前成绩

**行级（v2，口径与基线详见 GUIDE §五）**

| 口径 | 成绩 |
|---|---|
| 已入库重放（123 特征行，回顾性） | 组合 Top-1 **122/123（99%）** · Top-3 123/123 · 动作通道命中 **123/123（100%）** · 动作强档 60/123 |
| 前瞻批 data-921-930（未入库） | KNOWN 21 行：Top-1 21/21 · 动作通道 21/21；NOVEL 3 行零中/强档；样板行零动作误命中 |

**链级（v2.1，本轮实测）**

| 口径 | 成绩 |
|---|---|
| 组装质量（三入库数据集 30 单元） | 35 组"同案例多行" → **35/35 正确并链 · 0 碎片 · 0 跨案例误并** |
| 链级匹配 | 58 条链中 **57 条 Top-1 == 行级人工期望**（1 条混合载荷歧义已建例外表并注明原因） |
| 确定性 / 性能 | 乱序输入 200 次 **0 不一致**；5000 行 0.50s · 20000 行 2.00s · 50000 行 4.95s |
| 回归纪律 | 链层合入前后**行级数字零扰动**；`build_action_index.py` 幂等（两次 md5 一致） |
| 质量保障 | 3 个 deepseek-flash 子代理并行审查（组装/匹配/注入），全部发现逐条修复——见 `docs/MULTI_LOG_CHAIN_DESIGN.md` **§12.7** |

**库规模**：29 案例（CASE-001~029）· 83 动作（全部含 `stage`）· 29 案例含 `action_sources`。

## 已知边界（诚实标注）

- 组装是**批内**的：跨批次的链（前段在上一批）会断开。
- 同源模板重叠 > 300s 不并链（`TEMPLATE_SAME_SRC_S` 可调）；层间载荷形态与 URI 路径都不重合时仍可能碎片化。
- 链级评测体系（整链召回率 / 阶段精度 / 交错误并率）与交错攻击切分细化**属低优先，尚未做**（设计文档 §10）。

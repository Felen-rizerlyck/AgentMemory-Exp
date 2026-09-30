# 攻击检测 Agent 记忆机制验证

验证一个安全检测 Agent 如何把经手的每个攻击案例提取为**结构化实例记忆**，存入本地案例库（`data/memory_store.json`），供后续遇到相似攻击时检索辅助攻击链分析。

> **数据说明**：日志为清洗/模拟数据（使用文档 IP 段 `203.0.113.x` / `192.0.2.x` / `198.51.100.x`），仅用于记忆机制验证，非真实生产告警。

## 目录结构

| 路径 | 说明 |
|---|---|
| `src/retrieve.py` | 案例记忆检索器（双通道：词面 keys×3/mitre×2/ind×2/sig×1 + 模式 probes×4） |
| `data/memory_store.json` | 案例库（`cases` 案例实例 + `activity_patterns` 跨案例活动模式） |
| `dataset/` | 原始日志批次（`data-901-910` ~ `data-921-930`）+ 解析存档 |
| `data/` | 日志缓冲与回归留档（`incoming_logs.txt`、`test_prev_batches.txt`） |
| `eval/` | 评测脚手架（入口消融 C0–C2、图扩展对照 C3–C5、召回审计、前瞻测试） |
| `docs/` | 设计文档（准则、协议、决策简报、实体模型分析） |
| `Agent记忆产品落地-调研/` | 产品落地调研（独立于本验证流程） |

## 快速开始

> 所有命令在**项目根目录**执行。

```bash
# 单条检索
python src/retrieve.py "wmic /node:10.20.6.179 process call create"

# 批量检索（逐行）
python src/retrieve.py --batch data/incoming_logs.txt

# 评测（入口 C0–C2 + 扩展 C3–C5，结果写入 eval/results/）
python eval/run_eval.py

# 全数据集重放召回审计
python eval/run_recall_full.py

# 前瞻召回测试（未入库数据，先检索后提取）
python eval/run_recall_unseen.py
```

## 核心流程

每批日志固定流程：**先检索 → 再判断 → 后提取**（详见 `docs/EXTRACTION_CRITERIA.md`）。

1. **检索**：双通道匹配，命中案例标注 `[检索: CASE-xxx]`，无实质命中标【新案例】。
2. **判断**：日志按独立事件处理，不跨批次串链。
3. **提取**：高度相似 → 合并强化；新手法 → 新建案例（含 `pattern_probes` 结构正则）。

## 文档索引

| 文档 | 内容 |
|---|---|
| `docs/EXTRACTION_CRITERIA.md` | 案例提取准则 + schema + 检索协议（先读） |
| `docs/EVAL_PROTOCOL.md` | 评测协议（查询集构造、指标、判读规则） |
| `docs/RELATION_TIER_CRITERIA.md` | 案例关系档位判据（helpful/weak/unrelated） |
| `docs/GRAPH_DECISION.md` | 是否采用"案例关系图"的决策简报 |
| `docs/FRAMEWORK_READINESS.md` | 记忆模块框架选型就绪度评估 |
| `docs/PENDING.md` | 待议清单（现行标准冻结事项） |
| `docs/validation_notes.md` | 验证记录（重放测试、入库、评测轮次） |
| `docs/ENTITY_VS_CASE_GRAPH.md` 等 3 篇 | 实体-关系图模型分析（演进方向探讨） |

## 路径约定

`docs/` 下文档与本文档中的文件路径均**相对项目根目录**描述（如 `eval/results/report.md` 指根下的 `eval/results/report.md`）。

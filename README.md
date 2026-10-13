# 攻击检测 Agent 记忆机制验证（v2：动作匹配）

验证一个安全检测 Agent 如何把经手的每个攻击案例提取为**结构化实例记忆**（形式化攻击链 + 去变量的动作序列），存入本地案例库（`data/memory_store.json`），供后续遇到相似攻击时检索辅助攻击链分析。

> **数据说明**：日志为清洗/模拟数据（使用文档 IP 段 `203.0.113.x` / `192.0.2.x` / `198.51.100.x`），仅用于记忆机制验证，非真实生产告警。
> **方法说明**：现行方法为 **v2 动作匹配**（动作序列索引 + 关键词通道兜底），完整指南见 **[GUIDE.md](GUIDE.md)**。v1（关键词双通道打分）已归档至 `history/`（`old_` 前缀，保留可运行作对照）。

## 目录结构

| 路径 | 说明 |
|---|---|
| `src/retrieve.py` | 动作匹配检索器（动作通道：动作库识别 → 反向索引 → 序列对齐/预测/分叉；关键词通道：v1 打分兜底） |
| `scripts/build_action_index.py` | 动作库与案例动作序列注入/校验（幂等） |
| `data/memory_store.json` | 案例库（`cases` + `action_library` + `activity_patterns`） |
| `eval/` | v2 评测（`run_action_recall.py` → `results/report_action_recall.md`） |
| `docs/` | 设计文档（动作序列匹配可行性分析等） |
| `history/` | v1 归档（`old_retrieve.py`、`old_*.md`、`old_eval/`） |
| `dataset/` | 原始日志批次（`data-901-910` ~ `data-921-930`）+ 解析存档 |
| `Agent记忆产品落地-调研/` | 产品落地调研（独立于本验证流程） |

## 快速开始

> 所有命令在**项目根目录**执行。

```bash
# 单条检索（动作通道 + 关键词通道）
python src/retrieve.py "wmic /node:10.20.6.179 process call create"

# 批量检索（逐行）
python src/retrieve.py --batch data/incoming_logs.txt

# v2 召回审计（已入库重放 + data-921-930 前瞻）
python eval/run_action_recall.py

# 动作库注入/校验（新案例提取后执行）
python scripts/build_action_index.py

# v1 归档框架（对照用，仍可运行）
python history/old_eval/run_recall_full.py
```

## 核心流程

每批日志固定流程：**先检索 → 再判断 → 后提取**（详见 [GUIDE.md](GUIDE.md)）。

1. **检索**：动作序列对齐（完整/前缀/中段/缺口 + 预测下一步 + 分叉参考）+ 关键词兜底；命中案例标注 `[检索: CASE-xxx]`，无实质命中标【新案例】。
2. **判断**：日志按独立事件处理，不跨批次串链。
3. **提取**：高度相似 → 合并强化；新手法 → 新建案例（含动作序列，同步更新 `action_library` 并跑 `build_action_index.py`）。

## 当前成绩（v2 首轮，详见 GUIDE.md §五）

- 已入库重放（123 特征行）：组合 Top-1 122/123（99%）· 动作通道命中 123/123（100%）。
- 前瞻批 data-921-930：KNOWN 21/21 组合 Top-1；NOVEL 3 行动作通道零中强档；样板行零动作误命中。

# usability_ablation —— demo 记忆框架的可用性与消融实验

## 目录

```
eval/usability_ablation/
├── harness/                        实验脚本（全部只读 demo/data）
│   ├── build_gt.py                 140 unit 的"案例性质" GT（exact / family_variant / new）
│   ├── precompute_retrieval.py     对 140 unit 逐个跑 demo 检索 → 检索层底账
│   ├── build_stage2_sample.py      分层抽 60 条（7 精确重复 + 29 变体 + 24 新家族）
│   ├── build_step_gt.py            步骤划分 + 残缺变体 GT（waf+web 合并、rasp/hids 各一步、dns 合并）
│   ├── run_llm_arm.py              单轮判定跑批（direct / catalog / assisted / assisted_free）
│   └── score_next_phase.py         用 next-phase GT 给各条件的 next_step 打分
├── freeze.json                     实验开始前 demo/data 四个文件的 sha256（防写入/入库）
├── gt_units.json                   140 条"案例性质"GT（32 条标 needs_review）
├── gt_next_phase_60.json           60 条"下一阶段"GT（每条 2 个可接受阶段 + 关键词）
├── gt_step_level_60.json           60 unit 的步骤级 GT + 204 个残缺变体（full/del1/del2/delweb）
└── results/
    ├── dataset_1001_1140.csv       全量底账：序号 / 内容 / 检索结果 / 案例性质（140 行）
    ├── retrieval/                  每个 unit 的完整检索结果 + 供注入的"去 case_id"证据
    ├── retrieval_sweep.csv         每 unit 一行：top1 / tier / matched / order / kw
    ├── report_stage1.md            检索层全量扫描报告
    ├── next_phase_scores.csv       next-step 逐条得分（跨实验）
    ├── next_phase_report.md        next-step 汇总
    ├── exp1_memory_vs_retrieval/   ← 实验一（已完成，300 次调用）
    │   ├── runs.jsonl              每次调用一行：prompt_sha / raw / reasoning / parsed / 耗时 / 计分
    │   ├── runs_summary.csv        同上，扁平表
    │   ├── report_exp1_memory_vs_retrieval.md
    │   ├── stage2_sample_60.csv    60 条样本（序号 / 内容 / 检索结果 / 案例性质）
    │   └── stage2_sample_60.json   样本元数据（stratum / gt / 检索摘要）
    ├── exp2_catalog/               ← 实验二（只给案例摘要、不给检索）
    ├── gt_step_level_review.csv   步骤级 GT 的 204 个变体逐条明细
    ├── exp3_partial/               ← 实验三（残缺日志：del1/del2 × 三条件）
    └── exp4_channel_ablation/       ← 实验四（通道消融：raw.csv / report / summary.json）
        ├── runs.jsonl
        ├── runs_summary.csv
        ├── report_exp2_catalog.md
        └── run.log
```

## 实验清单

| 实验 | 条件 | 模型 | 调用数 | 目的 |
|---|---|---|---|---|
| exp1 | `direct`（只给日志） | qwen2.5:14b / deepseek-r1:14b | 120 | 无记忆基线（家族/阶段/下一步） |
| exp1 | `assisted`（案例库 + 检索证据，带"非 strong 不得 match"） | qwen2.5:14b | 60 | 测"照规则执行"（天花板对照） |
| exp1 | `assisted_free`（同上但去掉该句） | 两模型 | 120 | 测模型是否自行权衡证据 |
| exp2 | `catalog`（只给 8 条案例摘要，无检索） | 两模型 | 120 | 拆开"记忆本身"与"检索命中" |
| exp3（待跑） | `blind`（只有告警头）/ `retrieval_only`（只给召回，不给日志） | 两模型 | 240 | 补齐 2×2 矩阵缺失的两格 |
| exp3 | 残缺日志 × {`direct`,`catalog`,`assisted`} × {`del1`,`del2`} | qwen | 282 | 用步骤级 GT 测"补全/下一步来源"（已完成） |
| exp4 | 9 个通道配置 × 140 unit + 2 组压力输入 | 无模型 | 0 | 检索通道消融（已完成） |

`assisted_free − catalog` = 检索的增量；`catalog − direct` 只能比阶段/下一步（`direct` 无案例编号空间）。

## 两份可读报告

- `评估报告_记忆辅助效果_2026-10-22.md`：direct vs 加记忆 vs 加检索、exp3 补全、解读与局限
- `报告_检索通道消融_2026-10-22.md`：动作/关键词/闸门消融、分案例依赖、压力输入结论

## 复现

```bash
cd F:/AI_Learning/AgentMemory
python eval/usability_ablation/harness/build_gt.py
python eval/usability_ablation/harness/precompute_retrieval.py
python eval/usability_ablation/harness/build_stage2_sample.py

# 跑批（每个实验独立目录）
python eval/usability_ablation/harness/run_llm_arm.py --exp exp2_catalog \
       --models qwen2.5:14b,deepseek-r1:14b --conditions catalog

# 汇总（报告写到 --exp 指定目录）
python eval/usability_ablation/harness/run_llm_arm.py --exp exp2_catalog --score
python eval/usability_ablation/harness/score_next_phase.py
```

## 必须遵守的口径

1. **测试期不入库**：只调用 `run_demo.py` / `lookup_case_logs.py` / `retrieval.py`；不得调用 `ingest_logs.py`、`manage_memory.py add-pattern`、`link-events`。每轮跑完用 `freeze.json` 校验 hash。
2. **每轮独立**：一条 messages、无历史、`temperature=0`；子代理只在需要工具调用时使用。
3. **不要给提示性规则**：早期 `assisted` 在 prompt 里写了"档位非 strong 不得判 match"，任务退化成"读档位"（qwen 60/60），只能当天花板对照，不能当主结果。
4. **锚定率要单列**：模型给的 `case_id` 是否等于检索 top1；否则会把"检索对了"误读成"模型判断对了"。
5. **残缺实验的 GT 是机械生成的**：步骤划分规则（waf+web 同请求合并、每条 rasp/hids 各一步、连续 dns 合并）与 7 个入库案例的步数逐一吻合；60 个 unit 里 6 个单步 unit 无法减步（删后无日志），其 del1/del2 已标 `scorable:false`；2 步 unit 的 del2 与 del1 等价，也标为不可评分。
6. **next-phase GT 是粗粒度**：60 条全部 `needs_review`，每条给 2 个可接受阶段；文本→阶段用关键词近似映射，只用于横向比较，不作绝对分数。

# next-step 预测得分（GT: gt_next_phase_60.json，60 条，文本→阶段为关键词近似映射）

| 实验 | 模型 | 条件 | n | hit（含邻近） | 平均分 | 单点口径(primary) | 未映射 |
|---|---|---|---|---|---|---|---|
| exp1_memory_vs_retrieval | deepseek-r1:14b | assisted_free | 60 | 52/60 | 0.64 | 17/60 | 1 |
| exp1_memory_vs_retrieval | deepseek-r1:14b | direct | 60 | 51/60 | 0.71 | 13/60 | 3 |
| exp1_memory_vs_retrieval | qwen2.5:14b | assisted | 60 | 53/60 | 0.66 | 20/60 | 2 |
| exp1_memory_vs_retrieval | qwen2.5:14b | assisted_free | 60 | 50/60 | 0.58 | 16/60 | 3 |
| exp1_memory_vs_retrieval | qwen2.5:14b | direct | 60 | 48/60 | 0.65 | 13/60 | 3 |
| exp2_catalog | deepseek-r1:14b | catalog | 60 | 53/60 | 0.68 | 19/60 | 1 |
| exp2_catalog | qwen2.5:14b | catalog | 60 | 51/60 | 0.66 | 19/60 | 1 |

## 按分层（hit 含邻近）

| 实验 | 条件 | 模型 | exact | variant | new_with_candidate | new_no_candidate |
|---|---|---|---|---|---|---|
| exp1_memory_vs_retrieval | assisted_free | deepseek-r1:14b | 5/7 | 29/29 | 11/14 | 7/10 |
| exp1_memory_vs_retrieval | direct | deepseek-r1:14b | 6/7 | 27/29 | 10/14 | 8/10 |
| exp1_memory_vs_retrieval | assisted | qwen2.5:14b | 5/7 | 29/29 | 11/14 | 8/10 |
| exp1_memory_vs_retrieval | assisted_free | qwen2.5:14b | 5/7 | 28/29 | 11/14 | 6/10 |
| exp1_memory_vs_retrieval | direct | qwen2.5:14b | 5/7 | 24/29 | 11/14 | 8/10 |
| exp2_catalog | catalog | deepseek-r1:14b | 5/7 | 29/29 | 11/14 | 8/10 |
| exp2_catalog | catalog | qwen2.5:14b | 6/7 | 29/29 | 10/14 | 6/10 |

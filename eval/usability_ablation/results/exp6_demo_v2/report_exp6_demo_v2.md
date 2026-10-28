# exp6_demo_v2 · 60 unit × 条件 × 模型（单轮判定）

- 调用总数：121；解析失败：1；平均耗时：8.8s
- `assisted` = 带【档位非 strong 不得判 match】提示；`assisted_free` = 不给该提示，自行权衡证据

## catalog（只给案例摘要，无检索）

| 模型 | n | 归属正确 | 精确重复命中 | 变体/新案例误判 match | 平均置信 |
|---|---|---|---|---|---|
| qwen2.5:14b | 60 | 45 | 6/7 | 14/53 | 2.98 |


- （`catalog` 不给检索，锚定率不适用）
| 分层 | 模型 | n | 正确 | 判 match | 判 new |
|---|---|---|---|---|---|
| exact | qwen2.5:14b | 7 | 6 | 6 | 0 |
| variant | qwen2.5:14b | 29 | 20 | 9 | 20 |
| new_with_candidate | qwen2.5:14b | 14 | 11 | 3 | 11 |
| new_no_candidate | qwen2.5:14b | 10 | 8 | 2 | 8 |

## assisted_free（日志 + 案例库 + 召回证据）

| 模型 | n | 归属正确 | 精确重复命中 | 变体/新案例误判 match | 平均置信 |
|---|---|---|---|---|---|
| qwen2.5:14b | 61 | 41 | 7/7 | 20/54 | 2.95 |


- 锚定率：qwen2.5:14b：判 match 27 条，case_id=检索 top1 的 26 条（96%）
| 分层 | 模型 | n | 正确 | 判 match | 判 new |
|---|---|---|---|---|---|
| exact | qwen2.5:14b | 7 | 7 | 7 | 0 |
| variant | qwen2.5:14b | 29 | 13 | 16 | 13 |
| new_with_candidate | qwen2.5:14b | 14 | 10 | 4 | 10 |
| new_no_candidate | qwen2.5:14b | 11 | 11 | 0 | 11 |

## 置信度错配（assisted* 中 conf≥4 但判错）

共 0 条：无

# exp2_catalog · 60 unit × 条件 × 模型（单轮判定）

- 调用总数：120；解析失败：0；平均耗时：23.3s
- `assisted` = 带【档位非 strong 不得判 match】提示；`assisted_free` = 不给该提示，自行权衡证据

## catalog（只给案例摘要，无检索）

| 模型 | n | 归属正确 | 精确重复命中 | 变体/新案例误判 match | 平均置信 |
|---|---|---|---|---|---|
| deepseek-r1:14b | 60 | 24 | 7/7 | 36/53 | 2.93 |
| qwen2.5:14b | 60 | 45 | 7/7 | 15/53 | 2.98 |


- （`catalog` 不给检索，锚定率不适用）

| 分层 | 模型 | n | 正确 | 判 match | 判 new |
|---|---|---|---|---|---|
| exact | deepseek-r1:14b | 7 | 7 | 7 | 0 |
| exact | qwen2.5:14b | 7 | 7 | 7 | 0 |
| variant | deepseek-r1:14b | 29 | 2 | 27 | 2 |
| variant | qwen2.5:14b | 29 | 19 | 10 | 19 |
| new_with_candidate | deepseek-r1:14b | 14 | 10 | 4 | 10 |
| new_with_candidate | qwen2.5:14b | 14 | 11 | 3 | 11 |
| new_no_candidate | deepseek-r1:14b | 10 | 5 | 5 | 5 |
| new_no_candidate | qwen2.5:14b | 10 | 8 | 2 | 8 |

## 置信度错配（assisted* 中 conf≥4 但判错）

共 0 条：无

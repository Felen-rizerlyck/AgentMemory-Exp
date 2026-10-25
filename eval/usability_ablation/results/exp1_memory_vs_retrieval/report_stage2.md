# Stage 2 · 60 unit × 条件 × 模型（单轮判定）

- 调用总数：300；解析失败：0；平均耗时：29.9s
- `assisted` = 带【档位非 strong 不得判 match】提示；`assisted_free` = 不给该提示，自行权衡证据

## assisted（日志 + 案例库 + 召回证据）

| 模型 | n | 归属正确 | 精确重复命中 | 变体/新案例误判 match | 平均置信 |
|---|---|---|---|---|---|
| qwen2.5:14b | 60 | 60 | 7/7 | 0/53 | 2.95 |


- 锚定率：
qwen2.5:14b：判 match 7 条，case_id=检索 top1 的 7 条（100%）

| 分层 | 模型 | n | 正确 | 判 match | 判 new |
|---|---|---|---|---|---|
| exact | qwen2.5:14b | 7 | 7 | 7 | 0 |
| variant | qwen2.5:14b | 29 | 29 | 0 | 29 |
| new_with_candidate | qwen2.5:14b | 14 | 14 | 0 | 14 |
| new_no_candidate | qwen2.5:14b | 10 | 10 | 0 | 10 |

## assisted_free（日志 + 案例库 + 召回证据）

| 模型 | n | 归属正确 | 精确重复命中 | 变体/新案例误判 match | 平均置信 |
|---|---|---|---|---|---|
| deepseek-r1:14b | 60 | 33 | 7/7 | 27/53 | 2.68 |
| qwen2.5:14b | 60 | 43 | 7/7 | 17/53 | 2.98 |


- 锚定率：
deepseek-r1:14b：判 match 34 条，case_id=检索 top1 的 23 条（68%）；qwen2.5:14b：判 match 24 条，case_id=检索 top1 的 24 条（100%）

| 分层 | 模型 | n | 正确 | 判 match | 判 new |
|---|---|---|---|---|---|
| exact | deepseek-r1:14b | 7 | 7 | 7 | 0 |
| exact | qwen2.5:14b | 7 | 7 | 7 | 0 |
| variant | deepseek-r1:14b | 29 | 7 | 22 | 7 |
| variant | qwen2.5:14b | 29 | 15 | 14 | 15 |
| new_with_candidate | deepseek-r1:14b | 14 | 11 | 3 | 11 |
| new_with_candidate | qwen2.5:14b | 14 | 11 | 3 | 11 |
| new_no_candidate | deepseek-r1:14b | 10 | 8 | 2 | 8 |
| new_no_candidate | qwen2.5:14b | 10 | 10 | 0 | 10 |

## direct（只给日志，无记忆）

| 模型 | n | 家族命中（关键词宽松） | 编造案例编号 | 平均置信 | 平均耗时 |
|---|---|---|---|---|---|
| deepseek-r1:14b | 60 | 25/34 | 27/60 | 4.43 | 77.4s |
| qwen2.5:14b | 60 | 19/34 | 0/60 | 3.00 | 2.8s |

## 置信度错配（assisted* 中 conf≥4 但判错）

共 0 条：无

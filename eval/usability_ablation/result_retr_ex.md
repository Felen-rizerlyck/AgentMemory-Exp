# 检索通道消融报告（离线，140 unit，无模型参与）

- 日期：2026-10-22
- 对象：`demo/src/attack_memory/retrieval.py` 的检索通道
- 数据：140 个合成 unit（7 精确重复 / 29 同族变体 / 104 新家族），GT 见 `gt_units.json`
- 脚本：`harness/ablate_channels.py`；明细：`results/exp4_channel_ablation/raw.csv`

## 0. 自检

`full` 配置在 140 个 unit 上与 demo 原始 `retrieve()` 的 **top1 与 tier 完全一致（0/140 不一致）**，因此下面各配置的差异只来自被关掉的通道。

## 1. 通道结构（代码事实）

| 通道 | 实现 | 作用点 |
|---|---|---|
| 动作通道 | `steps[].action_id` + `action_regex` 匹配，`expected_sources` 兼容闸门，时间序 LCS 对齐 | 决定 `matched_steps`、`shape`、`tier`（strong/medium/weak） |
| 关键词通道 | `retrieval.keywords` ×3、`mitre` ×2、`retrieval.pattern_probes` ×4 | ① 第 5 排序键；② **候选生成**（动作索引未覆盖的案例靠词法兜底） |
| 分区 | `incident_id` 分组 | 决定"一条链"的边界 |

## 2. 主结果（每个配置只关一个通道）

| 配置 | T0 命中(7) | 变体落点(29) | 新家族硬误判(104) | MRR | 无候选 | strong | medium | weak | kw_only |
|---|---|---|---|---|---|---|---|---|---|
| `full` | 7/7 | 13/29 | 0/104 | 0.603 | 60 | 7 | 0 | 51 | 22 |
| `no_probes` | 7/7 | 13/29 | 0/104 | 0.603 | 61 | 7 | 0 | 51 | 21 |
| `no_mitre` | 7/7 | 13/29 | 0/104 | 0.603 | 60 | 7 | 0 | 51 | 22 |
| `no_keywords` | 7/7 | 12/29 | 0/104 | 0.574 | 81 | 7 | 0 | 51 | 1 |
| `no_lexical`（三个词法全关） | 7/7 | 12/29 | 0/104 | 0.559 | 82 | 7 | 0 | 51 | 0 |
| `no_action` | **0/7** | 14/29 | 0/104 | 0.618 | 70 | **0** | 0 | 0 | 70 |
| `no_source_gate` | 7/7 | 13/29 | 0/104 | 0.603 | 60 | 7 | 0 | 51 | 22 |
| `no_order_check` | 7/7 | 13/29 | 0/104 | 0.603 | 60 | 7 | 0 | 51 | 22 |
| `no_tier_rank` | 7/7 | 13/29 | 0/104 | 0.603 | 60 | 7 | 0 | 51 | 22 |

## 3. 分案例：谁依赖哪个通道

7 个 T0 案例在各配置下的 top1/tier：

| unit | GT 案例 | full | no_keywords | no_lexical | no_action | no_probes |
|---|---|---|---|---|---|---|
| 1001 | CASE-001 | CASE-001/strong | CASE-001/strong | CASE-001/strong | CASE-001/**keyword_only** | CASE-001/strong |
| 1021 | CASE-002 | CASE-002/strong | CASE-002/strong | CASE-002/strong | CASE-002/**keyword_only** | CASE-002/strong |
| 1042 | CASE-003 | CASE-003/strong | CASE-003/strong | CASE-003/strong | CASE-003/**keyword_only** | CASE-003/strong |
| 1061 | CASE-004 | CASE-004/strong | CASE-004/strong | CASE-004/strong | CASE-004/**keyword_only** | CASE-004/strong |
| 1081 | CASE-005 | CASE-005/strong | CASE-005/strong | CASE-005/strong | CASE-005/**keyword_only** | CASE-005/strong |
| 1102 | CASE-006 | CASE-006/strong | CASE-006/strong | CASE-006/strong | CASE-006/**keyword_only** | CASE-006/strong |
| 1121 | CASE-007 | CASE-007/strong | CASE-007/strong | CASE-007/strong | CASE-007/**keyword_only** | CASE-007/strong |

结论：**top1 从不依赖关键词通道，但档位依赖动作通道**。词法通道只影响两处变体的候选：

- `1048`（JSP webshell 执行，GT=CASE-002）：关掉词法后**没有候选**——它的动作与 CASE-002 的上传步不共享 `action_id`，只靠关键词兜底；
- `1050`（ASPX webshell，GT=新案例）：关掉词法后没有候选——**词法兜底同时也制造了一次错误的家族牵引**（full 下被拉到 CASE-008）。

## 4. 闸门有效性（需要构造异常输入才触发）

完整 unit 不会触发 `expected_sources` 与 `order` 闸门（0/140 变化），因此构造两种压力输入：

| 压力输入 | 配置 | n | 误报 strong | top1 正确 |
|---|---|---|---|---|
| `shuffle`（时间戳倒序） | `full` | 140 | **0** | 20 |
| `shuffle`（时间戳倒序） | `no_order_check` | 140 | **0** | 20 |
| `swap_src`（把 rasp 行改成 web） | `full` | 89 | **0** | 11 |
| `swap_src`（把 rasp 行改成 web） | `no_source_gate` | 89 | **6** | 11 |

- **`expected_sources` 闸门是必要的**：来源错位时会挡住 6 个本会误报 `strong` 的命中。
- **`order` 校验在本实现下不独立生效**：对齐前先按时间排序，时间戳乱序会直接把动作序列打乱、使 `matched < total`，因此无论有没有 `order_ok` 都拿不到 `strong`。`order_ok` 只能捕捉"同一时刻并列"这类边角情形。

## 5. 四条可引用结论

1. **动作通道是唯一能产出 `strong` 的通道**：关掉后 7 个 T0 全部降为 `keyword_only`，`strong` 归零；它同时是"链路完整性/缺口"的唯一来源。
2. **关键词通道基本不影响排序，但决定候选面**：关掉后 top1 只变 2 个 unit，但无候选从 60 升到 82（+22），MRR 从 0.603 降到 0.559。
3. **三部分词法通道里只有 `keywords` 在起作用**：`probes` 仅影响 2 个 unit，`mitre` 影响 0 个——权重 4 的 probes 和权重 2 的 mitre 在本数据集上几乎是冗余项。
4. **`expected_sources` 必要、`order` 冗余、`tier` 排序无差别**：前者在异常输入下挡住 6 个误报；后者因"先排序后对齐"而从不独立生效；档位排序与覆盖度排序在本数据上同序。

## 6. 局限与下一步

1. **数据太"干净"**：140 个 unit 都是完整、有序、来源正确的链，闸门类配置只有靠构造压力输入才有区分度；这也解释了为什么 `no_source_gate`/`no_order_check` 在主表里全是 0 变化。
2. **没有跨案例共享 `action_id` 的探针**：demo 的已知缺陷之一是同名 `action_id` 的正则并集；要测它需要专门构造两个案例共用 `action_id` 但正则不同，本批数据没有。
3. **`incident_id` 分区没有做消融**：需要把多个 unit 混成一批（不写 `incident_id`）看是否串链，这一步与上面的通道消融相互独立。
4. **MRR 只在 36 个有 GT 家族的 unit 上算**，新家族无法参与，样本偏小。

建议后续补两组构造：① `incident_id` 混批（链层分区消融）；② 同名 `action_id` 双案例（正则并集缺陷）；③ 乱序但保持动作序列的构造（例如只交换两条同 step 日志的时间），用来真正检验 `order` 校验。

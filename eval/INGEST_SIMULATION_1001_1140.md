# 140 unit 入库模拟（unit 1001–1140）

用当前 `demo/` 的算法与 `skills/attack-memory` 的规则，把 `dataset/` 的 140 个 unit（536 行）
作为独立批次灌入**隔离沙箱**，检验新增的“案例归类 / 优化”机制。

- 沙箱记忆：`eval/ingest_simulation_1001_1140/demo/data/`
- 决策明细：`decision_report.csv`
- 汇总：`summary.json`
- 两条提案：`proposals.json`
- 入库后审计：`audit_after_ingest.txt`

真实 `demo/` 未被修改。重跑：

```powershell
python eval/simulate_ingest_1001_1140.py
```

## 0. 为什么 attack_patterns.json 不会因入库自动增加

- `ingest_logs.py` 只把观测追加到 `raw_logs.csv`，留空 `case_id`；它不写 pattern。
- 建案只有 `add-pattern` 一条显式路径，需要人/agent 写完整 steps 与正则。
- 新规则：`add-pattern` 需要 **≥2 个 supporting incident**，或显式 `--force`。
  单条 unit 不能变成一个案例。

## 1. 归类规则

| 检索结果 | 动作 | 写入 |
|---|---|---|
| `strong` / `medium` | 链级证据成立 | confirmed link（写 case/incident 标签） |
| `weak` + `prefix`/`tail` | 单步变体 | related link（**不写标签**，只关联到该步） |
| FA / FC 家族 unit | 经复核的家族关联 | related link（无 step，关联到 CASE-005 / CASE-007） |
| 其它 | 未分类 | 不建案，留在 raw_logs |

`related` 的语义是“属于该 case 的变体/家族”，不是“确认了它的标准链”。它不设置
`case_id`，但会计入提案支持数。

## 2. 结果

```
unit 140 / 新增行 536
links 45 -> 261（confirmed 29 行；related 187 行：121 家族关联 + 66 步级关联）
patterns 8 -> 8（new cases 0）
versions: CASE-005 v2, CASE-007 v2
audit: clean（计数与 maturity 读时从 confirmed 链接推导）
```

| 决策 | 数量 |
|---|---|
| confirmed_existing | 7（1001/1021/1042/1061/1081/1102/1121） |
| related_step | 4 |
| related_family | 38（FA 19 + FC 19） |
| unclassified | 91 |
| **新建案例** | **0** |

关联到已有案例的 incident：

| case | related incidents |
|---|---|
| CASE-005 | 20（19 FA + 1 单步） |
| CASE-007 | 19（FC） |
| CASE-008 | 2（单步） |
| CASE-003 | 1（单步） |

## 3. 案例优化

两条 family-level 的 optional 步骤通过门禁并被接受：

| case | 新增步骤 | 支持 incident | 结果 |
|---|---|---|---|
| CASE-005 | S9 恢复能力破坏/批量加密变体 | 19 FA | v1 -> v2 |
| CASE-007 | S4 CI 构建期执行/凭据访问变体 | 19 FC | v1 -> v2 |

门禁读数（`proposals.json`）：support_incidents 分别 ≥19，`strong_before == strong_after`
（optional 不降级），top-1 只在支持 incident 上变化，foreign_matches = 0。

接受后把支持事件以 `related` + `step_id` 挂到新步骤上：CASE-005/S9 `linked=32`，
CASE-007/S4 `linked=30`，其余 matched 是已 confirmed 到其它步骤的事件（指标里的 ambiguity）。

## 4. 防碎片化

- 反事实：如果“没确认就建新案”，140 个 unit 会变成 **133 个新案例（8 -> 141）**。
- 实际：**0 个新案例**；42 个变体通过 `related` 归到已有案例；91 个真正不同的技术保持
  未分类，等待第二次出现或人工复核，而不是各自成为一个案例。
- 建案守卫实测：`require_pattern_support` 对单 incident 报
  `a new pattern needs at least 2 supporting incidents`；两个 incident 才通过。

91 个未分类的构成：FB 19、F1 19、F2 18、F3 17、F4 18。其中 FB（Kerberos/DCSync）
没有关联到 CASE-006（CASE-006 只是 BloodHound 侦察），避免把“域内攻击”过度合并。

## 5. 文件与复跑

```powershell
python eval/simulate_ingest_1001_1140.py
python eval/ingest_simulation_1001_1140/demo/src/manage_memory.py metrics --case-id CASE-005
```

sandbox 里的 `attack_patterns.json` 现在有 8 个案例，其中 CASE-005/CASE-007 为 v2，
`pattern_versions/` 下各有 v001/v002 快照。

# 正式入库结果（真实 `demo/`，unit 1001–1140）

2026-10-27 将 140 个 unit / 536 行正式写入真实 `demo/`，按当前 skill 执行
`ingest → 归类（confirmed / related / unclassified）→ 两条 family 提案 → audit`。

- 执行脚本：`eval/apply_ingest_1001_1140.py`
- 报告：`eval/ingest_applied_1001_1140/`
- 备份（入库前）：`demo_backup_20261027-171749`

## 结果

```
raw_logs.csv            45 -> 581 行
event_pattern_links.csv 45 -> 265 行
attack_patterns.json    8 -> 9 个案例（CASE-009 由候选晋升）
CASE-005                v1 -> v2（新增 optional S9）-> v3（S9 迁入 family）
CASE-007                v1 -> v2（新增 optional S4）-> v3（S4 迁入 family）
CASE-009                v1（CAND-0001 晋升，single_sample，unreviewed）
步数                    34 -> 32（0 optional case steps）
proposals               2 条 accepted（auto）
migrations              2 条 v2->v3
admissions              1 条（ADM-CASE-009 unreviewed）
candidate clusters     91 records -> 84 active (77 provisional / 6 promotable / 1 promoted) + 7 merged
audit                   clean（计数与 maturity 读时从 confirmed 链接推导）
```

| 决策 | 数量 |
|---|---|
| confirmed 到已有案例 | 7 |
| related_family（FA 19 + FC 19） | 38 |
| related_step | 4 |
| unclassified | 91 |
| **入库新建案例** | **0** |
| **候选晋升案例** | **1（CASE-009）** |
| 候选（provisional / promoted） | 90 / 1 |

`related` 关联的 incident：

| case | related incidents |
|---|---|
| CASE-005 | 20 |
| CASE-007 | 19 |
| CASE-008 | 2 |
| CASE-003 | 1 |

## 家族分布

9 个案例分到 5 个家族；91 个候选按 `form` 映射到家族：

| family | cases | candidates | family steps |
|---|---|---|---|
| web-exploit | 5（CASE-001/002/004/008/009） | 55 | - |
| host-persistence | 1（CASE-003） | 17 | - |
| ransomware | 1（CASE-005） | 0 | S9 |
| domain-identity | 1（CASE-006） | 19 | - |
| supply-chain | 1（CASE-007） | 0 | S4 |

S9/S4 已从 case 迁到 `families.json`；历史 `related + step` 链接仍按 family step 审计，
`run_demo` 单独显示 family evidence，不改变 case 的 strong/medium 判定。

## v3 迁移台账

`data/pattern_migrations.json` 记录两条 reviewed migration：

```
MIG-CASE-005-v3  CASE-005  v2->3  move_step_to_family  S9 -> ransomware
MIG-CASE-007-v3  CASE-007  v2->3  move_step_to_family  S4 -> supply-chain
```

每条记录包含 `snapshot`（v003）、`basis`、`decided_at`。`catalog migrations` 可列出；
`catalog validate` / `audit` 检查快照存在、版本连续、step 已从 case 迁出、family step 存在。

## 有效性对照

| 指标 | 入库前 | 入库后 |
|---|---|---|
| 案例数 | 8 | **9（含 1 个候选晋升）** |
| 入库新建案例 | — | 0（反事实 133） |
| 候选晋升案例 | — | 1（CASE-009） |
| 归到已有案例的变体 | 0 | 42 |
| 进化案例 | 0 | 2（CASE-005、CASE-007） |
| 每条链接/标签可审计 | 是 | 是（`audit` clean） |

原 8 个 seed incident 仍全部 `strong`；CASE-005/CASE-007 的 S9/S4 先作为 optional 步加入 v2，
再在 v3 迁入 family，case 的 required 骨架始终是 3 步。

## 检查入口

```powershell
cd demo
python src/manage_memory.py audit --verbose --case-id CASE-005
python src/manage_memory.py audit --verbose --case-id CASE-007
python src/manage_memory.py evolve list
python src/manage_memory.py catalog candidates
python src/manage_memory.py catalog families
python src/manage_memory.py catalog migrations
python src/manage_memory.py catalog admissions
python src/manage_memory.py catalog candidates --by-group
python src/manage_memory.py audit
python src/lookup_case_logs.py --case-id CASE-005 --status related
python src/run_demo.py --input data/raw_logs.csv --incident-id INC-CASE-005-001
```

期望：CASE-005 v3 `strong 3/3 required, 0 optional`，related_incidents=20，family evidence 显示 S9；
CASE-007 v3 `strong 3/3 required, 0 optional`，related_incidents=19，family evidence 显示 S4；
两条提案 accepted；91 个候选中 90 个 `provisional`、1 个 `promoted`；audit clean。

## 候选层

91 个未分类 unit 已通过 `eval/stage_candidates_1001_1140.py` 写入
`demo/data/case_candidates.json`：

```
91 candidate records: 84 active + 7 merged aliases
provisional=77, promotable=6, promoted=1, rejected=0, merged=7
```

每个 unit 的原始 `signature` 不同，所以最初都是 `provisional`；第 1 步签名归一化后，91 个候选
归为 84 个 `signature_key` 组，其中 7 个重复组、14 个成员。第 2 步已将这些重复组 merge：
6 组变 `promotable`，Spring4Shell 组保持 `promoted` 并记录 pending link，7 个 alias 变
`merged`。

## 候选晋升演示（CAND-0001 → CASE-009）

```
candidate   CAND-0001  F1::Spring4Shell CVE-2022-22965
incident    SIM-INC-1002（4 个事件：waf/web/rasp/hids）
pattern     data/promoted/CASE-009.json
promotion   catalog add --from-candidate CAND-0001 --input ... --force
result      CASE-009 v1，single_sample，strong 3/3，unreviewed
links       SIM-1002-1/2 → S1，SIM-1002-3 → S2，SIM-1002-4 → S3（confirmed）
metrics     S3 matched=1 linked=1 ambiguity=0
```

S1 的 `class.module.classLoader`、S2 的 `classLoader.first`、S3 的
`catalina.sh + whoami` 都从该候选自己的事件里提取；`--force` 只跳过“≥2 incident”的数量
门槛，仍校验事件匹配。晋升后候选标记 `promoted`，指向 `CASE-009`；CASE-009 同时写入
`case_admissions.json`（`ADM-CASE-009`，unreviewed）。

## 候选签名第 1 步

`eval/backfill_candidate_signatures.py` 给 91 个候选回填：

- `signature_key`：family + CVE + primary product + primary action 的哈希；
- `signature_terms`：CVE/产品/全部动作 token，供审阅；
- `signature_features`：cves/products/actions/primary_action。

结果：

```
91 candidates -> 84 signature groups
7 duplicate groups / 14 grouped members
Spring4Shell: CAND-0001 + CAND-0066
Spring Cloud Gateway: CAND-0002 + CAND-0058
Node.js vm: CAND-0014 + CAND-0059
GitLab ExifTool: CAND-0033 + CAND-0063
Solr / Confluence / Django: 各一对
```

`catalog candidates --by-group` 只分组，不合并、不改变 provisional/promotable。同产品不同技术
（OFBiz XML-RPC vs Groovy）保持分开；仅产品为 PHP 的候选不会被误合并。

## 候选签名第 2 步（merge/split）

`eval/merge_signature_groups.py` 把同 family、同 `signature_key` 的重复组 merge 成 cluster：

| primary | alias | 结果 |
|---|---|---|
| CAND-0002 | CAND-0058 | promotable（Spring Cloud Gateway） |
| CAND-0003 | CAND-0057 | promotable（Confluence OGNL） |
| CAND-0008 | CAND-0056 | promotable（Solr Velocity） |
| CAND-0014 | CAND-0059 | promotable（Node.js vm） |
| CAND-0018 | CAND-0070 | promotable（Django SQL） |
| CAND-0033 | CAND-0063 | promotable（GitLab ExifTool） |
| CAND-0001 | CAND-0066 | 保持 promoted（CASE-009），`pending_case_links=["SIM-INC-1073"]` |

`catalog merge` / `catalog split` 可手工审查；alias 以 `status=merged` 保留，`merged_into` 指回
primary，split 可还原非 promoted cluster。promoted cluster 不允许 split；新 incident 只进入
`pending_case_links`，不会自动建 CASE-010。

## 新 case 的审核状态

模型允许直接写 `attack_patterns.json`，但每个新 case 都留 admission：

```
ADM-CASE-009  CASE-009  unreviewed  candidate:CAND-0001
pattern: review_status=unreviewed, admission_id=ADM-CASE-009
```

实验阶段没有人工门禁，CASE-009 保持 `unreviewed`；`run_demo` 会显示 `UNREVIEWED`。部署时用
`catalog review-case --case-id CASE-009 --basis ... --reviewer ...` 清除标记，ledger 变为
reviewed，`admission_id` 保留用于追溯。`catalog validate` / `audit` 检查 ledger 与 marker 一致。

## 剩余说明

- 剩余候选：77 provisional、6 promotable、1 promoted、7 merged；6 个 promotable 待作者写 pattern。
- 它们留在 `raw_logs.csv`（`SIM-B-*` 批次）并由 `case_candidates.json` 跟踪，没有被强行建案。
- CAND-0001 的事件现在带 `CASE-009` / `SIM-INC-1002` 标签；CAND-0066 的 incident `SIM-INC-1073`
  进入 `pending_case_links`，尚未自动链到 CASE-009。
- FA→CASE-005、FC→CASE-007 的家族关联是复核判断，不是自动聚类。
- S9/S4 已迁到 family；case 只保留具体 required 链，`run_demo` 单独展示 family evidence。

# 案例写入规范（严格格式 — 模型写案例的唯一依据）

> 触发：检索判读为【新案例】或【合并强化】时。写之前先读本文件。
> 本文件补齐 GUIDE.md schema 表没有的机械步骤：何时写、写到哪个文件、精确格式、写完怎么验证。

## 一、何时写 / 写什么

| 情况 | 动作 |
|---|---|
| 无实质命中（动作零命中 + 关键词仅弱档≤3） | **新建案例**（CASE 顺序编号） |
| 高度相似（同路径/同指纹/同工具链；同模版再现；同链不完整观测=前缀） | **合并强化**（不新建，见 §四） |
| 技术不同（即使同家族、共享探针模板；后续动作不同=分叉） | **新建案例** |
| 重复送达（同日志 ID + 时间戳 + 实体三重一致） | **不写、不计数**（幂等） |

## 二、写到哪（两个文件、三处位置，缺一不可）

| 内容 | 文件 | 位置 |
|---|---|---|
| ① 案例本体 | `data/memory_store.json` | `cases` 数组末尾（`]` 之前）；**不写 `action_sequence`**（脚本注入） |
| ② 新动作 | `scripts/build_action_index.py` | `ACTIONS` 字典末尾（`}` 之前） |
| ③ 动作序列 | `scripts/build_action_index.py` | `SEQUENCES` 字典末尾（`}` 之前） |
| ④ 动作阶段 | `scripts/build_action_index.py` | `STAGES` 字典（每个新动作都要有一条阶段标注，取值见 §五） |
| ⑤ 观测来源 | `scripts/build_action_index.py` | `SOURCES` 字典（每个新案例一条，**键序必须与 SEQUENCES 完全一致**；单值为字符串，多来源用列表，如 `["waf","web","rasp"]`，无约束用 `"any"`） |

> **写入顺序（重要，实测踩过坑）**：① 案例本体 → ② `ACTIONS` → ③ `STAGES` → ④ `SEQUENCES` → ⑤ 在 `scripts/derive_action_sources.py` 的 `BATCH_EVIDENCE` 登记该批证据（批次文件路径 + 该批 `log_id`→案例 映射；不在 dataset/ 里的新案例都要登记）→ 跑 `python scripts/derive_action_sources.py`（自动生成 `SOURCES`）→ 跑 `python scripts/build_action_index.py`（注入 + 校验）。
> 乱序会被拦住（这就是门禁存在的意义）：只写①会报「案例缺 action_sources」；先写④不写①会报「序列引用了库中不存在的案例」；`SOURCES` 与 `SEQUENCES` 不对齐会报「SOURCES 与 SEQUENCES 未对齐」。`derive` 已改为以 build 脚本的 `SEQUENCES`/`ACTIONS` 为准，因此案例本体入库后即可先跑，不会与 build 死锁。
> 推荐用 `json` 库读写（load → append → dump, ensure_ascii=False, indent=2）保证合法与缩进统一；直接文本插入须严格对齐现有条目缩进（json.dumps indent=2：数组元素对象字段 6 空格）。

## 三、新建案例的精确字段（必填，顺序与现有条目一致）

| 字段 | 类型 | 约束 |
|---|---|---|
| `id` | str | `CASE-0NN` 顺序编号（取现有最大 +1） |
| `source` | str | `WAF`/`RASP`/`HIDS`/`DNS`，多源用 `+` 连接（如 `WAF+RASP`） |
| `attack_type` | str | 攻击类型中文短语，含手法/载体 |
| `kill_chain` | list[str] | 按攻击链阶段顺序（侦察→初始访问→执行→横向→持久化→外传…） |
| `mitre` | list[str] | ATT&CK 技术编号（如 `T1190`、`T1059.002`） |
| `indicators` | dict | 观测事实：列表字段用 `observed_*`（targets/domains/payloads/ips），单值字段用具体名（path/payload/encoding/detection…） |
| `signature` | str | 攻击指纹精简描述（用于相似性判断） |
| `reasoning` | str | 判定结论 + 攻击链推理；**证据从严，只记日志可见内容** |
| `retrieval_keys` | list[str] | 判别性红线：**禁系统文件路径**（/etc/*、/bin/*、/var/spool/*、/dev/tcp）；命令探针（whoami/id）与落地文件（/tmp/.svc）**保留** |
| `pattern_probes` | list[str] | 结构正则（关键词通道兜底）；**只锚定特有结构**（技术指纹/编码形态/完整路径模板），禁通用命令（;id/cmd=id/whoami）与通用路径（/etc/passwd、/bin/sh） |

**禁止手写 `action_sequence`** —— 由 `build_action_index.py` 按 SEQUENCES 注入。

正则转义提醒：JSON 里反斜杠要写 `\\`（双反斜杠）才能存成单个 `\`（如 `"\\$\\{jndi:"`）；`build_action_index.py` 里用 Python raw string `r"..."` 单反斜杠。

## 四、合并强化（不新建）

判据命中时改**既有案例**，不改 id：
- 追加观测值到 `indicators` 的 `observed_*` 列表（IP/域名/目标/载荷）；
- 观测次数 +1（signature 里的"已 N 次观测"）；
- `reasoning` 末尾追加「新增观测：日期 现象」段落；
- 出现编码/路径/载荷**变体** → 追加到对应 indicators 列表 + 修订/补 `pattern_probes`（补完须过 §六 门禁）。

## 五、动作与序列格式

- 动作（`ACTIONS` 字典条目）：`"action_id": {"label": 中文去变量名, "regex": r"结构正则", "generic": false}`
  - `generic: true` **仅限通用探针**（whoami/cmd=id/echo;id/id;hostname 等），单发命中=弱参照。
- 阶段（`STAGES` 字典条目）：`"action_id": "<阶段>"`，取值 = `recon`（侦察/发现，不参与顺序判定）/ `initial_access` / `execution` / `privilege` / `persistence` / `lateral` / `c2` / `exfil`；口径 = 该动作用于攻击链哪一步（按语义 + 案例证据，非臆造）。
- 序列（`SEQUENCES` 字典条目）：`"CASE-0NN": ["action_id", ...]`，按攻击链顺序。
- 来源（`SOURCES` 字典条目）：`"CASE-0NN": {"action_id": 来源, ...}`，**键序与 SEQUENCES 一致**；来源取值 = `waf` / `web` / `rasp` / `hids` / `dns` / `any`（多来源用列表，任一命中即通过；通用探针一律 `any`）。优先取"该动作实际被观测到的层"（可用 `python scripts/derive_action_sources.py --dry-run` 复核推导）。

## 六、验证门禁（写完必跑，全绿才算入库完成）

```bash
cd F:/AI_Learning/AgentMemory
# 1. 注入 + 校验（必须输出「校验通过: 77+ 动作 / N 案例序列 / ... / stage 标注 / action_sources N 案例」）
python scripts/build_action_index.py
# 2. 回顾性重检：该日志应命中新案例（行级）
python src/retrieve.py "<该日志行>"
# 2b. 链级重检（多行批）：组装是否正确并链、链级 Top-1 是否为新案例
python src/retrieve.py --chain data/incoming_logs.txt
# 3. 全量回归：既有数字不变（Top-1 122/123、动作通道 123/123、前瞻 KNOWN 21/21）
python eval/run_action_recall.py
# 4. 单测/集成测试（组装层 + 链级）
python tests/test_chain_assembly.py && python tests/test_chain_integration.py
```

## 七、防 drift 清单（写完自查）

- [ ] 案例本体写进 `cases` 数组、动作写进 `ACTIONS`、阶段写进 `STAGES`、序列写进 `SEQUENCES`、来源写进 `SOURCES`（五处都写了）
- [ ] `SOURCES` 的键序与 `SEQUENCES` 完全一致（动作数相同、顺序相同）
- [ ] 没手写 `action_sequence` / `action_sources`（脚本注入）
- [ ] `retrieval_keys` / `pattern_probes` 过了判别性红线（无系统路径/通用命令）
- [ ] JSON 逗号/括号闭合、缩进与现有条目一致
- [ ] build 脚本「校验通过」+ 行级重检命中 + **链级重检并链正确** + 回归数字不变 + tests 全绿
- [ ] 证据只记日志可见内容，未夸大

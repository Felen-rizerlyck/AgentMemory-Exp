# 加层 / 升级操作手册（AgentMemory 管线）

> ⚠ **仅开发/升级阶段使用**：本文件是给「改这套管线」（加层、改打分/动作库/参数、接新数据源、跑回归）用的，**不是每次分析日志要走的流程**——日常运行走 `SKILL.md` + `references/runtime-playbook.md`。

适用：给这套管线加一层能力（如多日志链层）、改打分/动作库/参数、或接入新数据源。目标 = 改动可验证、可回滚、不破行级铁律。本文件是 `SKILL.md`「加层/升级工作流」的展开。

## 0. 铁律（每次改动都成立）

- **行级基线是红线**：`python eval/run_action_recall.py` 的数字必须不变（基线：特征行 123 · Top-1 122 · Top-3 123 · 动作命中 123 · 强档 60 · 样板行 10 且误命中 0 · 前瞻 NOVEL 0 中/强档）。
- **只加层不改核心**：新能力 = 新模块 + 追加函数；既有行级函数保持不动。万不得已要动（如缓存键 bug），必须全量回归并在设计文档把该处记为"对既有代码的唯一触碰"。
- **改前留档**：大幅修改的已有文件先存 `history/old_<名>.py|md`；数据文件同样留 `history/old_memory_store_pre_*.json`（用户要求，用于回滚/对照）。
- **git 不提交**：改动留在工作区，用户自己统一处理。
- **参数集中在模块顶部常量**并标注"待真实数据校准"，不要散落到函数里；每条参数写清语义（尤其别让一个参数承担两种语义——曾出现 `window_s` 同时当拆簇窗与并链窗，调大拆簇窗会静默改变并链行为）。

## 1. 开工前（用户确认闸门）

1. 读现况：`GUIDE.md` + 目标设计文档 + `src/` `scripts/` `eval/` `tests/` 的当前实现；跑一遍基线（`scripts/build_action_index.py --dry-run`、`eval/run_action_recall.py`、两个测试文件）并记下数字。
2. 出「方案修改清单」：逐条给"文档原样实现会出的问题 / 建议改法 / 是否可回滚"。用户欢迎主动建议（照抄设计文档往往踩坑，如缺字段值域、缺顺序校验、缺阶段映射来源）。
3. 用 clarify 一次性确认：采纳范围 / 是否新增字段 / 标注要不要先审 / 流程接管时机 / 提交方式——一次问完，别逐个来回。
4. 流程接管：**先并行一批**（新旧输出并列给用户），确认输出形态后再改默认；不要擅自把新层设成默认判定单元。

## 2. 实施顺序（每步以可跑命令收尾）

1. 新模块 + 单测（stdlib `unittest`，零依赖；自造库让单测 hermetic）→ 跑单测。
2. 存储/注入改造（平行字典 + 校验 + 幂等）：`scripts/build_action_index.py` 连跑两次比对 md5，必须一致。
3. 入口追加（不改既有路径）→ 跑行级回归确认数字不变。
4. 输出格式 + 人可读渲染（含"进行中/待确认"提示语）。
5. fixture（从已有 dataset 导出，生成脚本要可重跑且字节一致）+ 集成测试（真实库 + fixture）。
6. 文档同步：设计文档"实现记录/偏差/实测"章节 + GUIDE 章节 + README + skill 双副本（仓库副本 + Hermes home 镜像，`cp` 后 `diff -q` 确认）。README 更新后**逐项核对而非凭记忆**：目录表/快速开始/成绩数字/已知边界要与真实状态一致，且**文档里出现的每条命令真跑一遍、引用的每个路径确认存在**（写个小脚本把反引号里的 `路径` 抽出来批量 `exists()`）——文档漂移比没有文档更糟，成绩数字一过期就没人敢信。

## 3. 沙箱实测配方（改"基线锁定"的东西前必做）

```python
lib2 = copy.deepcopy(lib)                       # 只改内存副本，不写盘
lib2[aid]["regex"] = new_rx                      # 或改打分/参数
ret._ACTION_RES.clear()                         # 清正则缓存，否则旧编译结果复用
# 跑全口径：Top-1 / 动作命中 / 强档 / 样板行误命中 / NOVEL 中强档 / 链级 并链·碎片·误并·Top-1
# 并逐行 diff 出"受影响的日志行"清单
```

只有全口径零扰动才落地；有影响就先回报用户影响面再决定。留档要求：改动前把将被改的文件复制到 `$LOCALAPPDATA/Temp/`（脚本类）或 `history/`（面向未来的留档）。

### 3.1 打分通道的边际贡献（变体实验：回答"某字段/通道是否冗余、能不能删"）

这类问题**不许凭直觉或数重叠率**，要量化。做法：每个变体独立加载一份 `retrieve` 模块（`importlib.util.spec_from_file_location`），覆写该模块的 `keyword_score`，再跑同一套指标（特征行 Top-1/Top-3/动作命中/强档 + 前瞻 KNOWN/NOVEL 中强档）：

```python
def make_ks(use_sig=True, probe_w=4, kw_off=False):    # 逐通道开关 + 可改权重
    def ks(case, ql):
        if kw_off:
            return 0, []
        # 照原实现逐通道累加（keys×3 → mitre×2 → ind×2 → sig×1 → probes×probe_w）
        # 并**保留原实现的 seen 跨字段去重**，否则测的是另一个打分器
        ...
    return ks

rt = load(BASE / "src" / "retrieve.py", "ret_v_V1")     # 每变体单独加载，避免互相污染
rt.keyword_score = make_ks(use_sig=False)
```

对照基线（可作为"这些通道到底值多少"的答案）：动作通道在**所有**关键词变体下不变（123/123 · 强档 60）；关键词通道整体只值 Top-1 **3 行**，其中 `signature` 通道 1 行、`pattern_probes` 权重 4→2 或不计分 **0 行**。字段重叠率（29 案例 / 224 个 `retrieval_keys`）：keys∩signature 31%、keys∩ind 22%、keys∩probe 字面 9%。

→ 结论：多字段重叠是**分层表达**（词面 / 结构 / 观测事实）的设计后果，且已做跨字段 token 去重，**不为"重复"删字段/改字段结构**；真要降噪优先动纪律（关键词强分不作判定依据）或给 `pattern_probes` 补"字面已在 seen 则跳过"这一条，且改前用本配方复测。

## 4. 子代理并行审查（固定动作）

- **编排**：一次 `delegate_task` 派 3 个**只读**子代理，按层分工（组装 / 匹配 / 注入与标注），模型用当前 Flash；给每个子代理 output_schema（verdict + findings[severity, where, actual, expected, evidence, fix] + verified）。
- **prompt 要素**：仓库绝对路径 + 设计文档路径 + **本层关键语义逐条列出**（让子代理"验真伪"而不是泛读代码）+ 要求最小复现命令 + 临时脚本只许放 `$LOCALAPPDATA/Temp`、**不许写仓库 / 不许 git**。
- **复核纪律**：子代理结论先复现再改；每条修复配回归用例（把复现脚本的期望值写进测试断言）。
- **收尾审计**：写一个把每条发现的"修复标记"当断言的脚本跑一遍（如"代码里是否还有按 id 重对齐的调用""缓存键是否含 regex"），30 条级别也能一次核完——不要用"我记得改过"代替。

## 5. 确定性 / 分组类代码的硬规则（踩过的坑）

- 排序键**不得含输入下标**（`idx`）：并列键（同时间戳 + 缺 log_id）时结果随输入顺序变。用内容完备键 `(ts, source, log_id, content)`。
- 确定性测试**必须构造并列键用例**（键全 distinct 的用例会空过）；再加"同一批随机打乱 N 次结果一致"的断言。
- 共现/并发信号用**窗内滑窗两两配对**，别只看全局相邻行（中间夹一行噪声即失效）。
- 跨源与同源用**不同阈值**：同源重叠是弱证据（同源模板 >300s 不并链）；**宁可切开让上层合并，不要粘连让上层拆开**——误并比碎片危害大。
- 最强信号（会话键）不被时间窗拆散，跨窗只标记；豁免切链要判"切点两侧是否直连"，不要按整分量一刀切。
- 切链/拆簇后，flag 只挂到**触发行所在的子链**，别复制给所有子链；单行碎片不要继承分量级"高置信"。
- 缓存键要含正则本身（`(aid, regex)`）；只按 id 缓存会让"换库不生效"。
- 匹配层要按**位置**复算形态（沿用集合语义的对齐函数会把"来源不符"的位置重新捞回，案例序列一旦含重复动作 id 就出错）。

## 6. 测试卫生

- 假 matcher 必须按**传入的 lib** 编译正则（否则临时新增的测试动作永不命中，用例空过——踩过）。
- 性能用例先断言"用例行全部被解析"（时间戳生成写错会让 5000 行只剩几十行，测了个空转），再断言耗时与"行数守恒"。
- 断言写成文档口径（如"缺口 3/4 + mismatch=[2]"），不要退化成"不崩溃就行"。

## 7. 一轮加层的完整交付形状

模块 + 单测 + 集成测试（真实库 + fixture）+ fixture 生成脚本 + 证据推导脚本 + 注入/校验脚本 + 入口命令 + 门禁脚本 + 文档（设计文档实现记录、GUIDE、README、skill 双副本）+ `history/` 留档 + 收尾报告（含"待用户决策项"清单）。

## 8. 编辑含反斜杠的内容（动作正则 / JSON 转义）

- **别手打反斜杠**：bash heredoc / patch 参数里手写的 `\` 会被 Python 字面量、JSON、工具参数各解析一遍——结果"看着对、实际不命中"；非 raw 字符串里的 `\u`（`C:\upd.exe`、`\uname`）直接抛 Unicode 解码错。
- 生成方式：用 `write_file` 直接写脚本文件；或在脚本里用 `chr(92)` 拼串（`'r"tmp' + chr(92)*2 + '?/' + chr(92) + '.svc"'`）——避开所有转义层。
- 落地后三步验证：`ast.parse()`（语法）→ 打印 `repr()` 与期望逐字对比 → **正向命中该动作自己的证据行** → 再跑门禁。
- 补丁工具报 `Escape-drift detected` 时不要加大反斜杠硬试：改走程序化修改（读文件行 → 定位字段 → 用构造好的字符串替换该字段 → 重新 `ast.parse()`）。
- 同理适用于 store 里的转义文本（指标/载荷里的 `C:\\ProgramData\\x.exe`、`\/tmp\/.svc`）：写案例本体用脚本 + `json.dumps`，不要手写 JSON 片段。

## 9. 门禁与回归命令（改完必跑）

| 命令 | 口径 / 期望 |
|---|---|
| `python scripts/check_gates.py` | 一把梭：行级口径 + 链级 Top-1 + 乱序确定性 + 解析完整性 → PASS/FAIL |
| `python scripts/measure_assembly_quality.py` | 组装质量：并链 / 碎片 / 误并（误并必须 0） |
| `python eval/run_action_recall.py` | 行级铁律：123 特征行 · Top-1 122 · Top-3 123 · 动作命中 123 · 强档 60 · 样板行 10 误命中 0 · 前瞻 NOVEL 0 中/强档 |
| `python tests/test_chain_assembly.py` / `test_chain_integration.py` | 43 条 / 14 条全绿 |
| `python scripts/build_action_index.py` 连跑两次 | md5 一致（幂等） |

## 10. v1 归档区与遗留待议（非现行，勿据此改代码）

- `history/` 对照区：`old_retrieve.py`（v1 打分器）、`old_EXTRACTION_CRITERIA.md`、`old_EVAL_PROTOCOL.md`、`old_PENDING.md`、`old_GRAPH_DECISION.md`、`old_FRAMEWORK_READINESS.md`、`old_GENERIC_TERM_LEAK_FIX.md`、`old_MEMORY_SCALING.md`、`old_validation_notes.md`、`old_eval/`（v1 评测框架，路径已补丁仍可运行）；链层前留档 `old_retrieve_v2_linelevel.py`、`old_build_action_index_v2.py`、`old_GUIDE.md`、`old_memory_store_pre_chain.json`。
- v1 遗留待议（未处理）：关系图是否采用（§6 决策记录待填）、gold 矩阵 38 条 `review=true` 未复核、`indicators` 拆 `iocs`/`notes`。
- v1 已收口并继承进 v2：通用词泄漏三机制修复（A 组件兜底 / B 通用路径作键 / C 多通道重复累计 → #2 结构化组件 + #4 跨通道去重 + B2 清系统路径键，详见 `history/old_GENERIC_TERM_LEAK_FIX.md`）。

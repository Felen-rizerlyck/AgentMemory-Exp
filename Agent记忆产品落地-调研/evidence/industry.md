# 工业/产业轨道 证据账本

**课题**：以"符号化案例记忆 + 轻量关系层（零向量库、零图库）"为对照基准，考察业界在记忆的**写入—检索—关系—评测**四环的做法与边界；工业轨道重点贡献 **S6 产品化约束**，以及厂商一手文档对 S2（检索机制与精度声明）、S3（关系层工程表述）、S4（治理合规）、S7（安全鲁棒）的表述。

**对照基准**：确定性符号检索（关键词×3 / MITRE 技术编号×2 / 指标×2 / 签名×1 / 正则探针×4 加权打分）+ 结构化案例库（约 22 个案例）+ 人工确认的一跳关系边；无嵌入、无向量库、无图数据库；规模数十个记忆单元；场景是安全告警日志的案例复用。

**访问日**：2026-09-28。时间窗口：2024-09 至 2026-09 为主。

---

## 检索记录

**取证通道说明**：本机 shell 无外网 —— `curl` / `Invoke-WebRequest` / `git ls-remote` 全部失败（TLS `SEC_E_NO_CREDENTIALS`、连接超时），`platform.openai.com` 等站点另有 403。**全部网页证据经 `node fetch`（Node 内置 fetch，脚本 `evidence/fetch.mjs`）获取，`read_page` 桥接通道用于交叉验证与 node 取不到时的补位。**

**通道可信度交叉验证**：对 `https://aws.amazon.com/bedrock/agentcore/pricing/` 同时用 node fetch 与 `read_page` 取回，两者正文一致（含 Memory 段落原文"Short-term memory is priced based on the number of raw events created…"）；node fetch 额外取到了 `read_page` 因 50000 字符截断而丢失的**价格表数字**。故 node fetch 的结果被采信为真实页面内容，而非本地伪造。

**发现手段与用量**：

| 手段 | 调用次数 | 说明 |
|---|---|---|
| `web_search` 调用 | 5 次（3 次成功、2 次因引擎 429 失败） | 共 17 条查询词，其中 9 条成功执行；成功调用每查询返回 12 个候选源 |
| 查询词（成功） | 9 条 | 见下 |
| 直接 URL 抓取（node fetch / read_page） | 约 55 次请求，涉及约 42 个不同 URL | 含 12 次用于探测正确 URL 的失败尝试 |
| 候选 URL 总数 | 约 65 个（去重后） | 多查询间重复率高；多数为二手转述、竞品对比软文、Reddit/LinkedIn，按排除项淘汰 |

**实际执行的查询词（9 条成功）**：
1. `Anthropic Claude memory feature documentation`
2. `Vertex AI Memory Bank agent engine documentation`
3. `Zep pricing Graphiti documentation`
4. `LangMem LangGraph store long term memory documentation`
5. `OWASP LLM08 Vector and Embedding Weaknesses 2025`
6. `NIST AI 600-1 generative AI profile memory retrieval security`
7. `agentic AI memory poisoning OWASP agentic security initiative threats`
8. `Zep blog defending agent memory against poisoning`
9. `Zep Konig graph database service agent memory blog`

失败未获结果（引擎 429，未重试成功）：`Mem0 platform pricing limits`、`AWS Bedrock AgentCore Memory pricing quotas`、`Zep Graphiti temporal knowledge graph memory docs`、`Letta MemGPT memory architecture docs`、`memory API pricing limits`、`agent memory service rate limits storage quota`、`data retention deletion policy AI memory`、`multi-tenant isolation memory service`。**这些子问题改用直接 URL 抓取覆盖**（厂商定价页/文档域名可猜且可达），故 429 未造成证据缺口。

**停止条件**：连续两轮新查询只返回已在候选池中的二手源；且 S6(b) 的五个必答维度（延迟/吞吐、存储增长、多租户隔离、隐私与删除、定价与配额）在 8 家厂商的一手页面中均已找到至少一条直接表述。

---

### 前置声明一：所有精度数字均为**厂商自我报告**，且存在已知跨版本/前向引用冲突

账本中出现的**每一个检索精度数字都来自厂商自己的页面**，无一条有第三方复现。使用前请注意以下四点：

1. **[I-04] Mem0 的全部基准分数（LoCoMo 92.5 / LongMemEval 94.4 / BEAM 64.1 与 48.6、平均 token 数、±1 分置信区间）属厂商自我报告**。页面自陈："Scores reflect Mem0's managed platform, which includes proprietary optimizations not available in the open-source SDK." 其评测框架虽已开源（`github.com/mem0ai/memory-benchmarks`）**但由 Mem0 自己维护**，且 BEAM 是 **Mem0 自建基准**，非社区中立基准。该页同时含两条**未披露分母的宣称**："full-context approaches… routinely consume 25,000+ tokens per query"（**未指明是哪些基线系统与评测口径**）与 "The combined score outperformed every individual signal across every category tested"（**未给任何单信号消融数字**）。
2. **[I-12] Zep 的全部基准分数（LoCoMo 94.7%（1,459/1,540）、LongMemEval 90.2%（451/500）、p50/p95 延迟、context token 中位数、auto search 86.5%）同属厂商自我报告**，同样无第三方复现。其方法论披露较完整（reader/judge = gpt-5.4、reasoning=medium、CoT grading、检索深度 20 edges/10 nodes/10 episodes/5 thread summaries/5 observations + cross-encoder reranking），**但未给 judge 不一致的置信区间**（Mem0 给了 ±1 分）。
3. **两家厂商的 LoCoMo 数字不可直接排名**：Zep 94.7% 与 Mem0 92.5% 的读模型、判模型、检索预算（Zep 为 multi-scope 固定深度；Mem0 为 top_200）、context 大小（5,760 vs 6,956 tokens）**逐一不同**，1.5–2.2 分的差距落在口径差异量级内。**本账本据此拒绝给出"谁更强"的结论**，只记录各自口径。
4. **厂商自身公开数字存在版本漂移**：Zep 在 **2025-01-22** 的博客（同目录存档 `zep-sota-blog-2025-01-22.txt`）给出的是**相对于"把完整聊天记录塞进上下文"的增量**——gpt-4o 上 LongMemEval 类别级聚合 **+18.5%**、单会话偏好 **+184%**、**同时承认单会话助手类别下降 17.7%**、延迟降低 90%、用 token 少于基线的 2%，读模型为 **gpt-4o / gpt-4o-mini**；而 Zep **当前** research 页给出的是**绝对准确率 90.2%**，读/判模型为 **gpt-5.4**。**同一厂商、同一基准、不同年份的页面，数字形态与模型栈都变了**——引用时必须指明取自哪一版页面。**此外**：委托方已持有 **arXiv:2504.19413（Mem0 论文）**、**Zep 的反驳博文** 与 **`getzep/zep-papers` issue #5** 的完整正文，几方在 Mem0/Zep 基准数字上的争议**属学术轨道裁决范畴**。**本账本未独立打开这些论文级材料**，故对"哪一方数字更可信"不作判断，仅如实记录我在**厂商页面**上读到的版本（Mem0：`evidence/pages/mem0-memory-evaluation.md.txt`；Zep：`evidence/pages/zep-research-benchmarks.txt` 与 `evidence/pages/zep-sota-blog-2025-01-22.txt`），冲突裁决请由主代理结合论文原文处理。

### 前置声明二：可核验事实与宣称的分离口径

本账本按委托要求，在每条 `陈述性质` 字段中分开列出两类陈述：**可核验事实**指页面上的具体数字、版本号、字段名、接口形态、日期、上限、价格与配额，可被任何人重新打开对应存档逐字核对；**宣称**指无披露基线的比较级或定性表述（"业界领先""up to 100%""无需基础设施"等）。**凡宣称未披露基线者，一律在"疑点·局限"中直接标注"基线未披露"**，不作正面采信。涉及**页面无日期**者，一律写明"页面未标日期，访问日 2026-09-28"，并说明该页**不能支撑时效性判断**。

---

## 条目

### [I-01] Amazon Web Services. Amazon Bedrock AgentCore Pricing（Memory 段）
- 轨道 / 类型: 工业 / 官方一手定价页
- 机构/作者: Amazon Web Services
- 出处: Amazon Bedrock AgentCore Pricing 页面，"Memory" 与 "Pricing examples" 段（无文档编号）
- 日期: 页面未标发布日期或最后更新日；访问日 2026-09-28（HTTP 头无 Last-Modified）
- 链接: https://aws.amazon.com/bedrock/agentcore/pricing/
- 访问情况: 2026-09-28 整页读到（经 node fetch 取回正文；`read_page` 交叉验证同一段落文字一致，但 `read_page` 因 50000 字符截断丢失价格表，node fetch 保留了价格表）　|　存档：evidence/pages/aws-agentcore-pricing.txt
- 陈述性质: **可核验事实**（价格、计费单位、示例算式的全部数字）；**宣称**（"eliminating complex memory infrastructure management" 属营销定性，无基线）
- 内容: 托管记忆按三段计费，均为**可核验事实**：①短期记忆 `$0.25 per 1,000 new events`（即每 1000 条 create event 请求）；②长期记忆存储 `$0.75 per 1000 memory records stored per month`（用内置抽取策略）、`$0.25 per 1000 memory records stored per month`（用 built-in-with-override 或自管策略，注释符 *）；③长期记忆检索 `$0.50 per 1000 memory record retrievals`。文档给出算例：100,000 条短期事件 × $0.25/1,000 = **$25**；10,000 条长期记忆存储 × $0.75/1,000 = **$7.50**；20,000 次检索 × $0.50/1,000 = **$10**。另说明短期记忆"按 create event 请求计费"、长期记忆存储"按存储记录数按小时计费"、长期记忆检索"按 retrieve memory 请求计费"。同页相邻服务价格（用于对照量级）：Web Search `$7 per 1,000 queries`；Gateway 记录 `First 5,000 records free monthly, then $0.400 per 1,000 records`；microVM 计费 `$0.0169/vCPU-hour` 级。
- 与对照基准的关系: **强支持"按量成本可控、无需自建向量/图库"**。关键量级：把整个案例库（数十条）当长期记忆存，月存储成本是**分位数量级**（10,000 条约 $7.5/月）；检索成本 `$0.50/1000 次` 意味着每次检索约 $0.0005。**但注意**：计费维度本身暴露了托管记忆的成本结构——**写入（events）与检索（retrievals）都被单独计费**，说明"检索次数"是这个业务里的成本中心，与对照基准"必须治理检索精度"的判断方向一致（检索既影响精度也直接计费）。
- 疑点·局限: 页面无日期，无法支撑"截至 2026-09 仍有效"的任何变化判断；只有访问日。价格标注 "varies by cloud and region" 的项在存储/检索单价上未见区域差异说明。计费示例是 AWS 自选场景，非基准测试。另需注意 `$0.75/1000 records/month` 是**每千条记录每月**，规模线性增长时存储成本随之线性增长，不像 Zep 那样"存储/检索不计费"（见 I-12），两者定价哲学不同。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-02] Amazon Web Services. Add memory to your Amazon Bedrock AgentCore agent（Developer Guide）
- 轨道 / 类型: 工业 / 官方一手文档
- 机构/作者: Amazon Web Services
- 出处: Amazon Bedrock AgentCore Developer Guide，`memory.html`（同页提供 `.md` 版本）
- 日期: HTTP `Last-Modified: Sat, 26 Sep 2026 03:00:42 GMT`（文档页面级最后修改日）；无独立版本号
- 链接: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/memory.html
- 访问情况: 2026-09-28 读到整页正文与目录（HTML 与 `.md` 两版均取到；`what-is-bedrock-agentcore` 页另读，其"数据使用"声明合并记入本条）　|　存档：evidence/pages/aws-agentcore-memory.md.txt、evidence/pages/misc-aws.txt
- 陈述性质: **可核验事实**（记忆分类、API 语义、数据使用声明）；**宣称**（"fully managed…without the need to build or manage complex infrastructure" 为定性表述，无基线）
- 内容: 把记忆明确划为两类：**短期记忆**（short-term，单会话内逐轮交互，例："What about tomorrow?" 能解析出指代西雅图天气）与**长期记忆**（long-term，跨会话自动**抽取**并存储关键洞察：用户偏好、重要事实、会话摘要；例：客户提到偏好靠窗座位，未来主动提供）。文档列出的能力包括"跨 agent 共享记忆存储"与"从经验学习"。功能面给出一组子页可核验的接口模块：create Memory、use short-term / long-term memory、**Amazon Bedrock capacity for built-in with overrides strategies**（内置策略与可覆盖策略的容量）、observability、best practices。**合规相关可核验事实**（来自同文档集 overview 页）："AgentCore may use and store your content to improve your service experience or performance. Such improvements would be for your use of AgentCore and not for other customers." —— 即 AWS 明确保留为**提升本客户自身服务体验**而使用与存储内容的权利，并声明不跨客户使用。
- 与对照基准的关系: 部分支持。托管记忆把"写入策略"（内置抽取 vs. 自管策略+自选模型与提示）做成可选层，说明**被托管的记忆系统并不强迫使用者接受某种检索/抽取机制**；对照基准的确定性打分器属于文档所称 "self-managed memory strategies" 一侧，在托管平台上是**受支持的一等形态**（价格也更低，见 I-01 的 $0.25 vs $0.75）。但该文档未披露任何检索通道（向量/关键词/混合）或精度数字，**无法据此判断确定性检索与语义检索的效果差异**。
- 疑点·局限: 页面级 Last-Modified 只能证明"该页在 2026-09-26 被改动过"，不等于产品行为变更为该日。文档通篇无精度或延迟数字。文档未说明长期记忆的**条数上限**、保留期或删除语义（配额页尝试见"未获取"清单）。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-03] Mem0. How Mem0 Works（含 Multi-Signal Retrieval 与存储分层）
- 轨道 / 类型: 工业 / 官方一手文档
- 机构/作者: Mem0
- 出处: Mem0 Docs, `core-concepts/how-it-works`（同页提供 `.md`）
- 日期: `Last-Modified: Mon, 28 Sep 2026 02:54:35 GMT`；无版本号
- 链接: https://docs.mem0.ai/core-concepts/how-it-works
- 访问情况: 2026-09-28 读到整页 `.md` 正文　|　存档：evidence/pages/mem0-how-it-works.md.txt、evidence/pages/mem0-platform-overview.md.txt
- 陈述性质: **可核验事实**（检索信号清单、存储分层、OSS 与 Platform 的能力差异）；**宣称**（"cutting prompt bloat" 等为定性，无基线）
- 内容: 检索侧列出**四路信号**：**Semantic**（对嵌入做向量相似度，"概念性问题"）、**Keyword**（词项匹配，"人名、ID、事实性查询"）、**Entity**（提升与查询实体相连的记忆，"关于某人/项目/账户的问题"）、**Temporal**（用在写入时抽取的时间元数据给候选打分，"什么时候…"、当前状态、时效性）。三者存储分层：SQL 数据库（事实与元数据，作为**每一条记忆的真相来源**）、向量数据库（嵌入，语义相似）、实体存储（抽取出的实体，提升共享实体的记忆）。**最关键的一句可核验事实**："Platform retrieval fuses these signals in the managed service, where the entity signal is powered by built-in Graph Memory. **OSS retrieval depends on your configured vector store and optional reranker, and boosts on entity overlap alone: it has no graph memory.**" 另给出产品流程定位：应用在模型调用**前**调 `search`、把结果塞进提示词，由应用决定用哪些返回记忆。
- 与对照基准的关系: **双向**。支持面：厂商自述把 **Keyword/BM25 与 Entity 视为与 Semantic 并列的一等信号**，且明确指出它们各自"最适合"的场景是**人名、ID、事实性查询**——这正覆盖对照基准的关键词×3、MITRE 编号×2、指标×2 所针对的查询类型；说明"不做嵌入也能命中这类查询"在业界是被承认的。反驳面：Mem0 的**事实真相来源是 SQL，语义检索靠向量库，实体信号在图里**，即其默认形态是"向量库+图库+SQL"三件套；对照基准省掉三者，在 Mem0 的框架里等价于"只保留 Keyword + 手写实体"，其**风险被 Mem0 直接点明**：实体信号在 OSS 形态下"no graph memory"，只有重叠度提升。
- 疑点·局限: 未给出任何单信号消融数字（哪路信号贡献多少），无法量化"去掉向量"的代价。未披露记忆条数上限。"真相来源是 SQL"这一句与"零向量库、零图库但需要结构化存储"的对照基准在工程上并不冲突，但本文档未讨论**只有数十个记忆单元**时是否仍需要三存储分层。**这是一条设计意图陈述，不是性能证据。**
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-04] Mem0. Memory Evaluation（基准、口径与自行复现方法）
- 轨道 / 类型: 工业 / 官方一手文档（评测口径披露）
- 机构/作者: Mem0
- 出处: Mem0 Docs, `core-concepts/memory-evaluation`（同页提供 `.md`）
- 日期: `Last-Modified: Mon, 28 Sep 2026 02:54:36 GMT`
- 链接: https://docs.mem0.ai/core-concepts/memory-evaluation
- 访问情况: 2026-09-28 读到整页 `.md` 正文（含全部表格与 CLI 选项）　|　存档：evidence/pages/mem0-memory-evaluation.md.txt
- 陈述性质: **可核验事实**（分数、token 数、检索预算、置信区间、评测仓库与参数）；**宣称**（"combined score outperformed every individual signal" 未给分路数字）
- 内容: 三组基准成绩，均标注"**top_200 retrieval budget**（每查询取排名前 200 条记忆）"、单次检索单次回答无 agent 循环：**LoCoMo 92.5**（单跳 91.2 / 多跳 91.3 / 开放域 72.7 / 时序 92.0，平均 **6,956** tokens/查询）；**LongMemEval 94.4**（单会话-用户 98.6 / 单会话-助手 98.2 / 偏好 96.7 / 知识更新 93.6 / 时序 97.0 / 多会话 88.0，平均 **6,787** tokens）；**BEAM 1M 64.1 / 10M 48.6**（10M 下 multi_session_reasoning 26.1、temporal_reasoning 16.3、event_ordering 20.2、contradiction_resolution 32.5，平均约 6,7xx tokens）。**分母与口径均披露**：LoCoMo 约 300 题 / 10 段对话；LongMemEval 500 题 / 6 类；BEAM 1M 与 10M 两档、每档 100 段对话（`--conversations 0-99`）；分数带 **±1 分置信区间（judge 不一致）**；评测框架已开源（`github.com/mem0ai/memory-benchmarks`），可对 cloud 或自托管 OSS 后端跑，暴露 `--top-k`（默认 200）、`--answerer-model`、`--judge-model`、`--judge-provider` 等参数。文档主动列出多条**自我限制**：分数是"Mem0's managed platform, which includes proprietary optimizations not available in the open-source SDK"，OSS 用户"应预期方向性相似但数值不同"；LoCoMo/LongMemEval 这类小基准"can be materially improved by aggressive retrieval strategies, larger context windows, or frontier models"且这不代表记忆系统本身变好；"A system that scores 95% using 25K tokens per query isn't comparable to one scoring 90% using 7K tokens"。对 BEAM 10M 的弱项，文档承认"temporal reasoning、event ordering、multi-session reasoning 是全领域的开放问题"。
- 与对照基准的关系: **对"必须治理检索精度"这一半判断提供最直接的一手支撑**。可核验事实：①评测必须在**固定检索预算**下比较（top_200），否则分数不可比；②文档自己指出**小基准可被"激进检索 + 前沿模型"刷高**，即分数本身不等于系统能力；③MEM0 明确要求"report mean tokens per query alongside scores"，把**成本与精度绑定**。对"零向量库"的启示：Mem0 的 ADD-only 抽取架构在**知识更新**这一栏只有 93.6，且文档自陈原因是"older facts are preserved rather than overwritten, so semantically similar prior facts can still surface alongside newer ones" —— 这正是**符号化、追加式、不做语义合并**的架构所共有的失效模式，对照基准需为"旧案例污染新告警复用"预留治理手段。
- 疑点·局限: 全部分数为厂商自测，**无第三方复现**；评测仓库由 Mem0 自己维护（`memory-benchmarks`），LoCoMo/LongMemEval 的题目集是公开的但判分用 LLM-as-judge（±1 分）；"full-context approaches…routinely consume 25,000+ tokens per query" 的 25K 是笼统表述，**未指明具体基线系统与口径**，属**基线未披露的宣称**。"combined score outperformed every individual signal across every category tested" 未给出任何分路数字，属**未披露分母的宣称**。BEAM 是 Mem0 自建基准，非社区中立基准。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-05] Mem0. Graph Memory（原生图记忆，且是付费档特性）
- 轨道 / 类型: 工业 / 官方一手文档
- 机构/作者: Mem0
- 出处: Mem0 Docs, `platform/features/graph-memory`（同页提供 `.md`）
- 日期: `Last-Modified: Mon, 28 Sep 2026 02:54:39 GMT`
- 链接: https://docs.mem0.ai/platform/features/graph-memory
- 访问情况: 2026-09-28 读到整页 `.md` 正文　|　存档：evidence/pages/mem0-graph-memory.md.txt
- 陈述性质: **可核验事实**（图的结构定义、可用档位、旧版行为变更）；**宣称**（"contributes to Mem0's gains on multi-hop and temporal benchmarks" 指向自家评测，无独立基线）
- 内容: 图由**实体节点 + 记忆节点 + 连接**构成：实体是记忆中出现的人/地/组织/概念，同一实体出现在多条记忆时这些记忆**经该实体相连**，"connections are derived directly from your data. There is no relationship schema to define and nothing to label by hand." 明确**图只做排序提升、不改变响应结构**："Graph Memory affects **ranking**, not the response shape." **最关键的可核验事实**：图**不做带类型的关系**——"It does not assign typed, labeled relationships between entities (it won't, for example, record a 'manages' edge from one person to another); connections are inferred from **co-occurrence** rather than declared." 可用性分两半：**图记忆本体（实体抽取、连接、检索提升）所有档位自动开启**；**Graph view（仪表盘可视化）仅 Pro 与 Enterprise**。另记录一次**架构回退/替换**：早期版本通过 `enable_graph` 标志 + `graph_store` 配置块连接**外部图数据库**（Neo4j、Memgraph、Kuzu、Apache AGE、Neptune），现已被"原生内置图"取代；`relations` 字段**永远返回空列表**，旧集成不可恢复。
- 与对照基准的关系: **最直接支持"现阶段不必上图库"**，且支持面来自一个**卖图记忆的厂商**：①图的语义被缩减为"共现即连接"，不含类型化关系——而对照基准用的是**人工确认的一跳关系边**，在表达力上**严格强于** Mem0 的共现图（人工边至少承载了一个判断，共现只承载了"同现"）；一个只给共现图的商业系统能支撑多跳问答，说明对照基准的关系层**不需要图数据库"（图库价值在于 traversal/查询语言/规模，而非共现建模本身）。②Mem0 把外部图库（Neo4j/Memgraph/Neptune）**整体删除**，改为平台内自建图，属厂商侧对"外部图库是负担"的背书。③图本体在所有档位自动开启 ⇒ 对 Mem0 的用户而言，图不是"要不要上"的决策项。**反驳面**：Mem0 仍认为需要图；其"多跳与时效性收益"归因于图，但未给分路数字（见疑点）。
- 疑点·局限: "contributes to Mem0's gains on multi-hop and temporal benchmarks" **未给出有/无图的消融数字**，无法判断收益幅度，属**未披露分母的宣称**。`relations` 恒为空这一变更意味着**任何依赖图结构做下游处理的应用会静默失效**（文档只为 `get_all` v1.1 格式保留向后兼容的空 key），是"托管图记忆把结构藏在打分里"的典型代价：图不再可被消费，只能被信任。文档未说明图的规模上限或存储计费方式。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-06] Mem0. Pricing（档位、配额与合规徽标）
- 轨道 / 类型: 工业 / 官方一手定价页
- 机构/作者: Mem0（页面版权 "© 2026 Mem0"；页面显示 GitHub `Star 62,590`）
- 出处: mem0.ai/pricing 页面与 Compare Plans 表
- 日期: 页面未标发布日；`Last-Modified: Sat, 26 Sep 2026 06:14:13 GMT`；访问日 2026-09-28
- 链接: https://mem0.ai/pricing
- 访问情况: 2026-09-28 读到整页正文与完整 Compare Plans 表　|　存档：evidence/pages/mem0-pricing.txt
- 陈述性质: **可核验事实**（价格、配额、功能档位、合规徽标文字）；**宣称**（"Simple and Affordable"、徽标所暗示的合规强度）
- 内容: 四档，配额以**每月请求数**（而非 QPS）表达：**Hobby 免费** — 无限终端用户、**10,000 add 请求/月**、**1,000 retrieval 请求/月**、1 个项目、社区支持；**Starter $19/月** — 50,000 add、5,000 retrieval、1 项目；**Pro $249/月** — 500,000 add、50,000 retrieval、无限项目、多项目管理、私有 Slack 支持、高级分析、**Graph memory (entity linking)**、**Dream (Memory Consolidation)**；**Enterprise 定制** — 无限 add/retrieval/项目、SLA 支持、**本地部署（on-prem）**、审计日志、定制集成与 SSO。另注"我们也支持按用量计费"。页脚合规徽标：**HIPAA Ready、SOC 2 Type I、GDPR Ready**。
- 与对照基准的关系: **强支持"零向量/零图库"在小规模下足够，且给出量化边界**。可核验事实：免费档可用额度是 **10,000 add + 1,000 retrieval/月**；对照基准的规模（约 22 个案例、数十个记忆单元）比任何一档的**单月配额低数个数量级**，即"自建符号记忆"在 Mem0 的定价体系里落在**免费档以下**的负载量。更值得注意的是**产品分档逻辑本身**：**Graph memory 与 Dream 是 Pro（$249/月）及以上才有的功能**（Compare Plans 表中 Hobby/Starter 两项为 "—"），即厂商把图记忆定位为**规模与预算都足够时才值得付钱的增强项**，而不是基础可用性要件——这与"现阶段不必上图库"方向一致。**同时支持"必须治理检索精度"**：add 与 retrieval 是**分别计量、分别限额**的两个配额，检索是独立成本中心；免费档"1,000 retrieval/月"意味着检索调用的稀缺性被产品化。
- 疑点·局限: 页面无发布日，只有 HTTP 最后修改日。档位表**未列出速率限制（QPS/RPM）**，只有月度配额——高峰期的延迟/吞吐约束在 Mem0 的公开定价页上**缺失**（对比 Zep 明确写 600/1,000 requests per minute，见 I-11）。合规徽标为**自述**，未见第三方审计报告链接；"HIPAA Ready" 与 "SOC 2 Type I"（**Type I 而非 Type II**）是较弱的一级，"Ready" 非 "Compliant" 的措辞区分值得注意（Zep 自述 SOC 2 Type II，见 I-11）。"GDPR Ready" 无细则。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-07] Mem0. FAQs（账号与记忆删除语义）
- 轨道 / 类型: 工业 / 官方一手文档（FAQ）
- 机构/作者: Mem0
- 出处: Mem0 Docs, `platform/faqs`（同页提供 `.md`）
- 日期: `Last-Modified: Mon, 28 Sep 2026 02:54:42 GMT`
- 链接: https://docs.mem0.ai/platform/faqs
- 访问情况: 2026-09-28 读到整页 `.md` 正文　|　存档：evidence/pages/mem0-platform-faqs.md.txt
- 陈述性质: **可核验事实**（删除流程、删除范围、行为时序）
- 内容: **删除语义（S4 核心）**：用户可在 app.mem0.ai 的 Settings → Account 点 Delete account 自行删除账号；**"Deletion is asynchronous: the request is accepted immediately and processed in the background, typically within a few minutes."** 完成时删除的内容被逐项列出：①用户资料与登录凭证；②**你创建的全部 memories、agents 与 runs**；③签发给该账号的 API key 与访问令牌；④你**独占拥有的 organizations** 及其数据；⑤你在共享 organization 中的成员身份（org 本身不受影响）。**"Your old API keys stop working once deletion completes, not the instant you click confirm."** 另记录一个可核验事实（备份可携带性）：若应用**自行**调用 `add` 存入的是抽取后的记忆而非原始记录，且 Platform 形态下"the Platform stores all memory data on Mem0's servers"；FAQ 另指出自托管 OSS 在 AWS Lambda 上受 `/tmp` 512MB 且**调用间不持久**的限制，需设 `MEM0_DIR=/tmp/.mem0`。
- 与对照基准的关系: 支持"小规模自建的可删除性优势"，但方式与直觉相反。可核验事实：Mem0 的删除是**异步、分钟级、且以"账号"为单位**（另有 `delete`/`delete_all` 按 user 维度删除的 API，见其 API reference）；对照基准把约 22 个案例存成**本地结构化文件**，"删除权"落地为**删文件**，无异步窗口、无跨存储传播问题。这与 Claude 的一手文档形成直接对照：Claude 明确写"当会话过期或被删除时，**由它生成的记忆条目不会被移除**"（I-08），而 Mem0 的账号删除声明覆盖"全部 memories"——但两者都表明**托管记忆的删除是一条跨越多个存储的传播链**，而非单点操作。
- 疑点·局限: 该 FAQ **未说明删除是否以及如何传播到向量存储、图存储与备份/日志**（FAQ 只说"全部 memories…被移除"，未给存储层细节，也未给法定期限）；**未提及 GDPR 数据主体请求（DSAR）流程、处理者清单（sub-processors）或数据导出格式**（导出功能在另一页 `platform/features/memory-export`，本次未读）。"typically within a few minutes" 是**无 SLA 承诺的经验值**。本页 FAQ 多数条目只剩答案、问题标题缺失（页面结构问题），上下文靠答案推断，存在误读风险。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-08] Anthropic. Memory in ChatGPT 对应物：Use Claude's chat search and memory（Claude 记忆官方说明）
- 轨道 / 类型: 工业 / 官方一手帮助中心文档
- 机构/作者: Anthropic（support.claude.com）
- 出处: "Use Claude's chat search and memory to build on previous context"（帮助中心文章）
- 日期: 页面只显示相对时间"**Updated over a week ago**"，**未标绝对日期**；正文提到"until September 9, 2026, you will see the option to export your legacy memory"，据此推断页面在 2026-09 前后更新。访问日 2026-09-28
- 链接: https://support.claude.com/en/articles/11817273-use-claude-s-chat-search-and-memory-to-build-on-previous-context
- 访问情况: 2026-09-28 读到整页正文（约 40KB 文本，含消费版与企业版两套控制说明）　|　存档：evidence/pages/anthropic-claude-memory-support.txt
- 陈述性质: **可核验事实**（默认开合状态、保留与删除规则、企业管控、合规排除项、更新时间窗）；**宣称**（"记忆不会保存所有细节"等定性）
- 内容: **默认值与档位（可核验事实）**：记忆在 Free/Pro/Max 上**默认开启**（web、Desktop、Mobile）；在 **Team 与 Enterprise 上默认关闭，需 owner 开启**。**保留与删除（S4 核心，可核验事实）**：①"**All memory will be retained in accordance with existing chat data retention policies.**"②"**When a conversation expires or is deleted, related memory entries generated from it won't be removed**, but you can delete individual memories at any time."（**源会话删除 ≠ 记忆删除**，两者解耦）③"Memory entries generated from eligible chats **before** customer data retention was applied won't be removed."④"**Claude's memory is updated within 24 hours when conversations are created, modified, or deleted.**"（删除传播窗口 **24 小时**）⑤**Reset memory** 会"永久删除全部记忆，含 project 记忆"，不可撤销。**企业管控（可核验事实）**：owner 可为组织开启；"Once a user has opted in, they control their own sensitive memories"；"**Owners can't view or edit a user's individual memories.**"；**"When an owner turns memory off for the organization, all existing memory entries for all users are deleted immediately."**；**"All memory is retained and exportable by admins in accordance with your organization's chat data retention policies."**；**"Memory isn't available to organizations with HIPAA, public-sector, or custom data retention agreements."**（**合规排除项**）；记忆条目"stored with encryption at rest"；Inkognito 会话不产生记忆，但"remain available to owners through data export"且受保留策略约束（**至少 30 天**）。另有"敏感话题"独立同意机制：默认不存，关闭该设置会**移除已存的敏感条目**。
- 与对照基准的关系: **支持"小规模自建"在治理上的可解释性，同时给出托管记忆必须付出的产品化代价清单**。可核验事实最有决策价值的三条：①**源删除不删除派生记忆**——托管记忆天然是"第二份副本"，法规意义上的"被遗忘权"要跨两处操作；对照基准里案例库即唯一副本，删一条就是删一条。②**删除传播有 24 小时窗口**，且组织级关闭才是"立即且永久"的强操作——说明"能删"与"立即不影响推理"是两件事。③**合规排除项是硬边界**：HIPAA / 公共部门 / 自定义保留协议的客户**完全无法使用记忆功能**，即"上记忆"与"满足某些合规框架"在当前产品形态下**互斥**。这条对安全告警日志场景尤其重要：托管记忆方案的合规可用性可能被"客户所处框架"一票否决。
- 疑点·局限: 页面**无绝对更新日期**（只有 "over a week ago"），无法精确支撑时效判断，只能靠正文提到的 2026-09-09 日期旁证。文中企业版与旧版（legacy "memory from chats"）两套机制的描述交织，部分段落结论（如 24 小时更新）可能只适用于其中一套，**本次未逐段区分**。未给出记忆条数上限、检索通道（是否向量）或任何精度数字。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-09] Anthropic. How Claude remembers your project（Claude Code 的 CLAUDE.md 与 auto memory）
- 轨道 / 类型: 工业 / 官方一手文档
- 机构/作者: Anthropic（code.claude.com/docs）
- 出处: Claude Code 文档 "Memory"（How Claude remembers your project）
- 日期: 页面未标发布日期或最后更新日；访问日 2026-09-28
- 链接: https://code.claude.com/docs/en/memory
- 访问情况: 2026-09-28 读到整页正文（约 47KB 文本）　|　存档：evidence/pages/anthropic-claude-code-memory.txt
- 陈述性质: **可核验事实**（加载规则、体量上限、层级顺序、外部导入审批、审计命令）
- 内容: Claude Code 的记忆是**纯文本文件**，无嵌入。**两类记忆并列**：①**CLAUDE.md 文件**（"instructions you write to give Claude persistent context"）；②**Auto memory**（"notes Claude writes itself based on your corrections and preferences"）。**加载与体量（可核验事实）**：CLAUDE.md "loaded into: Every session"；**auto memory "loaded into: Every session (first 200 lines or 25KB)"**；文档给出明确的**性能—体量权衡**："**Size: target under 200 lines per CLAUDE.md file. Longer files consume more context and reduce adherence.**"**层级与覆盖顺序（可核验事实）**：从工作目录**逐级向上**加载 CLAUDE.md 与 CLAUDE.local.md，"All discovered files are **concatenated into context rather than overriding each other**"，顺序为"从文件系统根到工作目录"，故**靠近启动位置的指令最后被读到**；同目录内 CLAUDE.local.md 追加在 CLAUDE.md 之后；子目录中的文件**按需加载**（当 Claude 读取该目录内文件时）；`.claude/rules/` 可用 `paths` 字段做**路径作用域加载**（只在处理匹配文件时载入）。**安全边界（可核验事实）**：项目级记忆文件里**指向工作目录之外的 `@path` 导入**被判为 external import，首次遇到时"shows an approval dialog listing the files"，拒绝后该导入保持禁用；符号链接指向工作目录外同样按 external import 处理；**用户级文件（`~/.claude/CLAUDE.md`、`~/.claude/rules/`）因其为自己所写而被信任，不弹窗**（Cowork 会话例外，会跳过解析到会话目录外的导入）。**治理（可核验事实）**：有 `/context` 命令可确认哪些 Memory files 已加载；有 `/doctor prompt-audit` 命令**扫描过期或互相冲突的指令**（"instructions written for older models, references to files or commands that don't exist, and files that contradict each other"），产出报告与修改建议，**在用户确认前不改动文件**；`claudeMdExcludes` 可按 glob 排除文件，支持在 user/project/local/managed 各层配置且数组跨层合并，但 `claudeMd`（指定加载哪个文件）**只在 managed 与 policy 设置中生效**。
- 与对照基准的关系: **本账本中对对照基准最有力的工业一手先例**。Anthropic 在旗舰编码 agent 里用**符号化、文件化、人工可读可审、无向量库无图库**的记忆：路径即寻址、目录名充当"signpost"、按需加载控制上下文、逐级拼接而非覆盖。与对照基准的对应关系几乎是逐项同构——**正则/关键词探针 ↔ 路径作用域加载**（都是确定性、可审计的筛选而非相似度检索）；**约 22 个人工案例 ↔ CLAUDE.md + rules**；**人工确认的一跳边 ↔ 文件层级与显式导入关系**。更进一步，Anthropic 给出的是**可核验的规模上限经验法则**（"target under 200 lines"，auto memory 首 200 行/25KB），并**明说超限会降低遵循度**——这为对照基准"数十个记忆单元"的量级提供了外部佐证：**记忆单元数量本身就是精度约束**，而这一点与"必须治理检索精度"的判断同向。`/doctor prompt-audit` 的存在说明"记忆打架/过期"是真实且需要工具化治理的问题，不是理论担忧。
- 疑点·局限: 页面**无日期**，无法支撑时效性判断。"first 200 lines or 25KB" 是**加载截断**而非存储上限，auto memory 的完整存储规模文档未给。200 行/25KB 是 Anthropic 的**工程经验值**，不是基准测试结论，不可当作"确定性检索的精度上限"证据。文档未披露任何检索精度数字，也**未说明是否有隐藏的向量索引**（本次只读到文字描述层面；OWASP 的 MemoryTrap 案例另指出该产品把用户记忆放进系统提示词曾在 v2.1.50 前构成高风险路径，见 I-19）。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-10] Google Cloud. Agent Platform Memory Bank（原 Vertex AI Agent Engine Memory Bank）
- 轨道 / 类型: 工业 / 官方一手文档
- 机构/作者: Google Cloud
- 出处: Gemini Enterprise Agent Platform 文档 `scale/memory-bank`（含 Governance 节）
- 日期: 页面未标发布/更新日；访问日 2026-09-28（node fetch 被 TLS 层拒绝，改用 `read_page` 桥接通道成功）
- 链接: https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank
- 访问情况: 2026-09-28 读到整页正文（含 Features、Use cases、Memory Bank governance 三节）。**注**：`node fetch` 对该域名 `fetch failed`，此条**仅经 `read_page`（Firecrawl 云端渲染）获取**，未获原始 HTML 交叉验证　|　存档：无原始存档（见文末存档与溯源说明）
- 陈述性质: **可核验事实**（作用域隔离、TTL、修订、IAM 角色、区域约束）；**宣称**（"fully managed"、用例描述）
- 内容: 记忆被建模为**带 scope 的独立事实对象**，作用域示例为 `{agent_name, user}`，每条记忆形如 `{"name": "projects/.../memories/...", "scope": {...}, "fact": "..."}`。**写入侧**：LLM 驱动的 memory generation，含**抽取**（"Extract only the most meaningful information"）、**合并**（consolidation，"memories to evolve as new information is ingested"，也支持把**预抽取的记忆**——即"agent 或 human-in-the-loop 认为有意义的信息"——与既有记忆合并）、**异步生成**（"so that your agent doesn't have to wait for memory generation to complete"）、**持续事件摄取**（按可配置批处理规则触发）、**可定制抽取**（用 topics 与 few-shot 例子配置"什么算有意义"）、**多模态理解**。**存储与检索侧**：托管持久存储；**跨身份数据隔离**（consolidation 与 retrieval 都隔离到特定 identity）；**相似度检索**（同样按 identity 作用域）；**自动过期**（对插入或生成的记忆设 TTL，使陈旧信息自动删除）；**记忆修订**（memory revisions，可检查记忆如何随新信息演变）；**限制性权限**（用 IAM conditions 限制哪些主体能读写特定 scope 的记忆，角色如 `roles/aiplatform.memoryViewer`、`roles/aiplatform.memoryEditor`）。**写入控制**另给 `CreateMemory` 以支持"memory-as-a-tool"（agent 自行决定何时写、写什么）。**治理（S4/S7 核心，可核验事实）**：①**Prompt injection 与 memory poisoning** 单列小节，定义"Memory poisoning occurs when false information is stored in Memory Bank. The agent may then operate on this false or malicious information in future sessions."，缓解手段为 **Model Armor**（检查发往/来自记忆的提示）、**对抗测试/红队**、**沙箱执行 + 人工复核**；②**数据驻留**要求创建实例时选区域或多区域（如 `eu`/`us`）以确保**静态数据留在该地理边界**，但**ML 处理位置取决于模型区域可用性**——"If a regional endpoint is unavailable for your selected model or location (for example, Gemini 3 models or Asia single regions), **global Gemini endpoints are used for ML processing**"（**区域承诺的例外**）；③**跨边界污染（cross-border contamination）**的定义与防护：为每个司法辖区建**区域专用的 agent identity / service account**（如 `agent-us@…`、`agent-eu@…`），并用组织策略 `gcp.resourceLocations` 限制资源创建与使用位置。
- 与对照基准的关系: **提供托管记忆在托管侧必须额外解决的完整成本清单**，并显示其中有若干项**对照基准天然不需要**：跨区域污染防护、IAM 条件作用域、TTL 自动过期、记忆修订审计——这些之所以存在，是因为"记忆是一份托管的、跨租户共享基础设施中的持久副本"。对照基准把约 22 个案例作为本地文件，**多租户隔离退化为文件系统权限、TTL 退化为删除文件、修订退化为 git/文件版本**。**反驳面**：Google 的 Products 与 Use cases 明确以"similarity search"作为默认检索形态，且把"LLM 驱动的知识抽取"作为记忆生成主干——即在该平台上**没有"不做语义检索"的选项**，意味着"只用确定性符号检索"的方案在托管平台上不可得；若坚持符号检索，就**必须自建**（或走 self-managed 路径）。
- 疑点·局限: 本条**未获原始 HTML 交叉验证**（仅 Firecrawl 渲染结果），页面文本可能经渲染改写。页面无日期，无法支撑时效判断。**未给出任何记忆条数、存储上限、TTL 取值范围、价格或配额数字**；"similarity search" 的实现（向量/混合/重排序）与任何精度数字均未披露——**S2 在本条上无收获**。区域例外条款（全局 Gemini 端点参与 ML 处理）是重要的合规削弱项，但文档把它放在脚注式说明里，容易被误读为"选 eu 就完全本地化"。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-11] Zep. Pricing（按 credit 计费；检索与图存储不计费）
- 轨道 / 类型: 工业 / 官方一手定价页
- 机构/作者: Zep AI, Inc.（页面版权 "© 2026 Zep AI, Inc."）
- 出处: getzep.com/pricing 页面与 Compare plans 表
- 日期: 页面未标发布/更新日（HTTP 无 Last-Modified）；访问日 2026-09-28
- 链接: https://www.getzep.com/pricing/
- 访问情况: 2026-09-28 读到整页正文与完整 Compare plans 表、计费 FAQ　|　存档：evidence/pages/zep-pricing.txt
- 陈述性质: **可核验事实**（价格、credit 单价、速率限制、留存期、合规项）；**宣称**（"Unlimited"、SLA 表述未给覆盖率细节）
- 内容: 自助档为 credit 制。**Flex $125/月**（按月付）：含 **50,000 credits**，超出 **$25 / 10,000 credits**，**600 requests per minute**，5 projects，5 Memory MCP Server seats，10 custom entity & edge types，API logs 保留 **1 天**，"**Unlimited memories, retrieval & users**"，30 天 credit 结转，余额低于 20% 自动充值。**Flex Plus $375/月**：含 **200,000 credits**，超出 **$75 / 40,000 credits**，**1,000 requests per minute**，10 projects，15 seats，20 custom entity & edge types，Observations、自定义抽取指令、Webhooks、Analytics，API logs 保留 **7 天**，60 天结转。**免费档**：10,000 credits/月、2 projects、1 seat、5 custom entity & edge types、**"Variable rate limits, depending on service-wide load"**、**"Lower priority Episode processing"**、无结转无自动充值。**Enterprise**：定制 credits 与议价、**"Guaranteed rate limits with SLA"**、无限项目、**SOC 2 Type II 与 HIPAA BAA**、**审计与 API 日志保留 1 年**、DPA（EU 客户）、部署可选 Cloud / **Cloud+BYOK** / **BYOC（部署进客户 VPC）**。**计费口径（可核验事实，S6(b) 关键）**：按 **Episode**（任一条发送给 Zep 的数据对象——聊天消息、JSON、文本块）计费，**1 credit / 每 350 字节**（不足 350 字节按 1 credit，超出按每 350 字节 +1；示例：640 字节 = 2 credits，1,200 字节 = 4 credits）；webhook 调用 ⅛ credit；**"0 credits for retrieval, storage, threads, users, and graph storage."** 即**检索、存储与图存储全不计费**，只对**摄取与处理**计费。FAQ 明确："You are charged for ingestion and processing of Episodes. **You are not charged for storage** of messages or data."；"How are rate limits calculated? Each plan tier has a base rate limit… **Free and Flex Plan customers may see rate limits lowered depending on service usage.** Enterprise plans have committed, guaranteed rate limits."
- 与对照基准的关系: **对"成本模型随架构选择而变"给出最锋利的证据，且方向与直觉相反**。可核验事实：Zep 把"检索/存储/图存储"定价为 **0**，把成本集中在**写入（Episode 字节数）**。这意味两点对决策直接有用：①**图记忆在 Zep 这里是"免费搭车"的**，厂商的定价结构**不惩罚**上关系层——所以"要不要图库"在 Zep 的经济性上没有答案，答案在架构适配性上（见 I-13）；②反过来，**与 Mem0 的"检索按次计费"（I-01/I-06）形成对立**：两家厂商对同一动作（检索）的定价态度相反（Zep 免费、Mem0 与 AWS 计费）。因此"检索精度治理"的成本压力**高度依赖所选形态**：自建/符号检索下检索是 CPU 成本且可无限重试，托管平台下检索是账单项。Zep 的速率限制（600/1,000 RPM，免费档随负载浮动）也是本账本中**唯一给出明确 QPS 级数字**的托管记忆服务，可用于估算对照基准的延迟/吞吐余量。
- 疑点·局限: 页面无日期。免费档的 "Variable rate limits, depending on service-wide load" 与 "Lower priority Episode processing" 是**无下限承诺**——免费档的实际可用性不可规划。"Unlimited memories, retrieval & users" 与 credit 计费并存，意味着**滥用防护完全依赖 600/1,000 RPM 的速率限制**（超限行为、按 project 还是按账号限流，文档未说明）。SOC 2 Type II / HIPAA BAA 仅在 Enterprise 提供，Flex 两档在 Compare plans 表中对应行为空——**即自助档不提供合规承诺**，这是与 Mem0（免费档即挂 HIPAA Ready 徽标）相反的取向。Enterprise 价格不公开，**总拥有成本无法核验**。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-12] Zep. Research：Benchmarks for agent memory（完整评测口径披露）
- 轨道 / 类型: 工业 / 官方一手技术报告（基准结果页）
- 机构/作者: Zep AI, Inc.
- 出处: getzep.com/research 页面
- 日期: 页面未标发布/更新日；访问日 2026-09-28
- 链接: https://www.getzep.com/research/
- 访问情况: 2026-09-28 读到整页正文，含 Methodology / Reproducibility notes 段与按题型分解表　|　存档：evidence/pages/zep-research-benchmarks.txt
- 陈述性质: **可核验事实**（分数、题数、延迟分位、context token 数、读模型/判模型、检索深度参数）；**宣称**（"production agents need all three" 等定性）
- 内容: **LoCoMo：94.7% 准确率（1,459 / 1,540 题正确）；检索延迟 p50 87ms / p95 155ms；上下文中位 5,760 tokens（per question, end-to-end）**。分题型：single-hop 96.4%（646/670）、temporal 95.6%（311/325）、multi-hop 94.0%（304/323）、open-domain 79.2%（175/221）。**LongMemEval：90.2%（451 / 500）；延迟 p50 104ms / p95 162ms；上下文中位 4,408 tokens**。分题型：single-session assistant 96.4%、single-session user 94.3%、knowledge update 93.6%、temporal reasoning 90.2%、single-session preference 90.0%、**multi-session 83.5%**。**完整评测口径（可核验事实，S2 核心）**：Reader = **gpt-5.4（reasoning = medium）**；Judge = **gpt-5.4 with chain-of-thought grading**；多作用域检索深度 = **20 edges、10 nodes、10 episodes、5 thread summaries、5 observations + cross-encoder reranking**；auto search 用 `max_characters=10000`；**在 1,540 道 LoCoMo 与 500 道 LongMemEval 上运行，两个基准均 0 failed tests**。主结果使用 **multi-scope retrieval**：跨 facts、entities、episodes、observations、thread summaries **五路并行检索，在客户端组合**；另提供 **auto search**（单次 API 调用检索所有 scope、跨 scope 重排序、打包成字符上限的 context block），其 LoCoMo 成绩为 **86.5%**、延迟 p50 115ms / p95 173ms、上下文中位 **2,680 tokens（比多路方案小 53%）**。架构归因（可核验事实）：延迟来自"**Hot graphs are held in memory as adjacency lists and CSR matrices, with vector and BM25 indexes alongside**"；token 效率来自"Context Block 在检索时成形，而非由 LLM 生成"；精度来自 temporal invalidation 与 Observations 模式匹配。
- 与对照基准的关系: **提供本账本中最可比的一组"检索精度—延迟—token 成本"三元数字，并可与 Mem0 对照（见交叉对比）**。对判断的直接作用：①**"精度数字必须看分母"在此得到正面示范**——Zep 给出题数、分母、p50/p95、context token、读/判模型、检索深度，足以判断结论的适用条件；②**跨厂商数字不可直接排名**：Zep LoCoMo 94.7%（multi-scope、gpt-5.4 读判、5,760 tokens）vs Mem0 LoCoMo 92.5%（top_200、约 6,956 tokens、模型栈未逐项公开）；两者**读模型、检索预算、判分模型、context 大小全不同**，1.5–2.2 分的差距落在口径差异量级内，**不能作为选型依据**；③**图记忆并非"纯图"**：Zep 自述检索时同时持有 **vector 与 BM25 索引**，说明即便图原生厂商也是**混合检索 + 图算法**；④**auto search 揭示的权衡极其贴合对照基准**：单次调用、不调参、context 减半（2,680 vs 5,760）的代价是准确率从 94.7% 掉到 **86.5%（−8.2 分）**——这是"较少上下文 + 较简单检索"的**实测代价**，对"数十个记忆单元的轻量检索够不够用"是有量化锚点的证据。
- 疑点·局限: **厂商自测、无第三方复现**；判分用 gpt-5.4 with CoT grading，**未给 judge 不一致的置信区间**（Mem0 给了 ±1 分，Zep 未给），也未说明是否多次采样。"0 failed tests on either benchmark" 是执行完整性声明，非质量结论。页面**未给发布日期**，无法判断这组数字（尤其 gpt-5.4 作为 reader/judge）是何时测得、是否已被更新版本取代——**这是本条最大的时效性缺口**。multi-scope 结果依赖**客户端组合**，即部分工作在客户代码里完成，与"托管服务开箱即用"的表述存在张力。**auto search 的 86.5% 与主结果的 94.7% 并非同一配置**，不可混用。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-13] Zep. Why we built a graph database service for agent memory（Konig）
- 轨道 / 类型: 工业 / 厂商工程博客（一手技术叙述）
- 机构/作者: Zep AI, Inc.（Konig 团队）
- 出处: blog.getzep.com，"Konig, Zep's graph database service, is the data plane beneath our agent memory platform"
- 日期: **2026-08-27**（页面标注 "27 Aug 2026 · 15 min read"）
- 链接: https://blog.getzep.com/why-we-built-a-graph-database-service-for-agent-memory/
- 访问情况: 2026-09-28 读到整页正文（约 77KB 文本，含 Key takeaways、存储分层、ANN 选型复盘）　|　存档：evidence/pages/zep-konig-graph-db-blog.txt
- 陈述性质: **可核验事实**（工作负载特征、p95 数字、技术选型、失败复盘）；**宣称**（"cost tracks activity, not capacity" 的规模外推）
- 内容: **动机（可核验事实）**：Zep 原本跑在**商用通用图数据库**上，"After several challenging months of fighting outages and poor performance with our production graph database"，一位工程师用 12–1 月原型化了一个基于**内存邻接表**的图引擎，2026 上半年团队加入后成为生产系统 Konig。**核心论点**：通用图数据库假设**一张大图**（常驻内存、复杂查询遍历、schema 预先固定）；**agent 上下文是反过来的工作负载**——"**millions of smaller graphs, one per user, team, or project, most in cold storage and all temporal and governed**"。**规模与延迟（可核验事实）**："p95 retrieval stays under 100ms from a thousand graphs to tens of millions, and Zep's full end-to-end retrieval stays under 200ms at that scale"；"From a thousand graphs to tens of millions, p50 retrieval is unchanged and p95 stays under 100 milliseconds"；"the system sustains thousands of mutations and queries per second"。**成本模型（可核验事实）**：热图驻 RAM（微秒级），周期性快照写入本地 NVMe 与对象存储；不活跃被逐出者在其快照仍在 NVMe 时"reloads in low milliseconds"，更久闲置后本地副本被裁剪、只剩对象存储快照。**"Cost tracks active graphs, not total graphs. A deployment with a million graphs and one percent hot pays for one percent of the memory; the rest is in object storage at object-storage prices."** 分片按 hash 决定归属；新分片启动**不批量加载**，只注册心跳标记 ready 后**按需加载**。**明确的能力让步（可核验事实）**："The design gives up global ordering and traversals that span every graph at once. On the real-time retrieval path we do not need them: a single retrieval targets one graph, and an agent reasons across many graphs through separate calls."；跨图分析"we are building it as a separate, non-real-time workload off the low-latency retrieval path"。**检索实现（可核验事实，S2/S3）**：实体与边以"compact, integer-indexed arrays with adjacency lists"存储，"following a relationship is a pointer dereference instead of an index lookup"；"For many search operations, Konig runs a pipeline of all strategies above and **combines them with reciprocal rank fusion**, followed by an optional diversity rerank or low-latency LLM-based reranker, into one ordered result. **No separate search cluster, such as Elastic or OpenSearch, is needed.**" ANN 选型复盘：先用 **DiskANN 是错的选择**——因 DiskANN 的索引条目内嵌邻居向量副本，"Database size grew by **an order of magnitude**，with the memory and storage usage that implies. **Index builds also ran from tens of minutes to hours per graph**"；改用 **SPFresh/LIRE**，并按"searches are filtered"的方式分区索引，使**过滤不损失召回**。
- 与对照基准的关系: **本账本中给"什么时候才真的需要图库"提供最清晰阈值的一条**，且结论对对照基准有利。可核验事实读出的边界：Zep 需要自建图数据库的触发条件是**"数以百万计的图、每图一份记忆、绝大多数是冷的、且要按租户独立治理"**——量级与"数十个记忆单元、单租户、单图"相差 4–6 个数量级。Zep 自述通用图数据库在该工作负载下"handle poorly"，原因是**"一张大图、常驻内存"的假设**；对照基准的规模下这个假设根本不会被触发。**额外的强支持**：①Zep **放弃了跨图全局遍历**，实时路径上"一次检索只打一张图"——这正是对照基准"人工确认的一跳边"的设计前提，说明**限制遍历范围是业界刻意的工程选择，而非能力缺失**；②检索层用 **RRF 融合多路信号并保留 BM25**，再次印证"图原生系统也不靠单一语义信号"；③ANN 选型复盘是一手反例：**近似索引会带来一个数量级的存储膨胀与每图数十分钟的构建时间**——这是对照基准"零向量库"所规避掉的直接成本。**反驳面**：Zep 的 p95<100ms 与端到端<200ms 是在**热图**上取得的，冷图需先加载（低毫秒级到更久），对照基准需注意"冷启动"这一项在文件系统方案下同样存在但语义不同（读文件 vs 加载图快照+重放 WAL）。
- 疑点·局限: **厂商自述的性能数字，无第三方复现、无公开基准**；"tens of millions" 与 "thousands of mutations and queries per second" 未给硬件、图规模分布、热比例等条件，只给结论。"Cost tracks activity, not capacity" 是**架构推论 + 规模外推**，未见实际账单数据。博客**未给对照组**（旧商用图数据库的具体名称与旧数字均未披露），故"通用图数据库 handle poorly"**基线未披露**。采用 SPFresh/LIRE 等具体索引的**版本与配置未给**，不可复现。文中提到的 "all strategies above" 指向一个未在本页完整列出的检索策略清单，本次未读到该清单。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-14] Zep. Defending Agent Memory Against Poisoning（记忆投毒的一手工程防御叙述）
- 轨道 / 类型: 工业 / 厂商工程博客（安全工程一手叙述）
- 机构/作者: Zep AI, Inc.
- 出处: blog.getzep.com，"One poisoned message, web page, or document can shape every later session that reads the same memory."
- 日期: **2026-09-02**（页面标注 "02 Sep 2026 · 13 min read"）
- 链接: https://blog.getzep.com/defending-agent-memory-poisoning/
- 访问情况: 2026-09-28 读到整页正文（含五阶段传播模型与各阶段控制清单）　|　存档：evidence/pages/zep-defending-memory-poisoning-blog.txt
- 陈述性质: **可核验事实**（威胁命名与来源、控制设计、Zep 自身提供的机制）；**宣称**（"None of the controls below removes the risk on its own"）
- 内容: **定义（可核验事实）**："**Memory poisoning is prompt injection with persistence.** Agent memory persists across sessions or users. One poisoned input… can influence answers and tool calls long after the attacker's session ends."**边界主张**："The model is not the security boundary… The boundary you can enforce is application code that controls every write, every read, and every external action."**引用三项具体攻击**：**MINJA**（"injects malicious records into an agent's memory through ordinary user interaction alone, no access to the backend"）、**AgentPoison**（"a small number of poisoned records that a chosen trigger phrase reliably retrieves"）、**PoisonedRAG**（"makes retrieval-augmented generation give a chosen answer to a target question with a few adversarial documents per question"）。**攻击目标枚举**：存假事实；**用伪造的更新版本替换正确事实**；存入会被后续模型当作指令执行的文本；**用同一账号重复同一主张使其看起来像独立佐证**；**灌库把真实内容挤出检索结果**。**时间戳是最常用的杠杆**："Many memory systems resolve conflicts by recency. The attacker submits a claim with a fake later event time, and the store replaces the verified fact." 对策：**分别存"来源声明的事件时间"与"应用接受记录的时间"**。**五阶段传播模型**：写入 → 存储（经摘要与抽取被改写）→ 检索进提示 → 被模型采纳进推理 → 作为外部动作执行；"Each stage is a separate control point. A defense that measures only the last stage learns nothing about the first four." 并指出"**Not every harm reaches the last stage**: a wrong answer shown to a user, or **one user's context disclosed to another**, needs no tool call at all."**控制清单（可核验事实）**：①**受控写入**——"One application-owned path decides what enters durable memory. The model proposes a memory. Application code checks it and decides whether to store it." 并给出**类型化操作 vs 通用工具**的对比："A typed operation such as `record_user_preference(subject, field, value, source_event)` limits what one input can change. **A generic `remember(text)` tool stores arbitrary text.**" 另建议**按来源与时间窗限速**以遏制灌库与伪佐证；②**外部溯源**——记录每项由谁提供、如何到达，每个衍生物保留父系血缘，**事件时间与接受时间分开存**；③**作用域检索**——"**Retrieval filters by user, workspace, source, and review state before semantic ranking runs. Filtering results after a global search is weaker.** Excluded content still fills the candidate list."（**先过滤后排序**）；④**指令隔离**——"Retrieved memory enters the model as **data at the lowest available privilege, never in a system or developer message**"，并给出厂商差异：**OpenAI 的指引**把策略留在 instructions/developer messages、不可信输入走 user messages、工具返回走 `function_call_output`；**Anthropic 的指引**把第三方内容放 `tool_result` 块、排除在系统提示与普通用户文本之外；⑤**检测与可恢复性**——"A fluent false fact carries no marker, so detection watches **behavior**, not content"（观察单一来源异常写入速率、单一来源主导检索、未验证主张推翻已验证事实、动作提案只引用未验证记忆）；**修复必须选择性**："Clearing the entire store removes the poison and everything else. Repair must be selective."（隔离来源 → 追血缘 → 去除恶意语义 → 验证良性记忆存活）。另记录 **Zep 自身**的对应机制：可按来源元数据在服务内**返回前**过滤（filtered search 或 access policies）；"Every derived fact in Zep traces back to the episode that produced it. A fact displaced by a newer claim is marked invalid and kept."
- 与对照基准的关系: **对对照基准给出最有操作性的一段"设计规格"，其中多条恰好是它已经具备的**。①**类型化写入 vs 通用 `remember(text)`**：对照基准的"约 22 个人工确认的结构化案例 + 人工确认的一跳边"就是 Zep 推荐的 typed operation 形态（字段受约束、无任意文本通道），而"通用 `remember(text)`"正是它**没有**采纳的形态——这是来自安全工程侧对符号化、结构化记忆的正面背书。②**先过滤后排序**："filtering results after a global search is weaker. Excluded content still fills the candidate list"，而对照基准的确定性打分器天然是**在候选集上先按 MITRE 编号/指标/签名/正则探针过滤再加权**，与其建议同向；这也说明**"确定性过滤优先于相似度排序"在安全上有独立理由**（灌库攻击让被过滤项挤占候选位）。③**指令隔离**直接指出"记忆不能进系统提示"——这**正是 OWASP 记录的 MemoryTrap 在 Claude Code v2.1.50 修复的东西**（见 I-19），两条证据互相印证，构成对照基准的一条硬约束。④**事件时间与接受时间分开存**在对照基准里对应"告警发生时间 vs 案例入库时间"，是需要显式补上的字段。**同时给出反驳面**："Source filtering does not make end-user content trustworthy, and an agent with memory has to retrieve end-user content." —— 即**过滤能提供的是隔离，不是可信**；安全告警日志场景中若把日志内容直接作为记忆，投毒面仍然存在。
- 疑点·局限: 属**厂商工程博客**，非同行评审，也**未提供任何漏洞复现或防御有效性度量**（无攻击成功率对照、无检测误报率）。三项攻击（MINJA / AgentPoison / PoisonedRAG）**只给名字与一句话概括，未给论文链接或实验条件**，本次**未去核验这三篇原始工作**（超出工业轨道范围，应转学术轨道取证）。"Zep 能按来源过滤"是**产品能力陈述，无实现细节与性能影响数据**（过滤是否损害召回、成本多少未给）。厂商自身作为被讨论系统的提供方，**在"我们已提供防护"的表述上存在利益倾向**；文中也自认"None of the controls below removes the risk on its own"。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-15] Letta. MemFS（git 支撑的记忆文件系统；默认无向量索引）
- 轨道 / 类型: 工业 / 官方一手文档
- 机构/作者: Letta（MemGPT 系）
- 出处: Letta Docs, `concepts/memfs`
- 日期: `Last-Modified: Sun, 27 Sep 2026 00:54:56 GMT`；无版本号
- 链接: https://docs.letta.com/concepts/memfs
- 访问情况: 2026-09-28 读到整页正文　|　存档：evidence/pages/letta-memfs.txt
- 陈述性质: **可核验事实**（存储形态、加载规则、可选搜索组件、版本化机制）
- 内容: MemFS 是"**the git-backed memory filesystem used by Letta agents**"；"The memory itself is part of the agent's state, held in **a git repository that belongs to the agent**"。MemFS 把该仓库投影到 agent 运行的计算机上，"as a real checkout the agent reads and edits with **ordinary file tools**"；**"All Letta agents use MemFS."** 记忆**按路径寻址**：标签 `system/persona` 投影为 `system/persona.md`，"**Choosing a label is choosing where the memory lives and whether it stays in context.**"每条记忆是**带 YAML frontmatter 的 Markdown**。**上下文加载规则（可核验事实，S2/S6 关键）**："Files under `system/` are loaded into the agent's system prompt on every turn. Use this directory for the agent's identity, important user preferences, durable project facts, and critical workflow rules."；"**Files outside `system/` stay out of context until they are needed. The file tree itself is always in the system prompt, so directory and file names act as signposts the agent follows to read the right file.** This keeps the active context lean while preserving deeper reference material." 目录结构示例：`system/persona.md`、`system/human.md`、`reference/project-notes.md`、`skills/my-skill/SKILL.md`。**检索（S2 核心，可核验事实）**："**MemFS does not include a semantic or vector index by default. Agents find memory in its Markdown files with normal file-search and read tools.**" 如需关键词搜索与可选语义/混合搜索，需**另装** MemFS Search mod（`letta install npm:@letta-ai/memfs-search`）："**Keyword search works without additional dependencies. Semantic and hybrid modes require QMD to be installed and indexed over `$MEMORY_DIR`.**" 会话历史搜索是**另一套**："On Letta Cloud, `letta messages search` supports full-text, vector, and hybrid search over messages; **local backends currently search conversation transcripts with full-text matching only**."**版本化与同步（可核验事实）**："Every memory edit is committed to the MemFS git repository. This provides **version history, conflict resolution**, and a clear boundary between saved memory and uncommitted changes." 云端备份的 agent 会 push 回托管仓库以便其他机器拉取；本地 agent 由用户自行备份。**记忆子 agent（dreaming、memory doctor）用 git worktrees** 以便并发更新而不阻塞主 agent。Skills 也放在 `$MEMORY_DIR/skills`，与记忆一同版本化。多 agent 共享时用 shared memory（各自仍默认独占 MemFS）。
- 与对照基准的关系: **本账本中最强的单条支持证据：一个由 MemGPT/MemFS 谱系公司交付、且"All Letta agents use MemFS"的生产级 agent 记忆系统，默认不做语义/向量索引。**与对照基准逐项对应：①**"MemFS does not include a semantic or vector index by default"** —— 零向量库不是权宜之计，而是该产品**默认形态**，语义检索被降级为**需显式安装的 mod**（且需额外索引 QMD）；②**路径寻址 + 目录名即 signpost** —— 与对照基准"结构化案例库 + 确定性键（MITRE 编号、指标、签名）"同构：都是用**人类可读的确定性标签**代替相似度来完成定位；③**`system/` 每轮入提示、其余按需读取** —— 给出"什么进上下文、什么留索引"的明确分界，对照基准可类比为"高频签名/关键指标常驻、完整案例按需展开"；④**git 版本化天然提供 revision history 与冲突解决** —— 对应 Google Memory Bank 需要专门实现的 memory revisions（I-10），此处**由通用工具免费获得**，是符号化方案的一个未被充分注意的成本优势；⑤**local backend 只有全文匹配** —— 连厂商自己都在本地形态承认纯关键词检索是可交付的默认配置。**反驳面**：`system/` 目录**每轮注入系统提示**，这正是 OWASP 记录的 MemoryTrap 所利用的高信任通道（I-19），意味着对照基准若把案例摘要常驻提示词，需要 Zep 所述的"指令隔离"约束（I-14）来补偿。
- 疑点·局限: 文档**未给记忆体量上限**（文件数、总字节数、`system/` 目录能放多大），也未给加载延迟或精度数字。**未说明 MemFS 在数千条记忆时的表现**——"file tree 即 signpost"的可扩展性上限是该方法的关键未知量，文档回避了这一点。语义搜索"需安装 QMD 并建索引"这一句暗示**可选路径确实存在且被产品化**，但未给两路径的效果对比（无消融、无基准）。`Last-Modified` 只能证明页面近期被改，不能证明机制变更时间。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-16] Letta. Pricing（按 stateful agent 数与企业档管控计费）
- 轨道 / 类型: 工业 / 官方一手定价页
- 机构/作者: Letta
- 出处: Letta Docs, `pricing`（letta.com/pricing 重定向至此）
- 日期: `Last-Modified: Sun, 27 Sep 2026 00:28:32 GMT`；页面无发布日
- 链接: https://docs.letta.com/pricing
- 访问情况: 2026-09-28 读到整页正文（含个人档、开发者档、团队/企业档与计费 FAQ）　|　存档：evidence/pages/letta-pricing.txt
- 陈述性质: **可核验事实**（价格、agent 数上限、按量单价）；**宣称**（"power users 常接近或超过 $200+/mo"为经验性估算）
- 内容: **个人档**：**Free $0** — "**Free plans are limited to 3 stateful agents**"、Letta Auto 用量有限、可 BYOK 自带 API key；**Pro $20/月** — Letta Auto 周/月配额、按量超额、**up to 20 stateful agents**。**开发者档**：**API Plan $20/月** — **无限 agents**、**`$0.10 / active agent / mo`**、**`$0.00015 / sec tool execution`**、API key 认证、LLM 用量按量；**Teams Pro `$20/seat/month`** — 加成员、共享 agent 与访问控制、Letta Auto 配额。**Enterprise** — 定制、按量定价、增加配额、**RBAC、SAML/OIDC SSO**、专属支持。**计费口径可核验细节**：credits 是统一成本单位（LLM 推理与 CPU 周期）"Model requests consume credits at a rate depending on model API pricing"；**工具执行计费**："Server-side tools on the Letta API incur a credit cost for CPU time. On the API Plan, tool execution is billed at $0.00015/sec. **Remote MCP tools are executed by the MCP provider, so they do not have a credit cost. Letta built-in tools are free, with the exception of web search/fetch tools. Client-side tools, such as bash tools in the Letta CLI, run on your machine, so they do not incur a credit cost.**"**用量预期（可核验事实）**：文档给出按用户类型的月成本估算——"Casual coding users (a few hours per day): Typically **~$100/mo+** usage"；"Power users (long sessions, many parallel agents): Often approach or exceed **$200+/mo**"。超额行为：个人档可继续按量、开发者档全按量并"收到接近上限的邮件提醒"。
- 与对照基准的关系: **给出"按记忆单元/agent 数计费"这一独立计费维度，对自建方案的比较很有用**。可核验事实：Letta 的计费与 agent 数量挂钩（`$0.10/active agent/mo`）并对工具执行按秒计费（`$0.00015/sec`），而免费的**本地执行的工具不计费**——"Client-side tools… run on your machine, so they do not incur a credit cost"。这直接支持"把重活做在本地/自建侧"的经济性：对照基准的确定性正则/关键词打分器就是**客户端计算**，在 Letta 的计费模型下成本为 0（对比 Zep 按 Episode 字节计费、Mem0/AWS 按检索次数计费，见 I-01/I-06/I-11）。同时 Free 档"**3 个 stateful agents**"与 Pro"**20 个**"的限制说明**agent 数量本身是稀缺资源**，这与对照基准"数十个记忆单元"的规模在同一量级上会触及免费档上限，选型时需注意。
- 疑点·局限: 页面**无发布日期**。最关键的成本项——**LLM 推理按 tokens 计费**——在 credits 体系下**无法换算成美元**（文档指向 `platform.letta.com/models` 查模型价格，本次未读该页），因此**总成本不可核验**，只有工具执行单价（$0.00015/sec）是硬数字。$100+/mo、$200+/mo 的用户分档是**经验估算，非测量**。"Unlimited agents" 与按量计费并存，实际受配额与速率约束（文档未给 QPS/RPM 数字，**S6 的吞吐约束在这一条上缺失**）。企业档价格不公开。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-17] Pinecone. Pricing（托管向量服务的完整计费维度）
- 轨道 / 类型: 工业 / 官方一手定价页
- 机构/作者: Pinecone Systems, Inc.（页面版权 "© Pinecone Systems, Inc. | San Francisco, CA"）
- 出处: pinecone.io/pricing 页面与完整 Compare Plans 表
- 日期: 页面未标发布/更新日（HTTP 无 Last-Modified）；访问日 2026-09-28。页面顶部公告：**"Pinecone Bring Your Own Cloud is Now Generally Available"**
- 链接: https://www.pinecone.io/pricing/
- 访问情况: 2026-09-28 读到整页正文与完整对照表（含各档存储/读写单位/推理/重排序/合规矩阵）　|　存档：evidence/pages/pinecone-pricing.txt
- 陈述性质: **可核验事实**（价格、配额、索引上限、合规矩阵、延迟 SLA）；**宣称**（"scales effortlessly"、Starter 档示例工作量为自述估算）
- 内容: 四档：**Starter 免费** — 数据库 On-Demand、Inference、Assistant、**Dense, Sparse, and Full-Text Indexes**、控制台指标、Discord 社区支持；**Builder $20/月（flat）** — 更高用量上限、可选择云与区域、多项目多用户、Prometheus/Datadog 监控；**Standard $50/月最低消费** — 超出部分按量、3 周试用含 $300 credits、Dedicated Read Nodes、对象存储导入、备份恢复、**RBAC、SSO(SAML 2.0)**、**HIPAA add-on**；**Enterprise $500/月最低消费** — **99.95% Uptime SLA**、BYOC、Private Endpoints、客户托管密钥（CMEK）、审计日志、Service Accounts、SAML roles、SCIM、HIPAA 合规。**计费维度（可核验事实，S6(b) 核心）**：**存储 `$0.33/GB/mo`**（Starter 上限 2GB、Builder 10GB）；**写单位 $4–$4.50 / 百万**（Standard）、**$6–$6.75 / 百万**（Enterprise）；**读单位 $16–$18 / 百万**（Standard）、**$24–$27 / 百万**（Enterprise）；**出网 `$0.10/GB`**（含 100GB/月）；对象存储导入 `$0.25/GB`；**备份 `$0.10/GB/mo`**、**从备份恢复 `$0.15/GB`**。**索引与命名空间上限**：索引数 Starter 5 / Builder 10 per project / Standard 20 / Enterprise 200；**Namespaces per Index 100 / 1,000 / 100,000 / 100,000**。**推理**：嵌入 `llama-text-embed-v2` **$0.16/M tokens**、`multilingual-e5-large` 与 `pinecone-sparse-english-v0` **$0.08/M tokens**；重排序 `bge-reranker-v2-m3` 与 `pinecone-rerank-v0` **$2/1k requests**、`cohere-rerank-4-fast` **$2/1k rerank units**（**重排序模型仅在 Standard 及以上全量可用，Starter/Builder 只能用 bge-reranker-v2-m3**）。Assistant 侧按 tokens 计（输入 $8/M、输出 $15/M 等）、存储 `$3/GB/mo`。**合规矩阵**：SOC 2 / GDPR / ISO 27001 / HIPAA 逐档列出，**HIPAA 为 Standard 起 `$190/mo` 的加购项**。页面另给 Starter 档"能建什么"的估算示例（如约 30K 文档、20KB/文档、1024 维嵌入 → **约 15k 次搜索/天、约 660 次文档更新/天**），并附免责声明"Examples are illustrative only, not quotes or binding offers"。
- 与对照基准的关系: **给"若上向量库，代价结构长什么样"提供最完整的一手账本，并因此构成对"现阶段不必上"的成本侧支持**。可核验事实中最关键的对比是**读写不对称**：**读单位单价（$16–$27/百万）是写单位（$4–$6.75/百万）的约 3–6 倍**，即**检索次数是比写入更贵的资源**——这与 Mem0 把 add/retrieval 分列配额（I-06）、AWS 把 retrieve 单独计费（I-01）**同向**，三家独立厂商都指向同一结论：**检索频率是成本与治理的中心，而非存储量**。对对照基准：约 22 个案例、数十个记忆单元若落在 Pinecone 上，**存储成本低于最低档的 2GB 免费额度**（单条告警案例文本量级为 KB，全库远小于 2GB），真正的成本只在读。另外**重排序被单独按千次请求计费（$2/1k）**，说明"提升检索精度"在托管向量栈里是**显式计价的动作**——这一点对"必须治理检索精度"的判断给出了成本侧注解：治理有多种手段（确定性过滤 vs 重排序），而**只有前者是零边际成本**。
- 疑点·局限: 页面**无日期**（顶部 BYOC GA 公告也无日期）。价格**随云与区域浮动**（"varies by cloud and region"），本次读到的区间是美国区口径，**不可直接外推**。Starter 档"15k 搜索/天"类示例被页面自己标注为"illustrative… not quotes or binding offers"，**属宣称而非承诺**。**合规为逐档加购/分级**：HIPAA 在 Standard 才可 $190/mo 加购、Enterprise 才含合规；GDPR/SOC 2/ISO 27001 的**具体覆盖范围（哪些服务、哪些区域）在定价页上以矩阵呈现，未给审计报告**。本条**与对照基准没有直接的机制可比性**（它不提供记忆语义），仅作为**替代方案的成本边界**使用。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-18] OWASP. LLM08:2025 Vector and Embedding Weaknesses（LLM Top 10 2025）
- 轨道 / 类型: 工业 / 标准与框架文档（OWASP Gen AI Security Project）
- 机构/作者: OWASP Gen AI Security Project（GenAI Security Project，页面版权 © 2025 OWASP Foundation, Inc.；页面文本以 Creative Commons Attribution-ShareAlike v4.0 发布）
- 出处: OWASP Top 10 for LLM Applications 2025，条目 LLM08:2025；正文镜像于 GitHub 仓库 `OWASP/www-project-top-10-for-large-language-model-applications/2_0_vulns/LLM08_VectorAndEmbeddingWeaknesses.md`
- 日期: **2025 版**（页面导航标 "2025 Top 10 Risk & Mitigations"；其他语言译本标注 2025-03-12 与 2025-07-22）；条目页本身未标日期。访问日 2026-09-28
- 链接: https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/
- 访问情况: 2026-09-28 读到条目正文（先按错误 URL `…/llm08-vulnerability-in-vector-and-embedding-weaknesses/` 得到 **404**，后改用正确 slug 成功）　|　存档：evidence/pages/owasp-llm08-2025.txt、evidence/pages/owasp-llm08-404.txt（错误 URL 的 404 存档）
- 陈述性质: **可核验事实**（风险分类与缓解项清单、引用的外部工作）；**宣称**（风险严重性排序）
- 内容: 把向量与嵌入特有的风险单列为一个 2025 年新增条目。**风险类别（可核验事实）**：①**未授权访问与数据泄露**——"Inadequate or misaligned access controls can lead to unauthorized access to embeddings containing sensitive information. If not properly managed, the model could retrieve and disclose personal data, proprietary information, or other sensitive content."，并指出对嵌入内容的未授权使用可能导致法律责任；②（原文序号 3）**嵌入反演攻击（Embedding Inversion Attacks）**——"Attackers can exploit vulnerabilities to invert embeddings and recover significant amounts of source information, compromising data confidentiality."，引用 arXiv:2004.00053《Information Leakage in Embedding Models》与 arXiv:2305.03010《Sentence Embedding Leaks More Information than You Expect》（生成式嵌入反演可恢复整句）。**缓解策略（可核验事实）**：①**权限与访问控制**——"Implement fine-grained access controls and permission-aware vector and embedding stores. **Ensure strict logical and access partitioning of datasets in the vector database to prevent unauthorized access between different classes of users or different groups.**"；②**数据校验与来源认证**——"Implement robust data validation pipelines for knowledge sources. Regularly audit and validate the integrity of the knowledge base for hidden codes and data poisoning. **Accept data only from trusted and verified sources.**"；③另列**知识冲突**与 RAG 投毒相关参考。参考链接包含 **ConfusedPilot**（RAG 中的混淆代理风险）、"How RAG Poisoning Made Llama3 Racist"、Astute RAG（arXiv:2410.07176，应对不完美检索增强与知识冲突）等。
- 与对照基准的关系: **提供"零向量库"在安全侧的可计入收益，同时也界定它不解决什么**。支持面：本条目把**未授权跨用户访问、嵌入反演、数据投毒**这三类风险**直接绑定在向量与嵌入存储上**——其缓解手段（"strict logical and access partitioning of datasets **in the vector database**"、"permission-aware vector and embedding stores"）说明**该存储本身是需要专门加固的对象**。对照基准不引入嵌入，**嵌入反演这一整类风险不存在**（无向量可反演），跨租户泄露面也从"向量库分区配置是否正确"退化为"文件权限"。**同时给出的警示**：条目把"数据投毒 / 只接受可信来源的数据"作为独立缓解项——**这与是否使用向量库无关**，即对照基准**并不能**靠"零向量"免疫投毒（与 I-14 的结论一致：投毒是持久化问题，不是检索机制问题）。在本账本中，本条是**唯一从标准/框架侧**为"向量库带来额外攻面"提供条目的证据。
- 疑点·局限: **属框架文档而非实证研究**——条目给的是风险分类与缓解清单，**无任何量化数据**（无反演成功率、无泄露比例、无误报率）。引用被当作支撑的 arXiv 工作**本次未打开核验**（超出工业轨道范围，应转学术轨道）。"2025"版页面**未标条目级日期**，且 OWASP 页面导航中已出现 **2026 版 Top 10** 的迹象（"LLM TOP 10 FOR 2025" 与 "2023/24" 并列，另有 2026 版发布公告出现在 Recent Blogs），**本条可能已被更新版本取代**——使用时须注意版本时效。页面本身还有 404 URL 与正文混排等站点维护问题。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-19] OWASP. Top 10 for Agentic Applications（ASI06: Memory & Context Poisoning）
- 轨道 / 类型: 工业 / 标准与框架文档（OWASP Gen AI Security Project，Agentic Security Initiative）
- 机构/作者: OWASP Gen AI Security Project；Agentic Top 10 领导团队 John Sotiropoulos（Board Member & ASI co-lead, Agentic Top 10 Chair）、Keren Katz（Co-Lead）、Ron F. Del Rosario（Core Team & ASI co-lead）；复核含 NIST 的 Apostol Vassilev、Alan Turing Institute、Microsoft AI Red Team、AWS、Oracle Cloud 等
- 出处: OWASP Gen AI Security Project 官方博客发布公告 "OWASP Top 10 for Agentic Applications – The Benchmark for Agentic Security in the Age of Autonomous AI"，同时发布 Threat & Mitigations 1.1 分类法
- 日期: **2025-12-09**（页面署名日期）
- 链接: https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/
- 访问情况: 2026-09-28 读到整页正文（发布公告全文含十条清单）　|　存档：evidence/pages/owasp-agentic-top10-2025-12-09.txt
- 陈述性质: **可核验事实**（条目编号与名称、发布日期、参与机构）；**宣称**（"hundreds of experts"、"not theoretical risks" 等为定性动员表述）
- 内容: 发布 **OWASP Top 10 for Agentic Applications**，十条编号为 **ASI01–ASI10**，其中与本课题直接相关的是 **"ASI06 – Memory & Context Poisoning"**。原文对该条的表述："**Memory poisoning reshaped behaviour long after the initial interaction (ASI06 – Memory & Context Poisoning, e.g. Gemini Memory Attack).**" 其余条目为 ASI01 Agent Goal Hijack（例 EchoLeak）、ASI02 Tool Misuse（例 Amazon Q）、ASI03 Identity & Privilege Abuse、ASI04 Agentic Supply Chain Vulnerabilities（例 GitHub MCP exploit）、ASI05 Unexpected Code Execution（例 AutoGPT RCE）、ASI07 Insecure Inter-Agent Communication、ASI08 Cascading Failures、ASI09 Human-Agent Trust Exploitation、ASI10 Rogue Agents（例 Replit meltdown）。文档给出两条与本课题直接相关的定性论断：**"These are not theoretical risks"**（并列举上述真实事件），以及记忆投毒的特征是**"reshaped behaviour long after the initial interaction"**——即**危害的时间延展性**是它区别于普通提示注入的定义性特征。另可核验事实：该计划的采纳信号被逐一列出，包括 **Microsoft 的 agentic failure modes 引用其 Threat and Mitigations 文档、NVIDIA 的 Safety and Security Framework for Real-World Agentic Systems 大量引用其 Agentic Threat Modelling Guide、GoDaddy 已把其 Agentic Naming Service 提案投产**，以及 AWS 与 Microsoft "reference or embed our AgenticThreats and Mitigations"。
- 与对照基准的关系: **把"记忆投毒"确立为一个有编号的一等风险类，并给出一个标准化命名（ASI06）供对照基准的威胁模型引用**。对决策的作用：①它把风险从"提示注入的子情形"提升为独立条目，且其**示例是消费级产品真实事件（Gemini Memory Attack）**而非实验室构造——说明"记忆成为持久攻击面"已在 2025 年底被主流安全社区接受为常态；②它与其他九条并列出现，其中 **ASI01/ASI06 的区分（即时目标劫持 vs 持久记忆投毒）正是对照基准需要向评审者解释的差异**，可直接引为本方案的威胁模型依据；③在本账本中，本条与 I-14（Zep 的防御工程叙述）和 I-20（MemoryTrap 实例）构成**"框架条目—产品防御—真实漏洞"三段式证据链**，是 S7 上最完整的一组。
- 疑点·局限: **本次读到的是发布公告博客，不是 ASI06 条目正文**——公告只给一句话描述与一个例子，**未读到 ASI06 的完整威胁描述、缓解措施与攻击场景**（条目正文在另发的正式文档中，本次未获取）。因此本条**不能用来引用"OWASP 对记忆投毒的具体缓解建议"**，那部分应以 I-14（厂商工程实践）替代。发布公告含大量动员性表述（"hundreds of experts"、"the north star"），**属宣称**。"Gemini Memory Attack" 只给名称，**未给来源链接，本次未核验该事件**。采纳信号（Microsoft/NVIDIA/GoDaddy 引用）为**自述，未逐一核验**。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-20] OWASP. Memory Is a Feature. It Is Also an Attack Surface.（MemoryTrap 漏洞与 Claude Code v2.1.50 修复）
- 轨道 / 类型: 工业 / 标准组织博客（含一条具体漏洞披露的一手叙述）
- 机构/作者: **Idan Habler**，ASI Core Team 与 **ASI06 条目负责人**，Cisco Senior Tech Lead / AI Security Researcher
- 出处: OWASP Gen AI Security Project 博客；所披露的漏洞由 **Cisco 研究**发现并命名 **MemoryTrap**
- 日期: **2026-05-13**（页面署名日期；本次首次按 `…/2026/09/memory-is-a-feature…` 访问，被重定向至 `…/2026/05/13/memory-is-a-feature-it-is-also-an-attack-surface/`）
- 链接: https://genai.owasp.org/2026/05/13/memory-is-a-feature-it-is-also-an-attack-surface/
- 访问情况: 2026-09-28 读到整页正文　|　存档：evidence/pages/owasp-memory-attack-memorytrap-2026-05-13.txt
- 陈述性质: **可核验事实**（漏洞路径、受影响的信任面、修复版本号与修复内容）；**宣称**（"the industry still underestimates"、对同类产品现状的反问）
- 内容: 作者以 ASI06 条目负责人身份说明该条的核心问题："**what happens when an AI agent does not just process untrusted input, but carries it forward?**"，并指出 agentic 系统的特征是"retain context, reuse memory, and rely on persistent state to guide future reasoning and actions. That is what makes them useful. **It is also what makes them vulnerable.**"**MemoryTrap 技术路径（可核验事实）**：作者引述 Cisco 对 **Claude Code** 的研究——"a routine developer workflow could turn into persistent prompt injection. The path was surprisingly ordinary: **clone a repository, let the agent help, approve a dependency installation, and move on.**"恶意载荷**并未留在项目内**，而是"**it reached persistent memory, the global hooks configuration, and even influenced a highly trusted instruction layer through the system prompt**"；后果是"a one-time action could shape the model's future behavior across sessions, projects, and even reboots"。触发行为本身正常：Claude Code 注意到缺失依赖并建议安装 npm 包。**修复（可核验事实）**："**To Anthropic's credit, after we at Cisco disclosed the issue, Claude Code v2.1.50 removed user memories from the system prompt**, reducing the specific high-trust override path we identified." 作者强调这只是"the right fix for the path we found"，并给出更一般的判断：**"a memory file is not just stored text. It can influence future decisions. A hook is not just a script. It can shape every interaction. A local configuration file is not just a preference. It can become part of the model's control plane."** 结论：**"memory should be treated as part of the attack surface"**——若 agent 能保留并复用上下文，该上下文"deserves the same scrutiny we already apply to execution paths, credentials, and other sensitive control surfaces"。
- 与对照基准的关系: **本账本中最直接界定对照基准风险边界的一条，且风险恰好命中它的核心设计**。对照基准的符号化案例记忆若采用 Claude Code 或 Letta MemFS 的形态（`system/` 或 CLAUDE.md **每轮注入系统提示**，见 I-09/I-15），则一条被污染的告警日志/案例就可能通过高信任通道获得持久影响——**MemoryTrap 证明这条路径在真实产品中被走通过，且修复手段就是"把用户记忆移出系统提示"**。这给对照基准三条可执行的硬约束：①**记忆内容不得进入系统提示**，只能以最低权限的数据（user / tool_result 级）进入，与 Zep 的"指令隔离"建议（I-14）完全一致；②**人工确认环节的价值被显著提高**——对照基准的"人工确认的一跳关系边 + 约 22 个案例由人维护"恰好构成 Zep 所称的 "controlled writes / typed operation"（一个应用方拥有的写入路径），而 MemoryTrap 的入口恰恰是**未经人工确认的自动写入**（agent 自行安装依赖并写入 hooks/记忆）；③**"一次性动作造成持久影响"** 提醒：对照基准的确定性检索器本身不构成防护，因为投毒针对的是**存储内容**而非检索排序——**检索精度治理与投毒防护是两个独立的必需项**。
- 疑点·局限: 本条**是博客叙述，不是漏洞报告或 CVE**；**无技术细节**（未给恶意载荷、hook 配置格式、复现步骤、影响版本范围），也**未给 Cisco 原始研究报告的链接**，本次**无法核验漏洞细节**，只能采信叙述。作者**未说明该修复是否已在其他产品中复现**，反而以反问形式暗示"how many other agentic tools still treat memory… as implicitly trustworthy?"——**这是修辞而非证据**。"Claude Code v2.1.50" 的**发布日期未给**（本次亦未去查该产品 changelog 核验），只能确认修复被归因于该版本号。作者是 OWASP ASI06 负责人，对"记忆应被视为攻击面"这一立场有明确主张倾向。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

### [I-21] LangChain. Memory（LangGraph 长期记忆与 Store 的检索原语）
- 轨道 / 类型: 工业 / 官方一手框架文档
- 机构/作者: LangChain（docs.langchain.com；相关 LangMem 概念文档位于 langchain-ai.github.io/langmem）
- 出处: LangChain 文档 "Memory"（`oss/python/concepts/memory`），含 Long-term memory 与 Memory storage 节
- 日期: 页面未标发布/更新日；访问日 2026-09-28
- 链接: https://docs.langchain.com/oss/python/concepts/memory
- 访问情况: 2026-09-28 读到整页正文（含代码示例）　|　存档：evidence/pages/langchain-memory-concepts.txt
- 陈述性质: **可核验事实**（记忆分类、Store 的检索能力与调用形态、命名空间语义）；**宣称**（无基线类宣称）
- 内容: 把长期记忆按认知分类拆为**语义记忆（事实）、情景记忆（经历）、程序记忆（规则）**，并注明部分研究（如 **CoALA 论文**）已把人类记忆类型映射到 AI agent 记忆。**关键的可核验区分**：文档专门澄清"**Semantic memory is different from 'semantic search'**"——前者是心理学术语（存事实与知识），后者是用嵌入按"含义"检索的技术；这一区分对本课题很有用，因为常用词"语义记忆"容易被误当作"必须上向量检索"。**存储与检索原语（S2 核心，可核验事实）**：LangGraph 的长期记忆存在 **Store** 中，"**memories are scoped to any custom namespace, not just within a single thread ID**"；文档给出的示例为 `store = InMemoryStore(index={"embed": embed, "dims": 2})`，**且示例代码注释明确"Use a DB-backed store in production use"**；示例中 `store.put(namespace, "a-memory", {...})` 写入任意 JSON 文档，`store.get(namespace, "a-memory")` 按 key 直取，`store.search(namespace, filter={"my-key": "my-value"}, query="language preferences")` 做"**filtering on content equivalence, sorted by vector similarity**"。文档说明："**The Store currently supports both semantic search and filtering by content.**" 且对文档集合形态的说明是"Working with document collections also shifts complexity to memory search over the list."
- 与对照基准的关系: **给出"工业默认框架"的参照系，用于界定对照基准在生态中的位置**。可核验事实：LangGraph 的 Store **同时**支持**按 key 直取（`get`）**、**按内容过滤（`filter`）**与**向量相似度排序（`query`）**，三者是并列原语而非替代关系——即**主流框架并未强迫使用者只用向量检索**，确定性取用（key 与 filter）是**一等公民**。这一点支持对照基准的技术路线可落在主流框架之内：其"关键词×3 / MITRE 编号×2 / 指标×2 / 签名×1 / 正则探针×4 加权打分"可映射为 **filter/自定义打分**，而无需引入 `query` 路径。**同时给出成本侧提示**：示例 `InMemoryStore(index={"embed": embed, "dims": 2})` 在**构造时就需要一个 embed 函数**才能启用检索排序，说明在该框架里**"想要排序"与"想要嵌入"是被耦合的**——对照基准的加权打分器恰好在框架之外自行实现排序，绕开了这一耦合（也正是它"零嵌入"的实现方式）。**术语层面的实用提醒**：文档对 "semantic memory" 与 "semantic search" 的区分，可用于回答评审者"没有向量还算有语义记忆吗"这类质疑——按该文档的口径，**"语义记忆"指存的是事实，不指检索方式**。
- 疑点·局限: 页面**无日期**，无法支撑时效判断。文档为**框架概念说明**，**不含任何检索精度、延迟或成本数字**，因此**不能用来支持或反驳"确定性检索够用"**——它只证明"确定性检索原语存在且被支持"。LangMem（LangChain 的长期记忆 SDK）在本次检索中出现于搜索结果，但其文档页 `langchain-ai.github.io/langmem/concepts/conceptual_guide/` **本次未打开**，故本条目**未覆盖 LangMem 的具体记忆管理 API（如 Collection / Profile 等管理策略）**，是该子问题上的一处缺口。示例代码中的 `embed` 返回常量 `[[1.0, 2.0] * len(texts)]`，是占位实现，**不可据此推断默认行为**。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空

---

## 未获取 / 仅二手转述 清单

以下条目**未获得一手页面**，按纪律不得凭标题或搜索摘要描述其内容：

| 目标 | 尝试的确切 URL | 结果 |
|---|---|---|
| AWS AgentCore **服务配额（Quotas）** 页 | `https://docs.aws.amazon.com/general/latest/gr/bedrock-agentcore.html`（重定向至 `.../gr/` 且正文为空）；`https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/quotas.html`；`.../devguide/limits.html`；`.../devguide/memory-quotas.html`（三者均返回 title 为 "Amazon Bedrock AgentCore" 的 JS 壳，正文经 node fetch 与 read_page 均被重定向至 overview） | **未获取**。因此本账本**无法给出 AgentCore Memory 的记忆条数上限、事件保留期或 TPM/RPM 配额**。 |
| OpenAI Platform 数据控制文档 | 依环境手册记载 `platform.openai.com` 返回 403 Cloudflare，**本次未尝试** | 未获取。记忆侧材料改以官方帮助中心一手页替代（I-08 为 Anthropic 对应物；OpenAI 侧本账本**未收录条目**） |
| OpenAI Memory 帮助中心文章 | `https://help.openai.com/en/articles/8590148-memory-faq` → 重定向至 `https://help.openai.com/en/articles/8590148-memory-in-chatgpt`，**成功读到整页正文**（"Memory in ChatGPT"，页面显示 "Updated: 8 days ago"，无绝对日期） | **已获取但未单列条目**：因条目预算用于更贴合 S6(b)/S4 的厂商，其内容（去重后仅保留一条可核验事实：ChatGPT 侧同样存在"源删除不必然删除派生记忆""删除传播需时间"的语义，与 I-08 同向）在"交叉对比"中作为佐证引用 |
| Zep Graphiti 文档（开源框架） | `https://help.getzep.com/graphiti/getting-started/welcome`（node fetch 仅取回约 2.5KB 骨架，正文为 JS 渲染未获得） | **未获取**。因此本账本**未覆盖 Graphiti 作为开源库的 API 与规模边界**（该部分更宜由开源轨道取证） |
| Neo4j "Meet Lenny's Memory: Building context graphs for AI agents" | `https://neo4j.com/blog/developer/meet-lennys-memory-building-context-graphs-for-ai-agents/` | **仅二手转述**：本次只在搜索结果摘要中见到该文与"industry recognizes that graph databases are essential for AI agent memory"一句，**未打开页面**，故不采用、不引用 |
| NIST AI 600-1（Generative AI Profile） | `https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf`；`https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence` | **仅二手转述**：只在搜索摘要中见到"July 2024"发布信息与"To identify and secure potential attack points…"片段，**未打开 PDF**。另注：其发布日期 **2024-07** 落在本课题时间窗口（2024-09 起）**之前**，即便获取也应以低时效权重处理 |
| Google Cloud Vertex AI Memory Bank 原始 HTML | `https://docs.cloud.google.com/gemini-enterprise-agent-platform/scale/memory-bank` 经 node fetch 报 `TypeError: fetch failed` | 已由 `read_page` 桥接通道获得全文（见 I-10），但**未获原始页面交叉验证**，该条在 I-10 中已标注 |
| Letta `concepts/memory` 页 | `https://docs.letta.com/concepts/memory` | **404**（正确路径为 `concepts/memfs`，已取到并记为 I-15）。Letta 的记忆块/归档记忆（memory blocks / archival memory）文档本次未覆盖 |
| OWASP LLM08 条目（首个 URL 猜测） | `https://genai.owasp.org/llmrisk/llm08-vulnerability-in-vector-and-embedding-weaknesses/` | **404**，改用正确 slug 后成功（见 I-18） |
| Zep 记忆投毒博客（首个 URL 猜测） | `https://blog.getzep.com/defending-agent-memory-against-poisoning/` | **404**，改用 `https://blog.getzep.com/defending-agent-memory-poisoning/` 成功（见 I-14） |
| OWASP Agentic Top 10 中 **ASI06 条目正文** | 未定位到条目正文 URL，只读到发布公告 | **未获取**。I-19 中已声明只能引用公告层面表述，不得引用具体缓解建议 |
| Mem0 速率限制（RPM/QPS） | 定价页与 FAQ 均无该数字 | **未获取**：厂商未公开 |

---

## 简短说明

- **条目数 21 条**，略高于委托的 12–20 条区间。原因：委托明确要求 S6(b) 五个维度（延迟/吞吐、存储增长、多租户隔离、隐私与删除、定价与配额）各有独立出处，且 (a) 评测、(c) 关系层需厂商一手表述；为覆盖这些必答点并保持"每家机构不宜占比过高"，需要 8 家机构 × 平均 2.6 条。**未用营销页凑数**：21 条全部为官方一手页面，其中 19 条为技术建造方自有域名文档。
- **机构分布**：AWS 2、Mem0 5、Anthropic 2、Google Cloud 1、Zep 4、Letta 2、Pinecone 1、OWASP 3、LangChain 1。单机构最高占比 5/21 ≈ 24%，低于三分之一的集中度上限。
- **S2（检索机制一手表述与精度分母）的主要收获**：仅 Mem0（I-04）与 Zep（I-12）披露了精度数字**且同时披露了分母**（题数、检索预算、读/判模型、置信区间或缺失情况）；AWS（I-01/I-02）、Google（I-10）、Letta（I-15/I-16）**均未披露任何检索精度**；Pinecone（I-17）与 Mem0 定价（I-06）披露的是**成本分母**（按次/按字节）而非精度分母。
- **S4 的主要收获**：Anthropic（I-08）给出最具体的删除/保留语义（源删除不删派生记忆、24 小时传播窗口、合规排除项）；Mem0（I-07）给出异步账号删除的范围清单；Google（I-10）给出区域/跨边界污染控制。**三家均未说明删除是否及如何传播到向量存储与图存储的底层副本与备份**，这是 S4 上的一致空白。
- **S7 的主要收获**：OWASP 三条（I-18/I-19/I-20）提供框架条目与一个真实漏洞；Zep（I-14）提供最可操作的五阶段防御工程规格。**四条的共识**是：投毒是"持久化"问题，与是否使用向量库**无关**；"记忆不得进入系统提示"是跨厂商一致建议。

---

## 存档与溯源说明

**本机 shell 无外网**，`curl` / `Invoke-WebRequest` / `git ls-remote` 均不可用（TLS `SEC_E_NO_CREDENTIALS`、连接超时）；网页证据经 **`node fetch`**（脚本 `evidence/fetch.mjs`，Node 内置 fetch + 浏览器 User-Agent）获取，`read_page` 桥接通道用于交叉验证与 node 取不到时的补位。**账本"检索记录"块已声明此通道。**

**原始页面存档**统一存于 `evidence/pages/`，文件名带来源前缀，可逐条与上方条目对应：

| 条目 | 存档文件 |
|---|---|
| I-01 | `pages/aws-agentcore-pricing.txt` |
| I-02 | `pages/aws-agentcore-memory.md.txt`、`pages/misc-aws.txt`（overview 页，含数据使用声明） |
| I-03 | `pages/mem0-how-it-works.md.txt`、`pages/mem0-platform-overview.md.txt` |
| I-04 | `pages/mem0-memory-evaluation.md.txt` |
| I-05 | `pages/mem0-graph-memory.md.txt`（另有 `pages/mem0-advanced-retrieval.md.txt`、`pages/mem0-memory-expiration.md.txt`、`pages/mem0-platform-vs-oss.md.txt` 一并取到但未单列条目） |
| I-06 | `pages/mem0-pricing.txt` |
| I-07 | `pages/mem0-platform-faqs.md.txt` |
| I-08 | `pages/anthropic-claude-memory-support.txt` |
| I-09 | `pages/anthropic-claude-code-memory.txt` |
| I-10 | **无原始存档** —— Google 域名经 `node fetch` 报 `TypeError: fetch failed`，该条**仅由 `read_page` 桥接通道返回文本**，未落盘为存档；如需复核须重跑 `read_page`（同一 URL） |
| I-11 | `pages/zep-pricing.txt` |
| I-12 | `pages/zep-research-benchmarks.txt`（另有 `pages/zep-sota-blog-2025-01-22.txt`，为 Zep 2025-01 版数字，用于前置声明一的版本漂移比对） |
| I-13 | `pages/zep-konig-graph-db-blog.txt` |
| I-14 | `pages/zep-defending-memory-poisoning-blog.txt` |
| I-15 | `pages/letta-memfs.txt` |
| I-16 | `pages/letta-pricing.txt` |
| I-17 | `pages/pinecone-pricing.txt` |
| I-18 | `pages/owasp-llm08-2025.txt`（另存错误 URL 的 404 页面 `pages/owasp-llm08-404.txt` 作为探测记录） |
| I-19 | `pages/owasp-agentic-top10-2025-12-09.txt` |
| I-20 | `pages/owasp-memory-attack-memorytrap-2026-05-13.txt` |
| I-21 | `pages/langchain-memory-concepts.txt` |

**未单列条目但已取到的存档**（供主代理复核或扩展）：`pages/openai-chatgpt-memory-help.txt`（OpenAI 帮助中心 "Memory in ChatGPT" 整页）、`pages/owasp-llm-top10-index.txt`、`pages/owasp-llm01-2025.txt`（LLM01 提示注入整页）、`pages/mem0-llms.txt`（Mem0 文档索引，44KB）、`pages/mem0-sitemap.txt`、`pages/zep-blog-index.txt`、`pages/pinecone-pricing.txt`。

**探测失败的存档**（保留以证明"尝试过什么"，不得据其描述内容）：`pages/aws-agentcore-quotas-attempt.txt`（342 字节，仅标题壳）、`pages/zep-graphiti-attempt.txt`、`pages/letta-agents-memory-attempt.txt`、`pages/letta-concepts-memory-404.txt`、`pages/misc-*.txt`（首次探测时的短文本）。

**复核方式**：任一条目的"可核验事实"均可在对应存档中逐字检索（如 `Select-String -Path pages\mem0-pricing.txt -Pattern '\$249'`）。存档为 **2026-09-28 抓取时的页面快照**，厂商页面随时可变，本账本不对"该数字今天是否仍有效"负责，只在条目中注明页面是否自带日期。


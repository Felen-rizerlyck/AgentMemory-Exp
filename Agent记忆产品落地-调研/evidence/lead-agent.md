# 主代理自采证据账本（lead-agent track）

> 本文件是主代理（报告作者）**亲自打开并核读**的证据，与三条子代理账本（`academic.md` / `industry.md` / `opensource.md`）分开保管，合并后再统一编号为报告正文的 A/I/O 键。
> 临时键：`L-A-xx`（学术）/ `L-I-xx`（工业）/ `L-O-xx`（开源）。合并时重编。
> 检索/访问日期：2026-09-28。

## 环境事实（影响全部证据的获取方式，必须在报告局限中声明）

- `github.com`、`raw.githubusercontent.com`、`cdn.jsdelivr.net`、`dl.acm.org`、`huggingface.co`、`api.openai.com`、`r.jina.ai` **均不可达**（connect timeout / ECONNRESET / 403）。
- `api.github.com` **可达**（未认证配额 60 次/小时/IP；实测 2026-09-28 03:55Z 时余 53/60）→ 仓库事实与文件原文经 REST API 获取，**无法 `git clone`**。
- `arxiv.org`（abs 与 /html/ 全文）、`aclanthology.org`、`openreview.net`、`pypi.org`、`nist.gov`、`genai.owasp.org`、`getzep.com`、`docs.mem0.ai` 可达。shell 的 `curl`/`git` 因 TLS/连接受限不可用，全部取数经 `node fetch`（工具：`assets/fetch.mjs`）。

---

### [L-A-01] Mem0: Building Production-Ready AI Agents with Scalable Long-Term Memory
- 轨道 / 类型: 学术 / 预印本（厂商自研，作者全部来自 Mem0）
- 作者·机构: Prateek Chhikara, Dev Khant, Saket Aryan, Taranjeet Singh, Deshraj Yadav（Mem0）
- 出处: arXiv:2504.19413 (v1) · cs.CL
- 日期: 2025-04-28
- 链接: https://arxiv.org/abs/2504.19413
- 访问情况: 2026-09-28 经 node fetch 读到 /html/ 全文并逐节核读（结果与附录节）；摘要与结论均读到
- 方法: 两套架构——Mem0（LLM 从会话中动态抽取/合并/检索显著信息）+ Mem0ᵍ（在图结构上表示会话元素间关系）；在 LOCOMO 上与六类基线比较：既有记忆增强系统、不同 chunk/k 的 RAG、full-context、开源记忆方案、专有模型系统、商业记忆平台。指标 F1 / BLEU-1 / LLM-as-a-Judge(J)，J 跑 10 次取均值±1SD。
- 结果（均来自论文原文，含成立条件）:
  - Mem0 搜索延迟 p50 0.148s / p95 0.200s，总延迟 p50 0.708s / p95 1.440s；full-context 总 p50 9.870s / p95 17.117s；Mem0ᵍ 总 p50 1.091s / p95 2.590s，J=68.44%（全文最高）。
  - **full-context 基线的 J 最高（约 73%）**，论文原文承认"can provide a slight accuracy edge"；记忆系统的收益在 token 与延迟（相对 full-context p95 降 ~91–92%）。
  - 摘要称"26% relative improvement in LLM-as-a-Judge over OpenAI"、"Mem0ᵍ 比 base 高约 2% overall"。
  - single-hop：Mem0 最强（F1 38.72 / B1 27.13 / J 67.13）；**加图后反而"marginal performance drop"**；图增益集中在 temporal 与 open-domain。
  - LangMem 搜索 p50 17.99s / p95 59.82s（论文称"impractical for interactive applications"）；A-Mem 搜索 p50 0.668s。
  - 结论节另称相对各题型最佳方法提升 single-hop 5% / temporal 11% / multi-hop 7%。
- 意义: 该文是该领域被引用最广的"记忆系统优于现状"证据，也是"图记忆只值 2%"这一判断的来源；对"小规模符号记忆够不够用"这一课题，它给出的关键对照是 **full-context 在准确率上并未被击败**。
- 疑点·局限（我核出的具体口径问题）:
  1. **OpenAI 基线的延迟/吞吐数字不含记忆抽取成本**——原文明确写 OpenAI 那一路是"processes manually extracted memories from their playground"，且"requires pre-extraction of relevant context, which is not reflected in the reported metrics"。故"相对 OpenAI 的 p95 优势"与"26% 相对提升"都不是端到端可比数字。
  2. OpenAI 基线被"intentionally granting the OpenAI approach privileged access to all memories rather than only question-relevant ones"——即对手在检索侧被优待、在抽取成本侧被豁免，方向相反的两种偏差同时存在。
  3. LOCOMO 的 **adversarial（不可回答）类被整类剔除**，理由是缺 ground truth；原文自述"this category was excluded from our evaluation"。
  4. 评测基准自身：论文称 LOCOMO 每会话约 600 轮 / 平均 26k tokens；而 LOCOMO 原论文自述"300 turns and 9K tokens on avg."（见 L-A-04）——**同一数据集两处描述相差近 3 倍**，口径未对齐。
  5. 作者机构与产品同一方，无第三方复现；随后被 Zep 公开质疑（见 L-I-01、L-I-02）。
- 采纳信号: 被 Zep、后续记忆系统论文与厂商对比文广泛引用；同时是争议中心。
- 评分: 待主代理统一评分
- 引用位置: 待定（预计 §2 评测 / §5 交叉对比 / §6 评价）

### [L-A-02] LongMemEval: Benchmarking Chat Assistants on Long-Term Interactive Memory
- 轨道 / 类型: 学术 / 预印本（基准数据集论文）
- 作者·机构: Di Wu 等（见论文；代码库 xiaowu0162/LongMemEval）
- 出处: arXiv:2410.10813 (v2)
- 日期: 2024-10-14 首发；v2 更新 2025-03-04
- 链接: https://arxiv.org/abs/2410.10813
- 访问情况: 2026-09-28 读到摘要全文（abs 页）；正文未取
- 方法: 500 条人工精编问题，嵌在可自由伸缩的用户-助手会话历史中；把长期记忆设计拆成**索引 / 检索 / 读取**三阶段统一框架；提出会话分解（值粒度）、事实增强的键扩展（索引）、时间感知查询扩展等优化。
- 结果: 五个核心长期记忆能力——信息抽取、跨会话推理、**时间推理、知识更新、拒答（abstention）**；商业对话助手与长上下文 LLM 在跨会话记忆上出现约 **30% 准确率下降**；上述优化同时提升召回与下游问答。基准与代码公开（github.com/xiaowu0162/LongMemEval）。
- 意义: 与本课题高度对齐——"知识更新"与"拒答"正是本项目"冲突更新/合并强化"与"负样本应静默（【新案例】）"的对应物；且它把记忆拆成索引/检索/读取三段，与本项目"写入-检索-关系-评测"四环可直接映射。
- 疑点·局限: abs 页未给逐能力分数与基线细节；未核正文；"30% 下降"的分母（哪些商业助手、什么配置）需读正文才能确认。
- 采纳信号: 被 Zep 明确推荐为比 LoCoMo 更严的基准（见 L-I-01）；2026 年出现 V2 与大量在其上做实验的工作（L-A-03、L-A-07）。
- 评分: 待统一评分
- 引用位置: 待定（预计 §2 评测 / §5）

### [L-A-03] LongMemEval-V2: Evaluating Long-Term Agent Memory Toward Experienced Colleagues
- 轨道 / 类型: 学术 / 预印本（基准数据集论文）
- 出处: arXiv:2605.12493 (v1)
- 日期: 2026-05-12
- 链接: https://arxiv.org/abs/2605.12493
- 访问情况: 2026-09-28 读到摘要全文；正文未取
- 方法: 面向"专用 Web 环境中的 agent 经验"设 451 条人工精编问题，五能力：静态状态回忆、动态状态追踪、工作流知识、环境陷阱（gotchas）、前提感知；历史轨迹最多 500 条 / **115M tokens**；采用 context gathering 形式（记忆系统消费历史轨迹、返回紧凑证据供下游问答）。提出 AgentRunbook-R（RAG 式记忆，含原始状态/事件/策略笔记三类知识池）与 AgentRunbook-C（把轨迹存成文件，调用编码 agent 在沙箱中取证）。
- 结果: AgentRunbook-C 平均准确率 72.5%，优于最强 RAG 基线 48.5% 与开箱编码 agent 基线 69.3%；代价是**高延迟**；作者称其推进了准确率-延迟 Pareto 前沿，但仍有大量改进空间。
- 意义: 2026 年的前沿已从"会话历史"转向"环境经验 + 极长轨迹"，且**用编码 agent 做取证式检索**成为新的强基线——这对本项目"符号检索 vs 语义检索"的取舍提供了第三种答案（agentic retrieval）。
- 疑点·局限: 结果来自作者自建基准与自建方法，无第三方复现；"72.5% vs 48.5%"的 RAG 基线配置未在摘要披露。
- 采纳信号: 尚新（2026-05），暂无独立复现证据；被 L-A-07 类工作引用。
- 评分: 待统一评分
- 引用位置: 待定（预计 §2 评测 / §5）

### [L-A-04] Evaluating Very Long-Term Conversational Memory of LLM Agents（LoCoMo 原始论文）
- 轨道 / 类型: 学术 / 预印本（基准数据集论文，后被会议收录）
- 作者·机构: Adyasha Maharana, Dong-Ho Lee, Sergey Tulyakov, Mohit Bansal, Francesco Barbieri, Yuwei Fang（Snap 研究）
- 出处: arXiv:2402.17753 · 项目页 snap-research.github.io/locomo
- 日期: 2024-02-27
- 链接: https://arxiv.org/abs/2402.17753
- 访问情况: 2026-09-28 读到 abs 页的 citation_abstract 与元数据；正文未取
- 方法: 机器-人流水线生成超长期对话，以 persona 与时间事件图接地；每轮对话 agent 还可分享/回应图像；人工标注者校验并编辑长程一致性与事件图接地。数据集成品：每个会话平均 **300 轮 / 9K tokens**，最多跨 35 个 session；基准含问答、事件摘要、多模态对话生成三类任务。
- 结果: LLM 在理解长对话、长程时间与因果动态上存在困难；长上下文 LLM 与 RAG 能带来改进，但仍显著落后于人类表现。
- 意义: 它是 Mem0/Zep 之争的战场，也是"基准长度是否真的构成压力"这一质疑的起点——**9K–26K tokens 落在现代上下文窗口内**，这正是 Zep 主张"LoCoMo 无法区分记忆系统与上下文窗口管理"的依据。
- 疑点·局限: 合成对话（机器生成+人工编辑），难度与真实流量不同；adversarial 类缺 ground truth（据 L-A-01 与 L-I-01）；2026 年有第三方审计称其答案键存在错误（仅见检索线索，本次未打开，见"未核验线索"）。
- 采纳信号: 被 Mem0、Zep、AgentIR 等广泛用作对比基准。
- 评分: 待统一评分
- 引用位置: 待定（预计 §2 评测 / §5）

### [L-A-05] A Survey of Agent Memory in the Second Half: Towards Self-Evolving and Long-Horizon Agents
- 轨道 / 类型: 学术 / 综述（预印本）
- 出处: arXiv:2602.06052 (v4)
- 日期: 首发 2026-01-14；v4 2026-08-04
- 链接: https://arxiv.org/abs/2602.06052
- 访问情况: 2026-09-28 读到摘要全文；正文（数百篇文献的梳理）未取
- 方法: 三维统一视角——记忆基质（内部参数化状态 vs 外部检索增强存储）、认知机制（感觉/工作/情景/语义/程序）、记忆主体（用户中心个性化 vs agent 中心经验）；再分析单/多 agent 拓扑下的记忆操作，并把"记忆管理"本身视为可训练能力（RL 上下文策展、决策时经验固化、可移植 agent 技能生态）；最后综述记忆效用的评测基准与指标。
- 结果: 定位性结论：2025 年记忆方向论文数量达数百篇；领域正处于"从模型创新与跑分转向问题定义与严格真实世界评测"的"下半场"；记忆是 agent 自我演化的基质。
- 意义: 为本报告提供分类坐标（尤其"记忆基质"二分正好对应本项目"零向量库 vs 向量/图库"的取舍），并**独立印证评测严谨性是当前公认短板**。
- 疑点·局限: 综述自身立场（"下半场"叙事）未经验证；摘要不含具体指标对比。
- 采纳信号: v4 版本迭代（2026-01 → 2026-08）说明仍在维护；本次未见引用计数。
- 评分: 待统一评分
- 引用位置: 待定（预计 §2 综述框架 / §6）

### [L-A-06] From Storage to Experience: A Survey on the Evolution of LLM Agent Memory Mechanisms
- 轨道 / 类型: 学术 / 综述（预印本）
- 出处: arXiv:2605.06716 (v1)
- 日期: 2026-05-07
- 链接: https://arxiv.org/abs/2605.06716
- 访问情况: 2026-09-28 读到摘要全文；正文未取
- 方法: 提出"存储（轨迹保存）→ 反思（轨迹精炼）→ 经验（轨迹抽象）"三阶段演化框架，并分析三个驱动因素（长程一致性需求、动态环境挑战、持续学习目标），重点讨论前沿"经验"阶段的两个机制：主动探索与跨轨迹抽象。
- 结果: 结论性判断为领域当前"在操作系统工程与认知科学之间摇摆、研究碎片化"，缺统一视角。
- 意义: 指出"轨迹抽象"（把多次观测凝练为可复用经验）是前沿方向——与本项目"合并强化 / 跨波次观测"的做法方向一致，但本项目止于"存储+反思"之间。
- 疑点·局限: 框架为作者自拟，非共识分类；摘要无实证数据。
- 采纳信号: 2026-05 新出，暂无独立复现。
- 评分: 待统一评分
- 引用位置: 待定（预计 §2 / §6）

### [L-A-07] AgentIR: A Workload-Adaptive Cascade Retrieval Substrate for Long-Term Conversational Memory
- 轨道 / 类型: 学术 / 预印本（系统论文）——**本次调研中对"要不要加向量层"最直接的一条量化证据**
- 出处: arXiv:2605.25092 (v1)
- 日期: 2026-05-24
- 链接: https://arxiv.org/abs/2605.25092
- 访问情况: 2026-09-28 读到摘要全文（含全部关键数字）；正文与代码未取
- 方法: 把"融合方式"当作每查询决策：BM25 / Dense / RRF / agent-aware RRF；并用**置信度触发的级联路由**（仅凭 BM25 top-k 的间隔判断）决定"本次是否值得跑约 52ms 的稠密通道"，跨工作负载重调而不重训。底层是时间分区索引，工作量随语料规模亚线性。
- 结果（关键，均在给定基准与 n 下成立）:
  - **LongMemEval（n=500）：稠密通道确有增量信息**，级联跳过 63% 查询、在 LLM 判定准确率持平下快 2.67 倍；按查询类型设阈后达 5.76 倍。
  - **LoCoMo（n=1,982）：BM25 单通道本身就是最强单系统**，同一触发器自动收敛到 **100% 跳过稠密通道**（快 132 倍，Hit@5 +0.089）。
  - 共享 8 核 VM 上并发 agent 数由 ~154 提升到 ~1,400（9 倍）；1234 倍语料增长仅带来 3.6 倍延迟；在 9 个 BEIR 数据集、最多 8.8M 文档上质量与 Lucene 持平而快约 10–11 倍；同时记录并修复了三个会让 nDCG@10 静默退化 6–8 倍的 BM25/GPU 实现陷阱。
- 意义: 把"要不要向量"从立场问题变成**工作负载测量问题**——同一套系统在 LoCoMo 上应完全跳过稠密通道，在 LongMemEval 上则应保留。这直接对标本项目"补测 3：查询形态测试"，并说明该测试应按**查询类型/工作负载分层**设计，而不是只测整体召回。
- 疑点·局限: 作者自建系统，未见他方复现；"BM25 在 LoCoMo 最强"与 Mem0/Zep 的结论相反，但两者的目标指标不同（AgentIR 看 retrieval-level Hit@5，Mem0/Zep 看端到端 LLM 判定准确率），**不可直接比大小**；作者自述修复了三处实现陷阱，意味着同类基准的历史数字可能受实现细节影响。
- 采纳信号: 2026-05 新出；摘要给出开源/可复现取向的细节（Pyserini/PISA 对照）。
- 评分: 待统一评分
- 引用位置: 待定（预计 §2 检索机制 / §5 交叉对比 / §6 建议）

### [L-A-08] Poison Once, Exploit Forever: Environment-Injected Memory Poisoning Attacks on Web Agents
- 轨道 / 类型: 学术 / 预印本（安全攻击论文）
- 出处: arXiv:2604.02623 (v2)
- 日期: 2026-04-03 首发；v2 2026-04-07
- 链接: https://arxiv.org/abs/2604.02623
- 访问情况: 2026-09-28 读到摘要全文；正文未取
- 方法: 提出 eTAMP（Environment-injected Trajectory-based Agent Memory Poisoning）——**仅靠环境观察污染记忆**，无需直接访问记忆存储、无需跨用户共享记忆；一次被污染的观察即可在后续不同网站的任务中激活，绕过基于权限的防御。在 (Visual)WebArena 上评测。
- 结果: 攻击成功率最高 32.5%（GPT-5-mini）、23.4%（GPT-5.2）、19.5%（GPT-OSS-120B）；发现"挫败利用"效应——agent 在环境压力下（点击丢失、文本乱码）易感性最高升至 8 倍；**能力更强的模型并不更安全**（GPT-5.2 任务表现更好但同样脆弱）。
- 意义: 把记忆风险从"存储被直接写入"推进到"只要经手过被污染的输入即可持久污染"，且跨会话、跨站点生效。对本项目意味着：负样本/通用词误命中不只是精度问题，**记忆若被恶意输入写入并被后续分析引用，会产生持续的误导链**。
- 疑点·局限: 作者自建攻击与自评，未见独立复现；WebArena 为合成环境；ASR 数字依赖具体模型版本。
- 采纳信号: 2026 年 memory poisoning 已成密集子领域（本次经 arXiv API 检出至少 6 篇 2026 年相关工作，见"未核验线索"）。
- 评分: 待统一评分
- 引用位置: 待定（预计 §2 安全 / §6 评价）

### [L-I-01] Zep. Lies, Damn Lies, & Statistics: Is Mem0 Really SOTA in Agent Memory?
- 轨道 / 类型: 工业 / 厂商工程博客（**竞争对手方的技术质疑，二手但具一手代码链接**）
- 机构: Zep（blog.getzep.com）
- 日期: 页面未标明确发布日期（正文含"May 12, 2025"更正说明）；页面顶部另有一条标注为 "December 9, 2015" 的横幅（明显站点日期异常，不采信）
- 链接: https://blog.getzep.com/lies-damn-lies-statistics-is-mem0-really-sota-in-agent-memory/
- 访问情况: 2026-09-28 经 node fetch 读到整页正文（含更正声明、图表说明与代码链接）
- 可核验事实（页面自陈的测量条件）:
  - 声称用"correct Zep implementation"重跑后 Zep 的 J=**75.14% ± 0.17**（并称 10 次运行），显著高于 Mem0 论文为 Zep 报告的 65.99%，约 10% 相对提升；页面同时保留一条**更正**：早期版本算错了 Zep 的分数，已修正为 75.14%±0.17。
  - Zep 搜索延迟 p95 **0.632s**（并发搜索；说明测自 AWS us-west-2，经 NAT），对比 Mem0 论文为 Zep 报告的 0.778s（Zep 称因对手用串行搜索而被抬高）与 Mem0ᵍ 的 0.657s；承认 Mem0 base 的 0.200s 更低，但指出那不是同类比较（base 是更简单的向量存储/缓存、无关系能力，且准确率在 Mem0 各变体中最低）。
  - 对 LoCoMo 的批评：会话平均约 16,000–26,000 tokens，**落在现代 LLM 上下文窗口内**；并直接引用对手数据指出 full-context 基线 J≈73% > Mem0 最佳≈68%；Category 5 因缺 ground truth 不可用，双方都剔除。
  - 声称 Mem0 对 Zep 的实现有两处错误：用户模型错误（把 user 角色同时给了两个参与者）、串行而非并行搜索。
  - 推荐改用 LongMemEval（称其平均约 115k tokens）。
- 宣称: "Zep outperforms Mem0 by 10%"、"LoCoMo is a flawed evaluation"。这些是**争讼中的一方口径**，基线是自建重跑，代码链接指向自家仓库。
- 意义: 这是本报告"基准数字不可跨厂商比较"的第一手证据的一半；它同时证明**厂商博客的评测结论会被对手以代码为依据反驳**。
- 疑点·局限: 利益相关方（Zep 是 Mem0 竞品）；其"更正"说明该文自身也曾算错；延迟测量含跨区 NAT 条件，与对手口径不统一。
- 评分: 待统一评分
- 引用位置: 待定（§2 评测 / §3 工业 / §5 分歧）

### [L-I-02] getzep/zep-papers issue #5: Revisiting Zep's 84% LoCoMo Claim: Corrected Evaluation & 58.44% Accuracy
- 轨道 / 类型: 工业 / 竞争对手公开质疑（GitHub issue，**一手文本，含复算脚本链接**）
- 机构: 由 Mem0 方在两个 Zep 仓库上提出
- 日期: 创建 2025-05-08；关闭 2025-05-19；共 3 条评论
- 链接: https://github.com/getzep/zep-papers/issues/5 （经 api.github.com 读取）
- 访问情况: 2026-09-28 经 GitHub REST API 读到 issue 标题、状态、创建/关闭时间与**完整正文**；评论仅见计数（3 条），未逐条读取
- 可核验事实（正文内容）:
  - 主张 Zep 的 84% 分数把**本应排除的 adversarial 类问题也算进去了**，因此"人为抬高约 25.56 个百分点"；在一致条件下（仅取前四个有效类别）复算得 Zep = **58.44% ± 0.20**，而 Mem0 论文为旧版 Zep 算法报告的为 **65.99% ± 0.16**。
  - 指控基准配置不一致：称 Zep 修改了 judge prompt（正文用词 "rig evaluation"）并变更模板变量，给出具体代码行链接。
  - 对"用户角色混淆""串行搜索"两项质疑逐一回应，并称 Mem0 当年使用的 `zep-cloud==2.10.1` 不支持 `created_at` 参数，该参数在对手论文发表后才于 2025-05-01 的 `zep-cloud==2.12.1` 加入，故"事后 SDK 更新不能回溯性地证明当时的评测有缺陷"。
  - 文中提及 Zep 作者（danielchalef）在评论中给出更正后的 75.14% ± 0.17（10 次运行）。
- 意义: 与 L-I-01 构成同一争议的对立两侧：同一个基准、同一个对手系统，双方给出的分数依次为 84% → 75.14% → 58.44%，**每一步都伴随方法学指控**。这是"记忆系统公开数字不可比"最完整的一条证据链。
- 疑点·局限: 由竞争对手方提出且由我方（Mem0）复算；issue 已被关闭；未读到 3 条评论的完整内容，也未独立复现任何一方的脚本。
- 评分: 待统一评分
- 引用位置: 待定（§5 分歧 / §6 评价）

### [L-O-01] mem0ai/mem0（仓库元数据，作为工业宣称的对照）
- 轨道 / 类型: 开源 / 记忆框架（Mem0 的开源实现）
- 许可: Apache-2.0（API `/repos` 返回的 license.spdx_id）
- 本次检查版本: 默认分支 main；`pushed_at = 2026-09-25T17:36:35Z`，`created_at = 2023-06-20`；未取 HEAD commit 哈希（配额约束）
- 链接: https://github.com/mem0ai/mem0
- 访问情况: 2026-09-28 经 api.github.com 读到仓库元数据与 README 原文（`/contents/README.md`，11879 字节）与递归文件树（2210 条路径）；**未读核心实现代码**
- 可核验事实: stars 66,117；语言 Python；仓库体积约 65.5 MB；开放 issue 数 752；未归档；仓库内含 `cli/python`、`integrations/*`（含 `integrations/hermes-plugin-mem0`、`integrations/openclaw`、`integrations/mem0-strands`）等目录。
- 意义: 说明 Mem0 已从"论文作品"演进为**多宿主集成的产品化仓库**（含编码 agent 与个人助理类集成），维护活跃度在 2026-09 仍高（数日内有推送）。
- 疑点·局限: stars 是弱信号；README 与论文的对应关系尚未逐项核对；本条目**不足以支撑"默认检索路径是向量库还是混合检索"的结论**，需读代码（开源轨道子代理负责）。
- 评分: 待统一评分
- 引用位置: 待定（§4 开源）

---

## 未核验线索（已见但**未打开**，不得作为引用使用）

以下条目在检索结果中出现，本次**未打开原文**，仅供后续追查，报告中不得当作已读证据：

1. LoCoMo 答案键审计（第三方）：称 1,540 题中 6.4% 答案键有错、judge 对"话题对但细节全错"的答案放行率最高约 63%。来源线索：dev.to/penfieldlabs「We audited LoCoMo: 6.4% of the answer key is wrong…」与 r/AIMemory 讨论「Serious flaws in two popular AI Memory Benchmarks (LoCoMo…)」。
2. Locomo-Plus：arXiv:2602.10715《Beyond-Factual Cognitive Memory Evaluation Framework for LLM Agents》，称长期会话记忆评测在退化为"表面形式回忆"时失效。
3. BEAM：arXiv:2510.27246（由上述审计文中引用），会话规模至 10M tokens。
4. 2026 年 memory poisoning 相关（经 arXiv API 检出，未读）：2606.04329《From Untrusted Input to Trusted Memory: A Systematic Study of Memory Poisoning Attacks in LLM Agents》(v2, 2026-06-18)、2601.05504《Memory Poisoning Attack and Defense on Memory Based LLM-Agents》(v2, 2026-01-12)、2609.13889《When Malicious Instructions Persist: Persistent Memory Poisoning Attack on Harness-Based Agents》(2026-09-12)、2603.20357、2609.00523。
5. 2026 年其他候选（未读）：2607.19096《Supra Cognitive Modes: A Routed Architecture for Agent Memory》、2606.10241《Regimes: An Auditable, Held-Out-Gated Improvement Loop Demonstrated on LongMemEval with ActiveGraph》、2606.26627《Agents That Know Too Much: A Data-Centric Survey of Privacy in LLM Agents》。
6. Zep 自身的 KG 论文（Zep: A Temporal Knowledge Graph Architecture for Agent Memory，Mem0 论文引用为 Rasmussen et al. 2025）——**尚未定位到其 arXiv 编号**，需补查。
7. Mem0 官方 2026 年评测对比页（mem0.ai/blog/ai-memory-benchmarks-in-2026、mem0.ai/compare/mem0-vs-zep）与第三方横评（dataaspirant、blog.devgenius）——均为二手或厂商自述，若采用需标注性质。

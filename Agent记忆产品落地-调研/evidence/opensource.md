# 开源轨道证据账本

课题：以「符号化案例记忆 + 轻量关系层（零向量库、零图库）」为对照基准，检视业界在记忆的**写入—检索—关系—评测**四环上的做法与边界。
本文件覆盖子问题 **S1**（写入与抽取）、**S2**（检索实现）、**S3**（关系层与图记忆，重点）、**S4**（更新与冲突）、**S5**（评测基准参考实现）、**S8**（规模与维护）。

---

## 检索记录

**取证方式说明（重要）**：**本机 shell 无外网，git clone 与 HTTP 抓取均不可用**（`git ls-remote https://github.com/...` 与 `curl` 均连接超时；环境已实测确认）；全部仓库证据经 `read_page` 读取 GitHub 网页 / `raw.githubusercontent.com` 原始文件 / `api.github.com` JSON 获取，**未能读取本地克隆，因此代码级事实以页面可见文件为准**。

- 本地 shell 探测：`git ls-remote` 对 github.com 5 个仓库全部 `Failed to connect to github.com port 443`（21160–21139 ms 超时）；`Invoke-RestMethod https://api.github.com/rate_limit` 连接被关闭。因此**放弃 clone 路线，未产生任何本地仓库副本**，`evidence/repos/` 为空。
- 替代路线（实测可用，全部证据由此取得）：
  - `api.github.com/repos/{owner}/{repo}` → 许可、star、`pushed_at`、`archived`、`default_branch`、`size`（**API 路线，非 clone**）。
  - `api.github.com/repos/{owner}/{repo}/commits?per_page=1` → 最新 commit 全文哈希与提交时间。
  - `raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}` → **读取真实源码文件正文**（等价于读文件，非仅读 README）。
  - `github.com/{owner}/{repo}` 网页 → 首页 README 渲染。
- 工具限制记录：`read_page` 的 firecrawl 引擎有 **15 req/min** 配额，超出返回 `429 Too Many Requests` 并回退到 local 引擎；local 引擎可取回 `raw.githubusercontent.com` 与 `api.github.com` 原文，但单页约 **50000 字符截断**，且较大的文件（`search.py` 约 800 行以上）会中途截断。因此对超长实现文件采取「读关键段落 + 辅以文件树确认路径存在」的方式，并在条目中写明截断情况。
- `web_search`：**7 次调用**（每次 1–4 条查询，共 **18 条查询词**）。查询词见各条目「检索来源」。首次调用遭遇 firecrawl 429，冷却后重试成功；另有 1 次 `read_page` 并行取数时撞上 429。
- **GitHub API 调用：累计约 46 次**（起始 60，结束时剩余 **14/60**）。其中阶段一（本机 shell 的 `Invoke-RestMethod` 失败后，改经 `read_page` 打 `api.github.com`）约 10 次；阶段二（改用 `assets/fetch.mjs` 直连 `api.github.com`）**27 次**，中途两次自查配额读数分别为 **48/60 → 21/60**，最终 **14/60**（最后一次自查本身消耗 1 次）。**配额未耗尽，但剩余 14 次不足以补齐下节 D 段缺口。**
- 候选来源：`web_search`（约 40 个来源条目）+ GitHub 元数据/文件树/源码探测（**13 个候选仓库进入账本**；2 个候选经 API 返回 **404** 已排除，2 个候选 `ghtree` 返回 0 路径未能取数）。
- 停止条件：S3（图记忆）候选饱和——不再出现未见过的图记忆实现；S5（评测基准）已覆盖三大主流基准 + mem0 官方基准仓；S1/S2/S4 机制在 Graphiti / mem0 层面已可互相印证。剩余未查项已在「未获取清单」中列明。
- 排除项：纯向量数据库本身（Milvus/Qdrant/FAISS）、通用 RAG 框架横评——按课题要求不纳入。

---

## 条目

### [O-01] getzep/graphiti
- 轨道 / 类型: 开源 / 图记忆（时序知识图谱框架，Zep 的开源内核）
- 许可: Apache-2.0（API `/repos/getzep/graphiti` 返回 `license.spdx_id = "Apache-2.0"`；源码文件头亦带 Apache 2.0 声明，`graphiti_core/search/search.py` 第 3–13 行）
- 本次检查版本: commit `6b4b56ff6f4b1e4e69c3c3c5487cf1b8762c483a`（2026-09-27T08:49:42Z），最后推送 `pushed_at = 2026-09-27T08:49:43Z`。检查方式: **API 路线**（`api.github.com` + `raw.githubusercontent.com` 取源码原文；本机无外网，无法 clone）
- 链接: https://github.com/getzep/graphiti
- 访问情况: 2026-09-28 实际读了 **源码文件正文**：`graphiti_core/search/search.py`（读到 `node_search` 中途被 50000 字符截断）、`graphiti_core/search/search_config.py`（全文）、`graphiti_core/utils/maintenance/edge_operations.py`（读到 `resolve_extracted_edges` 尾部截断）；另读了仓库根目录文件树、README、`.env.example`、最新 commit JSON。**未读**（受截断/额度限制）：`search_utils.py` 的 `rrf()` 与 `node_distance_reranker()` 内部实现、`prompts/dedupe_edges.py` 的判定提示词全文、`graphiti_core/utils/maintenance/node_operations.py`（实体消歧）。
- 定位与规模: 自称「Build Real-Time Knowledge Graphs for AI Agents / A Framework for Building Temporal Knowledge Graphs」。stars 31,229、forks 3,191、open issues 524（API 计数，弱信号）。存储后端**硬依赖第三方图数据库**：README「Requirements」写明需 Neo4j 5.26 / FalkorDB 1.1.2 / Amazon Neptune + OpenSearch Serverless / Kuzu 0.11.2；默认 LLM 与嵌入为 OpenAI（`OPENAI_API_KEY` 必需）。依赖与配置见 `.env.example`（`NEO4J_URI`、`FALKORDB_URI`、`SEMAPHORE_LIMIT`、`MAX_REFLEXION_ITERATIONS`）。
- 关键实现事实:
  - **建边是 LLM 抽取，不是机械规则**。`edge_operations.py::extract_edges()` 构造 context（episode 内容、已有节点名单、前序 episode、`edge_types` 与 node 签名对）后调用 `llm_client.generate_response(prompt_library.extract_edges.edge(context), response_model=ExtractedEdges, max_tokens=16384)`。抽取结果**做符号校验**：LLM 返回的 `source_entity_name` / `target_entity_name` 必须命中 `name_to_node` 映射，否则 `continue` 丢弃并 `logger.warning`；self-edge（源目标解析到同一 node uuid）被显式丢弃。`valid_at`/`invalid_at` 用 `datetime.fromisoformat` 解析，解析失败则 `warning` 并跳过。空 fact（`not edge_data.fact.strip()`）被过滤。
  - **边去重有两层，一层符号一层 LLM**。(1) 快路径为确定性符号去重：`_normalize_string_exact(edge.fact)` 归一化后以 `(source_uuid, target_uuid, normalized_fact)` 为键做内存内 `seen` dict 去重。(2) 慢路径把 LLM 抽取出的边与图中已存在边比对——先 `EntityEdge.get_between_nodes()` 取同源目标对的既有边，再用 `EDGE_HYBRID_SEARCH_RRF` 配置对 `extracted_edge.fact` 做**混合检索**得到 `related_edges`（去重候选）与 `edge_invalidation_candidates`（失效候选，用无过滤 `SearchFilters()` 的全图检索），两者去重（出现在去重候选里的从失效候选中剔除），最后**交给 LLM 判定** `resolve_extracted_edge(...)`。函数返回三元组 `(resolved_edges, invalidated_edges, new_edges)`——**失效不是删除，是把旧边标记为 invalidated 并保留时序历史**（README「old facts are invalidated — not deleted」）。
  - **检索默认是混合，且融合方式是可切换的排序器枚举**。`search_config.py`：`DEFAULT_SEARCH_LIMIT = 10`；`EdgeSearchMethod`/`NodeSearchMethod` = `cosine_similarity` / `bm25` / `breadth_first_search`；`EdgeReranker`/`NodeReranker` = `rrf`（reciprocal_rank_fusion）/ `node_distance` / `episode_mentions` / `mmr` / `cross_encoder`。每个 config 类的**字段默认值**为 `reranker = EdgeReranker.rrf`、`sim_min_score = DEFAULT_MIN_SCORE`、`mmr_lambda = DEFAULT_MMR_LAMBDA`、`bfs_max_depth = MAX_SEARCH_DEPTH`（常量定义在 `search_utils.py`，**本次未读到其数值**）。`SearchConfig.reranker_min_score` 默认 `0`。注意：`search_methods` 是**必填无默认值**的字段，即「用哪几种检索」由调用方的 recipe 决定，而非库内默认——真正的默认配方在 `search_config_recipes.py`（**未读**，仅从 `edge_operations.py` 的 import 确认存在 `EDGE_HYBRID_SEARCH_RRF`）。
  - **检索精度治理确实存在于代码**：`search.py::search()` 对每个检索方法都取 `2 * limit` 的候选（`candidate_limit = 2*limit`，即**先放大候选再重排**）；`edge_search()` 按配置分别调 `edge_fulltext_search`（BM25）、`edge_similarity_search`（带 `config.sim_min_score` 阈值）、`edge_bfs_search`；若有 `bfs` 方法且未给起点，会用**首轮检索结果的 source 节点**扩展一轮 BFS（`edge_bfs_search` 二次调用）——这是把「词汇检索的命中」当种子去做**一跳图扩展**，与对照基准的「人工确认一跳关系边」在机制上同类，但种子来自自动检索而非人工。
  - 融合/重排分支：`rrf` 与 `episode_mentions` 走 `rrf(search_result_uuids, min_score=reranker_min_score)`；`mmr` 走 `maximal_marginal_relevance(query_vector, ..., config.mmr_lambda, ...)`（需加载全部候选嵌入）；`cross_encoder` 是**先 RRF 截断到 `2*limit` 再调交叉编码器**（两段式）；`node_distance` 需 `center_node_uuid`，否则抛 `SearchRerankerError`，内部先 RRF 再用 `node_distance_reranker` 按图距离重排。
  - 嵌入并非可选项：`search()` 开头判定只要配置里含 `cosine_similarity` 或 `mmr`，就会 `await embedder.create(...)` 生成查询向量；否则才用 `[0.0] * EMBEDDING_DIM` 占位。也就是说**只有把 recipe 配成纯 BM25+BFS 才可能不调嵌入**，但库的默认配方是混合的。
  - 边与 episode 的溯源关系是显式边类型：`build_episodic_edges()` 建 `MENTIONED_IN` 边（entity → episode），`build_community_edges()` 建社区边。Kuzu 后端已在 README 中标注 **deprecated 并将在未来版本移除**（上游 Kuzu 项目停止维护），驱动仍随包发布但会发 `DeprecationWarning`。
- 维护与采纳信号: 最后提交 2026-09-27（检查日次日仍在推送）；CI 存在且被 README 徽章引用（`lint.yml`、`unit_tests.yml`、`typecheck.yml` 文件树中确认存在）；另有 `codeql.yml`、`dependabot.yml`、`stale.yml`、`issue-intake.yml` 与 `.github/intake/`（自动分诊脚本 + `decision.schema.json`）。有论文 arXiv:2501.13956 作为背书。open issues 524 相对 31k stars 属正常区间。
- 与对照基准的关系: Graphiti 在**每一环**都付出了对照基准刻意不付的代价——存储上要跑一个 Neo4j/FalkorDB/Neptune（对照基准是 JSON/SQLite 级零依赖）；检索上嵌入是默认路径的一部分（对照基准零嵌入）；关系上建边要过一次 LLM 抽取 + 一次 LLM 判重/判失效（对照基准是人工确认的一跳边）。换来的能力是**增量更新 + 双向时序（valid_at/invalid_at）+ 全量溯源（episode）+ 跨时间查询**，以及 BFS 图扩展带来的多跳召回。对本课题的关键含义：Graphiti 证明了「图记忆」在工程上等价于「图数据库 + LLM 抽取 + 混合检索」三件套齐上，**它是零图库路线要对比的最强反例，同时也是「记忆的时序失效」这一能力的最完整参考实现**。
- 疑点·局限: README 对「检索精度」的说法是营销口径（「high-precision queries without reliance on LLM summarization」「sub-second latency」注释给的是 **Zep 托管平台**而非 Graphiti 开源版——README 自己在 Zep vs Graphiti 对照表里写明 Graphiti「Custom implementation required; performance depends on your setup」）。所以**不能把 Zep 论文或 README 里的延迟/精度数字归给开源 Graphiti**。`resolve_extracted_edges` 对每条抽取边各发一次混合检索（`semaphore_gather` 并发），LLM 调用量与边数同阶，AI 成本随规模线性增长——这是零向量路线不承担的。代码未读全的部分（`rrf` 的 k 常数、`DEFAULT_MIN_SCORE`/`MAX_SEARCH_DEPTH` 的实际取值、`.env.example` 里 `MAX_REFLEXION_ITERATIONS` 所对应的反思环）是**推断（未读代码）**的边界，本条目不对其下结论。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空
- 检索来源: `web_search`「agent memory graph open source」/「temporal knowledge graph memory github」；GitHub API 元数据 + 文件树 + 源码原文

### [O-02] mem0ai/mem0
- 轨道 / 类型: 开源 / 记忆服务（库 + 自托管服务 + 托管平台三层）
- 许可: Apache-2.0（API 返回 `license.spdx_id = "Apache-2.0"`；README `## ⚖️ License` 节同述）
- 本次检查版本: 默认分支 `main`，`pushed_at = 2026-09-25T17:36:35Z`；本次**未取到具体 commit 短哈希**（依赖 `pushed_at` 与所读文件为准）。检查方式: **API 路线**（`api.github.com` 元数据 + `raw.githubusercontent.com` 源码原文；无法 clone）
- 链接: https://github.com/mem0ai/mem0
- 访问情况: 2026-09-28 实际读了 **源码文件正文**：`README.md`（全文）、`mem0/memory/main.py`（读到 `Memory.__init__` 后被 50000 字符截断，但**开头完整读到了全部 import 清单与顶层常量/校验函数**）、`mem0/utils/scoring.py`（**全文，约 120 行**）、`mem0/memory/notices.py`（读到 `display_scale_threshold_notice` 中途截断，但常量区完整）。**未读**：`mem0/configs/base.py`（默认 vector_store provider 的取值）、`mem0/utils/entity_extraction.py` 实现、`mem0/memory/notices.py` 中 `oss_notices_config.json` 的实际文案、检索主流程 `search()` 方法体。
- 定位与规模: 自称「The Memory Layer for AI Agents - Drop-in memory infrastructure」，Y Combinator S24。stars 66,117、forks 7,774、open issues 752、size 65,542 KB（API 计数）。**默认路径是向量库**：README 明写「Mem0 uses `text-embedding-3-small` from OpenAI as the default embedding model」，且 `Memory.__init__` 无条件创建 `EmbedderFactory.create(...)` 与 `VectorStoreFactory.create(...)`——**向量库是构造期必需组件，不是可选加速器**。另有独立的 `SQLiteManager(self.config.history_db_path)` 用于历史记录。
- 关键实现事实:
  - **检索是三路信号相加**（这是我读到的 `scoring.py` 全文，确定性代码，非 README 宣称）：`score_and_rank(semantic_results, bm25_scores, entity_boosts, threshold, top_k)`。`combined = (semantic_score + bm25_score + entity_boost) / max_possible`，其中 `max_possible` 按激活信号自适应：仅语义 = 1.0、语义+BM25 = 2.0、语义+BM25+实体 = 2.5、语义+实体 = 1.5；`ENTITY_BOOST_WEIGHT = 0.5`（硬编码常量）。**阈值口径很关键**：`threshold` 只在**语义分数**上做前置门（`if semantic_score < threshold: continue`），文档字符串明确写「Threshold gates the semantic score BEFORE combining -- candidates below the threshold are excluded even if BM25/entity would boost them」——即**词汇信号只能给已过语义门的候选加分，不能把纯关键词命中的记忆捞回来**。这一点直接限制了「用 BM25 补偿嵌入精度」的空间。
  - **BM25 归一化用查询长度自适应的 sigmoid**（`get_bm25_params`）：按切词后词数分档返回 `(midpoint, steepness)` —— ≤3 词 → (5.0, 0.7)、≤6 → (7.0, 0.6)、≤9 → (9.0, 0.5)、≤15 → (10.0, 0.5)、>15 → (12.0, 0.5)；`normalize_bm25` = `1/(1+exp(-steepness*(raw-midpoint)))`。**这是「治理检索精度」的一个具体形态**：因为长查询的原始 BM25 分会更高，所以给 sigmoid 中点做定标，避免长查询霸榜。切词走 `mem0.utils.lemmatization.lemmatize_for_bm25`（词形还原，非停用词表）。
  - **规模阈值被硬写进代码，这是本条最有决策价值的发现**。`mem0/memory/notices.py` 常量区（我直接读到）：`SCALE_MEMORY_COUNT_THRESHOLD = 2000`、`SCALE_MEMORY_COUNT_CHECK_INTERVAL = 100`、`SCALE_TOP_K_THRESHOLD = 50`、`PERFORMANCE_SLOW_QUERY_THRESHOLD_SECONDS = 2.0`（另有 `TEMPORAL_USAGE_CAP = 10` / `DECAY_USAGE_CAP = 10` 及 7 天窗口的提示节流）。触发逻辑：`detect_scale_threshold_from_top_k()` 在调用方传入 `top_k >= 50` 时返回 `("top_k", "high_top_k", ...)`；`detect_scale_threshold_from_add_result()` 累计新增记忆数**每 100 条检查一次**，调用 `_get_provider_memory_count()` 查后端真实条数，**≥ 2000 条**时标记并返回 `("memory_count", "memory_count_threshold", ..., provider_count, 2000)`。这些触发的是**提示文案**（`display_scale_threshold_notice`，走 PostHog 特性开关 + 远端 `oss_notices_config.json` 拉取文案，按 `variant_split` 做 50/50 displayed/holdout A/B），不是硬性降级——但厂商**选择在 2000 条、top_k 50、查询 2 秒这三个点向用户示警**，是它对「什么时候该换方案」的官方判定，可作为「数十条记忆单元远在安全区内」的一个外部锚点。
  - **时序能力在 OSS SDK 中是显式拒绝的**：`notices.py` 定义 `TEMPORAL_FEATURE_ERROR_MESSAGES = {"timestamp": "The timestamp parameter is not supported by the OSS Memory SDK.", "reference_date": "The reference_date parameter is not supported by the OSS Memory SDK."}` 与 `DECAY_FEATURE_ERROR_MESSAGE = "The decay parameter is not supported by the OSS Memory SDK."`；`_OSSProject.update()` 在 `decay is True` 时直接 `raise ValueError`。
  - **写入策略在 2026-04 版本发生方向性转变**：README「New Memory Algorithm (April 2026)」写「**Single-pass ADD-only extraction** -- one LLM call, no UPDATE/DELETE. Memories accumulate; nothing is overwritten.」「Agent-generated facts are first-class」「Entity linking: entities are extracted, embedded, and linked across memories」「Multi-signal retrieval: semantic, BM25 keyword, and entity matching scored in parallel and fused」。`main.py` 的 import 印证了这次改动是真实落地的代码：从 `mem0.configs.prompts` 引入 `ADDITIVE_EXTRACTION_PROMPT` 与 `generate_additive_extraction_prompt`（**加法式抽取提示词**），并有 `_strip_identity_keys` / `_reject_top_level_entity_params` 等作用域隔离校验（注释引用 issue #4490、#6277、#6655）。另有 `mem0/utils/entity_extraction.py` 的 `extract_entities` / `extract_entities_batch`，以及 `_entity_collection_name()` —— 实体被存进**独立的向量集合**（`f"{collection_name}_entities"`，s3_vectors 后端用 `-` 分隔），即**实体链接也是向量实现的，不是图结构**。
  - 可选重排器：`Memory.__init__` 中 `if config.reranker: self.reranker = RerankerFactory.create(...)`，**重排默认关闭**。混合检索需要装可选依赖：README 写 `pip install mem0ai[nlp]` + `python -m spacy download en_core_web_sm` 才有 BM25 关键词匹配与实体抽取。
  - 删除接口：`DELETE_ALL_BATCH_SIZE = 1000`（批量删除分片）；`_payload_is_expired()` 按 payload 的 `expiration_date` 判断过期（`expiration_date < 今天`），`_normalize_expiration_date` 只接受 `YYYY-MM-DD`。`detect_decay_usage_from_delete()` 在**同进程内成功删除累计 ≥ `DECAY_USAGE_DELETE_THRESHOLD = 5` 次**时触发「你似乎在手动做衰减」提示——说明 OSS 版把「记忆衰减」留给了用户手工删除。
- 维护与采纳信号: 最后推送 2026-09-25（检查前 3 天）；有 paper（arXiv:2504.19413）；`has_discussions = true`、topics 覆盖 `long-term-memory`/`memory-management`；README 引用 PyPI/npm 版本徽章与 PyPI 下载量徽章；评测框架 `mem0ai/memory-benchmarks` **单独开源**（见 [O-07]）。open issues 752（偏高，但项目体量也大）。
- 与对照基准的关系: mem0 是**本课题最重要的对照组**，因为它在 2026-04 明确砍掉了 UPDATE/DELETE 走向 ADD-only + 多信号检索 + 实体链接，方向上与「符号化案例记忆 + 轻量关系层」**部分收敛**（不再靠 LLM 覆写记忆，改靠累积 + 检索排序）。但它仍然：向量库是构造期必需依赖、实体链接仍建在向量集合上、时序/衰减能力只存在于托管平台、混合检索的阈值只作用在语义分上。**净判断：mem0 证明「多信号打分融合」是有效的方向，同时证明它自己认为离不开向量。**
- 疑点·局限: **README 的 benchmark 数字有明确的口径陷阱，已由厂商自己披露**：LoCoMo 71.4→92.5、LongMemEval 67.8→94.4、BEAM(1M) 64.1 / BEAM(10M) 48.6，紧随其后的小字写「Scores reflect **Mem0's managed platform, which includes proprietary optimizations not available in the open-source SDK**; open-source users should expect directionally similar gains but not identical numbers」。因此**这些数字不能用于评估开源 mem0**，也不能作为「向量方案在数十条规模下更好」的证据（基准规模是 1M–10M token）。另一方面，ADD-only 与 OSS 版拒绝 `timestamp`/`reference_date` 并置，构成一个未解释的张力：README 宣称的「Temporal Reasoning: time-aware retrieval that ranks the right dated instance for queries about current state」在 OSS 代码里对应的是**抛错**，我读到的 `main.py` 里也只有 `_normalize_iso_timestamp_to_utc` 这种存取时的格式归一，**未读到时间感知的排序逻辑**——两者口径不一致，需要向项目方或后续版本确认。`notices.py` 里 `_get_provider_memory_count()` 的具体实现与 `oss_notices_config.json` 文案未读。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空
- 检索来源: `web_search`「agent memory open source sqlite」；GitHub API 元数据；`raw.githubusercontent.com` 读 `scoring.py` / `notices.py` / `main.py` 原文

### [O-03] letta-ai/letta → letta-ai/letta-code
- 轨道 / 类型: 开源 / 记忆框架（原 MemGPT）——**含重大结构变更，须与其他项目区别对待**
- 许可: Apache-2.0（`letta-ai/letta` 与 `letta-ai/letta-code` 两个仓库的 API 均返回 `license.spdx_id = "Apache-2.0"`）
- 本次检查版本: `letta-ai/letta` HEAD = commit `5bcdd177d70fa2b31a754cfcd801e77b2e1ab16a`（2026-09-10T17:59:06Z，`pushed_at = 2026-09-10T17:59:08Z`）；`letta-ai/letta-code` `pushed_at = 2026-09-28T01:56:42Z`（检查当日）。检查方式: **API 路线**（元数据 + `ghtree` 递归文件树 + `ghfile` 源码原文；无法 clone）
- 链接: https://github.com/letta-ai/letta ； https://github.com/letta-ai/letta-code
- 访问情况: 2026-09-28 实际读了：`letta-ai/letta` 的**完整递归文件树**（仅 15 个路径）、`README.md` 原文、最新 commit JSON、branches 列表；`letta-ai/letta-code` 的元数据、**2553 个路径的完整文件树**，以及 `src/backend/message-search.ts`（全文）与 `src/backend/local/transcript-search.ts`（462 行，**读了头部 45 行 + 第 200–300 行的打分核心**）。**未读**：`src/agent/memory.ts`、`memory-filesystem.ts`、`memory-conflict-repair.ts`、`memory-format.ts`（已下载到 `assets/o-letacode-src_agent_memory-format.ts` 但未展开）、`src/agent/memory-git*.ts` 系列、`letta` 仓库 `archive` 分支下的 V1 服务器源码。
- 定位与规模:
  - **`letta-ai/letta` 的 `main` 分支已不含源码**。我拉到该分支的递归文件树，**只有 15 个路径**，全部是 `.github/`、`AGENTS.md`、`AI_POLICY.md`、`CITATION.cff`、`CONTRIBUTING.md`、`LICENSE`、`PRIVACY.md`、`README.md`、`SECURITY.md`、`TERMS.md`——**没有任何 `.py`/`.ts` 实现文件**。README 明写：「Letta (f.k.a. MemGPT) is actively developed. The current source code lives in `letta-ai/letta-code`」以及「**Historical source**: The `archive` branch contains the retired Letta V1 API server」。branches 列表确认存在 `archive` 分支。API 元数据中 `open_issues_count = 0`、`has_discussions = false`，`fork_count` 2,631、stars 24,921、size 293,597 KB（历史体积）。
  - 当前源码仓 `letta-ai/letta-code`：stars 3,444（明显低于旧仓，说明**大量引用旧仓的二手材料仍在描述已停维护的代码**）、Apache-2.0、TypeScript、size 98,609 KB、`pushed_at` 为检查当日。自述「Stateful agents that are like people, with memory, identity, and the ability to learn and adapt」。
- 关键实现事实:
  - **这是「零向量库」路线最有力的生产级正面证据，但要分清组件**。我在 2553 个路径的完整树里按 `embed|vector|graph|rag` 匹配，**命中数为 0**（仅命中两个巧合文件：`scripts/check-test-coverage.cjs` 命中 "coverage"、`src/skills/builtin/initializing-memory/scripts/history-coverage.mjs`）——即**该仓库没有任何嵌入、向量库或图数据库代码路径**。
  - **agent 的长期记忆是 git 版本化的文件系统**：`src/agent/` 下有 38 个 memory 相关路径（其中 17 个非测试实现文件），包括 `memory-filesystem.ts`、`memory-git.ts`、`memory-git-hooks.ts`、`memory-git-signing.ts`、`memory-git-windows-credentials.ts`、`memory-git-config-lock.ts`、`memory-worktree.ts`、`memory-conflict-repair.ts`、`memory-constraints.ts`、`memory-constraints-audit.ts`、`memory-scanner.ts`、`memory-format.ts`、`memory-operation.ts`、`memory-runtime.ts`、`memory-auth.ts`、`memory-constants.ts`、`memory.ts`；配套测试覆盖 precommit/postcommit 钩子、签名、Windows 凭据、worktree HTTP、本地作用域、重试、冲突修复。**git 用于记忆版本化与并发冲突修复（`memory-conflict-repair.ts` 存在且有测试），这对应本课题 S4（更新与冲突）的一个非数据库答案。**
  - **本地检索是纯符号实现，我读到了打分函数全文**。`src/backend/local/transcript-search.ts`：
    - `normalizeText()` = `value.toLowerCase().replace(/\s+/g, " ").trim()`（仅小写化 + 空白折叠，**无词干化、无停用词表**）。
    - `parseQuery()` 手写状态机解析引号：引号内为 `phrases`、引号外为 `terms`；**未闭合引号则整体退化为按空白切词的 terms**。
    - `matchScore(text, query)` 逻辑：先把消息的 content/reasoning/summary/工具调用名与参数/`tool_return`/`func_response` 拼成一个 haystack 再归一化；**每个 phrase 用 `indexOf` 精确子串匹配，任一 phrase 未命中即 `return null`（整条记忆被排除）**，命中则 `score += index * 0.1`；**每个 term 同样必须命中，否则 `return null`**（即 **AND 语义，纯合取**），命中则 `score += index + Math.max(0, 50 - term.length)`。最终按 score **升序**排序（`if (a.score !== b.score) return a.score - b.score;`），因为打分语义是「命中位置越靠前分越低 = 越好」，并为无查询时设 `score: Number.POSITIVE_INFINITY` 兜底。
    - 这条公式的形态与本课题对照基准高度同源：**确定性加权打分、位置项、长度项、无嵌入**。其中 `Math.max(0, 50 - term.length)` 是一个「短词命中给更多奖励（分更低）」的项，等价于一个粗糙的**通用词/长词偏好**；`index` 直接进入分数则等价于「靠前命中优先」。
    - 后端可切换：`message-search.ts` 定义 `type SearchMode = "vector" | "fts" | "hybrid"`，并把 `search_mode` 透传给 `./api/search` 的 `searchMessages`；但当后端能力标记 `localModelCatalog` 为真（本地后端）时，**改走 `searchLocalTranscriptMessages`，并且 `warmMessageSearchCache` 直接返回 `{ status: "local-backend-noop", warmed: false }`**。即：**vector/hybrid 只在托管 API 后端存在，本地后端只有上面这个符号检索，且完全没有索引缓存（每次全扫）。** 关于「全扫」这一点：函数签名与 `readdirSync`/`readFileSync`/`statSync` 的 import 表明它遍历本地存储目录读取转录文件；**但「每次查询扫描多少文件、有无预建倒排」我未读完函数体，属推断（未读代码）。**
- 维护与采纳信号: `letta-code` 检查当日仍在推送（`2026-09-28T01:56:42Z`），非 archived；旧仓 `letta` 在 2026-09-10 后仍有文档级提交（最新 commit 为安全政策文档更新）。旧仓 CI/workflow 仍在但只跑 issue 分流（`issue-guard.yml`）。旧仓 stars 24,921 与新仓 3,444 的巨大落差本身是**采纳信号的口径风险**：任何按 star 数选型的流程都会选到已退役的仓。
- 与对照基准的关系: 这是**本账本中唯一一个「长期记忆本体存成文件 + git、检索用合取式位置加权关键词」的生产级项目**，因此它直接支持「现阶段不必上向量库/图库」。同时它给出了对照基准尚未有的两块能力：**git 版本化带来的可删除性/可审计性/并发冲突修复**，以及**记忆的 access-control（`memory-auth.ts`）**。代价是它放弃了语义召回——`indexOf` 子串合取意味着**同义改写、缩写、"OOM" 与 "out of memory" 之间不互通**，这正是对照基准里「MITRE 技术编号×2 / 指标×2 / 正则探针×4」用**领域同义词与结构化键**去补的那部分，letta-code 靠的是**查询侧改写**（由 LLM agent 自己决定查什么词），而非索引侧语义扩展。
- 疑点·局限: **最大的局限是这条证据的适用范围**：letta-code 的符号检索服务对象是**对话转录（transcript）的本地搜索**，其 `search_mode` 枚举里 vector/hybrid 依然存在（走托管后端）；它的**agent 长期记忆（`src/agent/memory-*`）我未读实现**，因此**不能断言 Letta 的 agent 记忆本身也是符号检索**——两者可能是分开的机制。本条目只断言：(1) 该仓不存在嵌入/向量/图代码路径（基于完整文件树，强证据）；(2) 本地转录检索是合取式位置加权关键词（基于读到全文的打分函数，强证据）；(3) agent 记忆是 git 文件系统（基于文件命名与测试文件，中等证据）。另需注意 `README.md` 只说源码在 `letta-code`，未承诺 V1 服务器 API 的兼容性，迁移项目需自行评估。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空
- 检索来源: 候选来自 `web_search`「long-term memory LLM agent open source」与「Benchmarking AI Agent Memory: Is a Filesystem All You Need?」（letta.com 博文，仅作为线索，**未读该博文内容**）；事实全部来自 GitHub API 文件树与源码原文

### [O-04] akitaonrails/ai-memory ★ 本轨道对本课题最直接的正面证据
- 轨道 / 类型: 开源 / 记忆服务（Rust workspace，面向编码 agent CLI 的长期记忆）
- 许可: MIT（API 返回 `license.spdx_id = "MIT"`；`Cargo.toml` 的 `[workspace.package]` 亦声明 `license = "MIT"`，版本 `2.4.1`，`edition = "2024"`，`rust-version = "1.95"`）
- 本次检查版本: 默认分支 `main`，`pushed_at = 2026-09-27T16:47:59Z`（检查前一日）；**未取到具体 commit 短哈希**（未调用 `/commits`，配额优先给了文件阅读）。检查方式: **API 路线**（元数据 + `ghtree` 完整递归文件树 877 路径 + `ghfile` 读 `Cargo.toml` 与 `docs/vector-backend-policy.md` 原文）
- 链接: https://github.com/akitaonrails/ai-memory
- 访问情况: 2026-09-28 实际读了：仓库元数据（stars 8,496 / MIT / Rust / size 19,706 KB / 非 archived）、**877 个路径的完整文件树（未截断）**、工作区 `Cargo.toml` 原文（读了 `[workspace]`、`default-members`、`[workspace.package]`、依赖段开头）、`docs/vector-backend-policy.md` **全文（约 75 行）**。**未读**：`crates/ai-memory-store/src/fts_query.rs`、`retrieval_tuning.rs`、`decay.rs`、`belief.rs`、`reader.rs`/`writer.rs`、各 migration SQL 原文、`docs/benchmarks/longmemeval-s-2026-09-01-fts.md`、`docs/local-embeddings.md`。因此**下文凡涉及具体 SQL/权重取值的部分均为「未读代码」，只有策略文档明写的部分才算已读。**
- 定位与规模: 自称「Solution for long term memory for agent coding CLIs and to facilitate handoff between different agent vendors」。Rust 工作区含 11 个 crate：`ai-memory-core`、`ai-memory-store`、`ai-memory-wiki`、`ai-memory-mcp`、`ai-memory-hooks`、`ai-memory-llm`、`ai-memory-consolidate`、`ai-memory-web`、`ai-memory-cli`、`ai-memory-workstream`、`ai-memory-test-support`（另有 `evals` 成员）。**存储后端是 SQLite + git 版本化的 markdown wiki**：`ai-memory-store/migrations/` 下有 `V04__embeddings.sql`、`V07__observations_fts_and_link_index.sql`、`V12__fts_remove_diacritics.sql`、`V17__pages_fts_index_path.sql`、`V53__page_embed_failures.sql`、`V61__page_abstract_embeddings.sql` 等（**文件存在由文件树证明；SQL 内容未读**）。
- 关键实现事实:
  - **这是「零专用向量库」的显式工程政策，而且写了触发条件**。`docs/vector-backend-policy.md` 原文（我读到全文）：
    - 「ai-memory currently stores embeddings as packed vectors in **SQLite** and does **brute-force cosine** over latest pages at query time. `sqlite-vec` is deferred intentionally, not rejected.」
    - 「The expected corpus is usually **hundreds to low-thousands** of latest wiki pages per project. At that size, brute-force cosine is simple, inspectable, and fast enough, especially because vector retrieval is only one signal in the query path.」
    - **检索路径的完整描述（原文）**：「`memory_query` already combines **FTS5, lexical entity matching, graph-neighbor expansion, optional vector RRF, and raw observation fallback**. Each stream contributes through the same bounded candidate window, then a **page-authority adjustment** runs after fusion, so semantic similarity cannot by itself declare a session page more canonical than a maintained decision.」
    - **拒绝引入 sqlite-vec 的理由是运维面而非性能**：「Adding `sqlite-vec` would add operational surface before it has proven value: Extension loading must work consistently on every SQLite connection / Docker-static-link packaging must stay reliable / Startup diagnostics need to distinguish extension-load failures from embedding provider·model·dim drift / Derived vector tables need safe rebuild-backfill paths / Prior-art projects hit real bugs around native vector dependencies, extension loading, and silent embedding skips.」
    - **加向量索引的具体触发阈值（原文列举）**：每项目最新嵌入页数**经常超过约 5k–10k**；`memory_query` p95 在本地**超过约 150–250ms**（且 FTS/graph 路径已优化过）；剖面显示查询期点积占用可观 CPU；**真实检索评测显示向量相比 FTS5+实体+图 有实质召回提升，例如 +5–10% recall@5**；以及迁移必须能从现有 `page_embeddings` 回填而不重置用户数据。
    - 「**Non-Criteria**: Do not add `sqlite-vec` just because vector databases are conventional, or because it feels architecturally cleaner. Without measured latency or recall pressure, the extra dependency and repair surface are not worth it.」
  - **markdown 是唯一真相源、索引可重建**：「regular SQLite rows keep the vector contract simple: **markdown is source of truth**, `page_embeddings` is durable derived data, and status can report missing embeddings or provider/model/dim heterogeneity without a second index format.」迁移要求亦写明「The derived vector index can be dropped and rebuilt from markdown + `page_embeddings`; **repair must never delete source wiki files**」。
  - **检索精度治理有专项代码文件**（文件树证明存在，内容未读）：`crates/ai-memory-store/src/` 下同时存在 `fts_query.rs`、`retrieval_tuning.rs`、`scope.rs`、`decay.rs`、`belief.rs`、`auto_improve.rs`、`maintenance.rs`、`session_consolidation.rs`；CLI 侧有 `reindex.rs`、`restore.rs`、`search.rs`、`embed.rs`。另有测试 `crates/ai-memory-store/tests/suite/fts_drift_status.rs`（FTS 漂移状态）。**「检索参数可调」（retrieval_tuning）与「衰减」（decay）「信念修正」（belief）各有独立模块，是「检索精度必须治理」这一判断在工程分工上的体现——推断基于文件名，未读实现。**
  - 与嵌入解耦的设计：`ai-memory-consolidate/src/embed.rs` 与 `crates/ai-memory-llm/src/embedding.rs` 分离，测试含 `embed_backfill.rs`、`local_embeddings.rs`、`openai_compat_embedder.rs`、`copilot_embedder.rs`；`docs/local-embeddings.md` 存在——即**嵌入是可替换、可回填、可失败的派生数据**，不是主存储。`migrations/V53__page_embed_failures.sql` 专门建表记录嵌入失败，进一步印证「嵌入可缺省」的定位。
- 维护与采纳信号: 最后推送 2026-09-27（检查前一日，活跃）；`Cargo.toml` 版本 2.4.1，crate 间有显式版本号与 `test-support` 共享测试 crate，说明有发布节奏；工作区注释提到 CI、pre-push 钩子与 `cargo tf` 命令（读到原文注释）；`evals` 是独立的 A/B 评测 harness（注释：「Live A/B harness — not part of the shipped binary, but in the workspace so it shares deps + builds」）；`docs/benchmarks/` 下留有带日期的基准记录（`longmemeval-s-2026-09-01-fts.md`，**文件名与存在已确认，内容未读**）；测试目录成体系（`tests/suite/` 下有 `embeddings.rs`、`local_embeddings.rs`、`embed_backfill.rs`、`fts_drift_status.rs`、`admin_status_search.rs` 等）。stars 8,496（弱信号，但在本账本中仅次于 mem0/Graphiti）。
- 与对照基准的关系: **这是本账本中与用户对照基准形态最接近、且把「为什么现阶段不上向量库」写成可执行判据的项目**：同样是「结构化文件 + 符号检索 + 轻量关系」，差别在于 ai-memory 仍保留**可选**的向量通道（作为 RRF 的一路信号）并把嵌入存进 SQLite 普通行；对照基准则连嵌入都不生成。它给出的可迁移结论是：**把向量当作「可随时关闭的一路信号」而不是「架构地基」是可行的**，且「什么时候该升级」可以写成可测量的触发条件（页数 5k–10k / p95 150–250ms / recall@5 +5–10%），而不是凭架构美学决定。对照基准的规模（数十个记忆单元）比它的触发下限还低 2–3 个数量级。
- 疑点·局限: 政策文档的措辞「deferred intentionally, not rejected」表明作者**不否认向量最终会来**，只是要等测量压力——引用时不应把它读成「向量无用」。文档中「graph-neighbor expansion」的图结构实现细节我未读代码，**不能断言它是真图存储还是 SQLite 里的邻接索引**（推断：`V07__observations_fts_and_link_index.sql` 的文件名暗示是「链接索引」表，但**这是推断（未读代码）**）。同样，「page-authority adjustment」「bounded candidate window」的具体权重与窗口大小未读，属推断（未读代码）。`docs/benchmarks/longmemeval-s-2026-09-01-fts.md` 这份 FTS-only 的 LongMemEval-S 基准记录我**没有读**，因此**不能引用其数字**——但它的存在本身说明该项目在自己的仓库里跑过「纯 FTS 对比」的评测，是后续可追的线索。stars 8,496 无一号厂商背书，采用规模需另找证据。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空
- 检索来源: `web_search`「agent memory sqlite no vector database simple github」/「mcp memory server knowledge graph sqlite open source」；事实来自 GitHub API 文件树 + `Cargo.toml` + `docs/vector-backend-policy.md` 原文

### [O-05] snap-research/locomo（ACL 2024 基准参考实现）
- 轨道 / 类型: 开源 / 评测基准（数据 + 评测脚本）
- 许可: 仓库树含 `LICENSE.txt`（**内容未读**，故不声明具体许可类型；README 未提许可）。检查方式: **API 路线**（`ghtree`）
- 本次检查版本: 默认分支 `main`；**未取 commit 哈希与最后提交时间**（配额优先给了文件阅读）。检查方式: **API 路线**（文件树 + `ghfile` 读 `task_eval/evaluation.py` 全文 293 行）
- 链接: https://github.com/snap-research/locomo
- 访问情况: 2026-09-28 实际读了：**完整递归文件树**（含 `data/locomo10.json`、`data/msc_personas_all.json`、`generative_agents/`、`prompt_examples/`、`scripts/`、`task_eval/`、`requirements.txt`、`LICENSE.txt`），以及 `task_eval/evaluation.py` **全文 293 行**（读了顶层定义列表、第 70–145 行的归一化与 F1/BERTScore 实现、第 186–243 行的 `eval_question_answering`）。**未读**：`task_eval/evaluate_qa.py`、`task_eval/evaluation_stats.py`、`scripts/*.sh`、`generative_agents/generate_conversations.py`、`locomo10.json` 数据本体。**未通过网页 README 获取信息**（README 抓取失败，但代码已直读，不影响结论）。
- 定位与规模: ACL 2024 论文「Evaluating Very Long-Term Conversational Memory of LLM Agents」的官方数据与代码仓；论文 arXiv:2410.10813（由 `web_search` 返回的 BibTeX 确认标题/作者/年份，**论文正文未读**）。数据为多会话长对话（`locomo10.json`，10 段对话），另有 persona、多模态对话、因果事件图谱与事实生成的 prompt 样例目录。
- 关键实现事实（**判分口径是本条目对课题的核心贡献**）:
  - **LoCoMo 的 QA 判分是确定性指标，不是 LLM-as-judge。** 我读完 `evaluation.py`，它只依赖 `nltk.stem.PorterStemmer`、`regex`、`string`、`collections.Counter`、`numpy`，**全文没有任何 LLM/API 调用**。顶层定义依次为：`LENGTH_THRESHOLD = 5`、`SimpleTokenizer`、`check_answer`、`has_answer`、`normalize_answer`、`exact_match_score`、`bert_score`、`ems`、`f1_score`、`f1`、`rougel_score`、`rl`、三个任务级函数 `eval_recall` / `eval_question_answering` / `eval_fact_checking` / `eval_dialogue_system`。
  - `normalize_answer(s)` = 去逗号 → 正则删除 `\b(a|an|the|and)\b`（**注意：把 `and` 也当停用词删掉，且代码里注释掉的旧版只删 `a|an|the`，现行版本多删了 `and`**）→ 空白折叠 → 去 `string.punctuation` 全部标点 → 小写。
  - `exact_match_score` 是**集合相等**而非字符串相等：`set(prediction.split()) == set(ground_truth.split())`（第 101 行；上一行的字符串相等版本被注释掉）。即词序不计。
  - `f1_score` 是 **token 级词袋 F1**：对双方 `normalize_answer` 后按 `PorterStemmer().stem` 逐词词干化，`Counter` 取交集计 `num_same`，再算 precision/recall/F1（第 126–138 行；`return recall` 被注释掉）。**空答案边界**：`if num_same == 0: return 0`，而 `len(prediction_tokens)` 为 0 时不会除零崩溃（因为 num_same 也为 0 已提前返回）。
  - `f1(prediction, ground_truth)` 处理多答案：把预测与真值**按逗号切分**，对每个真值取与任一预测的最大 `f1_score`，再取 `np.mean`（第 141–145 行）。这是**多跳问题的部分信用**机制。
  - `eval_question_answering(qas, eval_key='prediction', metric='f1')` 的核心分支（第 189–241 行）：`category == 3` 时真值**只取分号前的第一段**（`answer.split(';')[0].strip()`）；`category in [2,3,4]`（单跳/时序/开放域）用 `f1_score`；`category == 1`（多跳）用逗号切分的 `f1`；`category == 5`（对抗题）**只看输出里是否含 `'no information available'` 或 `'not mentioned'` 字样，含则 1 否则 0**；其余 category 直接 `raise ValueError`。返回值是三元组 `(all_ems, lens, all_recall)`。
  - **证据召回也是确定性的**：当样本带 `prediction_context` 字段且 `evidence` 非空时，取上下文条目、剥掉前缀 `S`、算 `recall_acc = 命中证据数 / 证据总数`；否则默认填 `1`（第 228–237 行）。注意**无上下文时填 1 而不是 0**，这是一个会抬高均值的口径细节。
- 维护与采纳信号: 仓库内含 `__pycache__` 下多处 `.cpython-39/310.pyc` 与旧文件并存的痕迹（说明长期在 Python 3.9/3.10 下跑过）；`scripts/` 提供 7 个评测脚本（gpt/claude/gemini/hf_llm/rag_gpts 各一 + 两个生成脚本）；`requirements.txt` 存在。该基准被 mem0 等厂商当作对外报数口径（见 [O-07]、[O-08]），采用面广。
- 与对照基准的关系: LoCoMo 证明了**一个被广泛引用的记忆基准可以完全用确定性指标评测**——这直接支持「评测不必依赖 LLM-as-judge」的路线选择。同时它的指标设计给出两个可迁移的具体做法：**多真值按逗号切分做部分信用**、**对抗题用固定短语做确定性判定**。对安全告警案例复用的场景，这比 LLM 打分更容易做回归与版本对齐。样例中 `data/locomo10.json` 只有 10 段对话（README 与检索结果称约 300 题），说明**主流长记忆基准的绝对题目数并不大**——这与对照基准「约 22 个案例」在同一量级而非差几个数量级，是「数十条规模下简单方案够用」的一个可辩护论据。
- 疑点·局限: 该实现的 `f1_score` 是 **token 词袋 F1**，因此**答案啰嗦会被机械惩罚**（precision 分母变大），而答案越短越容易拿高分——**用这套指标比较不同系统时，输出长度与提示词风格会直接进入分数**，这是跨项目比数时必须声明的条件。`exact_match_score` 用集合相等则进一步弱化了词序信息。`bert_score` 依赖 `bert_score` 包与 `rescale_with_baseline=True`，**本项目实际是 BERTScore-F1**，但 `eval_question_answering` 默认走 F1 分支，BERT 与 ROUGE 是备选/辅助（`metric='f1'` 是默认参数）。`LICENSE.txt` 与 README 我未读，**许可类型待确认**。数据本体的构造细节（论文称由 generative agents 生成对话）我只看到目录与文件名，**未读 `generate_conversations.py`**，故不描述构造流程。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空
- 检索来源: `web_search`「long-term memory benchmark github LoCoMo evaluation script」

### [O-06] xiaowu0162/LongMemEval（ICLR 2025 基准参考实现）
- 轨道 / 类型: 开源 / 评测基准（数据 + 检索基线 + 生成 + 评测）
- 许可: 元数据**未取**（未调用 API 元数据端点）；故**不声明许可**。检查方式: **API 路线**（`ghfile` 读 README 与评测脚本）
- 本次检查版本: 默认分支 `main`；**未取 commit 哈希与最后提交时间**。检查方式: **API 路线**（`ghfile` 读 `README.md` 全文、`src/evaluation/evaluate_qa.py` 全文 134 行）
- 链接: https://github.com/xiaowu0162/LongMemEval ；论文 arXiv:2410.10813（ICLR 2025，README 徽章与 news 段确认）
- 访问情况: 2026-09-28 实际读了 `README.md` **全文**与 `src/evaluation/evaluate_qa.py` **全文 134 行**（含第 24–43 行的判分提示词模板、第 46–121 行的主流程、第 113–130 行的标注与聚合）。**未读**：`src/evaluation/print_qa_metrics.py`、`print_retrieval_metrics.py`、`src/retrieval/` 下的 BM25/contriever/stella/gte 实现、`src/index_expansion/temp_query_search_pruning.py`、`sample_haystack_and_timestamp.py`、数据集本体（在 HuggingFace，**本环境不可达**）。
- 定位与规模: README：「500 high quality questions to test five core long-term memory abilities: Information Extraction / Multi-Session Reasoning / Knowledge Updates / Temporal Reasoning / Abstention」。数据三个版本：`longmemeval_oracle.json`（只含证据会话）、`longmemeval_s_cleaned.json`（约 115k token / 约 40 个会话，适配 128k 上下文）、`longmemeval_m_cleaned.json`（每个历史约 500 个会话，**超出 128k 上下文，不能做 long-context 基线**）。每实例字段：`question_id`、`question_type`、`question`、`answer`、`question_date`、`haystack_session_ids`、`haystack_dates`、`haystack_sessions`、`answer_session_ids`；证据轮次带 `has_answer: true` 标记。
- 关键实现事实:
  - **判分口径是 LLM-as-judge，而且我读到了全部提示词模板**。`evaluate_qa.py` 用 `model_zoo` 指定 judge 模型（读到 `gpt-4o-mini → gpt-4o-mini-2024-07-18`、`gpt-4o → gpt-4o-2024-08-06`，均来自 openai），并对 `openai.RateLimitError` / `openai.APIError` 做指数退避重试。调用参数：`n=1`、`temperature=0`、**`max_tokens=10`**；判定为纯字符串包含：`label = 'yes' in eval_response.lower()`（第 113 行）——**只要 judge 输出里出现 "yes" 就算对**。
  - 分任务判定标准（第 24–43 行原文要点，**这是判断基准松紧的关键**）：单会话用户/助手/多会话任务用「answer yes if the response **contains** the correct answer…如果只包含所需信息的**子集**则 answer no」；`temporal-reasoning` 额外写「**do not penalize off-by-one errors** for the number of days… predicting 19 days when the answer is 18, the model's response is still correct」；`knowledge-update` 写「if the response contains some **previous information along with an updated answer**, the response should be considered as correct as long as the updated answer is the required answer」；`single-session-preference` 改用**评分量表（rubric）**且明确「The model **does not need to reflect all the points** in the rubric」；abstention（`_abs` 后缀）用「answer yes if the model correctly identifies the question as **unanswerable**」。
  - **同时提供确定性侧指标**：README 说明 `has_answer` 标记用于 **turn-level memory recall accuracy**，`answer_session_ids` 用于 **session-level memory recall accuracy**；`print_retrieval_metrics.py` 打印检索指标。即该基准是**「检索用确定性指标 + 生成用 LLM judge」的双轨**。
  - **评测与检索是分离的两条命令线**：`run_retrieval.sh IN_FILE RETRIEVER GRANULARITY` 支持 `flat-bm25`、`flat-contriever`、`flat-stella`（Stella V5 1.5B）、`flat-gte`（gte-Qwen2-7B-instruct），粒度支持 `turn` 或 `session`；**BM25 是一等公民基线**，与稠密检索并列对比。`print_retrieval_metrics.py log_file` 单独打印检索指标。
  - **有明确的检索精度治理手段，且不止一个**：(1) **Key Expansion** 支持 5 种扩展类型 `session-summ` / `session-keyphrase` / `session-userfact` / `turn-keyphrase` / `turn-userfact`，以及三种注入方式 `separate`（新增键值对）/ `merge`（与原键合并）/ `replace`（替换原键）——即**在索引侧扩充键，而不是改相似度函数**；(2) **Time-Aware Query Expansion**：从会话抽取带时间戳的事件，由查询推断时间范围，**用时间范围裁剪检索空间**（`temp_query_search_pruning.py`，论文用 `session` 粒度）；(3) 检索（不是生成）评测**跳过 30 道 abstention 题**，因为它们「generally refer to non-existing events and do not have a ground truth answer location」。
  - 可扩展性设计：README 提供 `sample_haystack_and_timestamp.py task n_questions min_n_haystack_filler max_n_haystack_filler enforce_json_length` 以**任意加长历史**（`longmemeval_s` 用 80 个会话、115000 token 上限；`longmemeval_m` 用 500 个会话且不设长度上限），并给出数据内任务名与论文任务名映射表（如 `single_hop → single-session-user`、`implicit_preference_v2 → single-session-preference`、`knowledge_update → knowledge-update`）。
  - News 段记载：**2025/09 清理了历史会话以减少对答案正确性的干扰**（新版数据在 HuggingFace `longmemeval-cleaned`，含变更日志），**2026/05 发布 LongMemEval-V2**（agentic context 下的长期记忆，仓库 `xiaowu0162/LongMemEval-V2`）。
- 维护与采纳信号: 有 ICLR 2025 接收与官方数据清理公告（说明维护方在乎标注质量并公开变更日志）；评测脚本提供 `requirements-lite.txt`（只跑评测）与 `requirements-full.txt`（含 memory systems 实验，torch 2.3.1 + CUDA 12.1）两档环境，降低复现门槛；MemoryAgentBench **直接复制了它的判分提示词**（见 [O-09]），是本账本中可交叉印证的采用信号。
- 与对照基准的关系: LongMemEval 的**检索侧**证据对零向量路线非常有利：它把 **BM25 与稠密检索并列为 `flat-*` 基线**，并证明在**索引侧做关键短语/用户事实扩展**与**在查询侧做时间范围裁剪**这两种**符号手段**是可发表的检索改进方向。它的**生成侧**则走了 LLM judge，与本课题对照基准的确定性符号打分形成路线分歧——但注意它**同时保留了 turn/session 级的确定性 recall 指标**，说明「确定性召回 + LLM 判答」的混合口径是被接受的折中。基准规模（S 版 40 会话 / M 版 500 会话）远大于对照基准（22 案例），因此它的结论**不能直接外推到数十条规模**。
- 疑点·局限: **LLM-as-judge 的口径宽松程度必须随分数一起引用**：`'yes' in eval_response.lower()` 的字符串包含判定 + 「answer yes if the response **contains** the correct answer」+ temporal 题的 off-by-one 豁免 + knowledge-update 允许同时含旧信息 + preference 题「不必覆盖 rubric 全部要点」——这些规则叠加后，**同一系统换 judge 模型（gpt-4o 与 gpt-4o-mini 的别名分别绑定 2024-08-06 与 2024-07-18 快照）或换本地 vLLM judge 都可能显著改变绝对分**。README 亦支持用本地 vLLM 模拟 OpenAI 接口当 judge（`openai_api_base = "http://localhost:8001/v1"`、`api_key = "EMPTY"`），**跨论文引用 LongMemEval 绝对分时若未注明 judge 模型即不可比**。另外我对数据集文件的**实际构造质量未做核对**（数据在 HuggingFace，本环境不可达），仅知 2025/09 有过一次清理。本条目**未取许可与 commit 哈希**，属信息缺口。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空
- 检索来源: `web_search`「LongMemEval benchmark code github」/「agent memory evaluation harness code MemoryAgentBench」

### [O-07] HUST-AI-HYZ/MemoryAgentBench
- 轨道 / 类型: 开源 / 评测基准（多方法对照框架）
- 许可: 元数据**未取**，故**不声明许可**。检查方式: **API 路线**（`ghtree` + `ghfile`）
- 本次检查版本: 默认分支 `main`；**未取 commit 哈希与最后提交时间**。检查方式: **API 路线**（完整文件树 1355 路径 + 读 `llm_based_eval/longmem_qa_evaluate.py` 全文 201 行、`utils/eval_other_utils.py` 的顶层定义列表）
- 链接: https://github.com/HUST-AI-HYZ/MemoryAgentBench ；论文 arXiv:2507.05257（由 `web_search` 返回，**正文未读**）
- 访问情况: 2026-09-28 实际读了：**完整文件树（1355 路径）**、`llm_based_eval/longmem_qa_evaluate.py` **全文 201 行**、`utils/eval_other_utils.py` 的**顶层函数签名列表**（该文件已下载，读了 `Select-String '^def '` 的结果，**未逐行读实现**）。**未读**：`configs/agent_conf/**` 下各 baseline YAML 的字段取值、`methods/` 下 `agentmemory.py` / `graph_rag.py` / `self_rag` / `hipporag` 的实现、`utils/templates.py`、`bash_files/` 下各运行脚本、`lettra/`（原文拼写）与 `mem0/` 适配目录的实际内容。
- 定位与规模: 面向「增量多轮交互」的记忆 agent 基准；README（由 `web_search` 摘要）命令形如 `bash bash_files/eniac/run_memagent_rag_agents_chunksize.sh`，含分块大小的消融实验。
- 关键实现事实:
  - **判分口径是「LLM-as-judge 为主 + 确定性指标为辅」的混合，且 LLM 侧直接沿用 LongMemEval**。我读的 `llm_based_eval/longmem_qa_evaluate.py` 第 20–43 行的 `get_anscheck_prompt(task, question, answer, response, abstention=False)` 与 [O-06] 的 `evaluate_qa.py` 第 24–43 行**逐字相同**（单会话/多会话模板、temporal 的 off-by-one 豁免、knowledge-update 的允许旧信息、preference 的 rubric 宽松口径、abstention 模板全部一致）；调用参数也是 `n=1`、`temperature=0`、`max_tokens=10`，判定同样是 `label = 'yes' in eval_response.lower()`（第 168 行），聚合同样为 `np.mean` 的 Accuracy（第 187、196 行）。即**两个基准的软判分是一个共同谱系，不是独立证据**——引用时不可当作两处相互印证。
  - **确定性侧确实存在**：`utils/eval_other_utils.py` 定义了 `normalize_answer`（第 32 行）、`f1_score`（第 51 行）、`drqa_exact_match_score`（第 91 行）、**`substring_exact_match_score`（第 105 行，文档串明写「Check if ground truth is a substring of the prediction after normalization」）**、`drqa_metric_max_over_ground_truths`（第 119 行）、`parse_output`（第 144 行，带 `answer_prefix="Answer:"`）。**注意 `substring_exact_match_score` 的包含方向是「真值是预测的子串」，与常见做法同向但比 token-F1 更宽松**（越长的回答越容易命中）。
  - **它是唯一把多种记忆方法放在同一 harness 里对照的基准仓**：`methods/` 下有 `agentmemory.py`、`embedding_retriever.py`、`graph_rag.py`、`self_rag`（由 configs 印证）、以及 vendored 的 `hipporag/`（含 `embedding_model/` 下 `Contriever.py`、`GritLM.py`、`NVEmbedV2.py`、`OpenAIEmbedding.py` 与 `embedding_store.py`）。`configs/agent_conf/RAG_Agents/` 下按模型分目录（`gpt-4.1-mini/`、`gpt-4o-mini/`…），每个目录内并列多种基线 YAML：`Agentic_memory_gpt-4o-mini-letta.yaml`、`Agentic_memory_gpt-4o-mini-letta_api.yaml`、`Agentic_memory_gpt-4o-mini-self_rag.yaml`、`Embedding_rag_gpt-4.1-mini-text_embedding_3_small.yaml`、`Structure_rag_gpt-4.1-mini-graph-rag.yaml`、`AgentMemory_gpt-4o-mini.yaml`；另有 `Long_Context_Agents/` 下 6 个模型的长上下文配置。**即基准把「嵌入 RAG（text-embedding-3-small）」「GraphRAG 结构化 RAG」「Letta 式 agentic memory」「Self-RAG」「长上下文直灌」放在同一评测口径下对比**——这正是课题需要的「做法对照表」的代码侧实现。
  - 检索与评测分离的痕迹：`utils/eval_data_utils.py`、`utils/eval_other_utils.py`、`utils/templates.py` 三件套，加上 `conversation_creator.py`、`initialization.py`、`main.py`、`agent.py` 在根目录，说明数据构造（`conversation_creator.py`）与运行（`agent.py`/`main.py`）与判分（utils/ + llm_based_eval/）分层。`methods/hipporag/` 是完整 vendored 依赖（含 `embedding_store.py`），属于第三方方法的整体内嵌。
- 维护与采纳信号: 文件树含 `bash_files/eniac/` 等按数据集/方法组织的运行脚本，`configs/` 按模型×方法二维展开，说明有多人协作的评测组织；vendored `hipporag` 与 `letta`/`mem0` 适配目录表明跟进主流记忆产品。stars/许可/最后提交**未取**，属信息缺口。
- 与对照基准的关系: 该基准给出的最有价值的结构性事实是：**在它的配置空间里，「嵌入 RAG」「GraphRAG」「长上下文」是并列的基线，而不是逐级递进的必需组件**——存在 `Embedding_rag_..._text_embedding_3_small.yaml` 与 `Structure_rag_..._graph-rag.yaml` 并列的写法，说明作者认为这些是可自由选择的路线，而非「不上向量就不行」。对课题的直接用法是：把它当作**可比口径的基线清单来源**，其 YAML 字段就是我方复现对照实验时应逐项记录的条件（模型、检索器、粒度、分块大小）。
- 疑点·局限: 我**没有读任何 YAML 的实际字段值**，因此「各方法的默认检索路径与参数」在本条目中属**未确认**；`methods/` 下各实现（尤其中文课题关心的 `agentmemory.py`、`graph_rag.py`）的建边方式是机械规则还是 LLM 抽取，**本次未读代码，不做断言**。判分提示词与 LongMemEval 逐字相同这一点意味着：**若把 MAB 与 LongMemEval 的分数并列做论据，会重复计入同一个软判分口径**。`lettra` 这一目录名的拼写（疑似 `letta` 笔误）我只在文件树中看到，**未验证其内容**。许可与 commit 未取。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空
- 检索来源: `web_search`「agent memory evaluation harness code MemoryAgentBench」

### [O-08] mem0ai/memory-benchmarks（厂商自建基准harness，与 [O-02] 配套）
- 轨道 / 类型: 开源 / 评测基准（工具 + 已发布结果 JSON）
- 许可: 仓库树含 `LICENSE`（size 10758；**内容未读**，故不声明具体许可）。检查方式: **API 路线**（`ghtree` + `ghfile` + `/commits`）
- 本次检查版本: commit `4b61c5d31b9c`（完整树 SHA `4b61c5d31b9c668a12b4f5e78064248a02c82d2b`，2026-05-13T20:26:23Z；这是仓库最后一次提交，其 message 见下）。检查方式: **API 路线**
- 链接: https://github.com/mem0ai/memory-benchmarks
- 访问情况: 2026-09-28 实际读了：**完整递归文件树（99 路径，未截断）**、最新 commit JSON、`benchmarks/common/metrics.py` 全文 205 行（仅确认顶层定义）、`benchmarks/locomo/run.py`（981 行，读了头部 docstring 与第 385–484 行的 search+answer+judge 主循环）、`benchmarks/locomo/prompts.py`（322 行，读了第 203–222 行的 `JUDGE_SYSTEM_PROMPT` 与 `_JUDGE_TEMPLATE` 规则 1–2）。**未读**：`results/` 下任何结果 JSON 的数值、`benchmarks/longmemeval/run.py`、`benchmarks/beam/`、`benchmarks/common/mem0_client.py`、`src/` 下的 Next.js 看板代码、`README.md` 全文。
- 定位与规模: mem0 官方开源的评测框架，README（由 `web_search` 摘要）列出三个基准：**LOCOMO**（10 段多会话对话、约 300 题，测事实回忆/时序推理/多跳推理）、**LongMemEval**（500 题 6 类型）、**BEAM**（可配置规模，如 `--chat-sizes 100K`）。运行入口 `python -m benchmarks.locomo.run --project-name ... --backend cloud|oss`；`--all-questions` 控制是否跑满。
- 关键实现事实:
  - **判分是「自建 LLM judge + CORRECT/WRONG 结构化输出」，与 LoCoMo 官方的确定性 F1 不是同一口径**。`benchmarks/locomo/run.py` 头部 docstring 明写流程「Ingest → Search → Answer → **Judge** … Compute metrics (by category, by cutoff)」，并在第 476–484 行用 `judge_llm.generate_structured(...)` 取结构化结果，判 `correct = label_val == "CORRECT"`（解析失败则 `correct = False`）。`prompts.py` 的 `JUDGE_SYSTEM_PROMPT` 原文仅一句：「You are evaluating conversational AI memory recall. Return JSON only with the format requested.」；第 7 行注释自述口径为「methodology: **binary LLM judge (CORRECT/WRONG)** on categories 1-4」。
  - **判分规则的宽松点写在模板里，我读到了其中两条原文**：(规则 1) 「**PARTIAL CREDIT**: If the generated answer includes **AT LEAST ONE** correct item from the gold answer's list, mark CORRECT. Getting 1 out of 2, 2 out of 4, etc. is always acceptable.」；(规则 2) 「**PARAPHRASES COUNT**: Same concept in different words is CORRECT.」（举例 "Chocolate raspberry tart" = "chocolate cake with raspberries"）。另有 `_EVIDENCE_RULE`（规则 5）：「If the evidence corroborates the generated answer, mark CORRECT — **even when the generated answer diverges from the gold answer**. The gold answer may be wrong or oversimplified… **Use evidence only to ACCEPT answers, never to reject them more strictly**」。**规则 5 与非 evidence 版本之间用 `_EVIDENCE_WRONG_CLAUSE = " AND is not supported by evidence"` 拼接**（第 215 行）——即有无证据会改变判分口径。
  - **结果按「检索预算 cutoff」分档保存，这使头条数字有口径歧义**。`results/` 下同名不同档的文件成对出现：`locomo_results.json` 与 `locomo_top50_results.json`、`longmemeval_results.json` 与 `longmemeval_top50_results.json`、`beam_1m_results.json` 与 `beam_1m_top50_results.json`、`beam_10m_results.json` 与 `beam_10m_top50_results.json`。`run.py` 的 docstring 说明按「by cutoff」计算指标，第 447 行注释为「Answer + Judge at each cutoff」。最后一次 commit 的 message 进一步给出两档数字：「LongMemEval overall improves from 90.4% to **94.8% at top_50** and 93.4% to **94.4% at top_200**. LoCoMo overall improves to **92.5% at top_200** and **91.8% at top_50**, with the largest category gains in temporal (+6.7 pts) and multi-hop (+6.9 pts)」，并注明这批结果是「**v3 algorithm with temporal reasoning always-on**」。
  - **OSS 与 Platform 结果分开存放，这是少见的正面做法**：`results/oss/` 下有 `longmemeval_gpt5.json`、`longmemeval_gemma4_31b.json`、`longmemeval_llama4_maverick.json`、`longmemeval_parasail_120b.json`（均为 0.66–1.07 MB 的单次运行记录）；`results/platform/` 下有 platform 版与各自 top50 版。**即 README 头条的 92.5/94.4 出自 `results/platform/`，开源实现的结果另存于 `results/oss/`**——与 [O-02] README 中「Scores reflect Mem0's managed platform, which includes proprietary optimizations not available in the open-source SDK」的自我声明一致。
  - 工程形态：Python 包（`benchmarks/` 下 `beam/`、`common/`、`locomo/`、`longmemeval/` 四个子包，各带 `run.py` 与 `prompts.py`）+ 一个 Next.js 对比看板（`src/app/`、`src/components/comparison-view.tsx`、`src/lib/adapters.ts`）+ `docker/mem0/`（含 `Dockerfile`、`main.py`、`sagemaker_embedder.py`、`requirements.txt` —— **部署时仍需要嵌入后端**）；配置 `configs/openai.yaml`、`configs/azure-openai.yaml`、`configs/ollama.yaml` 三档。
- 维护与采纳信号: 最后提交 2026-05-13；commit message 由 Claude Sonnet 4.6 联合署名（`Co-authored-by: Claude Sonnet 4.6`）——即该批基准数字由 AI 辅助产出，**是引用其数字时应记录的一个流程细节，不构成否定**。结果 JSON 直接入库（含 1M/10M 规模的 BEAM 逐题记录）是较强的可复核姿态。许可未读。
- 与对照基准的关系: 该 harness 的价值在于**它把「检索预算」与「判分模型」变成可声明参数**，间接印证本课题「检索精度必须治理」的判断：同一算法在 top_50 与 top_200 下 LoCoMo 相差 0.7 分（91.8 vs 92.5），LongMemEval 相差 0.4 分（94.8 vs 94.4，**注意此处 top_50 反而更高**）——说明**扩大召回预算不等于提分**，与「噪声随召回放大」的直觉一致，但该对比来自厂商自有 harness、单次运行，**不足以作为独立结论**。
- 疑点·局限: **最需要向读者交代的是「同分数不同口径」的风险**：mem0 报的 LoCoMo 92.5 由 (a) 厂商自建 harness、(b) LLM judge 且带 PARTIAL CREDIT / PARAPHRASES COUNT / 证据可放宽三重宽松规则、(c) top_200 检索预算、(d) platform 版私有优化 四个条件共同决定；而 LoCoMo 官方脚本（[O-05]）是 token 词袋 F1 的确定性打分。两者**不可直接比较**，本条目据此**拒绝把 mem0 的数字与任何确定性口径的分数并列**。我**未读任何 results JSON 的数值**，上文的 90.4/94.8/93.4/94.4/92.5/91.8 全部来自 **commit message 的文本**，是厂商自述而非我核算的数字——引用时应标为「厂商 commit message 口径」。许可、`README.md` 全文、`longmemeval/run.py` 的 judge 是否同样宽松，均**未确认**。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空
- 检索来源: `web_search`「memory evaluation harness code」（返回 mem0ai/memory-benchmarks）；事实来自 GitHub API 文件树 + `/commits` + `run.py`/`prompts.py` 原文

### [O-09] agiresearch/A-mem（A-MEM: Agentic Memory for LLM Agents）
- 轨道 / 类型: 开源 / 记忆框架（学术论文配套实现）
- 许可: **MIT（由 README 末段文字确认：「This project is licensed under the MIT License. See LICENSE for details」；`LICENSE` 文件存在于文件树，但文件内容未读）**。API 元数据亦返回 `license.spdx_id = "MIT"`（两次独立路线一致）。
- 本次检查版本: 默认分支 `main`；`pushed_at = 2025-12-12T21:15:29Z`；**未取 commit 短哈希**。检查方式: **API 路线**（元数据 + `ghtree` + `ghfile` 读 `requirements.txt`；README 经 `ghapi:.../readme` 取到 base64 正文）
- 链接: https://github.com/agiresearch/A-mem
- 访问情况: 2026-09-28 实际读了：仓库元数据（stars 1,185 / MIT / Python / size 1,069 KB / 非 archived / open issues 20）、**完整文件树（仅 23 个路径，未截断）**、`requirements.txt` **全文**、`README.md` 正文（经 API 返回的 base64 解码）。**未读**：`agentic_memory/memory_system.py` 实现、`pyproject.toml`、`LICENSE` 文件正文、`Figure/` 下示意图。**关键实现事实中凡涉及「如何建边」的机制描述，均来自 README 文字，未读代码——已逐条标注。**
- 定位与规模: 自称「A novel agentic memory system for LLM agents that can dynamically organize memories in an agentic way」；论文 arXiv:2502.12110（README 引用，**正文未读**）。README 的 Key Features 列出：基于 Zettelkasten 原则的动态记忆组织、**通过 ChromaDB 做记忆的智能索引与链接**、带结构化属性的笔记生成、互联知识网络、持续记忆演化、agent 驱动的记忆管理决策。仓库自述结果：「Empirical experiments conducted on **six foundation models** demonstrate superior performance compared to existing SOTA baselines」（**未读论文，不引用其具体数字**）。README 另有明确提示：**要复现论文结果需另用 `WujiangXu/AgenticMemory` 仓**，本仓是「a memory system to facilitate agent construction」。
- 关键实现事实:
  - **依赖清单是我直接读到的原文（`requirements.txt` 全文 10 行）**：`sentence-transformers>=2.2.2`、`chromadb>=0.4.22`、`rank_bm25>=0.2.2`、`nltk>=3.8.1`、`transformers>=4.36.2`、`litellm>=1.16.11`、`numpy>=1.24.3`、`scikit-learn>=1.3.2`、`openai>=1.3.7`、`ollama>=0.1.0`。**结论（基于依赖文件，强证据）：默认存储/检索路径 = ChromaDB 向量库 + BM25 关键词，且自带本地嵌入模型（sentence-transformers / transformers）**。没有图数据库依赖（无 neo4j / kuzu / networkx），也没有 faiss/qdrant/milvus——**其「知识网络」不是图库实现的**。
  - **建边方式是 LLM 驱动的相似度检索，而非图库边**（**此条来自 README，未读代码**）：README「How It Works」写新记忆加入时依次为「1. Generates comprehensive notes with structured attributes 2. Creates contextual descriptions and tags 3. **Analyzes historical memories for relevant connections** 4. **Establishes meaningful links based on similarities** 5. Enables dynamic memory evolution and updates」。Memory Evolution 段进一步写「The system automatically evolves memories by: **1. Finding semantic relationships using ChromaDB** 2. Updating metadata and context 3. **Creating connections between related memories**」，并强调「This happens **automatically** when adding or updating memories!」——**即无人工确认闸门，建边与演化全自动**。
  - **检索与写入 API 的形态**（README 代码示例原文）：`AgenticMemorySystem(model_name='all-MiniLM-L6-v2', llm_backend='openai', llm_model='gpt-4o-mini')`；`add_note(content, tags=[...], category=..., timestamp='YYYYMMDDHHmm')`；`read(memory_id)` 返回带 `content` / `tags` / `context` / `keywords` 的结构化对象；`search_agentic(query, k=5)`；`update(memory_id, content=...)`；`delete(memory_id)`。**注意 `timestamp` 格式为 `YYYYMMDDHHmm`（示例 `"202503021500"`），是写入时由调用方提供的属性，不是自动生成**。
  - **schema 是「结构化属性 + 自然语言正文」的混合体**：每条笔记有 content 正文，外加 tags（可自定义）、category、keywords（README 称「Automatic keyword extraction」）、context（自动生成）、timestamp。这回答 S1 的 schema 问题：**A-MEM 走的是「半结构化笔记」而非纯 blob**。
  - 去重/合并：README 的 Best Practices 建议「Review generated connections periodically」，暗示作者认可自动建边需要人工复核，**但代码里是否有去重或合并逻辑，我未读代码，未确认**。
- 维护与采纳信号: 最后推送 **2025-12-12**（距今约 9.5 个月，相对该领域已属停滞）；open issues 20；stars 1,185、forks 122（API 计数）；仓库体量小（1,069 KB，23 个路径）；无 CI workflow 出现在文件树中；依赖版本较旧（`chromadb>=0.4.22`、`litellm>=1.16.11`、`transformers>=4.36.2`）。**这些是「论文配套仓」的典型形态：实现完整度服务于论文复现，而非长期维护的产品。**
- 与对照基准的关系: A-MEM 是**「轻量关系层」的一个反例参照**：它想解决「记忆之间要有链接」这件事，但做法是**用向量相似度自动建边 + 全自动演化**，代价是引入 ChromaDB + 一份嵌入模型，且没有人工闸门。对照基准用「人工确认的一跳关系边」换取了边的高精度与可解释性，A-MEM 用相似度阈值换取了自动化——**两者都承认「关系层」是必要的，分歧只在于边从哪来**。这正好支持用户判断中「必须治理检索精度」的那一半：关系层的质量取决于建边判据，而 A-MEM 把判据交给了嵌入相似度。
- 疑点·局限: **本条目有明确的读取边界**：我读了依赖清单与 README，**没有读 `memory_system.py`**，所以「建边是相似度阈值还是 LLM 判定」「是否有去重/合并」属**推断（未读代码）**——README 说「Establishes meaningful links based on similarities」与「Finding semantic relationships using ChromaDB」，但**相似度阈值取值、是否二次 LLM 过滤均未确认**。README 的关键特征里同时写「Intelligent indexing and linking of memories via ChromaDB」和「Analysis of historical memories for relevant connections」，两者可能是同一件事的两种说法，也可能对应两段代码，**未读代码无法区分**。此外**论文结果需换仓复现**，本仓代码与论文实验代码不是同一份，**引用其 SOTA 声明时应指向 `WujiangXu/AgenticMemory` 而非本仓**。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空
- 检索来源: `web_search`「entity extraction memory pipeline open source」

### [O-10] topoteretes/cognee
- 轨道 / 类型: 开源 / 图记忆 + 评测框架（东欧团队，含自建 eval_framework）
- 许可: Apache-2.0（API 返回 `license.spdx_id = "Apache-2.0"`；**未单独读 LICENSE 文件正文**）
- 本次检查版本: 默认分支 `main`；`pushed_at = 2026-09-27T20:22:42Z`；**未取 commit 短哈希**。检查方式: **API 路线**（元数据 + `ghtree` 完整文件树 4660 路径 + `ghfile` 读 `cognee/base_config.py` 前 30 行）
- 链接: https://github.com/topoteretes/cognee
- 访问情况: 2026-09-28 实际读了：仓库元数据（stars 31,081 / Apache-2.0 / Python / size 256,978 KB / open issues 448 / 非 archived，topics 含 `graph-database`、`graph-rag`、`vector-database`、`agent-memory`）、**完整递归文件树（4660 路径，未截断）**、`cognee/base_config.py` **前 30 行**。**未读**：`cognee/infrastructure/databases/graph/config.py`、`.../vector/config.py`、`.../relational/config.py` 的**实际默认值**、`docker-compose.yml`、`pyproject.toml`、`cognee/eval_framework/**` 的判分实现、图抽取 pipeline 实现。**因此本条目对「默认存储后端与默认检索路径」只能给出「适配器体系存在」而非「默认值是什么」——按纪律标注为未确认。**
- 定位与规模: 自称「Cognee is the open-source AI memory platform for agents. Give your AI agents persistent long-term memory with small models for free」。规模在本账本中较大（4,660 个文件、约 257 MB 仓库）。**架构上明确是「三元存储适配器」结构**：文件树证明存在 `cognee/infrastructure/databases/graph/`（图库）、`cognee/infrastructure/databases/vector/`（向量库）、`cognee/infrastructure/databases/relational/`（关系库）、`cognee/infrastructure/databases/cache/`（缓存，含 `fscache/FsCacheAdapter.py`、`redis/RedisAdapter.py`、`sql/SqlCacheAdapter.py`、`tapes/TapesCacheAdapter.py` 四种适配器）。
  - `cognee/base_config.py` 的 `BaseConfig(BaseSettings)`（**读到原文**）给出三个本地目录默认值：`data_root_directory = get_absolute_path(".data_storage")`、`system_root_directory = get_absolute_path(".cognee_system")`、`cache_root_directory = get_absolute_path(".cognee_cache")`，日志默认 `~/.cognee/logs`。**即默认落盘位置是项目内点目录，而非外部服务**——但图/向量/关系适配器的**具体默认引擎取值我没读，属未确认**（推断：Cognee 文档通常以本地文件型图库 + 嵌入式向量库起步，但**这是推断（未读配置代码），不写入事实栏**）。
  - 另有 `cognee/infrastructure/databases/dataset_database_handler/`、`dataset_queue/`、`alembic/versions/` 下的 `create_principal_configuration_table`、`add_dataset_configuration_table` 等迁移——说明它自带关系库 schema 与多租户（principal）配置。
  - **自带完整评测框架 `cognee/eval_framework/`，是我在开源轨中见到结构最完整的评测实现之一**：含 `analysis/metrics_calculator.py`、`answer_generation/answer_generation_executor.py`、`corpus_builder/corpus_builder_executor.py`、`benchmark_adapters/`（`hotpot_qa_adapter.py`、`musique_adapter.py`、`twowikimultihop_adapter.py`、`base_benchmark_adapter.py`、`dummy_adapter.py`）。**多跳检索是它的基准取向**（HotpotQA / MuSiQue / 2WikiMultihop 三者都是多跳问答数据集）——即它把「图记忆」的收益押在**多跳推理**上。
  - **另有独立的 BEAM 评测子模块**：`cognee/eval_framework/beam/` 下有 `REPORT.md`、`local_ingest.py`、`run_sweep.py`、`sweep.py`、`eval/beam_eval_adapter.py`、`eval/aggregate_cross_run.py`、`eval/registry.py`、**`eval/metrics/beam_rubric.py`**、**`eval/metrics/kendall_tau.py`**。`beam_rubric.py`（评分量表）与 `kendall_tau.py`（秩相关系数，用于比较**排序**而非单一分数）的出现，说明该评测体系关心**排序质量与量表打分**，且 `run_sweep`/`sweep` 支持参数扫描式实验。**注意 BEAM 也是 mem0 使用的第三个基准（见 [O-08]），两个项目各自独立实现 BEAM 评测，是「同一基准多实现」的口径风险来源。**
  - `cognee/api/v1/config/` 与 `api/v1/settings/routers/` 表明配置可通过 API 在运行时读取/修改，即**存储后端是可被使用者替换的运行期配置**，而非编译期绑死。
- 维护与采纳信号: 最后推送 2026-09-27（检查前一日）；stars 31,081、forks 3,107、open issues 448；有 `has_wiki = true`、`has_discussions = true`；topics 覆盖 `good-first-issue`、`help-wanted`、`contributions-welcome`（对社区贡献开放）；含 `Dockerfile` 与 `docker-compose`（未读）；alembic 迁移数量多，说明 schema 迭代活跃。**未确认 CI workflow**（未筛 `^\.github/`）。
- 与对照基准的关系: Cognee 代表「**全都要**」路线：图库 + 向量库 + 关系库 + 缓存四类适配器并存，并把「多跳问答」当作主要收益场景。对本课题最有信息量的一点是**它把多跳基准（HotpotQA/MuSiQue/2WikiMultihop）作为图记忆的验证场地**——换句话说，**图记忆的可验证收益集中在多跳检索**，而安全告警的案例复用是否属多跳任务，是决定要不要上图库的关键问句（本账本只提供事实，不替主代理下判断）。其 `kendall_tau.py` 与 `beam_rubric.py` 提示评测还可以做成「排序相关性 + 量表」而非单一准确率，这是对照基准的确定性打分可以借鉴的扩展。
- 疑点·局限: **本条目最大的缺口是「默认值未确认」**：我确认了四类适配器目录存在、`base_config.py` 的三个本地目录默认值，但**没有读 `graph/config.py` 与 `vector/config.py`**，因此**不能声明 Cognee「默认用某个具体图库/向量库」**——这一点必须由主代理在引用前补齐，或标注为未确认。`eval_framework` 的判分口径（LLM-as-judge 还是确定性指标）我**只看到文件名（`beam_rubric.py` 暗示量表式、可能是 LLM 打分），未读实现，不做断言**。仓库 257 MB、4,660 文件，本环境无 clone 能力，故**不可能穷尽核对**，本条目是按目录结构定位关键文件的抽样，不代表已通读。许可只经 API 确认，未读 LICENSE 正文。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空
- 检索来源: 候选来自 `web_search`「agent memory graph open source」；事实来自 GitHub API 文件树 + `cognee/base_config.py` 原文

### [O-11] BAI-LAB/MemoryOS
- 轨道 / 类型: 开源 / 记忆框架（EMNLP 2025 Oral 配套）
- 许可: Apache-2.0（API 返回 `license.spdx_id = "Apache-2.0"`；未读 LICENSE 正文）
- 本次检查版本: 默认分支 `main`；`pushed_at = 2026-07-07T12:32:18Z`；**未取 commit 短哈希**。检查方式: **API 路线**（仅元数据端点）
- 链接: https://github.com/BAI-LAB/MemoryOS
- 访问情况: 2026-09-28 **仅读取了 GitHub API 的仓库元数据 JSON**（stars / license / pushed_at / archived / description / topics）。**未读文件树，未读 README，未读任何代码。** 因此本条目的「关键实现事实」一栏为空——按纪律不写任何实现断言。
- 定位与规模: 描述原文「[EMNLP 2025 Oral] MemoryOS is designed to provide a memory operating system for personalized AI agents」。stars 1,589、forks 164、open issues 22、size 30,015 KB、Python。topics 同时含 **`rag`、`retrieval-augmented-generation`、`long-term-memory`、`personalization`** ——即作者自我归类为 RAG 路线，**这是主题标签级证据，不是代码级证据**。
- 关键实现事实: **未获取（未读代码）**。可确认的只有：仓库存在、默认分支为 `main`、Apache-2.0、2026-07-07 有推送、未 archived、体量约 30 MB。**存储后端、默认检索路径、建边方式、去重与冲突策略均未确认。**
- 维护与采纳信号: 最后推送 2026-07-07（检查前约 2.7 个月）；有 EMNLP 2025 Oral 接收（venue 级信号，来自仓库描述，**未读论文**）；open issues 22；含 `has_wiki = true`。**未检查 CI/测试/依赖。**
- 与对照基准的关系: **无法评估**——需要读 `requirements.txt`/`pyproject.toml` 与检索实现后才能判断它是否依赖向量库。列出本条的目的是**如实标记覆盖缺口**：MemoryOS 是课题「候选项目方向」中明确点名的一项，本次因 API 配额优先分给了 [O-04] 与三条评测脚本，**只完成了存在性与元数据确认**。
- 疑点·局限: 本条**只有元数据，无实现证据**；任何关于「MemoryOS 用向量库」的说法在本次取证中**均无依据**。topics 里的 `rag` 标签**不足以**支撑「默认检索走向量」的结论（RAG 也可纯 BM25）。**后续若要采信，最低需要读 `requirements.txt` 或 `pyproject.toml` + 一条检索实现文件。**
- 评分: 留空（主代理统一评分）
- 引用位置: 留空
- 检索来源: `web_search`「agent memory graph open source」（候选方向由任务书点名）

### [O-12] n-r-w/knowledgegraph-mcp（轻量图记忆，SQLite 后端）
- 轨道 / 类型: 开源 / 图记忆（MCP server，轻量）
- 许可: MIT（API 返回 `license.spdx_id = "MIT"`）
- 本次检查版本: 默认分支 `main`；`pushed_at = 2025-11-10T16:37:58Z`；**未取 commit 短哈希**。检查方式: **API 路线**（仅元数据端点）
- 链接: https://github.com/n-r-w/knowledgegraph-mcp
- 访问情况: 2026-09-28 **仅读取了 GitHub API 的仓库元数据 JSON**。**未读文件树，未读 README，未读任何代码。**
- 定位与规模: 描述原文「MCP server for enabling persistent knowledge storage for Claude through a knowledge graph with **multiple storage backends and fuzzy search**」。stars **26**、forks 未记录、size **382 KB**、TypeScript、MIT、未 archived、最后推送 **2025-11-10**（约 10.5 个月前）。
- 关键实现事实: **未获取（未读代码）**。可确认的只有：这是一个 TypeScript 写的 MCP server、自述支持「多种存储后端」与「模糊搜索」、体量极小（382 KB）、MIT。**「多种存储后端」具体是哪些、「模糊搜索」是编辑距离还是 SQLite 的 LIKE/FTS 还是向量，均未确认。**
- 维护与采纳信号: stars 仅 26、最后推送 2025-11-10、体量 382 KB。**这是一条「小项目，采用信号极弱」的诚实记录**——它进入本账本只是因为课题要求覆盖「低依赖图记忆实现」这一形态，而它恰好是检索中出现的候选。**不应据其 star 数与宣传语推断可用性。**
- 与对照基准的关系: 形态上（MCP server + 知识图 + 模糊搜索 + 极小依赖）与对照基准的「轻量关系层」最接近，**因此在「是否存在零图库的图记忆实现」这一具体问句上是有意义的线索**；但本次**没有读代码**，所以它对课题的贡献**止步于「存在这样一个形态的项目」**，不能用于论证可行性。
- 疑点·局限: 全部实现性问题未确认。star 数过低（26）意味着**即使实现正确也缺乏采纳验证**。若要采信需先读文件树定位存储适配器与模糊搜索实现。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空
- 检索来源: `web_search`「mcp memory server knowledge graph sqlite open source」

### [O-13] HUST-AI-HYZ/MemoryAgentBench 中 vendored 的 `methods/hipporag`
- 轨道 / 类型: 开源 / 图记忆方法（第三方方法在 [O-07] 基准内的内嵌实现）
- 许可: **未取**（随宿主仓，宿主仓元数据未取）
- 本次检查版本: 随 [O-07] 的 `main` 分支文件树观察；**未读代码**
- 链接: https://github.com/HUST-AI-HYZ/MemoryAgentBench 路径 `methods/hipporag/`
- 访问情况: 2026-09-28 **仅在 [O-07] 的完整文件树中看到了路径清单**，未读任何 HippoRAG 源文件，未读其 README。
- 定位与规模: 文件树证明存在 `methods/hipporag/HippoRAG.py`、`methods/hipporag/__init__.py`、`methods/hipporag/embedding_store.py`、`methods/hipporag/evaluation/`，以及 `methods/hipporag/embedding_model/` 下的 `base.py`、`Contriever.py`、`GritLM.py`、`NVEmbedV2.py`、`OpenAIEmbedding.py`。即**该基准把 HippoRAG 连同其嵌入模型层一起内嵌**，并保留 `embedding_store.py` 作为独立的嵌入存储抽象。
- 关键实现事实: **未获取（未读代码）**。**唯一可陈述的事实是路径结构**：HippoRAG 在该基准内自带 4 种嵌入模型实现（Contriever / GritLM / NVEmbedV2 / OpenAI）与一个 `embedding_store.py`，说明其图检索以嵌入为前置。**建边机制、图存储介质（很可能是内存/文件而非图库）均未确认。**
- 维护与采纳信号: 未获取（未读元数据与提交）。
- 与对照基准的关系: 用于说明**「图记忆」在评测框架里的常见形态是「嵌入 + 图遍历」耦合**，而不是纯符号图。**本条目证据强度最低（仅路径级），主代理若不需凑条数可直接剔除，或在引用前补读 `embedding_store.py`。**
- 疑点·局限: 仅路径级证据，**不足以支撑任何实现性结论**。
- 评分: 留空（主代理统一评分）
- 引用位置: 留空
- 检索来源: 来自 [O-07] 文件树，非独立检索所得

---

## 覆盖缺口与未获取清单（供主代理判断）

**A. 尝试过但失败的检索通道**
- `git clone` / `git ls-remote` / `curl` / `Invoke-RestMethod`：本机无外网，全部连接超时，**未能获得任何本地仓库副本**，`evidence/repos/` 为空。
- `raw.githubusercontent.com` 经 `read_page` 的 local 引擎时好时坏（大文件超时），但经 firecrawl 引擎成功；**GitHub 网页版 `github.com` 未使用**（改用 `api.github.com`，更可靠）。
- HuggingFace 数据集（LongMemEval 数据本体、LongMemEval-S 的 `has_answer` 标注）**本环境不可达**，故未核对数据质量。
- `raw.githubusercontent.com` 单页约 50,000 字符截断，导致 `graphiti_core/search/search.py`、`edge_operations.py`、`mem0/memory/main.py`、`mem0/memory/notices.py` 均在尾部被截断（已在上文各条目中逐处标注截断位置）。

**B. 只拿到元数据、未读代码的项目（不可用于实现性断言）**
- `BAI-LAB/MemoryOS`（[O-11]）— 仅元数据。
- `n-r-w/knowledgegraph-mcp`（[O-12]）— 仅元数据。
- `HUST-AI-HYZ/MemoryAgentBench` 内嵌 `methods/hipporag`（[O-13]）— 仅路径。

**C. 探测返回 404、已排除的候选**
- `King-s-Knowledge/king`：API 返回 `404 Not Found`（该 owner/repo 组合不存在，或已改名/删除）。
- `agiresearch/OpenAI-Memory`：API 返回 `404 Not Found`。**注意**：任务书与既有材料中出现的「OpenAI-Memory」在 GitHub 上不以该 owner/repo 存在，主代理若在报告中使用此名，需另找准确仓库名。
- `BAI-LAB/MemoryScope`（`@master`）与 `King-s-Knowledge/memary`（`@main`）：`ghtree` 返回 0 路径（默认分支名猜测错误或仓库不存在），**未重试其它分支名**。

**D. 点名但本次未覆盖的候选**
- **memary、Second-Me、memobase、LangMem/LangGraph BaseStore**：任务书点名的候选方向，本次**未做任何探测**（API 配额优先分配给了代码级取证）。
- **Zep 本体**（`getzep/zep`，托管服务的开源部分）：本次只读了 `getzep/graphiti`（[O-01]），**未单独探测 Zep 仓库**。注意 Graphiti README 明确称 Zep 的 Context Graph Engine 为**专有（proprietary）**，故 Zep 的服务端实现不在开源轨可得范围内。
- **mem0 的 `mem0/configs/base.py`**（默认 vector store provider 取值）**未读**——这是 [O-02] 唯一的关键缺口。
- **Cognee 的 `graph/config.py` 与 `vector/config.py`**（默认图库/向量库取值）**未读**——这是 [O-10] 的关键缺口。
- **ai-memory 的 `docs/benchmarks/longmemeval-s-2026-09-01-fts.md`**（纯 FTS 的 LongMemEval-S 基准记录）与 `crates/ai-memory-store/src/fts_query.rs` / `retrieval_tuning.rs` **未读**——这是 [O-04] 最值得补的两处，**该文件的存在已由文件树确认，内容未读**。

**E. 本次未取的关键元数据（纪律上不可编造，故留空）**
- 各仓库的 **commit 短哈希**：仅 [O-01] Graphiti 取到（`6b4b56f`）与 [O-08] memory-benchmarks 取到（`4b61c5d`）；[O-02]、[O-03]（letta-code）、[O-04]–[O-07]、[O-09]–[O-13] 均**只有 `pushed_at` 或已发布的分支信息，没有 commit 哈希**。
- **LICENSE 正文**：所有条目的许可均来自 **GitHub API 的 `license.spdx_id` 字段**（[O-09] 另有 README 文字佐证），**没有一条是逐字读过 LICENSE 文件正文的**——任务书要求「读 LICENSE 文件确认」，本次因配额限制降级为 API 字段路线，**已在每条中标注**。
- **release 标签与 release 节奏**：本次**未取任何仓库的 `/releases`**，[O-04] 的版本号 2.4.1 来自 `Cargo.toml` 正文，其余仓库无版本信息。
- **issue/PR 历史**：任务书要求查「检索精度/噪声/规模」相关的 issue 讨论，**本次一条 issue 都未读**（配额优先给了源码与文件树）。这是**本账本最大的方法性缺口**：S8「有没有项目报告过规模上去以后精度退化」目前**只有 mem0 代码内的阈值常量（2000 条 / top_k 50 / 2 秒）与 ai-memory 的策略文档（5k–10k 页 / p95 150–250ms / recall@5 +5–10%）两条间接证据**，**没有任何一条来自真实用户报告的退化证据**。

**F. API 配额使用（最终）**
- 累计调用约 **46 次**，最终剩余 **14/60**。
- 阶段一（本机 shell 的 `Invoke-RestMethod` 失败后，改经 `read_page` 打 `api.github.com`，在拿到 `fetch.mjs` 之前）：约 10 次 —— Graphiti 元数据 / commits / tree、mem0 元数据、letta 元数据、cognee 元数据、A-mem 元数据、MemoryOS 元数据、2 个 404 探测（`King-s-Knowledge/king`、`agiresearch/OpenAI-Memory`）、GitHub `search/repositories` 1 次。
- 阶段二（改用 `assets/fetch.mjs` 直连 `api.github.com`）：起始 **48/60** → 期间 **21/60** → 结束 **14/60**，本阶段共消耗 **34 次**（含 3 次 `rate_limit` 自查）。
- **配额未耗尽**，但剩余 14 次不足以覆盖 D 段全部缺口（若只挑一处补，优先 [O-04] 的 `docs/benchmarks/longmemeval-s-2026-09-01-fts.md` 与 [O-02] 的 `mem0/configs/base.py`，各 1 次）。

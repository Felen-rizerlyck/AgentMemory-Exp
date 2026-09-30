# 案例记忆提取准则（攻击检测 Agent）

> 验证目标：安全检测 Agent 将经手的每个案例提取为**结构化实例记忆**，
> 存入本地记忆库，供后续遇到相似攻击时检索辅助分析。

## 一、提取准则（源自 Hermes 记忆机制）

1. **持久可复用，非流水账** —— 提取的是"可复用的分析知识"，不是原始日志的逐条转录。
2. **高信号、判别性** —— 记录能区分该攻击的特征（载荷签名、行为模式、技术手法），
   而非无关噪声字段。
3. **自包含** —— 每个案例条目独立可理解，不依赖其他条目或会话上下文。
4. **陈述式事实** —— 记录"该攻击是什么、如何判定、链如何串起"，而非给自己下指令。
5. **去重/合并** —— 新案例与已有记忆高度相似时，强化/更新既有条目，而非重复新建。
6. **可检索** —— 每个条目带明确的检索键，支持按攻击类型 / 技术 / 指标相似性召回。

## 二、案例记忆结构（schema）

| 字段 | 说明 |
|------|------|
| `id` | 案例编号（CASE-001…） |
| `source` | 日志来源：WAF / RASP / HIDS / DNS |
| `attack_type` | 攻击类型（SQL注入 / RCE / 目录穿越 / 暴力破解 / DNS隧道 / 钓鱼 等） |
| `kill_chain` | 攻击链阶段序列（侦察→初始访问→执行→横向移动…） |
| `mitre` | MITRE ATT&CK 技术编号（如 T1190） |
| `indicators` | 判别性指标：IP / 域名 / URL / UA / 载荷特征 |
| `signature` | 攻击指纹 —— 一段精简描述，用于相似性判断 |
| `reasoning` | 判定结论与攻击链推理（可复用的分析知识） |
| `retrieval_keys` | 检索键（用于相似案例匹配的标签） |
| `pattern_probes` | 结构模式探测正则（检索辅助：基础设施更名后仍可命中同类攻击，如 DGA 换域名） |

## 三、存储位置

- 案例记忆正文：`data/memory_store.json`
  - `cases`：案例实例（每轮分析后追加/合并）
  - `activity_patterns`：跨案例活动模式（**实验性子层**，观察级置信度，可整层移除而不影响案例主体）
- 本文件仅作准则说明，不写入真实 memories（验证工作，不落 Hermes 正式记忆）。

## 四、检索协议（每批日志的标准流程第一步）

每批新日志到达后：**先检索、再判断、后提取**。

1. **检索**：运行 `python src/retrieve.py --batch <日志文件>`（或单条 `python src/retrieve.py "日志行"`），
   对每条日志做双通道匹配：
   - 词面通道：案例 `retrieval_keys`(×3) / `mitre`(×2) / `indicators`(×2) / `signature`(×1)
   - 模式通道：案例 `pattern_probes` 正则结构探测（命中 ×4）
2. **判断**：分析结论对检索支撑显式标注 `[检索: CASE-xxx]`；无命中则标注【新案例】。
3. **提取**：新增案例（含 pattern_probes）或对相似案例合并强化。

## 五、pattern_probes 判别性准则（防 probe 过泛）

`pattern_probes` 权重 ×4（最高），过泛的 probe 会对无关行产生强分误命中（历史实例：CASE-013 `getRuntime().exec` 过泛命中 JSP webshell 负样本；CASE-005 `echo;id|;\s*(?:id|whoami|uname)\b` 的 `;id` 分支过泛命中任意 `;id` 探针）。设计 probe 必须遵守：

1. **锚定"特有结构"，不锚定"通用片段"**：
   - ✅ 特定技术指纹：`com\.tangosol\.coherence`、`spring\.cloud\.function\.routing-expression`、`__HALT_COMPILER`、`xp_dirtree`
   - ✅ 特定编码形态：`%%32%65`（双编码）、`rO0AB`（序列化魔数）
   - ✅ 特定完整路径结构：`cgi-bin/.*bin/sh`（完整路径，非片段）
   - ❌ 通用命令探针：`;id`、`cmd=id`、`whoami`、`id` 单独出现——这些放 `retrieval_keys` 词面通道（×3 低权重，弱档按噪声处理），不进 probe
   - ❌ 通用路径/词：`/etc/passwd`、`/bin/sh`、`process`、`select`

2. **每个 `|` 分支都要单独判别**：禁止"一个判别 + 一个通用"拼接；分支不过判别性检验的，拆掉。

3. **判别性检验（入库门禁）**：新增/修订 probe 必须——
   - 正向：命中该案例所有已知观测行（不丢召回）；
   - 反向：不命中负样本（eval 的 N-01~N-09）与通用样板行（`cat /etc/passwd` 类）；
   - 回归：`python eval/run_eval.py` + `python eval/run_recall_unseen.py`，确认负样本零扩展、NOVEL 行静默。

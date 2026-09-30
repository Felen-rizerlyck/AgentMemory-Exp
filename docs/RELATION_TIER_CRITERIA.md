# 案例关系档位判定准则（helpful / weak / unrelated / misleading）

> 定位：对应 `PENDING.md` §1.2「边判定方法论」——把 helpful / weak / unrelated 的判据书面化，避免每次裁定口径漂移。
> 状态：**DRAFT，待你复核**。本文件只提供判定口径，**不重裁现有 231 对**（现行 gold 矩阵冻结，见 `PENDING.md` 顶部声明）；落地方式为：给 38 条 `review=true` 提供统一口径、给未来新案例的新边提供裁定标准。
> 关联：`EVAL_PROTOCOL.md` §2.2/§2.3（qrels 与 gold 的原始定义）· `eval/relations_gold.json`（meta 的 tier_legend/type_legend）· `GRAPH_DECISION.md` §2.4（"边怎么产生"三步）。

---

## 一、总判定测试（所有裁定先问这一句）

> 对一对案例 (A, B)，问：**「分析 A 时，把 B 作为关联参考展示，能否实质增强 / 改变对 A 的判断？」**

- 能，且能指出**具体可引用的共享点** → `helpful`
- 不能增强，但存在可识别的表面关联 → `weak`
- 无任何共享技术 / 指标 / 阶段 → `unrelated`
- 表面相似但实质不同，引用会误导判断 → `misleading`

「实质增强」是唯一的分水岭；「有没有共同点」只是必要条件，不是充分条件。

---

## 二、四档判据

### 2.1 helpful —— 激活扩展（作为关联参考输出）

满足**任一条**即可，且共享点必须**具体、判别性**：

| # | 判据 | 正例（来自现有 gold） | 反例（不算数） |
|---|---|---|---|
| H1 | **shares_payload**：共享具体、判别性的载荷片段 / 特征值，可佐证工具链 / 攻击者复用 | `cmd=id`（006/016/022）、`echo;id`（005/017）、`rO0AB`（006/008）、`cmd=127.0.0.1;id` 模板（010/011）、`cmd_inject=#!//bin/bash`（014/015）、`cache_key=../../../tmp/<hex>` + `smuggle=GET / HTTP/1.1`（003/016） | 通用词 `id`/`select`/`process`/`base64`、单条 `/etc/passwd` 路径（见 §四） |
| H2 | **shares_infra**：共享精确 IOC（IP / 域名 / 证书等） | 当前无对（预留）；如两案例同解析 IP / 同 C2 域 | 仅同文档网段（203.0.113.x 等）不算 |
| H3 | **same_technique 且载体 / 机制同族**：同一具体缺陷类 / 引擎 / 向量，可互相印证（**不是** mitre 大类交集） | 表达式注入 Jinja2↔SpEL（008/013）；脚本 / 表达式引擎注入 SpEL↔Groovy（013/020）；SQL 注入认证绕过↔UNION 窃取（009/015）；Java 表达式引擎 MVEL↔SpEL（010/013） | 仅 `mitre∩={'T1190'}` 而技术栈不同（见 2.2 W1） |
| H4 | **same_phase 且同系统、链型可对照**：同一 kill-chain 阶段，且工具链对照能改变判断 | Windows 域内横向 WMIC↔SMB（001/007） | 横向但跨系统 SSH(Linux)↔SMB(Windows)（004/007，见 §六） |

**补充**：方向不对称时记录 `direction_note`（如「005→003 有帮助；003→005 较弱」）。判定默认双向对称，仅当一方是另一方的"模板 / 父类"时才标注方向。

### 2.2 weak —— 不激活扩展（不作关联参考输出，仅作潜在观察）

满足**任一条**但不满足任何 H 条：

| # | 判据 | 正例 |
|---|---|---|
| W1 | 同 mitre 大类（如仅 `T1190`）但技术栈 / 载体不同 | 003 Node LFI 链 ↔ 006 Java 反序列化；003↔008/009；005↔008（T1059.004 vs T1059.006） |
| W2 | 同"攻击家族 / 向量类"（同为 Web 利用、同为主机侧后利用）但具体机制不同 | 003↔010/011/012/013/015…（大量「同属 Web 利用类（技术面/载体不同）」） |
| W3 | 同 kill-chain 阶段但系统 / 机制不同 | 001 后门账户(Windows) ↔ 021 rc.local(Linux) 持久化；019 主机后利用 ↔ Web 利用 |
| W4 | **chain_sibling** 时序伴生（PAT-001），未证实因果 | 全部 15 条跨簇 chain_sibling；按「独立事件」准则默认 weak |
| W5 | 形态重叠但机制不同 | 022 xp_dirtree UNC ↔ 007 SMB 管理共享；002 DGA 信标 ↔ 019 DNS 外传（同通道不同用途） |

### 2.3 unrelated —— 不参与任何扩展

- 无共享技术（mitre 交集为空）/ 指标 / 阶段；或仅有无关字段的偶然共现。
- 正例：002 DGA ↔ 其余大部分案例（独立向量，解析 IP 未复用）；「都读 /etc/passwd」「都带 Mozilla/5.0 UA」不构成关联。

### 2.4 misleading —— 返回即有害（单独统计，一票否决）

- 表面相似（词面 / 探针命中、同被强档打分）但**实质是不同攻击**，引用会导致分析者误判为同一战役 / 同一攻击者。
- 保留位，当前无对；一旦出现，无论扩展配置如何都必须抑制。
- 与「通用词泄漏」（PENDING §2）的假命中重叠度高——凡由通用词强档误命中拉起的"关联"均应排查是否属 misleading 而非 weak。

---

## 三、关系类型 → 档位默认映射

| 类型 | 默认档位 | 升级 / 降级条件 |
|---|---|---|
| `shares_payload` | **推定 helpful** | 载荷不具体（通用词）→ 降 weak，并排查 misleading |
| `shares_infra` | **推定 helpful** | 仅同文档网段 → 降 weak/unrelated |
| `same_technique` | **需细化** | mitre 大类∩（T1190）→ weak；同具体缺陷类/引擎（T1059.004 + 同载体）→ helpful |
| `same_family` | **需细化** | 同向量类机制不同 → weak；同家族同机制 → helpful |
| `same_phase` | **需细化** | 同系统链型可对照 → helpful；跨系统机制不同 → weak |
| `chain_sibling` | **默认 weak** | 仅当批次留档确认真实波次同源配对才升 helpful（见 §六） |

---

## 四、载荷「具体性」排除规则（防通用词泄漏污染 shares_payload）

判定 H1 的"载荷片段"必须**判别性**，同时满足：

1. **含特定 token / 结构**：`rO0AB`、`com.tangosol.coherence`、`_method=__construct`、`xp_dirtree`、`echo;id`、`cmd=127.0.0.1;id` 等；
2. **非通用词**：以下单独出现不构成 shares_payload——`id`、`select`、`process`、`create`、`execute`、`base64`、`Windows`、`username`、`password`、单条 `/etc/passwd` / `/bin/sh` 路径；
3. **跨案例共享 = 行为复用证据**，而非"两个 Web 应用都读 /etc/passwd"这类普遍动作。

> 依据：`PENDING.md` §2 通用词泄漏（`select`/`process`/`base64` 等经多通道累计可达强档误命中）。判定 shares_payload 前先过 §四 排除表，否则会把假命中固化成"载荷共享"关系。

---

## 五、判定顺序（决策树，自上而下，命中即停）

1. **查 shares_payload / shares_infra**：有具体共享（过 §四）→ `helpful`（H1/H2）；仅通用词 → 记为 weak 并排查 misleading。
2. **查 same_technique**：mitre 交集里是否有**具体子技术**（T1059.004 / T1059.006 等）**且**载体同族 → `helpful`（H3）；仅 T1190 大类 → `weak`（W1/W2）。
3. **查 same_phase**：同阶段且同系统、链型可对照 → `helpful`（H4）；跨系统机制不同 → `weak`（W3/W5）。
4. **查 chain_sibling**：默认 `weak`（W4）；有确凿波次配对证据 → 转 §六。
5. 以上皆无 → `unrelated`。
6. 全程：词面 / 强档命中但实质不同 → `misleading`（一票否决，单列）。

---

## 六、校准样例：套用到现有 review=true 疑难对（建议裁定，待你确认）

> 本节用本判据对 `findings_round1.md` §四列出的疑难对给出**建议裁定**，作为判据的可检查产出；不改动 `relations_gold.json`。

| 对 | 现状 | 判据依据 | 建议裁定 |
|---|---|---|---|
| 001↔007（WMIC vs SMB 横向） | helpful, review | H4：同阶段 + 同系统(Windows) + 链型可对照 | **维持 helpful** |
| 004↔007（SSH 密钥 vs SMB 共享） | helpful, review | W3/W5：同横向阶段但跨系统、机制不同，无同环境对照价值 | **降 weak**（体现 H4 的"同系统"分界） |
| 003↔006（Node LFI vs Java 反序列化） | weak, review | W1：仅 T1190 大类，技术栈不同 | 维持 weak |
| 003↔009（LFI vs 登录认证攻击） | weak, review | W1/W2：T1190 + 双层形态宽泛交集 | 维持 weak |
| 005↔008（命令注入 vs SSTI） | weak, review | W1：T1059.004 vs T1059.006 子技术不同 | 维持 weak |
| 15 条跨簇 chain_sibling | weak, review | W4：默认 weak；升级需批次留档确认真实波次同源 | **暂维持 weak**，配对证据确凿再升（PENDING §1.1） |

其余 `review=true` 条目（如 003↔016/018、006↔010、008↔013/020、009↔015、010↔013/016/022、013↔020、014↔015、005↔022 等，多为 shares_payload / 同具体缺陷类）逐对套本判据核对，evidence 已具体的通常维持 helpful——**逐对结论以你复核为准，本节只列代表性的 6 组**。

---

## 七、裁定落盘约定

每裁定一对，evidence 必须满足：

1. **可引用**：写日志 / 案例里可见的具体 token（如 `cmd=id`、`rO0AB`、`169.254.169.254`），不写「同类手法」这类空泛词；
2. **档位 + 类型 + 理由三者自洽**：`helpful` 必须能对上 H1–H4 之一；`weak` 对上 W1–W5 之一；
3. **review 标记**：任何不按机械规则、依赖人工判断的裁定标 `review=true`，进复核队列；
4. **misleading 优先排查**：凡强档词面命中拉起的关联，先问"是不是通用词泄漏导致的误导"，再定档。

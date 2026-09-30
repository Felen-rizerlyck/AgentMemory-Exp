# 通用词泄漏修复决策记录

> 日期：2026-09-29 · 状态：**已执行（2026-09-29）——A（#2）+ B2 完成，B1 兜底观察中**
> 关联：`docs/PENDING.md` §2（已部分处理，本文收口层 1/2）· `docs/EXTRACTION_CRITERIA.md` §五（probe 判别性准则，本文把判别性准则扩展到 retrieval_keys）

## 一、问题重新分类（三机制，比 PENDING §2 更细）

前序（#4 跨通道去重 + CASE-005 probe 修订）已解决机制 C 和部分误报；剩余"通用词泄漏"经诊断拆成三个独立机制：

| 机制 | 根因 | 实例 | 采纳修法 |
|---|---|---|---|
| **A 组件兜底泄漏** | 多词键拆出 ≥6 字符**纯字母**通用词，单独命中 | `"process call create"` → `process` 命中 `return process`() | **#2 结构化组件** |
| **B 通用路径/词作为键或字段** | retrieval_keys/signature 含系统路径，整体或组件命中 | `etc/passwd` 键命中 `load_file('/etc/passwd')` | **B2 字段设计（主）+ B1 停用表（兜）** |
| **C 多通道重复累计** | 同一 token 跨 keys/ind/sig 重复计分 | `select` → 3+2+1=6 | **#4 已解决** ✓ |

## 二、采纳方案

### 1. #2 结构化组件（针对 A）
- **位置**：`src/retrieve.py` 的 `key_hits` 组件兜底循环。
- **改法**：组件参与匹配前加条件——须含非字母数字字符（数字或符号）：

```python
for t in _components(k):
    tl = t.lower()
    if len(tl) >= 6 and re.search(r"[^a-z0-9]", tl) and _wordish(tl).search(ql):
        hits.append(tl)
```

- **排除**：`process` / `windows` / `server` / `select` / `create` / `deserialization` / `username` / `password` 等纯字母通用词。
- **安全性**：真实召回靠多词键的**整体词边界命中**（查询含完整 `process call create`），组件兜底只在"查询仅含孤立组件"时触发——那正是泄漏场景；单词语义键（`wmic`、`whoami`、`ShellSession`）走整体匹配，不受影响。
- **盲区（诚实标注）**：以"含非字母数字字符（符号）"当"结构化"判据，拦不住**含符号**的通用词——`etc/passwd`（斜杠）、`cmd_inject`（下划线）等，这类恰是 B2 清理的对象；`base64` 为纯字母数字、不含符号，被 #2 一并排除（实现比 PENDING 原文"含非字母字符"更严）。

### 2. B2 字段设计（针对 B，主修法）
- **位置**：`data/memory_store.json` 各案例的 `retrieval_keys`。
- **原则**：把判别性准则从 `pattern_probes` 扩展到 `retrieval_keys`——**零判别性的系统文件路径移出 keys**，信息不删除，仍保留在 `signature` / `indicators`（`observed_payloads`、`path` 等）作推理上下文，只是不再参与检索打分。
- **已核对候选清单（执行时逐一确认，含行号）**：
  | 案例 | 移除的键 | 说明 |
  |---|---|---|
  | CASE-003 | `etc/passwd`（L187） | LFI 读 /etc/passwd，但读该文件是所有攻击共性 |
  | CASE-005 | `/bin/sh`（L275） | 命令注入落 shell，通用 |
  | CASE-014 | `/var/spool/cron`（L615）、`/dev/tcp`（L617） | cron 路径与反连路径，通用 |
  | CASE-019 | `/etc/shadow`（L808） | 凭据文件，通用 |
  | CASE-021 | `rc.local`（L879） | 启动脚本路径，通用 |
- **保留**：`pattern_probes` 里的系统路径（CASE-014 `"/var/spool/cron"`、CASE-021 `"/etc/rc\\.local"`）——它们是探测"**写**持久化"动作的结构正则，判别性高，与"读"路径的零判别性不同，保留。

### 3. B1 停用表兜底（针对 B 漏网，辅修法）
- **位置**：`src/retrieve.py`（小停用表，`key_hits` 命中即不返回）。
- **原则**：兜住 B2 红线之外、#2 拦不住的漏网含符号通用词（如 `base64`），词表保持最小。
- **候选（执行时定）**：`base64` 等含符号通用词。

## 三、判别性红线（"零判别性"标准）

1. **系统文件路径不作为 retrieval_keys**：`/etc/*`、`/bin/*`、`/var/spool/*`、`/dev/tcp` —— 读写系统文件是几乎所有攻击的共性动作，零判别性。
2. **命令探针保留**：`whoami`、`id`、`echo;id` —— 反映攻击者具体动作，有判别性。
3. **落地文件保留**：`/tmp/.svc`、`/tmp/.implant` —— 特定命名，有判别性；换名风险由 `pattern_probes` 兜。
4. **结构正则（probe）中的路径保留**：探测的是"动作"（写 cron、写 rc.local），非"提及路径"。

## 四、落选方案及理由

| 方案 | 落选理由 |
|---|---|
| #1 ≥2 组件命中（PENDING §2 候选 1） | 阈值难定，削弱"部分片段兜底"能力 |
| #3 停用表作主修法（PENDING §2 候选 3） | 治标，黑名单永涨；被吸收为 B1 兜底（降级为辅） |
| B3 通用路径降权 | 要改 schema 加"上下文键"标记，最复杂，收益不匹配成本 |
| 纯 B1 停用表（B 主修法） | 治标，不如 B2 从源头清键 |

## 五、实施清单（待执行，敲定后动手）

1. `src/retrieve.py`：`key_hits` 组件兜底加结构化条件（#2）+ 小停用表（B1）。
2. `data/memory_store.json`：按红线移除上表 5 案例的零判别性系统路径键（B2），保留上下文信息。
3. `eval/run_eval.py` 的 `score_case_cfg` 复用 `retrieve.key_hits`，无需单独改（若停用表写进 key_hits 即自动生效）。
4. 回归验证（§六）。
5. 更新 `docs/PENDING.md` §2：标记 A/B 已收口，候选修法 #1/#2/#3 状态落定。

## 六、验证口径（before/after 对照）

- **误报端**：NOVEL 2-1/2-2（`etc/passwd`）、2-3 最高分 <4（静默）；样板行（`cat /etc/passwd` 类）强档落点消失。
- **召回端**：KNOWN 21/21 不降；全量召回 Top-1 122/123、Top-3 123/123 不降（尤其 CASE-003/005/014/019/021 的 LFI/CGI/cron/凭据外传/rc.local 特征行）。
- **安全端**：负样本零扩展 9/9 保持；C2 自检（`score_case_cfg` ≡ `score_case`）0 差异。
- **回归**：改动后跑 `python eval/run_eval.py` + `python eval/run_recall_unseen.py` + `python eval/run_recall_full.py`。

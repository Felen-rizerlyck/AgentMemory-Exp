# 部署场景模拟测试报告：Flash 子代理 + 记忆系统实际使用表现

> 日期：2026-10-13 · 子代理模型：deepseek-flash（delegation 钉定）· 主代理：deepseek-v4-pro
> 目的：模拟"独立安全检测 Agent 实际运行"场景——用一个更贴近生产配置的模型（Flash），仅开放真实部署会存在的文件，喂一批未见过的告警日志，测量其在这套案例记忆系统下的攻击判定与提取表现。

---

## 一、测试设计

### 1.1 子代理环境（模拟生产）

- **模型**：deepseek-flash（首次用 `deepseek-v4.1-flash` 被 API 拒绝——DeepSeek 支持列表仅 `deepseek-flash` / `deepseek-v4-pro`，已改钉 `deepseek-flash` 重新派发）。
- **可见世界**：仅 `src/retrieve.py`、`scripts/build_action_index.py`、`data/memory_store.json`、`data/incoming_logs.txt` + skill 的 `references/case-write-spec.md`（写入规范）与 `references/production-log-schema.md`。**未暴露**：`dataset/`、`eval/`、`history/`、`docs/`、主 SKILL.md（含验证项目痕迹）、GUIDE/README。
- **角色设定**：某企业安全运营中心"攻击检测 Agent 的分析模块"，上下文无"模拟/测试"字样；约束：不用 git、不联网、不读未列文件（软约束）。
- 备注：子代理可能继承本机用户画像（含"日志为清洗/模拟数据"字样）——"不知是模拟"为尽力而为，核心隔离在于**流程只能依赖部署文件**。

### 1.2 测试数据（12 行，较既有数据更复杂）

| 行 | 来源 | 内容（摘要） | 设计意图 | Ground truth |
|---|---|---|---|---|
| 1 | hids | wmic /node:10.20.7.88 whoami（新目标） | 已知攻击·新观测 | 匹配 CASE-001（合并） |
| 2 | dns | 3fa2b9c1.xkqwvp-9d2f.net（全新 DGA 域） | 已知攻击·基础设施更名 | 匹配 CASE-002（合并） |
| 3 | waf | `${jndi:rmi://...}`（rmi 协议变体） | 已知攻击·变体 | 匹配 CASE-023（合并） |
| 4 | waf | `/uploads/shell.jsp?cmd=id` | **混淆**：仅共享通用探针 cmd=id，但关键词通道 CASE-006 强分陷阱 | 新案例（JSP webshell） |
| 5 | waf | `/api/v2/render deserialization=rO0AB…` | **混淆**：仅共享序列化魔数，载体/路径全新，CASE-006 关键词强分陷阱 | 新案例（反序列化新载体） |
| 6 | waf | `admin' AND (SELECT sleep(5))--` | **混淆**：仅共享 sleep 探针（CASE-017 弱参照） | 新案例（时间盲注） |
| 7 | hids | mimikatz 抓 LSASS 凭据 | 全新攻击 | 新案例 |
| 8 | hids | curl 下载 → /tmp/.x → chmod → 执行（3 动作链） | 全新攻击·多动作 | 新案例（下载执行） |
| 9 | hids | wmic + whoami + net user /add + net localgroup（4 动作完整链） | 已知攻击·**更多动作** | 匹配 CASE-001（完整 4/4，合并） |
| 10 | hids | systemctl restart nginx | **无关日志**混入 | 无关，不建案 |
| 11 | dns | www.example.org 正常解析 | **无关日志**混入 | 无关，不建案 |
| 12 | waf | 容器 exec API 内 wget 下载执行（双载体） | 全新攻击·与行 8 同技术链 | 新案例（与行 8 合并） |

---

## 二、子代理执行验证（父代理复核，非仅信自报）

- 步骤合规：先读 case-write-spec.md → 跑 `src/retrieve.py --batch` → 逐条判定 → 三处写入 → `build_action_index.py` **输出「校验通过: 77 动作 / 28 案例序列」** → 重检 12 行全部命中。
- 实际落盘（父代理读回验证）：`memory_store.json` cases 23→**28**、action_library 67→**77**；5 个新案例字段齐全（id/source/attack_type/kill_chain/mitre/indicators/signature/reasoning/retrieval_keys/pattern_probes + 注入的 action_sequence）；未手写 action_sequence。
- 合并属实：CASE-001 targets 4→6（10.20.7.88/99）、CASE-002 补域 xkqwvp-9d2f.net + 观测 11→12、CASE-023 补 rmi 变体（observed_paths/observed_payloads）。
- 无关行未建案：行 10/11 零命中且判"无关"，正确。

## 三、判定准确率：12/12（100%）

| 行 | 判定 | 正确性 | 要点 |
|---|---|---|---|
| 1 | [检索: CASE-001] 合并强化 | ✅ | 前缀 2/4 + 预测"创建后门账户"，且当日被行 9 证实（预测应验） |
| 2 | [检索: CASE-002] 合并强化 | ✅ | DGA 模式匹配克服域名更名（正是 pattern/动作设计目标） |
| 3 | [检索: CASE-023] 合并强化 | ✅ | probe `jndi:(ldap\|rmi\|…)` 覆盖协议变体 |
| 4 | 【新案例】CASE-024 | ✅ | **穿过关键词强分陷阱**：明确写"仅共享通用探针、载体不同（上传目录 JSP），不凭关键词高分判匹配" |
| 5 | 【新案例】CASE-025 | ✅ | **穿过 rO0AB 陷阱**：明确"路径/参数形态不同（/api/v2/render vs webtools）" |
| 6 | 【新案例】CASE-026 | ✅ | 弱档 sleep 探针正确按参照处理，未错挂 CASE-017 |
| 7 | 【新案例】CASE-027 | ✅ | 零命中正确新建 |
| 8 | 【新案例】CASE-028 | ✅ | 与行 12 判为同技术链合并（源 IP 203.0.113.91 相同 + 同模版） |
| 9 | [检索: CASE-001] 合并强化 | ✅ | 完整 4/4 强档；账户名轮换 backdoor→service 正确记为观测差异 |
| 10 | 无关 | ✅ | 未建案 |
| 11 | 无关 | ✅ | 未建案 |
| 12 | 【新案例】CASE-028（合并） | ✅ | 双载体（主机 shell / 容器 exec API）合并处理，载体差异用 indicators+probe 承载 |

## 四、提取质量评估

| 维度 | 结果 |
|---|---|
| 三处写入完整性 | ✅ 5 案例 ×（本体+动作+序列）全部到位 |
| 格式合规 | ✅ 字段齐全、无手写 action_sequence、build 校验通过 |
| 动作判别性门禁 | ✅ 10 个新动作正则均锚定特有结构（具体路径/具体命令/具体工具名），无通用词污染 |
| 合并判据 | ✅ 3 处合并（001/002/023）准确，均不新建 |
| 序列设计取舍 | ✅ 行 8/12 双载体合并时取共享核心三段（下载→chmod→执行），使两条观测均"完整·强"命中；容器 exec 载体以 probe `post\s+/containers/\w+/exec` 承载——比把 API 路径塞进序列（会降行 8 为中段）更优，设计合理 |
| 无关处理 | ✅ 未把运维命令/正常流量建案 |

## 五、回归（新动作零扰动旧数据）

`python eval/run_action_recall.py`：特征行 123 · **Top-1 122 · Top-3 123 · 动作命中 123 · 动作强档 60 · 样板行 10** —— 与测试前完全一致。新动作正则（`' AND (SELECT sleep(`、`chmod +x /tmp/.`、`mimikatz` 等）均未误触旧数据集行。

## 六、观察与结论

1. **判定层表现优秀（12/12）**：两个刻意设计的"共享探针+关键词强分"陷阱（行 4/5）均被正确识别为"载体不同→新案例"，且理由表述符合判读规则原文。这验证了动作通道作为主判据、关键词通道作参照的架构在弱模型上仍然稳健。
2. **写入层严格遵守规范**：Flash 模型能按 case-write-spec 三处写入、过 build 门禁、无污染——说明"严格写规"对弱模型是有效的防 drift 手段（本测试前刚固化的写规即投入使用）。
3. **预测能力应验**：行 1 前缀匹配预测"下一步=创建后门账户"，同批行 9 即完整复现该链——序列索引的预测价值在批内闭环体现。
4. **首观测案例的固有窄度**：CASE-024/025/026 的动作/探针锚定首次观测的具体路径（/uploads/、/api/v2/render、' AND (SELECT sleep(），未来同技术异路径再现时动作通道可能漏、需靠关键词兜底——属预期行为（案例随观测泛化），非缺陷。
5. **小瑕疵（无影响）**：判定表引用的关键词分数取自合并后重检（如行 1 报 17、行 9 报 31，略高于入库前），属报告口径不严谨，判定本身无误；子代理自建备份留在 `C:\Users\cui-home\agentmem_store_backup.json`（可自行删除）。
6. **模型钉定发现**：DeepSeek API 当前支持列表 = `deepseek-flash` / `deepseek-v4-pro`；`deepseek-v4.1-flash` 会 400。已用 `deepseek-flash` 完成测试。

## 七、测试后状态

- `data/memory_store.json`：28 案例 / 77 动作（新增 CASE-024~028 为正式数据保留）。
- `data/incoming_logs.txt`：本测试批次（与常规流程一致，入库后即被下批覆盖）。
- `delegation.model`：测试后已还原为继承（空），再测时重新钉 `deepseek-flash`。
- 主代理备份：`$LOCALAPPDATA/Temp/memory_store_backup.json` + `build_action_index_backup.py`（回滚用，验证通过后可删）。

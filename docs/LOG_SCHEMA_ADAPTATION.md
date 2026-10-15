# 生产日志 schema 适配分析（log-schema → v2 检索/提取）

> 状态：分析稿（留档）。**当前不改动任何检索/提取代码。**
> 数据来源：本地 `log-schema/` 目录（已加入 `.gitignore`，未入库 git），13 个日志类目字段字典 + `event_types.json` 事件类型字典。
> ⚠️ **schema 尚未定稿**：字段名/类型可能继续变动（"各产品自行决定"字段尤其不稳）。实装前必须用最新 schema 重新核对字段映射，本文的字段级细节仅作方向性参考。

---

## 一、这是什么

一套标准化、强类型的安全日志字段字典（国标 GB/T 20986-2023 / GB/T 37027-2025 风格 + 厂商统一规范）。字段对象统一结构：

```jsonc
{ "storage_name": "src_ip", "chinese_name": "源IP", "type": "IP", "array": "否", "description": "..." }
```

类型枚举：TIMESTAMP / STRING / KEYWORD / IP / INT / LONG / DOUBLE / TEXT。

**日志类目（13 个）**：

| 组 | 类目 |
|---|---|
| 协议日志 | `flow_log` `http_log` `dns_log` `ftp_log` `sql_log` `telnet_log` `mail_log` `nat_log` `os_log` |
| 安全日志 | `alarm_event`(安全告警) `security_event` `security_log` |
| 系统日志 | `sys_log` |
| 事件类型字典 | `event_types.json`：416 种，含 `name`(正则)/`cat1`/`cat2`/`level`/`attck_list`/`k_c`/`cat2_rule` |

---

## 二、关键字段 vs 现有案例字段

| 现有字段 | 生产 schema 对应 | 是否直接可用 |
|---|---|---|
| `attack_type` | `cat1`/`cat2`/`name` + `event_types` 分类字典 | ✅ 有，但更粗（有"命令注入/SQL注入/XXE/SSRF/DGA/WebShell"，**无"反序列化/SSTI"**等细分技术） |
| `mitre` | `attck_list`（`TA0001.T1190` 战术.技术格式） | ✅ 比现在手写更准更全，可反向校验 Agent 判断 |
| `kill_chain` | `k_c` / alarm 的"杀伤链阶段" | ✅ 有（"安装植入/命令执行"等战术阶段） |
| `indicators` | `src_ip`/`dst_ip`/`domain`/`url`/`src_file_md5` 等 | ✅ 天然结构化 IOC，直接解决 v1 遗留"indicators 拆 iocs/notes" |
| 检索"内容" | `raw`(原始日志) + `http_param`/`http_req_body`/`oper`(操作命令)/`domain` 等 | ⚠️ 有，但分散多字段，部分 Base64 编码 |
| `source`(waf/rasp/hids/dns) | 检测层概念 ≠ 日志类目概念 | ❌ 需重映射 |

---

## 三、分块评估

### 1. 检索（动作匹配）——小改，机制保留
- 动作库（66 个"去变量指令模板"正则）、序列对齐、完整/前缀/中段/缺口、预测下一步、分叉参考，**全部不动**。
- 唯一变化：动作正则现跑在自由文本 `content` 上，结构化后要跑在**正确字段**（DGA→`domain`、命令注入→`http_param`/`oper`、LFI→`http_path`）。需新增一个**动作抽取器/字段映射层**。
- 这其实是**改进**：按字段定向匹配，噪音更低。动作定义（去变量模板）本体可复用，因 payload/命令在结构化日志里仍是字符串。

### 2. 提取——中等改动，方向是简化
- 现在全靠 Agent 手工写 attack_type/mitre/kill_chain/indicators；结构化后这些字段**可直接映射**（`attck_list`→mitre、`cat1/cat2`→attack_type、`k_c`→kill_chain、`src_ip/domain`→iocs）。
- Agent 职责从"造字段"变"**校验 + 补充**"：reasoning、signature、动作去变量模板仍人工。
- 顺带兑现 v1 遗留项：`indicators` 拆 `iocs`/`notes` 零成本。

### 3. source 映射——数据接入层真正的改动点
- `waf/rasp/hids/dns` 是"检测层"概念，生产是"日志类目"概念。WAF→`alarm_event`/`http_log`、RASP→`security_log`/`os_log`、HIDS→`os_log`/`sys_log`/`security_log`、DNS→`dns_log`。需 source 重映射表，但属**新增适配器，不动核心**。

### 4. 风险点（接入时处理，非逻辑改动）
- **Base64 编码**：`http_req_body`/`http_res_body` 为"Base64 外发"，动作正则需**先解码再匹配**（把现有"先解码再判断"纪律系统化进动作抽取器）。
- **空字段回退**：大量字段"各产品自行决定"，单字段可能空——需 `oper → raw → msg` 多字段回退链。
- **`event_types.name` 是正则**（`(?i)Win32\s*病毒` 类）：与动作库正则**同构**，未来可复用/对齐其分类字典。
- **切真实数据后动作库需校准**：payload 落哪个字段、编码形态都要用真实样本回归，但动作定义不变。

---

## 四、结论

| 环节 | 改动量 | 说明 |
|---|---|---|
| 检索动作匹配核心 | 不大改 | 动作库/对齐/预测/分叉全保留，只加"字段映射动作抽取器" |
| 提取 | 中等，偏简化 | 字段自动映射 + 人工校验，顺带解决 iocs 拆分 |
| 数据接入层 | 新增 | source 重映射、编码解码前置、空字段回退 |
| 动作库本身 | 校准，不重写 | 真实数据回归，动作模板定义不变 |

一句话：v2 架构为"自由文本 + 4 来源"设计，这套 schema 是"强类型 + 多类目"——**架构能扛住，接的是适配层不是改核心**。落地优先级：动作抽取器 + source 映射两个小件，而非动动作库。

---

## 五、实装前待确认清单（schema 变动相关）

- [ ] 字段名/类型是否冻结（`storage_name` 与类型枚举以最新版为准重新核对）
- [ ] `raw` 字段是否完整落库（决定能否保留"整行匹配"路径）
- [ ] WAF/RASP/HIDS/DNS 四来源实际映射到哪些类目 + 哪些字段承载攻击 payload（决定动作抽取器字段定向表）
- [ ] `event_types` 的分类粒度是否够用（缺反序列化/SSTI 等细分技术，需确认是补充字典还是仍靠 Agent 判断）
- [ ] Base64/URL 编码字段的完整清单（决定解码前置范围）

# 生产结构化日志（log-schema/）适配分析

> 项目 `log-schema/` 目录是之后实际上线用的**强类型日志字段字典**。本文件记录「切到结构化日志后，v2 检索/提取要改什么」的结论，实装前先读。

## 一、log-schema 是什么

标准化安全日志规范（国标 GB/T 20986/37027 风格 + 厂商统一字典），13 个日志类目 + 1 个事件类型字典：

- 协议日志：`flow_log` `http_log` `dns_log` `ftp_log` `sql_log` `telnet_log` `mail_log` `nat_log` `os_log`
- 安全日志：`alarm_event`(安全告警) `security_event` `security_log`
- 系统日志：`sys_log`
- `event_types.json`：416 种事件类型，每条含 `name`(正则) `cat1`/`cat2`(国标分类) `level` `attck_list`(ATT&CK) `k_c`(杀伤链阶段) `cat2_rule`(正则)

字段统一结构 `{storage_name, chinese_name, type, array, description}`，类型 TIMESTAMP/STRING/KEYWORD/IP/INT/LONG/DOUBLE/TEXT。

## 二、字段映射（案例字段 → schema 字段）

| 现有字段 | 生产 schema 对应 | 可用性 |
|---|---|---|
| `attack_type` | `cat1`/`cat2`/`name` + `event_types` 分类 | 有，但更粗（416 类含命令注入/SQLi/XXE/SSRF/DGA/WebShell，**无反序列化/SSTI 细分**） |
| `mitre` | `attck_list`（`TA0001.T1190` 战术.技术格式） | **比手写更准更全**，可反向校验 Agent 判断 |
| `kill_chain` | `k_c` / alarm 的"杀伤链阶段" | 有（战术阶段粒度，比现在阶段字符串更规范） |
| `indicators` | `src_ip`/`dst_ip`/`domain`/`url`/`src_file_md5`… | **天然结构化 IOC**，直接解决 v1 遗留的 `indicators` 拆 `iocs`/`notes` |
| 检索"内容" | `raw` + `http_param`/`http_req_body`/`oper`(操作命令)/`domain` 等 | 有，但**分散多字段**且 http 体是 Base64 |
| `source`(waf/rasp/hids/dns) | 检测层概念 ≠ 日志类目概念 | **需重映射**（见下） |

## 三、改动评估

1. **检索（动作匹配）——小改，机制保留**：动作库、序列对齐、完整/前缀/中段/缺口、预测、分叉全部不动。只加一个**动作抽取器/字段映射层**（结构化记录 → 定向喂给动作正则：DGA 跑 `domain`、命令注入跑 `http_param`/`oper`、LFI 跑 `http_path`）。按字段定向匹配比整行 blob 噪音更低。
2. **提取——中等改动，方向是简化**：`attck_list`→mitre、`cat1/cat2`→attack_type、`k_c`→kill_chain、`src/dst_ip`+`domain`→iocs 直接映射；Agent 从"手写字段"变"校验 + 补充 reasoning/signature/动作去变量模板"。
3. **数据接入层——新增**：source 重映射（waf→`alarm_event`/`http_log`、rasp→`security_log`/`os_log`、hids→`os_log`/`sys_log`/`security_log`、dns→`dns_log`）；Base64 解码前置；空字段回退链 `oper → raw → msg`。

## 四、风险点

- `http_req_body`/`http_res_body` 是 **Base64 外发**，动作正则要先解码再匹配（现有"先解码再判断"纪律要系统化进动作抽取器）。
- 大量字段"各产品自行决定"，实际可能空 → 多字段回退，不能只依赖单一字段（如只读 `oper`）。
- `event_types.name` 是正则（`(?i)Win32\s*病毒`），与动作库正则**同构**，未来可复用/对齐其分类字典。
- 切真实数据后动作库要**回归校准**（payload 落在哪个字段、编码形态），但动作定义（去变量模板）不变。

## 五、结论

v2 架构（自由文本 + 4 来源）能扛住结构化日志；接的是**适配层**不是改核心。优先做两件小件：动作抽取器 + source 映射，再考虑字段自动映射提取。动动作库之前先做真实数据回归。

## 六、接入现状（截至本文件更新）

- `log-schema/`（本地、gitignore）= 生产日志字段字典（13 类目 + `event_types.json` 416 事件类型）。
- `mcp.txt` 端点 + `config.yaml` 的 `mcp_servers.hunt`：hunt MCP `http://10.7.194.120:22196/hunt/sse`（内网 SSE、`transport: sse`、`connect_timeout: 8`）→ 工具名待连通后自动发现（前缀 `mcp_hunt_*`）。
- **当前内网不可达**，尚未融入检索/提取主流程；适配层（动作抽取器 + source 映射）未实装。接真实日志前先读本文件，并**保留自由文本通道**（结构化字段可能大量为空，需多字段回退）。
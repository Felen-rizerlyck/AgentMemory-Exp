# 动作匹配检索器（v2）全量重放召回审计报告

- 范围: `dataset/` 三文件全部日志行 = **133 条**（特征行 123 + 通用样板行 10）
- 口径: 组合排序 = 动作通道优先（完整=强 / 命中≥2=中 / 命中1=弱参照）+ 关键词兜底（强≥6/中4–5/弱≤3）
- 期望映射: 沿用 v1 人工标注（`history/old_eval/run_recall_full.py` 的 EXPECT）
- 声明: 回顾性审计（证明已有知识可召回），不代表事前检出；通用样板行无唯一预期。

## 一、总览（特征行）

| 指标 | 值 |
|---|---|
| 特征行 | 123 |
| 组合 Top-1 | 122（99%） |
| 组合 Top-3 | 123（100%） |
| 组合出现 | 123（100%） |
| 动作通道命中 | 123（100%） |
| 动作通道强档（完整匹配） | 60（49%） |

### 分文件

| 文件 | 特征行 | Top-1 | Top-3 | 动作命中 | 动作强档 |
|---|---|---|---|---|---|
| 901-910 | 52 | 52（100%） | 52（100%） | 52（100%） | 37（71%） |
| 911-920 | 31 | 30（97%） | 31（100%） | 31（100%） | 12（39%） |
| 9101-9110 | 40 | 40（100%） | 40（100%） | 40（100%） | 11（28%） |

## 二、逐案例召回（特征行按预期案例聚合）

| 案例 | 特征行 | Top-1 | Top-3 | 动作命中 | 动作强档 | 说明 |
|---|---|---|---|---|---|---|
| CASE-001 | 4 | 4 | 4 | 4 | 0 | 横向移动 / 远程命令执行 (WMIC)（载荷演进：侦察 → |
| CASE-002 | 33 | 33 | 33 | 33 | 33 | DGA 域名生成 / C2 信标 (DNS) |
| CASE-003 | 22 | 22 | 22 | 22 | 0 | Web 漏洞利用链：路径穿越(LFI) → Node.js  |
| CASE-004 | 6 | 6 | 6 | 6 | 6 | SSH 横向移动（落地密钥 + 免主机校验） |
| CASE-005 | 5 | 5 | 5 | 5 | 2 | Web CGI 命令注入（双编码路径穿越绕过 + echo; |
| CASE-006 | 3 | 3 | 3 | 3 | 0 | Java 反序列化 RCE + 参数命令注入 |
| CASE-007 | 1 | 1 | 1 | 1 | 1 | Windows 网络枚举 + SMB 管理员共享横向移动 |
| CASE-008 | 1 | 1 | 1 | 1 | 1 | Web 模板注入 SSTI（Jinja2 对象链逃逸执行命令 |
| CASE-009 | 2 | 2 | 2 | 2 | 0 | Web 认证攻击：SQL 注入认证绕过 + 批量赋值（mas |
| CASE-010 | 3 | 3 | 3 | 3 | 2 | Web 应用命令执行：WebLogic ShellSessi |
| CASE-011 | 3 | 2 | 3 | 3 | 2 | Web 应用命令执行：F5 BIG-IP iControl ⚠️ 有非 Top-1 |
| CASE-012 | 3 | 3 | 3 | 3 | 0 | Web 文件上传反序列化：PHP phar 伪装上传（__H |
| CASE-013 | 3 | 3 | 3 | 3 | 0 | Web 表达式注入：Spring Cloud Functio |
| CASE-014 | 3 | 3 | 3 | 3 | 0 | Web 参数写持久化：注入 /var/spool/cron/ |
| CASE-015 | 3 | 3 | 3 | 3 | 2 | Web 注入组合：注册接口 cmd_inject + UNI |
| CASE-016 | 3 | 3 | 3 | 3 | 0 | Web 命令执行 + 路径穿越：/api/exec（cmd= |
| CASE-017 | 6 | 6 | 6 | 6 | 0 | PHP 框架参数覆盖命令执行（_method=__const |
| CASE-018 | 3 | 3 | 3 | 3 | 2 | XXE 外部实体注入（+ HTTP 走私标记） |
| CASE-019 | 5 | 5 | 5 | 5 | 5 | 凭据外传：/etc/shadow 经 DNS（nslooku |
| CASE-020 | 3 | 3 | 3 | 3 | 2 | 调度平台接口脚本注入（Groovy String.execu |
| CASE-021 | 5 | 5 | 5 | 5 | 0 | Linux 启动脚本持久化：/etc/rc.local 植入 |
| CASE-022 | 3 | 3 | 3 | 3 | 2 | PHP 路径命令执行（fpm_path）+ 数据库 xp_d |

## 三、非 Top-1 明细（1 条）

| 文件-单元-条 | 来源 | 预期 | Top1 | 动作档 | 动作形态 | 预期排名 | 行内容（截断） |
|---|---|---|---|---|---|---|---|
| 911-920-3-3 | rasp | CASE-011 | CASE-010 | 弱 | 前缀 | 2 | `https://app-go-128.ops-corp.com/api/v1/ping?cmd=…` |

## 四、通用样板行落点（10 条，无唯一预期案例）

| 文件-单元-条 | 动作命中数 | 关键词兜底 | 行内容（截断） |
|---|---|---|---|
| 911-920-2-4 | 0 | 4 条 | `cat /etc/passwd /bin/cat cat /etc/passwd <== /bi…` |
| 911-920-3-4 | 0 | 4 条 | `cat /etc/passwd /bin/cat cat /etc/passwd <== /bi…` |
| 911-920-4-4 | 0 | 2 条 | `cat /etc/passwd /bin/cat cat /etc/passwd <== /bi…` |
| 911-920-5-4 | 0 | 6 条 | `cat /etc/passwd /bin/cat cat /etc/passwd <== /bi…` |
| 911-920-6-4 | 0 | 3 条 | `cat /etc/passwd /bin/cat cat /etc/passwd <== /bi…` |
| 911-920-7-4 | 0 | 4 条 | `cat /etc/passwd /bin/cat cat /etc/passwd <== /bi…` |
| 911-920-8-4 | 0 | 2 条 | `cat /etc/passwd /bin/cat cat /etc/passwd <== /bi…` |
| 911-920-9-4 | 0 | 3 条 | `cat /etc/passwd /bin/cat cat /etc/passwd <== /bi…` |
| 911-920-10-4 | 0 | 4 条 | `cat /etc/passwd /bin/cat cat /etc/passwd <== /bi…` |
| 9101-9110-9-4 | 0 | 3 条 | `cat /etc/passwd /bin/cat cat /etc/passwd <== /bi…` |

## 五、前瞻批 data-921-930（未入库，40 行）

### KNOWN 已知家族行（应召回）（21 行）

- 组合 Top-1 命中目标: 21/21 · Top-3: 21/21 · 动作通道命中目标: 21/21

| 单元-行 | 目标 | 动作通道命中(档) | Top1 |
|---|---|---|---|
| 1-1 | CASE-010+CASE-011 | CASE-010(弱)、CASE-011(弱) | CASE-010 |
| 1-2 | CASE-010+CASE-011 | CASE-010(弱)、CASE-011(弱) | CASE-010 |
| 1-3 | CASE-010+CASE-011 | CASE-010(弱)、CASE-011(弱) | CASE-010 |
| 4-1 | CASE-006 | CASE-006(弱)、CASE-003(弱)、CASE-008(弱) | CASE-006 |
| 4-2 | CASE-006 | CASE-006(弱)、CASE-003(弱)、CASE-008(弱) | CASE-006 |
| 4-3 | CASE-006 | CASE-006(弱)、CASE-008(弱) | CASE-006 |
| 6-1 | CASE-006 | CASE-006(中)、CASE-008(弱) | CASE-006 |
| 6-2 | CASE-006 | CASE-006(中)、CASE-008(弱) | CASE-006 |
| 6-3 | CASE-006 | CASE-006(弱)、CASE-008(弱) | CASE-006 |
| 7-1 | CASE-005 | CASE-005(中)、CASE-017(弱) | CASE-005 |
| 7-2 | CASE-005 | CASE-005(中)、CASE-017(弱) | CASE-005 |
| 7-3 | CASE-005 | CASE-005(中)、CASE-017(弱) | CASE-005 |
| 8-1 | CASE-005 | CASE-005(中)、CASE-017(弱) | CASE-005 |
| 8-2 | CASE-005 | CASE-005(中)、CASE-017(弱) | CASE-005 |
| 8-3 | CASE-005 | CASE-005(中)、CASE-017(弱) | CASE-005 |
| 9-1 | CASE-009 | CASE-009(中) | CASE-009 |
| 9-2 | CASE-009 | CASE-009(中) | CASE-009 |
| 9-3 | CASE-009 | CASE-009(弱) | CASE-009 |
| 10-1 | CASE-010+CASE-011 | CASE-010(弱)、CASE-011(弱) | CASE-010 |
| 10-2 | CASE-010+CASE-011 | CASE-010(弱)、CASE-011(弱) | CASE-010 |
| 10-3 | CASE-010+CASE-011 | CASE-010(弱)、CASE-011(弱) | CASE-010 |

### SHARED 部分重叠行（6 行）

- 相关案例进入动作通道: 6/6

| 单元-行 | 相关案例 | 动作通道命中(档) |
|---|---|---|
| 3-1 | CASE-005 | CASE-005(弱)、CASE-017(弱) |
| 3-2 | CASE-005 | CASE-005(弱)、CASE-017(弱) |
| 3-3 | CASE-005 | CASE-005(弱)、CASE-017(弱) |
| 5-1 | CASE-009+CASE-010+CASE-011 | CASE-010(弱)、CASE-011(弱) |
| 5-2 | CASE-009+CASE-010+CASE-011 | CASE-010(弱)、CASE-011(弱) |
| 5-3 | CASE-009+CASE-010+CASE-011 | CASE-010(弱)、CASE-011(弱) |

### NOVEL 全新内容行（期望静默）（3 行）

- 动作通道静默: 3/3 · 中档命中: 0 · 强档误命中: 0

| 单元-行 | 动作通道命中(档) | 备注 |
|---|---|---|
| 2-1 | CASE-009(弱) | K8s 接口 + load_file SQLi（库中无） |
| 2-2 | CASE-009(弱) | 同上 |
| 2-3 | 静默 | cmd_inject';id' + loginNam 截断（库中无） |

### GENERIC 样板行（10 行）

- 动作通道误命中样板行: 0/10


## 六、结论（自动初判口径）

- 已入库重放: 组合 Top-1 99% · Top-3 100% · 动作通道命中 100% · 动作强档 49%（回顾性）。
- 前瞻批见第五节（未入库，成绩即真实召回口径）。

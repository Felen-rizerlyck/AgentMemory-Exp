# Stage 1 · 检索层全量扫描（140 unit，不调用模型）

- 案例库：8 个 pattern；unit：140（含 7 个精确重复）
- 口径：`top1` = 组合排序第一名；`strong` = 全覆盖 + 顺序可判且一致 + ≥1 非通用步

## 一、分组表现

| GT 类别 | n | top1 命中本家族/案例 | strong | medium | weak | keyword_only | 无候选 |
|---|---|---|---|---|---|---|---|
| exact | 7 | 7 | 7 | 0 | 0 | 0 | 0 |
| family_variant | 29 | 13 | 0 | 0 | 16 | 2 | 11 |
| new | 104 | 0 | 0 | 0 | 35 | 20 | 49 |

- **精确重复（T0）**：7/7 得到 strong 且 top1 正确（检索上界）。
- **新家族误匹配**：strong 0/104（0.0%），medium 0（0.0%）。
- **同族变体**：top1 落到本家族 13/29，strong 0（变体被判完整匹配 = 需要人看的点）。

## 二、逐案例召回（exact + same_pattern）

| 案例 | n | top1 | strong | 说明 |
|---|---|---|---|---|
| CASE-001 | 1 | 1 | 1 | 1001 |
| CASE-002 | 1 | 1 | 1 | 1021 |
| CASE-003 | 1 | 1 | 1 | 1042 |
| CASE-004 | 1 | 1 | 1 | 1061 |
| CASE-005 | 1 | 1 | 1 | 1081 |
| CASE-006 | 1 | 1 | 1 | 1102 |
| CASE-007 | 1 | 1 | 1 | 1121 |

## 三、新案例上的软性误匹配（weak / keyword_only 候选）

共 55/104 个新家族 unit 给出了候选（但都不是 strong）：

| unit | top1 | tier | matched | 事例 |
|---|---|---|---|---|
| 1002 | CASE-002 | keyword_only | 0/4 | Spring4Shell CVE-2022-22965（class.mo |
| 1004 | CASE-002 | keyword_only | 0/4 | Confluence OGNL 注入 CVE-2022-26134（do |
| 1005 | CASE-002 | weak | 1/4 | Struts2 S2-045（Content-Type 头 OGNL 表 |
| 1008 | CASE-001 | weak | 1/3 | Apache OFBiz XML-RPC 反序列化 CVE-2023-5 |
| 1009 | CASE-001 | weak | 1/3 | Apache Solr Velocity 模板 RCE CVE-2019 |
| 1010 | CASE-001 | weak | 1/3 | Jenkins CLI 任意文件读取 CVE-2024-23897（@/ |
| 1011 | CASE-004 | keyword_only | 0/4 | PHP 双编码路径穿越（%252e%252e 形态读 /etc/pass |
| 1012 | CASE-004 | keyword_only | 0/4 | PHP-FPM CVE-2019-11043（PATH_INFO 换行注 |
| 1014 | CASE-004 | keyword_only | 0/4 | ThinkPHP 多语言参数 RCE（invokefunction /  |
| 1020 | CASE-004 | weak | 1/4 | Rails Marshal 反序列化（ActiveSupport bas |
| 1022 | CASE-001 | weak | 1/3 | JBoss jmx-console MLet MBean 部署（Html |
| 1023 | CASE-002 | weak | 1/4 | Apache Axis2 admin 上传 aar webshell 部 |
| 1024 | CASE-002 | weak | 1/4 | UEditor 任意文件上传（net controller.ashx c |
| 1025 | CASE-002 | weak | 1/4 | Spring Boot Actuator heapdump 下载后从内存 |
| 1026 | CASE-002 | weak | 1/4 | WebLogic wls-wsat 未授权反序列化（Coordinato |
| 1027 | CASE-002 | weak | 1/4 | Nacos 默认 JWT 密钥伪造 token 后配置注入触发命令执行 |
| 1028 | CASE-002 | weak | 1/4 | Grafana CVE-2024-9264 SQL 表达式命令执行（ap |
| 1029 | CASE-002 | weak | 1/4 | Apache Dubbo Hessian 反序列化（applicatio |
| 1030 | CASE-001 | weak | 1/3 | Jenkins Groovy 脚本控制台命令执行（scriptText） |
| 1031 | CASE-002 | weak | 1/4 | Apache Airflow 示例 DAG 解析 RCE（DagBag  |

## 四、同族变体的落点

| unit | GT 家族 | top1 | tier | matched | 事例 |
|---|---|---|---|---|---|
| 1007 | CASE-001 | CASE-001 | weak | 1/3 | Fastjson autoType（JdbcRowSetImpl J |
| 1013 | CASE-004 | CASE-004 | weak | 0/4 | Laravel Ignition 反序列化 CVE-2021-312 |
| 1018 | CASE-001 | CASE-001 | weak | 2/3 | H2 Console JNDI 驱动加载（/h2-console/l |
| 1035 | CASE-008 | CASE-008 | weak | 1/6 | Exchange ProxyNotShell 风格（autodisc |
| 1047 | CASE-005 | CASE-005 | weak | 1/3 | 日志与卷影清理（wevtutil cl Security + vss |
| 1048 | CASE-002 | CASE-002 | keyword_only | 0/4 | JSP webshell 交互执行（shell.jsp 传 cmd  |
| 1049 |  | CASE-005 | weak | 1/3 | PHP webshell 文件管理动作（?act=upload /  |
| 1050 |  | CASE-008 | keyword_only | 0/6 | ASPX webshell 执行 whoami（cmd.aspx） |
| 1073 | CASE-002 | — | 无候选 |  | Spring4Shell 参数绑定 Tomcat 日志写入 JSP  |
| 1074 | CASE-002 | — | 无候选 |  | Tomcat Manager 未授权 WAR 部署（PUT war  |
| 1082 | CASE-005 | CASE-005 | weak | 1/3 | 凭据复用横向登录文件服务器后关闭恢复环境并加密数据盘 |
| 1083 | CASE-005 | CASE-005 | weak | 1/3 | RDP 弱口令爆破成功后删除备份编录并外传加密密钥 |
| 1084 | CASE-003 | CASE-005 | weak | 1/3 | 注册每日计划任务投放加密脚本并删除 C 盘卷影副本 |
| 1085 | CASE-005 | — | 无候选 |  | PowerShell 载入器清理安全日志并删除卷影后循环加密文档 |
| 1086 | CASE-005 | CASE-005 | weak | 1/3 | 停用 SQL Server 业务服务后删除卷影并加密 MDF 数据文 |
| 1087 | CASE-005 | — | 无候选 |  | 挂载共享盘并删除编录后用 gpg 递归批量加密 Office 文档 |
| 1088 | CASE-005 | — | 无候选 |  | 批量打包加密业务目录并投放 README_RESTORE.txt 说 |
| 1089 | CASE-005 | CASE-005 | weak | 1/3 | 停用实时防护进程后删除卷影并用 cipher 批量加密运维目录 |
| 1090 | CASE-005 | CASE-005 | weak | 1/3 | 通过 wmic 远程节点分发加密器并清除目标主机编录 |
| 1091 | CASE-005 | — | 无候选 |  | 加密完成后删除本地归档备份并 shred 加密脚本与密钥自毁 |
| 1092 | CASE-005 | CASE-002 | weak | 1/4 | 入侵备份服务器删除备份目录与 LVM 快照并外传文件清单 |
| 1093 | CASE-005 | — | 无候选 |  | 停用 mysqld 后删除归档备份并加密 InnoDB 表空间文件 |
| 1094 | CASE-005 | — | 无候选 |  | 删除虚拟机快照后加密 vmdk 镜像文件并清除镜像备份 |
| 1095 | CASE-005 | CASE-005 | weak | 1/3 | 删除卷影副本、全盘加密并投放 !RECOVER!.txt 说明文件 |
| 1096 | CASE-005 | — | 无候选 |  | 配置安全模式启动后删除备份编录并加密数据分区 |
| 1097 | CASE-005 | CASE-005 | weak | 1/3 | PsExec 远程会话投放并运行加密器清空共享目录 |
| 1098 | CASE-005 | CASE-002 | weak | 1/4 | 本地压缩加密后取走备份并删除原始数据目录形成双重破坏 |
| 1099 | CASE-005 | — | 无候选 |  | curl 下载加密脚本落地即执行并删除归档备份目录 |
| 1100 | CASE-005 | — | 无候选 |  | Web 接口触发横向扩散后加密多台主机并清理认证日志 |

## 五、需要人工判断的 unit

| unit | GT | top1 | tier | matched | 事例 |
|---|---|---|---|---|---|

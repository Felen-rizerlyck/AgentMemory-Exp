#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""动作索引构建脚本：为 data/memory_store.json 注入动作库与案例动作序列

机制（详见 主目录 GUIDE.md）:
- action_library: 动作 id -> {label, regex, generic}
  - 动作 = 去变量的攻击指令/行为模板（工具模板），正则即其结构指纹
  - generic=true 标记通用探针（whoami / cmd=id / echo;id 等），单发命中按弱参照处理
- 每案例 action_sequence: 按攻击链顺序排列的动作 id 列表（入库时人工标注，来源=日志可见证据）
- 校验: 正则可编译 / 序列无重复 / 动作均被至少一个案例引用 / 案例均有动作

用法: python scripts/build_action_index.py [--dry-run]
可重复运行（幂等：重写 action_library 与各案例 action_sequence）。
"""
import json
import pathlib
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = pathlib.Path(__file__).resolve().parent.parent
STORE = BASE / "data" / "memory_store.json"

# 取值域（与 src/chain_assembly.py 的 STAGE_ORDER / 来源枚举保持一致）
VALID_STAGES = ("recon", "initial_access", "execution", "privilege",
                "persistence", "lateral", "c2", "exfil")
VALID_SOURCES = ("waf", "web", "rasp", "hids", "dns", "any")

# ---------------- 动作库 ----------------
# label: 中文名（去变量后的动作描述）；regex: 结构正则（锚定特有结构，不锚定通用片段）；
# generic: 是否通用探针（单发命中=弱参照，不单独支撑结论）
ACTIONS = {
    # ---- 共享通用探针（跨案例复用；序列位置决定判别力） ----
    "whoami_probe":          {"label": "whoami 侦察探针", "regex": r"\bwhoami\b", "generic": True},
    "cmd_id_probe":          {"label": "cmd=id 命令探针", "regex": r"cmd=id\b", "generic": True},
    "cmd_loopback_probe":    {"label": "cmd=127.0.0.1;id 命令探针", "regex": r"cmd=127\.0\.0\.1;", "generic": True},
    "echo_id_probe":         {"label": "echo;id 命令探针", "regex": r"echo;id", "generic": True},
    "id_hostname_probe":     {"label": "id;hostname 侦察", "regex": r"id;\s*hostname", "generic": True},
    "smuggle_marker":        {"label": "HTTP 走私形态标记 smuggle", "regex": r"smuggle", "generic": True},
    "sqli_tautology":        {"label": "SQLi 恒真绕过 ' OR '1'='1", "regex": r"'\s*or\s+'?1'?(?:\s*=|$)", "generic": False},
    "java_ser_magic":        {"label": "Java 序列化流魔数 rO0AB", "regex": r"rO0AB", "generic": False},

    # ---- CASE-001 WMIC 横向 ----
    "wmic_remote_exec":      {"label": "WMIC 远程进程创建 (wmic /node:<ip>)", "regex": r"wmic\s+/node:[\d.]+", "generic": False},
    "net_user_add":          {"label": "创建后门账户 (net user /add)", "regex": r"net\s+user\s+/add", "generic": False},
    "net_localgroup_add":    {"label": "账户加入本地组 (net localgroup)", "regex": r"net\s+localgroup\s+ad", "generic": False},

    # ---- CASE-002 DGA ----
    "dga_hex_subdomain":     {"label": "DGA 随机子域查询 (8位hex.<域>)", "regex": r"\b[0-9a-f]{8}\.[a-z0-9-]+\.(net|com|org)\b", "generic": False},

    # ---- CASE-003 Node LFI -> 沙箱逃逸 -> SSRF ----
    "lfi_traversal":         {"label": "路径穿越 (../ 连写)", "regex": r"(?:\.\./){2,}", "generic": False},
    "node_sandbox_escape":   {"label": "Node.js 沙箱逃逸链 (constructor/mainModule)", "regex": r"this\.constructor\.constructor|mainModule\.require", "generic": False},
    "imds_target":           {"label": "SSRF 云元数据 (169.254.169.254)", "regex": r"169\.254\.169\.254", "generic": False},
    "mount_overlay_priv":    {"label": "overlay 挂载提权尝试", "regex": r"mount\s+-t\s+overlay", "generic": False},

    # ---- CASE-004 SSH 横向 ----
    "ssh_landed_key":        {"label": "落地密钥 SSH 登录 (ssh -i <key>)", "regex": r"ssh\s+-i\s+\S+", "generic": False},
    "ssh_no_hostcheck":      {"label": "SSH 免主机校验 (StrictHostKeyChecking=no)", "regex": r"stricthostkeychecking=no", "generic": False},

    # ---- CASE-005 CGI 双编码注入 ----
    "double_encoded_dot":    {"label": "双编码路径穿越 (%%32%65 / .%2e)", "regex": r"%%32%65|%252e|\.%2e", "generic": False},
    "cgi_sh_path":           {"label": "CGI 穿越至 /bin/sh", "regex": r"cgi-bin/.*bin/sh", "generic": False},
    "xp_cmdshell_probe":     {"label": "MSSQL xp_cmdshell 探针", "regex": r"xp_cmdshell\(", "generic": False},

    # ---- CASE-006 Java 反序列化 ----
    "com_sun_gadget":        {"label": "com.sun JNDI gadget 类名", "regex": r"com\.sun", "generic": False},
    "gcp_metadata_ssrf":     {"label": "GCP 元数据 SSRF (metadata.google.internal)", "regex": r"metadata\.google\.internal", "generic": False},

    # ---- CASE-007 SMB 横向 ----
    "net_view_domain":       {"label": "域枚举 (net view /domain)", "regex": r"net\s+view\s+/domain", "generic": False},
    "smb_admin_share":       {"label": "SMB 管理共享挂载 (net use \\\\<ip>\\C$)", "regex": r"net\s+use\s+\\\\[\d.]+\s*\\C\$", "generic": False},

    # ---- CASE-008 SSTI ----
    "ssti_object_chain":     {"label": "SSTI 对象链逃逸 (__class__/__globals__)", "regex": r"\{\{.*__(?:class|globals|init)__", "generic": False},
    "popen_exec":            {"label": "popen 命令执行", "regex": r"popen\(", "generic": False},

    # ---- CASE-009 SQLi 认证绕过 + 批量赋值 ----
    "mass_assignment_admin": {"label": "批量赋值 admin=true", "regex": r"\{\s*\\?\"?admin\\?\"?\s*:\s*true", "generic": False},
    "mysql_load_file":       {"label": "MySQL LOAD_FILE 外读", "regex": r"LOAD_FILE\(", "generic": False},

    # ---- CASE-010 WebLogic ShellSession ----
    "weblogic_shellsession": {"label": "WebLogic MVEL ShellSession 句柄", "regex": r"com\.tangosol\.coherence.{0,60}ShellSession", "generic": False},

    # ---- CASE-011 F5 tmshCmd ----
    "tmui_semicolon_bypass": {"label": "F5 分号路径穿越 (..;/tmui)", "regex": r"\.\.;/tmui", "generic": False},
    "tmshcmd_jsp":           {"label": "F5 tmshCmd 管理接口", "regex": r"tmshCmd\.jsp", "generic": False},
    "tmsh_list_auth":        {"label": "tmsh 账户枚举 (command=list+auth)", "regex": r"command=list\+auth", "generic": False},

    # ---- CASE-012 phar 上传 ----
    "phar_magic":            {"label": "PHP phar 魔数头 (__HALT_COMPILER)", "regex": r"__HALT_COMPILER", "generic": False},
    "phar_filename":         {"label": "phar 伪装上传 (filename=<n>.phar)", "regex": r"filename=\d+\.phar", "generic": False},
    "php_ser_payload":       {"label": "PHP 序列化载荷字段 (AAIJABIAAAA)", "regex": r"AAIJABIAAAA", "generic": False},

    # ---- CASE-013 Spring SpEL ----
    "spring_routing_expr":   {"label": "Spring 路由表达式注入 (routing-expression)", "regex": r"spring\.cloud\.function\.routing-expression", "generic": False},
    "spel_type_ref":         {"label": "SpEL 类型引用链 (java.lang.Runtime)", "regex": r"java\.lang\.Runtime", "generic": False},
    "script_javascript":     {"label": "${script:javascript 脚本变体", "regex": r"\$\{script:javascript", "generic": False},

    # ---- CASE-014 cron 持久化反连 ----
    "cron_root_write":       {"label": "写 root crontab (/var/spool/cron)", "regex": r"/var/spool/cron", "generic": False},
    "bash_reverse_shell":    {"label": "bash -i 反连", "regex": r"bash(\+|\s)-i", "generic": False},
    "dev_tcp_redir":         {"label": "/dev/tcp 反连通道", "regex": r"dev/tcp/", "generic": False},
    "shebang_cmd_inject":    {"label": "cmd_inject=#!//bin/bash 注入标记", "regex": r"cmd_inject[\"']?\s*[:=]\s*[\"']?#!//bin/bash", "generic": False},

    # ---- CASE-015 注册接口组合注入 ----
    "user_register_path":    {"label": "注册接口 /user/register", "regex": r"/user/register", "generic": False},
    "union_select_users":    {"label": "UNION 查询窃取 users 表", "regex": r"UNION\s+SELECT.{0,80}FROM\s+users", "generic": False},

    # ---- CASE-016 /api/exec + cache_key ----
    "api_exec_path":         {"label": "命令执行接口 /api/exec", "regex": r"/api/exec", "generic": False},
    "cache_key_traversal":   {"label": "cache_key 路径穿越", "regex": r"cache_key=\.\./", "generic": False},

    # ---- CASE-017 ThinkPHP 参数覆盖 ----
    "method_construct_override": {"label": "框架 _method=__construct 参数覆盖", "regex": r"_method=__construct", "generic": False},
    "filter_system_override":    {"label": "filter[]=system 过滤执行", "regex": r"filter\[\]=system", "generic": False},
    "time_blind_sleep":          {"label": "时间盲注 SELECT sleep(5)", "regex": r"SELECT sleep\(5\)", "generic": False},
    "server_req_method_probe":   {"label": "server[REQUEST_METHOD] 探针", "regex": r"server\[REQUEST_METHOD\]", "generic": False},

    # ---- CASE-018 XXE ----
    "xxe_doctype":           {"label": "XXE DOCTYPE 声明", "regex": r"<!DOCTYPE", "generic": False},
    "xxe_entity_system":     {"label": "XXE 外部实体 <!ENTITY ... SYSTEM", "regex": r"<!ENTITY\s+\w+\s+SYSTEM", "generic": False},

    # ---- CASE-019 shadow DNS 外传 ----
    "cat_shadow":            {"label": "读取 /etc/shadow", "regex": r"cat\s+/etc/shadow", "generic": False},
    "base64_w0":             {"label": "base64 -w0 编码", "regex": r"base64\s+-w0", "generic": False},
    "fold_w30":              {"label": "fold -w 30 分片", "regex": r"fold\s+-w\s+30", "generic": False},
    "nslookup_var":          {"label": "nslookup $<变量域> 外送", "regex": r"nslookup\s+\$", "generic": False},

    # ---- CASE-020 调度脚本注入 ----
    "dags_run_path":         {"label": "调度接口 /dags/run", "regex": r"dags/run", "generic": False},
    "cmd_inject_semi_id":    {"label": "cmd_inject=;id 命令续接探针", "regex": r"cmd_inject=;id", "generic": False},
    "script_exec_text":      {"label": "脚本内执行并回显 (.execute().text)", "regex": r"execute\(\)\.text", "generic": False},

    # ---- CASE-021 rc.local 持久化 ----
    "rclocal_sed_insert":    {"label": "sed 植入 rc.local 启动项", "regex": r"sed\s+-i.{0,80}rc\.local", "generic": False},
    "tmp_svc_drop":          {"label": "落地 /tmp/.svc", "regex": r"tmp\\?/\.svc", "generic": False},
    "tmp_implant_drop":      {"label": "落地 /tmp/.implant", "regex": r"/tmp/\.implant", "generic": False},
    "rclocal_append":        {"label": "追加写 rc.local", "regex": r">>\s*/etc/rc\.local", "generic": False},

    # ---- CASE-022 fpm_path + xp_dirtree ----
    "fpm_path_param":        {"label": "PHP fpm_path 路径参数", "regex": r"fpm_path", "generic": False},
    "xp_dirtree_unc":        {"label": "MSSQL xp_dirtree UNC 外连", "regex": r"xp_dirtree", "generic": False},

    # ---- CASE-023 Log4Shell JNDI 注入 ----
    "jndi_lookup":           {"label": "JNDI 注入查找 (${jndi:...})", "regex": r"\$\{jndi:(?:ldap|rmi|dns|iiop)", "generic": False},

    # ---- CASE-024 上传目录 JSP webshell ----
    "uploads_jsp_shell":     {"label": "上传目录 JSP webshell (/uploads/*.jsp)", "regex": r"/uploads/[a-z0-9_]+\.jsp", "generic": False},

    # ---- CASE-025 /api/v2/render 反序列化 ----
    "render_api_path":       {"label": "反序列化渲染接口 /api/v2/render", "regex": r"/api/v2/render", "generic": False},

    # ---- CASE-026 /api/v2/search 时间盲注 ----
    "search_api_path":       {"label": "搜索接口 /api/v2/search", "regex": r"/api/v2/search", "generic": False},
    "sqli_and_sleep":        {"label": "盲注 ' AND (SELECT sleep(5))--", "regex": r"'\s*AND\s*\(\s*SELECT\s+sleep\(", "generic": False},

    # ---- CASE-027 Mimikatz 凭据窃取 ----
    "mimikatz_exec":         {"label": "Mimikatz 工具执行 (mimikatz.exe)", "regex": r"\bmimikatz(?:\.exe)?\b", "generic": False},
    "mimikatz_privilege_debug": {"label": "Mimikatz privilege::debug 调试提权", "regex": r"privilege::debug", "generic": False},
    "sekurlsa_logonpasswords": {"label": "Mimikatz sekurlsa::logonpasswords 凭据抓取", "regex": r"sekurlsa::logonpasswords", "generic": False},

    # ---- CASE-028 载荷下载执行链 ----
    "tmp_dot_download":      {"label": "下载载荷落地 /tmp 隐藏文件 (curl/wget -o/-O)", "regex": r"(?:curl|wget)\b[^\n]{0,80}?-[oO]\s+/tmp/\.\w+", "generic": False},
    "chmod_x_tmp_dot":       {"label": "chmod +x 落地 /tmp 隐藏文件", "regex": r"chmod\s+\+x\s+/tmp/\.\w+", "generic": False},
    "exec_tmp_dot":          {"label": "执行落地 /tmp 隐藏文件", "regex": r"&&\s*/tmp/\.\w+", "generic": False},

    # ---- CASE-029 Exchange ProxyLogon 风格利用链（SSRF → IIS 执行 → ASPX webshell → 提权 → 服务持久化 → DNS 外传） ----
    "exch_proxylogon_ssrf":  {"label": "Exchange ProxyLogon SSRF 请求头 (X-BEResource)", "regex": r"x-beresource=", "generic": False},
    "w3wp_spawn_cmd":        {"label": "IIS 工作进程派生 cmd.exe (w3wp→cmd)", "regex": r"w3wp\.exe.{0,120}?cmd\.exe", "generic": False},
    "aspx_shell_path":       {"label": "aspnet_client 目录 ASPX webshell", "regex": r"/aspnet_client/[A-Za-z0-9_/]+\.aspx", "generic": False},
    "printspoofer_priv":     {"label": "PrintSpoofer 提权工具 (SeImpersonate)", "regex": r"printspoofer(?:\.exe)?", "generic": False},
    "sc_create_service":     {"label": "sc create 注册 Windows 服务", "regex": r"sc(?:\.exe)?\s+create\s+\w+\s+binpath=", "generic": False},
    "dns_b64_label_beacon":  {"label": "长 base64 标签 DNS TXT 外传", "regex": r"\b[A-Za-z0-9+/=]{18,}\.[a-z0-9-]+\.[a-z]{2,}\b", "generic": False},
}

# ---------------- 案例动作序列（按攻击链顺序，人工标注自日志证据） ----------------
SEQUENCES = {
    "CASE-001": ["wmic_remote_exec", "whoami_probe", "net_user_add", "net_localgroup_add"],
    "CASE-002": ["dga_hex_subdomain"],
    "CASE-003": ["lfi_traversal", "node_sandbox_escape", "imds_target", "mount_overlay_priv"],
    "CASE-004": ["ssh_landed_key", "ssh_no_hostcheck", "id_hostname_probe"],
    "CASE-005": ["double_encoded_dot", "cgi_sh_path", "echo_id_probe", "xp_cmdshell_probe"],
    "CASE-006": ["java_ser_magic", "cmd_id_probe", "com_sun_gadget", "gcp_metadata_ssrf"],
    "CASE-007": ["net_view_domain", "smb_admin_share"],
    "CASE-008": ["ssti_object_chain", "popen_exec", "java_ser_magic"],
    "CASE-009": ["sqli_tautology", "mass_assignment_admin", "mysql_load_file"],
    "CASE-010": ["cmd_loopback_probe", "weblogic_shellsession"],
    "CASE-011": ["cmd_loopback_probe", "tmui_semicolon_bypass", "tmshcmd_jsp", "tmsh_list_auth"],
    "CASE-012": ["phar_filename", "phar_magic", "sqli_tautology", "php_ser_payload"],
    "CASE-013": ["script_javascript", "spring_routing_expr", "spel_type_ref"],
    "CASE-014": ["cron_root_write", "bash_reverse_shell", "dev_tcp_redir", "shebang_cmd_inject"],
    "CASE-015": ["user_register_path", "shebang_cmd_inject", "union_select_users"],
    "CASE-016": ["api_exec_path", "cmd_id_probe", "cache_key_traversal", "smuggle_marker"],
    "CASE-017": ["method_construct_override", "filter_system_override", "echo_id_probe", "time_blind_sleep", "server_req_method_probe"],
    "CASE-018": ["smuggle_marker", "xxe_doctype", "xxe_entity_system"],
    "CASE-019": ["cat_shadow", "base64_w0", "fold_w30", "nslookup_var"],
    "CASE-020": ["dags_run_path", "cmd_inject_semi_id", "script_exec_text"],
    "CASE-021": ["rclocal_sed_insert", "tmp_svc_drop", "rclocal_append", "tmp_implant_drop"],
    "CASE-022": ["fpm_path_param", "cmd_id_probe", "xp_dirtree_unc"],
    "CASE-023": ["jndi_lookup"],
    "CASE-024": ["uploads_jsp_shell", "cmd_id_probe"],
    "CASE-025": ["render_api_path", "java_ser_magic"],
    "CASE-026": ["search_api_path", "sqli_and_sleep"],
    "CASE-027": ["mimikatz_exec", "mimikatz_privilege_debug", "sekurlsa_logonpasswords"],
    "CASE-028": ["tmp_dot_download", "chmod_x_tmp_dot", "exec_tmp_dot"],
    "CASE-029": ["exch_proxylogon_ssrf", "w3wp_spawn_cmd", "aspx_shell_path",
                 "printspoofer_priv", "sc_create_service", "dns_b64_label_beacon"],
}

# >>> ACTION_SOURCES_BEGIN
# ---------------- 案例动作观测来源（链层来源槽位校验用） ----------------
# 取值: waf / web / rasp / hids / dns / any（any = 不校验）；多来源用列表（任一命中即通过）
# 来源: 由 scripts/derive_action_sources.py 依 dataset/ 与 data/incoming_logs.txt 观测推导（可重跑复核）
# 分支构成: 直接观测 77 / generic→any 12 / 人工覆盖 4 / 回退推断 0（人工覆盖口径见 derive_action_sources.py 的 OVERRIDES）
SOURCES = {
    "CASE-001": {"wmic_remote_exec": "hids", "whoami_probe": "any", "net_user_add": "hids", "net_localgroup_add": "hids"},
    "CASE-002": {"dga_hex_subdomain": "dns"},
    "CASE-003": {"lfi_traversal": ["waf", "web", "rasp"], "node_sandbox_escape": "waf", "imds_target": ["waf", "web", "rasp"], "mount_overlay_priv": ["waf", "web"]},
    "CASE-004": {"ssh_landed_key": "hids", "ssh_no_hostcheck": "hids", "id_hostname_probe": "any"},
    "CASE-005": {"double_encoded_dot": ["waf", "web", "rasp"], "cgi_sh_path": ["waf", "web", "rasp"], "echo_id_probe": "any", "xp_cmdshell_probe": ["waf", "web"]},
    "CASE-006": {"java_ser_magic": ["waf", "rasp"], "cmd_id_probe": "any", "com_sun_gadget": "rasp", "gcp_metadata_ssrf": ["waf", "web"]},
    "CASE-007": {"net_view_domain": "hids", "smb_admin_share": "hids"},
    "CASE-008": {"ssti_object_chain": "waf", "popen_exec": "waf", "java_ser_magic": "waf"},
    "CASE-009": {"sqli_tautology": ["waf", "rasp"], "mass_assignment_admin": "rasp", "mysql_load_file": ["waf", "web"]},
    "CASE-010": {"cmd_loopback_probe": "any", "weblogic_shellsession": ["waf", "web"]},
    "CASE-011": {"cmd_loopback_probe": "any", "tmui_semicolon_bypass": ["waf", "web"], "tmshcmd_jsp": ["waf", "web"], "tmsh_list_auth": ["waf", "web"]},
    "CASE-012": {"phar_filename": ["waf", "web"], "phar_magic": ["waf", "web"], "sqli_tautology": ["waf", "web", "rasp"], "php_ser_payload": "rasp"},
    "CASE-013": {"script_javascript": ["waf", "web"], "spring_routing_expr": "rasp", "spel_type_ref": ["waf", "web"]},
    "CASE-014": {"cron_root_write": ["waf", "web"], "bash_reverse_shell": ["waf", "web"], "dev_tcp_redir": ["waf", "web"], "shebang_cmd_inject": "rasp"},
    "CASE-015": {"user_register_path": ["waf", "web", "rasp"], "shebang_cmd_inject": ["waf", "web", "rasp"], "union_select_users": ["waf", "web"]},
    "CASE-016": {"api_exec_path": ["waf", "web", "rasp"], "cmd_id_probe": "any", "cache_key_traversal": ["waf", "web"], "smuggle_marker": "any"},
    "CASE-017": {"method_construct_override": ["waf", "web", "rasp"], "filter_system_override": ["waf", "web", "rasp"], "echo_id_probe": "any", "time_blind_sleep": ["waf", "web", "rasp"], "server_req_method_probe": ["waf", "web"]},
    "CASE-018": {"smuggle_marker": "any", "xxe_doctype": ["waf", "web"], "xxe_entity_system": ["waf", "web"]},
    "CASE-019": {"cat_shadow": "hids", "base64_w0": "hids", "fold_w30": "hids", "nslookup_var": "hids"},
    "CASE-020": {"dags_run_path": ["waf", "web", "rasp"], "cmd_inject_semi_id": ["waf", "web", "rasp"], "script_exec_text": ["waf", "web"]},
    "CASE-021": {"rclocal_sed_insert": "hids", "tmp_svc_drop": "hids", "rclocal_append": "hids", "tmp_implant_drop": "hids"},
    "CASE-022": {"fpm_path_param": ["waf", "web", "rasp"], "cmd_id_probe": "any", "xp_dirtree_unc": ["waf", "web"]},
    "CASE-023": {"jndi_lookup": "waf"},
    "CASE-024": {"uploads_jsp_shell": "waf", "cmd_id_probe": "any"},
    "CASE-025": {"render_api_path": "waf", "java_ser_magic": "waf"},
    "CASE-026": {"search_api_path": "waf", "sqli_and_sleep": "waf"},
    "CASE-027": {"mimikatz_exec": "hids", "mimikatz_privilege_debug": "hids", "sekurlsa_logonpasswords": "hids"},
    "CASE-028": {"tmp_dot_download": ["waf", "hids"], "chmod_x_tmp_dot": ["waf", "hids"], "exec_tmp_dot": ["waf", "hids"]},
    "CASE-029": {"exch_proxylogon_ssrf": ["waf", "web"], "w3wp_spawn_cmd": "hids", "aspx_shell_path": ["web", "rasp"], "printspoofer_priv": "hids", "sc_create_service": "hids", "dns_b64_label_beacon": "dns"},
}
# <<< ACTION_SOURCES_END

# ---------------- 动作阶段标注（链层 Step5 阶段校验 + 链级输出用） ----------------
# 取值 = STAGE_ORDER（src/chain_assembly.py）: recon / initial_access / execution / privilege
#        / persistence / lateral / c2 / exfil；recon（侦察类）不参与阶段顺序判定。
# 口径: 按动作语义（该动作用于攻击链哪一步）+ 案例证据标注，一次性的小标注任务（非自动推导）。
STAGES = {
    # ---- 共享通用探针（探针=侦察/执行证据） ----
    "whoami_probe": "recon",
    "cmd_id_probe": "execution",
    "cmd_loopback_probe": "execution",
    "echo_id_probe": "execution",
    "id_hostname_probe": "recon",
    "smuggle_marker": "initial_access",
    "sqli_tautology": "initial_access",
    "java_ser_magic": "execution",
    # ---- CASE-001 ~ 010 ----
    "wmic_remote_exec": "lateral",
    "net_user_add": "persistence",
    "net_localgroup_add": "persistence",
    "dga_hex_subdomain": "c2",
    "lfi_traversal": "initial_access",
    "node_sandbox_escape": "execution",
    "imds_target": "execution",
    "mount_overlay_priv": "privilege",
    "ssh_landed_key": "lateral",
    "ssh_no_hostcheck": "lateral",
    "double_encoded_dot": "initial_access",
    "cgi_sh_path": "initial_access",
    "xp_cmdshell_probe": "execution",
    "com_sun_gadget": "execution",
    "gcp_metadata_ssrf": "execution",
    "net_view_domain": "recon",
    "smb_admin_share": "lateral",
    "ssti_object_chain": "execution",
    "popen_exec": "execution",
    "mass_assignment_admin": "privilege",
    "mysql_load_file": "exfil",
    "weblogic_shellsession": "execution",
    # ---- CASE-011 ~ 020 ----
    "tmui_semicolon_bypass": "initial_access",
    "tmshcmd_jsp": "execution",
    "tmsh_list_auth": "recon",
    "phar_magic": "execution",
    "phar_filename": "initial_access",
    "php_ser_payload": "execution",
    "spring_routing_expr": "initial_access",
    "spel_type_ref": "execution",
    "script_javascript": "execution",
    "cron_root_write": "persistence",
    "bash_reverse_shell": "c2",
    "dev_tcp_redir": "c2",
    "shebang_cmd_inject": "execution",
    "user_register_path": "initial_access",
    "union_select_users": "exfil",
    "api_exec_path": "initial_access",
    "cache_key_traversal": "initial_access",
    "method_construct_override": "initial_access",
    "filter_system_override": "execution",
    "time_blind_sleep": "execution",
    "server_req_method_probe": "recon",
    "xxe_doctype": "initial_access",
    "xxe_entity_system": "execution",
    "cat_shadow": "exfil",
    "base64_w0": "exfil",
    "fold_w30": "exfil",
    "nslookup_var": "exfil",
    "dags_run_path": "initial_access",
    "cmd_inject_semi_id": "execution",
    "script_exec_text": "execution",
    # ---- CASE-021 ~ 028 ----
    "rclocal_sed_insert": "persistence",
    "tmp_svc_drop": "persistence",
    "tmp_implant_drop": "persistence",
    "rclocal_append": "persistence",
    "fpm_path_param": "initial_access",
    "xp_dirtree_unc": "exfil",
    "jndi_lookup": "execution",
    "uploads_jsp_shell": "initial_access",
    "render_api_path": "initial_access",
    "search_api_path": "initial_access",
    "sqli_and_sleep": "execution",
    "mimikatz_exec": "execution",
    "mimikatz_privilege_debug": "privilege",
    "sekurlsa_logonpasswords": "exfil",
    "tmp_dot_download": "execution",
    "chmod_x_tmp_dot": "execution",
    "exec_tmp_dot": "execution",
    # ---- CASE-029 ----
    "exch_proxylogon_ssrf": "initial_access",
    "w3wp_spawn_cmd": "execution",
    "aspx_shell_path": "execution",
    "printspoofer_priv": "privilege",
    "sc_create_service": "persistence",
    "dns_b64_label_beacon": "c2",
}


def validate():
    """入库门禁校验：正则编译 / 序列无重复 / 引用完整性 / 覆盖完整性"""
    errors = []
    for aid, a in ACTIONS.items():
        try:
            re.compile(a["regex"], re.IGNORECASE)
        except re.error as e:
            errors.append(f"动作 {aid} 正则不可编译: {e}")
        for k in ("label", "regex", "generic"):
            if k not in a:
                errors.append(f"动作 {aid} 缺字段 {k}")
    for cid, seq in SEQUENCES.items():
        if len(seq) != len(set(seq)):
            errors.append(f"{cid} 序列含重复动作: {seq}")
        for aid in seq:
            if aid not in ACTIONS:
                errors.append(f"{cid} 引用未定义动作: {aid}")
    used = {aid for seq in SEQUENCES.values() for aid in seq}
    unused = set(ACTIONS) - used
    if unused:
        errors.append(f"动作库存在未被任何案例引用的动作: {sorted(unused)}")
    # 阶段标注（STAGES）: 必须与动作库一一对应，取值在枚举内
    if set(STAGES) != set(ACTIONS):
        miss, extra = sorted(set(ACTIONS) - set(STAGES)), sorted(set(STAGES) - set(ACTIONS))
        if miss:
            errors.append(f"动作缺 stage 标注: {miss}")
        if extra:
            errors.append(f"STAGES 含未定义动作: {extra}")
    for aid, st in STAGES.items():
        if st not in VALID_STAGES:
            errors.append(f"动作 {aid} 阶段取值非法: {st}")
    # 来源标注（SOURCES）: 必须与 SEQUENCES 逐案例、逐位置对齐
    if set(SOURCES) != set(SEQUENCES):
        miss, extra = sorted(set(SEQUENCES) - set(SOURCES)), sorted(set(SOURCES) - set(SEQUENCES))
        if miss:
            errors.append(f"案例缺 action_sources 标注: {miss}")
        if extra:
            errors.append(f"SOURCES 含未定义案例: {extra}")
    for cid, seq in SEQUENCES.items():
        srcs = SOURCES.get(cid, {})
        if list(srcs) != list(seq):
            errors.append(f"{cid} SOURCES 与 SEQUENCES 未对齐: {list(srcs)} vs {seq}")
            continue
        for aid, v in srcs.items():
            for x in (v if isinstance(v, list) else [v]):
                if x not in VALID_SOURCES:
                    errors.append(f"{cid}.{aid} 来源取值非法: {x}")
    if errors:
        for e in errors:
            print("校验失败:", e)
        sys.exit(1)
    shared = [a for a in used if sum(1 for s in SEQUENCES.values() if a in s) > 1]
    print(f"校验通过: {len(ACTIONS)} 动作 / {len(SEQUENCES)} 案例序列 / 共享动作 {len(shared)} 个"
          f" / stage 标注 {len(STAGES)} / action_sources {len(SOURCES)} 案例")


def main():
    dry = "--dry-run" in sys.argv
    store = json.loads(STORE.read_text(encoding="utf-8"))
    cases = store["cases"]
    ids = {c["id"] for c in cases}
    missing = set(SEQUENCES) - ids
    if missing:
        print(f"序列引用了库中不存在的案例: {sorted(missing)}")
        sys.exit(1)
    nocover = ids - set(SEQUENCES)
    if nocover:
        print(f"案例缺少动作序列: {sorted(nocover)}")
        sys.exit(1)
    validate()
    store["action_library"] = {aid: dict(a, stage=STAGES[aid]) for aid, a in ACTIONS.items()}
    for c in cases:
        cid = c["id"]
        c["action_sequence"] = SEQUENCES[cid]
        c["action_sources"] = [SOURCES[cid][aid] for aid in SEQUENCES[cid]]
    if dry:
        print("[--dry-run] 不写盘")
        return
    STORE.write_text(json.dumps(store, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已写入 {STORE.name}: action_library({len(ACTIONS)}，含 stage) + "
          f"{len(cases)} 案例 action_sequence + action_sources")


if __name__ == "__main__":
    main()

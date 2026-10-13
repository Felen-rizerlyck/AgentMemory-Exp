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
    "com_sun_gadget":        {"label": "com.sun JNDI gadget 类名", "regex": r"com\.sun\.", "generic": False},
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
    "spel_type_ref":         {"label": "SpEL 类型引用链 (T(java.lang.Runtime))", "regex": r"T\(java\.lang\.Runtime", "generic": False},
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
    "tmp_svc_drop":          {"label": "落地 /tmp/.svc", "regex": r"/tmp/\.svc", "generic": False},
    "tmp_implant_drop":      {"label": "落地 /tmp/.implant", "regex": r"/tmp/\.implant", "generic": False},
    "rclocal_append":        {"label": "追加写 rc.local", "regex": r">>\s*/etc/rc\.local", "generic": False},

    # ---- CASE-022 fpm_path + xp_dirtree ----
    "fpm_path_param":        {"label": "PHP fpm_path 路径参数", "regex": r"fpm_path", "generic": False},
    "xp_dirtree_unc":        {"label": "MSSQL xp_dirtree UNC 外连", "regex": r"xp_dirtree", "generic": False},
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
    if errors:
        for e in errors:
            print("校验失败:", e)
        sys.exit(1)
    print(f"校验通过: {len(ACTIONS)} 动作 / {len(SEQUENCES)} 案例序列 / 共享动作 {len(ACTIONS) - len(used) + len([a for a in used if sum(1 for s in SEQUENCES.values() if a in s) > 1])} 个")


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
    store["action_library"] = ACTIONS
    for c in cases:
        c["action_sequence"] = SEQUENCES[c["id"]]
    if dry:
        print("[--dry-run] 不写盘")
        return
    STORE.write_text(json.dumps(store, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"已写入 {STORE.name}: action_library({len(ACTIONS)}) + {len(cases)} 案例 action_sequence")


if __name__ == "__main__":
    main()

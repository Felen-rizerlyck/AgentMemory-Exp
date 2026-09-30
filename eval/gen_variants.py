#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""eval/gen_variants.py — 评测查询集生成器（确定性、可复现）

输入:
  eval/seed_queries.jsonl   Q-A 种子（archive 原样行 + constructed 合成行）
  eval/relations_gold.json  关系矩阵（用于机械派生 helpful/misleading）
  data/memory_store.json         仅用于 nl_summary 变换读取 attack_type（不读检索键/探测器）

输出:
  eval/queries.jsonl        全量查询（种子 + 机械变异 + 负样本），带标注

规则:
- 变异为确定性文本变换，固定随机种子；不读取 retrieval_keys / pattern_probes（防按检索键定制）。
- qrels 派生: helpful(q) = must 案例在 gold 中的 helpful 邻居；misleading 同理。
- 负样本为合成行（库中无此向量）+ 1 条历史原样未收录行。
"""
import json
import pathlib
import random
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EVAL = pathlib.Path(__file__).parent
BASE = EVAL.parent
RNG = random.Random(20260918)

LETTERS = "abcdefghijklmnopqrstuvwxyz"
DGA_RE = re.compile(r"\b[0-9a-f]{8}\.[a-z0-9-]+\.(net|com|org)\b", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
META_IP = "169.254.169.254"

# ---------------------------------------------------------------- transforms

def t_dga_rename(text, tld=None):
    def cb(m):
        prefix = "%08x" % RNG.randrange(16 ** 8)
        label = "".join(RNG.choice(LETTERS) for _ in range(6)) + "-" + "%04x" % RNG.randrange(16 ** 4)
        return f"{prefix}.{label}.{tld or m.group(1).lower()}"
    return DGA_RE.sub(cb, text)


def t_dga_com(text):
    return t_dga_rename(text, tld="com")


def t_ip_rotate(text):
    def cb(m):
        ip = m.group(0)
        if ip == META_IP or ip.startswith(("127.", "0.", "255.")):
            return ip
        p = ip.split(".")
        p[3] = str((int(p[3]) + 37) % 250 + 1)
        return ".".join(p)
    return IPV4_RE.sub(cb, text)


def t_dbl_traversal(text):
    return text.replace("../", "%%32%65%%32%65%%32%66")


def t_payload_mutate_006(text):
    return text.replace("rO0ABXNyABFqYXZhLnV0aWw=", "rO0ABXNyABpqYXZhLnV0aWwuTWFw==")


def t_payload_mutate_008(text):
    return text.replace('["os"]', '["subprocess"]').replace(".popen(", ".check_output(")


def t_sep_perturb(text):
    return text.replace(" && ", " %26%26 ")


def t_noise_append(text):
    return text + " referer=https://intranet.ops-corp.com/portal xff=198.51.100.9"


def t_probe_alias(text):
    """命令探针别名替换：;id → ;whoami / cmd=id → cmd=whoami（测试探测器对探针命令轮换的泛化）"""
    if ";id" in text:
        return text.replace(";id", ";whoami", 1)
    return text.replace("cmd=id", "cmd=whoami", 1)


def t_exfil_domain_rotate(text):
    """DNS 外传域轮换（保持 $var.domain.tld 形态）"""
    def cb(m):
        return "$svc-" + "%04x" % RNG.randrange(16 ** 4) + "." + \
               "relay-" + "".join(RNG.choice(LETTERS) for _ in range(4)) + ".net"
    return re.sub(r"\$[A-Za-z0-9][A-Za-z0-9\-]*(?:\.[A-Za-z0-9\-]+)+", cb, text)


def t_rc_payload_swap(text):
    """rc.local 落地文件名轮换：/tmp/.svc → /tmp/.srv2（兼容日志中的 \\/ 转义写法）"""
    return text.replace(".svc", ".srv2")


ADMIN_RE = re.compile(r'\\?"?admin\\?"?\s*:\s*true')


def t_url_encode_admin(text):
    return ADMIN_RE.sub("%22admin%22%3Atrue", text)


def t_nl_summary(text, case):
    at = case.get("attack_type", "")
    return f"分析请求：观察到疑似「{at}」的活动，请判断属于哪类攻击并给出依据。"


TRANSFORMS = {
    "dga_rename": t_dga_rename,
    "dga_com": t_dga_com,
    "ip_rotate": t_ip_rotate,
    "dbl_traversal": t_dbl_traversal,
    "payload_mutate_006": t_payload_mutate_006,
    "payload_mutate_008": t_payload_mutate_008,
    "sep_perturb": t_sep_perturb,
    "noise_append": t_noise_append,
    "url_encode_admin": t_url_encode_admin,
    "nl_summary": t_nl_summary,
    "probe_alias": t_probe_alias,
    "exfil_domain_rotate": t_exfil_domain_rotate,
    "rc_payload_swap": t_rc_payload_swap,
}

INVARIANCE = {
    "dga_rename": "must_hit", "dga_com": "must_hit",
    "payload_mutate_006": "must_hit", "payload_mutate_008": "must_hit",
    "noise_append": "must_hit", "sep_perturb": "must_hit",
    "ip_rotate": "may_degrade", "dbl_traversal": "may_degrade", "url_encode_admin": "may_degrade",
    "nl_summary": "nl_probe",
    "probe_alias": "may_degrade", "exfil_domain_rotate": "must_hit", "rc_payload_swap": "may_degrade",
}

PLAN = {
    "A-01": [("ip_rotate", {}), ("nl_summary", {"case": "CASE-001"})],
    "A-02": [("dga_rename", {}), ("nl_summary", {"case": "CASE-002"})],
    "A-03": [("dbl_traversal", {}), ("nl_summary", {"case": "CASE-003"})],
    "A-04": [("noise_append", {})],
    "A-05": [("ip_rotate", {}), ("nl_summary", {"case": "CASE-004"})],
    "A-06": [("dga_rename", {})],
    "A-08": [("noise_append", {}), ("nl_summary", {"case": "CASE-009"})],
    "A-09": [("url_encode_admin", {})],
    "A-10": [("ip_rotate", {})],
    "A-11": [("dga_rename", {})],
    "A-12": [("dga_com", {})],
    "A-13": [("noise_append", {})],
    "S-01B": [("sep_perturb", {})],
    "S-05": [("noise_append", {}), ("nl_summary", {"case": "CASE-005"})],
    "S-06": [("payload_mutate_006", {}), ("nl_summary", {"case": "CASE-006"})],
    "S-07": [("ip_rotate", {}), ("nl_summary", {"case": "CASE-007"})],
    "S-08": [("payload_mutate_008", {}), ("nl_summary", {"case": "CASE-008"})],
    # ---- 第二轮扩充：新案例种子变体 ----
    "A-U02-E1": [("noise_append", {}), ("probe_alias", {})],
    "A-U03-E1": [("noise_append", {})],
    "A-U04-E1": [("noise_append", {})],
    "A-U05-E1": [("noise_append", {})],
    "A-U06-E1": [("noise_append", {})],
    "A-U07-E1": [("noise_append", {})],
    "A-U08-E1": [("noise_append", {}), ("probe_alias", {})],
    "A-U09-E1": [("noise_append", {})],
    "A-U10-E1": [("noise_append", {})],
    "A-U11-E1": [("noise_append", {})],
    "A-U12-E1": [("noise_append", {})],
    "A-U16-E1": [("noise_append", {})],
    "A-U18-E1": [("noise_append", {})],
    "A-U11-E4": [("exfil_domain_rotate", {}), ("noise_append", {})],
    "A-U14-E1": [("noise_append", {})],
    "A-U14-E4": [("exfil_domain_rotate", {})],
    "A-U16-E4": [("rc_payload_swap", {})],
    "A-U17-E1": [("noise_append", {})],
    "A-U17-E4": [("noise_append", {})],
}

NEGATIVES = [
    ("N-01", "stratum+tcp://pool.supportxmr.com:3333 xmrig --donate-level 1 gpu0 10.30.22.61",
     "合成负样本：挖矿（库中无此向量）"),
    ("N-02", "SMTP mail-gw02 inbound from ceo@exfil-doc.example subject=\"Urgent Invoice\" attachment=INV0098.zip macro AutoOpen wscript",
     "合成负样本：钓鱼邮件（库中无此向量）"),
    ("N-03", "HIDS burst file rename 2143 files *.docx -> *.locked ransomnote README_RESTORE.txt user=svc_backup",
     "合成负样本：勒索行为（库中无此向量）"),
    ("N-04", "telnetd auth failure user=root source=198.51.100.77 attempts=312 port=23",
     "合成负样本：IoT 暴力破解（库中无此向量）"),
    ("N-05", "DNS TXT dGVzdC1leGZpbHRyYXRpb24.tunnel-relay.example from 10.30.6.77 len=182 repeats=48",
     "合成负样本：DNS 隧道（库中无此向量）"),
    ("N-06", "GET /admin.php /backup/db.sql /.git/config /.env 404 403 200 UA=dirbuster scanner scan",
     "合成负样本：目录扫描（库中无此向量）"),
    ("N-07", "PUT /upload/file.jsp <%Runtime.getRuntime().exec(request.getParameter(\"cmd\"))%> 200 app-tomcat-77.ops-corp.com",
     "合成负样本：JSP webshell 上传（库中无此向量）"),
    ("N-08", "NetrServerAuthenticate3 machine=DC01$ CVE-2020-1472 zerologon attempts=8 windows",
     "合成负样本：Zerologon（库中无此向量）"),
    ("N-09", "vssadmin delete shadows /all /quiet",
     "历史批次原样行：未收录向量（勒索恢复抑制），负样本"),
]


def load_jsonl(path):
    return [json.loads(l) for l in pathlib.Path(path).read_text(encoding="utf-8").splitlines() if l.strip()]


def main():
    seeds = load_jsonl(EVAL / "seed_queries.jsonl")
    gold = json.loads((EVAL / "relations_gold.json").read_text(encoding="utf-8"))
    store = json.loads((BASE / "data/memory_store.json").read_text(encoding="utf-8"))
    case_by_id = {c["id"]: c for c in store["cases"]}

    help_adj, mis_adj = {}, {}
    for p in gold["pairs"]:
        for x, y in ((p["a"], p["b"]), (p["b"], p["a"])):
            if p["tier"] == "helpful":
                help_adj.setdefault(x, set()).add(y)
            if p["tier"] == "misleading":
                mis_adj.setdefault(x, set()).add(y)

    def qrels_for(must):
        h, m = set(), set()
        for c in must:
            h |= help_adj.get(c, set())
            m |= mis_adj.get(c, set())
        h -= set(must)
        return sorted(h), sorted(m)

    queries = []

    # 1) 种子
    for s in seeds:
        h, m = qrels_for(s["must"])
        group = "A-archive" if s["origin"] == "archive" else "A-constructed"
        queries.append({
            "qid": f"Q-{s['sid']}", "group": group, "source": s["origin"],
            "text": s["text"], "must": s["must"], "helpful": h, "misleading": m,
            "variant_of": s["must"][0] if s["must"] else None,
            "transform": "seed", "invariance": "baseline", "note": s.get("note", ""),
        })

    # 2) 变异
    seed_by_sid = {s["sid"]: s for s in seeds}
    for sid, plan in PLAN.items():
        s = seed_by_sid[sid]
        if not s:
            print("WARN: plan for unknown sid", sid)
            continue
        for name, kw in plan:
            kw = dict(kw)
            if name == "nl_summary" and isinstance(kw.get("case"), str):
                kw["case"] = case_by_id.get(kw["case"], {})
            text = TRANSFORMS[name](s["text"], **kw)
            if text == s["text"]:
                print(f"WARN: transform {name} on {sid} produced no change")
            inv = INVARIANCE[name]
            group = "B-nl" if inv == "nl_probe" else ("B-must_hit" if inv == "must_hit" else "B-may_degrade")
            h, m = qrels_for(s["must"])
            queries.append({
                "qid": f"Q-{sid}-{name}", "group": group, "source": "variant",
                "text": text, "must": list(s["must"]), "helpful": h, "misleading": m,
                "variant_of": s["must"][0] if s["must"] else None,
                "transform": name, "invariance": inv,
                "note": f"变异自 {sid}（{s.get('note','')}）",
            })

    # 3) 负样本
    for nid, text, note in NEGATIVES:
        queries.append({
            "qid": f"Q-{nid}", "group": "C-negative", "source": "negative",
            "text": text, "must": [], "helpful": [], "misleading": [],
            "variant_of": None, "transform": "none", "invariance": "no_match", "note": note,
        })

    out = EVAL / "queries.jsonl"
    with out.open("w", encoding="utf-8") as f:
        for q in queries:
            f.write(json.dumps(q, ensure_ascii=False) + "\n")

    from collections import Counter
    grp = Counter(q["group"] for q in queries)
    print(f"queries.jsonl written: {len(queries)} queries")
    for g, n in sorted(grp.items()):
        print(f"  {g}: {n}")


if __name__ == "__main__":
    main()

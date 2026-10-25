#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""build_scenario2_chains.py —— 把场景二多源日志按攻击链组装成旧格式的 unit

思路：
  1. 从 labels/*.csv（GT）取出每个 test 的实体：异常账号、来源 IP、关联主机（含主机 IP）；
  2. 扫描该 test 的文本日志（logs/，不含 host_artifacts/meta），按格式解析成 (ts, source, text)；
  3. 保留提到任一实体的行 → 按时间排序 → 去重 → 截断到 max_lines；
  4. 输出旧格式 unit（`n. \\`ts\\` **[source]** \\`LOGID\\`` + 4 空格缩进内容）；
  5. GT 单独写到 gt/ 下，**不进入 data 目录**。

用法：python build_scenario2_chains.py [--only test_01] [--max-lines 30] [--out <dir>]
"""
import argparse
import csv
import io
import json
import pathlib
import re
import sys
from datetime import datetime, timezone, timedelta

BASE = pathlib.Path(__file__).resolve().parents[3]
NEW = BASE / "eval" / "usability_ablation" / "场景二_14源日志_18例_202607"
DEFAULT_OUT = BASE / "eval" / "usability_ablation" / "场景二_攻击链_202607"

FOLDERS = {}


def folder_of(test):
    if not FOLDERS:
        for d in (NEW / "logs").iterdir():
            m = re.match(r"(test_\d+)_", d.name)
            if m and d.is_dir():
                FOLDERS[m.group(1)] = d
    return FOLDERS[test]


TAG = {"W": "waf", "A": "net", "D": "rasp", "E": "edr", "T": "win", "L": "auditd", "N": "syslog",
       "B": "bastion", "V": "vpn", "C": "container", "G": "gitlab", "I": "jenkins", "J": "db", "M": "mail"}

TS_PATTERNS = [
    re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    re.compile(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?)"),
    re.compile(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]"),
    re.compile(r"audit\((\d{9,11})\.\d+:"),
    re.compile(r"^(?:\w{3}\s+\d{1,2}\s+(\d{1,2}:\d{2}:\d{2}))"),
    re.compile(r"^(\d{2}:\d{2}:\d{2}(?:\.\d+)?)"),
]


def read_text(p: pathlib.Path) -> str:
    raw = p.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "gbk", "gb18030", "utf-16"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", "replace")


def parse_ts(s: str, day: str):
    s = s.strip()
    try:
        if re.fullmatch(r"\d{9,11}", s):
            return datetime.fromtimestamp(int(s), tz=timezone(timedelta(hours=8)))
        if re.fullmatch(r"\d{2}:\d{2}:\d{2}(\.\d+)?", s):
            return datetime.fromisoformat(f"{day}T{s}+08:00")
        if re.fullmatch(r"\d{1,2}:\d{2}:\d{2}", s):
            return datetime.fromisoformat(f"{day}T{int(s.split(':')[0]):02d}:{s.split(':',1)[1]}+08:00")
        t = s.replace("Z", "+08:00")   # 场景二的 T_*.log 用 Z 但实际是本地时间（与 B/E 同钟）
        t = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", t)
        dt = datetime.fromisoformat(t)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone(timedelta(hours=8)))
    except Exception:
        return None


def render_obj(o, letter):
    """把一条 JSON 事件压成一行可读文本（保留判读所需字段）"""
    if isinstance(o.get("rule"), dict):
        ag = o.get("agent") or {}
        d = (o.get("data") or {}).get("audit") or {}
        parts = [f"host={ag.get('name','')}", f"ip={ag.get('ip','')}",
                 f"rule={o['rule'].get('description','')}", f"level={o['rule'].get('level','')}"]
        for k in ("comm", "exe", "path", "nametype", "auid", "uid", "key", "syscall"):
            if d.get(k):
                parts.append(f"{k}={d[k]}")
        return " ".join(x for x in parts if not x.endswith("="))
    keys = [k for k in ("session_id", "url", "method", "status", "remote", "path", "user", "account",
                        "src_ip", "username", "event_type", "action", "resource", "operation",
                        "process", "command_line", "parent_process", "host_name", "host_ip",
                        "login_user", "message", "subject", "attachment", "sender", "recipient")
            if k in o]
    if keys:
        return " ".join(f"{k}={o[k]}" for k in keys if o[k] not in (None, "", [], {}))
    return json.dumps(o, ensure_ascii=False)[:220]


def entries_of(p: pathlib.Path, day: str):
    """返回 [(ts, source_letter, text)]"""
    letter = p.name[0] if p.name[:1].isupper() else ""
    ext = p.suffix.lower()
    txt = read_text(p)
    out = []

    def add(ts_s, text):
        ts = parse_ts(ts_s, day) if ts_s else None
        if ts and text.strip():
            out.append((ts, letter, " ".join(text.split())))

    if letter == "B" and ext == ".log":                      # 六行一组的会话
        for block in re.split(r"\n\s*\n", txt):
            if "time=" not in block:
                continue
            kv = dict(re.findall(r"(\w+)=([^\n]*)", block))
            add(kv.get("time"), f"account={kv.get('account')} src={kv.get('src')} target={kv.get('target')} {kv.get('action','')}")
    elif ext == ".jsonl":
        for line in txt.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                add((TS_PATTERNS[0].search(line) or TS_PATTERNS[1].search(line) or [None, ""])[1], line)
                continue
            ts = next((o[k] for k in ("_ts", "timestamp", "event_time", "receive_time", "generate_time", "time")
                       if isinstance(o.get(k), str)), "")
            add(ts, line)
    elif ext == ".json":
        dec = json.JSONDecoder()
        i, n = 0, len(txt)
        while i < n:
            while i < n and txt[i] in " \r\n\t":
                i += 1
            if i >= n:
                break
            try:
                o, j = dec.raw_decode(txt, i)
            except Exception:
                break
            i = j
            objs = o if isinstance(o, list) else ([o] if isinstance(o, dict) else [])
            for ob in objs:
                if not isinstance(ob, dict):
                    continue
                ts = next((ob[k] for k in ("timestamp", "event_time", "@timestamp", "Created", "time")
                           if isinstance(ob.get(k), str)), "")
                if "events" in ob and isinstance(ob["events"], list):
                    for ev in ob["events"]:
                        if isinstance(ev, dict):
                            add(ev.get("event_time") or ts, json.dumps(ev, ensure_ascii=False))
                else:
                    add(ts, render_obj(ob, letter))
    elif ext == ".csv":
        rows = list(csv.reader(io.StringIO(txt)))
        if not rows:
            return out
        hdr = rows[0]
        for r in rows[1:]:
            if not any(r):
                continue
            kv = "; ".join(f"{h}={v}" for h, v in zip(hdr, r) if v)
            ts = next((v for h, v in zip(hdr, r)
                       if h.strip().lower() in ("event_time", "时间", "receive_time", "time")), "")
            add(ts, kv)
    else:                                                    # 纯文本：逐行
        for line in txt.splitlines():
            if not line.strip():
                continue
            m = next((pat.search(line) for pat in TS_PATTERNS if pat.search(line)), None)
            add(m.group(1) if m else "", line)
    return out


def load_gt():
    """读 labels/*.csv（GBK），按 test 聚合"""
    gt = {}
    for f in sorted((NEW / "labels").glob("*.csv")):
        txt = read_text(f)
        rows = [r for r in csv.reader(io.StringIO(txt)) if any(r)]
        if not rows:
            continue
        hdr, body = rows[0], rows[1:]
        m = re.match(r"(test_\d+)_(P\d+)", f.name)
        test, pc = m.group(1), f.name.split("__")[-1].replace(".csv", "")
        d = gt.setdefault(test, {"pcode": pc, "rows": []})
        for r in body:
            d["rows"].append(dict(zip(hdr, r)))
    return gt


def entities_of(row, hosts_ip):
    """按答案列语义拆出：攻击源 IP / 账号 / 主机（名与 IP）/ 证据文件"""
    def vals(keyword):
        out = []
        for h, v in row.items():
            if v and keyword in (h or ""):
                out += [x.strip() for x in re.split(r"[;,]", v) if x.strip()]
        return out

    def ips(tokens):
        return {x for x in tokens if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", x)}

    atk = ips(vals("来源") + vals("攻击源") + vals("跳板"))
    host_tokens = vals("主机") + vals("资产") + vals("节点") if not vals("关联主机") else vals("关联主机")
    host_tokens += vals("资产IP") + vals("受影响资产IP")
    hosts = {t for t in host_tokens if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", t)}
    hosts = {re.sub(r"（.*?）", "", h).strip() for h in hosts if h}
    hosts = {h for h in hosts if re.fullmatch(r"[A-Za-z0-9_.\-]{3,40}", h)}
    accts = {a for a in vals("账号") if re.fullmatch(r"[A-Za-z0-9_.\\@\-]{3,40}", a)}
    ev = {x for x in vals("关联数据编号") if re.search(r"^[A-Z]_\d{14}_\d{6}_\d+\.\w+$", x)}
    return atk, accts, hosts, ev


def ip_hit(ip, text):
    return re.search(r"(?<![\d.])" + re.escape(ip) + r"(?![\d.])", text) is not None


SUSPICIOUS = ("session_restore", "tar", "upload", "collect", "exec", "exfil", "tunnel", "webshell",
              "reverse", "scan", "dump", "chmod", "crontab", "schtasks", "vssadmin", "cipher",
              "curl", "wget", "base64", "whoami", "sudo", "net user", "kerberoast", "mimikatz",
              "procdump", "7z", "zip", "rar", "scp", "rsync", "nc ", "ncat")


def build(test, max_lines, truncate):
    gt = load_gt()
    rows = gt[test]["rows"]
    # 先收集 host→ip
    hosts_ip = {}
    for p in folder_of(test).iterdir():
        if p.suffix.lower() in (".json", ".jsonl", ".csv"):
            for ts, letter, text in entries_of(p, "2026-07-14"):
                for hn, ip in re.findall(r'(?:host_name|主机名|host|agent_name)"?[:=] ?"?([A-Za-z0-9-]{4,20})"?[;, ].{0,40}?"?((?:\d{1,3}\.){3}\d{1,3})', text):
                    hosts_ip.setdefault(hn.upper(), ip)
    att_ips, accts, host_ents, ev_files = set(), set(), set(), set()
    for r in rows:
        a, c, h, e = entities_of(r, hosts_ip)
        att_ips |= a; accts |= c; ev_files |= e
        for hn in h:
            host_ents.add(hn.lower())
            host_ents.add(hosts_ip.get(hn.upper(), "").lower())
    host_ents.discard("")
    ents = {x.lower() for x in att_ips} | {x.lower() for x in accts} | host_ents
    cand = []
    for p in sorted(folder_of(test).iterdir()):
        if p.suffix.lower() not in (".log", ".txt", ".jsonl", ".json", ".csv"):
            continue
        for ts, letter, text in entries_of(p, "2026-07-14"):
            low = text.lower()
            n_ip = sum(1 for i in att_ips if ip_hit(i, text))
            n_ent = sum(1 for a in ents if a and a in low and a not in att_ips)
            susp = any(k in low for k in SUSPICIOUS)
            n_acct = sum(1 for a in accts if a.lower() in low)
            if n_ip:
                cand.append(dict(ts=ts, letter=letter, text=text[:240], k="strong"))
            elif n_acct and susp:
                cand.append(dict(ts=ts, letter=letter, text=text[:240], k="mid"))
            elif susp or n_acct or n_ent:
                cand.append(dict(ts=ts, letter=letter, text=text[:240], k="weak"))
    strong = sorted([c for c in cand if c["k"] in ("strong", "mid")], key=lambda x: x["ts"])
    weak = sorted([c for c in cand if c["k"] == "weak"], key=lambda x: x["ts"])
    if strong:                             # 弱命中只保留在强命中时间窗 ±10 分钟内的
        lo, hi = strong[0]["ts"] - timedelta(minutes=5), strong[-1]["ts"] + timedelta(minutes=5)
        weak = [c for c in weak if lo <= c["ts"] <= hi]
    weak = weak[:4]
    seen, sel = set(), []
    for pool in (strong, weak):
        for c in pool:
            k = (c["ts"].isoformat(), c["text"][:100])
            if k in seen:
                continue
            seen.add(k); sel.append(c)
            if len(sel) >= max_lines:
                break
        if len(sel) >= max_lines:
            break
    sel.sort(key=lambda x: x["ts"])
    if len(sel) < 5:      # 兜底：文本证据文件里带可疑动作的行补上下文
        extra = []
        for p in sorted(folder_of(test).iterdir()):
            if p.name not in ev_files or p.suffix.lower() not in (".log", ".txt", ".jsonl", ".json", ".csv"):
                continue
            for ts, letter, text in entries_of(p, "2026-07-14"):
                if any(k in text.lower() for k in SUSPICIOUS):
                    extra.append(dict(ts=ts, letter=letter, text=text[:240], k="fill"))
        extra.sort(key=lambda x: x["ts"])
        have = {(c["ts"].isoformat(), c["text"][:100]) for c in sel}
        for c in extra:
            if (c["ts"].isoformat(), c["text"][:100]) in have:
                continue
            sel.append(c)
            if len(sel) >= 8:
                break
        sel.sort(key=lambda x: x["ts"])
    return sel, ents, ev_files


def fmt_unit(idx, entries, truncate):
    lines = []
    counters = {}
    for n, e in enumerate(entries, 1):
        tag = TAG.get(e["letter"], "misc")
        counters[tag] = counters.get(tag, 0) + 1
        logid = f"{tag.upper()}{counters[tag]:07d}"
        text = e["text"] if not truncate else e["text"][:truncate]
        lines.append(f"{n}. `{e['ts'].strftime('%Y-%m-%d %H:%M:%S')}` **[{tag}]** `{logid}`")
        lines.append(f"    `{text}`")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--max-lines", type=int, default=30)
    ap.add_argument("--truncate", type=int, default=0)
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    a = ap.parse_args()
    out = pathlib.Path(a.out)
    (out / "data").mkdir(parents=True, exist_ok=True)
    (out / "gt").mkdir(exist_ok=True)
    gt = load_gt()
    tests = [a.only] if a.only else sorted(gt)
    report, units = {}, []
    for i, test in enumerate(tests):
        unit = 2001 + i
        sel, ents, ev = build(test, a.max_lines, a.truncate)
        report[test] = dict(unit=unit, lines=len(sel), entities=sorted(ents)[:8], evidence=len(ev),
                            pcode=gt[test]["pcode"])
        units.append((unit, test, sel))
        print(f"unit {unit} ← {test}: {len(sel)} 行 | 证据文件 {len(ev)}")
        if a.only:
            print(fmt_unit(1, sel, a.truncate))
    if not a.only:
        # 数据文件：每 10 个 unit 一个文件，编号 2001 起
        for start in range(0, len(units), 10):
            chunk = units[start:start + 10]
            name = f"data-{chunk[0][0]}-{chunk[-1][0]}.txt"
            body = "\n\n".join(fmt_unit(u, sel, a.truncate) for u, _, sel in chunk)
            (out / "data" / name).write_text(body + "\n", encoding="utf-8")
            print("写出", name, len(chunk), "个 unit")
        umap = {}
        for u, t, sel in units:
            atk, accts, hosts, ev = set(), set(), set(), set()
            for r in gt[t]["rows"]:
                a, c, h, e = entities_of(r, {})
                atk |= a; accts |= c; hosts |= h; ev |= e
            umap[str(u)] = dict(unit=u, test=t, pcode=report[t]["pcode"], lines=len(sel),
                                attacker_ips=sorted(atk), accounts=sorted(accts),
                                hosts=sorted(hosts), evidence_files=sorted(ev),
                                answer_rows=gt[t]["rows"])
        json.dump(dict(schema="scenario2-chain-gt-v1",
                       note="unit→test 映射与标准答案；只放在 gt/ 下，严禁放进 data/ 或提示词",
                       units=umap), open(out / "gt" / "unit_map.json", "w", encoding="utf-8"),
                  ensure_ascii=False, indent=1)
        json.dump(report, open(out / "gt" / "_build_report.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()

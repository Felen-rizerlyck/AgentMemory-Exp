#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""dataset/gen/render_families.py —— 第二批「新攻击家族」渲染器（unit 1081~1140，2026-07 窗口）

与 render_chains.py（batch-1，1001~1080 / 2026-06）刻意分开：不动已交付的 batch-1 文件。
本批三份数据三个家族：
    FA 勒索与数据破坏链      data-1081-1100.txt   form5.json
    FB 域环境身份攻击链      data-1101-1120.txt   form6.json
    FC 供应链与 CI/CD 投毒链 data-1121-1140.txt   form7.json

机械面与 batch-1 一致（同一套 110 截断/UA/主机名/dns 三连规则），差别：
  - 时间窗口 2026-07-01 ~ 07-31（接在 batch-1 之后，日期仍与文件顺序无关）
  - log_id 接着 batch-1 各源上界往后走（SRC_BASE 读 batch2_bases.json），绝不复用
  - shape 白名单按家族给（含纯主机链、三 hids 链），无 waf/web/rasp 的 unit 允许 path/carrier 为空

用法: python dataset/gen/render_families.py [--out dataset] [--seed 20260701]
"""
import argparse
import datetime as dt
import json
import pathlib
import random
import re
import sys

GEN = pathlib.Path(__file__).resolve().parent
ROOT = GEN.parent.parent

FAMILIES = [
    ("FA", 1081, "data-1081-1100.txt", 5, "勒索与数据破坏链"),
    ("FB", 1101, "data-1101-1120.txt", 6, "域环境身份攻击链（AD/Kerberos）"),
    ("FC", 1121, "data-1121-1140.txt", 7, "供应链与 CI/CD 投毒链"),
]
WINDOW_START = dt.datetime(2026, 7, 1, 0, 0, 0)
WINDOW_END = dt.datetime(2026, 7, 31, 23, 59, 59)
SOURCE_T0 = WINDOW_START
CAP = 110
PREFIX = {"waf": "WAF", "web": "WEB", "rasp": "RASP", "hids": "HID", "dns": "DNS"}

SHAPES = [  # §8.2 白名单
    ["hids"], ["hids", "hids"], ["hids", "hids", "hids"],
    ["hids", "dns", "dns", "dns"], ["hids", "hids", "dns", "dns", "dns"],
    ["rasp", "hids"], ["rasp", "hids", "hids"],
    ["waf", "web", "rasp", "hids"], ["waf", "web", "rasp", "hids", "hids"],
    ["waf", "web", "rasp", "hids", "dns", "dns", "dns"], ["waf", "hids"],
]
WEB_SHAPES = [s for s in SHAPES if {"waf", "web", "rasp"} & set(s)]
HOST_ONLY = [s for s in SHAPES if not ({"waf", "web", "rasp"} & set(s))]


def load_forms():
    out = {}
    for fam, uid0, fname, n, title in FAMILIES:
        p = GEN / f"form{n}.json"
        if not p.exists():
            raise SystemExit(f"缺少内容文件: {p}（等待作者产出）")
        scen = json.loads(p.read_text(encoding="utf-8"))["scenarios"]
        assert len(scen) == 20, f"{p.name} 需要 20 个 unit，实际 {len(scen)}"
        assert sorted(s["idx"] for s in scen) == list(range(1, 21)), f"{p.name} idx 必须 1..20"
        for s in scen:
            assert s["shape"] in SHAPES, f"{p.name} idx{s['idx']} shape {s['shape']} 不在 §8.2 白名单"
        out[fam] = sorted(scen, key=lambda s: s["idx"])
    return out


def unit_duration(scen):
    shape, dur, seen = scen["shape"], 0.0, 0
    for pos, src in enumerate(shape):
        if pos == 0:
            continue
        if src == "dns":
            dur += float(scen["dns_gap_h"]) * 3600 if seen == 0 else float(scen["dns_steps"][seen - 1])
            seen += 1
        else:
            dur += int(scen["deltas"][pos])
    return dur


def dns_ip(rng, is_doc):
    if is_doc:
        pre, lo = random.choice([("203.0.113.", 35), ("192.0.2.", 28), ("198.51.100.", 22)])
        return f"{pre}{rng.randint(lo, lo + 120)}"
    return f"10.10.{rng.randint(23, 49)}.{rng.randint(2, 250)}"


def render_unit(uid, scen, rng, uas):
    shape = scen["shape"]
    deltas = list(scen["deltas"])
    assert len(deltas) == len(shape), f"unit {uid} deltas 长度 != shape 长度"
    assert deltas[0] == 0, f"unit {uid} deltas[0] 必须 0"
    n_dns = shape.count("dns")
    dns_rows = []
    if n_dns:
        doc_at = rng.randrange(n_dns)
        subs = rng.sample(range(16 ** 8), n_dns)
        dns_rows = [f"{subs[k]:08x}.{scen['dns_base']} A {dns_ip(rng, k == doc_at)}" for k in range(n_dns)]
    avail = int((WINDOW_END - WINDOW_START).total_seconds() - unit_duration(scen))
    assert avail > 0, f"unit {uid} 链时长超过窗口"
    t = WINDOW_START + dt.timedelta(seconds=rng.randrange(avail))
    ua = uas[scen["ua"]]
    host = f"app-{scen['stack']}-{scen['host_num']}.ops-corp.com"
    rows, tcur, hidx, seen_dns = [], t, 0, 0
    for pos, src in enumerate(shape):
        if pos > 0:
            if src == "dns":
                tcur += dt.timedelta(hours=float(scen["dns_gap_h"])) if seen_dns == 0 \
                    else dt.timedelta(seconds=float(scen["dns_steps"][seen_dns - 1]))
            else:
                tcur += dt.timedelta(seconds=int(deltas[pos]))
        if src in ("waf", "web"):
            content = f"{scen['path']} {scen['carrier']} {ua}"[:CAP]
        elif src == "rasp":
            content = f"https://{host}{scen['path']} {scen['rasp_evidence']} {ua}"[:CAP]
        elif src == "hids":
            content = scen["hids"][hidx][:CAP]
            hidx += 1
        else:
            content = dns_rows[seen_dns]
            seen_dns += 1
        rows.append([tcur, src, content])
    return rows


def assign_ids(all_units, bases):
    slots = [(ts, uid, k, src) for uid, _f, rows in all_units for k, (ts, src, _c) in enumerate(rows)]
    slots.sort(key=lambda x: (x[0], x[1], x[2]))
    rate = {"waf": 6920.0, "web": 6965.0, "rasp": 7657.0, "hids": 7499.0, "dns": 7424.0}
    last, ids = {}, {}
    for ts, uid, k, src in slots:
        n = bases[src] + int(rate[src] * (ts - SOURCE_T0).total_seconds() / 86400.0)
        n = max(n, last.get(src, 0) + 1)
        last[src] = n
        ids[(uid, k)] = f"{PREFIX[src]}{n:07d}"
    return ids


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dataset"))
    ap.add_argument("--seed", type=int, default=20260701)
    args = ap.parse_args()
    sys.path.insert(0, str(GEN))
    import render_chains as RC                      # 复用 UA 池与 dns/截断约定
    rng = random.Random(args.seed)
    forms = load_forms()
    bases = json.loads((GEN / "batch2_bases.json").read_text(encoding="utf-8"))
    all_units, labels = [], []
    for fam, uid0, fname, n, title in FAMILIES:
        for i, scen in enumerate(forms[fam]):
            uid = uid0 + i
            rows = render_unit(uid, scen, rng, RC.UAS)
            all_units.append((uid, fam, rows))
            labels.append(dict(unit=uid, family=fam, family_title=title, file=fname,
                               technique=scen["technique"], source_sequence=[r[1] for r in rows],
                               start=rows[0][0].strftime("%Y-%m-%d %H:%M:%S"), entries=[]))
    ids = assign_ids(all_units, bases)
    files = {fname: [] for _f, _u, fname, _n, _t in FAMILIES}
    idx_of = {lab["unit"]: lab for lab in labels}
    for uid, fam, rows in all_units:
        fname = {u0: fn for _f, u0, fn, _n, _t in FAMILIES}[uid - (uid - 1081) % 20]
        for k, (ts, src, content) in enumerate(rows):
            files[fname].append(f"{k+1}. `{ts.strftime('%Y-%m-%d %H:%M:%S')}` **[{src}]** `{ids[(uid, k)]}`")
            files[fname].append(f"    `{content}`")
        files[fname].append("")
        idx_of[uid]["entries"] = [dict(n=k + 1, ts=ts.strftime("%Y-%m-%d %H:%M:%S"), source=src,
                                       log_id=ids[(uid, k)], content=content)
                                  for k, (ts, src, content) in enumerate(rows)]
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for fname, lines in files.items():
        (out / fname).write_text("\n".join(lines).rstrip("\n") + "\n", encoding="utf-8")
    (out / "parsed_1081_1140.json").write_text(json.dumps(labels, ensure_ascii=False, indent=2),
                                               encoding="utf-8")
    flat = [f"{e['ts']} [{e['source']}] {e['log_id']} {e['content']}" for lab in labels for e in lab["entries"]]
    (out / "incoming_logs_1081_1140.txt").write_text("\n".join(flat) + "\n", encoding="utf-8")
    print(f"已写出 {len(files)} 个数据文件 + parsed_1081_1140.json + incoming_logs_1081_1140.txt")
    print(f"unit 数 {len(labels)}，日志行数 {len(flat)}")
    import validate_families
    return validate_families.run(out, quiet=False)


if __name__ == "__main__":
    sys.exit(main())

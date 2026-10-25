#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""dataset/gen/render_chains.py —— 把 form1..4.json 的语义片段渲染成 dataset/data-1001-1080.txt

作者（子代理）只写内容片段；本脚本统一负责：
  - unit 编号 1001~1080、文件切分（1001-1020 / 1021-1040 / 1041-1060 / 1061-1080）
  - 时间戳（2026-06-01 ~ 2026-06-30 内可容纳整条链，批次顺序 != 时间顺序）
  - log_id（五源各自独立计数器，接续 2026-05 窗口最大值，按时间全局排序后严格递增）
  - 主机名 app-<stack>-<num>.ops-corp.com / UA 池 / 110 字符硬截断
  - dns 三连（同一 C2 基线域、8 位 hex 子域、1 条文档段 + 2 条内网答案）
并输出 parsed_1001_1080.json（标签）与 incoming_logs_1001_1080.txt（扁平单行，喂检索器用），
最后跑一轮硬校验（格式 / 截断 / 跨字段自洽 / id 单调 / 反换皮去重）。

用法: python dataset/gen/render_chains.py [--out dataset] [--seed 20260616]
"""
import argparse
import datetime as dt
import json
import pathlib
import random
import sys

GEN = pathlib.Path(__file__).resolve().parent
ROOT = GEN.parent.parent

FORMS = [  # (表单, 起始 unit 号, 文件名)
    ("F1", 1001, "data-1001-1020.txt"),
    ("F2", 1021, "data-1021-1040.txt"),
    ("F3", 1041, "data-1041-1060.txt"),
    ("F4", 1061, "data-1061-1080.txt"),
]

WINDOW_START = dt.datetime(2026, 6, 1, 0, 0, 0)
WINDOW_END = dt.datetime(2026, 6, 30, 23, 59, 59)
CAP = 110                      # 内容硬上限（字符）
SOURCE_T0 = dt.datetime(2026, 6, 1, 0, 0, 0)
# 各源计数器接续 2026-05 窗口末值；速率取自语料实测（条/天）
SRC_BASE = {"waf": (200039, 6920.0), "web": (201341, 6965.0), "rasp": (221307, 7657.0),
            "hids": (216784, 7499.0), "dns": (202023, 7424.0)}
PREFIX = {"waf": "WAF", "web": "WEB", "rasp": "RASP", "hids": "HID", "dns": "DNS"}
UA_KEYS = ["windows-chrome", "windows11-edge", "windows-firefox", "mac-safari",
           "linux-x11-chrome", "android14-pixel", "ios-iphone", "windows-android13"]
UAS = {
    "windows-chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "windows11-edge": "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "windows-firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "mac-safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "linux-x11-chrome": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "android14-pixel": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
    "ios-iphone": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "windows-android13": "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
}
DOC_OCTETS = [("203.0.113.", 35), ("192.0.2.", 28), ("198.51.100.", 22)]

SHAPE_RULES = {
    "F1": [["waf", "web", "rasp", "hids"]],
    "F2": [["waf", "web", "rasp", "hids", "dns", "dns", "dns"]],
    "F3": [["waf", "rasp", "hids"], ["rasp", "hids"], ["hids"], ["waf", "hids"]],
    "F4": [["waf", "web", "rasp", "hids", "hids"]],
}


def cap(s):
    return s[:CAP]


def load_forms():
    out = {}
    for form, _, _ in FORMS:
        p = GEN / f"form{form[1]}.json"
        if not p.exists():
            raise SystemExit(f"缺少内容文件: {p}（等待作者产出）")
        scen = json.loads(p.read_text(encoding="utf-8"))["scenarios"]
        assert len(scen) == 20, f"{p.name} 需要 20 个 unit，实际 {len(scen)}"
        assert sorted(s["idx"] for s in scen) == list(range(1, 21)), f"{p.name} idx 必须 1..20"
        out[form] = sorted(scen, key=lambda s: s["idx"])
    return out


def unit_duration(scen):
    """整条链的持续秒数（用于把整条链塞进 6 月窗口）"""
    shape, dur, seen_dns = scen["shape"], 0.0, 0
    for pos, src in enumerate(shape):
        if pos == 0:
            continue
        if src == "dns":
            dur += float(scen["dns_gap_h"]) * 3600 if seen_dns == 0 else float(scen["dns_steps"][seen_dns - 1])
            seen_dns += 1
        else:
            dur += int(scen["deltas"][pos])
    return dur


def dns_ip(rng, is_doc):
    if is_doc:
        pre, lo = DOC_OCTETS[rng.randrange(len(DOC_OCTETS))]
        return f"{pre}{rng.randint(lo, lo + 120)}"
    return f"10.10.{rng.randint(23, 49)}.{rng.randint(2, 250)}"


def render_unit(uid, scen, rng):
    """→ rows = [(ts, src, content)]；log_id 在全局时间排序后统一分配"""
    shape = scen["shape"]
    assert shape in SHAPE_RULES[scen["_form"]], f"unit {uid} shape {shape} 不符 {scen['_form']}"
    deltas = list(scen["deltas"])
    assert len(deltas) == len(shape), f"unit {uid} deltas 长度 != shape 长度"
    assert deltas[0] == 0, f"unit {uid} deltas[0] 必须为 0"
    n_dns = shape.count("dns")
    dns_rows = []
    if n_dns:
        doc_at = rng.randrange(n_dns)              # 三条里恰好一条解析到文档段
        subs = rng.sample(range(16 ** 8), n_dns)
        dns_rows = [f"{subs[k]:08x}.{scen['dns_base']} A {dns_ip(rng, k == doc_at)}" for k in range(n_dns)]
        assert len({r.split(" ")[0] for r in dns_rows}) == n_dns
    avail = int((WINDOW_END - WINDOW_START).total_seconds() - unit_duration(scen))
    assert avail > 0, f"unit {uid} 链时长超过窗口"
    t = WINDOW_START + dt.timedelta(seconds=rng.randrange(avail))   # 批次顺序 != 时间顺序
    ua = UAS[scen["ua"]]
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
            content = cap(f"{scen['path']} {scen['carrier']} {ua}")
        elif src == "rasp":
            content = cap(f"https://{host}{scen['path']} {scen['rasp_evidence']} {ua}")
        elif src == "hids":
            content = cap(scen["hids"][hidx])
            hidx += 1
        else:                                     # dns
            content = dns_rows[seen_dns]
            seen_dns += 1
        rows.append([tcur, src, content])
    return rows


def assign_ids(all_units):
    """全局按时间排序，五源各自严格递增分配 log_id（时间倒挂的 id 不允许出现）"""
    slots = []
    for uid, _form, rows in all_units:
        for k, (ts, src, _c) in enumerate(rows):
            slots.append((ts, uid, k, src))
    slots.sort(key=lambda x: (x[0], x[1], x[2]))
    last, ids = {}, {}
    for ts, uid, k, src in slots:
        base, rate = SRC_BASE[src]
        n = base + int(rate * (ts - SOURCE_T0).total_seconds() / 86400.0)
        n = max(n, last.get(src, 0) + 1)
        last[src] = n
        ids[(uid, k)] = f"{PREFIX[src]}{n:07d}"
    return ids


def render_all(forms, rng):
    all_units, labels = [], []
    for form, uid0, fname in FORMS:
        for i, scen in enumerate(forms[form]):
            uid = uid0 + i
            scen["_form"] = form
            rows = render_unit(uid, scen, rng)
            all_units.append((uid, form, rows))
            labels.append(dict(unit=uid, form=form, file=fname, technique=scen["technique"],
                               source_sequence=[r[1] for r in rows],
                               start=rows[0][0].strftime("%Y-%m-%d %H:%M:%S"),
                               entries=[]))
    ids = assign_ids(all_units)
    files = {fname: [] for _, _, fname in FORMS}
    for uid, form, rows in all_units:
        fname = {u0: n for _, u0, n in FORMS}[uid - (uid - 1001) % 20]
        assert fname in files
        for k, (ts, src, content) in enumerate(rows):
            files[fname].append(f"{k+1}. `{ts.strftime('%Y-%m-%d %H:%M:%S')}` **[{src}]** `{ids[(uid, k)]}`")
            files[fname].append(f"    `{content}`")
        files[fname].append("")
        labels[[lab["unit"] for lab in labels].index(uid)]["entries"] = [
            dict(n=k + 1, ts=ts.strftime("%Y-%m-%d %H:%M:%S"), source=src,
                 log_id=ids[(uid, k)], content=content)
            for k, (ts, src, content) in enumerate(rows)]
    return {k: "\n".join(v).rstrip("\n") + "\n" for k, v in files.items()}, labels


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dataset"))
    ap.add_argument("--seed", type=int, default=20260616)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    forms = load_forms()
    files, labels = render_all(forms, rng)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for fname, text in files.items():
        (out / fname).write_text(text, encoding="utf-8")
    (out / "parsed_1001_1080.json").write_text(json.dumps(labels, ensure_ascii=False, indent=2),
                                               encoding="utf-8")
    flat = [f"{e['ts']} [{e['source']}] {e['log_id']} {e['content']}"
            for lab in labels for e in lab["entries"]]
    (out / "incoming_logs_1001_1080.txt").write_text("\n".join(flat) + "\n", encoding="utf-8")
    print(f"已写出 {len(files)} 个数据文件 + parsed_1001_1080.json + incoming_logs_1001_1080.txt")
    print(f"unit 数 {len(labels)}，日志行数 {len(flat)}")
    sys.path.insert(0, str(GEN))
    import validate_1001_1080
    return validate_1001_1080.run(out, quiet=False)


if __name__ == "__main__":
    sys.exit(main())

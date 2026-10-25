#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""dataset/gen/validate_families.py —— 第二批「新攻击家族」（1081~1140）硬校验

复用 batch-1 校验器的解析器/归一化/UA 池/杀软词表（import validate_1001_1080），
只实现本批特有的关口 G1~G14（含家族语义自检与与 batch-1 的 id 续接检查）。

用法: python dataset/gen/validate_families.py [dataset目录]
"""
import collections
import datetime as dt
import json
import pathlib
import re
import sys

GEN = pathlib.Path(__file__).resolve().parent
ROOT = GEN.parent.parent
sys.path.insert(0, str(GEN))
from validate_1001_1080 import (parse, norm, CAP, DNS_RE, DOC_PRE, AV_DENY, AV_WATCH,  # noqa: E402
                                PREFIX)
import render_families as RF  # noqa: E402  复用白名单与窗口常量
import render_chains as RC    # noqa: E402  复用 UA 池

FILES = [(f, u0, fn) for f, u0, fn, _n, _t in RF.FAMILIES]
TITLES = {f: t for f, _u, _fn, _n, t in RF.FAMILIES}
FAM_KEYWORDS = {
    # (家族语义关键词, 第二组关键词=额外的必备证据类)
    "FA": (["vssadmin", "wbadmin", "bcdedit", "recoveryenabled", "shadow", "快照", "备份", "catalog",
            "backup", "lvremove", "rm -rf", "删除", "snapshot", "镜像"],
           ["openssl enc", "gpg", "cipher /e", "加密", "enc -", "aes", "sdelete", ".lock", "locker",
            "tar czf", "ps1"]),
    "FB": (["kerberos", "krbtgt", "dcsync", "ntds", "lsadump", "ticket", "domain", "corp", "corp.local", "spn", "corp", "corp.local",
            "certipy", "gpo", "域控", "域内", "setspn", "rubeus", "dclist", "sysvol", "impacket"], []),
    "FC": (["npm", "pip ", "setup.py", "docker", "workflow", "jenkins", "gitlab", "ci_", "ci.",
            "github_token", "registry", "webhook", "index-url", "artifact", "缓存", "流水线", "构建",
            "runner", "terraform", "deploy", "git-credentials", "agent.env", "job", "publish",
            "token", "依赖", "包管理", "base64", "gem "], []),
}

errs, warns = [], []


def err(c, m):
    errs.append(f"[{c}] {m}")


def warn(c, m):
    warns.append(f"[{c}] {m}")


def run(outdir, quiet=False):
    out = pathlib.Path(outdir)
    labels = json.loads((out / "parsed_1081_1140.json").read_text(encoding="utf-8"))
    scenes = {f: json.loads((GEN / f"form{n}.json").read_text(encoding="utf-8"))["scenarios"]
              for f, _u, _fn, n, _t in RF.FAMILIES}
    b1 = collections.defaultdict(int)
    p1 = out / "parsed_1001_1080.json"
    if p1.exists():
        for l in json.loads(p1.read_text(encoding="utf-8")):
            for e in l["entries"]:
                b1[e["source"]] = max(b1[e["source"]], int(re.sub(r"\D", "", e["log_id"])))

    all_units, per_source, techs, cores, hids_norm = [], collections.defaultdict(list), [], [], []
    hosts = collections.Counter()
    ua_use = collections.defaultdict(collections.Counter)
    cut_n = cut_in_ua = payload_only = 0
    shape_use = collections.defaultdict(collections.Counter)

    for fam, uid0, fname in FILES:
        p = out / fname
        if not p.exists():
            err("G1", f"缺文件 {fname}")
            continue
        units = parse(p)
        if len(units) != 20:
            err("G1", f"{fname} unit 数 {len(units)} != 20")
        for ui, rows in enumerate(units, 1):
            uid = uid0 + ui - 1
            scen = scenes[fam][ui - 1]
            all_units.append((uid, fam, rows))
            shape = [r["src"] for r in rows]
            if shape != scen["shape"]:
                err("G3", f"unit {uid} 渲染形态 {shape} != 声明 {scen['shape']}")
            if shape not in RF.SHAPES:
                err("G3", f"unit {uid} shape 不在 §8.2 白名单: {shape}")
            shape_use[fam][tuple(shape)] += 1
            if [r["n"] for r in rows] != list(range(1, len(rows) + 1)):
                err("G1", f"unit {uid} 序号不是 1..N")
            # G13 家族语义
            blob = " ".join(r["content"] for r in rows).lower() + " " + scen["technique"].lower()
            need = FAM_KEYWORDS[fam][0]
            if need and not any(k in blob for k in need):
                err("G13", f"unit {uid}（{fam}）缺家族语义关键词之一: {need[:5]}…")
            if fam == "FA":
                enc = FAM_KEYWORDS["FA"][1]
                if not any(k in blob for k in enc):
                    err("G13", f"unit {uid}（FA）未见批量加密证据")
            # G2 内容
            for r in rows:
                c = r["content"]
                if "`" in c:
                    err("G2", f"unit {uid} 内容含反引号")
                if len(c) > CAP:
                    err("G2", f"unit {uid} 内容超 {CAP}: {len(c)}")
                if r["src"] == "dns":
                    if not DNS_RE.match(c):
                        err("G5", f"unit {uid} dns 行格式异常: {c!r}")
                elif len(c) < 12:
                    err("G2", f"unit {uid} 内容过短: {c!r}")
            # G4 跨字段
            ex = {r["src"]: r["content"] for r in rows}
            has_web = bool({"waf", "web", "rasp"} & set(shape))
            if has_web and not scen["path"]:
                err("G4", f"unit {uid} 含 waf/web/rasp 但 path 为空")
            if not has_web and (scen["path"] or scen["carrier"] or scen["rasp_evidence"]):
                err("G4", f"unit {uid} 纯主机链却填了 path/carrier/evidence")
            if "waf" in ex and "web" in ex and ex["waf"] != ex["web"]:
                err("G4", f"unit {uid} waf/web 不一致")
            if "rasp" in ex:
                pre = f"https://app-{scen['stack']}-{scen['host_num']}.ops-corp.com{scen['path']}"
                if not ex["rasp"].startswith(pre):
                    err("G4", f"unit {uid} rasp 前缀不符: {ex['rasp'][:60]!r}")
                if scen["rasp_evidence"] and scen["rasp_evidence"][:18] not in ex["rasp"]:
                    err("G4", f"unit {uid} rasp 未见 evidence 片段")
            if len([r for r in rows if r["src"] == "hids"]) != len(scen["hids"]):
                err("G4", f"unit {uid} hids 行数不符")
            # G5 dns
            dns = [r["content"] for r in rows if r["src"] == "dns"]
            if dns:
                ms = [DNS_RE.match(d) for d in dns]
                if not all(ms):
                    err("G5", f"unit {uid} dns 行格式异常")
                else:
                    if len({m.group(2) for m in ms}) != 1 or len({m.group(1) for m in ms}) != len(ms):
                        err("G5", f"unit {uid} dns 基线域不一致或子域重复")
                    if sum(1 for m in ms if m.group(3).startswith(DOC_PRE)) != 1:
                        err("G5", f"unit {uid} dns 文档段答案不是恰好 1 条")
            # G6 id
            for r in rows:
                if not re.fullmatch(PREFIX[r["src"]] + r"\d{7}", r["lid"]):
                    err("G6", f"unit {uid} log_id 格式异常 {r['lid']}")
                n = int(re.sub(r"\D", "", r["lid"]))
                if b1 and n <= b1.get(r["src"], 0):
                    err("G6", f"unit {uid} {r['lid']} 未续接 batch-1 上界 {b1.get(r['src'])}")
                per_source[r["src"]].append((r["ts"], r["lid"]))
            # G7 时间与步进
            ts = [dt.datetime.strptime(r["ts"], "%Y-%m-%d %H:%M:%S") for r in rows]
            if ts != sorted(ts) or len(set(ts)) != len(ts):
                err("G7", f"unit {uid} 组内时间非严格递增")
            for t in ts:
                if not (RF.WINDOW_START <= t <= RF.WINDOW_END):
                    err("G7", f"unit {uid} 时间越界 {t}")
            for a in range(1, len(shape)):
                if shape[a] == "dns":
                    continue
                if shape[a - 1] == "dns":
                    continue
                gap = (ts[a] - ts[a - 1]).total_seconds()
                if gap not in (1, 2) and not 5 <= gap <= 600:
                    err("G7", f"unit {uid} {shape[a-1]}→{shape[a]} 间隔 {int(gap)}s 不合 §8.4")
            if "dns" in shape:
                di = shape.index("dns")
                gap = (ts[di] - ts[di - 1]).total_seconds()
                want = float(scen["dns_gap_h"]) * 3600
                if abs(gap - want) > 2:
                    err("G7", f"unit {uid} dns 间隔 {int(gap)}s != dns_gap_h {int(want)}s")
            # G8 反换皮 / G9 UA / G10 截断 / G11 杀软 / G12 主机
            techs.append(scen["technique"])
            cores.append(norm(scen["path"] + " " + scen["carrier"]) if has_web else "")
            hids_norm.append(norm(" | ".join(scen["hids"])))
            if has_web:
                ua_use[fam][scen["ua"]] += 1
            hosts[(scen["stack"], scen["host_num"])] += 1
            ua_text = RC.UAS[scen["ua"]]
            for r in rows:
                for bad, why in AV_DENY:
                    if bad in r["content"]:
                        err("G11", f"unit {uid} 含杀软隔离字样 {bad!r}（{why}）")
                for w in AV_WATCH:
                    if w in r["content"]:
                        warn("G11", f"unit {uid} 含高危观察词 {w!r}")
                if r["src"] in ("waf", "web", "rasp") and len(r["content"]) == CAP:
                    cut_n += 1
                    idx = r["content"].find(ua_text[:20])
                    if idx >= 0:
                        cut_in_ua += 1
                    else:
                        payload_only += 1
    # 汇总
    for name, arr in (("technique", techs), ("path+carrier", [c for c in cores if c]), ("hids", hids_norm)):
        dup = [k for k, v in collections.Counter(arr).items() if v > 1]
        if dup:
            err("G8", f"{name} 重复（换皮嫌疑）: " + " | ".join(str(d)[:60] for d in dup[:4]))
    for fam, cnt in ua_use.items():
        for k, v in cnt.items():
            if not 1 <= v <= 4:
                err("G9", f"{fam} UA 键 {k} 用 {v} 次（应 1~4）")
    for fam, cnt in shape_use.items():
        if max(cnt.values()) > 7:
            err("G3", f"{fam} 单一 shape 用了 {max(cnt.values())} 次（应 ≤7）")
        if len(cnt) < 4:
            err("G3", f"{fam} 只用了 {len(cnt)} 种形态（应 ≥4）")
        if fam == "FC":
            web_n = sum(v for k, v in cnt.items() if {"waf", "web", "rasp"} & set(k))
            if web_n < 12:
                err("G3", f"FC 只有 {web_n} 个 unit 含 Web/CI 入口（应 ≥12）")
    dup_host = [k for k, c in hosts.items() if c > 1]
    if dup_host:
        err("G12", f"(stack,host_num) 跨 unit 复用: {dup_host}")
    for src, arr in per_source.items():
        arr = sorted(arr)
        nums = [int(re.sub(r"\D", "", l)) for _t, l in arr]
        bad = [(arr[i - 1], arr[i]) for i in range(1, len(nums)) if nums[i] <= nums[i - 1]]
        if bad:
            err("G6", f"{src} log_id 非严格递增: {bad[:2]}")
        span = (dt.datetime.strptime(arr[-1][0], "%Y-%m-%d %H:%M:%S")
                - dt.datetime.strptime(arr[0][0], "%Y-%m-%d %H:%M:%S")).total_seconds() or 1
        print(f"  {src:4s} n={len(arr):3d}  id {nums[0]:7d}..{nums[-1]:7d}  "
              f"≈{(nums[-1]-nums[0])/span*86400:,.0f} 条/天  （batch-1 上界 {b1.get(src, 0)}）")
    if not quiet:
        print(f"\nunit {len(all_units)} / 日志行 {sum(len(r) for _u, _f, r in all_units)}")
        print("家族形态分布:")
        for fam, cnt in shape_use.items():
            print(f"  {fam}: " + "; ".join(f"{'+'.join(k)}×{v}" for k, v in sorted(cnt.items(), key=lambda x: -x[1])))
        print(f"来源分布: {collections.Counter(r['src'] for _u, _f, rows in all_units for r in rows)}")
        if cut_n:
            r_ = cut_in_ua / cut_n
            if r_ < 0.5:
                err("G10", f"切口落在 UA 内比例过低 {r_:.0%}（语料 77%）")
            elif r_ > 0.95:
                warn("G10", f"切口落在 UA 内比例 {r_:.0%} 偏高（语料 77%，本批 web 行少，可接受）")
            print(f"截断行 {cut_n}：切口落在 UA 内 {cut_in_ua}（{r_:.0%}），载荷占满整行 {payload_only}")
    if warns:
        print(f"\n警告 {len(warns)}:")
        for w in warns[:15]:
            print("  " + w)
    if errs:
        print(f"\n错误 {len(errs)}:")
        for e in errs[:40]:
            print("  " + e)
        return 1
    print("\n✅ 全部校验通过（G1~G14）")
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else ROOT / "dataset"))

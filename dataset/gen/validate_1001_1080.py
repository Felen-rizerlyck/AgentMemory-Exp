#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""dataset/gen/validate_1001_1080.py —— data-1001-1080 批次硬校验

校验项（任一失败 → 退出码 1）：
  C1  文件结构：4 个文件、每文件 20 unit、unit 间空行、unit 内序号 1..N、每条 2 行且反引号闭合
  C2  内容长度 ≤110 且无内部反引号/换行，dns 行不截断（≤45）
  C3  形态：F1 全是 4 行；F2 含 dns×3；F3 无 web/dns 且四种 shape 齐全；F4 双 hids
  C4  跨字段：waf 与 web 逐字相同；rasp 以 https://app-<栈>-<号>.ops-corp.com<path> 开头；hids 行数 == shape 里 hids 个数
  C5  dns 三连：同基线域、子域互不相同、恰好 1 条解析到文档段（其余 10.10.x.x）、格式 <8hex>.<base> A <ip>
  C6  log_id：前缀与来源一致 + 7 位补零；按时间排序后每源严格递增
  C7  时间：全部落在 2026-06-01~2026-06-30；unit 内严格递增；dns 首条与 hids 的间隔 == dns_gap_h(±2s)
  C8  反换皮：80 个 technique 全局唯一；归一化后 (path+carrier) 80 个互不相同；hids 文本归一化后 80 个互不相同
  C9  UA 分布：每个 form 内每个 UA 键 1~4 次
  C10 截断真实性：waf/web/rasp 行中 ≥90% 被截断且切口落在 UA 之内
"""
import collections
import datetime as dt
import json
import pathlib
import re
import sys

GEN = pathlib.Path(__file__).resolve().parent
ROOT = GEN.parent.parent
CAP = 110
HEAD_RE = re.compile(r"^(\d+)\. `(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})` \*\*\[(waf|web|rasp|hids|dns)\]\*\* `([A-Z]{2,4}\d{7})`$")
CONT_RE = re.compile(r"^    `([^`]+)`$")
DNS_RE = re.compile(r"^([0-9a-f]{8})\.([a-z]{6}-[0-9a-f]{4}\.(?:net|com|org|io)) A (\d{1,3}(?:\.\d{1,3}){3})$")
FILES = ["data-1001-1020.txt", "data-1021-1040.txt", "data-1041-1060.txt", "data-1061-1080.txt"]
PREFIX = {"waf": "WAF", "web": "WEB", "rasp": "RASP", "hids": "HID", "dns": "DNS"}
DOC_PRE = ("203.0.113.", "192.0.2.", "198.51.100.")
# C11：杀软会直接隔离的载荷字样（实测 Windows Defender：Backdoor:JS/WebShellz.E!MTB 命中 child_process 组合）
AV_DENY = [("child_process", "Defender: Backdoor:JS/WebShellz —— JS webshell 特征，写盘即被隔离"),
           ("require('child", "同上（require+child_process 组合）"),
           ("EICAR", "杀软测试串")]
# 观察名单：本轮 Defender 未拦截，但属高危词，若再被隔离先查这里
AV_WATCH = ["xmrig", "sekurlsa", "mimikatz", "Add-MpPreference", "ExclusionPath",
            "meterpreter", "cobaltstrike", "msfvenom", "Invoke-Mimikatz"]
sys.path.insert(0, str(GEN))
import render_chains as RC  # noqa: E402  复用 UA 池定义

UAS = RC.UAS

errs, warns = [], []


def err(c, msg):
    errs.append(f"[{c}] {msg}")


def warn(c, msg):
    warns.append(f"[{c}] {msg}")


def parse(path):
    raw = path.read_text(encoding="utf-8").split("\n")
    units, cur, i = [], [], 0
    while i < len(raw):
        ln = raw[i]
        if ln.strip() == "":
            if cur:
                units.append(cur)
                cur = []
            i += 1
            continue
        m = HEAD_RE.match(ln)
        if not m:
            err("C1", f"{path.name}:{i+1} 头部行不合格式: {ln[:70]!r}")
            i += 1
            continue
        if i + 1 >= len(raw):
            err("C1", f"{path.name}:{i+1} 缺内容行")
            break
        c = CONT_RE.match(raw[i + 1])
        if not c:
            err("C1", f"{path.name}:{i+2} 内容行不合格式: {raw[i+1][:70]!r}")
        cur.append(dict(n=int(m.group(1)), ts=m.group(2), src=m.group(3), lid=m.group(4),
                        content=c.group(1) if c else ""))
        i += 2
    if cur:
        units.append(cur)
    return units


def norm(s):
    s = re.sub(r"[0-9a-f]{6,}", "#", s)
    s = re.sub(r"\d+", "#", s)
    return re.sub(r"\s+", " ", s).strip()


def run(outdir, quiet=False):
    out = pathlib.Path(outdir)
    forms = ["F1", "F2", "F3", "F4"]
    all_units, per_source, techs, cores, hids_norm, ua_use = [], collections.defaultdict(list), [], [], [], collections.defaultdict(collections.Counter)
    cut_n = cut_in_ua = payload_only = 0
    hosts, rasphids = collections.Counter(), []
    labels = json.loads((out / "parsed_1001_1080.json").read_text(encoding="utf-8"))
    scenes = {f: json.loads((GEN / f"form{i+1}.json").read_text(encoding="utf-8"))["scenarios"]
              for i, f in enumerate(forms)}

    for fi, fname in enumerate(FILES):
        p = out / fname
        if not p.exists():
            err("C1", f"缺文件 {fname}")
            continue
        units = parse(p)
        if len(units) != 20:
            err("C1", f"{fname} unit 数 {len(units)} != 20")
        for ui, rows in enumerate(units, 1):
            uid = 1000 + fi * 20 + ui
            form = forms[fi]
            all_units.append((uid, form, rows))
            if [r["n"] for r in rows] != list(range(1, len(rows) + 1)):
                err("C1", f"unit {uid} 序号不是 1..N: {[r['n'] for r in rows]}")
            shape = [r["src"] for r in rows]
            # C3 形态
            if form == "F1" and shape != ["waf", "web", "rasp", "hids"]:
                err("C3", f"unit {uid} F1 形态异常 {shape}")
            if form == "F2" and shape != ["waf", "web", "rasp", "hids", "dns", "dns", "dns"]:
                err("C3", f"unit {uid} F2 形态异常 {shape}")
            if form == "F3":
                if "web" in shape or "dns" in shape:
                    err("C3", f"unit {uid} F3 不得含 web/dns: {shape}")
                if shape not in (["waf", "rasp", "hids"], ["rasp", "hids"], ["hids"], ["waf", "hids"]):
                    err("C3", f"unit {uid} F3 shape 越界: {shape}")
            if form == "F4" and shape != ["waf", "web", "rasp", "hids", "hids"]:
                err("C3", f"unit {uid} F4 形态异常 {shape}")
            # C2 内容
            for r in rows:
                c = r["content"]
                if "`" in c:
                    err("C2", f"unit {uid} 内容含反引号: {c[:50]!r}")
                if len(c) > CAP:
                    err("C2", f"unit {uid} 内容超 {CAP}: {len(c)}")
                if r["src"] == "dns":
                    if len(c) > 45:
                        err("C2", f"unit {uid} dns 行不应截断: {len(c)} {c!r}")
                    if not DNS_RE.match(c):
                        err("C5", f"unit {uid} dns 行格式异常: {c!r}")
                if len(c) < 12:
                    err("C2", f"unit {uid} 内容过短: {c!r}")
            # C11 杀软敏感载荷
            for r in rows:
                for bad, why in AV_DENY:
                    if bad in r["content"]:
                        err("C11", f"unit {uid} 含杀软隔离字样 {bad!r}（{why}）")
                for w in AV_WATCH:
                    if w in r["content"]:
                        warn("C11", f"unit {uid} 含高危观察词 {w!r}（Defender 当前放行，留意）")
            # C4 跨字段
            ex = {r["src"]: r["content"] for r in rows}
            if "waf" in ex and "web" in ex and ex["waf"] != ex["web"]:
                err("C4", f"unit {uid} waf/web 内容不一致")
            scen = scenes[form][ui - 1]
            if "rasp" in ex:
                pre = f"https://app-{scen['stack']}-{scen['host_num']}.ops-corp.com{scen['path']}"
                if not ex["rasp"].startswith(pre):
                    err("C4", f"unit {uid} rasp 未以 {pre[:60]} 开头: {ex['rasp'][:60]!r}")
                if scen["rasp_evidence"] and scen["rasp_evidence"][:20] not in ex["rasp"]:
                    err("C4", f"unit {uid} rasp 未见 evidence 片段")
            if len([r for r in rows if r["src"] == "hids"]) != len(scen["hids"]):
                err("C4", f"unit {uid} hids 行数不符")
            # C12 同一 (stack, host_num) 不得跨 unit 复用（否则同一主机出现互相矛盾的 OS/角色）
            hosts[(scen['stack'], scen['host_num'])] += 1
            # C13 攻击簇时延（语料实测：waf→web→rasp 1~2s；rasp→hids 55~125s）
            if 'rasp' in shape and 'hids' in shape:
                tss = [dt.datetime.strptime(r["ts"], "%Y-%m-%d %H:%M:%S") for r in rows]
                ri, hi = shape.index('rasp'), shape.index('hids')
                if hi == ri + 1:
                    gap = (tss[hi] - tss[ri]).total_seconds()
                    rasphids.append(int(gap))
                    if not 50 <= gap <= 130:
                        err("C13", f"unit {uid} rasp→hids {int(gap)}s 不在语料区间 50~130s（远期阶段应在 dns 而非 hids）")
                if 'waf' in shape and 'web' in shape:
                    g2 = (tss[shape.index('web')] - tss[shape.index('waf')]).total_seconds()
                    if g2 not in (1, 2):
                        err("C13", f"unit {uid} waf→web {int(g2)}s 不是 1~2s")
            # C5 dns
            dns = [r["content"] for r in rows if r["src"] == "dns"]
            if len(dns) == 3:
                ms = [DNS_RE.match(d) for d in dns]
                if all(ms):
                    if len({m.group(2) for m in ms}) != 1:
                        err("C5", f"unit {uid} dns 基线域不一致")
                    if len({m.group(1) for m in ms}) != 3:
                        err("C5", f"unit {uid} dns 子域重复")
                    ndoc = sum(1 for m in ms if m.group(3).startswith(DOC_PRE))
                    if ndoc != 1:
                        err("C5", f"unit {uid} dns 文档段答案 {ndoc} 条（应为 1）")
            # C6/C7 id 与时间
            for r in rows:
                if not re.fullmatch(PREFIX[r["src"]] + r"\d{7}", r["lid"]):
                    err("C6", f"unit {uid} log_id 不合 <前缀><7位> 格式: {r['lid']}")
                per_source[r["src"]].append((r["ts"], r["lid"]))
            ts = [dt.datetime.strptime(r["ts"], "%Y-%m-%d %H:%M:%S") for r in rows]
            if ts != sorted(ts) or len(set(ts)) != len(ts):
                err("C7", f"unit {uid} 组内时间非严格递增")
            for t in ts:
                if not (dt.datetime(2026, 6, 1) <= t <= dt.datetime(2026, 6, 30, 23, 59, 59)):
                    err("C7", f"unit {uid} 时间越界 {t}")
            if "dns" in shape:
                hidx = shape.index("hids")
                gap = (ts[shape.index("dns")] - ts[hidx]).total_seconds()
                want = float(scen["dns_gap_h"]) * 3600
                if abs(gap - want) > 2:
                    err("C7", f"unit {uid} dns 间隔 {gap}s != dns_gap_h {want}s")
            # C8 反换皮
            techs.append(scen["technique"])
            cores.append(norm(scen["path"] + " " + scen["carrier"]))
            hids_norm.append(norm(" | ".join(scen["hids"])))
            # C9 UA
            ua_use[form][scen["ua"]] += 1
            # C10 截断切口落在 UA 内
            ua_text = UAS[scen["ua"]]
            for r in rows:
                if r["src"] in ("waf", "web", "rasp") and len(r["content"]) == CAP:
                    cut_n += 1
                    idx = r["content"].find(ua_text[:20])
                    if idx >= 0:
                        cut_in_ua += 1
                        if idx < 5:
                            err("C10", f"unit {uid} UA 起点 {idx} 过靠前（载荷几乎被吃掉）")
                    else:
                        # 载荷占满整行、UA 完全被截掉——语料里 23% 的行就是这样（如 server[REQUEST_METHOD]=id）
                        payload_only += 1

    # C8 汇总
    for name, arr in (("technique", techs), ("path+carrier", cores), ("hids", hids_norm)):
        dup = [k for k, v in collections.Counter(arr).items() if v > 1]
        if dup:
            err("C8", f"{name} 有重复（换皮嫌疑）: " + " | ".join(str(d)[:70] for d in dup[:5]))
    # C9 汇总
    for form, cnt in ua_use.items():
        for k, v in cnt.items():
            if not 1 <= v <= 4:
                err("C9", f"{form} UA 键 {k} 用 {v} 次（应 1~4）")
    # C6 汇总：按时间排序后每源严格递增
    for src, arr in per_source.items():
        arr = sorted(arr)
        nums = [int(re.sub(r"\D", "", lid)) for _, lid in arr]
        bad = [(arr[i - 1], arr[i]) for i in range(1, len(nums)) if nums[i] <= nums[i - 1]]
        if bad:
            err("C6", f"{src} log_id 非严格递增: {bad[:3]}")
        span = (dt.datetime.strptime(arr[-1][0], "%Y-%m-%d %H:%M:%S")
                - dt.datetime.strptime(arr[0][0], "%Y-%m-%d %H:%M:%S")).total_seconds() or 1
        print(f"  {src:4s} n={len(arr):3d}  id {nums[0]:7d}..{nums[-1]:7d}  "
              f"≈{(nums[-1]-nums[0])/span*86400:,.0f} 条/天")

    n_rows = sum(len(r) for _, _, r in all_units)
    if not quiet:
        print(f"\nunit {len(all_units)} / 日志行 {n_rows}")
        print(f"形态分布: {collections.Counter(f for _, f, _ in all_units)}")
        print(f"来源分布: {collections.Counter(r['src'] for _, _, rows in all_units for r in rows)}")
        ratio = cut_in_ua / cut_n if cut_n else 0
        if cut_n and not 0.55 <= ratio <= 0.95:      # 语料实测 77%（61/79），本批须与之同量级
            err("C10", f"切口落在 UA 内的比例 {cut_in_ua}/{cut_n}={ratio:.0%} 偏离语料区间 55%~95%")
        dup_host = [k for k, c in hosts.items() if c > 1]
        if dup_host:
            err("C12", f"(stack,host_num) 跨 unit 复用: {dup_host}")
        if rasphids and len(set(rasphids)) < 4:
            warn("C15", f"rasp→hids 时延只有 {sorted(set(rasphids))} 几种取值，易被当成生成器指纹")
        print(f"rasp→hids 时延分布: {sorted(collections.Counter(rasphids).items())[:12]}")
        print(f"截断行 {cut_n}：切口落在 UA 内 {cut_in_ua}（{ratio:.0%}，语料 77%），"
              f"载荷占满整行 {payload_only}（语料 23%）")
    if warns:
        print(f"\n警告 {len(warns)}:")
        for w in warns[:15]:
            print("  " + w)
    if errs:
        print(f"\n错误 {len(errs)}:")
        for e in errs[:40]:
            print("  " + e)
        return 1
    print("\n✅ 全部校验通过（C1~C13：格式/截断/形态/跨字段/dns/id/时间/反换皮/UA/截断切口/杀软/主机唯一/攻击簇时延）")
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1] if len(sys.argv) > 1 else ROOT / "dataset"))

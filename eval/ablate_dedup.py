#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""跨通道去重（修法 #4）离线对照：baseline（现状） vs dedup（去重）

不改动 src/retrieve.py 主流程；定义去重版打分函数，重放前瞻/全量/负样本数据对比关键指标。

输出: eval/results/report_dedup_ablation.md
"""
import importlib.util
import json
import pathlib
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = pathlib.Path(__file__).parent.parent
OUT = pathlib.Path(__file__).parent / "results"
OUT.mkdir(exist_ok=True)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


retrieve = load_module(BASE / "src" / "retrieve.py", "retrieve")
run_eval = load_module(BASE / "eval" / "run_eval.py", "run_eval")
run_unseen = load_module(BASE / "eval" / "run_recall_unseen.py", "run_unseen")
run_full = load_module(BASE / "eval" / "run_recall_full.py", "run_full")

CH = {"keys", "mitre", "ind", "sig", "probes"}  # C2 全通道


# ---------- 去重版打分（#4：同一 token 只按最高权重通道计一次） ----------

def score_case_dedup(case, ql):
    detail, score, seen = [], 0, set()
    hits = {h for k in case.get("retrieval_keys", []) for h in retrieve.key_hits(k, ql)} - seen
    if hits:
        score += 3 * len(hits); detail.append("keys×3: " + ",".join(sorted(hits))); seen |= hits
    hits = {t.lower() for t in case.get("mitre", []) if retrieve._wordish(t.lower()).search(ql)} - seen
    if hits:
        score += 2 * len(hits); detail.append("mitre×2: " + ",".join(hits)); seen |= hits
    hits = {h for v in retrieve.flatten_indicators(case.get("indicators", {})) for h in retrieve.key_hits(v, ql)} - seen
    if hits:
        score += 2 * len(hits); detail.append("ind×2: " + ",".join(sorted(hits))); seen |= hits
    hits = set(retrieve.key_hits(case.get("signature", ""), ql)) - seen
    if hits:
        score += 1 * len(hits); detail.append("sig×1: " + ",".join(sorted(hits)))
    for probe in case.get("pattern_probes", []):
        if re.search(probe, ql, re.I):
            score += 4; detail.append("probe×4: " + probe)
    return score, detail


def score_case_cfg_dedup(case, ql, channels):
    detail, score, seen = [], 0, set()
    if "keys" in channels:
        hits = {h for k in case.get("retrieval_keys", []) for h in retrieve.key_hits(k, ql)} - seen
        if hits:
            score += 3 * len(hits); detail.append("keys×3: " + ",".join(sorted(hits))); seen |= hits
    if "mitre" in channels:
        hits = {t.lower() for t in case.get("mitre", []) if retrieve._wordish(t.lower()).search(ql)} - seen
        if hits:
            score += 2 * len(hits); detail.append("mitre×2: " + ",".join(hits)); seen |= hits
    if "ind" in channels:
        hits = {h for v in retrieve.flatten_indicators(case.get("indicators", {})) for h in retrieve.key_hits(v, ql)} - seen
        if hits:
            score += 2 * len(hits); detail.append("ind×2: " + ",".join(sorted(hits))); seen |= hits
    if "sig" in channels:
        hits = set(retrieve.key_hits(case.get("signature", ""), ql)) - seen
        if hits:
            score += 1 * len(hits); detail.append("sig×1: " + ",".join(sorted(hits)))
    if "probes" in channels:
        for probe in case.get("pattern_probes", []):
            if re.search(probe, ql, re.I):
                score += 4; detail.append("probe×4: " + probe)
    return score, detail


def band(s):
    return "强" if s >= 6 else "中" if s >= 4 else "弱" if s >= 1 else "无"


def topn(scores, n=3):
    scores.sort(key=lambda x: (-x[0], x[1]))
    return scores[:n]


def main():
    cases = json.loads((BASE / "data" / "memory_store.json").read_text(encoding="utf-8"))["cases"]
    L = []
    L.append("# 跨通道去重（修法 #4）离线对照：baseline vs dedup")
    L.append("")
    L.append(f"- 案例库: {len(cases)} · 打分口径: C2 全通道（keys/mitre/ind/sig/probes）")
    L.append("- baseline = 现状 `score_case`；dedup = 同一 token 跨通道只按最高权重计一次（probes 不参与去重）")
    L.append("")

    # ============ 场景 A：前瞻测试（data-921-930，40 行） ============
    parsed = json.loads((BASE / "dataset" / "parsed_921_930.json").read_text(encoding="utf-8"))
    L.append("## 场景 A：前瞻测试（data-921-930，40 行）")
    L.append("")
    a_rows = []
    for p in parsed:
        ui = p["unit"]
        for ei, e in enumerate(p["entries"], 1):
            kind, targets, note = run_unseen.EXPECT[ui][ei - 1]
            ql = e["content"].lower()
            bs = [(run_eval.score_case_cfg(c, ql, CH)[0], c["id"]) for c in cases]
            ds = [(score_case_cfg_dedup(c, ql, CH)[0], c["id"]) for c in cases]
            a_rows.append(dict(unit=ui, entry=ei, kind=kind, targets=targets,
                               b_top3=topn(bs), d_top3=topn(ds),
                               b_max=bs[0][0] if bs else 0, d_max=ds[0][0] if ds else 0))

    def hit_targets(top3, targets):
        return any(t in [c for _, c in top3[:1]] for t in targets) if targets else None

    # NOVEL：期望静默（<4）
    nov = [r for r in a_rows if r["kind"] == "NOVEL"]
    L.append("### A.1 NOVEL 行（期望静默，<4 分）")
    L.append("")
    L.append("| 单元-行 | baseline 最高分 | dedup 最高分 | 变化 |")
    L.append("|---|---|---|---|")
    for r in nov:
        chg = f"{r['b_max']} → {r['d_max']}"
        flag = "✓静默" if r["d_max"] < 4 else ("✗仍≥4" if r["d_max"] >= 4 else "")
        L.append(f"| {r['unit']}-{r['entry']} | {r['b_max']}({band(r['b_max'])}) | {r['d_max']}({band(r['d_max'])}) | {chg} {flag} |")
    L.append("")

    # KNOWN：期望强档召回保持（≥6 且 top1 命中）
    kn = [r for r in a_rows if r["kind"] == "KNOWN"]
    b_strong = sum(1 for r in kn if r["b_max"] >= 6)
    d_strong = sum(1 for r in kn if r["d_max"] >= 6)
    b_hit1 = sum(1 for r in kn if hit_targets(r["b_top3"], r["targets"]))
    d_hit1 = sum(1 for r in kn if hit_targets(r["d_top3"], r["targets"]))
    L.append("### A.2 KNOWN 行（期望召回保持：强档 + Top-1 命中）")
    L.append("")
    L.append(f"- 强档(≥6) 行数: baseline **{b_strong}/{len(kn)}** → dedup **{d_strong}/{len(kn)}**")
    L.append(f"- Top-1 命中目标: baseline **{b_hit1}/{len(kn)}** → dedup **{d_hit1}/{len(kn)}**")
    L.append("")
    dropped = [r for r in kn if r["d_max"] < 6 or not hit_targets(r["d_top3"], r["targets"])]
    if dropped:
        L.append("**dedup 后降档/丢 Top-1 的 KNOWN 行**（需逐一核对是否误伤）：")
        L.append("")
        L.append("| 单元-行 | 目标 | baseline top1 | dedup top1 |")
        L.append("|---|---|---|---|")
        for r in dropped:
            L.append(f"| {r['unit']}-{r['entry']} | {'+'.join(r['targets'])} | {r['b_top3'][0] if r['b_top3'] else '—'} | {r['d_top3'][0] if r['d_top3'] else '—'} |")
        L.append("")

    # SHARED + GENERIC：简要
    sh = [r for r in a_rows if r["kind"] == "SHARED"]
    ge = [r for r in a_rows if r["kind"] == "GENERIC"]
    L.append("### A.3 SHARED / GENERIC 行（观察落点变化）")
    L.append("")
    L.append("| 类别 | 单元-行 | baseline 最高分 | dedup 最高分 |")
    L.append("|---|---|---|---|")
    for r in sh + ge:
        L.append(f"| {r['kind']} | {r['unit']}-{r['entry']} | {r['b_max']}({band(r['b_max'])}) | {r['d_max']}({band(r['d_max'])}) |")
    L.append("")

    # ============ 场景 B：全量召回（133 行） ============
    L.append("## 场景 B：全量召回（dataset 三文件，133 行）")
    L.append("")
    files = [("901-910", "data-901-910.txt"), ("911-920", "data-911-920.txt"), ("9101-9110", "data-9101-9110.txt")]
    b_rows = []
    for tag, fn in files:
        units = run_full.parse_file(BASE / "dataset" / fn)
        exp = run_full.EXPECT[tag]
        for ui, u in enumerate(units, 1):
            for ei, e in enumerate(u, 1):
                want = exp[ui][ei - 1]
                ql = e["content"].lower()
                bs = [(retrieve.score_case(c, ql)[0], c["id"]) for c in cases]
                ds = [(score_case_dedup(c, ql)[0], c["id"]) for c in cases]
                b_top3 = topn(bs)
                d_top3 = topn(ds)
                b_rows.append(dict(tag=tag, ui=ui, ei=ei, want=want,
                                   b_top3=b_top3, d_top3=d_top3))

    def acc(sub):
        n = len(sub)
        b1 = sum(1 for r in sub if r["want"] and r["b_top3"] and r["b_top3"][0][1] == r["want"])
        d1 = sum(1 for r in sub if r["want"] and r["d_top3"] and r["d_top3"][0][1] == r["want"])
        b3 = sum(1 for r in sub if r["want"] and any(c == r["want"] for _, c in r["b_top3"][:3]))
        d3 = sum(1 for r in sub if r["want"] and any(c == r["want"] for _, c in r["d_top3"][:3]))
        return n, b1, d1, b3, d3

    feat = [r for r in b_rows if r["want"]]
    n, b1, d1, b3, d3 = acc(feat)
    L.append(f"- 特征行 {n} 条：Top-1 baseline **{b1}** → dedup **{d1}**；Top-3 baseline **{b3}** → dedup **{d3}**")
    L.append("")
    # 丢 Top-1 或 Top-3 的特征行明细
    degraded = [r for r in feat if r["want"] and not any(c == r["want"] for _, c in r["d_top3"][:3])]
    if degraded:
        L.append("**dedup 后丢 Top-3 的特征行**：")
        L.append("")
        L.append("| 文件-单元-条 | 预期 | baseline top3 | dedup top3 |")
        L.append("|---|---|---|---|")
        for r in degraded:
            L.append(f"| {r['tag']}-{r['ui']}-{r['ei']} | {r['want']} | {r['b_top3'][:3]} | {r['d_top3'][:3]} |")
        L.append("")

    # ============ 场景 C：负样本（queries.jsonl C-negative 9 条） ============
    L.append("## 场景 C：负样本（queries.jsonl C-negative，9 条）")
    L.append("")
    queries = [json.loads(l) for l in (BASE / "eval" / "queries.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    negs = [q for q in queries if q["group"] == "C-negative"]
    L.append("| 负样本 | baseline 最高分 | dedup 最高分 | 变化 |")
    L.append("|---|---|---|---|")
    for q in negs:
        ql = q["text"].lower()
        bm = max((retrieve.score_case(c, ql)[0] for c in cases), default=0)
        dm = max((score_case_dedup(c, ql)[0] for c in cases), default=0)
        flag = "✓静默" if dm < 4 else ("✗仍≥4" if dm >= 4 else "")
        L.append(f"| {q['qid']} | {bm}({band(bm)}) | {dm}({band(dm)}) | {bm}→{dm} {flag} |")
    L.append("")

    L.append("---")
    L.append("*离线对照，未改动 `src/retrieve.py` 主流程。*")
    report = OUT / "report_dedup_ablation.md"
    report.write_text("\n".join(L), encoding="utf-8")
    print("\n".join(L))
    print(f"\n报告已写入: {report}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""eval/run_eval.py — 检索评测运行器（入口消融 C0–C2 + 扩展对照 C3–C5 × 门槛甲/乙）

输入: eval/queries.jsonl · eval/relations_gold.json · src/retrieve.py · data/memory_store.json
输出: eval/results/report.md · results/details.jsonl · results/summary.json

口径:
- 打分逻辑与 retrieve.score_case 一致（C2 自检：与官方函数逐条比对，须完全一致）。
- 扩展种子 = C2 返回中 score≥门槛 的案例；邻居来自 gold helpful 边（按配置过滤类型）。
- 指标定义见 EVAL_PROTOCOL.md §4。
"""
import importlib.util
import json
import pathlib
import sys
from collections import defaultdict

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

EVAL = pathlib.Path(__file__).parent
BASE = EVAL.parent
OUT = EVAL / "results"
OUT.mkdir(exist_ok=True)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


retrieve = load_module(BASE / "src/retrieve.py", "retrieve")

CHANNELS = {
    "C0": {"keys"},
    "C1": {"keys", "mitre", "ind", "sig"},
    "C2": {"keys", "mitre", "ind", "sig", "probes"},
}
EXPANSION = {
    "C3": None,
    "C4": {"shares_infra", "chain_sibling", "same_phase"},
    "C5": {"same_technique", "same_family", "shares_payload"},
}
GATES = [("甲", 6), ("乙", 4)]
GROUPS = ["A-archive", "A-constructed", "B-must_hit", "B-may_degrade", "B-nl", "C-negative"]


def score_case_cfg(case, ql, channels):
    """与 retrieve.score_case 同口径的分通道版本（跨通道去重）"""
    detail, score, seen = [], 0, set()
    if "keys" in channels:
        hits = {h for k in case.get("retrieval_keys", []) for h in retrieve.key_hits(k, ql)} - seen
        if hits:
            score += 3 * len(hits)
            detail.append("keys×3: " + ",".join(sorted(hits)))
            seen |= hits
    if "mitre" in channels:
        hits = {t.lower() for t in case.get("mitre", []) if retrieve._wordish(t.lower()).search(ql)} - seen
        if hits:
            score += 2 * len(hits)
            detail.append("mitre×2: " + ",".join(hits))
            seen |= hits
    if "ind" in channels:
        hits = {h for v in retrieve.flatten_indicators(case.get("indicators", {})) for h in retrieve.key_hits(v, ql)} - seen
        if hits:
            score += 2 * len(hits)
            detail.append("ind×2: " + ",".join(sorted(hits)))
            seen |= hits
    if "sig" in channels:
        hits = set(retrieve.key_hits(case.get("signature", ""), ql)) - seen
        if hits:
            score += 1 * len(hits)
            detail.append("sig×1: " + ",".join(sorted(hits)))
    if "probes" in channels:
        for probe in case.get("pattern_probes", []):
            if __import__("re").search(probe, ql, __import__("re").I):
                score += 4
                detail.append("probe×4: " + probe)
    return score, detail


def main():
    queries = [json.loads(l) for l in (EVAL / "queries.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    gold = json.loads((EVAL / "relations_gold.json").read_text(encoding="utf-8"))
    store = json.loads((BASE / "data/memory_store.json").read_text(encoding="utf-8"))
    cases = store["cases"]

    # ---- C2 自检：与官方 retrieve.score_case 完全一致
    mismatches = 0
    for q in queries:
        ql = q["text"].lower()
        for c in cases:
            s1, d1 = score_case_cfg(c, ql, CHANNELS["C2"])
            s2, d2 = retrieve.score_case(c, ql)
            if s1 != s2 or d1 != d2:
                mismatches += 1
                print(f"SELF-CHECK MISMATCH: {q['qid']} {c['id']}: {s1} vs {s2}")
    print(f"self-check C2 vs retrieve.score_case: {len(queries)*len(cases)} pairs, {mismatches} mismatches")

    # ---- 扩展邻接（按配置）
    neighbors = {cfg: defaultdict(set) for cfg in EXPANSION}
    for p in gold["pairs"]:
        if p["tier"] != "helpful":
            continue
        types = set(p.get("types") or [])
        for cfg, filt in EXPANSION.items():
            if filt is None or (types & filt):
                neighbors[cfg][p["a"]].add(p["b"])
                neighbors[cfg][p["b"]].add(p["a"])

    # ---- 入口：每配置 × 每查询
    entry = {}
    for cfg, ch in CHANNELS.items():
        rows = []
        for q in queries:
            ql = q["text"].lower()
            scored = []
            for c in cases:
                s, _ = score_case_cfg(c, ql, ch)
                if s > 0:
                    scored.append((s, c["id"]))
            scored.sort(key=lambda x: (-x[0], x[1]))
            ret = [i for _, i in scored]
            must, helpf, mis = set(q["must"]), set(q["helpful"]), set(q["misleading"])
            rank = next((r for r, i in enumerate(ret, 1) if i in must), None)
            rows.append({
                "qid": q["qid"], "group": q["group"],
                "ret": [(s, i) for s, i in scored],
                "hit1": bool(must & set(ret[:1])), "hit3": bool(must & set(ret[:3])),
                "rank": rank,
                "strong": any(s >= 6 and i in must for s, i in scored),
                "mid": any(s >= 4 and i in must for s, i in scored),
                "noise": len([i for i in ret if i not in must | helpf | mis]),
                "mis": len([i for i in ret if i in mis]),
                "max_any": max((s for s, _ in scored), default=0),
            })
        entry[cfg] = rows

    # ---- 扩展统计
    c2_by_qid = {r["qid"]: r["ret"] for r in entry["C2"]}
    expansion = {}
    details = []
    for cfg in EXPANSION:
        for gate_name, gate in GATES:
            st = dict(new_helpful=0, new_noise=0, new_mis=0, new_total=0,
                      h_total=0, h_ret=0, h_ret_b=0, ep_num=0, b_sum=0, e_sum=0,
                      neg_triggered=0, neg_total=0, pos_n=0)
            examples = []
            for q in queries:
                ret = c2_by_qid[q["qid"]]
                B = {i for _, i in ret}
                seeds = [i for s, i in ret if s >= gate]
                if not q["must"]:
                    st["neg_total"] += 1
                    if seeds:
                        st["neg_triggered"] += 1
                    continue
                st["pos_n"] += 1
                E = set(B)
                for sd in seeds:
                    E |= neighbors[cfg].get(sd, set())
                new = E - B
                must, H, mis = set(q["must"]), set(q["helpful"]), set(q["misleading"])
                st["new_helpful"] += len(new & H)
                st["new_noise"] += len([x for x in new if x not in H and x not in must])
                st["new_mis"] += len(new & mis)
                st["new_total"] += len(new)
                st["h_total"] += len(H)
                st["h_ret"] += len(H & E)
                st["h_ret_b"] += len(H & B)
                st["ep_num"] += len(new & (H | must))
                st["b_sum"] += len(B)
                st["e_sum"] += len(E)
                if new & H:
                    examples.append((q["qid"], sorted(new & H)))
                details.append({"qid": q["qid"], "cfg": cfg, "gate": gate_name,
                                "seeds": seeds, "new": sorted(new),
                                "new_helpful": sorted(new & H), "new_noise": sorted(new - H - must)})
            expansion[(cfg, gate_name)] = st
            st["examples"] = examples[:5]

    # ---- 报告
    def pct(x, n):
        return f"{100*x/n:.0f}%" if n else "—"

    def agg_rows(cfg_rows, group):
        rs = [r for r in cfg_rows if r["group"] == group]
        n = len(rs)
        if not n:
            return None
        pos = group != "C-negative"
        if pos:
            mrr = sum((1.0 / r["rank"]) if r["rank"] else 0 for r in rs) / n
            return (n, pct(sum(r["hit1"] for r in rs), n), pct(sum(r["hit3"] for r in rs), n),
                    f"{mrr:.2f}", pct(sum(r["strong"] for r in rs), n),
                    f"{sum(r['noise'] for r in rs)/n:.2f}", sum(r["mis"] for r in rs))
        else:
            empty = pct(sum(1 for r in rs if not r["ret"]), n)
            safe = pct(sum(1 for r in rs if r["max_any"] < 4), n)
            return (n, empty, safe, sum(r["mis"] for r in rs), f"{sum(r['noise'] for r in rs)/n:.2f}")

    lines = []
    lines.append("# 检索评测报告（DRAFT）")
    lines.append("")
    lines.append(f"- 查询数: {len(queries)}（分组: " + ", ".join(
        f"{g}={sum(1 for q in queries if q['group']==g)}" for g in GROUPS) + "）")
    lines.append(f"- 案例库: {len(cases)} 案例 · 关系矩阵: {len(gold['pairs'])} 对（{gold['meta']['status']}）")
    lines.append(f"- 配置: 入口 C0/C1/C2；扩展 C3(全边)/C4(跨簇: shares_infra+chain_sibling+same_phase)/C5(簇内: same_technique+same_family+shares_payload) × 门槛 甲(≥6)/乙(≥4)")
    lines.append(f"- C2 自检: 与 retrieve.score_case 比对 {len(queries)*len(cases)} 对，差异 {mismatches}")
    lines.append("")
    lines.append("## 表1 入口质量（分组合计）")
    lines.append("")
    lines.append("| 配置 | 分组 | n | Hit@1 | Hit@3 | MRR | 强命中率(≥6) | 噪声/查询 | misleading |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for cfg in CHANNELS:
        for g in GROUPS:
            if g == "C-negative":
                continue
            a = agg_rows(entry[cfg], g)
            if a:
                lines.append(f"| {cfg} | {g} | {a[0]} | {a[1]} | {a[2]} | {a[3]} | {a[4]} | {a[5]} | {a[6]} |")
    lines.append("")
    lines.append("负样本（C-negative）:  | 配置 | n | 空返回率 | 无中强命中率 | misleading | 噪声/查询 |")
    lines.append("|---|---|---|---|---|---|")
    for cfg in CHANNELS:
        a = agg_rows(entry[cfg], "C-negative")
        if a:
            lines.append(f"| {cfg} | {a[0]} | {a[1]} | {a[2]} | {a[3]} | {a[4]} |")
    lines.append("")
    lines.append("## 表2 扩展指标（C2 之上）")
    lines.append("")
    lines.append("| 配置 | 门槛 | 新发现(helpful) | 新增噪声 | 新增误导 | CR B→E | EP(micro) | 候选成本 B̄→Ē | 负样本触发扩展 |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for cfg in EXPANSION:
        for gate_name, gate in GATES:
            st = expansion[(cfg, gate_name)]
            cr = f"{st['h_ret_b']}/{st['h_total']}→{st['h_ret']}/{st['h_total']}" if st["h_total"] else "—"
            ep = f"{100*st['ep_num']/st['new_total']:.0f}%" if st["new_total"] else "—"
            # EP 分子：新增中属于 must∪helpful 的（must 通常已在 B 中，故≈new_helpful；保留口径说明）
            b̄ = st["b_sum"] / st["pos_n"] if st["pos_n"] else 0
            ē = st["e_sum"] / st["pos_n"] if st["pos_n"] else 0
            lines.append(f"| {cfg} | {gate_name} | {st['new_helpful']} | {st['new_noise']} | {st['new_mis']} | {cr} | {ep} | {b̄:.1f}→{ē:.1f} | {st['neg_triggered']}/{st['neg_total']} |")
    lines.append("")
    lines.append("> 注: 本阶段扩展边来自 gold 人工直连，CR(E) 为上界（按构造≈捞回 gold 邻居）；机械推导版（Phase 2）精度将低于此。CR(B)→CR(E) 的差与『新发现』列即扩展的上下文增益。")
    lines.append("")
    lines.append("## 表3 预注册判据核对（自动初判，人工终审）")
    lines.append("")
    for cfg in EXPANSION:
        for gate_name, gate in GATES:
            st = expansion[(cfg, gate_name)]
            noise = st["new_noise"]
            ratio = (st["new_helpful"] / noise) if noise else float("inf")
            r1 = "达标" if (noise == 0 and st["new_helpful"] > 0) or ratio >= 2 else ("无素材" if st["new_total"] == 0 else "未达标")
            r2 = "达标" if st["new_mis"] == 0 else "未达标"
            r3 = "达标" if st["neg_total"] and st["neg_triggered"] / st["neg_total"] <= 0.1 else ("无负样本" if not st["neg_total"] else "未达标")
            lines.append(f"- {cfg}@{gate_name}: 判据1 新发现:噪声≥2:1 → {r1}（{st['new_helpful']}:{noise}）; 判据2 误导=0 → {r2}（{st['new_mis']}）; 判据3 负样本零扩展≥90% → {r3}（{st['neg_triggered']}/{st['neg_total']}）")
    lines.append("")
    lines.append("## 附录A 扩展新发现样例")
    lines.append("")
    for cfg in EXPANSION:
        for gate_name, gate in GATES:
            st = expansion[(cfg, gate_name)]
            if st.get("examples"):
                lines.append(f"- {cfg}@{gate_name}: " + "; ".join(f"{q}→{'+'.join(ex)}" for q, ex in st["examples"]))
    lines.append("")
    lines.append("## 附录B 待复核的 gold 对（review=true）")
    lines.append("")
    for p in gold["pairs"]:
        if p.get("review"):
            lines.append(f"- {p['a']} ↔ {p['b']} [{p['tier']}] {'+'.join(p.get('types') or [])}: {p['evidence']}")
    lines.append("")
    lines.append("---")
    lines.append("*注：本报告为初版草稿；gold 矩阵与 qrels 复核后重跑 `python eval/run_eval.py` 即更新。*")

    (OUT / "report.md").write_text("\n".join(lines), encoding="utf-8")

    # details.jsonl（逐查询：C2 top3 + 各配置扩展新增）
    with (OUT / "details.jsonl").open("w", encoding="utf-8") as f:
        for q in queries:
            r = next(x for x in entry["C2"] if x["qid"] == q["qid"])
            row = {
                "qid": q["qid"], "group": q["group"], "text": q["text"],
                "must": q["must"], "helpful": q["helpful"],
                "c2_top3": r["ret"][:3],
                "expansion": [d for d in details if d["qid"] == q["qid"]],
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    summary = {
        "n_queries": len(queries),
        "entry": {cfg: {g: agg_rows(entry[cfg], g) for g in GROUPS} for cfg in CHANNELS},
        "expansion": {f"{cfg}@{g}": expansion[(cfg, g)] for cfg in EXPANSION for g, _ in GATES},
        "self_check_mismatches": mismatches,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"report: {OUT/'report.md'}")
    print(f"details: {OUT/'details.jsonl'}")
    print(f"summary: {OUT/'summary.json'}")


if __name__ == "__main__":
    main()

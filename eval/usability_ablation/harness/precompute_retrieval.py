#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""precompute_retrieval.py —— Stage 1：对 140 个 unit 逐个跑 demo 检索（只读，秒级）

产出：
  results/retrieval/<unit>.json     每个 unit 的完整检索结果 + 供 agent 注入的"去 case_id"证据
  results/retrieval_sweep.csv       每个 unit 一行：gt、top1、tier、matched/total、order、kw
  results/dataset_1001_1140.csv     4 列：序号 / 内容 / 检索结果（无则空） / 案例性质
  results/report_stage1.md          汇总：exact / same_pattern / family_variant / new 的分组表现

用法：python eval/usability_ablation/harness/precompute_retrieval.py
"""
import csv
import json
import pathlib
import sys
import collections

BASE = pathlib.Path(__file__).resolve().parents[3]
DEMO = BASE / "demo"
DS = BASE / "dataset"
OUT = BASE / "eval" / "usability_ablation" / "results"
GT_PATH = BASE / "eval" / "usability_ablation" / "gt_units.json"

sys.path.insert(0, str(DEMO / "src"))
from attack_memory.retrieval import build_action_index, retrieve  # noqa: E402
from attack_memory.storage import load_patterns  # noqa: E402

TIER_RANK = {"strong": 3, "medium": 2, "weak": 1, "keyword_only": 0, "none": -1}
LABEL = {"exact": "精确重复", "same_pattern": "同模式变体", "family_variant": "同族变体",
         "new": "新案例", "irrelevant": "无关"}


def load_units():
    lab = {}
    for fn in ("parsed_1001_1080.json", "parsed_1081_1140.json"):
        for l in json.loads((DS / fn).read_text(encoding="utf-8")):
            lab[l["unit"]] = l
    return dict(sorted(lab.items()))


def main():
    import argparse
    ap = argparse.ArgumentParser(); ap.add_argument("--out", default="")
    a = ap.parse_args()
    global OUT
    if a.out: OUT = BASE / "eval" / "usability_ablation" / "results" / a.out
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "retrieval").mkdir(exist_ok=True)
    patterns = load_patterns()["attack_patterns"]
    index = build_action_index(patterns)
    gt = json.loads(GT_PATH.read_text(encoding="utf-8"))["units"]
    units = load_units()

    rows, per_unit = [], {}
    for unit, l in units.items():
        logs = [dict(timestamp=e["ts"], source=e["source"], log_id=e["log_id"], content=e["content"],
                     event_id=f"{unit}-{e['log_id']}") for e in l["entries"]]
        results = retrieve(patterns, logs, index)
        top = results[0] if results else None
        g = gt[str(unit)]
        row = dict(unit=unit, gt_class=g["gt_class"], gt_case=g["gt_case"] or "",
                   top1=top["case_id"] if top else "", tier=top["tier"] if top else "",
                   matched=f"{top['matched_steps']}/{top['total_steps']}" if top else "",
                   order_ok=top["order_ok"] if top else "", kw=top["keyword_score"] if top else "",
                   n_candidates=len(results),
                   candidates=";".join(f"{r['case_id']}:{r['tier']}:{r['matched_steps']}/{r['total_steps']}"
                                       for r in results[:4]))
        rows.append(row)
        # 供 agent 注入的证据（去掉 case_id / name，避免抄答案）
        evidence = None
        if top:
            evidence = dict(
                tier=top["tier"], shape=top["shape"], matched_steps=top["matched_steps"],
                total_steps=top["total_steps"], order_ok=top["order_ok"],
                order_assessable=top["order_assessable"], source_fit_ratio=top["source_fit_ratio"],
                steps=[dict(step_id=e["step_id"], label=e["label"], sources=e["sources"],
                            generic=e["generic"], event_ids=e["event_ids"]) for e in top["evidence"]],
                unobserved_steps=top["unobserved_steps"], gap_steps=top["gap_steps"],
                before_steps=top["before_steps"],
                predict_next=top["predict_next"],
                source_mismatches=[dict(step_id=m["step_id"], observed_source=m["observed_source"],
                                        expected_sources=m["expected_sources"])
                                   for m in top["source_mismatches"]],
                keyword_score=top["keyword_score"], mitre=top["mitre"],
            )
        per_unit[unit] = dict(unit=unit, gt=g, technique=l["technique"],
                              sources=l["source_sequence"], logs=logs,
                              retrieval_full=results[:4], evidence_for_agent=evidence)
        (OUT / "retrieval" / f"{unit}.json").write_text(
            json.dumps(per_unit[unit], ensure_ascii=False, indent=1) + "\n", encoding="utf-8")

    # --- retrieval_sweep.csv ---
    with (OUT / "retrieval_sweep.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)

    # --- dataset_1001_1140.csv：4 列（序号 / 内容 / 检索结果 / 案例性质） ---
    with (OUT / "dataset_1001_1140.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["序号", "内容", "检索结果", "案例性质"])
        for unit, l in units.items():
            g = gt[str(unit)]
            top = per_unit[unit]["retrieval_full"][0] if per_unit[unit]["retrieval_full"] else None
            hit = f"{top['case_id']}({top['tier']},{top['matched_steps']}/{top['total_steps']})" if top else ""
            nature = LABEL[g["gt_class"]] + (f":{g['gt_case']}" if g["gt_case"] else "")
            w.writerow([unit, "\n".join(e["content"] for e in l["entries"]), hit, nature])

    # --- 汇总 ---
    def tier_of(r):
        return r["tier"] or "none"

    def strong_hit(r, case=None):
        return bool(r["top1"]) and tier_of(r) == "strong" and (case is None or r["top1"] == case)

    groups = collections.defaultdict(list)
    for r in rows:
        groups[r["gt_class"]].append(r)
    L = ["# Stage 1 · 检索层全量扫描（140 unit，不调用模型）", ""]
    L.append(f"- 案例库：8 个 pattern；unit：{len(rows)}（含 {len(groups['exact'])} 个精确重复）")
    L.append("- 口径：`top1` = 组合排序第一名；`strong` = 全覆盖 + 顺序可判且一致 + ≥1 非通用步")
    L.append("")
    L.append("## 一、分组表现")
    L.append("")
    L.append("| GT 类别 | n | top1 命中本家族/案例 | strong | medium | weak | keyword_only | 无候选 |")
    L.append("|---|---|---|---|---|---|---|---|")
    for cls in ("exact", "same_pattern", "family_variant", "new", "irrelevant"):
        sub = groups.get(cls, [])
        if not sub:
            continue
        if cls in ("exact", "same_pattern"):
            hit = sum(1 for r in sub if r["top1"] == r["gt_case"])
        else:
            hit = sum(1 for r in sub if r["gt_case"] and r["top1"] == r["gt_case"])
        tiers = collections.Counter(tier_of(r) for r in sub)
        none = sum(1 for r in sub if not r["top1"])
        L.append(f"| {cls} | {len(sub)} | {hit} | {tiers.get('strong',0)} | {tiers.get('medium',0)} | "
                 f"{tiers.get('weak',0)} | {tiers.get('keyword_only',0)} | {none} |")
    L.append("")
    if groups.get("exact"):
        L.append(f"- **精确重复（T0）**：{sum(1 for r in groups['exact'] if strong_hit(r, r['gt_case']))}/{len(groups['exact'])} 得到 strong 且 top1 正确（检索上界）。")
    if groups.get("new"):
        fm = [r for r in groups["new"] if tier_of(r) == "strong"]
        md = [r for r in groups["new"] if tier_of(r) == "medium"]
        L.append(f"- **新家族误匹配**：strong {len(fm)}/{len(groups['new'])}（{100*len(fm)/len(groups['new']):.1f}%），"
                 f"medium {len(md)}（{100*len(md)/len(groups['new']):.1f}%）。")
        if fm:
            L.append("  - strong 误匹配的 unit：" + ", ".join(f"{r['unit']}→{r['top1']}({r['matched']})" for r in fm[:12]))
    if groups.get("family_variant"):
        L.append(f"- **同族变体**：top1 落到本家族 {sum(1 for r in groups['family_variant'] if r['top1']==r['gt_case'])}/{len(groups['family_variant'])}，"
                 f"strong {sum(1 for r in groups['family_variant'] if tier_of(r)=='strong')}（变体被判完整匹配 = 需要人看的点）。")
    L.append("")
    L.append("## 二、逐案例召回（exact + same_pattern）")
    L.append("")
    L.append("| 案例 | n | top1 | strong | 说明 |")
    L.append("|---|---|---|---|---|")
    for case in sorted({r["gt_case"] for r in rows if r["gt_case"]}):
        sub = [r for r in rows if r["gt_case"] == case and r["gt_class"] in ("exact", "same_pattern")]
        if not sub:
            continue
        L.append(f"| {case} | {len(sub)} | {sum(1 for r in sub if r['top1']==case)} | "
                 f"{sum(1 for r in sub if strong_hit(r, case))} | "
                 f"{', '.join(str(r['unit']) for r in sub)} |")
    L.append("")
    L.append("## 三、新案例上的软性误匹配（weak / keyword_only 候选）")
    L.append("")
    soft = [r for r in rows if r["gt_class"] == "new" and r["top1"] and tier_of(r) != "strong"]
    L.append(f"共 {len(soft)}/{len(groups['new'])} 个新家族 unit 给出了候选（但都不是 strong）：")
    L.append("")
    L.append("| unit | top1 | tier | matched | 事例 |")
    L.append("|---|---|---|---|---|")
    for r in soft[:20]:
        L.append(f"| {r['unit']} | {r['top1']} | {r['tier']} | {r['matched']} | {units[r['unit']]['technique'][:36]} |")
    L.append("")
    L.append("## 四、同族变体的落点")
    L.append("")
    L.append("| unit | GT 家族 | top1 | tier | matched | 事例 |")
    L.append("|---|---|---|---|---|---|")
    for r in groups.get("family_variant", []):
        L.append(f"| {r['unit']} | {r['gt_case']} | {r['top1'] or '—'} | {r['tier'] or '无候选'} | {r['matched']} | "
                 f"{units[r['unit']]['technique'][:34]} |")
    L.append("")
    L.append("## 五、需要人工判断的 unit")
    L.append("")
    L.append("| unit | GT | top1 | tier | matched | 事例 |")
    L.append("|---|---|---|---|---|---|")
    for r in rows:
        if r["gt_class"] == "family_variant" and tier_of(r) == "strong":
            L.append(f"| {r['unit']} | {r['gt_class']}:{r['gt_case']} | {r['top1']} | {r['tier']} | {r['matched']} | "
                     f"{units[r['unit']]['technique'][:40]} |")
    (OUT / "report_stage1.md").write_text("\n".join(L) + "\n", encoding="utf-8")

    print(f"已写出：retrieval/{len(units)} 个 json · retrieval_sweep.csv · dataset_1001_1140.csv · report_stage1.md")
    for cls in ("exact", "same_pattern", "family_variant", "new"):
        sub = groups.get(cls, [])
        print(f"  {cls:14s} n={len(sub):3d}  top1命中={sum(1 for r in sub if r['gt_case'] and r['top1']==r['gt_case'])}  "
              f"strong={sum(1 for r in sub if tier_of(r)=='strong')}")


if __name__ == "__main__":
    main()

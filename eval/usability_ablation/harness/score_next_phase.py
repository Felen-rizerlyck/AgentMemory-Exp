#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""score_next_phase.py —— 用 gt_next_phase_60.json 给各条件的 next_step 打分

口径：
  hit      模型 next_step/stages 文本映射出的阶段 ∈ GT 可接受集合（1.0）
  adjacent 与任一可接受阶段在杀伤链上相差 1（0.5）
  miss     其余（0）
  primary  只看 gt_next_phases[0]（更严格的单点口径）
文本→阶段映射用关键词表（近似），映射不出任何阶段的记 miss 并单列。

用法：python score_next_phase.py [--exps exp1_memory_vs_retrieval,exp2_catalog]
输出：results/next_phase_scores.csv + results/next_phase_report.md
"""
import argparse
import csv
import json
import pathlib

BASE = pathlib.Path(__file__).resolve().parents[3]
EVA = BASE / "eval" / "usability_ablation"
RES = EVA / "results"
GT = json.loads((EVA / "gt_next_phase_60.json").read_text(encoding="utf-8"))
PHASES = GT["phases"]
ORDER = {p: i for i, p in enumerate(PHASES)}
KW = GT["keyword_map"]


def map_phases(text):
    t = (text or "").lower()
    hit = []
    for p, kws in KW.items():
        if any(k.lower() in t for k in kws):
            hit.append(p)
    return hit


def score_one(row):
    p = row.get("parsed") or {}
    g = GT["units"][str(row["unit"])]
    text = " ".join([str(p.get("next_step") or ""), " ".join(p.get("stages") or [])])
    pred = map_phases(text)
    acc = g["gt_next_phases"]
    if not pred:
        return dict(hit=0.0, primary=0.0, pred="(未映射)")
    if any(x in acc for x in pred):
        s = dict(hit=1.0, primary=1.0 if acc[0] in pred else 0.0)
    elif any(abs(ORDER[x] - ORDER[a]) == 1 for x in pred for a in acc):
        s = dict(hit=0.5, primary=0.0)
    else:
        s = dict(hit=0.0, primary=0.0)
    s["pred"] = "|".join(pred)
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exps", default="exp1_memory_vs_retrieval,exp2_catalog")
    a = ap.parse_args()
    rows = []
    for exp in a.exps.split(","):
        f = RES / exp / "runs.jsonl"
        if not f.exists():
            print(f"skip {exp}（无 runs.jsonl）")
            continue
        for line in f.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            r = json.loads(line)
            if not r.get("parse_ok"):
                continue
            r["exp"] = exp
            r["next"] = score_one(r)
            rows.append(r)

    out = RES / "next_phase_scores.csv"
    with out.open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["exp", "unit", "stratum", "gt_class", "gt_case", "model", "condition",
                    "gt_next", "pred_phases", "next_step", "hit", "primary"])
        for r in rows:
            w.writerow([r["exp"], r["unit"], r["stratum"], r["gt_class"], r["gt_case"], r["model"],
                        r["condition"], "|".join(GT["units"][str(r["unit"])]["gt_next_phases"]),
                        r["next"]["pred"], (r["parsed"] or {}).get("next_step", "")[:60],
                        r["next"]["hit"], r["next"]["primary"]])

    L = ["# next-step 预测得分（GT: gt_next_phase_60.json，60 条，文本→阶段为关键词近似映射）", ""]
    L.append("| 实验 | 模型 | 条件 | n | hit（含邻近） | 平均分 | 单点口径(primary) | 未映射 |")
    L.append("|---|---|---|---|---|---|---|---|")
    import collections
    groups = collections.defaultdict(list)
    for r in rows:
        groups[(r["exp"], r["model"], r["condition"])].append(r)
    for (exp, model, cond), sub in sorted(groups.items()):
        h = sum(1 for r in sub if r["next"]["hit"] > 0)
        avg = sum(r["next"]["hit"] for r in sub) / len(sub)
        pr = sum(1 for r in sub if r["next"]["primary"] > 0)
        nm = sum(1 for r in sub if r["next"]["pred"] == "(未映射)")
        L.append(f"| {exp} | {model} | {cond} | {len(sub)} | {h}/{len(sub)} | {avg:.2f} | {pr}/{len(sub)} | {nm} |")
    L.append("")
    L.append("## 按分层（hit 含邻近）")
    L.append("")
    L.append("| 实验 | 条件 | 模型 | exact | variant | new_with_candidate | new_no_candidate |")
    L.append("|---|---|---|---|---|---|---|")
    strata = ("exact", "variant", "new_with_candidate", "new_no_candidate")
    for (exp, model, cond), sub in sorted(groups.items()):
        cells = []
        for st in strata:
            x = [r for r in sub if r["stratum"] == st]
            cells.append(f"{sum(1 for r in x if r['next']['hit']>0)}/{len(x)}" if x else "—")
        L.append(f"| {exp} | {cond} | {model} | " + " | ".join(cells) + " |")
    (RES / "next_phase_report.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()

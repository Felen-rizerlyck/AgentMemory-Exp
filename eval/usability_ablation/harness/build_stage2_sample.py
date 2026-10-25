#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""build_stage2_sample.py —— Stage 2 抽样：60 个 unit（= 7 T0 + 29 变体 + 14 有候选新家族 + 10 无候选新家族）

输出：
  results/stage2_sample_60.csv   与 Stage 1 同格式 4 列（序号/内容/检索结果/案例性质）
  results/stage2_sample_60.json  分层元数据（stratum / gt / 检索证据摘要），供跑批脚本使用
"""
import csv
import json
import pathlib

BASE = pathlib.Path(__file__).resolve().parents[3]
EVA = BASE / "eval" / "usability_ablation"
RES = EVA / "results"
LABEL = {"exact": "精确重复", "family_variant": "同族变体", "new": "新案例", "irrelevant": "无关"}


def main():
    sweep = list(csv.DictReader((RES / "retrieval_sweep.csv").open(encoding="utf-8-sig", newline="")))
    gt = json.loads((EVA / "gt_units.json").read_text(encoding="utf-8"))["units"]
    units = {}
    for fn in ("parsed_1001_1080.json", "parsed_1081_1140.json"):
        for l in json.loads((BASE / "dataset" / fn).read_text(encoding="utf-8")):
            units[l["unit"]] = l

    exact = [r for r in sweep if r["gt_class"] == "exact"]
    var = [r for r in sweep if r["gt_class"] == "family_variant"]
    new_with = [r for r in sweep if r["gt_class"] == "new" and r["top1"]]
    new_without = [r for r in sweep if r["gt_class"] == "new" and not r["top1"]]

    # 有候选的新家族：按 top1 案例轮流取，保证 8 个案例的"关键词陷阱"都覆盖
    by_case = {}
    for r in new_with:
        by_case.setdefault(r["top1"], []).append(r)
    picked_with, i = [], 0
    while len(picked_with) < 14:
        for case in sorted(by_case):
            if len(picked_with) >= 14:
                break
            if i < len(by_case[case]):
                picked_with.append(by_case[case][i])
        i += 1
        if i > 10:
            break
    picked_without = new_without[:: max(1, len(new_without) // 10)][:10]

    sample = ([dict(r, stratum="exact") for r in exact]
              + [dict(r, stratum="variant") for r in var]
              + [dict(r, stratum="new_with_candidate") for r in picked_with]
              + [dict(r, stratum="new_no_candidate") for r in picked_without])
    assert len(sample) == 60, len(sample)

    with (RES / "stage2_sample_60.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["序号", "内容", "检索结果", "案例性质"])
        for r in sample:
            u = units[int(r["unit"])]
            top = (f"{r['top1']}({r['tier']},{r['matched']})" if r["top1"] else "")
            nature = LABEL[r["gt_class"]] + (f":{r['gt_case']}" if r["gt_case"] else "")
            w.writerow([r["unit"], "\n".join(e["content"] for e in u["entries"]), top, nature])

    meta = [dict(unit=int(r["unit"]), stratum=r["stratum"], gt_class=r["gt_class"],
                 gt_case=r["gt_case"], technique=units[int(r["unit"])]["technique"],
                 top1=r["top1"], tier=r["tier"], matched=r["matched"]) for r in sample]
    (RES / "stage2_sample_60.json").write_text(json.dumps(meta, ensure_ascii=False, indent=1) + "\n",
                                               encoding="utf-8")
    import collections
    print("样本 60 条：", dict(collections.Counter(m["stratum"] for m in meta)))
    print("GT 分布：", dict(collections.Counter(m["gt_class"] for m in meta)))
    print("无候选：", sum(1 for m in meta if not m["top1"]), "| top1 strong：", sum(1 for m in meta if m["tier"] == "strong"))


if __name__ == "__main__":
    main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""build_step_gt.py —— 为 60 个 unit 生成步骤级 GT（供"残缺补全/下一步"实验用）

步骤划分规则（与 7 个入库案例的步数逐一吻合，非人工猜测）：
  - waf 与 web 同一次请求（内容逐字相同）合并为一步，expected_sources=[waf,web]
  - 每条 rasp 一步，expected_sources=[rasp]
  - 每条 hids 一步，expected_sources=[hids]
  - 连续 dns 合并为一步（C2 突发），expected_sources=[dns]

每个 unit 产出 4 个变体：
  full     不删（对照：不应报缺口）
  del1     删掉中间一整步（应报 gap，并预测该步）
  del2     删掉中间步 + 末步（应报 gap + 预测下一步）
  delweb   只删 waf+web 步里的 web 行（步骤存在但来源不全，测 expected_sources 闸门）

输出：eval/usability_ablation/gt_step_level_60.json
"""
import json
import pathlib
import re

BASE = pathlib.Path(__file__).resolve().parents[3]
EVA = BASE / "eval" / "usability_ablation"
RES = EVA / "results"
OUT = EVA / "gt_step_level_60.json"


def load_units(units):
    got = {}
    for fn in ("parsed_1001_1080.json", "parsed_1081_1140.json"):
        for l in json.loads((BASE / "dataset" / fn).read_text(encoding="utf-8")):
            if l["unit"] in units:
                got[l["unit"]] = l
    return got


def split_steps(entries):
    """把渲染后的日志行切成步骤；返回 [{step_id, sources, idx:[行下标], label}]"""
    steps = []
    i = 0
    while i < len(entries):
        e = entries[i]
        src = e["source"]
        if src == "waf" and i + 1 < len(entries) and entries[i + 1]["source"] == "web" \
                and entries[i + 1]["content"] == e["content"]:
            idx, sources = [i, i + 1], ["waf", "web"]
            i += 2
        elif src == "dns":
            idx = [i]
            while i + 1 < len(entries) and entries[i + 1]["source"] == "dns":
                i += 1
                idx.append(i)
            sources = ["dns"]
            i += 1
        else:
            idx, sources = [i], [src]
            i += 1
        steps.append(dict(step_id=f"S{len(steps)+1}", sources=sources, idx=idx))
    for s in steps:
        first = entries[s["idx"][0]]["content"]
        src = s["sources"][0]
        if src in ("waf", "web"):
            path = first.split(" ")[0][:40]
            s["label"] = f"Web 入口（{path}）"
        elif src == "rasp":
            s["label"] = "应用侧证据（RASP 命中）"
        elif src == "hids":
            tok = first.split(" ")[0][:28]
            s["label"] = f"主机命令（{tok}）"
        elif src == "dns":
            dom = first.split(" ")[0][:40]
            s["label"] = f"DNS C2（{dom}）"
        s["n_lines"] = len(s["idx"])
    return steps


def variant(entries, steps, name, drop_steps=(), drop_sources=()):
    """生成一个残缺变体：drop_steps 整步删除；drop_sources 只删该来源的行（步骤仍在）"""
    drop_idx = set()
    for s in steps:
        if s["step_id"] in drop_steps:
            drop_idx.update(s["idx"])
        else:
            for k in s["idx"]:
                if entries[k]["source"] in drop_sources and len(s["idx"]) > 1:
                    drop_idx.add(k)
    kept_idx = [j for j in range(len(entries)) if j not in drop_idx]
    kept = [entries[j] for j in kept_idx]
    observed, missing = [], []
    for s in steps:
        remain = [j for j in s["idx"] if j not in drop_idx]
        (observed if remain else missing).append(s["step_id"])
    partial = []
    for s in steps:
        remain = [j for j in s["idx"] if j not in drop_idx]
        if remain and s["step_id"] in observed:
            seen_src = {entries[j]["source"] for j in remain}
            lost = [x for x in s["sources"] if x not in seen_src]
            if lost:
                partial.append(dict(step_id=s["step_id"], missing_sources=lost))
    nxt = missing[0] if missing else None
    scorable, note = True, ""
    if not kept:
        scorable, note = False, "删步后无日志（等同 blind 条件）"
    elif name == "del2" and len(missing) == 1:
        scorable, note = False, "与 del1 等价（只有 2 步）"
    elif name == "full":
        scorable, note = True, "对照：不应报缺口"
    return dict(scorable=scorable, note=note, kept_idx=kept_idx,
        variant=name, n_lines=len(kept), n_steps=len(steps),
        observed_steps=observed, missing_steps=missing, partial_source_steps=partial,
        gt_gap_expected=bool(missing) or bool(partial),
        gt_missing_sources=sorted({x for p_ in partial for x in p_["missing_sources"]}),
        gt_next_step=nxt,
        gt_next_label=next((s["label"] for s in steps if s["step_id"] == nxt), None),
        gt_next_sources=next((s["sources"] for s in steps if s["step_id"] == nxt), None),
        gt_missing_labels=[dict(step_id=s["step_id"], label=s["label"], sources=s["sources"])
                           for s in steps if s["step_id"] in missing],
    )


def main():
    sample = json.loads((RES / "exp1_memory_vs_retrieval" / "stage2_sample_60.json").read_text(encoding="utf-8"))
    units = load_units({m["unit"] for m in sample})
    store = {}
    for m in sample:
        u = m["unit"]
        entries = units[u]["entries"]
        steps = split_steps(entries)
        mids = [s["step_id"] for s in steps[1:-1]] or [steps[-1]["step_id"]]
        has_pair = any(s["sources"] == ["waf", "web"] for s in steps)
        vars_ = [variant(entries, steps, "full")]
        vars_.append(variant(entries, steps, "del1", drop_steps={mids[0]}))
        drop2 = {mids[0], steps[-1]["step_id"]} if len(steps) > 1 else {mids[0]}
        vars_.append(variant(entries, steps, "del2", drop_steps=drop2))
        if has_pair:
            vars_.append(variant(entries, steps, "delweb", drop_sources={"web"}))
        store[str(u)] = dict(
            unit=u, stratum=m["stratum"], gt_class=m["gt_class"], gt_case=m["gt_case"],
            technique=units[u]["technique"], source_sequence=units[u]["source_sequence"],
            steps=[dict(step_id=s["step_id"], sources=s["sources"], label=s["label"],
                        n_lines=s["n_lines"], lines=[entries[j]["content"] for j in s["idx"]])
                   for s in steps],
            variants=vars_,
        )
    (OUT).write_text(json.dumps(dict(schema="step-gt-v1", units=store), ensure_ascii=False, indent=1) + "\n",
                     encoding="utf-8")
    import collections
    print(f"已写 {OUT.name}：{len(store)} 个 unit")
    print("步数分布:", dict(collections.Counter(len(v["steps"]) for v in store.values())))
    print("变体总数:", sum(len(v["variants"]) for v in store.values()))
    for u in ("1001", "1021", "1042", "1061", "1081", "1102", "1121"):
        v = store[u]
        print(f"  {u} {len(v['steps'])} 步 | " + " / ".join(f"{s['step_id']}:{[x[0] for x in s['sources']]}" for s in v["steps"]))


if __name__ == "__main__":
    main()

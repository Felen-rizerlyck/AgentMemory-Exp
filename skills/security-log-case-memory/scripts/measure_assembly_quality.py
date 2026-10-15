#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""measure_assembly_quality.py — 链组装质量度量（并链 / 碎片 / 误并）

用途：调整 src/chain_assembly.py 的组装参数（WINDOW_S / CONCURRENT_S / CONCURRENT_LINK_S /
STAGE_TOLERANCE）后，用数据判断改得好不好。碎片或误并 > 0 时退出码非 0，可直接当门禁。

口径（取自三个入库数据集的单元结构 + history/old_eval 的 EXPECT 人工标注，单一事实源）：
  并链  同一单元内、期望同一案例的多行被组装进同一条链（越多越好）
  碎片  上述行被拆到多条链（漏并；基线目标 0）
  误并  一条链里混入期望不同案例的行（错并，危害最大，必须 0）

用法:
  python scripts/measure_assembly_quality.py [--repo F:/AI_Learning/AgentMemory]
         [--concurrent-window 30] [--window 3600] [--stage-tolerance 2]

依赖：仓库内 src/retrieve.py、src/chain_assembly.py、history/old_eval/run_recall_full.py、
dataset/data-901-910.txt|data-911-920.txt|data-9101-9110.txt（仅标准库）。
参数不传 = 用 chain_assembly 的默认值；--concurrent-window 0 = 关闭信号 2.5（做对照）。
"""
import argparse
import importlib.util
import pathlib
import sys
from collections import defaultdict

DATASETS = [("901-910", "data-901-910.txt"), ("911-920", "data-911-920.txt"),
            ("9101-9110", "data-9101-9110.txt")]


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    ap = argparse.ArgumentParser(description="链组装质量度量（并链/碎片/误并）")
    ap.add_argument("--repo", default="F:/AI_Learning/AgentMemory")
    ap.add_argument("--concurrent-window", type=float, default=None,
                    help="信号 2.5 并链窗（秒）；传 0 关闭该信号做对照")
    ap.add_argument("--window", type=float, default=None, help="宽松时间窗 WINDOW_S（秒）")
    ap.add_argument("--stage-tolerance", type=int, default=None, help="阶段倒置容忍档数")
    a = ap.parse_args()

    repo = pathlib.Path(a.repo)
    sys.path.insert(0, str(repo / "src"))
    import chain_assembly as ca          # noqa: E402
    import retrieve as ret               # noqa: E402
    rf = _load(repo / "history" / "old_eval" / "run_recall_full.py", "rf_measure")

    kw = {}
    if a.concurrent_window is not None:
        kw["concurrent_window"] = a.concurrent_window
    if a.window is not None:
        kw["window_s"] = a.window
    if a.stage_tolerance is not None:
        kw["stage_tolerance"] = a.stage_tolerance

    cases, lib = ret.load_store()
    merged = frag = mixed = 0
    details = []
    for tag, fn in DATASETS:
        units = rf.parse_file(repo / "dataset" / fn)
        exp = rf.EXPECT[tag]
        for ui, u in enumerate(units, 1):
            want = {e["log_id"]: exp[ui][i] for i, e in enumerate(u)}
            lines = [f"{e['ts']} [{e['source']}] {e['log_id']} {e['content']}" for e in u]
            chains = ca.assemble_chains(lines, lib=lib, matcher=ret.match_actions, **kw)
            loc = {l["log_id"]: ch["chain_id"] for ch in chains for l in ch["lines"]}
            groups = defaultdict(list)
            for e in u:
                groups[want[e["log_id"]] or "NONE"].append(e["log_id"])
            for g, ids in groups.items():
                if g == "NONE" or len(ids) < 2:
                    continue
                got = sorted({loc[i] for i in ids})
                if len(got) == 1:
                    merged += 1
                else:
                    frag += 1
                    details.append(f"[碎片] {tag} unit{ui} {g} 期望同链 {ids} → 实际 {got}")
            for ch in chains:
                ws = {want[l["log_id"]] for l in ch["lines"]} - {None}
                if len(ws) > 1:
                    mixed += 1
                    details.append(f"[误并] {tag} unit{ui} {ch['chain_id']} 混入 {sorted(ws)}")

    override = kw if kw else "默认参数"
    print(f"并链 {merged} / 碎片 {frag} / 误并 {mixed}   （{override}）")
    for d in details:
        print("   " + d)
    if frag or mixed:
        print("→ 未达标：碎片或误并 > 0，调参后重跑（误并必须为 0）")
        return 1
    print("→ 达标：碎片 0、误并 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""check_gates.py — AgentMemory 管线一次性门禁（行级铁律 + 链级指标 + 确定性 + 解析完整性）

用途：任何改动（打分/动作库/正则/参数/链层代码/案例库）之后跑这一条命令，拿到 PASS/FAIL。
参考基线（案例库扩充后数字会变，用 --expect-* 覆盖）：
  特征行 123 · Top-1 122 · Top-3 123 · 动作命中 123 · 强档 60 · 样板行 10
  链级：并链 35 / 碎片 0 / 误并 0 · 链级 Top-1 一致 57 / 1 条已知例外

用法:
  python check_gates.py [--repo F:/AI_Learning/AgentMemory] [--shuffle 200]
         [--expect-top1 122] [--expect-hit 123] [--expect-strong 60] [--expect-feat 123]
         [--skip-subprocess]     # 跳过 build/tests 子进程环节（只算指标，快）
退出码：0 全部通过；1 有失败项（逐项打印 got vs expected）。
依赖：仓库内 src/、scripts/、eval/、tests/、dataset/、history/old_eval（仅标准库）。
"""
import argparse
import importlib.util
import json
import pathlib
import random
import re
import subprocess
import sys
from collections import defaultdict

DATASETS = [("901-910", "data-901-910.txt"), ("911-920", "data-911-920.txt"),
            ("9101-9110", "data-9101-9110.txt")]
# 已知例外：链级 Top-1 与行级人工期望不同（混合载荷单元，期望案例仍在 Top-3）；新增例外要写明原因
KNOWN_TOP1_DIFF = {("9101-9110", "WAF0000272"): ("CASE-003", "CASE-016")}


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run(cmd, cwd):
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, encoding="utf-8", errors="replace")
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main():
    ap = argparse.ArgumentParser(description="AgentMemory 管线门禁")
    ap.add_argument("--repo", default="F:/AI_Learning/AgentMemory")
    ap.add_argument("--shuffle", type=int, default=200)
    ap.add_argument("--expect-feat", type=int, default=123)
    ap.add_argument("--expect-top1", type=int, default=122)
    ap.add_argument("--expect-hit", type=int, default=123)
    ap.add_argument("--expect-strong", type=int, default=60)
    ap.add_argument("--skip-subprocess", action="store_true")
    a = ap.parse_args()
    repo = pathlib.Path(a.repo)
    py = sys.executable
    fails, notes = [], []

    # ---- 1. 注入/校验 + 子进程测试 ----
    if not a.skip_subprocess:
        rc, out = run([py, "scripts/build_action_index.py", "--dry-run"], repo)
        (notes if "校验通过" in out else fails).append("build_action_index --dry-run: " + ("校验通过" if "校验通过" in out else out.strip()[-200:]))
        for t in ("tests/test_chain_assembly.py", "tests/test_chain_integration.py"):
            rc, out = run([py, t], repo)
            fails.append(f"{t}: 未通过\n{out.strip()[-300:]}") if rc != 0 else notes.append(f"{t}: OK")

    # ---- 2. 行级回归（eval 报告的总览行）----
    rc, out = run([py, "eval/run_action_recall.py"], repo)
    m = re.search(r"特征行 (\d+) · Top-1 (\d+) · Top-3 (\d+) · 出现 (\d+) · 动作命中 (\d+) · "
                  r"动作强档 (\d+) · 样板行 (\d+)", out)
    if rc != 0 or not m:
        fails.append("eval/run_action_recall.py: 无总览输出 → " + out.strip()[-200:])
    else:
        feat, top1, _t3, _pr, hit, strong, gen = (int(x) for x in m.groups())
        for label, got, want in (("特征行", feat, a.expect_feat), ("Top-1", top1, a.expect_top1),
                                 ("动作命中", hit, a.expect_hit), ("强档", strong, a.expect_strong)):
            (notes if got == want else fails).append(f"行级 {label}: {got}（期望 {want}）")
        notes.append(f"样板行 {gen}（无唯一预期）")
        report = (repo / "eval" / "results" / "report_action_recall.md")
        if report.exists():
            txt = report.read_text(encoding="utf-8")
            mm = re.search(r"动作通道静默: (\d+)/(\d+)", txt)
            (fails if mm and mm.group(1) != mm.group(2) else notes).append(
                f"前瞻 NOVEL 静默: {mm.group(1)}/{mm.group(2)}" if mm else "前瞻 NOVEL: 未取到")

    # ---- 3. 组装质量（并链/碎片/误并；误并必须 0）----
    sibling = pathlib.Path(__file__).resolve().parent / "measure_assembly_quality.py"
    rc, out = run([py, str(sibling), "--repo", str(repo)], repo)
    if rc != 0:
        fails.append("组装质量未达标: " + out.strip().splitlines()[0] if out.strip() else "组装质量未达标")
    else:
        notes.append("组装质量: " + out.strip().splitlines()[0])

    # ---- 4. 链级 Top-1 + 确定性 + 解析完整性（进程内，改链层/库后必跑）----
    sys.path.insert(0, str(repo / "src"))
    import chain_assembly as ca  # noqa: E402
    import retrieve as ret      # noqa: E402
    rf = _load(repo / "history" / "old_eval" / "run_recall_full.py", "rf_gate")
    cases, lib = ret.load_store()
    canon = lambda ls: json.dumps(ca.assemble_chains(ls, lib=lib, matcher=ret.match_actions),
                                  ensure_ascii=False, sort_keys=True)  # noqa: E731

    ok = bad = 0
    for tag, fn in DATASETS:
        units = rf.parse_file(repo / "dataset" / fn)
        exp = rf.EXPECT[tag]
        emap = {e["log_id"]: exp[ui][i] for ui, u in enumerate(units, 1) for i, e in enumerate(u)}
        lines = [f"{e['ts']} [{e['source']}] {e['log_id']} {e['content']}"
                 for u in units for e in u]
        chains = ca.assemble_chains(lines, lib=lib, matcher=ret.match_actions)
        for ch in chains:
            ws = {emap[l["log_id"]] for l in ch["lines"]} - {None}
            if len(ws) > 1:
                fails.append(f"链级误并: {tag} {ch['chain_id']} 混入 {sorted(ws)}")
                continue
            if not ws:
                continue
            want = sorted(ws)[0]
            ms = ret.chain_match(ch, cases, lib)
            top = ms[0]["id"] if ms else None
            key = (tag, ch["lines"][0]["log_id"])
            if key in KNOWN_TOP1_DIFF:
                ew, et = KNOWN_TOP1_DIFF[key]
                (notes if (want, top) == (ew, et) else fails).append(f"链级已知例外核对: {key} → {want}/{top}（期望 {ew}/{et}）")
            elif top == want:
                ok += 1
            else:
                bad += 1
                fails.append(f"链级 Top-1: {tag} {ch['chain_id']} 期望 {want} 得 {top}")
    notes.append(f"链级 Top-1: 一致 {ok} / 差异 {bad}（另 {len(KNOWN_TOP1_DIFF)} 条已知例外）")

    def shuffle_diff(base_lines, n):
        """每次都从原顺序复制后打乱（避免在已打乱的列表上继续打乱，保持 N 次独立置换）"""
        ref = canon(base_lines)
        bad_n = 0
        for s in range(n):
            ls = list(base_lines)
            random.Random(s).shuffle(ls)
            if canon(ls) != ref:
                bad_n += 1
        return bad_n

    live = repo / "data" / "incoming_logs.txt"
    if live.exists():
        diff = shuffle_diff(live.read_text(encoding="utf-8").splitlines(), a.shuffle)
        (fails if diff else notes).append(f"乱序确定性(真实批): {diff}/{a.shuffle} 次不一致")
    tie = ["2026-06-02 09:00:00 [waf] /api/v1/query a", "2026-06-02 09:00:00 [rasp] /api/v1/query b",
           "2026-06-02 09:00:00 [hids] net user /add x", "2026-06-02 09:00:00 [dns] q.host.net A 203.0.113.9"]
    diff = shuffle_diff(tie, a.shuffle)
    (fails if diff else notes).append(f"乱序确定性(并列键): {diff}/{a.shuffle} 次不一致")

    # ---- 汇总 ----
    print("== PASS ==")
    for n in notes:
        print("  ✓ " + n)
    if fails:
        print("== FAIL ==")
        for f in fails:
            print("  ✗ " + f)
        print(f"\n{len(fails)} 项未通过")
        return 1
    print("\n全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())

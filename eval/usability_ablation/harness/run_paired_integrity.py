#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""run_paired_integrity.py —— exp5d：配对判别（同一链的完整版 vs 删行版，同时呈现）

每对跑两种顺序（A=完整/B=删行 与 反过来），用于检查位置偏置。
GT：被删行的那个是不完整样本。
指标：配对正确率（选中完整版）、判 same 的比例、位置偏置。

提示词固定；输出 results/exp5d_paired/。
"""
import argparse
import json
import pathlib
import random
import sys
import time

BASE = pathlib.Path(__file__).resolve().parents[3]
EVA = BASE / "eval" / "usability_ablation"
OUT = EVA / "results" / "exp5d_paired"
RUNS = OUT / "runs.jsonl"
sys.path.insert(0, str(EVA / "harness"))
import run_llm_arm as H  # noqa: E402
import run_chain_integrity as E5  # noqa: E402

SYS = ("你是企业安全告警分析员。下面给出同一事件的两次日志导出（样本 A 与样本 B），"
       "其中一次被删掉了个别行。请判断哪一份更完整。"
       "只输出一个 JSON 对象，不要解释，不要代码块。字段："
       '{"more_complete":"A|B|same","reason":"不超过40字","confidence":3}')
USER = ("样本 A：\n\n{a}\n\n样本 B：\n\n{b}\n\n哪一份日志更完整？")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5:14b")
    ap.add_argument("--score", action="store_true")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    if a.score:
        return summary()

    units = E5.load_units()
    rng = random.Random(20261024)
    pairs = []
    sealed = {}
    for u, rows in sorted(units.items()):
        if len(rows) < 5:
            continue
        d1 = sorted(rng.sample(range(len(rows)), 1))
        drop = [r for i, r in enumerate(rows) if i not in d1]
        pairs.append((u, rows, drop)); sealed[str(u)] = d1
    (OUT / "sealed_deletions.json").write_text(json.dumps(sealed, indent=1), encoding="utf-8")

    jobs = []
    for u, full, drop in pairs:
        jobs.append((u, "full_A", full, drop))     # 完整在 A
        jobs.append((u, "full_B", drop, full))     # 完整在 B
    done = set()
    if RUNS.exists():
        for l in RUNS.read_text(encoding="utf-8").splitlines():
            if l.strip():
                r = json.loads(l); done.add((r["unit"], r["layout"]))
    todo = [j for j in jobs if (j[0], j[1]) not in done]
    print(f"待跑 {len(todo)} 次（已完成 {len(done)}）", flush=True)

    for i, (u, layout, sa, sb) in enumerate(todo, 1):
        user = USER.format(a=E5.render(sa), b=E5.render(sb))
        ok, raw, lat, err = False, "", 0.0, ""
        for attempt in range(2):
            try:
                raw, _, lat = H.call(a.model, SYS, user, 500 + attempt * 300); ok = True; break
            except Exception as e:
                err = f"{type(e).__name__}:{e}"; time.sleep(2)
        parsed = H.parse_json(raw)
        pick = (parsed or {}).get("more_complete")
        truth = "A" if layout == "full_A" else "B"
        row = dict(run_id=f"{u}-{layout}", ts=time.strftime("%Y-%m-%dT%H:%M:%S"), unit=u, layout=layout,
                   model=a.model, truth=truth, pick=pick, correct=(pick == truth),
                   n_a=len(sa), n_b=len(sb), prompt_sha=H.sha(SYS + "\n---\n" + user),
                   latency_s=round(lat, 1), ok=ok, error=err, raw=raw, parsed=parsed,
                   parse_ok=parsed is not None)
        with RUNS.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"[{i}/{len(todo)}] {u} {layout:7s} pick={pick} truth={truth} "
              f"({'✓' if pick == truth else '✗'}) {lat:.1f}s", flush=True)
    summary()


def summary():
    rows = [json.loads(l) for l in RUNS.read_text(encoding="utf-8").splitlines() if l.strip()]
    n = len(rows)
    ok = sum(1 for r in rows if r["correct"])
    same = sum(1 for r in rows if r["pick"] == "same")
    byA = [r for r in rows if r["layout"] == "full_A"]
    byB = [r for r in rows if r["layout"] == "full_B"]
    L = ["# exp5d · 配对判别（完整版 vs 删行版同时给出，无记忆）", "",
         f"- 模型：{rows[0]['model'] if rows else '-'}；调用 {n} 次；解析失败 {sum(1 for r in rows if not r['parse_ok'])}",
         f"- **配对正确率：{ok}/{n} = {100*ok/max(1,n):.0f}%**（随机基线 50%，全选 A 或全选 B 都是 50%）",
         f"- 判 same：{same}/{n}",
         f"- 位置：完整在 A 时正确 {sum(1 for r in byA if r['correct'])}/{len(byA)}；"
         f"完整在 B 时正确 {sum(1 for r in byB if r['correct'])}/{len(byB)}",
         "",
         "注意：完整版必然比删行版长，模型若只按“行数多”作答也能拿到高分——因此还要看它在 same 上的比例与 reason 是否提到具体内容。"]
    (OUT / "report.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()

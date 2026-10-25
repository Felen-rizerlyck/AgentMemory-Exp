#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""run_partial_arm.py —— exp3：残缺日志上的"补全 / 下一步来源"判定

条件：direct（只给残缺日志）/ catalog（+8 条案例摘要）/ assisted（+摘要+按残缺日志重算的召回证据）
数据：gt_step_level_60.json 的 del1 / del2（可加 delweb）；只跑 scorable 变体
记录：results/exp3_partial/runs.jsonl，字段与 exp1/exp2 对齐，便于合并分析

用法：
  python run_partial_arm.py --models qwen2.5:14b --conditions direct,catalog,assisted --variants del1,del2
  python run_partial_arm.py --models qwen2.5:14b --score
"""
import argparse
import json
import pathlib
import sys
import time

BASE = pathlib.Path(__file__).resolve().parents[3]
EVA = BASE / "eval" / "usability_ablation"
RES = EVA / "results"
OUTDIR = RES / "exp3_partial"
RUNS = OUTDIR / "runs.jsonl"
sys.path.insert(0, str(BASE / "demo" / "src"))
sys.path.insert(0, str(EVA / "harness"))

import run_llm_arm as H  # noqa: E402
from attack_memory.retrieval import build_action_index, retrieve  # noqa: E402
from attack_memory.storage import load_patterns  # noqa: E402

SCHEMA = ('{"verdict":"match|new|incomplete","case_id":"CASE-00x 或 null","gap":true,'
          '"missing_steps":["缺失的步骤描述"],"next_sources":["waf|web|rasp|hids|dns"],'
          '"next_step":"下一步最可能做什么","confidence":3}')
SYS = ("你是企业安全告警分析员。日志可能不完整：可能缺少某个阶段，或某一步只有部分来源的日志。"
       "请判断是否完整、缺什么、下一步最可能出现哪个来源的日志。只输出一个 JSON 对象，不要解释，不要代码块。字段：" + SCHEMA)


def build_prompt(cond, logs, catalog, evidence, n_lines):
    parts = []
    if cond in ("catalog", "assisted"):
        parts.append(H.fmt_catalog(catalog))
    if cond == "assisted":
        parts.append(H.fmt_evidence(evidence))
    parts.append(f"【待分析日志】（同一事件，按时间序，共 {n_lines} 条）\n\n{logs}")
    parts.append("请判断：这组日志是否完整？若缺少步骤或某一步缺少来源，gap 设为 true 并在 missing_steps 写明缺什么；"
                 "再给出下一步最可能出现哪个来源的日志（next_sources，可多选）。")
    return SYS, "\n\n".join(parts)


def make_logs(unit_json, kept_idx):
    return "\n".join(f"[{unit_json['logs'][j]['timestamp']}] [{unit_json['logs'][j]['source']}] "
                     f"{unit_json['logs'][j]['content']}" for j in kept_idx)


def log_dicts(unit_json, kept_idx):
    return [dict(timestamp=unit_json["logs"][j]["timestamp"], source=unit_json["logs"][j]["source"],
                 log_id=unit_json["logs"][j]["log_id"], content=unit_json["logs"][j]["content"],
                 event_id=f"{unit_json['unit']}-{unit_json['logs'][j]['log_id']}")
            for j in kept_idx]


def score(row, var):
    p = row.get("parsed") or {}
    gap = p.get("gap")
    ns = [x for x in (p.get("next_sources") or []) if isinstance(x, str)]
    s = dict(gap_ok=(bool(gap) == bool(var["gt_gap_expected"])),
             false_gap=(var["variant"] == "full" and bool(gap)),
             next_ok=None, missing_ok=None)
    if var.get("gt_next_sources"):
        pred = {x.lower() for x in ns}
        gt = set(var["gt_next_sources"])
        s["next_ok"] = gt.issubset(pred)
        s["next_exact"] = pred == gt
    if var.get("gt_missing_sources"):
        txt = " ".join(str(x) for x in (p.get("missing_steps") or [])).lower()
        s["missing_ok"] = all(src in txt for src in var["gt_missing_sources"])
    return s


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="qwen2.5:14b")
    ap.add_argument("--conditions", default="direct,catalog,assisted")
    ap.add_argument("--variants", default="del1,del2")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--score", action="store_true")
    a = ap.parse_args()
    OUTDIR.mkdir(parents=True, exist_ok=True)

    if a.score:
        return summary()

    gt = json.loads((EVA / "gt_step_level_60.json").read_text(encoding="utf-8"))["units"]
    cat = H.load_catalog()
    patterns = load_patterns()["attack_patterns"]
    index = build_action_index(patterns)
    want = {v.strip() for v in a.variants.split(",")}
    conds = [c.strip() for c in a.conditions.split(",")]
    models = [m.strip() for m in a.models.split(",")]

    done = set()
    if RUNS.exists():
        for line in RUNS.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                done.add((r["unit"], r["variant"], r["condition"], r["model"]))

    todo = []
    for u, g in gt.items():
        for var in g["variants"]:
            if var["variant"] not in want or not var["scorable"]:
                continue
            for c in conds:
                for m in models:
                    if (int(u), var["variant"], c, m) not in done:
                        todo.append((int(u), g, var, c, m))
    todo.sort(key=lambda x: (x[0], x[2]["variant"], x[3], x[4]))
    if a.limit:
        todo = todo[: a.limit]
    print(f"待跑 {len(todo)} 次（已完成 {len(done)}）", flush=True)

    for i, (u, g, var, cond, model) in enumerate(todo, 1):
        uj = json.loads((RES / "retrieval" / f"{u}.json").read_text(encoding="utf-8"))
        logs_txt = make_logs(uj, var["kept_idx"])
        ev = None
        if cond == "assisted":
            res = retrieve(patterns, log_dicts(uj, var["kept_idx"]), index)
            if res:
                t = res[0]
                t = dict(t, case_id=t["case_id"])  # 保留 id：与 exp1 assisted_free 口径一致
                ev = dict(tier=t["tier"], shape=t["shape"], matched_steps=t["matched_steps"],
                          total_steps=t["total_steps"], order_ok=t["order_ok"],
                          order_assessable=t["order_assessable"], source_fit_ratio=t["source_fit_ratio"],
                          steps=[dict(step_id=e["step_id"], label=e["label"], sources=e["sources"],
                                      generic=e["generic"], event_ids=e["event_ids"]) for e in t["evidence"]],
                          unobserved_steps=t["unobserved_steps"], gap_steps=t["gap_steps"],
                          predict_next=t["predict_next"], source_mismatches=t["source_mismatches"],
                          keyword_score=t["keyword_score"], mitre=t["mitre"])
                ev["case_id"] = t["case_id"]
        sys_p, user_p = build_prompt(cond, logs_txt, cat, ev, var["n_lines"])
        mt = 1600 if "r1" in model else 700
        ok, raw, reasoning, lat, err = False, "", "", 0.0, ""
        for attempt in range(2):
            try:
                raw, reasoning, lat = H.call(model, sys_p, user_p, mt + attempt * 800)
                ok = True
                break
            except Exception as e:
                err = f"{type(e).__name__}:{e}"
                time.sleep(3)
        parsed = H.parse_json(raw)
        row = dict(run_id=f"{u}-{var['variant']}-{model.split(':')[0]}-{cond}",
                   ts=time.strftime("%Y-%m-%dT%H:%M:%S"), unit=u, variant=var["variant"],
                   stratum=g["stratum"], gt_class=g["gt_class"], gt_case=g["gt_case"],
                   model=model, condition=cond, prompt_sha=H.sha(sys_p + "\n---\n" + user_p),
                   prompt_chars=len(sys_p) + len(user_p), temperature=0, ok=ok,
                   latency_s=round(lat, 1), error=err, raw=raw, reasoning=(reasoning or "")[:4000],
                   parsed=parsed, parse_ok=parsed is not None)
        row["scores"] = score(row, var)
        with RUNS.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        p = parsed or {}
        print(f"[{i}/{len(todo)}] {u} {var['variant']:6s} {model.split(':')[0]:8s} {cond:8s} "
              f"{lat:5.1f}s gap={p.get('gap')} ns={p.get('next_sources')} conf={p.get('confidence')}", flush=True)
    summary()


def summary():
    if not RUNS.exists():
        print("no runs")
        return
    rows = [json.loads(l) for l in RUNS.read_text(encoding="utf-8").splitlines() if l.strip()]
    gt = json.loads((EVA / "gt_step_level_60.json").read_text(encoding="utf-8"))["units"]
    vmap = {(int(u), v["variant"]): v for u, g in gt.items() for v in g["variants"]}
    for r in rows:
        r["scores"] = score(r, vmap[(r["unit"], r["variant"])])
    import collections
    L = ["# exp3_partial · 残缺日志上的补全/下一步判定", ""]
    L.append(f"- 调用数：{len(rows)}；解析失败：{sum(1 for r in rows if not r['parse_ok'])}")
    L.append("")
    L.append("| 模型 | 条件 | 变体 | n | gap 判对 | 下一步来源(覆盖) | 下一步来源(全等) | 缺来源判对 |")
    L.append("|---|---|---|---|---|---|---|---|")
    for (m, c, v), sub in sorted(collections.defaultdict(list, {
            k: [r for r in rows if (r["model"], r["condition"], r["variant"]) == k]
            for k in {(r["model"], r["condition"], r["variant"]) for r in rows}}).items()):
        g = sum(1 for r in sub if r["scores"].get("gap_ok"))
        nxt = [r for r in sub if r["scores"].get("next_ok") is not None]
        ms = [r for r in sub if r["scores"].get("missing_ok") is not None]
        L.append(f"| {m} | {c} | {v} | {len(sub)} | {g} | "
                 f"{sum(1 for r in nxt if r['scores']['next_ok'])}/{len(nxt)} | "
                 f"{sum(1 for r in nxt if r['scores'].get('next_exact'))}/{len(nxt)} | "
                 f"{sum(1 for r in ms if r['scores']['missing_ok'])}/{len(ms)} |")
    (OUTDIR / "report_exp3_partial.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()

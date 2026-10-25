#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""run_chain_integrity.py —— exp5：只给日志，测模型能否判断"攻击链是否完整"（qwen2.5:14b，无记忆模块）

条件：
  full    完整链（GT: complete=true）
  drop1   随机删 1 行（GT: complete=false）
  drop2   随机删 2 行（GT: complete=false，仅用于 ≥10 行的链）

prompt 固定：同一 system + 同一 user 模板，只有日志块不同；模板落盘 prompt_template.txt。
每行记录 prompt_sha，保证可复核"是否用了同一提示词"。

输出（与 exp1–4 完全分离）：results/exp5_chain_integrity/{runs.jsonl,summary.csv,report.md,prompt_template.txt,sealed_deletions.json}
用法：python run_chain_integrity.py [--models qwen2.5:14b] [--limit N] [--score]
"""
import argparse
import csv
import json
import pathlib
import random
import re
import sys
import time

BASE = pathlib.Path(__file__).resolve().parents[3]
EVA = BASE / "eval" / "usability_ablation"
DATA = EVA / "场景二_攻击链_202607" / "data"
OUT = EVA / "results" / "exp5_chain_integrity"
RUNS = OUT / "runs.jsonl"
sys.path.insert(0, str(EVA / "harness"))
import run_llm_arm as H  # noqa: E402

SYS = ("你是企业安全告警分析员。你会看到一条攻击链的日志，它可能完整，也可能被删掉了个别行。"
       "请判断这条链的日志是否完整（是否缺少必要阶段或某个阶段的日志来源）。"
       "只输出一个 JSON 对象，不要解释，不要代码块。字段："
       '{"complete":true,"missing":["缺失的阶段或来源"],"reason":"不超过40字","confidence":3}')

USER_TMPL = ("以下是一条攻击链的日志（按时间序）：\n\n{logs}\n\n"
             "请判断这组日志是否完整；若不完整，missing 里写明缺什么。")

UNIT_RE = re.compile(r"(?m)^(\d+)\.\s+`([^`]+)`\s+\*\*\[([^\]]+)\]\*\*\s+`([^`]+)`\n\s+`([^`]*)`")


def load_units():
    units = {}
    for f in sorted(DATA.glob("data-*.txt")):
        txt = f.read_text(encoding="utf-8")
        blocks = re.split(r"(?m)(?=^1\.\s+`)", txt)
        uid = 2000 + len(units) + 1
        for b in blocks:
            rows = UNIT_RE.findall(b)
            if rows:
                units[uid] = [dict(n=int(r[0]), ts=r[1], source=r[2], logid=r[3], text=r[4]) for r in rows]
                uid += 1
    return units


def render(rows):
    out = []
    for r in rows:
        out.append(f"[{r['ts']}] [{r['source']}] {r['text']}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--models", default="qwen2.5:14b")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--seed", type=int, default=20261023)
    ap.add_argument("--score", action="store_true")
    a = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "prompt_template.txt").write_text("=== SYSTEM ===\n" + SYS + "\n\n=== USER ===\n" + USER_TMPL + "\n",
                                             encoding="utf-8")
    if a.score:
        return summary()

    units = load_units()
    rng = random.Random(a.seed)
    cases, sealed = [], {}
    for u, rows in sorted(units.items()):
        if len(rows) < 5:          # 太短的链删一行就失真，只测完整
            cases.append((u, "full", rows)); continue
        cases.append((u, "full", rows))
        d1 = sorted(rng.sample(range(len(rows)), 1))
        cases.append((u, "drop1", [r for i, r in enumerate(rows) if i not in d1]))
        sealed[f"{u}-drop1"] = d1
        if len(rows) >= 10:
            d2 = sorted(rng.sample(range(len(rows)), 2))
            cases.append((u, "drop2", [r for i, r in enumerate(rows) if i not in d2]))
            sealed[f"{u}-drop2"] = d2
    (OUT / "sealed_deletions.json").write_text(json.dumps(sealed, indent=1), encoding="utf-8")

    done = set()
    if RUNS.exists():
        for line in RUNS.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line); done.add((r["unit"], r["condition"], r["model"]))
    models = [m.strip() for m in a.models.split(",")]
    todo = [(u, c, rows, m) for m in models for (u, c, rows) in cases if (u, c, m) not in done]
    if a.limit:
        todo = todo[:a.limit]
    print(f"待跑 {len(todo)} 次（已完成 {len(done)}）", flush=True)

    for i, (u, cond, rows, model) in enumerate(todo, 1):
        user = USER_TMPL.format(logs=render(rows))
        ok, raw, reasoning, lat, err = False, "", "", 0.0, ""
        for attempt in range(2):
            try:
                raw, reasoning, lat = H.call(model, SYS, user, 600 + attempt * 400)
                ok = True; break
            except Exception as e:
                err = f"{type(e).__name__}:{e}"; time.sleep(3)
        parsed = H.parse_json(raw)
        gt_complete = (cond == "full")
        pred = None if not parsed else bool(parsed.get("complete"))
        row = dict(run_id=f"{u}-{cond}-{model.split(':')[0]}", ts=time.strftime("%Y-%m-%dT%H:%M:%S"),
                   unit=u, condition=cond, model=model, n_lines=len(rows),
                   gt_complete=gt_complete, pred_complete=pred,
                   correct=(pred == gt_complete) if pred is not None else None,
                   prompt_sha=H.sha(SYS + "\n---\n" + user), prompt_chars=len(SYS) + len(user),
                   latency_s=round(lat, 1), ok=ok, error=err, raw=raw,
                   reasoning=(reasoning or "")[:2000], parsed=parsed, parse_ok=parsed is not None)
        with RUNS.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"[{i}/{len(todo)}] {u} {cond:6s} {len(rows):2d}行 {lat:5.1f}s "
              f"complete={pred} (GT={gt_complete}) conf={(parsed or {}).get('confidence')}", flush=True)
    summary()


def summary():
    rows = [json.loads(l) for l in RUNS.read_text(encoding="utf-8").splitlines() if l.strip()]
    import collections
    L = ["# exp5 · 攻击链完整性判断（只给日志，无记忆模块）", ""]
    L.append(f"- 模型：{', '.join(sorted({r['model'] for r in rows}))}；调用 {len(rows)} 次；"
             f"解析失败 {sum(1 for r in rows if not r['parse_ok'])}")
    L.append("- 条件：`full`=完整链；`drop1`/`drop2`=随机删 1/2 行（删除位置封存在 sealed_deletions.json）")
    L.append("")
    L.append("| 条件 | 模型 | n | 判对 | 准确率 | 平均置信 |")
    L.append("|---|---|---|---|---|---|")
    for (c, m), sub in sorted(collections.defaultdict(list, {
            k: [r for r in rows if (r["condition"], r["model"]) == k]
            for k in {(r["condition"], r["model"]) for r in rows}}).items()):
        ok = sum(1 for r in sub if r["correct"])
        conf = [r["parsed"].get("confidence") for r in sub if r.get("parsed") and r["parsed"].get("confidence")]
        L.append(f"| {c} | {m} | {len(sub)} | {ok} | {100*ok/len(sub):.0f}% | "
                 f"{(sum(conf)/len(conf)) if conf else 0:.2f} |")
    full = [r for r in rows if r["condition"] == "full"]
    drop = [r for r in rows if r["condition"] != "full"]
    if full and drop:
        fa = sum(1 for r in full if r["pred_complete"] is False)
        det = sum(1 for r in drop if r["pred_complete"] is False)
        L.append("")
        L.append(f"- **完整链上的误报（说“不完整”）**：{fa}/{len(full)}")
        L.append(f"- **删行后的检出（说“不完整”）**：{det}/{len(drop)} = {100*det/len(drop):.0f}%")
    with (OUT / "summary.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["unit", "condition", "model", "n_lines", "gt_complete", "pred_complete", "correct",
                    "confidence", "missing", "parse_ok", "latency_s"])
        for r in rows:
            p = r.get("parsed") or {}
            w.writerow([r["unit"], r["condition"], r["model"], r["n_lines"], r["gt_complete"],
                        r["pred_complete"], r["correct"], p.get("confidence"),
                        ";".join(p.get("missing") or []), r["parse_ok"], r["latency_s"]])
    (OUT / "report.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()

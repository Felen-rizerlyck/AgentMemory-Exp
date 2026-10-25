#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""run_chain_integrity_mem.py —— exp5b：同样的完整性判断，但插入一段"参考案例"

与 exp5 的唯一差别：USER 里多一段【参考案例】（来自 demo 现有 8 个案例的检索结果）。
SYS 与 exp5 完全一致；其他格式、条件、删行封存也一致。

输出（与 exp5 分离）：results/exp5b_chain_integrity_mem/
"""
import argparse
import json
import pathlib
import sys
import time

BASE = pathlib.Path(__file__).resolve().parents[3]
EVA = BASE / "eval" / "usability_ablation"
OUT = EVA / "results" / "exp5b_chain_integrity_mem"
RUNS = OUT / "runs.jsonl"
sys.path.insert(0, str(EVA / "harness")); sys.path.insert(0, str(BASE / "demo" / "src"))
import run_llm_arm as H  # noqa: E402
import run_chain_integrity as E5  # noqa: E402
from attack_memory.retrieval import build_action_index, retrieve  # noqa: E402
from attack_memory.storage import load_patterns  # noqa: E402

SRC_MAP = {"waf": "waf", "net": "waf", "rasp": "rasp", "edr": "hids", "win": "hids", "auditd": "hids",
           "syslog": "hids", "bastion": "hids", "vpn": "hids", "container": "hids", "db": "hids",
           "mail": "hids", "gitlab": "web", "jenkins": "web"}


def case_block(patterns, index, rows):
    logs = [dict(timestamp=r["ts"], source=SRC_MAP.get(r["source"], "hids"), content=r["text"],
                 log_id=r["logid"]) for r in rows]
    res = retrieve(patterns, logs, index)
    if not res:
        return "【参考案例】未检索到相关案例。"
    lines = ["【参考案例】以下是从案例库检索到的相似案例，供参考："]
    for c in res[:2]:
        steps = "；".join(f"{s['step_id']}:{s['label']}" for s in c["evidence"]) or "无"
        pn = c.get("predict_next") or {}
        lines.append(f"- {c['case_id']} {c['name']}｜档位={c['tier']}，覆盖 {c['matched_steps']}/{c['total_steps']} 步"
                     f"｜命中步骤：{steps}｜下一步：{pn.get('label', '无')}")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="qwen2.5:14b")
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--force-ref", action="store_true")
    ap.add_argument("--outdir", default="")
    a = ap.parse_args()
    global OUT, RUNS
    if a.outdir:
        OUT = EVA / "results" / a.outdir; RUNS = OUT / "runs.jsonl"
    OUT.mkdir(parents=True, exist_ok=True)
    if a.score:
        return summary()
    units = E5.load_units()
    import random
    rng = random.Random(20261023)          # 与 exp5 相同的删行种子 → 同样的 41 个用例
    cases, sealed = [], {}
    for u, rows in sorted(units.items()):
        if len(rows) < 5:
            cases.append((u, "full", rows)); continue
        cases.append((u, "full", rows))
        d1 = sorted(rng.sample(range(len(rows)), 1))
        cases.append((u, "drop1", [r for i, r in enumerate(rows) if i not in d1])); sealed[f"{u}-drop1"] = d1
        if len(rows) >= 10:
            d2 = sorted(rng.sample(range(len(rows)), 2))
            cases.append((u, "drop2", [r for i, r in enumerate(rows) if i not in d2])); sealed[f"{u}-drop2"] = d2
    (OUT / "sealed_deletions.json").write_text(json.dumps(sealed, indent=1), encoding="utf-8")

    pats = load_patterns()["attack_patterns"]; idx = build_action_index(pats)
    done = set()
    if RUNS.exists():
        for l in RUNS.read_text(encoding="utf-8").splitlines():
            if l.strip():
                r = json.loads(l); done.add((r["unit"], r["condition"]))
    todo = [(u, c, rows) for u, c, rows in cases if (u, c) not in done]
    print(f"待跑 {len(todo)} 次（已完成 {len(done)}）", flush=True)
    for i, (u, cond, rows) in enumerate(todo, 1):
        block = case_block(pats, idx, rows)
        if a.force_ref:
            text = " ".join(r["text"] for r in rows).lower()
            best = max(pats, key=lambda p: sum(len(k) for k in p.get("retrieval", {}).get("keywords", [])
                                               if str(k).lower() in text)
                       + sum(2 for s in p["steps"] if any(w in text for w in str(s.get("label", "")).lower().split())))
            steps = "；".join(f"{s['step_id']}:{s.get('label', s['action_id'])}" for s in best["steps"])
            block = (f"【参考案例】{best['case_id']} {best['name']}（仅部分相似，档位 weak）\n"
                     f"该案例的标准步骤：{steps}")
        user = block + "\n\n" + E5.USER_TMPL.format(logs=E5.render(rows))
        ok, raw, reasoning, lat, err = False, "", "", 0.0, ""
        for attempt in range(2):
            try:
                raw, reasoning, lat = H.call(a.model, E5.SYS, user, 600 + attempt * 400); ok = True; break
            except Exception as e:
                err = f"{type(e).__name__}:{e}"; time.sleep(3)
        parsed = H.parse_json(raw)
        pred = None if not parsed else bool(parsed.get("complete"))
        gt = (cond == "full")
        row = dict(run_id=f"{u}-{cond}-mem", ts=time.strftime("%Y-%m-%dT%H:%M:%S"), unit=u, condition=cond,
                   model=a.model, n_lines=len(rows), gt_complete=gt, pred_complete=pred,
                   correct=(pred == gt) if pred is not None else None,
                   case_block=block, prompt_sha=H.sha(E5.SYS + "\n---\n" + user),
                   prompt_chars=len(E5.SYS) + len(user), latency_s=round(lat, 1), ok=ok, error=err,
                   raw=raw, reasoning=(reasoning or "")[:2000], parsed=parsed, parse_ok=parsed is not None)
        with RUNS.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"[{i}/{len(todo)}] {u} {cond:6s} {lat:5.1f}s complete={pred} GT={gt} "
              f"| 参考:{'无' if '未检索' in block else '有'}", flush=True)
    summary()


def summary():
    rows = [json.loads(l) for l in RUNS.read_text(encoding="utf-8").splitlines() if l.strip()]
    full = [r for r in rows if r["condition"] == "full"]
    drop = [r for r in rows if r["condition"] != "full"]
    sens = sum(1 for r in drop if r["pred_complete"] is False) / max(1, len(drop))
    spec = sum(1 for r in full if r["pred_complete"] is True) / max(1, len(full))
    L = ["# exp5b · 完整性判断 + 参考案例（记忆检索结果，实际与数据不匹配）", "",
         f"- 调用 {len(rows)} 次；解析失败 {sum(1 for r in rows if not r['parse_ok'])}",
         f"- 完整链判「完整」（特异度）：{sum(1 for r in full if r['pred_complete'])}/{len(full)} = {spec:.0%}",
         f"- 删行后判「不完整」（灵敏度）：{sum(1 for r in drop if r['pred_complete'] is False)}/{len(drop)} = {sens:.0%}",
         f"- **Youden J = {sens + spec - 1:+.2f}**（exp5 无记忆时为 +0.00）",
         f"- 检索到案例的轮次：{sum(1 for r in rows if '未检索' not in r['case_block'])}/{len(rows)}"]
    (OUT / "report.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))


if __name__ == "__main__":
    main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""ablate_channels.py —— 实验四：检索通道离线消融（不需要模型）

配置（每一项只关掉一个通道/闸门）：
  full            原样（必须与 demo 的 retrieve() 完全一致，作为自检）
  no_probes       pattern_probes 权重 0
  no_mitre        mitre 权重 0
  no_keywords     retrieval.keywords 权重 0
  no_lexical      三个词法通道全关（候选只来自动作反向索引）
  no_action       动作通道全关（matched 归零，只剩词法排序）
  no_source_gate  对齐忽略 expected_sources（来源不符也算命中）
  no_order_check  strong 不再要求 order_ok
  no_tier_rank    排序忽略档位（按覆盖/来源/关键词排）

指标（140 unit，GT 见 gt_units.json）：
  T0 命中      7 个精确重复中 top1 正确且 strong
  变体落点     29 个同族变体中 top1 落到本家族
  新家族误判   104 个新家族中拿到 strong/medium 的数量
  MRR@8        36 个有 GT 家族的 unit 上首次命中正确案例的倒数排名均值
  no_cand      无任何候选的 unit 数

输出：results/exp4_channel_ablation/raw.csv + report_exp4_channel_ablation.md
"""
import csv
import json
import pathlib
import sys
from datetime import datetime, timezone

BASE = pathlib.Path(__file__).resolve().parents[3]
EVA = BASE / "eval" / "usability_ablation"
OUT = EVA / "results" / "exp4_channel_ablation"
sys.path.insert(0, str(BASE / "demo" / "src"))

from attack_memory import retrieval as R  # noqa: E402
from attack_memory.storage import load_patterns  # noqa: E402

TIER_RANK = {"strong": 4, "medium": 3, "weak": 2, "keyword_only": 1, "none": 0}
W = {"keywords": 3, "mitre": 2, "probe": 4}
CONFIGS = {
    "full": {},
    "no_probes": {"w_probe": 0},
    "no_mitre": {"w_mitre": 0},
    "no_keywords": {"w_keywords": 0},
    "no_lexical": {"w_keywords": 0, "w_mitre": 0, "w_probe": 0},
    "no_action": {"no_action": True},
    "no_source_gate": {"no_source_gate": True},
    "no_order_check": {"no_order_check": True},
    "no_tier_rank": {"no_tier_rank": True},
}


def cfg_of(spec):
    c = dict(w_keywords=W["keywords"], w_mitre=W["mitre"], w_probe=W["probe"],
             no_action=False, no_source_gate=False, no_order_check=False, no_tier_rank=False)
    for k, v in spec.items():
        c[k] = v
    return c


def kw_score(pattern, text, c):
    if c["no_action"] is None:
        pass
    lowered = text.casefold()
    score, details, seen = 0, [], set()
    ret = pattern.get("retrieval", {})
    for key in ret.get("keywords", []):
        tok = str(key).casefold().strip()
        if tok and tok in lowered and tok not in seen:
            score += c["w_keywords"]; seen.add(tok); details.append(f"kw:{key}")
    for tech in pattern.get("mitre", []):
        tok = str(tech).casefold()
        if tok and R.re.search(r"(?<![a-z0-9])" + R.re.escape(tok) + r"(?![a-z0-9])", lowered) and tok not in seen:
            score += c["w_mitre"]; seen.add(tok); details.append(f"mitre:{tech}")
    for probe in ret.get("pattern_probes", []):
        if R.re.search(probe, text, R.re.IGNORECASE):
            score += c["w_probe"]; details.append(f"probe:{probe[:24]}")
    return score, details


def compatible(step, action, c):
    if step["action_id"] != action["action_id"]:
        return False
    if c["no_source_gate"]:
        return True
    expected = {str(s).casefold() for s in step.get("expected_sources", [])}
    return not expected or action["source"] in expected or "any" in expected


def align(pattern, actions, c):
    steps = pattern["steps"]
    n, m = len(steps), len(actions)
    dp = [[0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            best = max(dp[i - 1][j], dp[i][j - 1])
            if compatible(steps[i - 1], actions[j - 1], c):
                best = max(best, dp[i - 1][j - 1] + 1)
            dp[i][j] = best
    out, i, j = [], n, m
    while i and j:
        if compatible(steps[i - 1], actions[j - 1], c) and dp[i][j] == dp[i - 1][j - 1] + 1:
            out.append((i - 1, actions[j - 1])); i -= 1; j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    out.reverse()
    return out


def match_pattern(pattern, logs, all_actions, c):
    step_ids = {s["action_id"] for s in pattern["steps"]}
    case_actions = [a for a in all_actions if a["action_id"] in step_ids]
    case_actions.sort(key=lambda a: (R._event_time(a["log"]) is None,
                                     R._event_time(a["log"]) or datetime.max.replace(tzinfo=timezone.utc),
                                     a["event_id"], a["action_id"]))
    aligned = align(pattern, case_actions, c) if not c["no_action"] else []
    positions = [p for p, _ in aligned]
    total = len(pattern["steps"])
    matched = len(positions)
    matched_ng = sum(not bool(pattern["steps"][p].get("generic", False)) for p, _ in aligned)
    detected, mismatches, signal = {}, [], set()
    for i, step in enumerate(pattern["steps"]):
        expected = {str(s).casefold() for s in step.get("expected_sources", [])}
        for a in case_actions:
            if a["action_id"] != step["action_id"]:
                continue
            signal.add(i)
            if not expected or a["source"] in expected or "any" in expected or c["no_source_gate"]:
                pass
            else:
                mismatches.append(dict(step_id=step["step_id"], observed_source=a["source"]))
    if c["no_action"]:
        mismatches = []
    for pos, action in aligned:
        detected.setdefault(pos, []).append(action)
    present = sorted(detected)
    times = []
    for pos in present:
        vals = [t for a in detected[pos] if (t := R._event_time(a["log"])) is not None]
        if vals:
            times.append(min(vals))
    order_assessable = bool(present) and len(times) == len(present)
    order_ok = all(a <= b for a, b in zip(times, times[1:])) if order_assessable else False
    src_ok = sum(1 for i in signal if detected.get(i))
    src_ratio = src_ok / len(signal) if signal else 0.0
    kw, details = kw_score(pattern, "\n".join(l.get("content", "") for l in logs), c)
    order_gate = True if c["no_order_check"] else (order_assessable and order_ok)
    if matched == total and total and order_gate and matched_ng:
        tier = "strong"
    elif matched_ng >= 2:
        tier = "medium"
    elif matched or mismatches:
        tier = "weak"
    elif kw:
        tier = "keyword_only"
    else:
        tier = "none"
    return dict(case_id=pattern["case_id"], tier=tier, matched_steps=matched, total_steps=total,
                matched_non_generic_steps=matched_ng, source_fit_ratio=round(src_ratio, 3),
                keyword_score=kw, order_ok=order_ok, order_assessable=order_assessable)


def retrieve(patterns, logs, index, c):
    all_actions = R.extract_log_actions(logs, index)
    case_ids = {ref["case_id"] for a in all_actions for ref in index[a["action_id"]]["refs"]}
    text = "\n".join(l.get("content", "") for l in logs)
    res = []
    for p in patterns:
        if p["case_id"] not in case_ids:
            if not kw_score(p, text, c)[0]:
                continue
        m = match_pattern(p, logs, all_actions, c)
        if m["tier"] != "none":
            res.append(m)
    if c["no_tier_rank"]:
        res.sort(key=lambda r: (-r["matched_non_generic_steps"], -r["matched_steps"],
                                -r["keyword_score"], r["case_id"]))
    else:
        res.sort(key=lambda r: (-TIER_RANK[r["tier"]], -r["matched_non_generic_steps"],
                                -r["matched_steps"], -r["source_fit_ratio"], -r["keyword_score"], r["case_id"]))
    return res



def stress_logs(logs, kind):
    """压力输入：shuffle=倒序（触发 order 校验）；swap_src=把 rasp 行改成 web（触发 expected_sources 校验）"""
    if kind == "shuffle":
        ts = [x["timestamp"] for x in logs][::-1]
        return [dict(x, timestamp=ts[i]) for i, x in enumerate(logs)]
    if kind == "swap_src":
        out = [dict(x) for x in logs]
        for i, x in enumerate(out):
            if x["source"] == "rasp":
                out[i]["source"] = "web"
                return out
        return None
    return None


def run_stress(patterns, index, units):
    rows = []
    pairs = [("shuffle", ["full", "no_order_check"]), ("swap_src", ["full", "no_source_gate"])]
    for kind, cfgs in pairs:
        for name in cfgs:
            c = cfg_of(CONFIGS[name])
            n = strong = top_ok = 0
            for unit, logs in sorted(units.items()):
                sl = stress_logs(logs, kind)
                if sl is None:
                    continue
                n += 1
                res = retrieve(patterns, sl, index, c)
                top = res[0] if res else None
                if top and top["tier"] == "strong":
                    strong += 1
                if top and gt_case_ok(unit, top["case_id"]):
                    top_ok += 1
            rows.append((kind, name, n, strong, top_ok))
    return rows


_GT = {}


def gt_case_ok(unit, case_id):
    g = _GT.get(str(unit)) or {}
    return bool(g.get("gt_case")) and g["gt_case"] == case_id


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    patterns = load_patterns()["attack_patterns"]
    index = R.build_action_index(patterns)
    gt = json.loads((EVA / "gt_units.json").read_text(encoding="utf-8"))["units"]
    _GT.update(gt)
    # 复用 Stage 1 已落盘的逐 unit 日志
    units = {}
    for f in (EVA / "results" / "retrieval").glob("*.json"):
        d = json.loads(f.read_text(encoding="utf-8"))
        units[d["unit"]] = d["logs"]

    rows, per_cfg = [], {}
    for name, spec in CONFIGS.items():
        c = cfg_of(spec)
        agg = dict(t0_hit=0, t0_n=0, var_hit=0, var_n=0, new_hard=0, new_n=0, mrr=0.0, mrr_n=0,
                   no_cand=0, tiers={})
        for unit, logs in sorted(units.items()):
            res = retrieve(patterns, logs, index, c)
            g = gt[str(unit)]
            top = res[0] if res else None
            if not res:
                agg["no_cand"] += 1
            if top:
                agg["tiers"][top["tier"]] = agg["tiers"].get(top["tier"], 0) + 1
            if g["gt_class"] == "exact":
                agg["t0_n"] += 1
                if top and top["case_id"] == g["gt_case"] and top["tier"] == "strong":
                    agg["t0_hit"] += 1
            elif g["gt_class"] == "family_variant":
                agg["var_n"] += 1
                if top and top["case_id"] == g["gt_case"]:
                    agg["var_hit"] += 1
            else:
                agg["new_n"] += 1
                if top and top["tier"] in ("strong", "medium"):
                    agg["new_hard"] += 1
            if g["gt_case"]:
                agg["mrr_n"] += 1
                rank = next((i + 1 for i, r in enumerate(res) if r["case_id"] == g["gt_case"]), None)
                agg["mrr"] += (1.0 / rank) if rank else 0.0
            rows.append([unit, g["gt_class"], g["gt_case"] or "", name,
                         top["case_id"] if top else "", top["tier"] if top else "none",
                         top["matched_steps"] if top else 0, top["total_steps"] if top else 0,
                         top["keyword_score"] if top else 0, len(res)])
        agg["mrr"] = agg["mrr"] / agg["mrr_n"] if agg["mrr_n"] else 0.0
        per_cfg[name] = agg

    with (OUT / "raw.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["unit", "gt_class", "gt_case", "config", "top1", "tier", "matched", "total", "kw", "n_cand"])
        w.writerows(rows)

    L = ["# 实验四 · 检索通道消融（离线，140 unit，无模型参与）", ""]
    L.append("规则：每个配置只关掉一个通道/闸门；`full` 必须与 demo 的 `retrieve()` 完全一致（见自检）。")
    L.append("")
    L.append("| 配置 | T0 命中(7) | 变体落点(29) | 新家族硬误判(104) | MRR | 无候选 | strong | medium | weak | kw_only |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    base = per_cfg["full"]
    for name in CONFIGS:
        a = per_cfg[name]
        t = a["tiers"]
        L.append(f"| {name} | {a['t0_hit']}/{a['t0_n']} | {a['var_hit']}/{a['var_n']} | "
                 f"{a['new_hard']}/{a['new_n']} | {a['mrr']:.3f} | {a['no_cand']} | "
                 f"{t.get('strong',0)} | {t.get('medium',0)} | {t.get('weak',0)} | {t.get('keyword_only',0)} |")
    L.append("")
    L.append("## 相对 full 的增量")
    L.append("")
    L.append("| 配置 | ΔT0 | Δ变体落点 | Δ新家族误判 | ΔMRR |")
    L.append("|---|---|---|---|---|")
    for name in CONFIGS:
        if name == "full":
            continue
        a = per_cfg[name]
        L.append(f"| {name} | {a['t0_hit']-base['t0_hit']:+d} | {a['var_hit']-base['var_hit']:+d} | "
                 f"{a['new_hard']-base['new_hard']:+d} | {a['mrr']-base['mrr']:+.3f} |")
    sr = run_stress(patterns, index, units)
    L.append("")
    L.append("## 压力输入下的闸门有效性（完整 unit 不触发闸门，故需构造）")
    L.append("")
    L.append("| 压力输入 | 配置 | n | 误报 strong | top1 正确 |")
    L.append("|---|---|---|---|---|")
    for kind, name, n, strong, top_ok in sr:
        L.append(f"| {kind} | {name} | {n} | {strong} | {top_ok} |")
    (OUT / "report_exp4_channel_ablation.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))
    json.dump(per_cfg, open(OUT / "summary.json", "w", encoding="utf-8"), ensure_ascii=False, indent=1)


if __name__ == "__main__":
    main()

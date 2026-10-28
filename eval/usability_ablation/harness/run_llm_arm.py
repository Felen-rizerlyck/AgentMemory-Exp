#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""run_llm_arm.py —— Stage 2：60 个 unit × {direct, assisted} × {qwen2.5:14b, deepseek-r1:14b} 单轮判定

条件：
  direct   只给日志（无记忆、无检索），输出 verdict/family/stages/next_step/confidence
  assisted 日志 + 8 案例清单 + 本 unit 的召回证据（含 case_id），输出 verdict/case_id/.../confidence

协议：OpenAI 兼容 /v1/chat/completions（默认 127.0.0.1:11435），temperature=0，无历史，
      每次调用独立 messages；增量写 runs.jsonl，可按 (unit, model, condition) 断点续跑。

用法：
  python run_llm_arm.py --models qwen2.5:14b --conditions direct --limit 2 --tag smoke
  python run_llm_arm.py --models qwen2.5:14b,deepseek-r1:14b --conditions direct,assisted
  python run_llm_arm.py --score
"""
import argparse
import hashlib
import json
import pathlib
import re
import time
import urllib.error
import urllib.request

BASE = pathlib.Path(__file__).resolve().parents[3]
EVA = BASE / "eval" / "usability_ablation"
RES = EVA / "results"
OUTDIR = RES / "exp1_memory_vs_retrieval"   # 由 --exp 覆盖
RUNS = OUTDIR / "runs.jsonl"
EXPNAME = "exp1_memory_vs_retrieval"
HOST = "http://127.0.0.1:11435/v1/chat/completions"
NATIVE = "http://127.0.0.1:11435/api/chat"

SCHEMA_DIRECT = ('{"verdict":"attack|unclear|benign","family":"攻击类型(<=20字)","stages":["阶段1","阶段2"],'
                 '"next_step":"下一步最可能做什么","known_case":"若你确信对应某个已登记案例则写编号，否则 null",'
                 '"confidence":3}')
SCHEMA_ASSISTED = ('{"verdict":"match|new","case_id":"CASE-00x 或 null","family":"攻击类型(<=20字)",'
                   '"stages":["阶段1","阶段2"],"next_step":"下一步最可能做什么","confidence":3}')

SYS_DIRECT = ("你是企业安全告警分析员。仅根据给出的告警日志判断攻击类型、阶段与下一步。"
              "只输出一个 JSON 对象，不要解释，不要代码块。字段：" + SCHEMA_DIRECT)
SYS_CATALOG = ("你是企业安全告警分析员。你可以参考【案例库】中的案例摘要，但系统没有为本批日志提供自动检索结果，"
               "你需要自己判断日志是否与某个案例属于同一行为模式。只输出一个 JSON 对象，不要解释，不要代码块。字段："
               + SCHEMA_ASSISTED)

SYS_ASSISTED = ("你是企业安全告警分析员。你可使用【案例库】与【检索证据】。"
                "检索证据由系统自动匹配产生，档位 strong 表示日志完整覆盖该案例的全部步骤且时序一致；"
                "weak/keyword_only 只表示部分相似，不能作为确认依据。只输出一个 JSON 对象，不要解释，不要代码块。字段："
                + SCHEMA_ASSISTED)

FAMILY_KW = {
    "CASE-001": ["log4j", "log4shell", "jndi", "日志4j"],
    "CASE-002": ["tomcat", "jsp", "webshell", "文件上传", "war"],
    "CASE-003": ["计划任务", "schtasks", "定时任务"],
    "CASE-004": ["laravel", "ignition", "phar"],
    "CASE-005": ["勒索", "加密", "卷影", "vssadmin", "cipher"],
    "CASE-006": ["bloodhound", "sharphound", "域内", "活动目录"],
    "CASE-007": ["npm", "postinstall", "供应链", "node"],
    "CASE-008": ["exchange", "proxylogon", "owa", "autodiscover"],
}


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16]


def load_catalog():
    pats = json.loads((BASE / "demo" / "data" / "attack_patterns.json").read_text(encoding="utf-8"))
    pats = pats.get("attack_patterns", pats) if isinstance(pats, dict) else pats
    out = []
    for p in pats:
        out.append(dict(case_id=p["case_id"], name=p["name"], summary=p["summary"][:120],
                        steps=[s["label"] for s in p["steps"]]))
    return out


def fmt_logs(unit_json):
    lines = []
    for e in unit_json["logs"]:
        lines.append(f"[{e['timestamp']}] [{e['source']}] {e['content']}")
    return "\n".join(lines)


def fmt_catalog(cat):
    out = ["【案例库】"]
    for c in cat:
        out.append(f"- {c['case_id']} | {c['name']} | 步骤：{' → '.join(c['steps'])} | {c['summary']}")
    return "\n".join(out)


def _ids(xs):
    out = []
    for x in xs or []:
        out.append(f"{x.get('step_id')}:{x.get('label')}" if isinstance(x, dict) else str(x))
    return "、".join(out) or "无"


def fmt_evidence(ev):
    if not ev:
        return "【检索证据】无候选（检索未命中任何案例）"
    steps = "；".join(f"{s.get('step_id')}:{s.get('label')}[{','.join(s.get('sources') or [])}]"
                      f"{'*' if not s.get('generic') else ''}" for s in ev.get("steps") or []) or "无"
    pn = ev.get("predict_next") or {}
    return ("【检索证据】（系统自动匹配）\n"
            f"- 档位 tier={ev.get('tier')}，覆盖 {ev.get('matched_steps')}/{ev.get('total_steps')} 步，"
            f"时序一致={ev.get('order_ok')}，来源吻合度={ev.get('source_fit_ratio')}\n"
            f"- 命中步骤：{steps}\n"
            f"- 未观察到的步骤：{_ids(ev.get('unobserved_steps'))}\n"
            f"- 缺失/跳步：{_ids(ev.get('gap_steps'))}\n"
            f"- 下一步预测：{pn.get('label') or '无'}（{','.join(pn.get('sources') or []) or '-'}）")


def build_prompt(cond, unit_json, cat, ev):
    logs = fmt_logs(unit_json)
    if cond == "direct":
        user = f"以下是一次安全事件中收集到的告警日志（按时间序，共 {len(unit_json['logs'])} 条）：\n\n{logs}\n\n" \
               "请判断：这是什么攻击、处于哪些阶段、攻击者下一步最可能做什么。"
        return SYS_DIRECT, user
    if cond == "catalog":
        user = (fmt_catalog(cat) + "\n\n【检索证据】系统未提供检索结果（本条件不给召回）。"
                + f"\n\n【待分析日志】（同一事件，按时间序，共 {len(unit_json['logs'])} 条）\n\n{logs}\n\n"
                "请判断：这组日志是否与案例库中某个案例属于同一行为模式（match 并给出 case_id），还是应判为新案例（new）。")
        return SYS_CATALOG, user
    user = (fmt_catalog(cat) + "\n\n" + fmt_evidence(ev)
            + f"\n\n【待分析日志】（同一事件，按时间序，共 {len(unit_json['logs'])} 条）\n\n{logs}\n\n"
            "请判断：这组日志是否与案例库中某个案例属于同一行为模式（match 并给出 case_id），"
            "还是应判为新案例（new）。"
            + ("" if cond == "assisted_free" else "若证据档位不是 strong，不得判 match。"))
    return SYS_ASSISTED, user


def call(model, sys_p, user_p, max_tokens):
    body = json.dumps({"model": model, "stream": False,
                       "options": {"temperature": 0, "num_ctx": 8192, "num_predict": max_tokens},
                       "messages": [{"role": "system", "content": sys_p},
                                    {"role": "user", "content": user_p}]}).encode()
    req = urllib.request.Request(NATIVE, data=body, headers={"Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=900) as r:
        d = json.loads(r.read())
    msg = d.get("message", {})
    return msg.get("content") or "", (msg.get("thinking") or msg.get("reasoning") or ""), time.time() - t0


def parse_json(txt):
    if not txt:
        return None
    t = re.sub(r"^```(?:json)?|```$", "", txt.strip(), flags=re.M).strip()
    m = re.search(r"\{.*\}", t, re.S)
    if not m:
        return None
    raw = m.group(0)
    for cand in (raw, re.sub(r",\s*([}\]])", r"\1", raw)):
        try:
            return json.loads(cand)
        except Exception:
            continue
    return None


def score(row):
    cond, gt_class, gt_case = row["condition"], row["gt_class"], row["gt_case"]
    p = row.get("parsed") or {}
    txt = json.dumps(p, ensure_ascii=False).lower() + " " + (row.get("raw") or "").lower()
    s = dict(family_hit=None, claims_case=None, verdict_correct=None, overclaim=None, exact_hit=None)
    if cond == "direct":
        if gt_case:
            s["family_hit"] = any(k.lower() in txt for k in FAMILY_KW.get(gt_case, []))
        kc = str(p.get("known_case") or "").strip()
        s["claims_case"] = bool(kc and kc.lower() not in ("null", "none") and "填写" not in kc
                                and "否则" not in kc)
        s["next_step_ok"] = bool(p.get("next_step"))
    else:
        v, cid = p.get("verdict"), p.get("case_id")
        if gt_class == "exact":
            s["exact_hit"] = (v == "match" and cid == gt_case)
            s["verdict_correct"] = s["exact_hit"]
        else:
            s["verdict_correct"] = (v == "new")
            s["overclaim"] = (v == "match")
        if gt_case:
            s["family_hit"] = any(k.lower() in txt for k in FAMILY_KW.get(gt_case, []))
    return s


def load_done():
    done = set()
    if RUNS.exists():
        for line in RUNS.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
                done.add((r["unit"], r["model"], r["condition"]))
            except Exception:
                pass
    return done


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", default="exp1_memory_vs_retrieval")
    ap.add_argument("--retrieval-dir", default="")
    ap.add_argument("--models", default="qwen2.5:14b")
    ap.add_argument("--conditions", default="direct,assisted")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--tag", default="")
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--no-resume", action="store_true")
    a = ap.parse_args()

    global OUTDIR, RUNS, EXPNAME, RETR
    RETR = pathlib.Path(a.retrieval_dir) if a.retrieval_dir else (RES / "retrieval")
    EXPNAME = a.exp
    OUTDIR = RES / a.exp
    OUTDIR.mkdir(parents=True, exist_ok=True)
    RUNS = OUTDIR / "runs.jsonl"
    if a.score:
        return summary()

    sample = json.loads((RES / "stage2_sample_60.json").read_text(encoding="utf-8"))
    if a.limit:
        sample = sample[: a.limit]
    cat = load_catalog()
    done = set() if a.no_resume else load_done()
    models = [m.strip() for m in a.models.split(",") if m.strip()]
    conds = [c.strip() for c in a.conditions.split(",") if c.strip()]

    todo = [(m["unit"], m, mo, c) for mo in models for c in conds for m in sample
            if (m["unit"], mo, c) not in done]
    print(f"待跑 {len(todo)} 次（已完成 {len(done)}）", flush=True)
    for i, (unit, meta, model, cond) in enumerate(todo, 1):
        uj = json.loads((RETR / f"{unit}.json").read_text(encoding="utf-8"))
        sys_p, user_p = build_prompt(cond, uj, cat, uj["evidence_for_agent"])
        mt = 1600 if "r1" in model else 700
        ok, raw, reasoning, lat, err = False, "", "", 0.0, ""
        for attempt in range(2):
            try:
                raw, reasoning, lat = call(model, sys_p, user_p, mt + attempt * 800)
                ok = True
                break
            except urllib.error.URLError as e:
                err = f"URLError:{e}"
                time.sleep(5)
            except Exception as e:
                err = f"{type(e).__name__}:{e}"
                time.sleep(2)
        parsed = parse_json(raw)
        row = dict(run_id=f"{unit}-{model.split(':')[0]}-{cond}", ts=time.strftime("%Y-%m-%dT%H:%M:%S"),
                   unit=unit, stratum=meta["stratum"], gt_class=meta["gt_class"], gt_case=meta["gt_case"],
                   technique=meta["technique"], retrieval_top1=meta["top1"], retrieval_tier=meta["tier"],
                   model=model, condition=cond, tag=a.tag,
                   prompt_sha=sha(sys_p + "\n---\n" + user_p), prompt_chars=len(sys_p) + len(user_p),
                   temperature=0, ok=ok, latency_s=round(lat, 1), error=err,
                   raw=raw, reasoning=(reasoning or "")[:4000], parsed=parsed,
                   parse_ok=parsed is not None)
        row["scores"] = score(row)
        with RUNS.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        p = parsed or {}
        print(f"[{i}/{len(todo)}] {unit} {model.split(':')[0]:8s} {cond:8s} "
              f"{lat:5.1f}s {str(p.get('verdict')):8s} {str(p.get('case_id') or p.get('family'))[:26]} "
              f"conf={p.get('confidence')}", flush=True)
    summary()


def summary():
    if not RUNS.exists():
        print("no runs")
        return
    rows = [json.loads(l) for l in RUNS.read_text(encoding="utf-8").splitlines() if l.strip()]
    rows = [r for r in rows if not r.get("tag", "").startswith("smoke")]
    for r in rows:                      # 用当前口径重算，修正历史行的计分
        r["scores"] = score(r)
    L = [f"# {EXPNAME} · 60 unit × 条件 × 模型（单轮判定）", ""]
    L.append(f"- 调用总数：{len(rows)}；解析失败：{sum(1 for r in rows if not r['parse_ok'])}；"
             f"平均耗时：{sum(r['latency_s'] for r in rows)/max(1,len(rows)):.1f}s")
    L.append("- `assisted` = 带【档位非 strong 不得判 match】提示；`assisted_free` = 不给该提示，自行权衡证据")
    L.append("")
    for cond in [c for c in ("catalog", "assisted", "assisted_free") if any(r["condition"] == c for r in rows)]:
        L.append(f"## {cond}（{'只给案例摘要，无检索' if cond == 'catalog' else '日志 + 案例库 + 召回证据'}）")
        L.append("")
        L.append("| 模型 | n | 归属正确 | 精确重复命中 | 变体/新案例误判 match | 平均置信 |")
        L.append("|---|---|---|---|---|---|")
        for m in sorted({r["model"] for r in rows if r["condition"] == cond}):
            sub = [r for r in rows if r["model"] == m and r["condition"] == cond]
            ex = [r for r in sub if r["gt_class"] == "exact"]
            ov = [r for r in sub if r["gt_class"] in ("family_variant", "new")]
            conf = [r["parsed"].get("confidence") for r in sub if r.get("parsed") and r["parsed"].get("confidence")]
            L.append(f"| {m} | {len(sub)} | {sum(1 for r in sub if r['scores'].get('verdict_correct'))} | "
                     f"{sum(1 for r in ex if r['scores'].get('exact_hit'))}/{len(ex)} | "
                     f"{sum(1 for r in ov if r['scores'].get('overclaim'))}/{len(ov)} | "
                     f"{(sum(conf)/len(conf)) if conf else 0:.2f} |")
        L.append("")
        L.append("")
        miss_ = []
        for m in sorted({r["model"] for r in rows if r["condition"] == cond}):
            sub = [r for r in rows if r["model"] == m and r["condition"] == cond]
            mt = [r for r in sub if (r["parsed"] or {}).get("verdict") == "match"]
            anch = sum(1 for r in mt if (r["parsed"] or {}).get("case_id") == r["retrieval_top1"])
            miss_.append(f"{m}：判 match {len(mt)} 条，case_id=检索 top1 的 {anch} 条"
                         f"（{100*anch/max(1,len(mt)):.0f}%）")
        if cond != "catalog":
            L.append("- 锚定率：" + "；".join(miss_))
        else:
            L.append("- （`catalog` 不给检索，锚定率不适用）")
        L.append("| 分层 | 模型 | n | 正确 | 判 match | 判 new |")
        L.append("|---|---|---|---|---|---|")
        for st in ("exact", "variant", "new_with_candidate", "new_no_candidate"):
            for m in sorted({r["model"] for r in rows if r["condition"] == cond}):
                sub = [r for r in rows if r["model"] == m and r["condition"] == cond and r["stratum"] == st]
                if not sub:
                    continue
                L.append(f"| {st} | {m} | {len(sub)} | {sum(1 for r in sub if r['scores'].get('verdict_correct'))} | "
                         f"{sum(1 for r in sub if (r['parsed'] or {}).get('verdict')=='match')} | "
                         f"{sum(1 for r in sub if (r['parsed'] or {}).get('verdict')=='new')} |")
        L.append("")
    if any(r["condition"] == "direct" for r in rows):
        L.append("## direct（只给日志，无记忆）")
        L.append("")
        L.append("| 模型 | n | 家族命中（关键词宽松） | 编造案例编号 | 平均置信 | 平均耗时 |")
        L.append("|---|---|---|---|---|---|")
        for m in sorted({r["model"] for r in rows if r["condition"] == "direct"}):
            sub = [r for r in rows if r["model"] == m and r["condition"] == "direct"]
            fh = [r for r in sub if r["scores"].get("family_hit") is not None]
            conf = [r["parsed"].get("confidence") for r in sub if r.get("parsed") and r["parsed"].get("confidence")]
            L.append(f"| {m} | {len(sub)} | {sum(1 for r in fh if r['scores']['family_hit'])}/{len(fh)} | "
                     f"{sum(1 for r in sub if r['scores'].get('claims_case'))}/{len(sub)} | "
                     f"{(sum(conf)/len(conf)) if conf else 0:.2f} | {sum(r['latency_s'] for r in sub)/len(sub):.1f}s |")
        L.append("")
    L.append("## 置信度错配（assisted* 中 conf≥4 但判错）")
    L.append("")
    bad = [r for r in rows if r["condition"] != "direct" and r.get("parsed")
           and (r["parsed"].get("confidence") or 0) >= 4 and r["scores"].get("verdict_correct") is False]
    L.append(f"共 {len(bad)} 条：" + ("、".join(f"{r['unit']}/{r['model'].split(':')[0]}/{r['condition']}" for r in bad[:20]) or "无"))
    (OUTDIR / f"report_{EXPNAME}.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L))

    with (OUTDIR / "runs_summary.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        import csv as _csv
        w = _csv.writer(fh)
        w.writerow(["unit", "stratum", "gt_class", "gt_case", "model", "condition", "verdict", "case_id",
                    "family", "confidence", "parse_ok", "latency_s", "verdict_correct", "exact_hit",
                    "overclaim", "family_hit", "claims_case", "next_step"])
        for r in rows:
            p = r.get("parsed") or {}
            s = r["scores"]
            w.writerow([r["unit"], r["stratum"], r["gt_class"], r["gt_case"], r["model"], r["condition"],
                        p.get("verdict"), p.get("case_id"), (p.get("family") or "")[:40], p.get("confidence"),
                        r["parse_ok"], r["latency_s"], s.get("verdict_correct"), s.get("exact_hit"),
                        s.get("overclaim"), s.get("family_hit"), s.get("claims_case"), (p.get("next_step") or "")[:60]])
    print(f"\n→ {OUTDIR/f'report_{EXPNAME}.md'} · {OUTDIR/'runs_summary.csv'}")


if __name__ == "__main__":
    main()

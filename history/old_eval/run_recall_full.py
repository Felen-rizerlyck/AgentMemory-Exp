#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""eval/run_recall_full.py — 全数据集重放召回审计

范围: dataset/ 三个文件全部日志行（data-901-910 / data-911-920 / data-9101-9110），
逐条对当前 data/memory_store.json（22 案例）重放检索，审计"可召回性"。

输出: eval/results/report_recall_full.md + eval/results/recall_details.jsonl

口径与声明:
- 检索口径 = 现状 C2（retrieve.score_case 全通道），判读带 强≥6 / 中4–5 / 弱≤3 / 无。
- 预期案例映射为人工整理（依据案例记录中的观测日期/实体）；样板通用行（如 cat /etc/passwd …）
  无唯一预期案例，单独归类统计。
- 本审计为**回顾性**（证明已有知识可被召回），不代表"事前检出"能力。
"""
import json
import pathlib
import re
import sys
from collections import Counter, defaultdict

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = pathlib.Path(__file__).parent.parent.parent
DS = BASE / "dataset"
OUT = pathlib.Path(__file__).parent / "results"
OUT.mkdir(exist_ok=True)

HEADER = re.compile(r"^(\d+)\.\s+`([^`]+)`\s+\*\*\[([a-z]+)\]\*\*\s+`([^`]+)`$")

def parse_file(path):
    lines = path.read_text(encoding="utf-8").splitlines()
    entries, i = [], 0
    while i < len(lines):
        s = lines[i].strip()
        if not s:
            i += 1; continue
        m = HEADER.match(s)
        if m:
            n, ts, src, hid = int(m.group(1)), m.group(2), m.group(3), m.group(4)
            j = i + 1
            while j < len(lines) and not lines[j].strip(): j += 1
            c = lines[j].strip()
            if c.startswith("`"): c = c[1:]
            if c.endswith("`"): c = c[:-1]
            entries.append(dict(n=n, ts=ts, source=src, log_id=hid, content=c))
            i = j + 1
        else:
            i += 1
    units, cur = [], []
    for e in entries:
        if e["n"] == 1 and cur:
            units.append(cur); cur = []
        cur.append(e)
    if cur: units.append(cur)
    return units

# ---------------- 预期映射（人工整理） ----------------
# 依据: 案例记录中的观测目标/日期/载荷 + 数据集单元结构；None = 通用样板行（无唯一预期）
EXPECT = {
    "901-910": {
        1:  ["CASE-009", "CASE-009", "CASE-004", "CASE-002", "CASE-002", "CASE-002"],
        2:  ["CASE-003", "CASE-003", "CASE-004", "CASE-002", "CASE-002", "CASE-002"],
        3:  ["CASE-005", "CASE-005", "CASE-004", "CASE-002", "CASE-002", "CASE-002"],
        4:  ["CASE-006", "CASE-006", "CASE-001", "CASE-002", "CASE-002", "CASE-002"],
        5:  ["CASE-003", "CASE-003", "CASE-004", "CASE-002", "CASE-002", "CASE-002"],
        6:  ["CASE-006", "CASE-007", "CASE-002", "CASE-002", "CASE-002"],
        7:  ["CASE-008", "CASE-001", "CASE-002", "CASE-002", "CASE-002"],
        8:  ["CASE-004", "CASE-002", "CASE-002", "CASE-002"],
        9:  ["CASE-001", "CASE-002", "CASE-002", "CASE-002"],
        10: ["CASE-001", "CASE-002", "CASE-002", "CASE-002"],
    },
    "911-920": {
        1:  ["CASE-004", "CASE-002", "CASE-002", "CASE-002"],
        2:  ["CASE-010", "CASE-010", "CASE-010", None],
        3:  ["CASE-011", "CASE-011", "CASE-011", None],
        4:  ["CASE-012", "CASE-012", "CASE-012", None],
        5:  ["CASE-013", "CASE-013", "CASE-013", None],
        6:  ["CASE-014", "CASE-014", "CASE-014", None],
        7:  ["CASE-015", "CASE-015", "CASE-015", None],
        8:  ["CASE-016", "CASE-016", "CASE-016", None],
        9:  ["CASE-017", "CASE-017", "CASE-017", None],
        10: ["CASE-018", "CASE-018", "CASE-018", None],
    },
    "9101-9110": {
        1:  ["CASE-003", "CASE-003", "CASE-003", "CASE-019"],
        2:  ["CASE-003", "CASE-003", "CASE-003", "CASE-019"],
        3:  ["CASE-003", "CASE-003", "CASE-003", "CASE-019"],
        4:  ["CASE-020", "CASE-020", "CASE-020", "CASE-019"],
        5:  ["CASE-003", "CASE-003", "CASE-003", "CASE-019"],
        6:  ["CASE-003", "CASE-003", "CASE-003", "CASE-021"],
        7:  ["CASE-022", "CASE-022", "CASE-022", "CASE-021"],
        8:  ["CASE-003", "CASE-003", "CASE-003", "CASE-021"],
        9:  ["CASE-005", "CASE-005", "CASE-005", None, "CASE-021"],
        10: ["CASE-017", "CASE-017", "CASE-017", "CASE-021"],
    },
}

def band(score):
    if score >= 6: return "强"
    if score >= 4: return "中"
    if score >= 1: return "弱"
    return "无"

def main():
    import importlib.util
    spec = importlib.util.spec_from_file_location("retrieve", BASE / "history/old_retrieve.py")
    retrieve = importlib.util.module_from_spec(spec); spec.loader.exec_module(retrieve)

    files = [("901-910", "data-901-910.txt"), ("911-920", "data-911-920.txt"), ("9101-9110", "data-9101-9110.txt")]
    rows = []
    for tag, fn in files:
        units = parse_file(DS / fn)
        exp = EXPECT[tag]
        assert len(units) == len(exp), f"{tag}: units {len(units)} vs expect {len(exp)}"
        for ui, u in enumerate(units, 1):
            exp_u = exp[ui]
            assert len(u) == len(exp_u), f"{tag} unit{ui}: entries {len(u)} vs expect {len(exp_u)}"
            for ei, e in enumerate(u, 1):
                want = exp_u[ei - 1]
                res = retrieve.retrieve(e["content"])
                ids = [c for _, c, _, _ in res]
                rank = ids.index(want) + 1 if want and want in ids else None
                escore = next((s for s, c, _, _ in res if c == want), 0) if want else 0
                rows.append(dict(
                    file=tag, unit=ui, entry=ei, ts=e["ts"], source=e["source"],
                    log_id=e["log_id"], text=e["content"], want=want,
                    top1=(ids[0] if ids else None), top1_score=(res[0][0] if res else 0),
                    top3=[(s, c) for s, c, _, _ in res[:3]],
                    rank=rank, escore=escore, band=band(escore) if want else None,
                    n_returns=len(res),
                ))

    det = [(r["file"], r["unit"], r["entry"], r["ts"], r["source"], r["log_id"], r["want"], r["top1"], r["rank"], r["escore"], r["band"], r["text"])
           for r in rows]
    with (OUT / "recall_details.jsonl").open("w", encoding="utf-8") as f:
        for d in det:
            f.write(json.dumps(dict(zip(["file","unit","entry","ts","source","log_id","want","top1","rank","escore","band","text"], d)), ensure_ascii=False) + "\n")

    feat = [r for r in rows if r["want"]]
    gen  = [r for r in rows if not r["want"]]

    def acc(sub, key):
        n = len(sub)
        top1 = sum(1 for r in sub if r["rank"] == 1)
        top3 = sum(1 for r in sub if r["rank"] and r["rank"] <= 3)
        strong = sum(1 for r in sub if r["escore"] >= 6)
        return n, top1, top3, strong

    L = []
    L.append("# 全数据集重放召回审计报告（22 案例库）")
    L.append("")
    L.append(f"- 范围: `dataset/` 三个文件全部日志行 = **{len(rows)} 条**（特征行 {len(feat)} + 通用样板行 {len(gen)}）")
    L.append(f"- 口径: 逐条重放检索（现状 C2 全通道）；判读带 强≥6 / 中4–5 / 弱≤3 / 无")
    L.append(f"- 日期: 2026-09-18 · 脚本: `eval/run_recall_full.py`（可重复运行）")
    L.append("")
    L.append("> 声明: 本审计为**回顾性**（已有知识可被召回），不代表事前检出；通用样板行（cat /etc/passwd 类）无唯一预期案例，单独统计。")
    L.append("")

    n, t1, t3, st = acc(feat, None)
    L.append("## 一、总览（特征行）")
    L.append("")
    L.append("| 指标 | 值 |")
    L.append("|---|---|")
    L.append(f"| 特征行 | {n} |")
    L.append(f"| Top-1 命中 | {t1}（{100*t1/n:.0f}%） |")
    L.append(f"| Top-3 命中 | {t3}（{100*t3/n:.0f}%） |")
    L.append(f"| 强档命中（≥6） | {st}（{100*st/n:.0f}%） |")
    L.append(f"| 未入前 3 | {n - t3} |")
    L.append("")
    L.append("### 分文件")
    L.append("")
    L.append("| 文件 | 特征行 | Top-1 | Top-3 | 强档 |")
    L.append("|---|---|---|---|---|")
    for tag, _ in files:
        sub = [r for r in feat if r["file"] == tag]
        a = acc(sub, None)
        L.append(f"| {tag} | {a[0]} | {a[1]}（{100*a[1]/a[0]:.0f}%） | {a[2]}（{100*a[2]/a[0]:.0f}%） | {a[3]}（{100*a[3]/a[0]:.0f}%） |")
    L.append("")
    L.append("### 分来源")
    L.append("")
    L.append("| 来源 | 特征行 | Top-1 | Top-3 | 强档 |")
    L.append("|---|---|---|---|---|")
    for src in ["waf", "web", "rasp", "hids", "dns"]:
        sub = [r for r in feat if r["source"] == src]
        if not sub: continue
        a = acc(sub, None)
        L.append(f"| {src} | {a[0]} | {a[1]}（{100*a[1]/a[0]:.0f}%） | {a[2]}（{100*a[2]/a[0]:.0f}%） | {a[3]}（{100*a[3]/a[0]:.0f}%） |")
    L.append("")

    L.append("## 二、逐案例召回（特征行按预期案例聚合）")
    L.append("")
    L.append("| 案例 | 特征行 | Top-1 | Top-3 | 强档 | 说明 |")
    L.append("|---|---|---|---|---|---|")
    cases = sorted({r["want"] for r in feat}, key=lambda c: int(c.split("-")[1]))
    case_notes = {}
    store = json.loads((BASE / "data/memory_store.json").read_text(encoding="utf-8"))
    for c in store["cases"]:
        case_notes[c["id"]] = (c.get("attack_type") or "")[:34]
    for cid in cases:
        sub = [r for r in feat if r["want"] == cid]
        a = acc(sub, None)
        flag = ""
        if a[1] < a[0]: flag = "⚠️ 有非 Top-1" if a[2] == a[0] else "⚠️ 有未入前 3"
        L.append(f"| {cid} | {a[0]} | {a[1]}（{100*a[1]/a[0]:.0f}%） | {a[2]}（{100*a[2]/a[0]:.0f}%） | {a[3]}（{100*a[3]/a[0]:.0f}%） | {case_notes.get(cid,'')} {flag} |")
    L.append("")

    edge = [r for r in feat if r["rank"] != 1]
    L.append(f"## 三、非 Top-1 明细（{len(edge)} 条）")
    L.append("")
    if edge:
        L.append("| 文件-单元-条 | 来源 | 预期 | Top1 | 预期档位 | 预期排名 | 行内容（截断） |")
        L.append("|---|---|---|---|---|---|---|")
        for r in edge:
            t3s = "/".join(f"{c}" for _, c in r["top3"])
            L.append(f"| {r['file']}-{r['unit']}-{r['entry']} | {r['source']} | {r['want']} | {r['top1']} | {r['band']} | {'—' if not r['rank'] else r['rank']} | `{r['text'][:56]}…` |")
    else:
        L.append("（无）")
    L.append("")

    L.append(f"## 四、通用样板行落点（{len(gen)} 条，无唯一预期案例）")
    L.append("")
    L.append("| 文件-单元-条 | Top1 | 分数 | Top3 | 行内容（截断） |")
    L.append("|---|---|---|---|---|")
    for r in gen:
        t3s = "、".join(f"{c}({s})" for s, c in r["top3"]) or "无返回"
        L.append(f"| {r['file']}-{r['unit']}-{r['entry']} | {r['top1'] or '—'} | {r['top1_score']} | {t3s} | `{r['text'][:56]}…` |")
    L.append("")

    noise = sum(r["n_returns"] for r in rows) / len(rows)
    L.append("## 五、与既往评测的关系")
    L.append("")
    L.append("- 本审计 = **全量数据重放**（所有日志行 × 22 案例库），与 `report.md`（配置消融评测：入口 C0–C2 / 扩展 C3–C5）互补。")
    L.append("- `report.md` 回答「检索机制在受控查询集下的表现」；本报告回答「数据集中每条已知日志能否被召回」。")
    L.append(f"- 参考: 平均返回 {noise:.1f} 条/行（规模效应下的交叉面，含弱档噪声）。")
    L.append("")
    L.append("## 六、结论（自动初判口径）")
    L.append("")
    L.append(f"- 特征行召回: Top-1 {100*t1/n:.0f}% · Top-3 {100*t3/n:.0f}% · 强档 {100*st/n:.0f}%；未入前 3 共 {n-t3} 条。")
    L.append(f"- 通用样板行 {len(gen)} 条: 无唯一预期，落点见第四节（用途: 观察通用内容交叉面）。")
    L.append("")

    (OUT / "report_recall_full.md").write_text("\n".join(L), encoding="utf-8")
    print(f"报告: {OUT/'report_recall_full.md'}")
    print(f"明细: {OUT/'recall_details.jsonl'}（{len(rows)} 条）")
    print(f"总览: 特征行 {len(feat)} · Top-1 {t1} · Top-3 {t3} · 强档 {st} · 通用行 {len(gen)}")
    for tag, _ in files:
        sub = [r for r in feat if r["file"] == tag]
        a = acc(sub, None)
        print(f"  {tag}: 特征行 {a[0]} · Top-1 {a[1]} · Top-3 {a[2]} · 强档 {a[3]}")

if __name__ == "__main__":
    main()

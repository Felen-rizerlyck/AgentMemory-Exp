#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""eval/run_action_recall.py — 动作匹配检索器全量重放召回审计（v2）

范围:
  A. dataset/ 三个已入库文件（data-901-910 / data-911-920 / data-9101-9110）
     全部日志行，对当前 data/memory_store.json（22 案例 + 动作库）逐条重放；
     行级期望映射沿用 v1 人工标注（history/old_eval/run_recall_full.py 的 EXPECT，单一事实源）。
  B. dataset/data-921-930 未入库前瞻批（期望映射沿用 history/old_eval/run_recall_unseen.py）。

口径:
  - 组合排序 = 动作通道（档位/命中数/覆盖度/关键词分）优先，其后关键词兜底区。
  - 动作档位: 完整匹配=强；命中≥2=中；命中1=弱（参照）。
  - 关键词兜底沿用 v1 判读带: 强≥6 / 中4–5 / 弱≤3。
  - 回顾性声明: 已入库文件为重放（证明可召回）；data-921-930 为前瞻（未参与动作库编写）。

输出: eval/results/report_action_recall.md + eval/results/action_recall_details.jsonl
"""
import json
import pathlib
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = pathlib.Path(__file__).parent.parent
DS = BASE / "dataset"
OUT = pathlib.Path(__file__).parent / "results"
OUT.mkdir(exist_ok=True)


def load_module(path, name):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


retrieve = load_module(BASE / "src" / "retrieve.py", "retrieve_v2")
run_full = load_module(BASE / "history" / "old_eval" / "run_recall_full.py", "run_full")
run_unseen = load_module(BASE / "history" / "old_eval" / "run_recall_unseen.py", "run_unseen")


def combined_ids(res):
    """组合排序的案例 id 列表（动作通道 + 关键词兜底）"""
    return [h["id"] for h in res[0]] + [k[1] for k in res[1]]


def main():
    cases, lib = retrieve.load_store()
    store = (cases, lib)
    rows = []

    # ---------- A. 已入库三文件全量重放 ----------
    files = [("901-910", "data-901-910.txt"), ("911-920", "data-911-920.txt"),
             ("9101-9110", "data-9101-9110.txt")]
    for tag, fn in files:
        units = run_full.parse_file(DS / fn)
        exp = run_full.EXPECT[tag]
        assert len(units) == len(exp), f"{tag}: units {len(units)} vs expect {len(exp)}"
        for ui, u in enumerate(units, 1):
            exp_u = exp[ui]
            assert len(u) == len(exp_u), f"{tag} unit{ui}: entries {len(u)} vs expect {len(exp_u)}"
            for ei, e in enumerate(u, 1):
                want = exp_u[ei - 1]
                hits, kw_only, observed = retrieve.retrieve(e["content"], store)
                ids = combined_ids((hits, kw_only, observed))
                rank = ids.index(want) + 1 if want and want in ids else None
                in_action = want in {h["id"] for h in hits} if want else None
                atier = next((h["tier"] for h in hits if h["id"] == want), None) if want else None
                amtype = next((h["mtype"] for h in hits if h["id"] == want), None) if want else None
                rows.append(dict(
                    file=tag, unit=ui, entry=ei, ts=e["ts"], source=e["source"],
                    log_id=e["log_id"], text=e["content"], want=want,
                    top1=ids[0] if ids else None, top3=ids[:3], rank=rank,
                    in_action=in_action, atier=atier, amtype=amtype,
                    n_action=len(hits), n_kw=len(kw_only),
                ))

    # ---------- B. data-921-930 前瞻 ----------
    parsed = json.loads((DS / "parsed_921_930.json").read_text(encoding="utf-8"))
    assert len(parsed) == len(run_unseen.EXPECT)
    unseen_rows = []
    for p in parsed:
        ui = p["unit"]
        assert len(p["entries"]) == len(run_unseen.EXPECT[ui])
        for ei, e in enumerate(p["entries"], 1):
            kind, targets, note = run_unseen.EXPECT[ui][ei - 1]
            hits, kw_only, observed = retrieve.retrieve(e["content"], store)
            ids = combined_ids((hits, kw_only, observed))
            unseen_rows.append(dict(
                unit=ui, entry=ei, ts=e["ts"], source=e["source"], log_id=e["log_id"],
                text=e["content"], kind=kind, targets=targets, note=note,
                top1=ids[0] if ids else None,
                top3=[(h["id"], h["tier"], h["mtype"]) for h in hits[:3]],
                action_ids=[h["id"] for h in hits],
                action_tiers=[(h["id"], h["tier"], f"{h['matched']}/{h['total']}") for h in hits],
                n_kw=len(kw_only),
            ))

    # ---------- 统计 ----------
    feat = [r for r in rows if r["want"]]
    gen = [r for r in rows if not r["want"]]

    def acc(sub):
        n = len(sub)
        top1 = sum(1 for r in sub if r["rank"] == 1)
        top3 = sum(1 for r in sub if r["rank"] and r["rank"] <= 3)
        present = sum(1 for r in sub if r["rank"])
        action_hit = sum(1 for r in sub if r["in_action"])
        strong = sum(1 for r in sub if r["atier"] == "强")
        return n, top1, top3, present, action_hit, strong

    L = []
    L.append("# 动作匹配检索器（v2）全量重放召回审计报告")
    L.append("")
    L.append(f"- 范围: `dataset/` 三文件全部日志行 = **{len(rows)} 条**（特征行 {len(feat)} + 通用样板行 {len(gen)}）")
    L.append("- 口径: 组合排序 = 动作通道优先（完整=强 / 命中≥2=中 / 命中1=弱参照）+ 关键词兜底（强≥6/中4–5/弱≤3）")
    L.append("- 期望映射: 沿用 v1 人工标注（`history/old_eval/run_recall_full.py` 的 EXPECT）")
    L.append("- 声明: 回顾性审计（证明已有知识可召回），不代表事前检出；通用样板行无唯一预期。")
    L.append("")
    n, t1, t3, pr, ah, st = acc(feat)
    L.append("## 一、总览（特征行）")
    L.append("")
    L.append("| 指标 | 值 |")
    L.append("|---|---|")
    L.append(f"| 特征行 | {n} |")
    L.append(f"| 组合 Top-1 | {t1}（{100*t1/n:.0f}%） |")
    L.append(f"| 组合 Top-3 | {t3}（{100*t3/n:.0f}%） |")
    L.append(f"| 组合出现 | {pr}（{100*pr/n:.0f}%） |")
    L.append(f"| 动作通道命中 | {ah}（{100*ah/n:.0f}%） |")
    L.append(f"| 动作通道强档（完整匹配） | {st}（{100*st/n:.0f}%） |")
    L.append("")
    L.append("### 分文件")
    L.append("")
    L.append("| 文件 | 特征行 | Top-1 | Top-3 | 动作命中 | 动作强档 |")
    L.append("|---|---|---|---|---|---|")
    for tag, _ in files:
        sub = [r for r in feat if r["file"] == tag]
        a = acc(sub)
        L.append(f"| {tag} | {a[0]} | {a[1]}（{100*a[1]/a[0]:.0f}%） | {a[2]}（{100*a[2]/a[0]:.0f}%） | {a[4]}（{100*a[4]/a[0]:.0f}%） | {a[5]}（{100*a[5]/a[0]:.0f}%） |")
    L.append("")
    L.append("## 二、逐案例召回（特征行按预期案例聚合）")
    L.append("")
    L.append("| 案例 | 特征行 | Top-1 | Top-3 | 动作命中 | 动作强档 | 说明 |")
    L.append("|---|---|---|---|---|---|---|")
    case_notes = {c["id"]: (c.get("attack_type") or "")[:30] for c in cases}
    for cid in sorted({r["want"] for r in feat}, key=lambda c: int(c.split("-")[1])):
        sub = [r for r in feat if r["want"] == cid]
        a = acc(sub)
        flag = ""
        if a[1] < a[0]:
            flag = "⚠️ 有非 Top-1" if a[2] == a[0] else "⚠️ 有未入前 3"
        if a[4] < a[0]:
            flag += " ·⚠️ 有未入动作通道"
        L.append(f"| {cid} | {a[0]} | {a[1]} | {a[2]} | {a[4]} | {a[5]} | {case_notes.get(cid,'')}{flag} |")
    L.append("")
    edge = [r for r in feat if r["rank"] != 1]
    L.append(f"## 三、非 Top-1 明细（{len(edge)} 条）")
    L.append("")
    if edge:
        L.append("| 文件-单元-条 | 来源 | 预期 | Top1 | 动作档 | 动作形态 | 预期排名 | 行内容（截断） |")
        L.append("|---|---|---|---|---|---|---|---|")
        for r in edge:
            t3s = "/".join(r["top3"])
            L.append(f"| {r['file']}-{r['unit']}-{r['entry']} | {r['source']} | {r['want']} | {r['top1']} | {r['atier'] or '—'} | {r['amtype'] or '—'} | {'—' if not r['rank'] else r['rank']} | `{r['text'][:48]}…` |")
    else:
        L.append("（无）")
    L.append("")
    L.append(f"## 四、通用样板行落点（{len(gen)} 条，无唯一预期案例）")
    L.append("")
    L.append("| 文件-单元-条 | 动作命中数 | 关键词兜底 | 行内容（截断） |")
    L.append("|---|---|---|---|")
    for r in gen:
        L.append(f"| {r['file']}-{r['unit']}-{r['entry']} | {r['n_action']} | {r['n_kw']} 条 | `{r['text'][:48]}…` |")
    L.append("")
    L.append("## 五、前瞻批 data-921-930（未入库，40 行）")
    L.append("")
    for kind, title in [("KNOWN", "KNOWN 已知家族行（应召回）"), ("SHARED", "SHARED 部分重叠行"),
                        ("NOVEL", "NOVEL 全新内容行（期望静默）"), ("GENERIC", "GENERIC 样板行")]:
        sub = [r for r in unseen_rows if r["kind"] == kind]
        L.append(f"### {title}（{len(sub)} 行）")
        L.append("")
        if kind == "KNOWN":
            h1 = h3 = act = 0
            for r in sub:
                allids = r["action_ids"] + ([r["top1"]] if r["top1"] else [])
                if allids and allids[0] in (r["targets"] or []):
                    h1 += 1
                if any(t in allids[:3] for t in (r["targets"] or [])):
                    h3 += 1
                if any(t in r["action_ids"] for t in (r["targets"] or [])):
                    act += 1
            nk = len(sub)
            L.append(f"- 组合 Top-1 命中目标: {h1}/{nk} · Top-3: {h3}/{nk} · 动作通道命中目标: {act}/{nk}")
            L.append("")
            L.append("| 单元-行 | 目标 | 动作通道命中(档) | Top1 |")
            L.append("|---|---|---|---|")
            for r in sub:
                tiers = "、".join(f"{i}({t})" for i, t, _ in r["action_tiers"])
                L.append(f"| {r['unit']}-{r['entry']} | {'+'.join(r['targets'] or [])} | {tiers or '—'} | {r['top1'] or '—'} |")
        elif kind == "SHARED":
            rel = 0
            for r in sub:
                if any(t in r["action_ids"] for t in (r["targets"] or [])):
                    rel += 1
            L.append(f"- 相关案例进入动作通道: {rel}/{len(sub)}")
            L.append("")
            L.append("| 单元-行 | 相关案例 | 动作通道命中(档) |")
            L.append("|---|---|---|")
            for r in sub:
                tiers = "、".join(f"{i}({t})" for i, t, _ in r["action_tiers"])
                L.append(f"| {r['unit']}-{r['entry']} | {'+'.join(r['targets'] or [])} | {tiers or '—'} |")
        elif kind == "NOVEL":
            st_ = md_ = sil_ = 0
            for r in sub:
                mx = max((3 if t == "强" else 2 if t == "中" else 1 for _, t, _ in r["action_tiers"]), default=0)
                if mx == 3:
                    st_ += 1
                elif mx == 2:
                    md_ += 1
                else:
                    sil_ += 1
            L.append(f"- 动作通道静默: {sil_}/{len(sub)} · 中档命中: {md_} · 强档误命中: {st_}")
            L.append("")
            L.append("| 单元-行 | 动作通道命中(档) | 备注 |")
            L.append("|---|---|---|")
            for r in sub:
                tiers = "、".join(f"{i}({t})" for i, t, _ in r["action_tiers"]) or "静默"
                L.append(f"| {r['unit']}-{r['entry']} | {tiers} | {r['note'][:36]} |")
        else:
            noisy = [r for r in sub if r["action_ids"]]
            L.append(f"- 动作通道误命中样板行: {len(noisy)}/{len(sub)}")
            L.append("")
            if noisy:
                L.append("| 单元-行 | 动作通道命中(档) |")
                L.append("|---|---|")
                for r in noisy:
                    tiers = "、".join(f"{i}({t})" for i, t, _ in r["action_tiers"])
                    L.append(f"| {r['unit']}-{r['entry']} | {tiers} |")
        L.append("")

    L.append("## 六、结论（自动初判口径）")
    L.append("")
    L.append(f"- 已入库重放: 组合 Top-1 {100*t1/n:.0f}% · Top-3 {100*t3/n:.0f}% · 动作通道命中 {100*ah/n:.0f}% · 动作强档 {100*st/n:.0f}%（回顾性）。")
    L.append("- 前瞻批见第五节（未入库，成绩即真实召回口径）。")
    L.append("")

    (OUT / "report_action_recall.md").write_text("\n".join(L), encoding="utf-8")
    with (OUT / "action_recall_details.jsonl").open("w", encoding="utf-8") as f:
        for r in rows + [dict(r, part="unseen") for r in unseen_rows]:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    print(f"报告: {OUT/'report_action_recall.md'}")
    print(f"明细: {OUT/'action_recall_details.jsonl'}")
    print(f"总览: 特征行 {n} · Top-1 {t1} · Top-3 {t3} · 出现 {pr} · 动作命中 {ah} · 动作强档 {st} · 样板行 {len(gen)}")


if __name__ == "__main__":
    main()

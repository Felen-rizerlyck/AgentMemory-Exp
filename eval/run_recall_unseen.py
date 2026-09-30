#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""eval/run_recall_unseen.py — 未入库数据的前瞻召回测试（data-921-930）

设计（与回顾性审计的区别）:
- 查询 = 从未参与案例编写的新数据（无 keys/probes 污染），检索先于任何入库动作——"前瞻"测试。
- 四种行级期望（EXPECT，人工按攻击内容标注）:
    KNOWN   : 应召回指定案例集合（工具链/载荷指纹客观一致）
    SHARED  : 与已知案例存在部分重叠（共享探针/载荷片段/字段），召回"相关案例"为合理行为
    NOVEL   : 攻击链内容不在库中 → 期望静默（无 ≥4 分命中）
    GENERIC : 通用样板行（cat /etc/passwd 类），无唯一期望，单独统计落点
- 基线: C0(仅keys) / C1(全词面) / C2(现状+probes)，评分实现与 run_eval.py 同源。

输出: eval/results/report_recall_unseen.md + recall_unseen_details.jsonl
"""
import importlib.util
import json
import pathlib
import sys
from collections import Counter

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = pathlib.Path(__file__).parent.parent
OUT = BASE / "eval" / "results"
OUT.mkdir(exist_ok=True)


def load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


retrieve = load_module(BASE / "src/retrieve.py", "retrieve")
run_eval = load_module(BASE / "eval" / "run_eval.py", "run_eval")

CHANNELS = {"C0": {"keys"}, "C1": {"keys", "mitre", "ind", "sig"},
            "C2": {"keys", "mitre", "ind", "sig", "probes"}}

# ---------------- 行级期望映射（按攻击内容人工标注，先于看结果） ----------------
EXPECT = {
    1:  [("KNOWN", ["CASE-010", "CASE-011"], "同 /api/v1/ping?cmd=127.0.0.1;id 探针模板（产品特征缺失）"),
         ("KNOWN", ["CASE-010", "CASE-011"], "同上"),
         ("KNOWN", ["CASE-010", "CASE-011"], "同上"),
         ("GENERIC", None, "样板行")],
    2:  [("NOVEL", None, "K8s 接口 + load_file SQLi（库中无）"),
         ("NOVEL", None, "同上"),
         ("NOVEL", None, "cmd_inject';id' + loginNam 截断（库中无）"),
         ("GENERIC", None, "样板行")],
    3:  [("SHARED", ["CASE-005"], "echo;id 探针（同 005 指纹）；php-fpm RCE 标记为新增"),
         ("SHARED", ["CASE-005"], "同上"),
         ("SHARED", ["CASE-005"], "同上"),
         ("GENERIC", None, "样板行")],
    4:  [("KNOWN", ["CASE-006"], "rO0AB + /webtools/control/main（006 指纹）；cron.d 落点为新增"),
         ("KNOWN", ["CASE-006"], "同上"),
         ("KNOWN", ["CASE-006"], "同上"),
         ("GENERIC", None, "样板行")],
    5:  [("SHARED", ["CASE-009", "CASE-010", "CASE-011"], "cmd 探针(010/011) + admin:true(009) 组合，库中无此组合"),
         ("SHARED", ["CASE-009", "CASE-010", "CASE-011"], "同上"),
         ("SHARED", ["CASE-009", "CASE-010", "CASE-011"], "同上"),
         ("GENERIC", None, "样板行")],
    6:  [("KNOWN", ["CASE-006"], "rO0AB（006 指纹）；GCP 元数据目标为新增"),
         ("KNOWN", ["CASE-006"], "同上"),
         ("KNOWN", ["CASE-006"], "同上"),
         ("GENERIC", None, "样板行")],
    7:  [("KNOWN", ["CASE-005"], "cgi-bin .%2e 变体 + echo;id（005 已obs形态）；XSLT 为新增"),
         ("KNOWN", ["CASE-005"], "同上"),
         ("KNOWN", ["CASE-005"], "同上"),
         ("GENERIC", None, "样板行")],
    8:  [("KNOWN", ["CASE-005"], "cgi-bin %%32%65 双编码 + echo;id（005 原形态）"),
         ("KNOWN", ["CASE-005"], "同上"),
         ("KNOWN", ["CASE-005"], "同上"),
         ("GENERIC", None, "样板行")],
    9:  [("KNOWN", ["CASE-009"], "mass_assignment+admin:true（009 指纹）；LOAD_FILE UNC 为新增"),
         ("KNOWN", ["CASE-009"], "同上"),
         ("KNOWN", ["CASE-009"], "同上"),
         ("GENERIC", None, "样板行")],
    10: [("KNOWN", ["CASE-010", "CASE-011"], "cmd=127.0.0.1;id 探针（同 010/011 模板）；rememberMe 为新增"),
         ("KNOWN", ["CASE-010", "CASE-011"], "同上"),
         ("KNOWN", ["CASE-010", "CASE-011"], "同上"),
         ("GENERIC", None, "样板行")],
}

UNIT_THEME = {
    1: "命令探针模板（/api/v1/ping，无产品特征）",
    2: "K8s 接口探测 + load_file SQLi（全新）",
    3: "php-fpm RCE 标记 + echo;id（部分重叠）",
    4: "Java 反序列化（006 指纹）+ cron.d 落点（新增）",
    5: "cmd 探针 + admin:true 组合（部分重叠）",
    6: "Java 反序列化 + GCP 元数据 SSRF（新增目标）",
    7: "CGI .%2e 变体 + XSLT（已知形态+新增）",
    8: "CGI %%32%65 双编码（已知形态）",
    9: "mass_assignment + LOAD_FILE UNC（已知指纹+新增）",
    10: "cmd 探针 + rememberMe 反序列化（部分新增）",
}


def main():
    parsed = json.loads((BASE / "dataset" / "parsed_921_930.json").read_text(encoding="utf-8"))
    assert len(parsed) == len(EXPECT)

    rows = []
    for p in parsed:
        ui = p["unit"]
        assert len(p["entries"]) == len(EXPECT[ui])
        for ei, e in enumerate(p["entries"], 1):
            kind, targets, note = EXPECT[ui][ei - 1]
            per_cfg = {}
            for cfg, ch in CHANNELS.items():
                scored = []
                for c in json.loads((BASE / "data/memory_store.json").read_text(encoding="utf-8"))["cases"]:
                    s, _ = run_eval.score_case_cfg(c, e["content"].lower(), ch)
                    if s > 0:
                        scored.append((s, c["id"]))
                scored.sort(key=lambda x: (-x[0], x[1]))
                per_cfg[cfg] = scored
            rows.append(dict(unit=ui, entry=ei, ts=e["ts"], source=e["source"], log_id=e["log_id"],
                             text=e["content"], kind=kind, targets=targets, note=note, per_cfg=per_cfg))

    with (OUT / "recall_unseen_details.jsonl").open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    def band(s):
        return "强" if s >= 6 else "中" if s >= 4 else "弱" if s >= 1 else "无"

    L = []
    L.append("# 未入库数据前瞻召回测试报告（data-921-930）")
    L.append("")
    L.append("- 设计: **前瞻测试**——查询数据从未参与案例编写（无 keys/probes 污染），检索先于任何入库动作；")
    L.append("  与回顾性审计（`report_recall_full.md`，重放已入库行）互补，回答「真实新数据下的召回效率」。")
    L.append("- 数据: 10 单元 / 40 行（waf×10 · web×10 · rasp×10 · hids×10）；行级期望人工标注（先于结果）")
    L.append("- 基线: C0=仅 keys / C1=全词面 / C2=现状(+probes)，评分实现与 `run_eval.py` 同源")
    L.append("- 期望分类: KNOWN=应召回指定案例 / SHARED=部分重叠（召回相关案例为合理行为） / NOVEL=库外内容（期望静默） / GENERIC=样板行")
    L.append("")

    for kind, title in [("KNOWN", "一、已知家族行（应召回）"), ("SHARED", "二、部分重叠行"), ("NOVEL", "三、全新内容行（期望静默）")]:
        sub = [r for r in rows if r["kind"] == kind]
        L.append(f"## {title}（{len(sub)} 行）")
        L.append("")
        if kind == "KNOWN":
            L.append("| 基线 | Top-1 | Top-3 | 强档(≥6) | 目标最高分(均值) |")
            L.append("|---|---|---|---|---|")
            for cfg in CHANNELS:
                h1 = h3 = st = 0; ss = []
                for r in sub:
                    sc = {c: s for s, c in r["per_cfg"][cfg]}
                    ts_ = [sc.get(t, 0) for t in r["targets"]]
                    best = max(ts_)
                    ids = [i for _, i in r["per_cfg"][cfg]]
                    if ids and ids[0] in r["targets"]: h1 += 1
                    if any(t in ids[:3] for t in r["targets"]): h3 += 1
                    if best >= 6: st += 1
                    ss.append(best)
                n = len(sub)
                L.append(f"| {cfg} | {h1}/{n}（{100*h1/n:.0f}%） | {h3}/{n}（{100*h3/n:.0f}%） | {st}/{n}（{100*st/n:.0f}%） | {sum(ss)/n:.1f} |")
            L.append("")
            misses = []
            for r in sub:
                ids = [i for _, i in r["per_cfg"]["C1"]]
                if not (ids and ids[0] in r["targets"]):
                    misses.append(f"{r['unit']}-{r['entry']}（C1 top1={ids[0] if ids else '无'}）")
            L.append(f"C1 丢 Top-1 的行: {'；'.join(misses) if misses else '无'}")
            L.append("")
            L.append("| 单元-行 | 期望 | C2 Top3 |")
            L.append("|---|---|---|")
            for r in sub:
                t3 = "、".join(f"{c}({s})" for s, c in r["per_cfg"]["C2"][:3]) or "无返回"
                L.append(f"| {r['unit']}-{r['entry']} | {'+'.join(r['targets'])} | {t3} |")
        elif kind == "SHARED":
            L.append("| 基线 | 相关案例命中(≥4) | 静默 | 串扰(≥4 且非相关) |")
            L.append("|---|---|---|---|")
            for cfg in CHANNELS:
                rel = sil = cross = 0
                for r in sub:
                    sc = {c: s for s, c in r["per_cfg"][cfg]}
                    related = any(sc.get(t, 0) >= 4 for t in r["targets"])
                    any4 = [c for s, c in r["per_cfg"][cfg] if s >= 4]
                    if related: rel += 1
                    elif not any4: sil += 1
                    else: cross += 1
                n = len(sub)
                L.append(f"| {cfg} | {rel}/{n} | {sil}/{n} | {cross}/{n} |")
            L.append("")
            L.append("| 单元-行 | 相关案例 | C2 Top3 | 备注 |")
            L.append("|---|---|---|---|")
            for r in sub:
                t3 = "、".join(f"{c}({s})" for s, c in r["per_cfg"]["C2"][:3]) or "无返回"
                L.append(f"| {r['unit']}-{r['entry']} | {'+'.join(r['targets'])} | {t3} | {r['note'][:40]} |")
        else:  # NOVEL
            L.append("| 基线 | 静默(无≥4) | 中档(4–5) | 强档(≥6) |")
            L.append("|---|---|---|---|")
            for cfg in CHANNELS:
                sil = mid = st = 0
                for r in sub:
                    mx = max((s for s, _ in r["per_cfg"][cfg]), default=0)
                    if mx < 4: sil += 1
                    elif mx < 6: mid += 1
                    else: st += 1
                n = len(sub)
                L.append(f"| {cfg} | {sil}/{n} | {mid}/{n} | {st}/{n} |")
            L.append("")
            L.append("| 单元-行 | C0 Top3 | C1 Top3 | C2 Top3 |")
            L.append("|---|---|---|---|")
            for r in sub:
                def t3(cfg):
                    return "、".join(f"{c}({s})" for s, c in r["per_cfg"][cfg][:3]) or "无返回"
                L.append(f"| {r['unit']}-{r['entry']} | {t3('C0')} | {t3('C1')} | {t3('C2')} |")
        L.append("")

    gen = [r for r in rows if r["kind"] == "GENERIC"]
    L.append(f"## 四、通用样板行落点（{len(gen)} 行，无唯一期望）")
    L.append("")
    L.append("| 单元-行 | C2 Top3 |")
    L.append("|---|---|")
    for r in gen:
        t3 = "、".join(f"{c}({s})" for s, c in r["per_cfg"]["C2"][:3]) or "无返回"
        L.append(f"| {r['unit']}-{r['entry']} | {t3} |")
    L.append("")

    L.append("## 五、与回顾性审计的对照")
    L.append("")
    L.append("| 维度 | 回顾性（report_recall_full，123 特征行） | 前瞻（本报告，31 特征行） |")
    L.append("|---|---|---|")
    def kn_metrics(cfg):
        sub = [r for r in rows if r["kind"] == "KNOWN"]
        h1 = sum(1 for r in sub if r["per_cfg"][cfg] and r["per_cfg"][cfg][0][1] in r["targets"])
        return f"{h1}/{len(sub)}"
    L.append(f"| Top-1 | 122/123（99%） | C2: {kn_metrics('C2')} / C1: {kn_metrics('C1')} / C0: {kn_metrics('C0')} |")
    L.append(f"| 数据来源 | 已入库证据行（近同义反复） | 未入库新行（无污染） |")
    L.append("")

    L.append("## 六、观察与分析（批注）")
    L.append("")
    L.append("**1. 一号根因：通用 token 的多通道重复累计——本批所有异常都由它解释**")
    L.append("- 机制：同一/同类通用 token（英文单词、字段名）同时出现在案例的 keys(×3)、indicators(×2)、signature(×1) 中时被重复计分——单个或两个 token 即可凑到 6 分强档。")
    L.append("- 实例（逐条溯源）：`select`（2-1/2-2/7-x × CASE-015，3+2+1=6）；`cmd_inject`（2-3 × CASE-014/020，3+2 及 +1）；`process`（3-4 × CASE-001，3+2+1=6）；`deserialization`（4-x × CASE-012，3+2+1=6）；`base64`（10-1 × CASE-019，3+2+1=6）；`username`+`password`（5-x × CASE-015，ind 4 + sig 2 = 6）。")
    L.append("- 连带影响：C1 丢的 2 条 Top-1（6-1/6-2）同因——CASE-012 经 `deserialization` 得 6 超过 CASE-006 的 5；C2 靠 CASE-006 的 `rO0AB` 探针（+4）恢复正确排序。")
    L.append("")
    L.append("**2. 召回端（KNOWN 21 行）**：C2 全部 Top-1 且目标全部强档；C0（仅 keys）也已 21/21——本批新数据与已知案例共享的指纹（命令探针、rO0AB 序列化流、路径模版）足够具体。probes 在本批的主要贡献是排序稳定性（对 C1 串扰的恢复）。")
    L.append("")
    L.append("**3. 误报端（NOVEL 3 行）：3/3 被误报至强档**——这是「数据好看是否属实」的直接回答：关联指纹的召回可靠，但真实新内容会遭遇强档误报。其中 2-1/2-2 为清晰误报（`select`）；2-3 为边界案例（`cmd_inject` 是真实共享参数名，但强档判定偏高，应属中/弱候选）。")
    L.append("")
    L.append("**4. 关联面与样板行**：SHARED 行相关案例均强档召回（005=9、010=10）✓；7-x 的 CASE-017(6) 虽非目标但属 005 的 helpful 关联案例（gold 边），为可接受上下文；样板行 3-4 出现 CASE-001=6 / CASE-003=7（同族问题再现）。")
    L.append("")
    L.append("**5. 建议**：将「跨通道去重（同一 token 只按其最高权重通道计一次）」列入 PENDING §2 候选修法；修复前强档结果一律人工复核。本批数据保持未入库状态（保留前瞻性）。")
    L.append("")

    (OUT / "report_recall_unseen.md").write_text("\n".join(L), encoding="utf-8")
    print(f"报告: {OUT/'report_recall_unseen.md'}")
    print(f"明细: {OUT/'recall_unseen_details.jsonl'}")
    # 控制台摘要
    sub = [r for r in rows if r["kind"] == "KNOWN"]
    for cfg in CHANNELS:
        h1 = sum(1 for r in sub if r["per_cfg"][cfg] and r["per_cfg"][cfg][0][1] in r["targets"])
        print(f"KNOWN 行 {cfg}: Top-1 {h1}/{len(sub)}")
    no = [r for r in rows if r["kind"] == "NOVEL"]
    for cfg in CHANNELS:
        viol = [f"{r['unit']}-{r['entry']}:{[(s,c) for s,c in r['per_cfg'][cfg] if s>=4]}" for r in no
                if max((s for s,_ in r["per_cfg"][cfg]), default=0) >= 4]
        print(f"NOVEL 行 {cfg}: 非静默={viol}")


if __name__ == "__main__":
    main()

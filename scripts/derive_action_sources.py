#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""derive_action_sources.py — 案例 `action_sources` 标注的**证据推导**脚本（可审计、可重跑）

做什么：为每个案例的每个动作推出"该动作被哪些检测层观测到"，写入
        `scripts/build_action_index.py` 的 SOURCES 字典（标记块之间），并打印标注表。

推导口径（按优先级，全部基于仓库内已有数据/字段，不臆造）：
  (a) 动作在 dataset/ 入库数据集（901-910 / 911-920 / 9101-9110）的**期望行**里被动作库正则命中
      → 取该行的来源层（waf/web/rasp/hids/dns）；
  (b) 未命中（如载荷在日志里被截断、正则形态不覆盖）→ 取该案例证据行的来源层集合
      ∩ 案例 `source` 字段层，空则退化为案例 `source` 字段；
  (c) 不在数据集的案例（CASE-023~028，来自部署场景测试批）→ 按 `data/incoming_logs.txt`
      的 log_id→案例映射推导；
  (d) generic 通用探针（whoami / cmd=id / smuggle 等）→ `any`（不参与来源校验，
      探针可在任意层出现，约束它只会制造假告警）。

用法: python scripts/derive_action_sources.py [--dry-run]
"""
import importlib.util
import json
import pathlib
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = pathlib.Path(__file__).resolve().parent.parent
BUILD = BASE / "scripts" / "build_action_index.py"
BEGIN, END = "# >>> ACTION_SOURCES_BEGIN", "# <<< ACTION_SOURCES_END"

# (c) 批次证据：真实批次文件 + 该批 log_id → 案例 映射。
# 新建案例若来自真实批次（不在 dataset/ 里），**在此登记其来源批次**，标注即可自动推导（区别于 OVERRIDES 的事后人工覆盖）。
BATCH_EVIDENCE = [
    ("data/batches/deploy_test_2026-10-14.txt", {   # 部署场景测试批（CASE-023~028；2026-10-15 从 incoming_logs.txt 归档，避免被下批覆盖）
        "WAF0303110": "CASE-023", "WAF0303221": "CASE-024", "WAF0303304": "CASE-025",
        "WAF0303412": "CASE-026", "HID0303555": "CASE-027", "HID0303601": "CASE-028",
        "WAF0304010": "CASE-028",
    }),
    ("data/batches/CASE-029_ProxyLogon_原样本.txt", {   # 参考样例批（CASE-029）
        "WAF0410001": "CASE-029", "WEB0410002": "CASE-029", "HID0410003": "CASE-029",
        "RASP0410004": "CASE-029", "WEB0410005": "CASE-029", "HID0410006": "CASE-029",
        "HID0410007": "CASE-029", "DNS0410008": "CASE-029",
    }),
]
# 人工覆盖（优先于自动推导；审查发现：语料里载荷被截断或正则形态不覆盖时的显式口径）
# 依据逐条注明；改动此处 = 改动标注，需重跑本脚本 + build_action_index.py
OVERRIDES = {
    "CASE-006": {
        "com_sun_gadget": "rasp",              # 语料仅 data-901-910 的 [rasp] 行含 "com.sun"（载荷被截断），案例记录亦载"仅 RASP 层"
        "gcp_metadata_ssrf": ["waf", "web"],   # metadata.google.internal 载荷文本仅见 data-921-930 的 waf/web 行（未入库批）
    },
    "CASE-009": {
        "mysql_load_file": ["waf", "web"],     # LOAD_FILE 载荷文本仅见 data-921-930 的 waf/web 行
    },
    "CASE-013": {
        "spel_type_ref": ["waf", "web"],       # java.lang.Runtime 文本仅见 waf/web 行（rasp 行截断）
    },
}
DATASETS = [("901-910", "data-901-910.txt"), ("911-920", "data-911-920.txt"),
            ("9101-9110", "data-9101-9110.txt")]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def main():
    ret = load(BASE / "src" / "retrieve.py", "ret")
    rf = load(BASE / "history" / "old_eval" / "run_recall_full.py", "rf")
    build = load(BUILD, "build_idx")
    cases, _store_lib = ret.load_store()
    # 动作库以 build 脚本的 ACTIONS 为准（新动作此时尚未注入 store；标注推导必须看最新定义）
    lib = {aid: dict(a) for aid, a in build.ACTIONS.items()}
    # 序列以 build 脚本的 SEQUENCES 为准（案例本体入库后、首次 build 注入前也能推导来源：
    # 避免"derive 需要 action_sequence / build 需要 SOURCES"的先后依赖死锁）
    seq = {c["id"]: list(build.SEQUENCES.get(c["id"]) or c.get("action_sequence", []))
           for c in cases}
    case_layers = {c["id"]: [s.strip().lower() for s in (c.get("source") or "").split("+") if s.strip()]
                   for c in cases}

    matched = {}                       # case -> action -> set(layers)
    line_layers = {}                    # case -> set(layers)（案例证据行来源层）
    for tag, fn in DATASETS:
        units = rf.parse_file(BASE / "dataset" / fn)
        exp = rf.EXPECT[tag]
        for ui, u in enumerate(units, 1):
            for ei, e in enumerate(u, 1):
                want = exp[ui][ei - 1]
                if not want:
                    continue
                line_layers.setdefault(want, set()).add(e["source"])
                for aid, _lbl, _pos in ret.match_actions(e["content"], lib):
                    if aid in seq[want]:
                        matched.setdefault(want, {}).setdefault(aid, set()).add(e["source"])
    # (c) 批次证据（逐批登记的真实批次）
    for path, logmap in BATCH_EVIDENCE:
        fp = BASE / path
        if not fp.exists():
            continue
        for line in fp.read_text(encoding="utf-8").splitlines():
            m = re.search(r"\[(\w+)\]\s+([A-Z]{2,6}\d{4,})", line)
            if not m or m.group(2) not in logmap:
                continue
            cid, src = logmap[m.group(2)], m.group(1).lower()
            line_layers.setdefault(cid, set()).add(src)
            for aid, _lbl, _pos in ret.match_actions(line, lib):
                if aid in seq.get(cid, []):
                    matched.setdefault(cid, {}).setdefault(aid, set()).add(src)

    sources, rows = {}, []
    LAYER_ORDER = ["waf", "web", "rasp", "hids", "dns"]   # 展示顺序（waf→web→rasp→hids→dns）
    lk = lambda s: LAYER_ORDER.index(s) if s in LAYER_ORDER else 99  # noqa: E731
    branch = {"override": 0, "any-generic": 0, "direct": 0, "fallback": 0}
    for c in cases:
        cid = c["id"]
        per_case = {}
        for aid in seq[cid]:
            ov = OVERRIDES.get(cid, {})
            if aid in ov:                                                 # (0) 人工覆盖
                per_case[aid] = ov[aid]
                branch["override"] += 1
                continue
            if (lib.get(aid) or {}).get("generic"):
                per_case[aid] = "any"                                     # (d)
                branch["any-generic"] += 1
                continue
            hit = sorted(matched.get(cid, {}).get(aid, []), key=lk)        # (a)/(c)
            if hit:
                branch["direct"] += 1
            if not hit:                                                   # (b)
                hit = sorted(line_layers.get(cid, set()) & set(case_layers[cid]), key=lk)
                if hit:
                    branch["fallback"] += 1
            if not hit:
                hit = sorted(case_layers[cid] or ["any"], key=lk)
                branch["fallback"] += 1
            per_case[aid] = hit[0] if len(hit) == 1 else hit
        sources[cid] = per_case
        rows.append((cid, c.get("source"), per_case))

    # ---- 打印标注表 ----
    print("| 案例 | 案例 source | 动作 → 观测来源 |")
    print("|---|---|---|")
    for cid, src, per in rows:
        cell = " · ".join(f"`{a}`={('+'.join(v) if isinstance(v, list) else v)}" for a, v in per.items())
        print(f"| {cid} | {src} | {cell} |")

    # ---- 写入 build 脚本（标记块之间；无标记则插到 SEQUENCES 之后） ----
    block = [BEGIN]
    block.append("# ---------------- 案例动作观测来源（链层来源槽位校验用） ----------------")
    block.append("# 取值: waf / web / rasp / hids / dns / any（any = 不校验）；多来源用列表（任一命中即通过）")
    block.append("# 来源: 由 scripts/derive_action_sources.py 依 dataset/ 与 data/incoming_logs.txt 观测推导（可重跑复核）")
    block.append(f"# 分支构成: 直接观测 {branch['direct']} / generic→any {branch['any-generic']}"
                 f" / 人工覆盖 {branch['override']} / 回退推断 {branch['fallback']}"
                 f"（人工覆盖口径见 derive_action_sources.py 的 OVERRIDES）")
    block.append("SOURCES = {")
    for cid, _src, per in rows:
        items = ", ".join(f'"{a}": {json.dumps(v, ensure_ascii=False)}' for a, v in per.items())
        block.append(f'    "{cid}": {{{items}}},')
    block.append("}")
    block.append(END)
    new_block = "\n".join(block)
    text = BUILD.read_text(encoding="utf-8")
    if BEGIN in text and END in text:
        # replacement 用 lambda：new_block 按字面量插入（避免反斜杠被 re 解释）
        text = re.sub(re.escape(BEGIN) + r".*?" + re.escape(END), lambda _m: new_block, text, flags=re.S)
    else:
        anchor = "# ---------------- 动作阶段标注"
        text = text.replace(anchor, new_block + "\n\n" + anchor, 1)
    if "--dry-run" in sys.argv:
        print("\n[--dry-run] 不写盘；生成块长度", len(new_block))
        return
    BUILD.write_text(text, encoding="utf-8")
    print(f"\n已写入 {BUILD.name} 的 SOURCES（{len(sources)} 案例）")


if __name__ == "__main__":
    main()

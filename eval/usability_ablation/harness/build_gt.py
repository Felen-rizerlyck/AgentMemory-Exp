#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""build_gt.py —— 为 140 个合成 unit 生成 GT（案例性质）

GT 分类（人工规则 + 显式覆盖，供你抽检）：
  exact          与已入库案例完全同一组日志（7 个，T0 对照）
  same_pattern   同一行为模式、应能完整匹配到某个案例（变体，非逐字重复）
  family_variant 同一攻击家族但阶段不全（不应判 strong 完整匹配，最多 medium/partial）
  new            库里没有这个家族（正确行为是判"新案例"）
  irrelevant     无关日志（本批没有，保留类别）

输出：eval/usability_ablation/gt_units.json
"""
import json
import pathlib

BASE = pathlib.Path(__file__).resolve().parents[3]
DATASET = BASE / "dataset"
OUT = pathlib.Path(__file__).resolve().parents[1] / "gt_units.json"

INGESTED = {1001: "CASE-001", 1021: "CASE-002", 1042: "CASE-003", 1061: "CASE-004",
            1081: "CASE-005", 1102: "CASE-006", 1121: "CASE-007"}

# 家族关键词（只用于把 unit 归到"家族"，不等于 same_pattern）
FAMILY_KEYWORDS = {
    "CASE-001": ["log4shell", "log4j", "jndi"],
    "CASE-002": ["tomcat", "jsp webshell", "webshell 上传"],
    "CASE-003": ["schtasks", "计划任务"],
    "CASE-004": ["laravel", "ignition"],
    "CASE-005": ["勒索", "卷影", "vssadmin", "cipher /e", "加密"],
    "CASE-006": ["bloodhound", "sharphound"],
    "CASE-007": ["npm", "postinstall"],
    "CASE-008": ["proxylogon", "proxynotshell", "exchange"],
}

# 显式覆盖：unit → (gt_class, 说明)
OVERRIDES = {
    1013: ("family_variant", "Laravel Ignition 同一 CVE 但换端点（/_ignition vs /execute-solution），动作正则不覆盖"),
    1035: ("family_variant", "Exchange 但为 ProxyNotShell（CVE-2022-41040），与 CASE-008 的 ProxyLogon 不同链"),
    1106: ("new", "Exchange PrivExchange+中继，与 CASE-008 的 webshell 链不同族"),
    1007: ("family_variant", "JNDI 家族（Fastjson autoType），注入载体与 CASE-001 的 ${jndi: 不同"),
    1018: ("family_variant", "JNDI 家族（H2 驱动加载），注入载体不同"),
    1048: ("family_variant", "webshell 交互，缺 CASE-002 的 PUT 上传与 DNS 阶段"),
    1049: ("family_variant", "webshell 文件管理，缺 CASE-002 的上传/DNS 阶段"),
    1050: ("family_variant", "ASPX webshell 执行，缺 CASE-002 的 PUT 上传与 DNS 阶段"),
    1084: ("family_variant", "含 schtasks 持久化但缺 CASE-003 的 waf/rasp 入口阶段"),
    1051: ("new", "冰蝎/哥斯拉加密参数流量，与 CASE-005 的勒索加密无关（关键词误命中）"),
    1002: ("new", "Spring4Shell，与 CASE-002 的 Tomcat PUT 上传无关（关键词误命中）"),
    1047: ("family_variant", "日志清理+卷影删除，属 CASE-005 的破坏恢复阶段但无批量加密"),
}

# FA 家族（1081-1100）除已入库的 1081 外，都是"同族变体"（勒索链，但阶段组合不同）
FA_EXTRA = {u: ("family_variant", "勒索家族变体：阶段组合与 CASE-005 不完全一致")
            for u in range(1082, 1101)}


def load_units():
    lab = {}
    for fn in ("parsed_1001_1080.json", "parsed_1081_1140.json"):
        for l in json.loads((DATASET / fn).read_text(encoding="utf-8")):
            lab[l["unit"]] = l
    return lab


def main():
    lab = load_units()
    gt = {}
    for unit, l in sorted(lab.items()):
        tech = l["technique"]
        if unit in INGESTED:
            gt[unit] = dict(gt_class="exact", gt_case=INGESTED[unit], confidence="high",
                            needs_review=False, reason=f"与 {INGESTED[unit]} 入库时使用同一组日志")
            continue
        if unit in OVERRIDES:
            cls, reason = OVERRIDES[unit]
            case = None if cls == "new" else next(
                (c for c, kws in FAMILY_KEYWORDS.items() if any(k in tech.lower() for k in kws)), None)
            gt[unit] = dict(gt_class=cls, gt_case=case, confidence="medium", needs_review=True, reason=reason)
            continue
        if unit in FA_EXTRA:
            gt[unit] = dict(gt_class="family_variant", gt_case="CASE-005", confidence="medium",
                            needs_review=True, reason=FA_EXTRA[unit][1])
            continue
        case = next((c for c, kws in FAMILY_KEYWORDS.items() if any(k in tech.lower() for k in kws)), None)
        if case:
            gt[unit] = dict(gt_class="family_variant", gt_case=case, confidence="low", needs_review=True,
                            reason="关键词命中家族，但阶段结构未核实")
        else:
            gt[unit] = dict(gt_class="new", gt_case=None, confidence="high", needs_review=False,
                            reason="不属于已入库的 8 个案例家族")

    OUT.write_text(json.dumps({"schema": "gt-v1", "units": gt}, ensure_ascii=False, indent=1) + "\n",
                   encoding="utf-8")
    import collections
    cnt = collections.Counter(v["gt_class"] for v in gt.values())
    print(f"GT 写入 {OUT}：{len(gt)} 个 unit")
    for k, v in cnt.most_common():
        print(f"  {k:14s} {v:3d}")
    rev = [u for u, v in gt.items() if v["needs_review"]]
    print(f"需人工复核 {len(rev)} 个：{rev}")
    for case in sorted({v['gt_case'] for v in gt.values() if v['gt_case']}):
        same = [u for u, v in gt.items() if v["gt_case"] == case and v["gt_class"] == "same_pattern"]
        exact = [u for u, v in gt.items() if v["gt_case"] == case and v["gt_class"] == "exact"]
        var = [u for u, v in gt.items() if v["gt_case"] == case and v["gt_class"] == "family_variant"]
        print(f"  {case}: exact={exact} same_pattern={same} family_variant={len(var)}")


if __name__ == "__main__":
    main()

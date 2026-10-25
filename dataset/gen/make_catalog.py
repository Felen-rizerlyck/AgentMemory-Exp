#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""dataset/gen/make_catalog.py —— 生成「合成数据目录」（只覆盖 unit 1001 起的合成批次）

用法: python dataset/gen/make_catalog.py [--out dataset]
输出: dataset/CATALOG_1001-1140.md
内容全部从 parsed_1001_1080.json / parsed_1081_1140.json 现算，保证与实际数据一致。
"""
import argparse
import datetime as dt
import json
import pathlib
import collections

GEN = pathlib.Path(__file__).resolve().parent
ROOT = GEN.parent.parent

BATCHES = [  # (标签文件, 说明)
    ("parsed_1001_1080.json", "第一批：已有家族的形态扩展（Web 利用链为主）"),
    ("parsed_1081_1140.json", "第二批：新攻击家族（勒索/域身份/供应链）"),
]
FORM_MEAN = {
    "F1": ("形态①", "Web 利用链（waf → web → rasp → hids）"),
    "F2": ("形态②", "利用链 + DNS C2/外传三连"),
    "F3": ("形态③", "无 web 行（waf→rasp→hids / rasp→hids / 仅 hids / waf→hids）"),
    "F4": ("形态④", "双 hids（执行 + 后续动作）"),
    "FA": ("家族 FA", "勒索与数据破坏链（破坏恢复能力 → 批量加密 → 横向）"),
    "FB": ("家族 FB", "域环境身份攻击链（枚举 → Kerberos 滥用 → DCSync → 域控持久化）"),
    "FC": ("家族 FC", "供应链与 CI/CD 投毒链（依赖/镜像投毒 → 构建机执行 → 窃取 CI 密钥 → 制品投毒）"),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dataset"))
    ap.add_argument("--name", default="CATALOG_1001-1140.md")
    args = ap.parse_args()
    out = pathlib.Path(args.out)
    groups, files = [], collections.OrderedDict()
    for fname, blob in BATCHES:
        p = out / fname
        if not p.exists():
            continue
        labels = json.loads(p.read_text(encoding="utf-8"))
        key = "form" if "form" in labels[0] else "family"
        for lab in labels:
            g = lab[key]
            files.setdefault(g, dict(batch=blob, file=lab.get("file", ""), units=[]))
            files[g]["units"].append(lab)
    order = ["F1", "F2", "F3", "F4", "FA", "FB", "FC"]
    keys = [k for k in order if k in files] + [k for k in files if k not in order]

    L = []
    L.append("# 合成攻击日志数据集 · 目录（unit 1001 起）")
    L.append("")
    L.append(f"生成时间：{dt.datetime.now().strftime('%Y-%m-%d %H:%M')}　|　"
             f"覆盖：unit 1001~{max(l['unit'] for k in keys for l in files[k]['units'])}，"
             f"{sum(len(files[k]['units']) for k in keys)} 组、"
             f"{sum(len(l['entries']) for k in keys for l in files[k]['units'])} 条日志")
    L.append("")
    L.append("> 本目录**只收录 unit 1001 起的合成批次**；`dataset/data-901-910.txt` / `911-920` / `9101-9110` / `921-930.txt` "
             "是早期标注语料，不在本目录内。")
    L.append("")
    L.append("## 一、总览")
    L.append("")
    L.append("| 文件 | 分组 | unit 区间 | 组数 | 行数 | 形态 / 家族 |")
    L.append("|---|---|---|---|---|---|")
    for k in keys:
        us = sorted(l["unit"] for l in files[k]["units"])
        f0 = files[k]["file"] or "-"
        rows = sum(len(l["entries"]) for l in files[k]["units"])
        L.append(f"| `{f0}` | {FORM_MEAN.get(k, (k, ''))[0]} | {us[0]}~{us[-1]} | {len(us)} | {rows} | "
                 f"{FORM_MEAN.get(k, (k, k))[1]} |")
    L.append("")
    L.append("## 二、日志格式（与早期语料一致）")
    L.append("")
    L.append("```")
    L.append("1. `2026-06-21 07:34:46` **[waf]** `WAF0340624`")
    L.append("    `/api/v1/ping?cmd=127.0.0.1;id cmd=127.0.0.1;id Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/5`")
    L.append("```")
    L.append("")
    L.append("- 每组（unit）是一段攻击链，组内每条日志占 2 行：头部行 + 4 空格缩进的反引号包裹内容行；内容**硬截断到 110 字符**。")
    L.append("- 来源 5 种：`waf`（边缘 WAF）· `web`（Web 访问日志，与 waf 内容逐字相同）· `rasp`（应用运行时，含 `https://app-<栈>-<号>.ops-corp.com` 与 JSON 证据）· `hids`（主机侧）· `dns`（`<8位hex>.<C2基线域> A <IP>`）。")
    L.append("- 地址均为文档段/内网模拟段：`203.0.113.x` `192.0.2.x` `198.51.100.x` `10.10.x.x` `10.20.x.x`，无真实资产。")
    L.append("- 直接喂检索器：`python src/retrieve.py --chain dataset/incoming_logs_<区间>.txt`（扁平单行版同目录）。")
    L.append("")
    L.append("## 三、分组明细")
    for k in keys:
        meta = FORM_MEAN.get(k, (k, ""))
        us = sorted(files[k]["units"], key=lambda l: l["unit"])
        L.append("")
        L.append(f"### {meta[0]} · {meta[1]}（{us[0]['unit']}~{us[-1]['unit']}，{len(us)} 组，`{files[k]['file']}`）")
        L.append("")
        L.append(f"*{files[k]['batch']}*")
        L.append("")
        L.append("| unit | 来源序列（形态） | 行数 | 攻击手法 / 主题 |")
        L.append("|---|---|---|---|")
        for lab in us:
            seq = " → ".join(lab["source_sequence"])
            L.append(f"| {lab['unit']} | `{seq}` | {len(lab['entries'])} | {lab['technique']} |")
    L.append("")
    L.append("## 四、说明")
    L.append("")
    L.append("- unit 号 = 1000 + 组内序号；每个文件 20 组，文件名即 unit 区间。")
    L.append("- 第一批（1001~1080）用已有家族的手法扩展四种链形态；第二批（1081~1140）换攻击家族（勒索 / 域身份 / 供应链）。")
    L.append("- 合成数据的时间是模拟时间轴（第一批 2026-06、第二批 2026-07），`log_id` 五源各自递增并与早期语料续接（无重复）。")
    L.append("- 重新生成：`python dataset/gen/render_chains.py`、`python dataset/gen/render_families.py`、"
             "`python dataset/gen/make_catalog.py`（内容源：`dataset/gen/form1..7.json` + `SPEC.md`）。")
    L.append("")
    (out / args.name).write_text("\n".join(L), encoding="utf-8")
    print(f"已写出 {out / args.name}：{len(keys)} 个分组，"
          f"{sum(len(files[k]['units']) for k in keys)} 组，{len(L)} 行")
    for k in keys:
        us = files[k]["units"]
        print(f"   {FORM_MEAN.get(k,(k,''))[0]:8s} {us[0]['unit']}~{us[-1]['unit']}  {len(us):2d} 组  {files[k]['file']}")


if __name__ == "__main__":
    main()

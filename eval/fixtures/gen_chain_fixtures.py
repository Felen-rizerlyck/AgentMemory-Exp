#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""gen_chain_fixtures.py — 从 dataset/ 导出链级 fixture（扁平格式，证据可追溯）

产出（写入 eval/fixtures/）:
  chain_units_901910.txt       data-901-910 全部单元的扁平化（每行一条：ts [source] log_id content）
  chain_units_911920.txt       data-911-920 同上
  chain_units_91019110.txt     data-9101-9110 同上
  chain_demo_cross_source.txt  手工挑选的演示批（完整跨源链 + 前缀链 + 单例 + 噪声 + DNS 链）

用途: 链级装配/匹配的最小回归素材（见 tests/test_chain_integration.py）。
说明: dataset 原文件是 markdown 编号格式（带单元分组），链级入口只吃扁平批格式，
      故此处做一次确定性转换；单元边界（=现实"一次攻击的多行"）保留为时间上的自然分组。
用法: python eval/fixtures/gen_chain_fixtures.py
"""
import importlib.util
import pathlib
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
BASE = pathlib.Path(__file__).resolve().parent.parent.parent
OUT = pathlib.Path(__file__).resolve().parent

FILES = [("901910", "data-901-910.txt"), ("911920", "data-911-920.txt"),
         ("91019110", "data-9101-9110.txt")]

# 演示批：从数据集单元中挑选代表性片段（单元号, 行号列表）
DEMO_PICKS = [
    ("911-920", 2, [1, 2, 3]),        # 完整跨源链：waf+web+rasp 同请求（WebLogic ShellSession）
    ("911-920", 2, [4]),              # 噪声单例：HIDS 通用样板行（cat /etc/passwd 组合）
    ("901-910", 1, [1, 2]),           # 前缀链：waf+rasp 同请求（SQLi 认证绕过 + 批量赋值，缺后续）
    ("901-910", 1, [3]),              # 主机侧单例：SSH 横向（与上面不同链，实体/模板均不重叠）
    ("901-910", 1, [4, 5, 6]),        # DNS 信标链：同域族三次 DGA 查询
]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def flat(entries):
    return [f"{e['ts']} [{e['source']}] {e['log_id']} {e['content']}" for e in entries]


def main():
    rf = load(BASE / "history" / "old_eval" / "run_recall_full.py", "rf")
    written = []
    for tag, fn in FILES:
        units = rf.parse_file(BASE / "dataset" / fn)
        lines = [l for u in units for l in flat(u)]
        p = OUT / f"chain_units_{tag}.txt"
        p.write_text("\n".join(lines) + "\n", encoding="utf-8")
        written.append((p.name, len(units), len(lines)))

    demo = []
    for tag, ui, entries in DEMO_PICKS:
        units = rf.parse_file(BASE / "dataset" / f"data-{tag}.txt")
        unit = units[ui - 1]
        picked = [unit[i - 1] for i in entries]
        demo.extend(flat(picked))
        print(f"  [demo] data-{tag} unit{ui} 行{entries} → {[e['log_id'] for e in picked]}")
    p = OUT / "chain_demo_cross_source.txt"
    p.write_text("\n".join(demo) + "\n", encoding="utf-8")
    written.append((p.name, len(DEMO_PICKS), len(demo)))

    print("\n导出 fixture:")
    for name, nu, nl in written:
        print(f"  {name}: {'单元/pick'} {nu} · 行 {nl}")


if __name__ == "__main__":
    main()

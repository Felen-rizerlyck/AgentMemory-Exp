#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""案例记忆检索器（攻击检测 Agent 验证用）

用法:
    python src/retrieve.py "查询文本"          # 单条检索
    python src/retrieve.py --batch file.txt    # 每行一条，逐条检索
    （无参数时从 stdin 读取，整行逐条）

读取 data/memory_store.json，对每条案例做双通道打分:
  1. 词面通道: retrieval_keys(×3) / mitre(×2) / indicators(×2) / signature(×1)
  2. 模式通道: pattern_probes 正则命中 (每条 ×4)
输出按得分排序的候选案例 + 命中明细（可解释、可审计）。
"""
import json
import pathlib
import re
import sys

STORE_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "memory_store.json"


def load_store(path=STORE_PATH):
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return data.get("cases", [])


def _wordish(token):
    return re.compile(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])")


def _components(s):
    """从字符串中拆出 >=4 字符的英文/数字子令牌（忽略占位符片段）"""
    toks = re.findall(r"[A-Za-z0-9_./:@=\-]{4,}", s)
    return [t for t in toks if not t.startswith("<")]


def key_hits(key, ql):
    """返回 key 在查询文本中的命中片段列表（ql 需已小写）"""
    k = key.lower().strip()
    if not k:
        return []
    if "<" not in k:
        if _wordish(k).search(ql):
            return [k]
        if len(k) >= 5 and re.search(r"[^a-z ]", k) and k in ql:
            # 长键子串兜底：仅限含非纯字母字符的"结构化"键（载荷片段/URL/IP/参数，如 rO0AB 内嵌于 rO0ABXNy）；
            # 纯字母词组不走子串，避免 "net use" 命中 "net user" 类误报
            return [k]
        if not re.search(r"[a-z]", k):  # 纯中文键：直接子串包含
            return [k] if k in ql else []
    hits = []
    for t in _components(k):
        tl = t.lower()
        if len(tl) >= 6 and re.search(r"[^a-z0-9]", tl) and _wordish(tl).search(ql):
            hits.append(tl)
    return hits


def flatten_indicators(indicators):
    out = []
    for v in (indicators or {}).values():
        if isinstance(v, list):
            out.extend(str(x) for x in v)
        else:
            out.append(str(v))
    return out


def score_case(case, ql):
    detail, score, seen = [], 0, set()

    hits = {h for k in case.get("retrieval_keys", []) for h in key_hits(k, ql)} - seen
    if hits:
        score += 3 * len(hits)
        detail.append("keys×3: " + ",".join(sorted(hits)))
        seen |= hits

    hits = {t.lower() for t in case.get("mitre", []) if _wordish(t.lower()).search(ql)} - seen
    if hits:
        score += 2 * len(hits)
        detail.append("mitre×2: " + ",".join(hits))
        seen |= hits

    hits = {h for v in flatten_indicators(case.get("indicators", {})) for h in key_hits(v, ql)} - seen
    if hits:
        score += 2 * len(hits)
        detail.append("ind×2: " + ",".join(sorted(hits)))
        seen |= hits

    hits = set(key_hits(case.get("signature", ""), ql)) - seen
    if hits:
        score += 1 * len(hits)
        detail.append("sig×1: " + ",".join(sorted(hits)))

    for probe in case.get("pattern_probes", []):
        if re.search(probe, ql, re.I):
            score += 4
            detail.append("probe×4: " + probe)

    return score, detail


def retrieve(query, cases=None):
    ql = query.lower()
    results = []
    for case in (cases if cases is not None else load_store()):
        score, detail = score_case(case, ql)
        if score > 0:
            results.append((score, case.get("id", "?"), case.get("attack_type", ""), detail))
    results.sort(key=lambda x: (-x[0], x[1]))
    return results


def show(query, results):
    print("== 查询: " + query.strip()[:160])
    if not results:
        print("   无相似案例命中 → 按【新案例】处理")
        return
    for score, cid, atype, detail in results:
        tag = "强" if score >= 6 else ("中" if score >= 4 else "弱")
        print(f"   [{cid}] score={score}({tag}) {atype}")
        for line in detail:
            print("        -", line)


def main():
    args = sys.argv[1:]
    if not args:
        text = sys.stdin.read().strip()
        if not text:
            print(__doc__)
            return
        lines = text.splitlines()
    elif args[0] == "--batch":
        lines = pathlib.Path(args[1]).read_text(encoding="utf-8").splitlines()
    else:
        lines = [" ".join(args)]
    lines = [l for l in lines if l.strip()]
    for line in lines:
        show(line, retrieve(line))
        print()


if __name__ == "__main__":
    main()

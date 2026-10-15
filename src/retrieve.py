#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""动作匹配检索器 v2（攻击检测 Agent 验证用）

用法:
    python src/retrieve.py "查询文本"          # 单条检索
    python src/retrieve.py --batch file.txt    # 每行一条，逐条检索
    python src/retrieve.py --chain file.txt    # 链级：批内组装候选链 + 链整体匹配（行级降为分诊）
    （无参数时从 stdin 读取，整行逐条）

双通道机制（详见 主目录 GUIDE.md）:
  1. 动作通道（主，v2）: 动作库正则识别日志行中的动作 -> 反向索引取候选案例
     -> 案例动作序列位置对齐 -> 完整/前缀/中段/缺口匹配
     -> 输出匹配深度、预测下一步、分叉相似案例
  2. 关键词通道（辅，v1 保留）: retrieval_keys×3 / mitre×2 / indicators×2 / signature×1
     + pattern_probes×4（跨通道去重，与 v1 同口径），作召回兜底与并列排序参考

排序: 动作通道档位（强/中/弱）优先，同档按动作命中数、覆盖度、关键词分排序；
仅关键词命中的案例列于「关键词通道」兜底区。无任何实质命中 => 【新案例】。
"""
import json
import pathlib
import re
import sys

STORE_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "memory_store.json"

TIER_RANK = {"强": 3, "中": 2, "弱": 1}
_ACTION_RES = {}  # action_id -> compiled regex


def load_store(path=STORE_PATH):
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    return data.get("cases", []), data.get("action_library", {})


def _action_regex(lib, aid):
    # 缓存键含正则本身：换库（同 id 不同 regex）时不复用旧编译结果（进程内行为可预期）
    key = (aid, lib[aid]["regex"])
    if key not in _ACTION_RES:
        _ACTION_RES[key] = re.compile(lib[aid]["regex"], re.IGNORECASE)
    return _ACTION_RES[key]


# ---------------- 动作通道 ----------------

def match_actions(query, lib):
    """识别日志行中的动作，返回 [(action_id, label, 首次出现位置)]，按位置排序"""
    found = []
    for aid, a in lib.items():
        m = _action_regex(lib, aid).search(query)
        if m:
            found.append((aid, a.get("label", aid), m.start()))
    found.sort(key=lambda x: x[2])
    return found


def build_reverse_index(cases):
    """动作 -> 案例列表（反向索引）"""
    idx = {}
    for c in cases:
        for aid in c.get("action_sequence", []):
            idx.setdefault(aid, []).append(c["id"])
    return idx


def align_case(case, observed_ids):
    """观察到的动作集合在案例动作序列上的对齐。

    返回 dict: matched(案例位置列表) / mtype(完整|前缀|中段|缺口) / tier(强|中|弱)
      / longest_run / coverage / predict(下一动作 id) / before(前段未观察动作) / gaps(缺口动作)
    未命中返回 None。
    """
    seq = case.get("action_sequence", [])
    n = len(seq)
    if not n:
        return None
    obs = set(observed_ids)
    pos = [i for i, a in enumerate(seq) if a in obs]
    if not pos:
        return None
    matched = len(pos)
    contiguous = all(pos[i + 1] == pos[i] + 1 for i in range(len(pos) - 1))
    start0 = pos[0] == 0
    endfull = pos[-1] == n - 1
    if contiguous and start0 and endfull:
        mtype = "完整"
    elif contiguous and start0:
        mtype = "前缀"
    elif contiguous:
        mtype = "中段"
    else:
        mtype = "缺口"
    run = best = 1
    for i in range(1, len(pos)):
        run = run + 1 if pos[i] == pos[i - 1] + 1 else 1
        best = max(best, run)
    tier = "强" if mtype == "完整" else ("中" if matched >= 2 else "弱")
    predict = seq[pos[-1] + 1] if pos[-1] + 1 < n else None
    before = seq[:pos[0]]
    gaps = [seq[i] for i in range(pos[0], pos[-1] + 1) if i not in pos]
    return dict(matched=matched, total=n, coverage=matched / n, longest_run=best,
                mtype=mtype, tier=tier, positions=pos, predict=predict,
                before=before, gaps=gaps)


# ---------------- 关键词通道（v1 打分保留，跨通道去重版） ----------------

def _wordish(token):
    return re.compile(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])")


def _components(s):
    toks = re.findall(r"[A-Za-z0-9_./:@=\\-]{4,}", s)
    return [t for t in toks if not t.startswith("<")]


def key_hits(key, ql):
    k = key.lower().strip()
    if not k:
        return []
    if "<" not in k:
        if _wordish(k).search(ql):
            return [k]
        if len(k) >= 5 and re.search(r"[^a-z ]", k) and k in ql:
            return [k]
        if not re.search(r"[a-z]", k):
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


def keyword_score(case, ql):
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


# ---------------- 综合检索 ----------------

def retrieve(query, store=None):
    """返回 (action_hits, keyword_only, observed)

    action_hits: 动作通道命中案例，按档位/命中数/覆盖度/关键词分排序，元素 dict:
      {id, attack_type, mtype, tier, matched, total, coverage, predict, before, gaps,
       positions, kw_score, kw_detail}
    keyword_only: 无动作命中但关键词命中的案例 [(score, id, attack_type, detail)]（兜底区）
    observed: [(action_id, label, pos)] 识别到的动作
    """
    ql = query.lower()
    cases, lib = store if store is not None else load_store()
    observed = match_actions(query, lib)
    observed_ids = [a for a, _, _ in observed]
    hits, kw_only = [], []
    for case in cases:
        al = align_case(case, observed_ids)
        kw, kw_detail = keyword_score(case, ql)
        if al is None:
            if kw > 0:
                kw_only.append((kw, case.get("id", "?"), case.get("attack_type", ""), kw_detail))
            continue
        hits.append(dict(
            id=case.get("id", "?"), attack_type=case.get("attack_type", ""),
            mtype=al["mtype"], tier=al["tier"], matched=al["matched"], total=al["total"],
            coverage=al["coverage"], predict=al["predict"], before=al["before"],
            gaps=al["gaps"], positions=al["positions"],
            kw_score=kw, kw_detail=kw_detail, seq=case.get("action_sequence", []),
        ))
    hits.sort(key=lambda h: (-TIER_RANK[h["tier"]], -h["matched"], -h["kw_score"],
                             -h["coverage"], h["id"]))
    kw_only.sort(key=lambda x: (-x[0], x[1]))
    return hits, kw_only, observed


def _kw_band(score):
    return "强" if score >= 6 else ("中" if score >= 4 else "弱")


def _chain_marks(case, lib):
    """把案例动作序列渲染为 ①②③… 标注，观察重合/缺口"""
    marks = []
    for i, aid in enumerate(case["seq"], 1):
        hit = i - 1 in case["positions"]
        mark = "●" if hit else "○"
        marks.append(f"{mark}{i}.{lib.get(aid, {}).get('label', aid)}")
    return "  ".join(marks)


def show(query, store, results):
    cases, lib, (hits, kw_only, observed) = store[0], store[1], results
    observed_ids = {a for a, _, _ in observed}
    print("== 查询: " + query.strip()[:160])
    if observed:
        print("   [动作] 识别: " + " → ".join(f"{lbl}" for _, lbl, _ in observed))
    if not hits and not kw_only:
        print("   无相似案例命中 → 按【新案例】处理")
        return
    if hits:
        for h in hits:
            note = ""
            if h["mtype"] != "完整":
                if h["before"]:
                    note = "；前段未观察: " + "、".join(lib.get(a, {}).get("label", a) for a in h["before"])
                if h["gaps"]:
                    note += "；缺口(未观察): " + "、".join(lib.get(a, {}).get("label", a) for a in h["gaps"])
                if h["predict"]:
                    note += f"；预测下一步: {lib.get(h['predict'], {}).get('label', h['predict'])}"
            print(f"   [动作] [{h['id']}] {h['mtype']}匹配 {h['matched']}/{h['total']}（{h['tier']}）{h['attack_type']}")
            print("        - 链: " + _chain_marks(h, lib) + (note if note else " — 链完整重合"))
            if h["kw_score"] > 0:
                print(f"        - 关键词: score={h['kw_score']}({_kw_band(h['kw_score'])}) " +
                      "; ".join(h["kw_detail"]))
            forks = []
            for c2 in hits:
                if c2["id"] == h["id"]:
                    continue
                shared = [aid for aid in c2["seq"] if aid in observed_ids]
                if shared:
                    forks.append((c2["id"], shared))
            if forks:
                forks.sort(key=lambda f: -len(f[1]))
                shown = "、".join(
                    f"{cid}(共享:{'/'.join(lib.get(a, {}).get('label', a) for a in lbl[:2])})"
                    for cid, lbl in forks[:3])
                print(f"        - 分叉参考: {shown}")
    if kw_only:
        print("   [关键词兜底] 无动作命中，仅词面通道:")
        for score, cid, atype, detail in kw_only:
            print(f"     [{cid}] score={score}({_kw_band(score)}) {atype}")
            for line in detail:
                print("        -", line)


# ---------------- 链级匹配（多日志攻击链：加层，不改上面行级路径） ----------------
# 设计: docs/MULTI_LOG_CHAIN_DESIGN.md §6 — 链整体对齐（复用 align_case）+ 来源槽位校验
#       + 顺序一致性检查（行级 align_case 是集合语义，链级补顺序判定，不改既有函数）

_TIER_DOWN = {"强": "中", "中": "弱", "弱": "弱"}


def _case_sources(case):
    """案例每个动作位置的预期观测来源（缺省 any；长度不足按 any 补齐；裸字符串按单值处理）"""
    seq = case.get("action_sequence", [])
    srcs = case.get("action_sources") or []
    if isinstance(srcs, str):                      # 类型漂移：裸串按单值归一化（不按下标取字符）
        srcs = [srcs]
    return [(srcs[i] if i < len(srcs) and srcs[i] else "any") for i in range(len(seq))]


def _source_accepts(want, observed_sources):
    """来源槽位校验：any 跳过；列表任一命中即通过（列表内含 'any' 同样跳过）"""
    if not want or want == "any":
        return True
    wants = want if isinstance(want, list) else [want]
    if not wants or "any" in wants:
        return True
    return any(w in observed_sources for w in wants)


def _classify_positions(seq, positions):
    """按**位置集合**复算形态/档位/预测（规则与 align_case 一致）。

    链级必须用位置复算：align_case 是集合语义，若案例序列含重复动作 id，
    再次按 id 对齐会把"来源不符"的位置重新捞回（子代理审查发现 F1）。
    """
    n = len(seq)
    pos = list(positions)
    matched = len(pos)
    contiguous = all(pos[i + 1] == pos[i] + 1 for i in range(len(pos) - 1))
    start0, endfull = pos[0] == 0, pos[-1] == n - 1
    if contiguous and start0 and endfull:
        mtype = "完整"
    elif contiguous and start0:
        mtype = "前缀"
    elif contiguous:
        mtype = "中段"
    else:
        mtype = "缺口"
    run = best = 1
    for i in range(1, len(pos)):
        run = run + 1 if pos[i] == pos[i - 1] + 1 else 1
        best = max(best, run)
    tier = "强" if mtype == "完整" else ("中" if matched >= 2 else "弱")
    pset = set(pos)
    return dict(matched=matched, total=n, coverage=matched / n, longest_run=best, mtype=mtype,
                tier=tier, positions=pos,
                predict=(seq[pos[-1] + 1] if pos[-1] + 1 < n else None),
                before=seq[:pos[0]],
                gaps=[seq[i] for i in range(pos[0], pos[-1] + 1) if i not in pset])


def _fmt_src(v):
    if v in (None, "any"):
        return "any"
    return "|".join(v) if isinstance(v, list) else v


def chain_match(chain, cases, lib):
    """链整体对每个案例做对齐（复用 align_case）+ 来源槽位校验 + 顺序一致性。

    返回 matches（排序键：档位→命中数→关键词分→覆盖度→案例号），元素字段:
      {id, attack_type, seq, case_srcs, mtype, tier, matched, total, coverage, before, gaps,
       positions(案例位置), predict, predict_source, source_ok, source_mismatch, observed_src,
       order_ok, kw_score, kw_detail, evidence_lines, in_progress}
    """
    obs = chain["ordered_actions"]                        # [(action_id, source)] 时间序
    observed_ids = [a for a, _ in obs]
    obs_index = {}
    for ci, (aid, src) in enumerate(obs):
        obs_index.setdefault(aid, []).append((ci, src))
    out = []
    for case in cases:
        seq = case.get("action_sequence", [])
        al = align_case(case, observed_ids)                # 复用行级对齐
        if al is None:
            continue
        case_srcs = _case_sources(case)
        keep, mismatch = [], []
        for pos in al["positions"]:
            observed = {s for _, s in obs_index.get(seq[pos], [])}
            (keep if _source_accepts(case_srcs[pos], observed) else mismatch).append(pos)
        if not keep:
            continue                                       # 全部来源不符 → 不列为候选
        al2 = _classify_positions(seq, keep)               # 按位置复算形态/档位/预测（见函数说明）
        cpos = {p: min(ci for ci, _ in obs_index[seq[p]]) for p in keep}
        order = [cpos[p] for p in keep]
        order_ok = all(x <= y for x, y in zip(order, order[1:]))
        tier = al2["tier"] if order_ok else _TIER_DOWN[al2["tier"]]
        predict, predict_pos = al2["predict"], keep[-1] + 1
        kw, detail = 0, []
        for l in chain["lines"]:
            k, d = keyword_score(case, l["content"].lower())
            kw += k
            for x in d:
                if x not in detail:
                    detail.append(x)
        hit_ids = {seq[p] for p in keep}
        evidence = [l["log_id"] or f"L{i + 1}" for i, l in enumerate(chain["lines"])
                    if any(a["id"] in hit_ids for a in l["actions"])]
        out.append(dict(
            id=case.get("id", "?"), attack_type=case.get("attack_type", ""), seq=seq,
            case_srcs=case_srcs, mtype=al2["mtype"], tier=tier, matched=len(keep), total=len(seq),
            coverage=len(keep) / len(seq), before=al2["before"], gaps=al2["gaps"],
            positions=keep, source_ok=not mismatch, source_mismatch=mismatch,
            observed_src={p: sorted({s for _, s in obs_index[seq[p]]}) for p in keep + mismatch},
            order_ok=order_ok, predict=predict,
            predict_source=(case_srcs[predict_pos] if predict and predict_pos < len(seq) else None),
            kw_score=kw, kw_detail=detail, evidence_lines=evidence,
            in_progress=(al2["mtype"] != "完整"),
        ))
    out.sort(key=lambda h: (-TIER_RANK[h["tier"]], -h["matched"], -h["kw_score"],
                            -h["coverage"], h["id"]))
    return out


def _chain_line_marks(m, lib):
    """案例序列渲染：● 命中 / ◐ 来源不符 / ○ 未观察，附观测来源与预期来源"""
    parts = []
    for i, aid in enumerate(m["seq"], 1):
        lbl = lib.get(aid, {}).get("label", aid)
        want = _fmt_src(m["case_srcs"][i - 1])
        if i - 1 in m["positions"]:
            parts.append(f"●{i}.{lbl}[{'/'.join(m['observed_src'].get(i - 1, []))}]")
        elif i - 1 in m["source_mismatch"]:
            parts.append(f"◐{i}.{lbl}[预期 {want}｜观测 "
                         f"{'/'.join(m['observed_src'].get(i - 1, []))}]")
        else:
            parts.append(f"○{i}.{lbl}[预期 {want}]")
    return "  ".join(parts)


def show_chain(chain, store, top_n=3):
    """链级输出（设计文档 §6.4 格式 + §7 进行中语义 + 行级分诊并列）"""
    cases, lib = store
    print(f"== 链 {chain['chain_id']}（{len(chain['lines'])} 行证据，"
          f"{'→'.join(chain['sources'])}；{chain['link_basis']}/{chain['confidence']}）")
    for f in chain["flags"]:
        print("   ⚑ " + f)
    for l in chain["lines"]:
        acts = "、".join(a["label"] for a in l["actions"]) or "（无动作）"
        print(f"   · 行 {l['ts']} [{l['source']}] {l['log_id'] or '-'} | {acts}")
    matches = chain_match(chain, cases, lib)
    if not matches:
        print("   [链] 无相似案例命中 → 按【新链案例】处理")
    for m in matches[:top_n]:
        print(f"   [链] [{m['id']}] {m['mtype']}匹配 {m['matched']}/{m['total']}（{m['tier']}）"
              f"{m['attack_type']}")
        print("        - 已重合: " + _chain_line_marks(m, lib))
        if m["source_mismatch"]:
            print("        - 来源不符(◐): 该阶段疑似非本案证据，不计入匹配计数")
        if not m["order_ok"]:
            print("        - ⚠ 顺序异常: 链内时间序与案例序列相反（已降档），待确认")
        if m["predict"]:
            print(f"        - 预测下一步: {lib.get(m['predict'], {}).get('label', m['predict'])}"
                  f" [预期来源: {_fmt_src(m['predict_source'])}]")
        print("        - 证据行: " + ("、".join(m["evidence_lines"]) or "—"))
        if m["kw_score"] > 0:
            print(f"        - 关键词(链内合计): score={m['kw_score']}"
                  f"({_kw_band(m['kw_score'])}) " + "; ".join(m["kw_detail"][:3]))
    if matches and matches[0]["in_progress"]:
        ps = matches[0]["predict_source"]
        tip = (f"建议持续关注 / 拉取 [{_fmt_src(ps)}] 侧证据" if ps
               else "暂无明确下一步，建议各来源补证")
        print(f"   ⚠ 链未闭合（{matches[0]['mtype']}匹配）→ 攻击进行中：{tip}")
    triage = []
    for l in chain["lines"][:4]:
        hits, kw_only, _obs = retrieve(l["content"], store)
        if hits:
            triage.append(f"{l['log_id'] or '?'}→{hits[0]['id']}({hits[0]['tier']})")
        elif kw_only:
            triage.append(f"{l['log_id'] or '?'}→kw:{kw_only[0][1]}(弱)")
        else:
            triage.append(f"{l['log_id'] or '?'}→无")
    if triage:
        print("   [分诊·行级] " + " / ".join(triage))
    print()


def _load_chain_assembly():
    import importlib.util
    p = pathlib.Path(__file__).resolve().parent / "chain_assembly.py"
    spec = importlib.util.spec_from_file_location("chain_assembly", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def run_chain(lines, store, window_s=None):
    """批内组装候选链 → 逐链链级匹配输出（--chain 入口）"""
    kw = {} if window_s is None else {"window_s": window_s}
    chains = _load_chain_assembly().assemble_chains(lines, lib=store[1], matcher=match_actions, **kw)
    if not chains:
        print("（无可解析日志行）")
        return
    n_multi = sum(1 for c in chains if len(c["lines"]) > 1)
    print(f"# 链级分析：{len(chains)} 条候选链（多行链 {n_multi}），"
          f"组装仅做候选生成，链归属由 Agent 确认\n")
    for ch in chains:
        show_chain(ch, store)


def main():
    cases, lib = load_store()
    args = sys.argv[1:]
    if not args:
        text = sys.stdin.read().strip()
        if not text:
            print(__doc__)
            return
        lines = text.splitlines()
    elif args[0] == "--batch":
        lines = pathlib.Path(args[1]).read_text(encoding="utf-8").splitlines()
    elif args[0] == "--chain":
        # 链级入口：批内组装候选链 → 链整体匹配（行级结果降级为分诊提示）
        rest = args[1:]
        window = None
        if "--window" in rest:
            i = rest.index("--window")
            if i + 1 >= len(rest):
                print("用法: python src/retrieve.py --chain <日志文件> [--window <拆簇窗口秒数>]")
                return
            try:
                window = int(rest[i + 1])
            except ValueError:
                print(f"--window 需要整数秒数，收到: {rest[i + 1]!r}")
                return
            rest = rest[:i] + rest[i + 2:]
        if rest:
            lines = pathlib.Path(rest[0]).read_text(encoding="utf-8").splitlines()
        else:
            lines = sys.stdin.read().splitlines()
        run_chain(lines, (cases, lib), window_s=window)
        return
    else:
        lines = [" ".join(args)]
    lines = [l for l in lines if l.strip()]
    for line in lines:
        show(line, (cases, lib), retrieve(line, (cases, lib)))
        print()


if __name__ == "__main__":
    main()

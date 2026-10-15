#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""chain_assembly.py — 多日志攻击链「组装层」（v2 之上的加层，不改行级检索核心）

职责：把批内日志行聚成候选链（哪些行属于同一次攻击）。这是**机械确定性的候选生成**，
不是打分；链归属最终由 Agent 确认（与关系图"候选+人工确认"同哲学）。
链的整体匹配/预测见 src/retrieve.py 的 chain_match()。

组装信号（按可靠性排序，见 docs/MULTI_LOG_CHAIN_DESIGN.md §2/§5/§12）:
  1  会话/关联 ID      session_id / alert_id / rule_id 等键相同 → 确定性同簇（不被时间窗拆散）
  2  实体连续性        共享端点（IP / 完整主机名，去通用清单）→ 同簇
  2.5 同请求跨源并发    不同来源 + Δt ≤ CONCURRENT_LINK_S + 共享动作或 URI 路径相关
                       + 至少一侧有非通用动作 + 实体不冲突 → 中置信候选（补截断行造成的碎片）
  3  载荷模版跨层一致    共享非 generic 动作；跨源用宽窗、**同源仅紧邻窗**（弱证据，防同源噪声粘连）
  4  阶段顺序          组装后校验杀伤链阶段倒置（倒置 + 实体不同 → 切链；实体相同/会话直连 → 标记）
  5  时间窗            默认 3600s，仅作宽松簇跨度过滤，不可作主信号

确定性保证：所有排序键都是**与输入顺序无关**的完备键 (ts, source, log_id, content)；
不使用行下标作 tie-break；同输入（含乱序输入）→ 同输出。

用法:
    python src/chain_assembly.py data/incoming_logs.txt      # 打印候选链（调试视图）
    （无参数时从 stdin 读）

输入行格式（扁平批格式，与 data/incoming_logs.txt 一致）:
    <YYYY-MM-DD HH:MM:SS> [<source>] [<log_id>] <content>
    - source / log_id 均可缺省（缺失记 unknown / 空）；markdown 编号格式不支持（整行跳过）
"""
import json
import pathlib
import re
import sys
import time

BASE = pathlib.Path(__file__).resolve().parent.parent
STORE = BASE / "data" / "memory_store.json"

# ---------------- 参数（待真实数据校准，见设计文档 §11/§12.3） ----------------
WINDOW_S = 3600          # 宽松时间窗：簇跨度超此值 → 拆簇（会话键分量除外，见 assemble_chains）
CONCURRENT_S = 300       # 同事件多源观测窗：同一事件的多层观测不判阶段倒置
CONCURRENT_LINK_S = 30   # 同请求跨源**并链**窗（信号 2.5）；设 0 可关闭该信号
TEMPLATE_LINK_S = WINDOW_S       # 信号 3 跨源并链窗（与拆簇窗解耦，可单独调）
TEMPLATE_SAME_SRC_S = 300        # 信号 3 同源并链窗（同源模板重叠属弱证据，只在紧邻时间内承认）
STAGE_TOLERANCE = 2      # 阶段倒置容忍：阶段序号回退 ≥2 才算倒置（回退 1 视为自然交错）

# 杀伤链阶段顺序（None = 不参与顺序校验：侦察/发现类动作天然可出现在任意阶段）
STAGE_ORDER = {
    "recon": None,           # 侦察/发现：whoami、cmd=id 等，不参与顺序判定
    "initial_access": 1,
    "execution": 2,
    "privilege": 3,
    "persistence": 4,
    "lateral": 5,
    "c2": 6,
    "exfil": 7,
}

# 通用端点（loopback / 云元数据 / 样例域名）：不作实体连续性依据
GENERIC_ENTITIES = {
    "127.0.0.1", "0.0.0.0", "169.254.169.254", "localhost",
    "www.example.org", "example.com", "example.org", "metadata.google.internal",
}

LINE_RE = re.compile(
    r"^\s*(?:[*\-]\s*)?(?:(?P<n>\d+)\.\s*)?`?(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})`?\s*"
    r"(?:\[(?P<source>[A-Za-z][A-Za-z0-9_.\-]*)\]|\[\])?\s*"
    r"(?:\[(?P<log_id_b>[A-Z]{2,6}\d{4,})\]|(?P<log_id>[A-Z]{2,6}\d{4,}))?\s*"
    r"(?P<content>.*)$"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# 主机名：TLD 清单可扩（默认含常见内网后缀）；.io/.corp/.lan 等内网资产名同样视为实体
HOST_TLDS = ("com", "net", "org", "io", "co", "internal", "local", "corp", "lan", "intranet", "cn")
HOST_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:" + "|".join(HOST_TLDS) + r")\b", re.I)
# 系统路径前缀（按路径段匹配，避免 /binfoo 被误当 /bin）
SYS_PATH_PREFIX = ("/bin", "/etc", "/dev", "/tmp", "/usr", "/var", "/opt", "/proc", "/sys")
PATH_RE = re.compile(r"(?<![\w])(/[A-Za-z0-9_\-][A-Za-z0-9_\-./]{2,})")   # URI 路径 token（同请求的强指示）
SESSION_RES = [
    re.compile(r"session[_-]?id[\"'=:\s]+([A-Za-z0-9_.:\-]{2,})(?![A-Za-z0-9_.:\-])", re.I),
    re.compile(r"\bsid[\"'=:\s]+([A-Za-z0-9_.:\-]{2,})(?![A-Za-z0-9_.:\-])", re.I),
    re.compile(r"alert[_-]?id[\"'=:\s]+([A-Za-z0-9_.:\-]{2,})(?![A-Za-z0-9_.:\-])", re.I),
    re.compile(r"rule[_-]?id[\"'=:\s]+([A-Za-z0-9_.:\-]{2,})(?![A-Za-z0-9_.:\-])", re.I),
]


def sort_key(row):
    """确定性完备排序键（与输入顺序无关）"""
    return (row["ts_epoch"], row["source"], row["log_id"], row["content"])


# ---------------- Step 1 行解析 ----------------

def parse_log_line(line, idx=0):
    """单行 → {ts, ts_epoch, source, log_id, content, session_key, entities, paths, actions}
    无法解析（空行/非日志行/markdown 编号行）返回 None，外层跳过。actions 由 matcher 填。
    """
    line = line.rstrip("\n").rstrip()
    if not line.strip():
        return None
    m = LINE_RE.match(line)
    if not m:
        return None
    tail = line[m.end("ts"):].lstrip("` ").lstrip()
    if tail[:1] in ("`", "*"):        # markdown 编号格式（`ts` **[src]** `id`）不支持：整行跳过
        return None
    ts = m.group("ts").replace("T", " ")
    try:
        epoch = int(time.mktime(time.strptime(ts, "%Y-%m-%d %H:%M:%S")))
    except ValueError:
        return None
    content = (m.group("content") or "").strip()
    source = (m.group("source") or "unknown").lower()
    log_id = m.group("log_id_b") or m.group("log_id") or ""
    return dict(idx=idx, ts=ts, ts_epoch=epoch, source=source, log_id=log_id, content=content,
                session_key=_session_key(content), entities=_entities(content), paths=_paths(content),
                actions=[])


def _session_key(content):
    for r in SESSION_RES:
        m = r.search(content)
        if m:
            return m.group(1).lower()
    return None


def _entities(content):
    """端点 token（IP / 完整主机名），去通用清单；用于实体连续性判定。"""
    out = set()
    for m in IP_RE.finditer(content):
        tok = m.group(0)
        if tok not in GENERIC_ENTITIES:
            out.add(tok)
    for m in HOST_RE.finditer(content):
        tok = m.group(0).lower()
        if tok not in GENERIC_ENTITIES:
            out.add(tok)
    return out


def _is_sys_path(p):
    """系统路径判定（按路径段，避免 /binfoo /varnish 之类被误排除）"""
    for pre in SYS_PATH_PREFIX:
        if p == pre or p.startswith(pre + "/"):
            return True
    return False


def _paths(content):
    """URI 路径 token（去系统路径：/bin /etc /dev /tmp /usr /var /opt /proc /sys 不作判别性依据）"""
    out = set()
    for p in PATH_RE.findall(content):
        if _is_sys_path(p):
            continue
        out.add(p.rstrip("/"))
    return out


def _norm_path(p):
    """规范化路径：去掉 URL 解析残留的主机名首段（/app-x.ops-corp.com/api/v1 → /api/v1）"""
    parts = p.split("/")
    if len(parts) > 2 and "." in parts[1]:
        return "/" + "/".join(parts[2:])
    return p


def _paths_related(pa, pb):
    """路径相关：规范化后**相等**（同请求在不同层的两种 URL 形态；不做任意后缀匹配，
    避免 /a/b/users 与 /admin/x/a/b/users 这类无关请求被拼链）"""
    return bool({_norm_path(p) for p in pa} & {_norm_path(q) for q in pb})


# ---------------- 动作识别（默认复用 retrieve.match_actions） ----------------

def _load_retrieve():
    """复用行级检索器的动作识别（避免重复正则实现）；__main__ 复用同一实例。"""
    mod = sys.modules.get("__main__")
    if mod is not None and pathlib.Path(getattr(mod, "__file__", "") or "").name == "retrieve.py" \
            and hasattr(mod, "match_actions"):
        return mod
    import importlib.util
    spec = importlib.util.spec_from_file_location("retrieve_v2", BASE / "src" / "retrieve.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def load_library():
    data = json.loads(STORE.read_text(encoding="utf-8"))
    return data.get("action_library", {}), data.get("cases", [])


# ---------------- Step 2-5 聚类 ----------------

class _UF:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[max(ra, rb)] = min(ra, rb)
            return True
        return False


def _group_merge_pairs(rows, keyfn, pair_ok=None):
    """按 keyfn(line) 收集键 → 键内按时间序**相邻**配对（pair_ok 决定该对是否并）。
    返回 [(idx, idx, 键)]。排序键与输入顺序无关（sort_key）。
    """
    buckets = {}
    for r in rows:
        for k in keyfn(r):
            buckets.setdefault(k, []).append(r)
    pairs = []
    for k in sorted(buckets):
        grp = sorted(buckets[k], key=sort_key)
        for i in range(len(grp) - 1):
            if pair_ok is not None and not pair_ok(grp[i], grp[i + 1]):
                continue
            pairs.append((grp[i]["idx"], grp[i + 1]["idx"], k))
    return pairs


def _template_pair_ok(ra, rb, link_s, same_src_s):
    """信号 3 配对判据：跨源用宽窗；同源只在紧邻窗内承认（同源模板重叠是弱证据，防噪声粘连）"""
    dt = rb["ts_epoch"] - ra["ts_epoch"]
    if ra["source"] == rb["source"]:
        return dt <= same_src_s
    return dt <= link_s


def _concurrent_pairs(rows, window_s=CONCURRENT_LINK_S):
    """信号 2.5「同请求跨源并发」：**窗内滑窗两两配对**（不只看相邻行，中间夹噪声行也不失效）。

    判据：不同来源 + Δt ≤ window_s + 共享至少一个动作 id **或** URI 路径相关
    + 至少一侧含非通用动作 + 实体不冲突（两端各有实体时须有交集）。
    依据：同一请求被多层同时捕获时，某一层载荷常被截断而只剩通用探针（信号 3 失效 → 碎片化）。
    结果只作**候选**（中置信，Agent 可拆）。
    """
    if window_s <= 0:
        return []
    order = sorted(range(len(rows)), key=lambda i: sort_key(rows[i]))
    pairs = []
    for x in range(len(order)):
        a = order[x]
        ra = rows[a]
        for y in range(x + 1, len(order)):
            b = order[y]
            rb = rows[b]
            if rb["ts_epoch"] - ra["ts_epoch"] > window_s:
                break                                  # 时间序：后续行更远，跳出本行扫描
            if ra["source"] == rb["source"]:
                continue
            sa = {k["id"] for k in ra["actions"]}
            sb = {k["id"] for k in rb["actions"]}
            if not ((sa & sb) or _paths_related(ra["paths"], rb["paths"])):
                continue
            if not {k["id"] for k in ra["actions"] if not k["generic"]} \
                    and not {k["id"] for k in rb["actions"] if not k["generic"]}:
                continue                               # 两侧都只有通用探针 → 不足以并链
            ea, eb = ra["entities"], rb["entities"]
            if ea and eb and not (ea & eb):
                continue
            pairs.append((min(a, b), max(a, b), "concurrent"))
    return pairs


def _split_by_window(idxs, rows, span_limit=WINDOW_S):
    """Step 3 窗口过滤（单趟线性扫描，O(n log n)）：按时间序闭块，
    块内跨度（首行到当前行）将超 span_limit 时切块。确定性、与输入顺序无关。
    """
    ordered = sorted(idxs, key=lambda i: sort_key(rows[i]))
    out, cur = [], []
    for i in ordered:
        if cur and (rows[i]["ts_epoch"] - rows[cur[0]]["ts_epoch"]) > span_limit:
            out.append(cur)
            cur = []
        cur.append(i)
    if cur:
        out.append(cur)
    return out


def _line_stage(line, lib):
    """行阶段 = 行内**最深**（阶段序最大）的有效动作阶段；无 → None。

    取最深而非最后一个：一条日志行常同时暴露同一请求的多个阶段（如 waf 行同时含
    写入 crontab 与反连命令），行阶段应表达"该行证据已推进到哪"。侦察类（None）不参与。
    """
    best, best_rank = None, -1
    for a in line["actions"]:
        s = a.get("stage")
        s = s.strip() if isinstance(s, str) else None
        if not s:
            continue
        rank = STAGE_ORDER.get(s)
        if rank is not None and rank > best_rank:
            best, best_rank = s, rank
    return best


def _unknown_stages(line):
    """行内出现但不在 STAGE_ORDER 里的阶段取值（类型/取值异常时给链级提示，不静默）"""
    out = set()
    for a in line["actions"]:
        s = a.get("stage")
        if isinstance(s, str) and s.strip() and s.strip() not in STAGE_ORDER:
            out.add(s.strip())
    return out


def _stage_check(grp, rows, lib, tolerance=STAGE_TOLERANCE, concurrent_s=CONCURRENT_S):
    """Step 5 阶段校验。返回 (切分点列表, flags)。

    切分点/标记判据（相邻行对比较）：
      · 阶段回退 ≥ tolerance，且
          - 实体不同、且两侧非同一会话直连 → **切链**；
          - 实体相同 → 标记"待确认"（不切）；
          - 两侧同一会话键直连 → 标记"待确认"（不切，会话为确定性分组）；
          - 与"当前最高阶段来源行"时间差 ≤ concurrent_s（同一事件的多源观测）→ 跳过判定。
    返回的 cut 项带触发行，便于把 flag 挂到对应的子链（不复制给所有子链）。
    """
    stages = [(i, _line_stage(rows[i], lib)) for i in grp]
    cuts, flags, maxrank, max_src, max_stage = [], [], None, None, None
    for k, (i, s) in enumerate(stages):
        if s is None:
            continue
        rank = STAGE_ORDER[s]
        prev = stages[k - 1][0] if k > 0 else None
        dt_ref = (rows[i]["ts_epoch"] - rows[max_src]["ts_epoch"]) if max_src is not None else None
        concurrent = dt_ref is not None and dt_ref <= concurrent_s
        if maxrank is not None and rank <= maxrank - tolerance and not concurrent:
            same_entity = bool(rows[prev]["entities"] & rows[i]["entities"]) if prev is not None else False
            same_session = bool(prev is not None and rows[prev]["session_key"]
                                and rows[prev]["session_key"] == rows[i]["session_key"])
            label = rows[i]["log_id"] or f"行{i + 1}"
            ref = f"前序已达 {max_stage}（行{rows[max_src]['log_id'] or max_src + 1}）"
            if same_entity or same_session:
                why = "实体相同" if same_entity else "同一会话键"
                flags.append((i, f"顺序异常待确认: 行{label} 阶段 {s} 回退（{ref}，{why}，不切链）"))
            else:
                cuts.append({"k": k, "idx": i,
                             "flag": f"阶段倒置切链: 行{label} 阶段 {s} 回退（{ref}，实体不同）"})
                maxrank, max_src, max_stage = rank, i, s
                continue
        if maxrank is None or rank > maxrank:
            maxrank, max_src, max_stage = rank, i, s
    return cuts, flags


def assemble_chains(lines, lib=None, matcher=None, window_s=WINDOW_S, stage_tolerance=STAGE_TOLERANCE,
                    concurrent_window=CONCURRENT_LINK_S, template_link_s=TEMPLATE_LINK_S,
                    template_same_src_s=TEMPLATE_SAME_SRC_S, stats=None):
    """批内日志行 → 候选链列表（确定性：输入乱序结果一致）。

    lines: 原始行字符串列表
    lib:   action_library（None → 读 data/memory_store.json）
    matcher: 动作识别函数 (content, lib) -> [(action_id, label, pos)]（None → retrieve.match_actions）
    concurrent_window: 信号 2.5 并链窗（秒；0 = 关闭）
    template_link_s / template_same_src_s: 信号 3 跨源/同源并链窗
    stats: 可选 dict，回填 {'total': 输入行数, 'parsed': 解析成功行数}
    返回 [{chain_id, lines, ordered_actions, sources, entities, link_basis, confidence, flags}]
    """
    if matcher is None:
        matcher = _load_retrieve().match_actions
    if lib is None:
        lib, _ = load_library()

    # Step 1 行解析 + 动作识别
    rows = []
    for ln in lines:
        r = parse_log_line(ln, idx=len(rows))
        if r is None:
            continue
        found = matcher(r["content"], lib)
        r["actions"] = [dict(id=aid, label=lbl, pos=pos,
                             generic=bool((lib.get(aid) or {}).get("generic")),
                             stage=(lib.get(aid) or {}).get("stage"))
                        for aid, lbl, pos in found]
        rows.append(r)
    if stats is not None:
        stats["total"] = len(lines)
        stats["parsed"] = len(rows)
    if not rows:
        return []

    uf = _UF(len(rows))
    basis = {}                                     # 行 idx -> 最高优先级信号
    _SIGNAL_RANK = {"session": 4, "entity": 3, "concurrent": 2, "template": 1}

    def _mark(pairs, tag):
        for a, b, _k in pairs:
            if uf.union(a, b):
                for x in (a, b):
                    if _SIGNAL_RANK[tag] > _SIGNAL_RANK.get(basis.get(x, ""), 0):
                        basis[x] = tag

    # Step 2a 会话键（最强，确定性分组）
    _mark(_group_merge_pairs(rows, lambda r: [r["session_key"]] if r["session_key"] else []), "session")
    # Step 2b 实体连续性（共享端点 token；时间跨度由 Step 3 窗口过滤兜底）
    _mark(_group_merge_pairs(rows, lambda r: sorted(r["entities"])), "entity")
    # Step 2b' 同请求跨源并发（信号 2.5；concurrent_window=0 关闭）
    _mark(_concurrent_pairs(rows, concurrent_window), "concurrent")
    # Step 2c 载荷模版（仅非 generic 动作；跨源宽窗 / 同源紧邻窗）
    _mark(_group_merge_pairs(rows, lambda r: sorted({a["id"] for a in r["actions"] if not a["generic"]}),
                             pair_ok=lambda ra, rb: _template_pair_ok(ra, rb, template_link_s,
                                                                      template_same_src_s)), "template")

    groups = {}
    for r in rows:
        groups.setdefault(uf.find(r["idx"]), []).append(r["idx"])

    # Step 3 窗口过滤（会话键分量不拆：会话是确定性分组，跨窗只标记）+ Step 5 阶段校验
    clusters = []
    for _root, idxs in sorted(groups.items()):
        extra = []
        if any(basis.get(i) == "session" for i in idxs):
            grps = [sorted(idxs, key=lambda i: sort_key(rows[i]))]
            span = rows[grps[0][-1]]["ts_epoch"] - rows[grps[0][0]]["ts_epoch"]
            if span > window_s:
                extra.append(f"会话键分量跨窗（跨度 {span}s > {window_s}s）→ 按分组保留，待确认")
        else:
            grps = _split_by_window(idxs, rows, window_s)
        for grp in grps:
            cuts, flags = _stage_check(grp, rows, lib, stage_tolerance)
            if not cuts:
                clusters.append((grp, [t for _i, t in flags] + extra))
                continue
            # 切链：flag 只挂到**触发行所在的那条子链**（不复制给所有子链）
            subs, prev = [], 0
            for c in cuts:
                subs.append(grp[prev:c["k"]])
                prev = c["k"]
            subs.append(grp[prev:])
            for members in subs:
                mset = set(members)
                own = [t for i2, t in flags if i2 in mset]
                own += [c["flag"] for c in cuts if c["idx"] in mset]
                clusters.append((members, own + extra))

    # Step 4 排序（按簇内最早行的确定性完备键；members 已按 sort_key 有序）+ 链对象
    clusters.sort(key=lambda c: sort_key(rows[c[0][0]]))
    chains = []
    for n, (grp, flag_list) in enumerate(clusters, 1):
        grp = sorted(grp, key=lambda i: sort_key(rows[i]))
        line_objs = [dict(ts=rows[i]["ts"], source=rows[i]["source"], log_id=rows[i]["log_id"],
                          content=rows[i]["content"], entities=sorted(rows[i]["entities"]),
                          actions=[{k: a[k] for k in ("id", "label", "stage", "generic")}
                                   for a in rows[i]["actions"]]) for i in grp]
        ordered = [(a["id"], rows[i]["source"]) for i in grp for a in rows[i]["actions"]]
        sources, seen = [], set()
        for l in line_objs:
            if l["source"] not in seen:
                seen.add(l["source"])
                sources.append(l["source"])
        tags = {basis.get(i, "singleton") for i in grp}
        if len(grp) > 1:
            link = next((t for t in ("session", "entity", "concurrent", "template") if t in tags),
                        "singleton")
        else:
            link = "singleton"                     # 单行链不宣称"高置信实体链"（可能是窗口拆出的碎片）
        conf = {"session": "高", "entity": "高", "concurrent": "中",
                "template": "低", "singleton": "低"}[link]
        flags = list(flag_list)
        if len(grp) == 1 and tags != {"singleton"}:
            flags.append("单行链（原分量连接依据: " + "/".join(sorted(t for t in tags if t != "singleton"))
                         + "，已按时间窗/阶段切分）→ 待确认")
        if link == "concurrent":
            flags.append(f"同请求跨源并发拼接（Δt≤{concurrent_window}s 且各层均见攻击动作）→ 待确认")
        if link == "template":
            hits = sorted({a["id"] for i in grp for a in rows[i]["actions"] if not a["generic"]})
            flags.append("低置信拼接（模板重叠: " + "/".join(hits[:4]) + "）→ 待确认")
        if len(grp) > 1 and not any(l["actions"] for l in line_objs):
            flags.append("簇内无动作识别行 → 仅时间/实体拼接")
        unknown = sorted({s for i in grp for s in _unknown_stages(rows[i])})
        if unknown:
            flags.append("含未知阶段标注已忽略: " + "/".join(unknown) + "（检查动作库 stage 取值）")
        chains.append(dict(
            chain_id=f"CHAIN-{n:02d}",
            lines=line_objs,
            ordered_actions=ordered,
            sources=sources,
            entities=sorted({e for i in grp for e in rows[i]["entities"]}),
            link_basis=link,
            confidence=conf,
            flags=flags,
            window_s=window_s,
        ))
    return chains


# ---------------- CLI（调试视图；正式输出走 retrieve.py --chain） ----------------

def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = sys.argv[1:]
    if args and not args[0].startswith("-"):
        raw = pathlib.Path(args[0]).read_text(encoding="utf-8").splitlines()
    else:
        raw = sys.stdin.read().splitlines()
    stats = {}
    chains = assemble_chains(raw, stats=stats)
    if not chains:
        print(f"（无可解析日志行：{stats.get('parsed', 0)}/{stats.get('total', len(raw))} 行解析成功）")
        return
    for ch in chains:
        srcs = "→".join(ch["sources"])
        print(f"== {ch['chain_id']}（{len(ch['lines'])} 行，{srcs}；{ch['link_basis']}/{ch['confidence']}）")
        for l in ch["lines"]:
            acts = "、".join(a["label"] for a in l["actions"]) or "（无动作）"
            print(f"   - {l['ts']} [{l['source']}] {l['log_id'] or '-'} | {acts}")
        for f in ch["flags"]:
            print(f"   ⚑ {f}")
    print(f"\n共 {len(chains)} 条候选链（{len([c for c in chains if len(c['lines']) > 1])} 条多行链）；"
          f"解析 {stats.get('parsed', 0)}/{stats.get('total', len(raw))} 行")


if __name__ == "__main__":
    main()

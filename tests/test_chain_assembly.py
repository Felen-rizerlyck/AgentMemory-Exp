#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""tests/test_chain_assembly.py — 组装层单测（M1，stdlib unittest，零依赖）

覆盖 docs/MULTI_LOG_CHAIN_DESIGN.md §5 Step 1-5 与确定性保证：
  Step1 行解析 / Step2 键聚类（会话·实体·模板）/ Step3 窗口过滤 / Step4 排序 /
  Step5 阶段校验 / 确定性（同输入同输出、输入乱序结果一致）

运行: python tests/test_chain_assembly.py        （或 python -m unittest discover tests）
本文件使用自造动作库（hermetic）：不依赖 data/memory_store.json 的具体内容。
"""
import json
import pathlib
import random
import re
import sys
import unittest

BASE = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "src"))
import chain_assembly as ca  # noqa: E402

# ---------------- 自造动作库（regex / generic / stage 三要素） ----------------
LIB = {
    "t_recon":   {"label": "whoami 侦察", "regex": r"\bwhoami\b", "generic": True,  "stage": "recon"},
    "t_exec":    {"label": "共享执行模板", "regex": r"SHAREDTOK",  "generic": False, "stage": "execution"},
    "t_persist": {"label": "创建后门账户", "regex": r"net\s+user\s+/add", "generic": False, "stage": "persistence"},
    "t_early":   {"label": "恒真注入", "regex": r"EARLYTOK", "generic": False, "stage": "initial_access"},
    "t_lat":     {"label": "横向移动", "regex": r"LATOK",   "generic": False, "stage": "lateral"},
    "t_late":    {"label": "凭据外传", "regex": r"EXFILTOK", "generic": False, "stage": "exfil"},
}
_RES_CACHE = {}


def matcher(content, lib):
    """按**传入的 lib** 编译/匹配（镜像 retrieve.match_actions 语义，测试可临时扩库）"""
    out = []
    for aid, a in lib.items():
        r = _RES_CACHE.get(aid)
        if r is None or r.pattern != a["regex"]:
            r = _RES_CACHE[aid] = re.compile(a["regex"], re.I)
        m = r.search(content)
        if m:
            out.append((aid, a.get("label", aid), m.start()))
    out.sort(key=lambda x: x[2])
    return out


def L(ts, source, log_id, content):
    """构造扁平格式日志行：<ts> [<source>] <log_id> <content>（log_id 形如 WAF0001）"""
    return f"2026-06-02 {ts} [{source}] {log_id} {content}"


def run(lines, **kw):
    return ca.assemble_chains(lines, lib=LIB, matcher=matcher, **kw)


def _paths_of_line(content):
    """构造一行并取出其 URI 路径 token（供路径判定测试用）"""
    return ca.parse_log_line(L("09:00:00", "waf", "WAF0001", content))["paths"]


def _epoch(ts):
    import time as _t
    return int(_t.mktime(_t.strptime(ts, "%Y-%m-%d %H:%M:%S")))


class TestStep1Parse(unittest.TestCase):
    def test_parse_variants(self):
        r = ca.parse_log_line(L("09:00:00", "waf", "WAF0001234", "/a?x=1"))
        self.assertEqual((r["source"], r["log_id"], r["content"]),
                         ("waf", "WAF0001234", "/a?x=1"))
        r2 = ca.parse_log_line(L("09:12:05", "dns", "", "3fa2b9c1.xkqwvp-9d2f.net A 203.0.113.77"))
        self.assertEqual(r2["log_id"], "")
        self.assertEqual(r2["content"], "3fa2b9c1.xkqwvp-9d2f.net A 203.0.113.77")

    def test_parse_rejects_non_log_lines(self):
        for bad in ("", "   ", "1. `2026-05-08 02:07:56` **[waf]** `WAF0048744`", "just text"):
            self.assertIsNone(ca.parse_log_line(bad), bad)

    def test_entities_and_session(self):
        r = ca.parse_log_line(L("09:00:00", "waf", "WAF0001",
                                "POST /x host=app-nginx-9.ops-corp.com ip=10.20.7.9"))
        self.assertIn("app-nginx-9.ops-corp.com", r["entities"])
        self.assertIn("10.20.7.9", r["entities"])
        g = ca.parse_log_line(L("09:00:00", "waf", "WAF0002",
                                "cmd=id target=127.0.0.1 meta=169.254.169.254"))
        self.assertNotIn("127.0.0.1", g["entities"])
        self.assertNotIn("169.254.169.254", g["entities"])
        s = ca.parse_log_line(L("09:00:00", "rasp", "RASP0001", 'session_id=sess1 {"cmd":"id"}'))
        self.assertEqual(s["session_key"], "sess1")

    def test_actions_annotated_with_stage_and_generic(self):
        ch = run([L("09:00:00", "hids", "HID0001", "SHAREDTOK && net user /add bob")])[0]
        acts = ch["lines"][0]["actions"]
        self.assertEqual([a["id"] for a in acts], ["t_exec", "t_persist"])
        self.assertEqual([a["stage"] for a in acts], ["execution", "persistence"])
        self.assertFalse(acts[0]["generic"])


class TestStep2Clustering(unittest.TestCase):
    def test_session_key_is_decisive(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "session_id=sess1 /a?x=1"),
                  L("09:00:01", "rasp", "RASP0001", "session_id=sess1 /b?y=2")])
        self.assertEqual(len(ch), 1)
        self.assertEqual(ch[0]["link_basis"], "session")
        self.assertEqual(ch[0]["confidence"], "高")

    def test_entity_continuity_merges(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "POST /x dst=10.20.7.9"),
                  L("09:01:00", "hids", "HID0001", "curl http://10.20.7.9/a.sh")])
        self.assertEqual(len(ch), 1)
        self.assertEqual(ch[0]["link_basis"], "entity")

    def test_generic_entity_does_not_merge(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "cmd=id dst=127.0.0.1"),
                  L("09:00:01", "hids", "HID0001", "cmd=id dst=127.0.0.1")])
        self.assertEqual(len(ch), 2)

    def test_template_overlap_merges_low_confidence(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "SHAREDTOK /a"),
                  L("09:01:30", "hids", "HID0001", "SHAREDTOK /b")])
        self.assertEqual(len(ch), 1)
        self.assertEqual(ch[0]["link_basis"], "template")
        self.assertEqual(ch[0]["confidence"], "低")
        self.assertTrue(any("低置信拼接" in f for f in ch[0]["flags"]))

    def test_generic_probe_alone_does_not_merge(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "whoami /a dst=10.0.0.1"),
                  L("09:00:05", "hids", "HID0001", "whoami /b dst=10.0.0.2")])
        self.assertEqual(len(ch), 2)


class TestStep3Window(unittest.TestCase):
    def test_span_over_window_splits(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "SHAREDTOK dst=10.0.0.5"),
                  L("10:10:00", "hids", "HID0001", "SHAREDTOK dst=10.0.0.5")])  # 间隔 4200s > 3600s
        self.assertEqual(len(ch), 2)
        self.assertEqual([c["lines"][0]["log_id"] for c in ch], ["WAF0001", "HID0001"])

    def test_within_window_kept(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "SHAREDTOK dst=10.0.0.5"),
                  L("09:30:00", "hids", "HID0001", "SHAREDTOK dst=10.0.0.5")])
        self.assertEqual(len(ch), 1)

    def test_window_param_configurable(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "SHAREDTOK dst=10.0.0.5"),
                  L("09:30:00", "hids", "HID0001", "SHAREDTOK dst=10.0.0.5")], window_s=600)
        self.assertEqual(len(ch), 2)


class TestStep4Ordering(unittest.TestCase):
    def test_lines_and_actions_sorted_by_time(self):
        ch = run([L("09:05:00", "hids", "HID0002", "SHAREDTOK"),
                  L("09:00:00", "waf", "WAF0001", "SHAREDTOK")])
        self.assertEqual([l["log_id"] for l in ch[0]["lines"]], ["WAF0001", "HID0002"])
        self.assertEqual([s for _, s in ch[0]["ordered_actions"]], ["waf", "hids"])
        self.assertEqual(ch[0]["sources"], ["waf", "hids"])


class TestStep5Stage(unittest.TestCase):
    # 行阶段 = 行内最深阶段：EXFILTOK=exfil(7) / LATOK=lateral(5) / net user /add=persistence(4)
    #                        / SHAREDTOK=execution(2) / EARLYTOK=initial_access(1)
    def test_stage_inversion_cuts_chain(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "SHAREDTOK && EXFILTOK"),
                  L("09:30:00", "hids", "HID0001", "SHAREDTOK && EARLYTOK")])  # 回退 5 档，实体不同
        self.assertEqual(len(ch), 2)
        # flag 只挂到**切出点所在的那条子链**（改进项：以前会复制给所有子链）
        self.assertFalse(any("阶段倒置切链" in f for f in ch[0]["flags"]))
        self.assertTrue(any("阶段倒置切链" in f for f in ch[1]["flags"]))
        self.assertIn("HID0001", ch[1]["flags"][0])

    def test_stage_inversion_same_entity_flagged_not_cut(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "SHAREDTOK && EXFILTOK dst=10.1.1.1"),
                  L("09:30:00", "hids", "HID0001", "SHAREDTOK && EARLYTOK dst=10.1.1.1")])
        self.assertEqual(len(ch), 1)
        self.assertTrue(any("顺序异常待确认" in f for f in ch[0]["flags"]))

    def test_stage_inversion_session_group_not_cut(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "session_id=sess9 SHAREDTOK && EXFILTOK"),
                  L("09:30:00", "hids", "HID0001", "session_id=sess9 SHAREDTOK && EARLYTOK")])
        self.assertEqual(len(ch), 1)
        self.assertTrue(any("同一会话键" in f for f in ch[0]["flags"]))

    def test_concurrent_multi_source_not_flagged(self):
        # 同请求被两层同时捕获（间隔 2s）：阶段差异只是各层侧面不同，不判倒置
        ch = run([L("09:00:00", "waf", "WAF0001", "SHAREDTOK && EXFILTOK"),
                  L("09:00:02", "rasp", "RASP0001", "SHAREDTOK && EARLYTOK")])
        self.assertEqual(len(ch), 1)
        self.assertFalse(any(("倒置切链" in f) or ("顺序异常" in f) for f in ch[0]["flags"]))

    def test_small_backstep_tolerated(self):
        # 回退 1 档（lateral → persistence 视为自然交错）不触发倒置
        ch = run([L("09:00:00", "waf", "WAF0001", "SHAREDTOK && LATOK"),
                  L("09:30:00", "hids", "HID0001", "SHAREDTOK && net user /add bob")])
        self.assertEqual(len(ch), 1)
        self.assertFalse(any(("倒置切链" in f) or ("顺序异常" in f) for f in ch[0]["flags"]))

    def test_recon_stage_excluded_from_order_check(self):
        ch = run([L("09:00:00", "hids", "HID0001", "SHAREDTOK /a dst=10.0.0.7"),
                  L("09:01:00", "hids", "HID0002", "whoami dst=10.0.0.7")])
        self.assertEqual(len(ch), 1)   # recon 不参与顺序判定
        self.assertEqual(ch[0]["flags"], [])


class TestStep2bConcurrent(unittest.TestCase):
    """信号 2.5「同请求跨源并发」：Δt≤30s + 不同来源 + 共享动作或同 URI 路径 + 至少一侧有非通用动作"""
    def test_shared_action_links_cross_source(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "/api/v1/query SHAREDTOK"),
                  L("09:00:02", "rasp", "RASP0001", "/api/v1/query whoami")])
        self.assertEqual(len(ch), 1)
        self.assertEqual(ch[0]["link_basis"], "concurrent")
        self.assertEqual(ch[0]["confidence"], "中")
        self.assertTrue(any("同请求跨源并发拼接" in f for f in ch[0]["flags"]))

    def test_same_uri_path_links_without_shared_action(self):
        # rasp 行载荷形态不同（只剩另一动作），但 URI 路径一致 + 秒级同现 → 补链
        ch = run([L("09:00:00", "waf", "WAF0001", "/api/v1/query EARLYTOK"),
                  L("09:00:01", "rasp", "RASP0001",
                    "https://app-x.ops-corp.com/api/v1/query LATOK")])
        self.assertEqual(len(ch), 1)
        self.assertEqual(ch[0]["link_basis"], "concurrent")

    def test_entity_conflict_blocks_link(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "dst=10.1.1.1 /api/v1/query LATOK"),
                  L("09:00:01", "rasp", "RASP0001",
                    "https://app-b.ops-corp.com/api/v1/query net user /add x")])
        self.assertEqual(len(ch), 2)

    def test_generic_only_does_not_link(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "whoami /api/v1/query"),
                  L("09:00:03", "hids", "HID0001", "whoami /api/v1/query")])
        self.assertEqual(len(ch), 2)

    def test_outside_window_does_not_link(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "/api/v1/query EARLYTOK"),
                  L("09:05:00", "hids", "HID0001", "/api/v1/query LATOK")])
        self.assertEqual(len(ch), 2)

    def test_system_paths_not_used_for_linking(self):
        # /etc/passwd 之类系统路径不作判别性依据（项目红线）
        ch = run([L("09:00:00", "waf", "WAF0001", "/etc/passwd EARLYTOK"),
                  L("09:00:02", "rasp", "RASP0001", "/etc/passwd LATOK")])
        self.assertEqual(len(ch), 2)


class TestReviewFixes(unittest.TestCase):
    """子代理审查发现的缺陷对应回归（非确定性/滑窗/同源模板/单行链/会话跨窗/类型健壮/性能）"""

    def test_windowed_pairs_survive_intervening_row(self):
        # 审查发现#5：信号 2.5 原先只看全局相邻行，中间夹一行噪声即失效
        ch = run([L("09:00:00", "waf", "WAF0001", "/api/v1/query EARLYTOK"),
                  L("09:00:05", "dns", "DNS0001", "noise.host.net A 203.0.113.9"),
                  L("09:00:10", "rasp", "RASP0001", "/api/v1/query LATOK")])
        multi = [c for c in ch if len(c["lines"]) > 1]
        self.assertEqual(len(multi), 1)
        self.assertEqual([l["source"] for l in multi[0]["lines"]], ["waf", "rasp"])
        self.assertEqual(multi[0]["link_basis"], "concurrent")

    def test_tied_sort_keys_are_deterministic(self):
        # 审查发现#1/#2：全同行无 log_id 时，排序键必须与输入顺序无关
        lines = [L("09:00:00", "waf", "", "/api/v1/query EARLYTOK"),
                 L("09:00:00", "dns", "", "noise.host.net A 203.0.113.9"),
                 L("09:00:00", "rasp", "", "/api/v1/query LATOK"),
                 L("09:00:00", "hids", "", "net user /add bob")]
        ref = json.dumps(run(lines), ensure_ascii=False, sort_keys=True)
        for seed in range(6):
            shuffled = list(lines)
            random.Random(seed).shuffle(shuffled)
            self.assertEqual(json.dumps(run(shuffled), ensure_ascii=False, sort_keys=True), ref)

    def test_template_same_source_needs_tight_window(self):
        # 审查发现#9：同源模板重叠只在紧邻窗内承认（防"同源 24 分钟"噪声粘连）
        near = run([L("09:00:00", "hids", "HID0001", "SHAREDTOK /a"),
                    L("09:01:40", "hids", "HID0002", "SHAREDTOK /b")])            # 100s ≤ 300s
        self.assertEqual(len(near), 1)
        far = run([L("09:00:00", "hids", "HID0001", "SHAREDTOK /a"),
                   L("09:10:00", "hids", "HID0002", "SHAREDTOK /b")])            # 600s > 300s
        self.assertEqual(len(far), 2)

    def test_session_component_not_split_by_window(self):
        # 审查发现#7：会话键是确定性分组，不被时间窗拆散；跨窗时保留并标记
        ch = run([L("09:00:00", "waf", "WAF0001", "session_id=sess1 /a?x=1"),
                  L("10:05:00", "hids", "HID0001", "session_id=sess1 /b?y=2")])
        self.assertEqual(len(ch), 1)
        self.assertEqual(ch[0]["link_basis"], "session")
        self.assertTrue(any("会话键分量跨窗" in f for f in ch[0]["flags"]))

    def test_window_split_fragment_is_singleton_not_high_confidence(self):
        # 审查发现#13：窗口拆出的单行碎片不得宣称"高置信实体链"
        ch = run([L("09:00:00", "waf", "WAF0001", "SHAREDTOK dst=10.0.0.5"),
                  L("12:30:00", "hids", "HID0001", "SHAREDTOK dst=10.0.0.5")])
        self.assertEqual(len(ch), 2)
        for c in ch:
            self.assertEqual(c["link_basis"], "singleton")
            self.assertEqual(c["confidence"], "低")
            self.assertTrue(any("原分量连接依据" in f for f in c["flags"]))

    def test_stage_type_robustness(self):
        # 审查发现#11：stage 非字符串（int/list）不得崩溃
        lib = dict(LIB)
        lib["t_bad"] = {"label": "坏阶段", "regex": r"BADSTAGE", "generic": False, "stage": 3}
        lines = [L("09:00:00", "waf", "WAF0001", "BADSTAGE")]
        out = ca.assemble_chains(lines, lib=lib, matcher=matcher)
        self.assertEqual(len(out), 1)
        lib2 = dict(LIB)
        lib2["t_bad"] = {"label": "坏阶段", "regex": r"BADSTAGE", "generic": False,
                         "stage": ["persistence"]}
        self.assertEqual(len(ca.assemble_chains(lines, lib=lib2, matcher=matcher)), 1)

    def test_unknown_stage_value_flagged(self):
        lib = dict(LIB)
        lib["t_odd"] = {"label": "未知档", "regex": r"ODDSTAGE", "generic": False, "stage": "stealth"}
        out = ca.assemble_chains([L("09:00:00", "waf", "WAF0001", "ODDSTAGE")], lib=lib, matcher=matcher)
        self.assertTrue(any("含未知阶段标注已忽略" in f for f in out[0]["flags"]))

    def test_concurrent_flag_text_uses_runtime_window(self):
        # 审查发现#17：flag 文案须反映本次运行实际阈值
        ch = run([L("09:00:00", "waf", "WAF0001", "/api/v1/query EARLYTOK"),
                  L("09:00:40", "rasp", "RASP0001", "/api/v1/query LATOK")], concurrent_window=120)
        self.assertEqual(len(ch), 1)
        self.assertTrue(any("Δt≤120s" in f for f in ch[0]["flags"]))

    def test_bracketed_log_id_and_missing_source(self):
        # 审查发现#14：方括号 log_id 与空 source 形态
        r = ca.parse_log_line("2026-06-02 09:00:00 [waf] [WAF0001] content")
        self.assertEqual((r["source"], r["log_id"], r["content"]), ("waf", "WAF0001", "content"))
        r2 = ca.parse_log_line("2026-06-02 09:00:00 [] HID0001 content")
        self.assertEqual((r2["source"], r2["log_id"]), ("unknown", "HID0001"))

    def test_paths_related_boundary_rules(self):
        self.assertTrue(ca._paths_related({"/app-x.ops-corp.com/api/v1/query"}, {"/api/v1/query"}))
        self.assertFalse(ca._paths_related({"/a/b/users"}, {"/admin/x/a/b/users"}))
        self.assertFalse(ca._paths_related({"/x"}, {"/a/x"}))

    def test_sys_path_prefix_is_segment_based(self):
        # 段级匹配：/binfoo、/varnish 不是系统路径的前缀段，应保留为普通路径（不被误排除）
        self.assertIn("/binfoo", _paths_of_line("/binfoo EARLYTOK x.ops-corp.com"))
        self.assertIn("/varnish", _paths_of_line("/varnish EARLYTOK x.ops-corp.com"))
        self.assertNotIn("/bin", _paths_of_line("/bin/cat EARLYTOK x.ops-corp.com"))
        self.assertNotIn("/etc/passwd", _paths_of_line("/etc/passwd EARLYTOK x.ops-corp.com"))

    def test_window_split_performance_and_semantics(self):
        # 审查发现#3：拆簇须线性（原实现大簇等距时退化为逐行剥离：n=5000 约 2.5s、n=20000 约 100s）
        import time as _t
        from datetime import datetime, timedelta
        n = 8000
        start = datetime(2026, 6, 2, 9, 0, 0)
        lines = [f"{(start + timedelta(seconds=i)).strftime('%Y-%m-%d %H:%M:%S')} "
                 f"[waf] W{i:06d} SHAREDTOK dst=10.0.0.5" for i in range(n)]
        parsed = sum(1 for ln in lines if ca.parse_log_line(ln))
        self.assertEqual(parsed, n, "用例行未被完整解析（时间戳生成有误）")
        t0 = _t.time()
        ch = run(lines)
        elapsed = _t.time() - t0
        self.assertLess(elapsed, 1.5, f"拆簇耗时 {elapsed:.2f}s（应线性近似）")
        total = sum(len(c["lines"]) for c in ch)
        self.assertEqual(total, n, "行数守恒（拆簇不应丢行）")
        for c in ch:
            first, last = c["lines"][0]["ts"], c["lines"][-1]["ts"]
            self.assertLessEqual(_epoch(last) - _epoch(first), ca.WINDOW_S, f"链跨度超窗: {first}~{last}")


class TestDeterminism(unittest.TestCase):
    LINES = [L("09:00:00", "waf", "WAF0001", "SHAREDTOK /a dst=10.0.0.5"),
             L("09:00:30", "hids", "HID0001", "SHAREDTOK /b dst=10.0.0.5"),
             L("09:00:40", "waf", "WAF0002", "EARLYTOK"),
             L("09:02:00", "hids", "HID0002", "net user /add bob dst=10.9.9.9"),
             L("10:30:00", "dns", "DNS0001", "3fa2b9c1.xkqwvp-9d2f.net A 203.0.113.77")]

    def test_same_input_same_output(self):
        a = json.dumps(run(self.LINES), ensure_ascii=False, sort_keys=True)
        b = json.dumps(run(self.LINES), ensure_ascii=False, sort_keys=True)
        self.assertEqual(a, b)

    def test_shuffled_input_same_output(self):
        ref = json.dumps(run(self.LINES), ensure_ascii=False, sort_keys=True)
        for seed in (1, 2, 3):
            lines = list(self.LINES)
            random.Random(seed).shuffle(lines)
            self.assertEqual(json.dumps(run(lines), ensure_ascii=False, sort_keys=True), ref)

    def test_chain_ids_sequential_by_time(self):
        ch = run(self.LINES)
        self.assertEqual([c["chain_id"] for c in ch], [f"CHAIN-{i:02d}" for i in range(1, len(ch) + 1)])


class TestEdge(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(run([]), [])
        self.assertEqual(run(["", "noise"]), [])

    def test_singleton_no_action_line(self):
        ch = run([L("09:00:00", "hids", "HID0001", "systemctl restart nginx")])
        self.assertEqual(len(ch), 1)
        self.assertEqual(ch[0]["link_basis"], "singleton")
        self.assertEqual(ch[0]["ordered_actions"], [])

    def test_chain_object_fields(self):
        ch = run([L("09:00:00", "waf", "WAF0001", "SHAREDTOK")])[0]
        for k in ("chain_id", "lines", "ordered_actions", "sources", "entities",
                  "link_basis", "confidence", "flags"):
            self.assertIn(k, ch)
        self.assertEqual(ch["lines"][0]["log_id"], "WAF0001")
        self.assertEqual(ch["entities"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

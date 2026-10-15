#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""tests/test_chain_integration.py — 链级集成测试（M5，真实 case 库 + 数据集 fixture）

验证（真实数据，非自造动作库）:
  1. 组装质量：三个入库数据集的单元内"同案例多行"是否被正确并成**一条链**
     （期望: 35 组正确并链 / 0 碎片 / 0 跨案例误并）
  2. 链级匹配：每条多行链的最优案例 == 该链行的期望案例（history/old_eval 的 EXPECT，单一事实源）
  3. 演示批（eval/fixtures/chain_demo_cross_source.txt）：
     完整跨源链 → 案例唯一；前缀链 → 预测下一步带预期来源；噪声单例 → 无命中
  4. 行级不受影响：抽样行级检索结果与链层并行（行级通道仍是原口径）

运行: python tests/test_chain_integration.py
说明: fixture 由 eval/fixtures/gen_chain_fixtures.py 从 dataset/ 导出（静态副本）；
      若动作库/案例库大改，期望值可能需重新校准（属正常回归维护）。
"""
import importlib.util
import pathlib
import sys
import unittest
from collections import defaultdict

BASE = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE / "src"))
import retrieve as ret  # noqa: E402
import chain_assembly as ca  # noqa: E402


def _load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


RF = _load(BASE / "history" / "old_eval" / "run_recall_full.py", "rf_it")
FIX = BASE / "eval" / "fixtures"
UNITS = [("901-910", "chain_units_901910.txt"), ("911-920", "chain_units_911920.txt"),
         ("9101-9110", "chain_units_91019110.txt")]
CASES, LIB = ret.load_store()
STORE = (CASES, LIB)


def expected_map():
    """fixture 行序 → 期望案例（依 dataset 单元结构 + EXPECT 单一事实源）"""
    exp = {}
    for tag, _fn in UNITS:
        units = RF.parse_file(BASE / "dataset" / f"data-{tag}.txt")
        for ui, u in enumerate(units, 1):
            for ei, e in enumerate(u, 1):
                exp[e["log_id"]] = RF.EXPECT[tag][ui][ei - 1]
    return exp


class TestAssemblyOnDatasets(unittest.TestCase):
    # 已知链级 Top-1 与行级人工期望不同的例外（数据本身混合证据导致，非缺陷）：
    # 9101-9110 单元 6 的 waf/web/rasp 行同时携带 CASE-003（LFI 路径）与 CASE-016（cache_key+smuggle）
    # 载荷；该单元 rasp 行载荷被截断（169.254 未落文本 → CASE-003 只剩 1/4 弱档），链级把
    # cache_key+smuggle 并成 CASE-016 中段 2/4（中档）→ Top-1 由 CASE-016 取得（行级期望 CASE-003 在 Top-3）。
    KNOWN_TOP1_DIFF = {("9101-9110", "WAF0000272"): ("CASE-003", "CASE-016")}

    @classmethod
    def setUpClass(cls):
        cls.exp = expected_map()

    def _chains(self, fn):
        lines = (FIX / fn).read_text(encoding="utf-8").splitlines()
        return ca.assemble_chains(lines, lib=LIB, matcher=ret.match_actions), lines

    def test_no_fragmentation_and_no_over_merge(self):
        merged = frag = mixed = 0
        for tag, fn in UNITS:
            chains, _ = self._chains(fn)
            loc = {l["log_id"]: ch["chain_id"] for ch in chains for l in ch["lines"]}
            # 以单元为单位统计"同案例多行"
            units = RF.parse_file(BASE / "dataset" / f"data-{tag}.txt")
            for ui, u in enumerate(units, 1):
                g = defaultdict(list)
                for ei, e in enumerate(u, 1):
                    w = RF.EXPECT[tag][ui][ei - 1]
                    if w:
                        g[w].append(e["log_id"])
                for w, ids in g.items():
                    if len(ids) < 2:
                        continue
                    if len({loc[i] for i in ids}) == 1:
                        merged += 1
                    else:
                        frag += 1
                        self.fail(f"碎片化: {tag} unit{ui} {w} 期望同链 {ids} → "
                                  f"{sorted({loc[i] for i in ids})}")
            for ch in chains:
                ws = {self.exp[l["log_id"]] for l in ch["lines"]} - {None}
                if len(ws) > 1:
                    mixed += 1
                    self.fail(f"跨案例误并: {tag} {ch['chain_id']} 混入 {sorted(ws)}")
        self.assertEqual((merged, frag, mixed), (35, 0, 0))

    @staticmethod
    def _ids_of(tag):
        units = RF.parse_file(BASE / "dataset" / f"data-{tag}.txt")
        return {e["log_id"] for u in units for e in u}

    def test_multiline_chain_top1_equals_expected_case(self):
        checked = 0
        for tag, fn in UNITS:
            chains, _ = self._chains(fn)
            for ch in chains:
                ws = {self.exp[l["log_id"]] for l in ch["lines"]} - {None}
                if not ws or len(ws) > 1:
                    continue
                want = sorted(ws)[0]
                matches = ret.chain_match(ch, CASES, LIB)
                self.assertTrue(matches, f"{tag} {ch['chain_id']} 无链级候选（期望 {want}）")
                key = (tag, ch["lines"][0]["log_id"])
                if key in self.KNOWN_TOP1_DIFF:
                    exp_want, exp_top1 = self.KNOWN_TOP1_DIFF[key]
                    self.assertEqual((want, matches[0]["id"]), (exp_want, exp_top1),
                                     f"{tag} {ch['chain_id']} 例外表与实际不符")
                    self.assertIn(want, [m["id"] for m in matches[:3]],
                                  f"{tag} {ch['chain_id']} 期望案例未进 Top-3")
                else:
                    self.assertEqual(matches[0]["id"], want,
                                     f"{tag} {ch['chain_id']} Top-1={matches[0]['id']} 期望 {want}")
                checked += 1
        self.assertGreaterEqual(checked, 30)

    def test_datasets_assembly_deterministic(self):
        for tag, fn in UNITS:
            lines = (FIX / fn).read_text(encoding="utf-8").splitlines()
            a = ca.assemble_chains(lines, lib=LIB, matcher=ret.match_actions)
            b = ca.assemble_chains(list(reversed(lines)), lib=LIB, matcher=ret.match_actions)
            self.assertEqual([c["chain_id"] for c in a], [c["chain_id"] for c in b])
            self.assertEqual([[l["log_id"] for l in c["lines"]] for c in a],
                             [[l["log_id"] for l in c["lines"]] for c in b])


class TestDemoFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.chains = ca.assemble_chains(
            (FIX / "chain_demo_cross_source.txt").read_text(encoding="utf-8").splitlines(),
            lib=LIB, matcher=ret.match_actions)

    def _chain_with(self, log_id):
        for ch in self.chains:
            if any(l["log_id"] == log_id for l in ch["lines"]):
                return ch
        self.fail(f"未找到含 {log_id} 的链")

    def test_complete_cross_source_chain(self):
        ch = self._chain_with("RASP0006051")
        self.assertEqual([l["source"] for l in ch["lines"]], ["waf", "web", "rasp"])
        m = ret.chain_match(ch, CASES, LIB)[0]
        self.assertEqual(m["id"], "CASE-010")
        self.assertEqual(m["mtype"], "完整")
        self.assertEqual(m["tier"], "强")
        self.assertEqual(len(m["evidence_lines"]), 3)

    def test_prefix_chain_predicts_with_source(self):
        ch = self._chain_with("WAF0048744")
        self.assertEqual([l["log_id"] for l in ch["lines"]], ["WAF0048744", "RASP0053691"])
        m = ret.chain_match(ch, CASES, LIB)[0]
        self.assertEqual(m["id"], "CASE-009")
        self.assertEqual(m["mtype"], "前缀")
        self.assertEqual(m["predict"], "mysql_load_file")
        # LOAD_FILE 载荷文本在入库数据集中缺席（见 derive_action_sources.py 的 OVERRIDES）：
        # 该动作来源按"同一载荷的观测行"标注为 waf|web
        self.assertEqual(m["predict_source"], ["waf", "web"])
        self.assertTrue(m["in_progress"])

    def test_noise_singleton_has_no_chain_match(self):
        ch = self._chain_with("HID0005785")
        self.assertEqual(len(ch["lines"]), 1)
        self.assertEqual(ret.chain_match(ch, CASES, LIB), [])

    def test_dns_beacon_chain(self):
        ch = self._chain_with("DNS0098419")
        self.assertEqual(len(ch["lines"]), 3)
        m = ret.chain_match(ch, CASES, LIB)[0]
        self.assertEqual(m["id"], "CASE-002")
        self.assertEqual(m["mtype"], "完整")


class TestChainMatchReviewFixes(unittest.TestCase):
    """链级匹配审查修复的回归（F1 位置复算 / F2 列表含 any / F3 裸串归一 / predict 与来源同源）"""

    def _case(self, **kw):
        c = {"id": "CASE-T1", "attack_type": "测试案例",
             "action_sequence": ["t_exec", "t_persist", "t_exec", "t_early"],
             "action_sources": ["waf", "waf", "hids", "waf"]}
        c.update(kw)
        return c

    def _chain(self, ordered, sources=("waf", "rasp")):
        return {"chain_id": "CHAIN-T", "sources": list(sources),
                "lines": [{"ts": "2026-06-02 09:00:00", "source": s, "log_id": f"L{i}",
                           "content": "x", "actions": []} for i, s in enumerate(sources)],
                "ordered_actions": list(ordered)}

    def test_source_mismatch_positions_are_not_realigned(self):
        # F1：案例序列含重复动作 id 时，按位置复算（旧实现按 id 重对齐会把不符位置捞回 → 误判完整）
        chain = self._chain([("t_exec", "waf"), ("t_persist", "waf"),
                             ("t_exec", "rasp"), ("t_early", "waf")])
        m = ret.chain_match(chain, [self._case()], {})[0]
        self.assertEqual(m["mtype"], "缺口")
        self.assertEqual((m["matched"], m["total"], m["positions"]), (3, 4, [0, 1, 3]))
        self.assertEqual(m["source_mismatch"], [2])
        self.assertTrue(m["gaps"])

    def test_list_with_any_skips_source_check(self):
        # F2：来源值为列表且含 any → 等同 any（跳过校验，不误判不符）
        self.assertTrue(ret._source_accepts(["any"], {"rasp"}))
        self.assertTrue(ret._source_accepts([], {"rasp"}))
        self.assertFalse(ret._source_accepts(["hids"], {"rasp"}))

    def test_bare_string_action_sources_normalized(self):
        # F3：action_sources 为裸字符串时不按下标取字符
        self.assertEqual(ret._case_sources({"action_sequence": ["a", "b"], "action_sources": "waf"}),
                         ["waf", "any"])

    def test_predict_source_matches_predict_position(self):
        # predict 与 predict_source 必须同源（同一个案例位置）；此处下一位置预期来源为 hids
        case = self._case(action_sources=["waf", "waf", "waf", "hids"])
        chain = self._chain([("t_exec", "waf"), ("t_persist", "waf"), ("t_exec", "waf")])
        m = ret.chain_match(chain, [case], {})[0]
        self.assertEqual(m["predict"], "t_early")
        self.assertEqual(m["predict_source"], "hids")
        self.assertEqual(m["positions"][-1] + 1, 3)

    def test_empty_ordered_actions_yields_no_candidates(self):
        m = ret.chain_match(self._chain([], sources=("waf", "hids")), [self._case()], {})
        self.assertEqual(m, [])

    def test_fixture_predict_source_is_consistent(self):
        """演示批/数据集 fixture 上：predict_source 与案例 action_sources 的同位置值一致"""
        cases_by_id = {c["id"]: c for c in CASES}
        checked = 0
        for fn in ("chain_demo_cross_source.txt", "chain_units_901910.txt",
                   "chain_units_911920.txt", "chain_units_91019110.txt"):
            lines = (FIX / fn).read_text(encoding="utf-8").splitlines()
            for ch in ca.assemble_chains(lines, lib=LIB, matcher=ret.match_actions):
                for m in ret.chain_match(ch, CASES, LIB):
                    if not m["predict"]:
                        continue
                    case = cases_by_id[m["id"]]
                    pos = m["positions"][-1] + 1
                    want = ret._case_sources(case)[pos]
                    self.assertEqual(m["predict_source"], want,
                                     f"{fn} {ch['chain_id']} {m['id']} 预测来源与位置不一致")
                    checked += 1
        self.assertGreater(checked, 0)


class TestLineLevelUnaffected(unittest.TestCase):
    """链层是加层：行级检索结果照旧（抽样断言，全量口径由 eval/run_action_recall.py 守）"""

    def test_sample_lines_still_hit_expected_case(self):
        for line, want in [
            ("2026-05-01 20:04:36 [waf] WAF0005562 /api/v1/ping?cmd=127.0.0.1;id "
             "handle=com.tangosol.coherence.mvel2.sh.ShellSession&cmd=id", "CASE-010"),
            ("2026-05-08 02:07:56 [waf] WAF0048744 /users/sign_in email=' OR '1'='1'--&password=x",
             "CASE-009"),
            ("2026-05-14 11:15:20 [dns] DNS0098419 2fa0ad21.kpedpm-3d20.net A 203.0.113.35", "CASE-002"),
        ]:
            hits, _kw, _obs = ret.retrieve(line, STORE)
            self.assertTrue(hits, line)
            self.assertEqual(hits[0]["id"], want, line)


if __name__ == "__main__":
    unittest.main(verbosity=2)

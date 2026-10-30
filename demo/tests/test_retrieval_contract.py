"""Contract tests for retrieval indexing, CLI JSON, aliases, and negative memory.

Run from demo/:  python -m unittest tests.test_retrieval_contract -v
"""
from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

DEMO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEMO_ROOT / "src"))

import lookup_case_logs  # noqa: E402
import run_demo  # noqa: E402
from attack_memory.retrieval import (TIER_RANK, _keyword_score, _leading_literal,  # noqa: E402
                                     build_action_index, extract_log_actions, match_pattern,
                                     retrieve)
from attack_memory.storage import (RAW_LOGS_PATH, load_patterns, read_csv,  # noqa: E402
                                   read_links)


def capture_main(module, argv):
    """Run a CLI main() with argv and return (stdout, SystemExit code or None)."""
    output = io.StringIO()
    code = None
    with contextlib.redirect_stdout(output):
        with mock.patch.object(sys, "argv", argv):
            try:
                module.main()
            except SystemExit as error:  # argparse errors
                code = error.code
    return output.getvalue(), code


def plain_scan_actions(logs, action_index):
    """Reference implementation of the pre-index scan contract."""
    output = []
    for log in logs:
        content = log.get("content") or ""
        for action_id, entry in action_index.items():
            if not entry["regex"].search(content):
                continue
            output.append({
                "action_id": action_id,
                "event_id": log.get("event_id") or log.get("log_id", ""),
                "source": (log.get("source") or "").casefold(),
                "timestamp": log.get("timestamp", ""),
                "generic": entry["generic"],
                "log": log,
            })
    return output


def old_style_retrieve(patterns, logs, action_index):
    """The pre-optimization retrieve pipeline, kept as an oracle for equivalence."""
    actions = plain_scan_actions(logs, action_index)
    text = "\n".join(log.get("content") or "" for log in logs)
    indexed_cases = {ref["case_id"] for action in actions
                     for ref in action_index[action["action_id"]]["refs"]}
    results = []
    for pattern in patterns:
        if pattern.get("status") == "retired":
            continue
        if pattern["case_id"] not in indexed_cases and not _keyword_score(pattern, text)[0]:
            continue
        result = match_pattern(pattern, logs, actions, text)
        if result["tier"] != "none":
            results.append(result)
    results.sort(key=lambda r: (-TIER_RANK[r["tier"]], -r["matched_non_generic_steps"],
                                -r["matched_steps"], -r["source_fit_ratio"],
                                -r["keyword_score"], r["case_id"]))
    return results


class RetrievalIndexEquivalenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = load_patterns()["attack_patterns"]
        cls.index = build_action_index(cls.patterns)
        cls.logs = read_csv(RAW_LOGS_PATH)
        cls.scopes = run_demo.partition_logs(cls.logs) + [("all", "ALL", cls.logs)]

    def test_plain_scan_extraction_is_unchanged(self):
        got = [(action["action_id"], action["event_id"], action["source"], action["timestamp"],
                action["generic"], id(action["log"]))
               for action in extract_log_actions(self.logs, self.index)]
        expected = [(action["action_id"], action["event_id"], action["source"],
                     action["timestamp"], action["generic"]) for action in
                    plain_scan_actions(self.logs, self.index)]
        self.assertEqual([item[:5] for item in got], expected)
        for action in extract_log_actions(self.logs, self.index):
            self.assertIn(action["log"], self.logs)

    def test_new_retrieve_matches_the_old_pipeline(self):
        for kind, identifier, rows in self.scopes:
            with self.subTest(scope=identifier):
                expected = old_style_retrieve(self.patterns, rows, self.index)
                got = retrieve(self.patterns, rows, self.index)
                self.assertEqual(json.dumps(got, sort_keys=True, default=str),
                                 json.dumps(expected, sort_keys=True, default=str),
                                 f"retrieve drifted for scope {kind}:{identifier}")

    def test_actions_by_id_and_keyword_do_not_change_a_pattern_result(self):
        for kind, identifier, rows in self.scopes:
            actions = extract_log_actions(rows, self.index)
            by_id: dict[str, list[dict]] = {}
            for action in actions:
                by_id.setdefault(action["action_id"], []).append(action)
            text = "\n".join(row.get("content") or "" for row in rows)
            lowered = text.casefold()
            for pattern in self.patterns:
                with self.subTest(scope=identifier, case=pattern["case_id"]):
                    keyword = _keyword_score(pattern, text, lowered)
                    legacy = match_pattern(pattern, rows, actions, text)
                    optimized = match_pattern(pattern, rows, actions, text,
                                              actions_by_id=by_id, keyword=keyword)
                    self.assertEqual(json.dumps(legacy, sort_keys=True, default=str),
                                     json.dumps(optimized, sort_keys=True, default=str))

    def test_actions_by_id_explicit_none_is_the_legacy_path(self):
        rows = self.logs[:25]
        actions = extract_log_actions(rows, self.index)
        pattern = self.patterns[0]
        self.assertEqual(match_pattern(pattern, rows, actions),
                         match_pattern(pattern, rows, actions, actions_by_id=None))

    def test_retired_patterns_stay_out_of_retrieval(self):
        patterns = [dict(pattern) for pattern in self.patterns]
        patterns[0] = dict(patterns[0], status="retired")
        rows = [row for row in self.logs if row.get("case_id") == patterns[0]["case_id"]]
        self.assertNotIn(patterns[0]["case_id"],
                         [result["case_id"] for result in retrieve(patterns, rows)])

    def test_literal_prefilter_never_rejects_a_real_match(self):
        for action_id, entry in self.index.items():
            literal = entry["literal"]
            if literal is None:
                continue
            samples = [row.get("content") or "" for row in self.logs]
            samples += ["", " ", "classLoader.first", "x" * 64]
            for content in samples:
                if entry["regex"].search(content):
                    self.assertIn(literal, content.casefold(),
                                  f"literal {literal!r} would hide a real match for {action_id}")

    def test_leading_literal_is_conservative(self):
        # Top-level alternation makes the prefix non-mandatory, so it must be refused.
        self.assertIsNone(_leading_literal(r"(?i)classLoader\.first|class\.module\.classLoader"))
        self.assertIsNone(_leading_literal(r"(?i)wp-admin/admin-ajax\.php\?action=upload|\"upload\""))
        self.assertIsNone(_leading_literal(r"(?i)[a-z]abc"))
        self.assertIsNone(_leading_literal(r"(?i)\babc"))
        self.assertIsNone(_leading_literal(r"(?i)ab?c"))
        self.assertEqual(_leading_literal(r"(?i)/uploads?/"), "/upload")
        self.assertEqual(_leading_literal(r"(?i)\$\{jndi:(?:ldap|rmi)://"), "${jndi:")
        self.assertEqual(_leading_literal(r"(?i)/bin/(?:sh|bash)"), "/bin/")


class RunDemoJsonContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stdout, code = capture_main(run_demo, ["run_demo.py", "--json", "--top", "3"])
        assert code is None, code
        cls.data = json.loads(stdout)

    def test_top_level_contract(self):
        data = self.data
        self.assertIsInstance(data["schema_version"], int)
        self.assertEqual(data["schema_version"], 1)
        for field in ("input", "log_count", "min_tier", "scopes"):
            self.assertIn(field, data)
        self.assertIsInstance(data["scopes"], list)
        self.assertTrue(data["scopes"])
        self.assertIn("not a probability", data["evidence_confidence_note"])

    def test_scope_and_candidate_field_types(self):
        checked = 0
        for scope in self.data["scopes"]:
            self.assertIsInstance(scope["scope_type"], str)
            self.assertIsInstance(scope["scope_id"], str)
            self.assertIsInstance(scope["log_count"], int)
            self.assertIsInstance(scope["hosts"], list)
            self.assertIsInstance(scope["family_matches"], list)
            self.assertIsInstance(scope["candidates"], list)
            for candidate in scope["candidates"]:
                checked += 1
                self.assertIsInstance(candidate["case_id"], str)
                self.assertIn(candidate["tier"], TIER_RANK)
                self.assertIsInstance(candidate["required_steps"], int)
                self.assertGreater(candidate["required_steps"], 0)
                self.assertIsInstance(candidate["matched_required_steps"], int)
                self.assertIsInstance(candidate["evidence_confidence"], float)
                self.assertGreaterEqual(candidate["evidence_confidence"], 0.0)
                self.assertLessEqual(candidate["evidence_confidence"], 1.0)
                self.assertTrue(candidate["historical_precision"] is None
                                or isinstance(candidate["historical_precision"], float))
                self.assertIsInstance(candidate["prior_rejections"], list)
                self.assertIsInstance(candidate["evidence"], list)
        self.assertGreater(checked, 0, "no candidates in the contract sample")

    def test_confidence_formula_is_reproducible(self):
        checked = 0
        for scope in self.data["scopes"]:
            for candidate in scope["candidates"]:
                ratio = candidate["matched_required_steps"] / candidate["required_steps"]
                precision = candidate["historical_precision"]
                expected = round(ratio * (1.0 if precision is None else precision), 3)
                self.assertAlmostEqual(candidate["evidence_confidence"], expected, places=9)
                checked += 1
        self.assertGreater(checked, 0)

    def test_confidence_does_not_reorder_tiers(self):
        rank = [TIER_RANK[candidate["tier"]] for scope in self.data["scopes"]
                for candidate in scope["candidates"]]
        self.assertEqual(rank, sorted(rank, reverse=True))

    def test_prior_rejections_are_rendered_from_the_ledger(self):
        ledger_record = {
            "correction_id": "COR-0001", "incident_id": "INC-CASE-001-001",
            "case_id": "CASE-001", "decision": "reject_match", "reason_code": "generic_only",
            "event_ids": ["EVT-CASE001-01"], "basis": "only a shared generic probe",
            "reviewer": "tester", "decided_at": "2026-10-30T00:00:00Z",
        }
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "corrections.json"
            path.write_text(json.dumps({"schema_version": 1,
                                        "corrections": [ledger_record]}), encoding="utf-8")
            with mock.patch.object(run_demo.corrections, "CORRECTIONS_PATH", path):
                items = run_demo.prior_rejections_for("CASE-001", "INC-CASE-001-001")
                self.assertEqual(len(items), 1)
                self.assertEqual(items[0]["correction_id"], "COR-0001")
                self.assertIn("generic_only", items[0]["summary"])
                self.assertIn("shared generic probe", items[0]["summary"])
                # A different incident must not inherit the rejection.
                self.assertEqual(run_demo.prior_rejections_for("CASE-001", "INC-OTHER"), [])
                stdout, code = capture_main(
                    run_demo, ["run_demo.py", "--json", "--top", "1",
                               "--incident-id", "INC-CASE-001-001"])
        self.assertIsNone(code)
        data = json.loads(stdout)
        candidates = data["scopes"][0]["candidates"]
        self.assertTrue(candidates)
        self.assertTrue(candidates[0]["prior_rejections"])
        self.assertIn("COR-0001", candidates[0]["prior_rejections"][0]["summary"])

    def test_text_mode_keeps_the_new_information_compact(self):
        stdout, code = capture_main(run_demo, ["run_demo.py", "--top", "1",
                                               "--incident-id", "INC-CASE-001-001"])
        self.assertIsNone(code)
        lines = stdout.splitlines()
        self.assertTrue(any("evidence confidence=" in line and "not a probability" in line
                            for line in lines), stdout[:2000])
        self.assertTrue(any("candidate" in line.lower() or "[" in line for line in lines))
        # One extra context line per candidate at most; no wall of explanatory prose.
        self.assertLess(len(lines), 40)


class LookupJsonContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        stdout, code = capture_main(lookup_case_logs,
                                    ["lookup_case_logs.py", "--case-id", "CASE-005", "--json"])
        assert code is None, code
        cls.data = json.loads(stdout)

    def test_top_level_contract(self):
        data = self.data
        self.assertIsInstance(data["schema_version"], int)
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["case_id"], "CASE-005")
        self.assertIsNone(data["alias_of"])
        self.assertEqual(data["resolved_case_id"], "CASE-005")
        self.assertIsInstance(data["count"], int)
        self.assertIsInstance(data["observations"], list)
        self.assertEqual(len(data["observations"]), data["count"])
        for observation in data["observations"]:
            for field in ("event_id", "link_status", "content"):
                self.assertIn(field, observation)

    def test_select_observations_alias_is_opt_in(self):
        rows = [
            {"event_id": "E1", "case_id": "CASE-980"},
            {"event_id": "E2", "case_id": "CASE-981"},
        ]
        latest = {
            "E1": {"link_status": "confirmed", "case_id": "CASE-980"},
            "E2": {"link_status": "confirmed", "case_id": "CASE-981"},
        }
        target_only, _ = lookup_case_logs.select_observations(
            rows, latest, case_id="CASE-981")
        self.assertEqual([row["event_id"] for row, _ in target_only], ["E2"])
        union, _ = lookup_case_logs.select_observations(
            rows, latest, case_id="CASE-981", alias_case_id="CASE-980")
        self.assertEqual([row["event_id"] for row, _ in union], ["E1", "E2"])


class LookupAliasTests(unittest.TestCase):
    """Alias merge: the source label keeps its links but lookup follows to the target."""

    def setUp(self):
        def pattern(case_id, action_id, regex):
            return {"case_id": case_id, "name": case_id, "summary": f"synthetic {case_id}",
                    "mitre": ["T0000"], "family_id": "web-exploit", "version": 1,
                    "steps": [{"step_id": "S1", "order": 1, "action_id": action_id,
                               "label": case_id, "action_regex": regex,
                               "expected_sources": ["hids"], "required": True}],
                    "retrieval": {"keywords": [regex], "pattern_probes": [regex]}}
        self.patterns = [pattern("CASE-980", "a980", "alpha"),
                         pattern("CASE-981", "a981", "beta")]
        self.patterns[0]["status"] = "retired"
        self.patterns[0]["merged_into"] = "CASE-981"
        self.rows = [
            {"event_id": "E1", "incident_id": "INC-1", "case_id": "CASE-980",
             "timestamp": "2026-01-01", "source": "hids", "log_id": "L1", "content": "alpha"},
            {"event_id": "E2", "incident_id": "INC-2", "case_id": "CASE-981",
             "timestamp": "2026-01-02", "source": "hids", "log_id": "L2", "content": "beta"},
        ]
        self.links = [
            {"event_id": "E1", "incident_id": "INC-1", "case_id": "CASE-980", "step_id": "S1",
             "action_id": "a980", "link_status": "confirmed", "decided_at": "2026-01-01"},
            {"event_id": "E2", "incident_id": "INC-2", "case_id": "CASE-981", "step_id": "S1",
             "action_id": "a981", "link_status": "confirmed", "decided_at": "2026-01-02"},
        ]

    def run_lookup(self, argv):
        with mock.patch.object(lookup_case_logs, "load_patterns",
                               lambda: {"attack_patterns": self.patterns}), \
                mock.patch.object(lookup_case_logs, "read_csv", lambda path=None: self.rows), \
                mock.patch.object(lookup_case_logs, "read_links", lambda: self.links):
            return capture_main(lookup_case_logs, argv)

    def test_source_case_follows_alias_and_keeps_both_labels(self):
        stdout, code = self.run_lookup(["lookup_case_logs.py", "--case-id", "CASE-980",
                                        "--json"])
        self.assertIsNone(code)
        data = json.loads(stdout)
        self.assertEqual(data["case_id"], "CASE-980")
        self.assertEqual(data["alias_of"], "CASE-980")
        self.assertEqual(data["resolved_case_id"], "CASE-981")
        self.assertEqual(data["pattern_version"], 1)
        self.assertEqual(data["status"], "active")
        self.assertEqual(sorted(item["event_id"] for item in data["observations"]),
                         ["E1", "E2"])
        # Both confirmed incidents count under the resolved case, without double counting.
        self.assertEqual(data["derived_real_observations"], 2)

    def test_target_case_does_not_pull_in_the_alias(self):
        stdout, code = self.run_lookup(["lookup_case_logs.py", "--case-id", "CASE-981",
                                        "--json"])
        self.assertIsNone(code)
        data = json.loads(stdout)
        self.assertIsNone(data["alias_of"])
        self.assertEqual(data["resolved_case_id"], "CASE-981")
        self.assertEqual([item["event_id"] for item in data["observations"]], ["E2"])
        self.assertEqual(data["derived_real_observations"], 1)

    def test_alias_step_validation_accepts_steps_from_both_patterns(self):
        stdout, code = self.run_lookup(["lookup_case_logs.py", "--case-id", "CASE-980",
                                        "--step-id", "S1", "--json"])
        self.assertIsNone(code)
        self.assertEqual(json.loads(stdout)["step_id"], "S1")


class CorrectionsLedgerReadTests(unittest.TestCase):
    """The real corrections module read path, against a tempfile ledger."""

    def test_real_ledger_is_read_and_summarized(self):
        record = {
            "correction_id": "COR-0007", "incident_id": "INC-CASE-001-001",
            "case_id": "CASE-001", "decision": "reject_match", "reason_code": "generic_only",
            "event_ids": ["EVT-CASE001-01"], "basis": "shared generic probe only",
            "reviewer": "tester", "decided_at": "2026-10-30T00:00:00Z",
            "created_at": "2026-10-30T00:00:00Z",
        }
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "corrections.json"
            path.write_text(json.dumps({"schema_version": 1, "corrections": [record]}),
                            encoding="utf-8")
            with mock.patch.object(run_demo.corrections, "CORRECTIONS_PATH", path):
                items = run_demo.prior_rejections_for("CASE-001")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["correction_id"], "COR-0007")
        self.assertEqual(items[0]["reason_code"], "generic_only")
        self.assertIn("COR-0007", items[0]["summary"])
        self.assertIn("reject_match", items[0]["summary"])


if __name__ == "__main__":
    unittest.main()

"""Focus tests for T3: negative memory, signature grouping, candidate staging gates.

Covers backlog P1-2 (ungrouped signatures + external lexicon), P1-3 (correction
ledger), P2-1 (family ``any`` source) and P2-2 (staged-event validation).

Every write goes to a tempfile; ``demo/data`` is only ever read. Run from demo/::

    python -m unittest tests.test_memory_ops -v
"""
from __future__ import annotations

import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

DEMO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEMO_ROOT / "src"))

from attack_memory import candidates as candidates_module  # noqa: E402
from attack_memory import corrections as corrections_module  # noqa: E402
from attack_memory import families as families_module  # noqa: E402
from attack_memory import signatures as signatures_module  # noqa: E402
from attack_memory import storage  # noqa: E402

PATTERNS = [
    {"case_id": "CASE-001", "name": "Synthetic spring", "summary": "synthetic",
     "family_id": "web-exploit", "mitre": ["T1190"], "version": 1,
     "steps": [{"step_id": "S1", "order": 1, "action_id": "case001_probe",
                "label": "probe", "action_regex": r"(?i)probe",
                "expected_sources": ["waf"], "required": True}],
     "retrieval": {"keywords": ["probe"], "pattern_probes": ["probe"]}},
    {"case_id": "CASE-002", "name": "Synthetic second", "summary": "synthetic",
     "family_id": "host-persistence", "mitre": ["T1059"], "version": 1,
     "steps": [{"step_id": "S1", "order": 1, "action_id": "case002_probe",
                "label": "probe", "action_regex": r"(?i)probe",
                "expected_sources": ["hids"], "required": True}],
     "retrieval": {"keywords": ["probe"], "pattern_probes": ["probe"]}},
]

LOGS = [
    {"event_id": "EVT-A1", "incident_id": "INC-A", "case_id": "", "source": "waf",
     "content": "probe alpha one"},
    {"event_id": "EVT-A2", "incident_id": "INC-A", "case_id": "", "source": "waf",
     "content": "probe alpha two"},
    {"event_id": "EVT-B1", "incident_id": "INC-B", "case_id": "", "source": "hids",
     "content": "probe beta one"},
    {"event_id": "EVT-U1", "incident_id": "", "case_id": "", "source": "edr",
     "content": "probe unowned"},
]


class CorrectionLedgerTests(unittest.TestCase):
    def setUp(self):
        self._folder = tempfile.TemporaryDirectory()
        self.addCleanup(self._folder.cleanup)
        self.folder = pathlib.Path(self._folder.name)
        self.corrections_path = self.folder / "corrections.json"
        self.journal_path = self.folder / "ops_journal.jsonl"
        corrections_patch = mock.patch.object(
            corrections_module, "CORRECTIONS_PATH", self.corrections_path)
        corrections_patch.start()
        self.addCleanup(corrections_patch.stop)
        journal_patch = mock.patch.object(storage, "JOURNAL_PATH", self.journal_path)
        journal_patch.start()
        self.addCleanup(journal_patch.stop)

    def _add(self, **overrides):
        values = {
            "incident_id": "INC-A",
            "case_id": "CASE-001",
            "reason_code": "generic_only",
            "event_ids": ["EVT-A1"],
            "basis": "only a shared probe string; no case-specific step",
            "reviewer": "analyst",
            "patterns": PATTERNS,
            "logs": LOGS,
            "links": [],
        }
        values.update(overrides)
        return corrections_module.add_correction(**values)

    def test_add_persists_record_with_commit_and_journal(self):
        record = self._add()
        self.assertEqual(record["correction_id"], "COR-0001")
        self.assertEqual(record["decision"], "reject_match")
        self.assertEqual(record["reason_code"], "generic_only")
        self.assertEqual(record["event_ids"], ["EVT-A1"])
        self.assertTrue(record["created_at"])
        self.assertTrue(record["decided_at"])
        self.assertEqual(self._ledger()["corrections"], [record])
        journal = storage.load_journal(self.journal_path)
        pending = [item for item in journal if item.get("status") == "pending"]
        done = [item for item in journal if item.get("status") == "done"]
        self.assertTrue(any(item.get("kind") == "correction" for item in pending))
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0]["txn_id"], pending[0]["txn_id"])
        self.assertEqual(storage.audit_journal(self.journal_path), [])

    def _ledger(self):
        return corrections_module.load_corrections(self.corrections_path)

    def test_second_correction_gets_the_next_id(self):
        first = self._add()
        second = self._add(incident_id="INC-B", event_ids=["EVT-B1"], basis="wrong family")
        self.assertEqual(first["correction_id"], "COR-0001")
        self.assertEqual(second["correction_id"], "COR-0002")

    def test_list_and_for_case_filters(self):
        self._add()
        self._add(incident_id="INC-B", event_ids=["EVT-B1"], case_id="CASE-002",
                  reason_code="wrong_family", basis="belongs to another family")
        self.assertEqual(len(corrections_module.list_corrections()), 2)
        self.assertEqual(len(corrections_module.list_corrections(case_id="CASE-001")), 1)
        self.assertEqual(len(corrections_module.list_corrections(incident_id="INC-B")), 1)
        self.assertEqual(corrections_module.list_corrections(case_id="CASE-999"), [])
        self.assertEqual(len(corrections_module.for_case("CASE-001")), 1)
        self.assertEqual(len(corrections_module.for_case("CASE-001", "INC-A")), 1)
        self.assertEqual(corrections_module.for_case("CASE-001", "INC-B"), [])
        self.assertEqual(corrections_module.for_case(""), [])

    def test_summary_line_is_readable_and_complete(self):
        record = self._add()
        line = corrections_module.summary_line(record)
        for fragment in ("COR-0001", "reject_match", "CASE-001", "INC-A", "reason=generic_only",
                         "basis=", "reviewer=analyst"):
            self.assertIn(fragment, line)
        self.assertNotIn("\n", line)

    def test_reject_case_decision_is_allowed(self):
        record = self._add(decision="reject_case", reason_code="insufficient_evidence")
        self.assertEqual(record["decision"], "reject_case")

    def test_rejects_unknown_case(self):
        with self.assertRaisesRegex(ValueError, "unknown case_id"):
            self._add(case_id="CASE-999")

    def test_rejects_unknown_incident(self):
        with self.assertRaisesRegex(ValueError, "unknown incident_id"):
            self._add(incident_id="INC-NOPE")

    def test_rejects_unknown_event(self):
        with self.assertRaisesRegex(ValueError, "Unknown event_id"):
            self._add(event_ids=["EVT-NOPE"])

    def test_rejects_event_from_another_incident(self):
        with self.assertRaisesRegex(ValueError, "belongs to incident INC-B"):
            self._add(incident_id="INC-A", event_ids=["EVT-B1"])

    def test_rejects_invalid_reason_code(self):
        with self.assertRaisesRegex(ValueError, "unsupported reason_code"):
            self._add(reason_code="because_i_said_so")

    def test_rejects_invalid_decision(self):
        with self.assertRaisesRegex(ValueError, "unsupported decision"):
            self._add(decision="accept_match")

    def test_requires_non_empty_basis(self):
        with self.assertRaisesRegex(ValueError, "basis must not be empty"):
            self._add(basis="   ")

    def test_rejects_exact_duplicate(self):
        self._add()
        with self.assertRaisesRegex(ValueError, "already records this exact rejection"):
            self._add()

    def test_missing_ledger_is_an_empty_store_not_an_error(self):
        store = corrections_module.load_corrections(self.folder / "missing.json")
        self.assertEqual(store, {"schema_version": 1, "corrections": []})

    def test_audit_clean_ledger_and_injected_problems(self):
        self._add()
        self.assertEqual(corrections_module.audit_corrections(
            PATTERNS, LOGS, links=[]), [])
        broken = {
            "schema_version": 1,
            "corrections": [
                {"correction_id": "COR-9001", "incident_id": "INC-NOPE",
                 "case_id": "CASE-001", "decision": "reject_match",
                 "reason_code": "generic_only", "event_ids": [], "basis": "x",
                 "reviewer": "analyst", "decided_at": "2026-01-01T00:00:00Z"},
                {"correction_id": "COR-9002", "incident_id": "INC-A",
                 "case_id": "CASE-NOPE", "decision": "reject_match",
                 "reason_code": "made_up", "event_ids": ["EVT-NOPE"], "basis": "",
                 "reviewer": "", "decided_at": ""},
                {"correction_id": "COR-9002", "incident_id": "INC-A",
                 "case_id": "CASE-001", "decision": "reject_match",
                 "reason_code": "generic_only", "event_ids": ["EVT-B1"], "basis": "x",
                 "reviewer": "analyst", "decided_at": "2026-01-01T00:00:00Z"},
            ],
        }
        self.corrections_path.write_text(json.dumps(broken), encoding="utf-8")
        problems = corrections_module.audit_corrections(PATTERNS, LOGS, links=[])
        joined = "\n".join(problems)
        self.assertIn("unknown incident_id", joined)
        self.assertIn("unknown case_id", joined)
        self.assertIn("unsupported reason_code", joined)
        self.assertIn("unknown event_id", joined)
        self.assertIn("missing basis", joined)
        self.assertIn("missing reviewer", joined)
        self.assertIn("duplicate correction_id", joined)
        self.assertIn("belongs to incident INC-B", joined)


class SignatureGroupingTests(unittest.TestCase):
    def setUp(self):
        self._folder = tempfile.TemporaryDirectory()
        self.addCleanup(self._folder.cleanup)
        self.folder = pathlib.Path(self._folder.name)

    def test_candidate_without_terms_is_ungrouped(self):
        features = signatures_module.extract_features(
            "Mimikatz grabs LSASS credentials (sekurlsa::logonpasswords)",
            ["lsass access via mimikatz sekurlsa"], ["hids"], "host-persistence")
        self.assertEqual(features["signature_source"], "fallback")
        self.assertIsNone(features["signature_key"])
        self.assertEqual(features["signature_terms"], [])
        candidates = [
            {"candidate_id": "CAND-0001", "signature": "F3::mimikatz",
             "label": "Mimikatz", "family_id": "host-persistence", "status": "provisional",
             "signature_key": None, "signature_terms": [], "signature_source": "fallback"},
            {"candidate_id": "CAND-0002", "signature": "F3::lsass",
             "label": "LSASS dump", "family_id": "host-persistence", "status": "provisional",
             "signature_key": None, "signature_terms": [], "signature_source": "fallback"},
        ]
        groups = signatures_module.group_candidates(candidates)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["signature_key"], "ungrouped")
        self.assertTrue(groups[0]["ungrouped"])
        self.assertEqual(len(groups[0]["candidates"]), 2)
        for group in groups:
            for field in ("signature_key", "signature_source", "terms", "candidates"):
                self.assertIn(field, group)

    def test_legacy_hashed_fallback_still_goes_ungrouped(self):
        legacy = {"candidate_id": "CAND-0073", "signature": "FB::legacy",
                  "signature_key": "083ee70bc62f07f2", "signature_terms": []}
        grouped = {"candidate_id": "CAND-0001", "signature": "F1::spring",
                   "signature_key": "cb7586b1291ed571",
                   "signature_terms": ["CVE-2022-22965", "spring"]}
        groups = signatures_module.group_candidates([legacy, grouped])
        self.assertEqual(groups[-1]["signature_key"], "ungrouped")
        self.assertEqual([item["candidate_id"] for item in groups[-1]["candidates"]],
                         ["CAND-0073"])
        self.assertEqual(groups[0]["signature_key"], "cb7586b1291ed571")

    def test_same_technique_with_different_whitespace_groups(self):
        left = signatures_module.extract_features(
            "Spring4Shell CVE-2022-22965 class.module.classLoader writes JSP webshell",
            ["spring classloader probe"], ["waf"], "web-exploit")
        right = signatures_module.extract_features(
            "Spring4Shell   CVE-2022-22965 class.module.classLoader writes JSP webshell",
            ["spring   classloader probe"], ["waf"], "web-exploit")
        self.assertEqual(left["signature_source"], "terms")
        self.assertIsNotNone(left["signature_key"])
        self.assertEqual(left["signature_key"], right["signature_key"])

    def test_terms_candidates_keep_key_group_and_union_terms(self):
        features = signatures_module.extract_features(
            "Spring4Shell CVE-2022-22965 class.module.classLoader writes JSP webshell",
            ["spring classloader"], ["waf"], "web-exploit")
        candidates = [
            {"candidate_id": "CAND-0001", "signature": "F1::spring",
             "signature_key": features["signature_key"],
             "signature_source": "terms", "signature_terms": features["signature_terms"]},
            {"candidate_id": "CAND-0066", "signature": "F1::spring2",
             "signature_key": features["signature_key"],
             "signature_source": "terms", "signature_terms": ["extra-token"]},
        ]
        groups = signatures_module.group_candidates(candidates)
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0]["candidates"]), 2)
        self.assertIn("extra-token", groups[0]["terms"])

    def test_lexicon_file_extends_products_and_actions(self):
        lexicon_path = self.folder / "signature_lexicon.json"
        lexicon_path.write_text(json.dumps({
            "schema_version": 1,
            "products": {"acme-cms": r"\bacme\s+cms\b"},
            "actions": {"acme-rce": r"acme_rce"},
        }), encoding="utf-8")
        with mock.patch.object(signatures_module, "LEXICON_PATH", lexicon_path):
            features = signatures_module.extract_features(
                "ACME CMS acme_rce CVE-2024-1234", ["acme_cms exploit"],
                ["waf"], "web-exploit")
        self.assertEqual(features["lexicon_source"], "file")
        self.assertIn("acme-cms", features["products"])
        self.assertIn("acme-rce", features["actions"])
        self.assertIsNotNone(features["signature_key"])

    def test_missing_lexicon_falls_back_to_builtin(self):
        with mock.patch.object(signatures_module, "LEXICON_PATH",
                               self.folder / "does-not-exist.json"):
            lexicon = signatures_module.load_lexicon()
            features = signatures_module.extract_features(
                "Spring4Shell CVE-2022-22965", ["classloader"], ["waf"], "web-exploit")
        self.assertEqual(lexicon["source"], "builtin")
        self.assertEqual(features["lexicon_source"], "builtin")
        self.assertIn("spring", features["products"])

    def test_broken_lexicon_falls_back_to_builtin(self):
        lexicon_path = self.folder / "broken.json"
        lexicon_path.write_text("{not json", encoding="utf-8")
        with mock.patch.object(signatures_module, "LEXICON_PATH", lexicon_path):
            lexicon = signatures_module.load_lexicon()
        self.assertEqual(lexicon["source"], "builtin")
        self.assertIn("fallback_reason", lexicon)

    def test_invalid_lexicon_regex_falls_back_to_builtin(self):
        lexicon_path = self.folder / "bad_regex.json"
        lexicon_path.write_text(json.dumps({
            "schema_version": 1,
            "products": {"broken": "("},
            "actions": {"broken": "x"},
        }), encoding="utf-8")
        with mock.patch.object(signatures_module, "LEXICON_PATH", lexicon_path):
            lexicon = signatures_module.load_lexicon()
        self.assertEqual(lexicon["source"], "builtin")

    def test_real_candidate_store_has_one_visible_ungrouped_bucket(self):
        candidates = candidates_module.load_candidates()["candidates"]
        groups = signatures_module.group_candidates(candidates)
        self.assertEqual(groups[-1]["signature_key"], "ungrouped")
        self.assertTrue(groups[-1]["candidates"])
        spring = {candidate["candidate_id"]: candidate for candidate in candidates}
        pair = next(group for group in groups
                    if {"CAND-0001", "CAND-0066"}
                    <= {item["candidate_id"] for item in group["candidates"]})
        self.assertEqual(pair["signature_key"], spring["CAND-0001"]["signature_key"])


class CandidateStagingTests(unittest.TestCase):
    def setUp(self):
        self._folder = tempfile.TemporaryDirectory()
        self.addCleanup(self._folder.cleanup)
        self.folder = pathlib.Path(self._folder.name)
        self.candidate_path = self.folder / "case_candidates.json"

    def _stage(self, signature, label, incident_id, event_ids, **overrides):
        values = {"family_id": "web-exploit", "logs": LOGS, "links": [],
                  "path": self.candidate_path}
        values.update(overrides)
        return candidates_module.upsert_candidate(signature, label, incident_id,
                                                  event_ids, **values)

    def test_stage_accepts_owned_events_and_marks_unlinked_ones(self):
        candidate = self._stage("F1::spring", "Spring4Shell CVE-2022-22965", "INC-A",
                                ["EVT-A1", "EVT-U1"])
        self.assertEqual(candidate["status"], "provisional")
        incident = candidate["incidents"][0]
        self.assertEqual(incident["event_ids"], ["EVT-A1", "EVT-U1"])
        self.assertEqual(incident["unlinked_events"], ["EVT-U1"])
        self.assertEqual(candidate["signature_source"], "terms")
        self.assertTrue(candidate["signature_key"])
        self.assertEqual(candidates_module.audit_candidates([], path=self.candidate_path,
                                                            logs=LOGS), [])

    def test_stage_full_fallback_candidate_is_ungrouped(self):
        candidate = self._stage("F3::mimikatz", "Mimikatz grabs LSASS credentials",
                                "INC-B", ["EVT-B1"], family_id="host-persistence")
        self.assertEqual(candidate["signature_source"], "fallback")
        self.assertIsNone(candidate["signature_key"])
        self.assertEqual(candidate["signature_terms"], [])

    def test_stage_rejects_unknown_event(self):
        with self.assertRaisesRegex(ValueError, "do not exist"):
            self._stage("F1::x", "label", "INC-A", ["EVT-NOPE"])

    def test_stage_rejects_event_owned_by_another_incident(self):
        with self.assertRaisesRegex(ValueError, "already labeled incident INC-B"):
            self._stage("F1::x", "label", "INC-A", ["EVT-B1"])

    def test_stage_rejects_event_linked_to_another_incident(self):
        links = [{"event_id": "EVT-U1", "incident_id": "INC-B", "case_id": "CASE-002",
                  "step_id": "", "action_id": "", "link_status": "related",
                  "link_basis": "related variant", "decided_at": "2026-01-01T00:00:00Z"}]
        with self.assertRaisesRegex(ValueError, "linked to incident INC-B"):
            self._stage("F1::x", "label", "INC-A", ["EVT-U1"], links=links)

    def test_merge_ungrouped_requires_explicit_allow(self):
        first = self._stage("F3::mimikatz", "Mimikatz grabs LSASS credentials",
                            "INC-B", ["EVT-B1"], family_id="host-persistence")
        second = self._stage("F3::lsass", "LSASS memory dump via task manager",
                             "INC-A", ["EVT-A1"], family_id="host-persistence")
        with self.assertRaisesRegex(ValueError, "ungrouped"):
            candidates_module.merge_candidates(first["candidate_id"], second["candidate_id"],
                                               "same technique", path=self.candidate_path)
        merged = candidates_module.merge_candidates(
            first["candidate_id"], second["candidate_id"], "reviewed same technique",
            path=self.candidate_path, allow_ungrouped=True)
        self.assertEqual(merged["status"], "promotable")
        self.assertEqual(merged["signature_source"], "fallback")
        self.assertEqual(merged["aliases"], [second["candidate_id"]])
        self.assertEqual(candidates_module.audit_candidates(
            [], path=self.candidate_path, logs=LOGS), [])

    def test_merge_grouped_candidates_needs_no_override(self):
        first = self._stage("F1::spring", "Spring4Shell CVE-2022-22965", "INC-A",
                            ["EVT-A1"])
        second = self._stage("F1::spring2", "Spring4Shell CVE-2022-22965 exploit",
                             "INC-B", ["EVT-B1"])
        merged = candidates_module.merge_candidates(
            first["candidate_id"], second["candidate_id"], "same signature",
            path=self.candidate_path)
        self.assertEqual(merged["status"], "promotable")
        self.assertEqual(merged["signature_source"], "terms")

    def test_merge_rejects_different_signature_keys_when_grouped(self):
        first = self._stage("F1::spring", "Spring4Shell CVE-2022-22965", "INC-A",
                            ["EVT-A1"])
        second = self._stage("F1::ofbiz", "OFBiz XML-RPC CVE-2023-51467", "INC-B",
                             ["EVT-B1"])
        with self.assertRaisesRegex(ValueError, "different signature_key"):
            candidates_module.merge_candidates(
                first["candidate_id"], second["candidate_id"], "different",
                path=self.candidate_path)

    def test_audit_flags_unknown_events_and_inconsistent_unlinked_list(self):
        candidate_path = self.candidate_path
        candidate_path.write_text(json.dumps({
            "schema_version": 1,
            "candidates": [{
                "candidate_id": "CAND-0001", "signature": "F1::x", "label": "x",
                "family_id": "web-exploit", "status": "provisional",
                "incidents": [{"incident_id": "INC-A",
                               "event_ids": ["EVT-A1", "EVT-MISSING"],
                               "unlinked_events": ["EVT-OTHER"]}],
                "signature_source": "fallback", "signature_terms": [],
            }],
        }), encoding="utf-8")
        problems = candidates_module.audit_candidates([], path=candidate_path, logs=LOGS)
        joined = "\n".join(problems)
        self.assertIn("references unknown event", joined)
        self.assertIn("unlinked_events", joined)

    def test_audit_flags_fallback_with_terms(self):
        candidate_path = self.candidate_path
        candidate_path.write_text(json.dumps({
            "schema_version": 1,
            "candidates": [{
                "candidate_id": "CAND-0001", "signature": "F1::x", "label": "x",
                "family_id": "web-exploit", "status": "provisional",
                "incidents": [{"incident_id": "INC-A", "event_ids": ["EVT-A1"]}],
                "signature_source": "fallback", "signature_terms": ["spring"],
                "signature_key": None,
            }],
        }), encoding="utf-8")
        problems = candidates_module.audit_candidates([], path=candidate_path, logs=LOGS)
        self.assertTrue(any("fallback signature cannot carry" in problem
                            for problem in problems))

    def test_warnings_expose_ungrouped_but_audit_does_not_fail(self):
        self._stage("F3::mimikatz", "Mimikatz grabs LSASS credentials",
                    "INC-B", ["EVT-B1"], family_id="host-persistence")
        warnings = candidates_module.candidate_warnings(self.candidate_path)
        self.assertTrue(any("ungrouped" in warning for warning in warnings))
        self.assertEqual(candidates_module.audit_candidates(
            [], path=self.candidate_path, logs=LOGS), [])

    def test_real_candidate_warnings_are_non_fatal(self):
        patterns = storage.load_patterns()["attack_patterns"]
        self.assertEqual(candidates_module.audit_candidates(patterns), [])
        warnings = candidates_module.candidate_warnings()
        self.assertTrue(any("ungrouped" in warning for warning in warnings))


class FamilyEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.family = {
            "family_id": "web-exploit",
            "steps": [
                {"step_id": "S1", "action_id": "any_probe", "label": "any probe",
                 "generic": True, "action_regex": r"(?i)probe",
                 "expected_sources": ["any"]},
                {"step_id": "S2", "action_id": "waf_only", "label": "waf only",
                 "generic": False, "action_regex": r"(?i)wafonly",
                 "expected_sources": ["waf"]},
            ],
        }

    def test_any_source_step_surfaces_evidence(self):
        logs = [{"event_id": "EVT-1", "source": "edr", "content": "probe from edr"}]
        evidence = families_module.family_evidence(self.family, logs)
        self.assertEqual([item["step_id"] for item in evidence], ["S1"])
        self.assertEqual(evidence[0]["sources"], ["edr"])

    def test_specific_source_step_still_requires_that_source(self):
        logs = [{"event_id": "EVT-1", "source": "edr", "content": "wafonly from edr"}]
        evidence = families_module.family_evidence(self.family, logs)
        self.assertEqual(evidence, [])
        matching = [{"event_id": "EVT-2", "source": "waf", "content": "wafonly from waf"}]
        evidence = families_module.family_evidence(self.family, matching)
        self.assertEqual([item["step_id"] for item in evidence], ["S2"])

    def test_empty_expected_sources_behaves_like_any(self):
        family = {"family_id": "x", "steps": [
            {"step_id": "S1", "action_id": "a", "label": "a",
             "action_regex": r"(?i)probe", "expected_sources": []},
        ]}
        evidence = families_module.family_evidence(
            family, [{"event_id": "EVT-1", "source": "edr", "content": "probe"}])
        self.assertEqual(len(evidence), 1)


if __name__ == "__main__":
    unittest.main()

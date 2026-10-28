"""Regression tests for the attack-memory demo (stdlib unittest only).

Run from demo/:  python -m unittest discover -s tests -v
"""
from __future__ import annotations

import copy
import csv
import json
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

DEMO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEMO_ROOT / "src"))

from attack_memory import admissions as admissions_module  # noqa: E402
from attack_memory import candidates as candidates_module  # noqa: E402
from attack_memory import catalog as catalog_module  # noqa: E402
from attack_memory import evolution as evolution_module  # noqa: E402
from attack_memory import families as families_module  # noqa: E402
from attack_memory import links as links_module  # noqa: E402
from attack_memory import migrations as migrations_module  # noqa: E402
from attack_memory import signatures as signatures_module  # noqa: E402
from attack_memory import storage  # noqa: E402
from attack_memory.catalog import (add_pattern, add_pattern_from_candidate,  # noqa: E402
                                   load_validated_catalog, maturity, require_pattern_support,
                                   review_case)
from attack_memory.diagnostics import audit_problems, step_statistics, unexplained_events  # noqa: E402
from attack_memory.evolution import (accept_proposal, create_proposal, evaluate_proposal,  # noqa: E402
                                     load_proposals, reject_proposal, rollback_pattern)
from attack_memory.ingest import ingest  # noqa: E402
from attack_memory.links import (append_links, audit_links, derived_observations,  # noqa: E402
                                 related_incidents, support_pairs)
from attack_memory.retrieval import (build_action_index, extract_log_actions,  # noqa: E402
                                     match_pattern, retrieve)
from attack_memory.storage import (LINK_FIELDS, RAW_FIELDS, load_patterns, read_csv,  # noqa: E402
                                   read_links)
from lookup_case_logs import select_observations  # noqa: E402
from run_demo import filter_candidates, partition_logs  # noqa: E402

CASE008_INCIDENT = "INC-CASE008-001"


def case008_rows(logs):
    return [row for row in logs if row.get("incident_id") == CASE008_INCIDENT]


def mentioned_events(result):
    """Every event id the result mentions anywhere in its evidence."""
    events = set()
    for evidence in result["evidence"]:
        events.update(evidence["event_ids"])
    events.update(detection["event_id"] for detection in result["unaligned_detections"])
    events.update(mismatch["event_id"] for mismatch in result["source_mismatches"])
    return events


class CatalogTests(unittest.TestCase):
    def test_catalog_and_action_library_load(self):
        catalog = load_validated_catalog()
        self.assertGreaterEqual(len(catalog["attack_patterns"]), 8)
        build_action_index(catalog["attack_patterns"])

    def test_conflicting_action_regex_is_rejected(self):
        catalog = load_validated_catalog()["attack_patterns"]
        pattern = copy.deepcopy(catalog[0])
        pattern["case_id"] = "CASE-099"
        pattern["steps"] = [dict(catalog[0]["steps"][0], action_regex=r"only-this-token")]
        with self.assertRaisesRegex(ValueError, "conflicting action_regex"):
            build_action_index(catalog + [pattern])

    def test_shared_action_id_with_identical_regex_is_allowed(self):
        catalog = load_validated_catalog()["attack_patterns"]
        clone = copy.deepcopy(catalog[0])
        clone["case_id"] = "CASE-098"
        build_action_index(catalog + [clone])  # must not raise

    def test_conflicting_generic_flag_is_rejected(self):
        catalog = load_validated_catalog()["attack_patterns"]
        clone = copy.deepcopy(catalog[0])
        clone["case_id"] = "CASE-097"
        clone["steps"][0]["generic"] = not catalog[0]["steps"][0].get("generic", False)
        with self.assertRaisesRegex(ValueError, "conflicting generic"):
            build_action_index(catalog + [clone])

    def test_duplicate_action_id_inside_one_pattern_is_rejected(self):
        pattern = copy.deepcopy(load_validated_catalog()["attack_patterns"][0])
        pattern["steps"][1]["action_id"] = pattern["steps"][0]["action_id"]
        pattern["steps"][1]["action_regex"] = pattern["steps"][0]["action_regex"]
        with self.assertRaisesRegex(ValueError, "duplicate action_id"):
            storage.validate_pattern(pattern)

    def test_expected_sources_must_be_a_list(self):
        pattern = copy.deepcopy(load_validated_catalog()["attack_patterns"][0])
        pattern["steps"][0]["expected_sources"] = "waf"
        with self.assertRaisesRegex(ValueError, "expected_sources"):
            storage.validate_pattern(pattern)

    def test_regex_matching_everything_is_rejected(self):
        for bad in ("", ".*", r"\s*"):
            pattern = copy.deepcopy(load_validated_catalog()["attack_patterns"][0])
            pattern["steps"][0]["action_regex"] = bad
            with self.assertRaises(ValueError, msg=f"regex {bad!r} should be rejected"):
                storage.validate_pattern(pattern)

    def test_mitre_must_be_technique_ids(self):
        pattern = copy.deepcopy(load_validated_catalog()["attack_patterns"][0])
        pattern["mitre"] = "T1190"
        with self.assertRaisesRegex(ValueError, "mitre"):
            storage.validate_pattern(pattern)


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = load_validated_catalog()["attack_patterns"]
        cls.index = build_action_index(cls.patterns)
        cls.logs = read_csv(storage.RAW_LOGS_PATH)

    def test_every_seed_incident_retrieves_its_own_case_first(self):
        incidents = {}
        for row in self.logs:
            if row.get("case_id") and not (row.get("event_id") or "").startswith("SIM-"):
                incidents.setdefault(row["incident_id"], []).append(row)
        self.assertEqual(len(incidents), 8)
        for incident_id, rows in incidents.items():
            with self.subTest(incident=incident_id):
                results = retrieve(self.patterns, rows, self.index)
                self.assertTrue(results)
                self.assertEqual(results[0]["case_id"], rows[0]["case_id"])

    def test_case008_evidence_lists_every_observed_row(self):
        rows = case008_rows(self.logs)
        self.assertEqual(len(rows), 8)
        result = next(item for item in retrieve(self.patterns, rows, self.index)
                      if item["case_id"] == "CASE-008")
        self.assertEqual(mentioned_events(result), {row["event_id"] for row in rows})
        self.assertEqual(result["matched_steps"], 6)
        self.assertEqual(result["detected_steps"], 6)
        self.assertEqual(result["unaligned_detections"][0]["reason"], "extra_detection_for_S1")
        by_step = {evidence["step_id"]: evidence for evidence in result["evidence"]}
        self.assertEqual(by_step["S1"]["sources"], ["waf", "web"])
        self.assertEqual(by_step["S3"]["sources"], ["rasp", "web"])
        self.assertIn("WAF0410001", by_step["S1"]["event_ids"])
        self.assertIn("RASP0410004", by_step["S3"]["event_ids"])
        self.assertIsNotNone(by_step["S1"]["aligned_event_id"])

    def test_detected_but_out_of_order_step_is_not_called_unobserved(self):
        rows = copy.deepcopy(case008_rows(self.logs))
        dns = next(row for row in rows if row["event_id"] == "DNS0410008")
        dns["timestamp"] = "2026-10-14T07:00:00+08:00"
        result = next(item for item in retrieve(self.patterns, rows, self.index)
                      if item["case_id"] == "CASE-008")
        self.assertNotIn("S6", result["unobserved_steps"])
        self.assertEqual(result["detected_steps"], 6)
        self.assertIn("DNS0410008", {item["event_id"] for item in result["unaligned_detections"]})
        self.assertNotEqual(result["shape"], "complete")

    def test_unobserved_steps_still_reported_when_truly_absent(self):
        rows = [row for row in case008_rows(self.logs) if row["event_id"] != "HID0410006"]
        result = next(item for item in retrieve(self.patterns, rows, self.index)
                      if item["case_id"] == "CASE-008")
        self.assertIn("S4", result["unobserved_steps"])
        self.assertEqual(result["detected_steps"], 5)

    def test_source_mismatch_is_visible_and_not_counted_as_evidence(self):
        rows = copy.deepcopy(case008_rows(self.logs))
        target = next(row for row in rows if row["event_id"] == "HID0410007")
        target["source"] = "dns"
        result = next(item for item in retrieve(self.patterns, rows, self.index)
                      if item["case_id"] == "CASE-008")
        self.assertIn("HID0410007", {item["event_id"] for item in result["source_mismatches"]})
        self.assertNotIn("S5", [evidence["step_id"] for evidence in result["evidence"]])

    def test_pattern_caveats_reach_the_result(self):
        result = next(item for item in retrieve(self.patterns, case008_rows(self.logs), self.index)
                      if item["case_id"] == "CASE-008")
        self.assertIn("variant_note", result["pattern_scope"])
        self.assertTrue(result["negative_and_unknown_evidence"]["not_observed"])
        self.assertEqual(result["provenance"]["evidence_status"], "single_observation_demo")


class PartitionTests(unittest.TestCase):
    def test_unlabeled_batch_is_split_per_host(self):
        rows = []
        for suffix, host in (("a", "app-a.test"), ("b", "app-b.test")):
            for row in case008_rows(read_csv(storage.RAW_LOGS_PATH)):
                clone = dict(row, event_id=f"{suffix.upper()}-{row['event_id']}",
                             incident_id="", case_id="", batch_id="B-MIX",
                             content=row["content"].replace("host=app-web-31.ops-corp.com", f"host={host}"))
                rows.append(clone)
        groups = partition_logs(rows)
        self.assertEqual(len(groups), 2)
        self.assertTrue(all(kind == "unassigned host" for kind, _, _ in groups))
        patterns = load_validated_catalog()["attack_patterns"]
        index = build_action_index(patterns)
        for _, identifier, group_rows in groups:
            prefix = "A-" if "app-a" in identifier else "B-"
            result = next(item for item in retrieve(patterns, group_rows, index)
                          if item["case_id"] == "CASE-008")
            self.assertEqual(result["tier"], "strong")
            self.assertTrue(all(event.startswith(prefix) for event in mentioned_events(result)))

    def test_known_incident_is_not_split_across_hosts(self):
        rows = case008_rows(read_csv(storage.RAW_LOGS_PATH))
        rows[0]["content"] = rows[0]["content"].replace("host=app-web-31.ops-corp.com", "host=other.test")
        groups = partition_logs(rows)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0][0], "incident")


class LinkAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = load_validated_catalog()["attack_patterns"]
        cls.logs = read_csv(storage.RAW_LOGS_PATH)
        cls.links = read_links()

    def test_seed_links_are_clean(self):
        self.assertEqual(audit_links(self.patterns, self.logs, self.links), [])

    def test_confirmed_counts_are_derived_from_links(self):
        self.assertEqual(derived_observations(self.links, "CASE-008"), (1, 8))
        self.assertEqual(derived_observations(self.links, "CASE-005"), (2, 0))

    def test_wrong_step_is_detected(self):
        links = copy.deepcopy(self.links)
        target = next(link for link in links if link["event_id"] == "WAF0410001")
        target["step_id"] = "S6"
        problems = audit_links(self.patterns, self.logs, links)
        self.assertTrue(any("recorded step is wrong" in problem for problem in problems), problems)

    def test_wrong_action_id_is_detected(self):
        links = copy.deepcopy(self.links)
        links[0]["action_id"] = "something_else"
        problems = audit_links(self.patterns, self.logs, links)
        self.assertTrue(any("does not match" in problem for problem in problems), problems)

    def test_fixture_rows_are_unlabeled(self):
        fixtures = [row for row in self.logs if (row.get("batch_id") or "").startswith("BATCH-DEMO-SYNTHETIC")]
        self.assertEqual(len(fixtures), 8)
        self.assertTrue(all(not row["case_id"] for row in fixtures))
        latest = storage.latest_link_by_event(self.links)
        self.assertEqual(latest["EVT-SIM008-001"]["link_status"], "fixture")


class IngestTests(unittest.TestCase):
    def _write_input(self, folder, extra_row=""):
        source = pathlib.Path(folder) / "incoming.csv"
        source.write_text(
            "event_id,timestamp,source,log_id,content,incident_id\n"
            "EVT-DUP,2026-01-01T00:00:00+00:00,WAF,L1,hello,INC-CLAIMED\n" + extra_row,
            encoding="utf-8",
        )
        return source

    def test_incident_id_is_withheld_by_default(self):
        with tempfile.TemporaryDirectory() as folder:
            source = self._write_input(folder)
            destination = pathlib.Path(folder) / "raw.csv"
            count, withheld = ingest(source, destination)
            self.assertEqual((count, withheld), (1, 1))
            row = storage.read_csv(destination)[0]
            self.assertEqual(row["incident_id"], "")
            self.assertEqual(row["case_id"], "")
            self.assertTrue(row["event_id"].startswith("EVT-"))

    def test_incident_id_is_kept_only_when_explicitly_allowed(self):
        with tempfile.TemporaryDirectory() as folder:
            source = self._write_input(folder)
            destination = pathlib.Path(folder) / "raw.csv"
            count, withheld = ingest(source, destination, allow_incident_id=True)
            self.assertEqual((count, withheld), (1, 0))
            self.assertEqual(storage.read_csv(destination)[0]["incident_id"], "INC-CLAIMED")

    def test_duplicate_event_id_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            source = self._write_input(folder)
            destination = pathlib.Path(folder) / "raw.csv"
            ingest(source, destination)
            with self.assertRaisesRegex(ValueError, "duplicate append"):
                ingest(source, destination)


class LinkWriteTests(unittest.TestCase):
    def test_link_events_refuses_a_step_its_content_does_not_support(self):
        with tempfile.TemporaryDirectory() as folder:
            raw = pathlib.Path(folder) / "raw.csv"
            raw.write_text(",".join(storage.RAW_FIELDS) + "\n"
                           "EVT-X,,INC-X,,2026-01-01T00:00:00+00:00,waf,L1,完全无关的日志内容\n",
                           encoding="utf-8")
            links = pathlib.Path(folder) / "links.csv"
            with mock.patch.object(storage, "RAW_LOGS_PATH", raw), \
                    mock.patch.object(storage, "LINKS_PATH", links):
                with self.assertRaisesRegex(ValueError, "do not match"):
                    append_links(["EVT-X"], "INC-X", "CASE-008", "S1",
                                               "candidate", "guessing")
                written = append_links(["EVT-X"], "INC-X", "CASE-008", "S1",
                                                     "candidate", "reviewed exception", force=True)
            self.assertEqual(written, 1)
            self.assertEqual(len(storage.read_csv(links)), 1)


class StorageTests(unittest.TestCase):
    def test_update_labels_preserves_columns_and_line_endings(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "raw.csv"
            header = ",".join(storage.RAW_FIELDS + ["note"])
            lines = [
                "EVT-A,,,,2026-01-01T00:00:00+00:00,waf,L1,content-a,keepme",
                "EVT-B,,INC-1,CASE-001,2026-01-01T00:00:01+00:00,web,L2,content-b,keepme2",
            ]
            path.write_bytes((header + "\n" + "\n".join(lines) + "\n").encode("utf-8"))
            with mock.patch.object(storage, "RAW_LOGS_PATH", path):
                storage.update_event_labels({"EVT-A"}, "CASE-008", "INC-X", "confirmed")
                first = path.read_bytes()
                self.assertNotIn(b"\r\n", first)
                self.assertIn(b"keepme", first)
                parsed = storage.read_csv(path)
                self.assertEqual(parsed[0]["case_id"], "CASE-008")
                self.assertEqual(parsed[0]["incident_id"], "INC-X")
                self.assertEqual(parsed[0]["note"], "keepme")
                self.assertEqual(parsed[1]["case_id"], "CASE-001")
                storage.update_event_labels({"EVT-A"}, "CASE-008", "INC-X", "confirmed")
                self.assertEqual(path.read_bytes(), first)  # idempotent, no rewrite
                storage.update_event_labels({"EVT-A"}, "CASE-008", "INC-X", "rejected")
                self.assertEqual(storage.read_csv(path)[0]["case_id"], "")

    def test_bare_incident_label_can_be_withdrawn(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "raw.csv"
            path.write_text(",".join(storage.RAW_FIELDS) + "\n"
                            "EVT-C,,INC-OLD,,2026-01-01T00:00:00+00:00,waf,L1,content\n",
                            encoding="utf-8")
            with mock.patch.object(storage, "RAW_LOGS_PATH", path):
                storage.update_event_labels({"EVT-C"}, "CASE-008", "INC-OLD", "rejected")
                self.assertEqual(storage.read_csv(path)[0]["incident_id"], "")

    def test_append_refuses_a_different_header(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "raw.csv"
            path.write_text("a,b\n1,2\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "does not match expected fields"):
                storage.append_csv(path, ["b", "a"], [{"a": "3", "b": "4"}])

    def test_ragged_csv_is_rejected_with_a_clear_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "raw.csv"
            path.write_text("a,b\n1\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "fewer values"):
                storage.read_csv(path)


# ------------------------------------------------------- evolution / optimization


ALPHA_ACTION = "alpha_action"


def alpha_step(regex: str = "alpha", sources=("any",)) -> dict:
    return {"step_id": "S1", "order": 1, "action_id": ALPHA_ACTION, "label": "alpha",
            "action_regex": regex, "expected_sources": list(sources), "generic": False,
            "required": True}


def beta_step(required: bool) -> dict:
    return {"step_id": "S2", "order": 2, "action_id": "beta_action", "label": "beta",
            "action_regex": "beta", "expected_sources": ["any"], "generic": False,
            "required": required}


def default_events() -> dict:
    return {
        "INC-A": [("E-A1", "alpha one", "hids"), ("E-A2", "beta two", "hids")],
        "INC-B": [("E-B1", "alpha two", "hids"), ("E-B2", "beta three", "hids")],
        "INC-C": [("E-C1", "alpha three", "hids")],
    }


CONFIRMED_EVENTS = ["E-A1", "E-B1", "E-C1"]


def build_case_900(steps, incident_events, confirmed_events):
    """Synthetic CASE-900 catalog + logs + confirmed links for gate tests."""
    pattern = {
        "schema_version": "demo-1.1",
        "case_id": "CASE-900",
        "name": "synthetic evolving case",
        "summary": "synthetic case used by the proposal-gate tests",
        "mitre": ["T1190"],
        "steps": steps,
        "retrieval": {"keywords": ["alpha"], "pattern_probes": ["alpha"]},
        "negative_and_unknown_evidence": {"not_observed": [], "interpretation": "synthetic"},
        "provenance": {"evidence_status": "repeated"},
        "version": 1,
    }
    logs = []
    minute = 0
    for incident, events in incident_events.items():
        for event_id, content, source in events:
            logs.append({
                "event_id": event_id, "batch_id": "B-TEST", "incident_id": incident, "case_id": "",
                "timestamp": f"2026-01-01T00:{minute:02d}:00+00:00", "source": source,
                "log_id": event_id, "content": content,
            })
            minute += 1
    by_id = {row["event_id"]: row for row in logs}
    links = []
    for event_id in confirmed_events:
        row = by_id[event_id]
        row["case_id"] = "CASE-900"
        links.append({"event_id": event_id, "incident_id": row["incident_id"], "case_id": "CASE-900",
                      "step_id": "S1", "action_id": ALPHA_ACTION, "link_status": "confirmed",
                      "link_basis": "synthetic", "decided_at": "2026-01-01T00:00:00Z"})
    return [pattern], logs, links


class RequiredStepTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case008 = next(pattern for pattern in load_validated_catalog()["attack_patterns"]
                           if pattern["case_id"] == "CASE-008")
        cls.rows = case008_rows(read_csv(storage.RAW_LOGS_PATH))

    def match(self, pattern, rows):
        index = build_action_index([pattern])
        return match_pattern(pattern, rows, extract_log_actions(rows, index))

    def test_optional_step_missing_keeps_strong(self):
        pattern = copy.deepcopy(self.case008)
        pattern["steps"][5]["required"] = False
        rows = [row for row in self.rows if row["event_id"] != "DNS0410008"]
        result = self.match(pattern, rows)
        self.assertEqual(result["tier"], "strong")
        self.assertEqual(result["shape"], "complete")
        self.assertEqual(result["required_steps"], 5)
        self.assertEqual(result["matched_required_steps"], 5)
        self.assertEqual(result["unobserved_optional_steps"], ["S6"])
        self.assertEqual(result["unobserved_required_steps"], [])

    def test_missing_required_step_is_not_strong(self):
        pattern = copy.deepcopy(self.case008)
        rows = [row for row in self.rows if row["event_id"] != "HID0410006"]
        result = self.match(pattern, rows)
        self.assertNotEqual(result["tier"], "strong")
        self.assertIn("S4", result["unobserved_required_steps"])
        self.assertEqual(result["required_steps"], 6)

    def test_pattern_needs_at_least_one_required_step(self):
        pattern = copy.deepcopy(self.case008)
        for step in pattern["steps"]:
            step["required"] = False
        with self.assertRaisesRegex(ValueError, "at least one required step"):
            storage.validate_pattern(pattern)


class MetricsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = load_validated_catalog()["attack_patterns"]
        cls.logs = read_csv(storage.RAW_LOGS_PATH)
        cls.links = read_links()

    def test_ambiguous_step_is_reported(self):
        stats = step_statistics(self.patterns, self.logs, self.links)
        case004_s2 = next(item for item in stats
                          if item["case_id"] == "CASE-004" and item["step_id"] == "S2")
        self.assertGreaterEqual(case004_s2["matched"], 3)
        self.assertGreaterEqual(case004_s2["linked"], 1)
        self.assertEqual(case004_s2["ambiguity"],
                         case004_s2["matched"] - case004_s2["linked"])

    def test_seed_data_has_no_unexplained_events(self):
        found = unexplained_events(self.patterns, self.logs, self.links)
        self.assertTrue(all(not events for events in found.values()), found)

    def test_maturity_thresholds(self):
        self.assertEqual(maturity(0), "single_sample")
        self.assertEqual(maturity(1), "single_sample")
        self.assertEqual(maturity(2), "repeated")
        self.assertEqual(maturity(3), "validated")


class ProposalGateTests(unittest.TestCase):
    def setUp(self):
        self.patterns, self.logs, self.links = build_case_900(
            [alpha_step()], default_events(), CONFIRMED_EVENTS)

    def proposal(self, **overrides):
        base = {"case_id": "CASE-900", "base_version": 1, "operation": "add_step",
                "rationale": "two incidents continue into beta",
                "supporting_event_ids": ["E-A2", "E-B2"], "step": beta_step(False)}
        base.update(overrides)
        return base

    def evaluate(self, proposal):
        return evaluate_proposal(self.patterns, self.logs, self.links, proposal)

    def test_optional_completion_passes_and_is_auto_eligible(self):
        result = self.evaluate(self.proposal())
        self.assertTrue(result["ok"], result["problems"])
        self.assertTrue(result["auto_eligible"])
        self.assertEqual(result["metrics"]["support_incidents"], 2)
        self.assertEqual(result["metrics"]["strong_before"], 3)
        self.assertEqual(result["metrics"]["strong_after"], 3)

    def test_required_completion_that_drops_strong_is_rejected(self):
        result = self.evaluate(self.proposal(step=beta_step(True)))
        self.assertFalse(result["ok"])
        self.assertTrue(any("strong incidents would drop" in problem for problem in result["problems"]),
                        result["problems"])

    def test_single_incident_support_is_rejected(self):
        result = self.evaluate(self.proposal(supporting_event_ids=["E-A2"]))
        self.assertFalse(result["ok"])
        self.assertTrue(any("at least 2 independent incidents" in problem for problem in result["problems"]))

    def test_stale_base_version_is_rejected(self):
        result = self.evaluate(self.proposal(base_version=9))
        self.assertFalse(result["ok"])
        self.assertTrue(any("stale proposal" in problem for problem in result["problems"]))

    def test_foreign_match_is_rejected(self):
        foreign = {"event_id": "E-X1", "batch_id": "B", "incident_id": "INC-X", "case_id": "CASE-901",
                   "timestamp": "2026-01-01T01:00:00+00:00", "source": "hids",
                   "log_id": "E-X1", "content": "beta four"}
        result = evaluate_proposal(self.patterns, self.logs + [foreign], self.links,
                                                 self.proposal())
        self.assertFalse(result["ok"])
        self.assertTrue(any("other cases" in problem for problem in result["problems"]))

    def test_narrowing_extend_step_needs_human(self):
        patterns, logs, links = build_case_900([alpha_step("alpha|beta")], default_events(),
                                               CONFIRMED_EVENTS)
        proposal = {"case_id": "CASE-900", "base_version": 1, "operation": "extend_step",
                    "rationale": "narrow", "supporting_event_ids": ["E-A1"], "step_id": "S1",
                    "action_regex": "alpha"}
        result = evaluate_proposal(patterns, logs, links, proposal)
        self.assertFalse(result["ok"])
        self.assertTrue(any("narrowing" in problem for problem in result["problems"]))
        self.assertFalse(result["auto_eligible"])

    def test_broadening_extend_step_passes(self):
        proposal = self.proposal(operation="extend_step", step_id="S1", action_regex="alpha|beta")
        proposal.pop("step")
        result = self.evaluate(proposal)
        self.assertTrue(result["ok"], result["problems"])
        self.assertEqual(result["metrics"]["narrowing"], 0)

    def test_add_source_increases_coverage(self):
        patterns, logs, links = build_case_900([alpha_step("alpha", ["hids"])], default_events(),
                                               CONFIRMED_EVENTS)
        for row in logs:
            if row["event_id"] in ("E-B1", "E-C1"):
                row["source"] = "rasp"
        proposal = {"case_id": "CASE-900", "base_version": 1, "operation": "add_source",
                    "rationale": "same action on RASP", "supporting_event_ids": ["E-B1", "E-C1"],
                    "step_id": "S1", "add_sources": ["rasp"]}
        result = evaluate_proposal(patterns, logs, links, proposal)
        self.assertTrue(result["ok"], result["problems"])
        self.assertGreater(result["metrics"]["coverage_after"], result["metrics"]["coverage_before"])

    def test_set_required_demotion_passes_but_is_not_auto(self):
        patterns, logs, links = build_case_900([alpha_step(), beta_step(True)], default_events(),
                                               CONFIRMED_EVENTS)
        proposal = {"case_id": "CASE-900", "base_version": 1, "operation": "set_required",
                    "rationale": "only two incidents reach beta",
                    "supporting_event_ids": ["E-A1", "E-B1"], "step_id": "S2", "required": False}
        result = evaluate_proposal(patterns, logs, links, proposal)
        self.assertTrue(result["ok"], result["problems"])
        self.assertFalse(result["auto_eligible"])
        self.assertEqual(result["metrics"]["strong_before"], 2)
        self.assertEqual(result["metrics"]["strong_after"], 3)

    def test_demoting_a_universal_step_is_rejected(self):
        patterns, logs, links = build_case_900([alpha_step(), beta_step(True)],
                                               {"INC-A": [("E-A1", "alpha one", "hids"),
                                                          ("E-A2", "beta two", "hids")],
                                                "INC-B": [("E-B1", "alpha two", "hids"),
                                                          ("E-B2", "beta three", "hids")]},
                                               ["E-A1", "E-B1"])
        proposal = {"case_id": "CASE-900", "base_version": 1, "operation": "set_required",
                    "rationale": "demote anyway", "supporting_event_ids": ["E-A1", "E-B1"],
                    "step_id": "S2", "required": False}
        result = evaluate_proposal(patterns, logs, links, proposal)
        self.assertFalse(result["ok"])
        self.assertTrue(any("every confirmed incident" in problem for problem in result["problems"]))


class ProposalLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = pathlib.Path(self.folder.name)
        self.patterns_path = root / "attack_patterns.json"
        self.raw_path = root / "raw_logs.csv"
        self.links_path = root / "event_pattern_links.csv"
        self.proposals_path = root / "pattern_proposals.json"
        self.versions_dir = root / "pattern_versions"
        patterns, logs, links = build_case_900([alpha_step()], default_events(), CONFIRMED_EVENTS)
        self.patterns_path.write_text(
            json.dumps({"schema_version": "demo-1.1", "attack_patterns": patterns}, ensure_ascii=False),
            encoding="utf-8")
        with self.raw_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=RAW_FIELDS)
            writer.writeheader()
            writer.writerows(logs)
        with self.links_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=LINK_FIELDS)
            writer.writeheader()
            writer.writerows(links)
        for patcher in (
            mock.patch.object(storage, "PATTERNS_PATH", self.patterns_path),
            mock.patch.object(storage, "RAW_LOGS_PATH", self.raw_path),
            mock.patch.object(storage, "LINKS_PATH", self.links_path),
            mock.patch.object(evolution_module, "PROPOSALS_PATH", self.proposals_path),
            mock.patch.object(catalog_module, "VERSIONS_DIR", self.versions_dir),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def proposal(self, **overrides):
        base = {"case_id": "CASE-900", "base_version": 1, "operation": "add_step",
                "rationale": "two incidents continue into beta",
                "supporting_event_ids": ["E-A2", "E-B2"], "step": beta_step(False)}
        base.update(overrides)
        return base

    def catalog(self):
        return json.loads(self.patterns_path.read_text(encoding="utf-8"))["attack_patterns"]

    def audit(self):
        return audit_problems(
            load_validated_catalog()["attack_patterns"],
            read_csv(self.raw_path), read_links(self.links_path),
            load_proposals(self.proposals_path))

    def test_propose_accept_and_rollback(self):
        record, evaluation = create_proposal(self.proposal())
        self.assertEqual(record["status"], "ready", evaluation["problems"])
        result = accept_proposal(record["proposal_id"], "synthetic accept", auto=True)
        self.assertEqual((result["old_version"], result["new_version"]), (1, 2))
        self.assertTrue((self.versions_dir / "CASE-900" / "v001.json").exists())
        self.assertTrue((self.versions_dir / "CASE-900" / "v002.json").exists())
        self.assertEqual(len(self.catalog()[0]["steps"]), 2)
        self.assertEqual(self.catalog()[0]["version"], 2)
        self.assertEqual(self.audit(), [])
        rollback_pattern("CASE-900", 1, "synthetic rollback")
        self.assertEqual(len(self.catalog()[0]["steps"]), 1)
        self.assertEqual(self.catalog()[0]["version"], 1)
        self.assertEqual(self.audit(), [])

    def test_blocked_proposal_is_candidate_and_cannot_be_accepted(self):
        record, evaluation = create_proposal(self.proposal(supporting_event_ids=["E-A2"]))
        self.assertFalse(evaluation["ok"])
        self.assertEqual(record["status"], "candidate")
        with self.assertRaisesRegex(ValueError, "no longer passes the gate"):
            accept_proposal(record["proposal_id"], "too eager")
        reject_proposal(record["proposal_id"], "single incident only")
        proposals = load_proposals(self.proposals_path)
        self.assertEqual(proposals[0]["status"], "rejected")
        self.assertEqual(len(self.catalog()[0]["steps"]), 1)
        with self.assertRaisesRegex(ValueError, "rejected"):
            accept_proposal(record["proposal_id"], "again")

    def test_auto_is_refused_for_set_required(self):
        catalog = json.loads(self.patterns_path.read_text(encoding="utf-8"))
        catalog["attack_patterns"][0]["steps"].append(beta_step(True))
        self.patterns_path.write_text(json.dumps(catalog), encoding="utf-8")
        record, evaluation = create_proposal(self.proposal(
            operation="set_required", step_id="S2", required=False,
            supporting_event_ids=["E-A1", "E-B1"]))
        self.assertTrue(evaluation["ok"], evaluation["problems"])
        self.assertFalse(evaluation["auto_eligible"])
        with self.assertRaisesRegex(ValueError, "not eligible for --auto"):
            accept_proposal(record["proposal_id"], "auto attempt", auto=True)
        accept_proposal(record["proposal_id"], "explicit human accept")
        self.assertFalse(self.catalog()[0]["steps"][1]["required"])


class LinkTimestampTests(unittest.TestCase):
    def test_append_links_stamps_decided_at(self):
        with tempfile.TemporaryDirectory() as folder:
            raw = pathlib.Path(folder) / "raw.csv"
            raw.write_text(",".join(RAW_FIELDS) + "\n"
                           "EVT-X,,INC-X,CASE-008,2026-01-01T00:00:00+00:00,waf,L1,"
                           "host=x POST /ecp/7b37f0/ecp.aspx X-BEResource=localhost 502\n",
                           encoding="utf-8")
            links = pathlib.Path(folder) / "links.csv"
            with mock.patch.object(storage, "RAW_LOGS_PATH", raw), \
                    mock.patch.object(storage, "LINKS_PATH", links):
                append_links(["EVT-X"], "INC-X", "CASE-008", "S1", "candidate",
                                           "synthetic", force=True)
            row = storage.read_csv(links)[0]
            self.assertTrue(row["decided_at"].endswith("Z"))

    def test_latest_link_prefers_decided_at_over_file_order(self):
        links = [
            {"event_id": "E1", "decided_at": "2026-01-02T00:00:00Z", "link_status": "confirmed"},
            {"event_id": "E1", "decided_at": "2026-01-01T00:00:00Z", "link_status": "candidate"},
        ]
        self.assertEqual(storage.latest_link_by_event(links)["E1"]["link_status"], "confirmed")


class WeakKindTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = load_validated_catalog()["attack_patterns"]
        cls.logs = read_csv(storage.RAW_LOGS_PATH)

    def result_for(self, rows, case_id):
        return next(item for item in retrieve(self.patterns, rows) if item["case_id"] == case_id)

    def test_generic_only(self):
        rows = [row for row in self.logs if row["event_id"] == "EVT-CASE002-05"]
        result = self.result_for(rows, "CASE-002")
        self.assertEqual(result["tier"], "weak")
        self.assertEqual(result["weak_kind"], "generic_only")

    def test_prefix(self):
        rows = [row for row in self.logs if row["event_id"] == "EVT-CASE001-01"]
        result = self.result_for(rows, "CASE-001")
        self.assertEqual(result["weak_kind"], "prefix")

    def test_tail(self):
        rows = [row for row in self.logs if row["event_id"] == "EVT-CASE004-04"]
        result = self.result_for(rows, "CASE-004")
        self.assertEqual(result["weak_kind"], "tail")

    def test_mismatch_only(self):
        row = {"event_id": "E-M", "incident_id": "INC-M", "case_id": "",
               "timestamp": "2026-01-01T00:00:00+00:00", "source": "waf", "log_id": "L",
               "content": '{"viewFile":"phar:///tmp/a.phar"}'}
        result = self.result_for([row], "CASE-004")
        self.assertEqual(result["tier"], "weak")
        self.assertEqual(result["weak_kind"], "mismatch_only")

    def test_chain_results_have_no_weak_kind(self):
        result = self.result_for(case008_rows(self.logs), "CASE-008")
        self.assertEqual(result["tier"], "strong")
        self.assertIsNone(result["weak_kind"])


class MinTierTests(unittest.TestCase):
    def test_filter_by_min_tier(self):
        results = [{"tier": "strong"}, {"tier": "medium"}, {"tier": "weak"}, {"tier": "keyword_only"}]
        self.assertEqual([item["tier"] for item in filter_candidates(results, "medium")],
                         ["strong", "medium"])
        self.assertEqual([item["tier"] for item in filter_candidates(results, "weak")],
                         ["strong", "medium", "weak"])
        self.assertEqual(len(filter_candidates(results, "keyword_only")), 4)


class RecallFilterTests(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"event_id": "E1", "incident_id": "INC-A", "case_id": "CASE-008"},
            {"event_id": "E2", "incident_id": "INC-A", "case_id": ""},
            {"event_id": "E3", "incident_id": "INC-B", "case_id": "CASE-008"},
        ]
        self.latest = {
            "E1": {"link_status": "confirmed", "case_id": "CASE-008", "step_id": "S1"},
            "E2": {"link_status": "fixture", "case_id": "CASE-008", "step_id": "S4"},
            "E3": {"link_status": "confirmed", "case_id": "CASE-008", "step_id": "S4"},
        }

    def ids(self, selected):
        return [row["event_id"] for row, _ in selected]

    def test_step_filter_returns_only_that_step(self):
        selected, hidden = select_observations(self.rows, self.latest,
                                               case_id="CASE-008", step_id="S4")
        self.assertEqual(self.ids(selected), ["E3"])
        self.assertEqual(hidden, 0)

    def test_step_filter_can_include_fixtures(self):
        selected, _ = select_observations(self.rows, self.latest, case_id="CASE-008",
                                          step_id="S4", include_fixtures=True)
        self.assertEqual(self.ids(selected), ["E2", "E3"])

    def test_exclude_current_incident(self):
        selected, _ = select_observations(self.rows, self.latest, case_id="CASE-008",
                                          exclude_incident="INC-B")
        self.assertEqual(self.ids(selected), ["E1"])

    def test_status_filter(self):
        selected, _ = select_observations(self.rows, self.latest, case_id="CASE-008",
                                          status="confirmed")
        self.assertEqual(self.ids(selected), ["E1", "E3"])


class OrderSemanticsTests(unittest.TestCase):
    def test_optional_step_does_not_break_required_order(self):
        patterns = load_validated_catalog()["attack_patterns"]
        base = next(pattern for pattern in patterns if pattern["case_id"] == "CASE-005")
        candidate = copy.deepcopy(base)
        # Compare against the required skeleton, independent of any evolved optional steps.
        candidate["steps"] = [step for step in candidate["steps"] if step.get("required", True)]
        candidate["steps"].append({
            "step_id": "S99", "order": 99, "action_id": "sim_optional_probe",
            "label": "sim optional", "action_regex": "(?i)vssadmin|cipher",
            "expected_sources": ["hids"], "generic": True, "required": False,
        })
        rows = [row for row in read_csv(storage.RAW_LOGS_PATH)
                if row["incident_id"] == "INC-CASE-005-001"]
        index = build_action_index([candidate])
        result = match_pattern(candidate, rows, extract_log_actions(rows, index))
        self.assertEqual(result["tier"], "strong")
        self.assertTrue(result["order_ok"])
        self.assertTrue(result["order_assessable"])


class RelatedAssociationTests(unittest.TestCase):
    def test_related_link_does_not_label_or_require_a_step(self):
        with tempfile.TemporaryDirectory() as folder:
            raw = pathlib.Path(folder) / "raw.csv"
            raw.write_text(",".join(RAW_FIELDS) + "\n"
                           "EVT-X,,INC-X,,2026-01-01T00:00:00+00:00,hids,L1,"
                           "vssadmin delete shadows /all\n", encoding="utf-8")
            links = pathlib.Path(folder) / "links.csv"
            with mock.patch.object(storage, "RAW_LOGS_PATH", raw), \
                    mock.patch.object(storage, "LINKS_PATH", links):
                append_links(["EVT-X"], "INC-X", "CASE-005", "", "related",
                                           "same ransomware family, different tooling")
                rows = storage.read_csv(raw)
            link = storage.read_csv(links)[0]
            self.assertEqual(link["link_status"], "related")
            self.assertEqual(link["step_id"], "")
            self.assertEqual(link["action_id"], "")
            self.assertEqual(rows[0]["case_id"], "")
            self.assertEqual(rows[0]["incident_id"], "INC-X")
            patterns = load_validated_catalog()["attack_patterns"]
            self.assertEqual(audit_links(patterns, rows, [link]), [])
            self.assertIn(("INC-X", "CASE-005"), support_pairs([link]))
            self.assertEqual(related_incidents([link], "CASE-005"), {"INC-X"})

    def test_related_incident_can_support_a_proposal(self):
        patterns, logs, links = build_case_900([alpha_step()], default_events(), CONFIRMED_EVENTS)
        for link in links:
            if link["event_id"] == "E-B1":
                link["link_status"] = "related"
        proposal = {"case_id": "CASE-900", "base_version": 1, "operation": "add_step",
                    "rationale": "beta continues in a related incident",
                    "supporting_event_ids": ["E-A2", "E-B2"], "step": beta_step(False)}
        result = evaluate_proposal(patterns, logs, links, proposal)
        self.assertTrue(result["ok"], result["problems"])
        self.assertEqual(result["metrics"]["support_incidents"], 2)
        self.assertEqual(result["metrics"]["related_incidents"], 1)


class AddPatternSupportTests(unittest.TestCase):
    def setUp(self):
        self.pattern = {"steps": [{"action_regex": "alpha"}]}
        self.logs = [
            {"incident_id": "INC-A", "content": "alpha one"},
            {"incident_id": "INC-B", "content": "beta two"},
            {"incident_id": "INC-C", "content": "alpha three"},
        ]

    def test_singleton_support_is_refused(self):
        with self.assertRaisesRegex(ValueError, "at least 2 supporting incidents"):
            require_pattern_support(self.pattern, ["INC-A"], self.logs)
        with self.assertRaisesRegex(ValueError, "at least 2 supporting incidents"):
            require_pattern_support(self.pattern, [], self.logs)

    def test_two_matching_incidents_pass(self):
        self.assertEqual(require_pattern_support(self.pattern, ["INC-A", "INC-C"], self.logs),
                         ["INC-A", "INC-C"])

    def test_unmatched_or_unknown_incident_is_refused(self):
        with self.assertRaisesRegex(ValueError, "does not|no event"):
            require_pattern_support(self.pattern, ["INC-A", "INC-B"], self.logs)
        with self.assertRaisesRegex(ValueError, "unknown"):
            require_pattern_support(self.pattern, ["INC-A", "INC-NOPE"], self.logs)

    def test_force_allows_a_reviewed_singleton(self):
        self.assertEqual(require_pattern_support(self.pattern, ["INC-A"], self.logs, force=True),
                         ["INC-A"])
        self.assertEqual(require_pattern_support(self.pattern, [], self.logs, force=True), [])


class CandidateStoreTests(unittest.TestCase):
    def test_single_incident_is_provisional_and_two_are_promotable(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "case_candidates.json"
            first = candidates_module.upsert_candidate("sig", "label", "INC-1", ["E1"], path=path)
            self.assertEqual(first["status"], "provisional")
            again = candidates_module.upsert_candidate("sig", "label", "INC-1", ["E1"], path=path)
            self.assertEqual(len(again["incidents"]), 1)
            second = candidates_module.upsert_candidate("sig", "label", "INC-2", ["E2"], path=path)
            self.assertEqual(second["candidate_id"], first["candidate_id"])
            self.assertEqual(second["status"], "promotable")
            self.assertEqual(candidates_module.counts(path)["promotable"], 1)

    def test_singleton_promotion_needs_force_and_marks_candidate(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = pathlib.Path(folder)
            candidate_path = folder / "case_candidates.json"
            catalog_path = folder / "attack_patterns.json"
            catalog_path.write_text(json.dumps({"attack_patterns": []}), encoding="utf-8")
            rows = [row for row in read_csv(storage.RAW_LOGS_PATH)
                    if row.get("incident_id") == "INC-CASE-001-001"]
            self.assertTrue(rows)
            candidate = candidates_module.upsert_candidate(
                "singleton", "singleton", "INC-CAND-950",
                [row["event_id"] for row in rows], path=candidate_path)
            pattern = {
                "case_id": "CASE-950", "name": "Synthetic singleton", "summary": "synthetic",
                "mitre": ["T1190"],
                "steps": [{"step_id": "S1", "order": 1, "action_id": "case950_probe",
                           "label": "JNDI probe", "action_regex": "(?i)jndi",
                           "expected_sources": ["waf"], "required": True}],
                "retrieval": {"keywords": ["jndi"], "pattern_probes": ["jndi"]},
                "provenance": {"evidence_status": "synthetic"},
            }
            pattern_path = folder / "pattern.json"
            pattern_path.write_text(json.dumps(pattern), encoding="utf-8")
            with mock.patch.object(storage, "PATTERNS_PATH", catalog_path), \
                    mock.patch.object(candidates_module, "CANDIDATES_PATH", candidate_path), \
                    mock.patch.object(admissions_module, "ADMISSIONS_PATH",
                                      folder / "case_admissions.json"):
                with self.assertRaisesRegex(ValueError, "promotion needs"):
                    add_pattern_from_candidate(candidate["candidate_id"], pattern_path)
                case_id, promoted = add_pattern_from_candidate(
                    candidate["candidate_id"], pattern_path, force=True)
            self.assertEqual(case_id, "CASE-950")
            self.assertEqual(promoted["candidate_id"], candidate["candidate_id"])
            self.assertEqual(
                candidates_module.get_candidate(candidate["candidate_id"], path=candidate_path)["status"],
                "promoted")

    def test_two_incidents_promote_without_force(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = pathlib.Path(folder)
            candidate_path = folder / "case_candidates.json"
            catalog_path = folder / "attack_patterns.json"
            catalog_path.write_text(json.dumps({"attack_patterns": []}), encoding="utf-8")
            for incident in ("INC-CASE-001-001", "INC-CASE-002-001"):
                rows = [row for row in read_csv(storage.RAW_LOGS_PATH)
                        if row.get("incident_id") == incident]
                candidates_module.upsert_candidate(
                    "broad", "broad", incident, [row["event_id"] for row in rows],
                    path=candidate_path)
            pattern = {
                "case_id": "CASE-951", "name": "Synthetic repeated", "summary": "synthetic",
                "mitre": ["T1190"],
                "steps": [{"step_id": "S1", "order": 1, "action_id": "case951_probe",
                           "label": "any letter", "action_regex": "(?i)[a-z]",
                           "expected_sources": ["waf"], "required": True}],
                "retrieval": {"keywords": ["alpha"], "pattern_probes": ["alpha"]},
                "provenance": {"evidence_status": "synthetic"},
            }
            pattern_path = folder / "pattern.json"
            pattern_path.write_text(json.dumps(pattern), encoding="utf-8")
            with mock.patch.object(storage, "PATTERNS_PATH", catalog_path), \
                    mock.patch.object(candidates_module, "CANDIDATES_PATH", candidate_path), \
                    mock.patch.object(admissions_module, "ADMISSIONS_PATH",
                                      folder / "case_admissions.json"):
                case_id, candidate = add_pattern_from_candidate("CAND-0001", pattern_path)
            self.assertEqual(case_id, "CASE-951")
            self.assertEqual(len(candidate["incidents"]), 2)
            self.assertEqual(
                candidates_module.get_candidate("CAND-0001", path=candidate_path)["status"],
                "promoted")

    def test_audit_flags_a_promoted_candidate_without_a_case(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "case_candidates.json"
            candidates_module.upsert_candidate("sig", "label", "INC-1", ["E1"], path=path)
            candidates_module.mark_promoted("CAND-0001", "CASE-999", path=path)
            problems = candidates_module.audit_candidates([], path=path)
            self.assertTrue(any("missing case" in problem for problem in problems))


class FamilyRegistryTests(unittest.TestCase):
    def test_real_families_match_catalog(self):
        patterns = load_validated_catalog()["attack_patterns"]
        data = families_module.load_families()
        self.assertEqual(families_module.validate_families(data, patterns), [])
        self.assertTrue(all(pattern.get("family_id") for pattern in patterns))

    def test_unknown_family_is_reported(self):
        data = {"families": [{"family_id": "web-exploit", "case_ids": ["CASE-001"]}]}
        patterns = [{"case_id": "CASE-001", "family_id": "web-exploit"},
                    {"case_id": "CASE-002", "family_id": "nope"}]
        problems = families_module.validate_families(data, patterns)
        self.assertTrue(any("unknown family_id" in problem for problem in problems))

    def test_candidate_unknown_family_is_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "case_candidates.json"
            candidates_module.upsert_candidate("sig", "label", "INC-1", ["E1"],
                                               family_id="nope", path=path)
            problems = candidates_module.audit_candidates([], path=path,
                                                          family_ids={"web-exploit"})
            self.assertTrue(any("unknown family_id" in problem for problem in problems))

    def test_extracted_steps_left_the_case(self):
        patterns = {pattern["case_id"]: pattern
                    for pattern in load_validated_catalog()["attack_patterns"]}
        self.assertEqual(patterns["CASE-005"]["version"], 3)
        self.assertEqual(patterns["CASE-007"]["version"], 3)
        self.assertNotIn("S9", {step["step_id"] for step in patterns["CASE-005"]["steps"]})
        self.assertNotIn("S4", {step["step_id"] for step in patterns["CASE-007"]["steps"]})

    def test_family_steps_surface_variant_evidence(self):
        family = next(item for item in families_module.load_families()["families"]
                      if item["family_id"] == "ransomware")
        rows = [row for row in read_csv(storage.RAW_LOGS_PATH)
                if row.get("incident_id") == "INC-CASE-005-001"]
        evidence = families_module.family_evidence(family, rows)
        self.assertTrue(any(item["step_id"] == "S9" for item in evidence))

    def test_family_step_cannot_be_confirmed(self):
        with self.assertRaisesRegex(ValueError, "family step"):
            append_links(["EVT-CASE005-02"], "INC-CASE-005-001", "CASE-005", "S9",
                         "confirmed", "family steps are related-only")


class CandidateMergeTests(unittest.TestCase):
    def _pair(self, path):
        first = candidates_module.upsert_candidate(
            "sig-a", "A", "INC-1", ["E1"], family_id="web-exploit", path=path)
        second = candidates_module.upsert_candidate(
            "sig-b", "B", "INC-2", ["E2"], family_id="web-exploit", path=path)
        data = candidates_module.load_candidates(path)
        for candidate in data["candidates"]:
            candidate["signature_key"] = "key"
        candidates_module.save_candidates(data, path)
        return first, second

    def test_merge_makes_a_promotable_primary_and_split_restores_it(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "case_candidates.json"
            first, second = self._pair(path)
            merged = candidates_module.merge_candidates(
                first["candidate_id"], second["candidate_id"], "same key", path=path)
            self.assertEqual(merged["status"], "promotable")
            self.assertEqual(len(merged["incidents"]), 2)
            self.assertEqual(merged["aliases"], [second["candidate_id"]])
            self.assertEqual(candidates_module.get_candidate(
                second["candidate_id"], path=path)["status"], "merged")
            self.assertEqual(candidates_module.audit_candidates(
                [], path=path, family_ids={"web-exploit"}), [])
            candidates_module.split_candidate(
                first["candidate_id"], second["candidate_id"], "wrong merge", path=path)
            self.assertEqual(candidates_module.get_candidate(
                first["candidate_id"], path=path)["status"], "provisional")
            self.assertEqual(candidates_module.get_candidate(
                second["candidate_id"], path=path)["status"], "provisional")
            self.assertEqual(candidates_module.get_candidate(
                first["candidate_id"], path=path)["aliases"], [])

    def test_merge_into_promoted_keeps_status_and_marks_pending_label(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "case_candidates.json"
            first, second = self._pair(path)
            candidates_module.mark_promoted(first["candidate_id"], "CASE-999", path=path)
            merged = candidates_module.merge_candidates(
                first["candidate_id"], second["candidate_id"], "same key", path=path)
            self.assertEqual(merged["status"], "promoted")
            self.assertEqual(merged["pending_case_links"], ["INC-2"])
            self.assertEqual(candidates_module.audit_candidates(
                [{"case_id": "CASE-999"}], path=path, family_ids={"web-exploit"}), [])
            with self.assertRaisesRegex(ValueError, "promoted cluster"):
                candidates_module.split_candidate(
                    first["candidate_id"], second["candidate_id"], "no", path=path)


class SignatureTests(unittest.TestCase):
    def _features(self, candidate_id):
        candidate = next(item for item in candidates_module.load_candidates()["candidates"]
                         if item["candidate_id"] == candidate_id)
        rows_by_id = {row["event_id"]: row for row in read_csv(storage.RAW_LOGS_PATH)}
        rows = [rows_by_id[event_id] for incident in candidate["incidents"]
                for event_id in incident["event_ids"]]
        return signatures_module.extract_features(
            candidate["label"], [row["content"] for row in rows],
            [row["source"] for row in rows], candidate["family_id"])

    def test_spring4shell_pair_shares_a_key(self):
        first = self._features("CAND-0001")
        second = self._features("CAND-0066")
        self.assertEqual(first["signature_key"], second["signature_key"])
        self.assertIn("CVE-2022-22965", first["cves"])

    def test_ofbiz_same_cve_different_technique_stays_apart(self):
        xmlrpc = self._features("CAND-0007")
        groovy = self._features("CAND-0068")
        self.assertNotEqual(xmlrpc["signature_key"], groovy["signature_key"])

    def test_product_alone_does_not_merge_php_variants(self):
        keys = {self._features(candidate)["signature_key"]
                for candidate in ("CAND-0010", "CAND-0013", "CAND-0060")}
        self.assertEqual(len(keys), 3)

    def test_group_candidates_pairs_spring4shell(self):
        candidates = candidates_module.load_candidates()["candidates"]
        groups = signatures_module.group_candidates(candidates)
        pair = next(group for group in groups
                    if {"CAND-0001", "CAND-0066"} <= {item["candidate_id"]
                                                       for item in group["candidates"]})
        self.assertEqual(len(pair["candidates"]), 2)

    def test_real_duplicate_groups_are_reviewable_clusters(self):
        promotable = candidates_module.list_candidates(status="promotable")
        self.assertGreaterEqual(len(promotable), 6)
        self.assertTrue(all(len(item["incidents"]) >= 2 for item in promotable))
        self.assertTrue(all(item.get("aliases") for item in promotable))
        self.assertEqual(candidates_module.audit_candidates(
            load_validated_catalog()["attack_patterns"]), [])

    def test_promoted_spring4shell_cluster_has_pending_case_link(self):
        spring = candidates_module.get_candidate("CAND-0001")
        self.assertEqual(spring["status"], "promoted")
        self.assertEqual(spring["promoted_case_id"], "CASE-009")
        self.assertIn("SIM-INC-1073", spring.get("pending_case_links") or [])
        self.assertIn("CAND-0066", spring.get("aliases") or [])


class MigrationLedgerTests(unittest.TestCase):
    def test_real_migration_ledger_is_clean(self):
        patterns = load_validated_catalog()["attack_patterns"]
        records = migrations_module.load_migrations()["migrations"]
        self.assertEqual(len(records), 2)
        self.assertEqual(migrations_module.audit_migrations(patterns), [])

    def test_missing_snapshot_is_reported(self):
        patterns = load_validated_catalog()["attack_patterns"]
        record = {"migration_id": "MIG-TEST", "case_id": "CASE-005", "from_version": 2,
                  "to_version": 99, "kind": "move_step_to_family", "step_id": "S9",
                  "family_id": "ransomware", "snapshot": "pattern_versions/NOPE.json"}
        problems = migrations_module.audit_migrations_for_record(record, patterns)
        self.assertTrue(any("snapshot is missing" in problem for problem in problems))

    def test_move_step_still_in_case_is_reported(self):
        patterns = load_validated_catalog()["attack_patterns"]
        record = {"migration_id": "MIG-TEST", "case_id": "CASE-005", "from_version": 2,
                  "to_version": 3, "kind": "move_step_to_family", "step_id": "S1",
                  "family_id": "ransomware", "snapshot": "pattern_versions/CASE-005/v003.json"}
        problems = migrations_module.audit_migrations_for_record(record, patterns)
        self.assertTrue(any("still in CASE-005" in problem for problem in problems))


class AdmissionTests(unittest.TestCase):
    def test_added_case_is_unreviewed_until_review(self):
        with tempfile.TemporaryDirectory() as folder:
            folder = pathlib.Path(folder)
            catalog_path = folder / "attack_patterns.json"
            admissions_path = folder / "case_admissions.json"
            catalog_path.write_text(json.dumps({"attack_patterns": []}), encoding="utf-8")
            pattern = {
                "case_id": "CASE-960", "name": "Synthetic admission", "summary": "synthetic",
                "mitre": ["T1190"],
                "steps": [{"step_id": "S1", "order": 1, "action_id": "case960_probe",
                           "label": "alpha", "action_regex": "(?i)alpha",
                           "expected_sources": ["waf"], "required": True}],
                "retrieval": {"keywords": ["alpha"], "pattern_probes": ["alpha"]},
            }
            pattern_path = folder / "pattern.json"
            pattern_path.write_text(json.dumps(pattern), encoding="utf-8")
            with mock.patch.object(storage, "PATTERNS_PATH", catalog_path), \
                    mock.patch.object(admissions_module, "ADMISSIONS_PATH", admissions_path):
                add_pattern(pattern_path, force=True)
                added = next(item for item in load_validated_catalog()["attack_patterns"]
                             if item["case_id"] == "CASE-960")
                self.assertEqual(added["review_status"], "unreviewed")
                self.assertEqual(added["admission_id"], "ADM-CASE-960")
                self.assertEqual(
                    admissions_module.get_admission("CASE-960", path=admissions_path)["status"],
                    "unreviewed")
                review_case("CASE-960", "reviewed in test", reviewer="tester")
                reviewed = next(item for item in load_validated_catalog()["attack_patterns"]
                                if item["case_id"] == "CASE-960")
                self.assertNotIn("review_status", reviewed)
                self.assertEqual(reviewed["admission_id"], "ADM-CASE-960")
                record = admissions_module.get_admission("CASE-960", path=admissions_path)
                self.assertEqual(record["status"], "reviewed")
                self.assertEqual(record["reviewed_by"], "tester")
                self.assertEqual(admissions_module.audit_admissions(
                    [reviewed], path=admissions_path), [])

    def test_real_case009_is_unreviewed(self):
        patterns = load_validated_catalog()["attack_patterns"]
        case9 = next(item for item in patterns if item["case_id"] == "CASE-009")
        self.assertEqual(case9["review_status"], "unreviewed")
        self.assertEqual(admissions_module.audit_admissions(patterns), [])

    def test_unreviewed_marker_without_admission_is_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            path = pathlib.Path(folder) / "case_admissions.json"
            problems = admissions_module.audit_admissions(
                [{"case_id": "CASE-999", "review_status": "unreviewed"}], path=path)
            self.assertTrue(any("no admission record" in problem for problem in problems))


if __name__ == "__main__":
    unittest.main()

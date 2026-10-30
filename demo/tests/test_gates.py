"""Regression tests for the T2 trust gates (stdlib unittest only).

Every test here runs against a temporary clone of the store: no test may write
``demo/data``. Each gate has a positive and a rejecting case:

* forced links: reviewed exception ledger, basis required, orphan detection;
* new-case support: required-step union coverage, per-incident coverage, force singleton;
* version snapshots: v001 on creation, audit, idempotent backfill;
* evolution: optional-by-default add_step, owner-based foreign checks, held-out gate;
* repair: derived labels, missing snapshots, orphan admissions, idempotency.
"""
from __future__ import annotations

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
from attack_memory import lifecycle as lifecycle_module  # noqa: E402
from attack_memory import links as links_module  # noqa: E402
from attack_memory import repair as repair_module  # noqa: E402
from attack_memory import storage  # noqa: E402


# ---------------------------------------------------------------------------
# Synthetic store helpers
# ---------------------------------------------------------------------------

def make_step(step_id: str, order: int, action_id: str, regex: str,
              required: bool = True, sources=("any",), generic: bool = False) -> dict:
    return {"step_id": step_id, "order": order, "action_id": action_id, "label": step_id,
            "action_regex": regex, "expected_sources": list(sources), "generic": generic,
            "required": required}


def make_pattern(case_id: str, steps: list[dict], keywords: list[str] | None = None,
                 **extra) -> dict:
    pattern = {
        "case_id": case_id,
        "name": f"synthetic {case_id}",
        "summary": f"synthetic case {case_id}",
        "mitre": ["T1190"],
        "steps": steps,
        "retrieval": {"keywords": keywords or [steps[0]["action_regex"]]},
        "provenance": {"evidence_status": "synthetic"},
        "version": 1,
    }
    pattern.update(extra)
    return pattern


def make_log(event_id: str, incident_id: str, content: str, source: str = "hids",
             case_id: str = "", minute: int = 0, batch_id: str = "B-TEST") -> dict:
    return {"event_id": event_id, "batch_id": batch_id, "incident_id": incident_id,
            "case_id": case_id, "timestamp": f"2026-01-01T00:{minute:02d}:00+00:00",
            "source": source, "log_id": event_id, "content": content}


def make_link(event_id: str, incident_id: str, case_id: str, step_id: str,
              action_id: str, status: str = "confirmed", basis: str = "synthetic",
              decided_at: str = "2026-01-01T00:00:00Z") -> dict:
    return {"event_id": event_id, "incident_id": incident_id, "case_id": case_id,
            "step_id": step_id, "action_id": action_id, "link_status": status,
            "link_basis": basis, "decided_at": decided_at}


def base_fixture() -> tuple[list[dict], list[dict], list[dict]]:
    """CASE-900 (alpha, hids) + CASE-901 (delta); confirmed A/B/C, related D1."""
    patterns = [
        make_pattern("CASE-900", [make_step("S1", 1, "alpha900", "alpha")], ["alpha"]),
        make_pattern("CASE-901", [make_step("S1", 1, "delta901", "delta")], ["delta"]),
    ]
    logs = [
        make_log("E-A1", "INC-A", "alpha one", "hids", "CASE-900", 0),
        make_log("E-A2", "INC-A", "beta two", "hids", "", 1),
        make_log("E-B1", "INC-B", "alpha two", "hids", "CASE-900", 2),
        make_log("E-B2", "INC-B", "beta three", "hids", "", 3),
        make_log("E-C1", "INC-C", "alpha three", "hids", "CASE-900", 4),
        make_log("E-D1", "INC-R", "delta four", "hids", "", 5),
        make_log("E-X1", "INC-X", "alpha foreign", "rasp", "CASE-901", 6),
    ]
    links = [
        make_link("E-A1", "INC-A", "CASE-900", "S1", "alpha900"),
        make_link("E-B1", "INC-B", "CASE-900", "S1", "alpha900"),
        make_link("E-C1", "INC-C", "CASE-900", "S1", "alpha900"),
        make_link("E-D1", "INC-R", "CASE-901", "", "", status="related",
                  basis="variant of another technique"),
    ]
    return patterns, logs, links


def three_step_pattern() -> dict:
    return make_pattern("CASE-950", [
        make_step("S1", 1, "alpha950", "alpha"),
        make_step("S2", 2, "beta950", "beta"),
        make_step("S3", 3, "gamma950", "gamma"),
    ], ["alpha"])


def three_step_events() -> dict:
    return {
        "INC-A": [make_log("E-A1", "INC-A", "alpha one", minute=0),
                  make_log("E-A2", "INC-A", "beta two", minute=1),
                  make_log("E-A3", "INC-A", "gamma three", minute=2)],
        "INC-B": [make_log("E-B1", "INC-B", "alpha four", minute=3)],
    }


class GateStoreTestCase(unittest.TestCase):
    """Temporary store with every path constant redirected."""

    def setUp(self) -> None:
        self._folder = tempfile.TemporaryDirectory()
        self.addCleanup(self._folder.cleanup)
        root = pathlib.Path(self._folder.name)
        self.patterns_path = root / "attack_patterns.json"
        self.raw_path = root / "raw_logs.csv"
        self.links_path = root / "event_pattern_links.csv"
        self.candidates_path = root / "case_candidates.json"
        self.versions_dir = root / "pattern_versions"
        self.proposals_path = root / "pattern_proposals.json"
        self.admissions_path = root / "case_admissions.json"
        self.exceptions_path = root / "link_exceptions.json"
        self.journal_path = root / "ops_journal.jsonl"
        self.repair_log_path = root / "repair_log.json"
        self.lifecycle_path = root / "case_lifecycle.json"
        for patcher in (
            mock.patch.object(storage, "PATTERNS_PATH", self.patterns_path),
            mock.patch.object(storage, "RAW_LOGS_PATH", self.raw_path),
            mock.patch.object(storage, "LINKS_PATH", self.links_path),
            mock.patch.object(storage, "JOURNAL_PATH", self.journal_path),
            mock.patch.object(catalog_module, "VERSIONS_DIR", self.versions_dir),
            mock.patch.object(evolution_module, "PROPOSALS_PATH", self.proposals_path),
            mock.patch.object(admissions_module, "ADMISSIONS_PATH", self.admissions_path),
            mock.patch.object(links_module, "LINK_EXCEPTIONS_PATH", self.exceptions_path),
            mock.patch.object(candidates_module, "CANDIDATES_PATH", self.candidates_path),
            mock.patch.object(candidates_module, "RAW_LOGS_PATH", self.raw_path),
            mock.patch.object(candidates_module, "LINKS_PATH", self.links_path),
            mock.patch.object(lifecycle_module, "LIFECYCLE_PATH", self.lifecycle_path),
            mock.patch.object(repair_module, "REPAIR_LOG_PATH", self.repair_log_path),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    # -- store writers ------------------------------------------------------
    def write_store(self, patterns: list[dict], logs: list[dict], links: list[dict],
                    snapshots: bool = True) -> None:
        self.patterns_path.write_text(
            json.dumps({"schema_version": "demo-1.1", "attack_patterns": patterns},
                       ensure_ascii=False), encoding="utf-8")
        self.write_csv(self.raw_path, storage.RAW_FIELDS, logs)
        self.write_csv(self.links_path, storage.LINK_FIELDS, links)
        if snapshots:
            for pattern in patterns:
                for number in range(1, catalog_module.pattern_version(pattern) + 1):
                    path = catalog_module.version_path(pattern["case_id"], number)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(json.dumps(catalog_module.snapshot_payload(pattern, number)),
                                    encoding="utf-8")

    @staticmethod
    def write_csv(path: pathlib.Path, fields: list[str], rows: list[dict]) -> None:
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def write_pattern_file(self, pattern: dict, name: str = "new_pattern.json") -> pathlib.Path:
        path = pathlib.Path(self._folder.name) / name
        path.write_text(json.dumps(pattern, ensure_ascii=False), encoding="utf-8")
        return path

    # -- store readers ------------------------------------------------------
    def patterns(self) -> list[dict]:
        return json.loads(self.patterns_path.read_text(encoding="utf-8-sig"))["attack_patterns"]

    def logs(self) -> list[dict]:
        return storage.read_csv(self.raw_path)

    def link_rows(self) -> list[dict]:
        return storage.read_links(self.links_path)

    def audit_problems(self) -> list[str]:
        patterns = catalog_module.load_validated_catalog()["attack_patterns"]
        logs = storage.read_csv(storage.RAW_LOGS_PATH)
        link_rows = storage.read_links(storage.LINKS_PATH)
        problems = links_module.audit_links(patterns, logs, link_rows)
        problems += links_module.audit_link_exceptions(link_rows)
        problems += catalog_module.audit_versions(patterns)
        problems += catalog_module.audit_aliases(patterns)
        problems += admissions_module.audit_admissions(patterns)
        return problems

    def load_proposals(self) -> list[dict]:
        return evolution_module.load_proposals(self.proposals_path)

    def committed_transactions(self) -> list[dict]:
        """Merge each pending record (kind/summary) with its done record (files)."""
        records = storage.load_journal()
        pending = {record.get("txn_id"): record for record in records
                   if record.get("status") == "pending"}
        merged = []
        for done in records:
            if done.get("status") != "done":
                continue
            transaction = dict(pending.get(done.get("txn_id"), {}))
            transaction.update({"txn_id": done.get("txn_id"),
                                "files": done.get("files") or []})
            merged.append(transaction)
        return merged


# ---------------------------------------------------------------------------
# I4 forced links / exception ledger
# ---------------------------------------------------------------------------

class ForceExceptionTests(GateStoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        patterns, logs, links = base_fixture()
        logs.append(make_log("E-NM", "INC-NM", "completely unrelated payload", "hids", "", 9))
        logs.append(make_log("E-CONF", "INC-CONF", "alpha candidate", "hids", "", 10))
        self.write_store(patterns, logs, links)
        self.patterns_data = patterns
        self.logs_data = logs + []

    def force_append(self, event_id: str, basis: str, status: str = "candidate",
                     **kwargs) -> int:
        return links_module.append_links([event_id], "INC-NM", "CASE-900", "S1", status,
                                         basis, force=True, **kwargs)

    def test_forced_link_with_basis_is_auditable_and_counted(self):
        self.force_append("E-NM", "reviewed: source log truncated the payload")
        exceptions = links_module.load_exceptions()["exceptions"]
        self.assertEqual(len(exceptions), 1)
        self.assertEqual(exceptions[0]["event_id"], "E-NM")
        self.assertEqual(exceptions[0]["reviewer"], "analyst")
        self.assertTrue(exceptions[0]["basis"])
        self.assertTrue(exceptions[0]["decided_at"].endswith("Z"))
        rows = self.link_rows()
        self.assertEqual(len(rows), len(base_fixture()[2]) + 1)
        self.assertEqual(links_module.audit_links(self.patterns_data, self.logs(), rows), [])
        self.assertEqual(len(links_module.force_exceptions(rows)), 1)
        self.assertEqual(links_module.audit_link_exceptions(rows), [])

    def test_forced_link_without_basis_is_rejected_before_any_write(self):
        before = len(self.link_rows())
        with self.assertRaisesRegex(ValueError, "basis"):
            links_module.append_links(["E-NM"], "INC-NM", "CASE-900", "S1", "candidate",
                                      "", force=True)
        self.assertEqual(len(self.link_rows()), before)
        self.assertFalse(self.exceptions_path.exists())

    def test_unforced_mismatch_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "do not match"):
            links_module.append_links(["E-NM"], "INC-NM", "CASE-900", "S1", "candidate",
                                      "no force")
        self.assertFalse(self.exceptions_path.exists())

    def test_matching_link_needs_no_exception(self):
        links_module.append_links(["E-CONF"], "INC-CONF", "CASE-900", "S1", "candidate",
                                  "clean match", force=True)
        self.assertFalse(self.exceptions_path.exists())
        self.assertEqual(links_module.force_exceptions(self.link_rows()), [])

    def test_exception_for_a_different_key_does_not_waive_the_problem(self):
        self.force_append("E-NM", "reviewed exception")
        ledger = links_module.load_exceptions()
        ledger["exceptions"][0]["step_id"] = "S2"  # no such link row
        self.exceptions_path.write_text(json.dumps(ledger), encoding="utf-8")
        rows = self.link_rows()
        problems = links_module.audit_links(self.patterns_data, self.logs(), rows)
        self.assertTrue(any("action_regex" in problem for problem in problems), problems)

    def test_orphan_exception_is_reported(self):
        ledger = {"schema_version": 1, "exceptions": [{
            "event_id": "EVT-GHOST", "incident_id": "INC-GHOST", "case_id": "CASE-900",
            "step_id": "S1", "decided_at": "2026-01-01T00:00:00Z",
            "basis": "reviewed exception", "reviewer": "analyst"}]}
        self.exceptions_path.write_text(json.dumps(ledger), encoding="utf-8")
        problems = links_module.audit_link_exceptions(self.link_rows())
        self.assertTrue(any("no matching link row" in problem for problem in problems), problems)
        self.assertEqual(links_module.force_exceptions(self.link_rows()), [])

    def test_exception_without_basis_is_a_problem(self):
        self.force_append("E-NM", "reviewed exception")
        ledger = links_module.load_exceptions()
        ledger["exceptions"][0]["basis"] = ""
        self.exceptions_path.write_text(json.dumps(ledger), encoding="utf-8")
        problems = links_module.audit_link_exceptions(self.link_rows())
        self.assertTrue(any("missing basis" in problem for problem in problems), problems)
        # audit_links must not waive on an unexplained exception.
        problems = links_module.audit_links(self.patterns_data, self.logs(), self.link_rows())
        self.assertTrue(any("action_regex" in problem for problem in problems), problems)

    def test_forced_confirmed_link_updates_labels_in_one_transaction(self):
        links_module.append_links(["E-CONF"], "INC-CONF", "CASE-900", "S1", "confirmed",
                                  "clean reviewed link")
        row = next(item for item in self.logs() if item["event_id"] == "E-CONF")
        self.assertEqual(row["case_id"], "CASE-900")
        self.assertEqual(row["incident_id"], "INC-CONF")
        journal = storage.load_journal()
        done = [record for record in journal if record.get("status") == "done"]
        self.assertEqual(len(done), 1)
        transaction = self.committed_transactions()[0]
        self.assertEqual(transaction["kind"], "link_append")
        applied = transaction["files"]
        self.assertTrue(any(path.endswith("raw_logs.csv") for path in applied), applied)
        self.assertTrue(any(path.endswith("event_pattern_links.csv") for path in applied), applied)

    def test_conflicting_label_is_rejected_without_partial_write(self):
        before = len(self.link_rows())
        with self.assertRaisesRegex(ValueError, "already has case_id"):
            links_module.append_links(["E-X1"], "INC-X", "CASE-900", "S1", "confirmed",
                                      "wrong owner")
        self.assertEqual(len(self.link_rows()), before)
        self.assertEqual(storage.load_journal(), [])

    def test_rejected_force_link_needs_no_exception(self):
        links_module.append_links(["E-NM"], "INC-NM", "CASE-900", "S1", "rejected",
                                  "reviewed rejection of a non-matching hint", force=True)
        self.assertFalse(self.exceptions_path.exists())
        self.assertEqual(links_module.audit_links(self.patterns_data, self.logs(),
                                                  self.link_rows()), [])


# ---------------------------------------------------------------------------
# I5 new-case support gate
# ---------------------------------------------------------------------------

class PatternSupportGateTests(GateStoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.write_store([], [], [])

    def report(self, incidents, force=False, events=None):
        return catalog_module.pattern_support_report(
            three_step_pattern(), incidents, [], force=force,
            events_by_incident=events or three_step_events())

    def test_one_of_three_steps_is_rejected(self):
        events = {"INC-A": [make_log("E-A1", "INC-A", "alpha one")],
                  "INC-B": [make_log("E-B1", "INC-B", "alpha two")]}
        with self.assertRaisesRegex(ValueError, "required step"):
            self.report(["INC-A", "INC-B"], events=events)

    def test_complementary_incidents_cover_the_required_union(self):
        events = {
            "INC-A": [make_log("E-A1", "INC-A", "alpha one", minute=0),
                      make_log("E-A2", "INC-A", "beta two", minute=1)],
            "INC-B": [make_log("E-B1", "INC-B", "gamma three", minute=2)],
        }
        report = self.report(["INC-A", "INC-B"], events=events)
        self.assertEqual(report["covered_required"], ["S1", "S2", "S3"])
        self.assertEqual(report["missing_required"], [])
        self.assertEqual(report["coverage"]["INC-A"]["tier"], "medium")
        self.assertEqual(report["coverage"]["INC-B"]["coverage"], 0.333)
        self.assertFalse(report["single_sample"])

    def test_union_without_a_strong_medium_incident_is_rejected(self):
        events = {
            "INC-A": [make_log("E-A1", "INC-A", "alpha one", minute=0)],
            "INC-B": [make_log("E-B1", "INC-B", "beta two", minute=1)],
            "INC-C": [make_log("E-C1", "INC-C", "gamma three", minute=2)],
        }
        with self.assertRaisesRegex(ValueError, "strong/medium"):
            self.report(["INC-A", "INC-B", "INC-C"], events=events)

    def test_singleton_support_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least 2 supporting incidents"):
            self.report(["INC-A"])

    def test_force_singleton_records_partial_coverage(self):
        events = {"INC-A": [make_log("E-A1", "INC-A", "alpha one", minute=0)]}
        report = self.report(["INC-A"], force=True, events=events)
        self.assertTrue(report["single_sample"])
        self.assertEqual(report["coverage"]["INC-A"]["coverage"], 0.333)
        self.assertEqual(report["missing_required"], ["S2", "S3"])

    def test_unknown_incident_is_rejected_even_with_force(self):
        with self.assertRaisesRegex(ValueError, "unknown or unlabeled"):
            self.report(["INC-GHOST"], force=True)

    def test_add_pattern_rejects_partial_coverage_without_writing(self):
        pattern_file = self.write_pattern_file(three_step_pattern())
        events = {"INC-A": [make_log("E-A1", "INC-A", "alpha one")],
                  "INC-B": [make_log("E-B1", "INC-B", "alpha two")]}
        with self.assertRaisesRegex(ValueError, "required step"):
            catalog_module.add_pattern(pattern_file, ["INC-A", "INC-B"],
                                       events_by_incident=events)
        self.assertEqual(self.patterns(), [])
        self.assertFalse(self.admissions_path.exists())
        self.assertFalse(self.versions_dir.exists())
        self.assertEqual(storage.load_journal(), [])

    def test_add_pattern_writes_v001_provenance_and_support_coverage(self):
        pattern_file = self.write_pattern_file(three_step_pattern())
        events = three_step_events()
        case_id = catalog_module.add_pattern(pattern_file, ["INC-A", "INC-B"],
                                             events_by_incident=events)
        self.assertEqual(case_id, "CASE-950")
        added = self.patterns()[0]
        self.assertEqual(added["version"], 1)
        self.assertEqual(added["review_status"], "unreviewed")
        self.assertTrue(added["provenance"]["created_at"])
        self.assertTrue(added["provenance"]["updated_at"])
        self.assertEqual(added["provenance"]["admission_id"], added["admission_id"])
        snapshot = json.loads((self.versions_dir / "CASE-950" / "v001.json")
                              .read_text(encoding="utf-8-sig"))
        self.assertEqual(snapshot["version"], 1)
        self.assertNotIn("review_status", snapshot)
        admission = admissions_module.get_admission("CASE-950")
        self.assertFalse(admission["single_sample"])
        self.assertEqual(admission["support_coverage"]["per_incident"]["INC-B"]["coverage"], 0.333)
        journal = self.committed_transactions()
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0]["kind"], "catalog_add")
        self.assertEqual(len(journal[0]["files"]), 3)
        self.assertEqual(self.audit_problems(), [])

    def test_force_singleton_admission_is_marked_single_sample(self):
        pattern_file = self.write_pattern_file(three_step_pattern())
        events = {"INC-A": [make_log("E-A1", "INC-A", "alpha one")]}
        catalog_module.add_pattern(pattern_file, ["INC-A"], force=True,
                                   events_by_incident=events)
        admission = admissions_module.get_admission("CASE-950")
        self.assertTrue(admission["single_sample"])
        self.assertEqual(admission["support_coverage"]["required_steps"], ["S1", "S2", "S3"])
        self.assertEqual(admission["support_coverage"]["missing_required"], ["S2", "S3"])
        self.assertEqual(
            admission["support_coverage"]["per_incident"]["INC-A"]["coverage"], 0.333)

    def test_promote_candidate_uses_every_incident_event(self):
        logs = three_step_events()["INC-A"] + three_step_events()["INC-B"]
        patterns, _, _ = base_fixture()
        self.write_store(patterns, logs, [], snapshots=True)
        candidates_module.upsert_candidate("sig", "sig", "INC-A", ["E-A1"])
        candidates_module.upsert_candidate("sig", "sig", "INC-B", ["E-B1"])
        pattern_file = self.write_pattern_file(three_step_pattern())
        case_id, candidate = catalog_module.add_pattern_from_candidate("CAND-0001", pattern_file)
        self.assertEqual(case_id, "CASE-950")
        self.assertEqual(candidate["status"], "promoted")
        self.assertEqual(candidates_module.get_candidate("CAND-0001")["status"], "promoted")
        self.assertTrue((self.versions_dir / "CASE-950" / "v001.json").exists())
        journal = self.committed_transactions()
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0]["kind"], "candidate_promote")
        applied = journal[0]["files"]
        self.assertTrue(any(path.endswith("case_candidates.json") for path in applied), applied)
        self.assertTrue(any(path.endswith("case_admissions.json") for path in applied), applied)

    def test_promote_candidate_counts_link_owned_related_events(self):
        """Evidence attached to an incident through a related link counts toward coverage."""
        logs = [
            make_log("E-A1", "INC-A", "alpha one", minute=0),
            make_log("E-A2", "", "beta two", minute=1),
            make_log("E-A3", "", "gamma three", minute=2),
            make_log("E-B1", "INC-B", "alpha four", minute=3),
        ]
        links = [
            make_link("E-A1", "INC-A", "CASE-950", "S1", "alpha950", status="related",
                      basis="staged evidence"),
            make_link("E-A2", "INC-A", "CASE-950", "S2", "beta950", status="related",
                      basis="staged evidence"),
            make_link("E-A3", "INC-A", "CASE-950", "S3", "gamma950", status="related",
                      basis="staged evidence"),
            make_link("E-B1", "INC-B", "CASE-950", "S1", "alpha950", status="related",
                      basis="staged evidence"),
        ]
        self.write_store([], logs, links, snapshots=True)
        candidates_module.upsert_candidate("sig", "sig", "INC-A", ["E-A1"])
        candidates_module.upsert_candidate("sig", "sig", "INC-B", ["E-B1"])
        pattern_file = self.write_pattern_file(three_step_pattern())
        case_id, _ = catalog_module.add_pattern_from_candidate("CAND-0001", pattern_file)
        self.assertEqual(case_id, "CASE-950")


# ---------------------------------------------------------------------------
# I3 version snapshots / aliases
# ---------------------------------------------------------------------------

class VersionSnapshotTests(GateStoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.patterns_data = base_fixture()[0]
        self.write_store(*base_fixture(), snapshots=False)

    def test_missing_current_snapshot_fails_audit(self):
        problems = catalog_module.audit_versions(self.patterns_data)
        self.assertTrue(any("CASE-900: missing v001 snapshot" in problem for problem in problems),
                        problems)

    def test_backfill_snapshots_is_idempotent_and_audits_clean(self):
        written = catalog_module.backfill_snapshots()
        self.assertEqual(len(written), 2)
        for path in written:
            self.assertTrue(pathlib.Path(path).exists())
        self.assertEqual(catalog_module.audit_versions(self.patterns_data), [])
        self.assertEqual(catalog_module.backfill_snapshots(), [])
        journal = self.committed_transactions()
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0]["kind"], "snapshot_backfill")
        self.assertEqual(self.audit_problems(), [])

    def test_backfill_writes_every_missing_version_number(self):
        versioned = make_pattern("CASE-960", [make_step("S1", 1, "alpha960", "alpha")],
                                 ["alpha"], version=3)
        self.write_store([versioned], [], [], snapshots=False)
        written = catalog_module.backfill_snapshots(["CASE-960"])
        self.assertEqual(len(written), 3)
        for number in (1, 2, 3):
            path = self.versions_dir / "CASE-960" / f"v{number:03d}.json"
            self.assertEqual(json.loads(path.read_text(encoding="utf-8-sig"))["version"], number)
        self.assertEqual(catalog_module.audit_versions([versioned]), [])

    def test_unknown_backfill_case_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown case_id"):
            catalog_module.backfill_snapshots(["CASE-999"])

    def test_snapshot_version_mismatch_is_reported(self):
        catalog_module.backfill_snapshots()
        path = self.versions_dir / "CASE-900" / "v001.json"
        snapshot = json.loads(path.read_text(encoding="utf-8-sig"))
        snapshot["version"] = 7
        path.write_text(json.dumps(snapshot), encoding="utf-8")
        problems = catalog_module.audit_versions(self.patterns_data)
        self.assertTrue(any("records version 7" in problem for problem in problems), problems)

    def test_snapshot_refuses_to_rewrite_history(self):
        path = self.versions_dir / "CASE-900" / "v001.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(dict(self.patterns_data[0], version=1, name="old name")),
                        encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "refusing to rewrite history"):
            catalog_module.version_snapshot(self.patterns_data[0])

    def test_alias_audit_accepts_valid_merge_and_rejects_breaks(self):
        source = make_pattern("CASE-901", [make_step("S1", 1, "delta901", "delta")],
                              status="retired", merged_into="CASE-900")
        target = make_pattern("CASE-900", [make_step("S1", 1, "alpha900", "alpha")])
        self.assertEqual(catalog_module.audit_aliases([target, source]), [])
        broken = make_pattern("CASE-902", [make_step("S1", 1, "x902", "xyz")],
                              status="retired", merged_into="CASE-999")
        self.assertTrue(catalog_module.audit_aliases([target, broken]))
        cycle_a = make_pattern("CASE-903", [make_step("S1", 1, "x903", "abc")],
                               status="retired", merged_into="CASE-904")
        cycle_b = make_pattern("CASE-904", [make_step("S1", 1, "x904", "abd")],
                               status="retired", merged_into="CASE-903")
        problems = catalog_module.audit_aliases([cycle_a, cycle_b])
        self.assertTrue(any("cycle" in problem for problem in problems), problems)


# ---------------------------------------------------------------------------
# Admissions ledger / orphan repair
# ---------------------------------------------------------------------------

class AdmissionRepairTests(GateStoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        patterns, logs, links = base_fixture()
        self.write_store(patterns, logs, links)

    def test_audit_accepts_support_coverage_fields(self):
        support = {"single_sample": True, "required_steps": ["S1", "S2"],
                   "covered_required": ["S1"], "missing_required": ["S2"],
                   "has_strong_medium": False,
                   "coverage": {"INC-A": {"tier": "weak", "coverage": 0.5,
                                          "required_total": 2, "covered_required": ["S1"]}}}
        record = admissions_module.build_admission("CASE-997", "catalog_add", support=support)
        pattern = make_pattern("CASE-997", [make_step("S1", 1, "x997", "abc")],
                               review_status="unreviewed",
                               admission_id=record["admission_id"])
        self.write_store(self.patterns() + [pattern], self.logs(), self.link_rows())
        admissions_module.save_admissions({"schema_version": 1, "admissions": [record]})
        self.assertEqual(admissions_module.audit_admissions(self.patterns()), [])
        record["single_sample"] = "yes"
        admissions_module.save_admissions({"schema_version": 1, "admissions": [record]})
        problems = admissions_module.audit_admissions(self.patterns())
        self.assertTrue(any("single_sample" in problem for problem in problems), problems)

    def test_orphan_admission_is_reported_then_removed(self):
        orphan = admissions_module.build_admission("CASE-999", "catalog_add")
        admissions_module.save_admissions({"schema_version": 1, "admissions": [orphan]})
        reports = admissions_module.repair_orphans()
        self.assertEqual([(item["case_id"], item["action"]) for item in reports],
                         [("CASE-999", "report")])
        self.assertEqual(len(admissions_module.load_admissions()["admissions"]), 1)
        applied = admissions_module.repair_orphans(apply=True)
        self.assertEqual(applied[0]["action"], "remove")
        self.assertEqual(admissions_module.load_admissions()["admissions"], [])
        self.assertEqual(admissions_module.repair_orphans(), [])
        journal = self.committed_transactions()
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0]["kind"], "repair_admissions")


# ---------------------------------------------------------------------------
# Evolution gates: add_step default, owner-based foreign, held-out, commit
# ---------------------------------------------------------------------------

class EvolutionGateTests(GateStoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.patterns_data, self.logs_data, self.links_data = base_fixture()
        self.write_store(self.patterns_data, self.logs_data, self.links_data)

    def proposal(self, **overrides) -> dict:
        base = {"case_id": "CASE-900", "base_version": 1, "operation": "add_step",
                "rationale": "two incidents continue into beta",
                "supporting_event_ids": ["E-A2", "E-B2"],
                "step": make_step("S2", 2, "beta900", "beta", required=False)}
        base.update(overrides)
        return base

    def evaluate(self, proposal: dict, logs=None, links=None) -> dict:
        return evolution_module.evaluate_proposal(
            self.patterns_data, logs if logs is not None else self.logs_data,
            links if links is not None else self.links_data, proposal)

    def test_add_step_defaults_to_optional(self):
        payload = self.proposal()
        payload["step"].pop("required")
        record, evaluation = evolution_module.create_proposal(payload)
        self.assertTrue(evaluation["ok"], evaluation["problems"])
        self.assertFalse(record["step"]["required"])
        stored = self.load_proposals()[0]
        self.assertFalse(stored["step"]["required"])
        self.assertTrue(evaluation["auto_eligible"])

    def test_explicit_required_completion_is_rejected_with_hint(self):
        result = self.evaluate(self.proposal(
            step=make_step("S2", 2, "beta900", "beta", required=True)))
        self.assertFalse(result["ok"])
        joined = " | ".join(result["problems"])
        self.assertIn("strong incidents would drop", joined)
        self.assertIn("required: false", joined)

    def test_heldout_regression_is_rejected_and_metrics_recorded(self):
        result = self.evaluate(self.proposal(
            step=make_step("S2", 2, "beta900", "beta", required=True)))
        self.assertFalse(result["ok"])
        joined = " | ".join(result["problems"])
        self.assertIn("held-out", joined)
        self.assertEqual(result["metrics"]["heldout_incidents"], 1)
        self.assertGreater(result["metrics"]["heldout_strong_before"],
                           result["metrics"]["heldout_strong_after"])

    def test_optional_completion_keeps_heldout_metrics_stable(self):
        result = self.evaluate(self.proposal())
        self.assertTrue(result["ok"], result["problems"])
        metrics = result["metrics"]
        self.assertEqual(metrics["heldout_incidents"], 1)
        self.assertEqual(metrics["heldout_strong_before"], metrics["heldout_strong_after"])
        self.assertEqual(metrics["heldout_coverage_before"],
                         metrics["heldout_coverage_after"])

    def test_foreign_label_is_rejected_for_add_step(self):
        extra = make_log("E-F1", "INC-F", "beta four", "hids", "CASE-901", 7)
        result = self.evaluate(self.proposal(), logs=self.logs_data + [extra])
        self.assertFalse(result["ok"])
        self.assertEqual(result["metrics"]["foreign_matches"], 1)
        self.assertTrue(any("other cases" in problem for problem in result["problems"]))

    def test_related_owner_counts_as_foreign(self):
        extra = make_log("E-R1", "INC-R1", "delta five", "hids", "", 7)
        related = make_link("E-R1", "INC-R1", "CASE-901", "", "", status="related",
                            basis="variant")
        links = self.links_data + [related]
        proposal = {"case_id": "CASE-900", "base_version": 1, "operation": "extend_step",
                    "rationale": "broaden", "supporting_event_ids": ["E-A1", "E-B1"],
                    "step_id": "S1", "action_regex": "alpha|delta"}
        result = self.evaluate(proposal, logs=self.logs_data + [extra], links=links)
        self.assertFalse(result["ok"])
        self.assertGreaterEqual(result["metrics"]["foreign_matches"], 1)
        joined = " | ".join(result["problems"])
        self.assertIn("E-R1", joined)
        self.assertIn("other cases", joined)

    def test_unlabeled_event_without_link_is_not_foreign(self):
        extra = make_log("E-U1", "INC-U", "beta four", "hids", "", 7)
        result = self.evaluate(self.proposal(), logs=self.logs_data + [extra])
        self.assertEqual(result["metrics"]["foreign_matches"], 0)
        self.assertFalse(any("other cases" in problem for problem in result["problems"]))

    def test_fixture_owner_counts_as_foreign(self):
        extra = make_log("E-FX", "INC-FX", "beta four", "hids", "", 7)
        fixture = make_link("E-FX", "INC-FX", "CASE-901", "S1", "delta901",
                            status="fixture", basis="synthetic fixture")
        result = self.evaluate(self.proposal(), logs=self.logs_data + [extra],
                               links=self.links_data + [fixture])
        self.assertEqual(result["metrics"]["foreign_matches"], 1)

    def test_add_source_cannot_widen_into_another_case(self):
        proposal = {"case_id": "CASE-900", "base_version": 1, "operation": "add_source",
                    "rationale": "same action on RASP",
                    "supporting_event_ids": ["E-A1", "E-B1"],
                    "step_id": "S1", "add_sources": ["rasp"]}
        result = self.evaluate(proposal)
        self.assertFalse(result["ok"])
        self.assertEqual(result["metrics"]["foreign_matches"], 1)
        self.assertEqual(result["metrics"]["new_sources"], ["rasp"])
        self.assertTrue(any("other cases" in problem for problem in result["problems"]))

    def test_add_source_related_owner_counts_as_foreign(self):
        extra = make_log("E-R2", "INC-R2", "alpha variant", "rasp", "", 7)
        related = make_link("E-R2", "INC-R2", "CASE-901", "", "", status="related",
                            basis="variant")
        proposal = {"case_id": "CASE-900", "base_version": 1, "operation": "add_source",
                    "rationale": "same action on RASP",
                    "supporting_event_ids": ["E-A1", "E-B1"],
                    "step_id": "S1", "add_sources": ["rasp"]}
        result = self.evaluate(proposal, logs=self.logs_data + [extra],
                               links=self.links_data + [related])
        self.assertFalse(result["ok"])
        self.assertGreaterEqual(result["metrics"]["foreign_matches"], 2)

    def test_add_source_without_foreign_is_auto_eligible(self):
        patterns = [make_pattern("CASE-900",
                                 [make_step("S1", 1, "alpha900", "alpha", sources=("hids",))],
                                 ["alpha"])]
        logs = [
            make_log("E-A1", "INC-A", "alpha one", "hids", "CASE-900", 0),
            make_log("E-B1", "INC-B", "alpha two", "rasp", "CASE-900", 2),
            make_log("E-C1", "INC-C", "alpha three", "rasp", "CASE-900", 3),
        ]
        links = [
            make_link("E-A1", "INC-A", "CASE-900", "S1", "alpha900"),
            make_link("E-B1", "INC-B", "CASE-900", "S1", "alpha900"),
            make_link("E-C1", "INC-C", "CASE-900", "S1", "alpha900"),
        ]
        self.write_store(patterns, logs, links)
        proposal = {"case_id": "CASE-900", "base_version": 1, "operation": "add_source",
                    "rationale": "same action on RASP",
                    "supporting_event_ids": ["E-B1", "E-C1"],
                    "step_id": "S1", "add_sources": ["rasp"]}
        result = evolution_module.evaluate_proposal(patterns, logs, links, proposal)
        self.assertTrue(result["ok"], result["problems"])
        self.assertTrue(result["auto_eligible"])
        self.assertEqual(result["metrics"]["foreign_matches"], 0)
        self.assertGreater(result["metrics"]["coverage_after"],
                           result["metrics"]["coverage_before"])

    def test_accept_proposal_commits_snapshots_catalog_and_proposals(self):
        record, evaluation = evolution_module.create_proposal(self.proposal())
        self.assertTrue(evaluation["ok"], evaluation["problems"])
        result = evolution_module.accept_proposal(record["proposal_id"], "synthetic accept",
                                                  auto=True)
        self.assertEqual((result["old_version"], result["new_version"]), (1, 2))
        for path in result["snapshots"]:
            self.assertTrue(pathlib.Path(path).exists(), path)
        self.assertTrue((self.versions_dir / "CASE-900" / "v001.json").exists())
        self.assertTrue((self.versions_dir / "CASE-900" / "v002.json").exists())
        self.assertEqual(self.patterns()[0]["version"], 2)
        self.assertEqual(self.load_proposals()[0]["status"], "accepted")
        journal = self.committed_transactions()
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0]["kind"], "proposal_accept")
        applied = journal[0]["files"]
        self.assertTrue(any(path.endswith("attack_patterns.json") for path in applied), applied)
        self.assertTrue(any(path.endswith("pattern_proposals.json") for path in applied), applied)
        self.assertEqual(self.audit_problems(), [])

    def test_accept_proposal_writes_baseline_snapshot_when_missing(self):
        patterns, logs, links = base_fixture()
        self.write_store(patterns, logs, links, snapshots=False)
        self.patterns_data, self.logs_data, self.links_data = patterns, logs, links
        record, evaluation = evolution_module.create_proposal(self.proposal())
        self.assertTrue(evaluation["ok"], evaluation["problems"])
        evolution_module.accept_proposal(record["proposal_id"], "accept", auto=True)
        self.assertTrue((self.versions_dir / "CASE-900" / "v001.json").exists())
        self.assertTrue((self.versions_dir / "CASE-900" / "v002.json").exists())


# ---------------------------------------------------------------------------
# I7 case merge/split: one transaction across patterns, candidates, lifecycle
# ---------------------------------------------------------------------------

class CaseMergeTransactionTests(GateStoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        patterns, logs, links = base_fixture()
        self.write_store(patterns, logs, links)
        self.candidates_path.write_text(json.dumps({
            "schema_version": 1,
            "candidates": [{
                "candidate_id": "CAND-0001", "signature": "sig", "label": "sig",
                "status": "promoted", "promoted_case_id": "CASE-900", "incidents": [],
                "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
            }],
        }), encoding="utf-8")

    def candidates(self) -> list[dict]:
        return candidates_module.load_candidates()["candidates"]

    def test_merge_then_split_are_single_transactions(self):
        merged = catalog_module.merge_case("CASE-900", "CASE-901", "same family alias")
        self.assertEqual(merged["case_id"], "CASE-900")
        self.assertEqual(merged["target"], "CASE-901")
        self.assertEqual(merged["status"], "retired")
        self.assertEqual(merged["candidate_ids"], ["CAND-0001"])
        self.assertEqual(merged["event"]["action"], "merge")
        self.assertEqual(merged["event"]["event_id"], "LIF-0001")
        patterns = {pattern["case_id"]: pattern for pattern in self.patterns()}
        self.assertEqual(patterns["CASE-900"]["status"], "retired")
        self.assertEqual(patterns["CASE-900"]["merged_into"], "CASE-901")
        self.assertEqual(self.candidates()[0]["promoted_case_id"], "CASE-901")
        self.assertEqual(lifecycle_module.audit_lifecycle(self.patterns()), [])
        journal = self.committed_transactions()
        self.assertEqual([entry["kind"] for entry in journal], ["merge_case"])
        applied = journal[0]["files"]
        self.assertEqual(len(applied), 3, applied)
        for suffix in ("attack_patterns.json", "case_candidates.json", "case_lifecycle.json"):
            self.assertTrue(any(path.endswith(suffix) for path in applied), (suffix, applied))

        split = catalog_module.split_case("CASE-900", "undo the alias merge")
        self.assertEqual(split["status"], "active")
        self.assertEqual(split["event"]["action"], "split")
        self.assertEqual(split["event"]["event_id"], "LIF-0002")
        patterns = {pattern["case_id"]: pattern for pattern in self.patterns()}
        self.assertEqual(patterns["CASE-900"]["status"], "active")
        self.assertNotIn("merged_into", patterns["CASE-900"])
        self.assertEqual(self.candidates()[0]["promoted_case_id"], "CASE-900")
        self.assertEqual(lifecycle_module.audit_lifecycle(self.patterns()), [])
        journal = self.committed_transactions()
        self.assertEqual([entry["kind"] for entry in journal],
                         ["merge_case", "split_case"])
        self.assertEqual(len(journal[1]["files"]), 3, journal[1]["files"])

    def test_merge_staging_failure_leaves_no_partial_state(self):
        patterns_before = self.patterns_path.read_bytes()
        candidates_before = self.candidates_path.read_bytes()
        original = storage._write_temp
        calls = {"count": 0}

        def fail_on_second_stage(target, data):
            calls["count"] += 1
            if calls["count"] == 2:
                raise OSError("simulated staging failure")
            return original(target, data)

        with mock.patch.object(storage, "_write_temp", side_effect=fail_on_second_stage):
            with self.assertRaises(OSError):
                catalog_module.merge_case("CASE-900", "CASE-901", "must not apply")
        self.assertEqual(self.patterns_path.read_bytes(), patterns_before)
        self.assertEqual(self.candidates_path.read_bytes(), candidates_before)
        self.assertFalse(self.lifecycle_path.exists())
        self.assertFalse(self.journal_path.exists())
        leftovers = [path.name for path in pathlib.Path(self._folder.name).iterdir()
                     if path.name.endswith(".tmp") or path.name.startswith(".")]
        self.assertEqual(leftovers, [])
        # The store was untouched, so the same command can be retried as one transaction.
        merged = catalog_module.merge_case("CASE-900", "CASE-901", "retry after failure")
        self.assertEqual(merged["event"]["event_id"], "LIF-0001")
        self.assertEqual([entry["kind"] for entry in self.committed_transactions()],
                         ["merge_case"])


# ---------------------------------------------------------------------------
# I6 repair: derived state, idempotent, journaled
# ---------------------------------------------------------------------------

class RepairTests(GateStoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        patterns, logs, links = base_fixture()
        self.patterns_data = patterns
        self.write_store(patterns, logs, links)

    def _clear_labels(self, event_id: str) -> None:
        rows = self.logs()
        for row in rows:
            if row["event_id"] == event_id:
                row["case_id"] = ""
                row["incident_id"] = ""
        self.write_csv(self.raw_path, storage.RAW_FIELDS, rows)

    def test_repair_rederives_labels_from_the_latest_link(self):
        self._clear_labels("E-C1")
        before = self.raw_path.read_bytes()
        plan = repair_module.repair_plan()
        self.assertEqual(plan["labels"]["count"], 1)
        dry = repair_module.repair(dry_run=True)
        self.assertTrue(dry["ok"])
        self.assertFalse(dry["applied"])
        self.assertEqual(self.raw_path.read_bytes(), before)
        self.assertFalse(self.repair_log_path.exists())
        applied = repair_module.repair(dry_run=False)
        self.assertTrue(applied["applied"])
        self.assertTrue(applied["txn_id"])
        self.assertTrue(self.repair_log_path.exists())
        row = next(item for item in self.logs() if item["event_id"] == "E-C1")
        self.assertEqual((row["case_id"], row["incident_id"]), ("CASE-900", "INC-C"))
        self.assertEqual(self.audit_problems(), [])
        log = repair_module.load_repair_log()
        self.assertEqual(len(log["repairs"]), 1)
        self.assertEqual(log["repairs"][0]["kind"], "label")
        self.assertEqual(log["repairs"][0]["basis"],
                         "label is a derived cache of the latest reviewed link")
        # idempotent: a second run has nothing to do and writes no log entry.
        again = repair_module.repair(dry_run=False)
        self.assertFalse(again["applied"])
        self.assertEqual(len(repair_module.load_repair_log()["repairs"]), 1)

    def test_repair_removes_orphan_admission(self):
        orphan = admissions_module.build_admission("CASE-999", "catalog_add")
        admissions_module.save_admissions({"schema_version": 1, "admissions": [orphan]})
        plan = repair_module.repair_plan()
        self.assertEqual(plan["admissions"]["count"], 1)
        self.assertFalse(repair_module.repair(dry_run=True)["applied"])
        self.assertEqual(len(admissions_module.load_admissions()["admissions"]), 1)
        applied = repair_module.repair(dry_run=False)
        self.assertTrue(applied["applied"])
        self.assertEqual(admissions_module.load_admissions()["admissions"], [])
        kinds = [action["kind"] for action in applied["actions"]]
        self.assertEqual(kinds, ["admission"])
        self.assertTrue(repair_module.repair(dry_run=False)["applied"] is False)

    def test_repair_backfills_missing_snapshots(self):
        for path in (self.versions_dir).rglob("v*.json"):
            path.unlink()
        self.assertTrue(catalog_module.audit_versions(self.patterns_data))
        plan = repair_module.repair_plan()
        self.assertEqual(plan["snapshots"]["count"], 2)
        self.assertFalse(repair_module.repair(dry_run=True)["applied"])
        self.assertFalse((self.versions_dir / "CASE-900" / "v001.json").exists())
        applied = repair_module.repair(dry_run=False)
        self.assertTrue(applied["applied"])
        self.assertEqual(catalog_module.audit_versions(self.patterns_data), [])
        self.assertFalse(repair_module.repair(dry_run=False)["applied"])

    def test_repair_never_deletes_raw_logs_links_or_cases(self):
        self._clear_labels("E-C1")
        logs_before = self.logs()
        links_before = self.link_rows()
        patterns_before = self.patterns()
        repair_module.repair(dry_run=False)
        self.assertEqual(len(self.logs()), len(logs_before))
        self.assertEqual(len(self.link_rows()), len(links_before))
        self.assertEqual(len(self.patterns()), len(patterns_before))

    def test_repair_result_matches_cli_contract(self):
        result = repair_module.repair(dry_run=True)
        for key in ("ok", "dry_run", "lines", "actions"):
            self.assertIn(key, result)
        self.assertTrue(result["ok"])
        self.assertIsInstance(result["lines"], list)
        self.assertIsInstance(result["actions"], list)
        self.assertFalse(result["dry_run"] is True and result["applied"])

    def test_repair_writes_log_inside_the_repair_transaction(self):
        self._clear_labels("E-C1")
        repair_module.repair(dry_run=False)
        journal = self.committed_transactions()
        self.assertEqual(len(journal), 1)
        self.assertEqual(journal[0]["kind"], "repair")
        applied = journal[0]["files"]
        self.assertTrue(any(path.endswith("raw_logs.csv") for path in applied), applied)
        self.assertTrue(any(path.endswith("repair_log.json") for path in applied), applied)


if __name__ == "__main__":
    unittest.main()

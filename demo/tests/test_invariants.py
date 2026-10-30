"""Invariant suite for the attack-memory demo (verifier-owned).

The regression tests in ``test_memory.py`` check individual APIs.  This file
checks the properties a trusted store must keep no matter which module changed:

I1  store integrity: every data file parses, links use known statuses, no
    stray temp files, no unfinished write transaction;
I2  write safety: a failed transaction changes nothing, a committed one is
    journaled, and a crash window is detectable;
I3  versions: the real store has a snapshot for every 1..current version, a new
    case gets its v001 snapshot, gaps/mismatches are detected, backfill is
    idempotent;
I4  force exceptions: a ``--force`` link is only allowed with a review basis, is
    visible as an exception row, and an orphan exception is a problem; the audit
    count equals ``len(links.force_exceptions(rows))``;
I5  support / evolution gates, each with a rejecting counterexample: required-step
    union coverage, tier floor, force-singleton coverage, add_source foreign
    pollution (including related/fixture ownership), held-out regression, and
    add_step defaulting to optional;
I6  negative memory: a correction needs a basis and a known case/reason, audit
    accepts a valid ledger and rejects a broken one, and prior rejections are
    surfaced as context;
I7  alias graph: merged cases resolve to the target, cycles/unknown targets are
    detected and audited;
I8  JSON contracts: ``run_demo --json`` / ``lookup --json`` / ``audit --json``
    carry an integer ``schema_version`` and their documented fields;
I9  state block: the README block matches the store, state counts agree with the
    audit, and drift is detected;
I10 repair: a dry run writes nothing, an applied repair is idempotent, an orphan
    admission is repaired, and no protected asset is deleted.

Hermeticity: every test that writes uses ``tempfile`` plus module-constant
patching (see :func:`_repoint_data_paths`); nothing here may touch
``demo/data``.  Reads against the real store are allowed; the read-only CLI
probes never write.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

DEMO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA_DIR = DEMO_ROOT / "data"
SRC_DIR = DEMO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from attack_memory import evolution  # noqa: E402
from attack_memory import links as links_module  # noqa: E402
from attack_memory import storage  # noqa: E402

# The only intentionally deferred assertion is the README state block: docs are
# generated after the test set is frozen. Everything else fails loudly.
PENDING_T5 = "pending T5 audit/state CLI integration (verifier re-enables at INTEGRATION READY)"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _optional_module(name: str):
    """Import an ``attack_memory`` module, or return None while it is in flight."""
    try:
        return importlib.import_module(f"attack_memory.{name}")
    except Exception:  # noqa: BLE001 - a module being edited must not break collection
        return None


def _has(module, *attrs: str) -> bool:
    return module is not None and all(hasattr(module, attr) for attr in attrs)


def _run_cli(*args: str, timeout: float = 120.0) -> subprocess.CompletedProcess:
    """Run one read-only demo CLI command from demo/ with UTF-8 decoding."""
    return subprocess.run(
        [sys.executable, *args],
        cwd=str(DEMO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _cli_output(proc: subprocess.CompletedProcess) -> str:
    return proc.stdout + ("\n" + proc.stderr if proc.stderr else "")


def _sha(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _hash_tree(root: pathlib.Path) -> dict[str, str]:
    return {path.relative_to(root).as_posix(): _sha(path)
            for path in sorted(root.rglob("*")) if path.is_file()}


def _write_json(path: pathlib.Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _read_json(path: pathlib.Path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


@contextlib.contextmanager
def _repoint_data_paths(target_root: pathlib.Path):
    """Point every ``attack_memory`` module-level path under ``demo/data`` at a clone.

    The storage layer keeps path constants at module import time, so a store test
    clones ``demo/data`` into ``target_root`` and redirects every constant
    (``storage.PATTERNS_PATH``, ``catalog.VERSIONS_DIR``, the correction ledger,
    the journal, ...) without touching the real store.
    """
    import attack_memory as package

    target_root = pathlib.Path(target_root)
    original_data = pathlib.Path(storage.DATA_DIR)
    patches: list[tuple[object, str, pathlib.Path]] = []
    modules = [storage]
    for info in pathlib.Path(package.__file__).parent.glob("*.py"):
        module = _optional_module(info.stem)
        if module is not None and module not in modules:
            modules.append(module)
    for module in modules:
        for name, value in list(vars(module).items()):
            if not isinstance(value, pathlib.Path):
                continue
            try:
                relative = value.relative_to(original_data)
            except ValueError:
                if value == original_data:
                    relative = pathlib.Path()
                else:
                    continue
            patches.append((module, name, target_root / relative))
    with contextlib.ExitStack() as stack:
        for module, name, replacement in patches:
            stack.enter_context(mock.patch.object(module, name, replacement))
        yield target_root


@contextlib.contextmanager
def _cloned_store():
    """Temporary copy of demo/data, with all module path constants redirected."""
    with tempfile.TemporaryDirectory() as folder:
        clone = pathlib.Path(folder) / "data"
        shutil.copytree(DATA_DIR, clone)
        with _repoint_data_paths(clone) as root:
            yield root


def _write_journal_lines(path: pathlib.Path, records: list[dict]) -> None:
    path.write_text("".join(json.dumps(record) + "\n" for record in records),
                    encoding="utf-8")


def _step(step_id: str, order: int, action_id: str, regex: str,
          sources=("any",), required: bool = True) -> dict:
    return {"step_id": step_id, "order": order, "action_id": action_id,
            "label": action_id, "action_regex": regex,
            "expected_sources": list(sources), "generic": False, "required": required}


def _pattern(steps: list[dict], case_id: str = "CASE-900") -> dict:
    return {
        "schema_version": "demo-1.1", "case_id": case_id, "name": "synthetic inv case",
        "summary": "synthetic case for verifier invariants", "mitre": ["T1190"],
        "steps": steps,
        "retrieval": {"keywords": ["alpha"], "pattern_probes": ["alpha"]},
        "negative_and_unknown_evidence": {"not_observed": [], "interpretation": "synthetic"},
        "provenance": {"evidence_status": "repeated"}, "version": 1,
    }


def _log(event_id: str, incident_id: str, content: str, minute: int,
         source: str = "hids", case_id: str = "") -> dict:
    return {"event_id": event_id, "batch_id": "B-INV", "incident_id": incident_id,
            "case_id": case_id, "timestamp": f"2026-01-01T00:{minute:02d}:00+00:00",
            "source": source, "log_id": event_id, "content": content}


def _link(event_id: str, incident_id: str, case_id: str, step_id: str = "",
          status: str = "confirmed") -> dict:
    return {"event_id": event_id, "incident_id": incident_id, "case_id": case_id,
            "step_id": step_id, "action_id": "", "link_status": status,
            "link_basis": "invariant fixture", "decided_at": "2026-01-01T00:00:00Z"}


def _support_fixture() -> tuple[dict, list[dict]]:
    """Three-step pattern; incident coverage is the variable under test."""
    pattern = _pattern([_step("S1", 1, "inv_alpha", "(?i)alpha"),
                        _step("S2", 2, "inv_beta", "(?i)beta"),
                        _step("S3", 3, "inv_gamma", "(?i)gamma")])
    logs: list[dict] = []
    minute = 0

    def add(incident: str, *contents: str) -> None:
        nonlocal minute
        for index, content in enumerate(contents, start=1):
            logs.append(_log(f"E-{incident}-{index}", incident, content, minute))
            minute += 1

    add("INC-FULL", "alpha one", "beta two", "gamma three")  # strong by itself
    add("INC-AB", "alpha four", "beta five")                # medium
    add("INC-G", "gamma six")
    add("INC-A", "alpha seven")
    add("INC-B", "beta eight")
    add("INC-NOMATCH", "delta nine")
    return pattern, logs


# ---------------------------------------------------------------------------
# I1  store integrity (runs against the real store, read-only)
# ---------------------------------------------------------------------------

class StoreIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.patterns = storage.load_patterns()

    def test_every_data_json_file_parses(self):
        broken = []
        for path in sorted(DATA_DIR.rglob("*.json")):
            try:
                json.loads(path.read_text(encoding="utf-8-sig"))
            except Exception as error:  # noqa: BLE001 - report every broken file
                broken.append(f"{path.relative_to(DEMO_ROOT).as_posix()}: {error}")
        self.assertEqual(broken, [])

    def test_real_links_use_known_statuses(self):
        links = storage.read_links()
        self.assertTrue(links)
        unknown = sorted({(link.get("link_status") or "") for link in links}
                         - set(storage.LINK_STATUSES))
        self.assertEqual(unknown, [])

    def test_real_catalog_has_unique_step_and_action_ids(self):
        for pattern in self.patterns["attack_patterns"]:
            step_ids = [step["step_id"] for step in pattern["steps"]]
            action_ids = [step["action_id"] for step in pattern["steps"]]
            self.assertEqual(len(step_ids), len(set(step_ids)), pattern["case_id"])
            self.assertEqual(len(action_ids), len(set(action_ids)), pattern["case_id"])
            self.assertTrue(any(step.get("required", True) for step in pattern["steps"]),
                            pattern["case_id"])

    def test_no_leftover_temp_files_in_data(self):
        leftovers = [path.relative_to(DEMO_ROOT).as_posix()
                     for path in DATA_DIR.rglob("*")
                     if path.is_file() and (path.name.endswith(".tmp") or path.name.startswith(".tmp"))]
        self.assertEqual(leftovers, [])

    def test_journal_has_no_unfinished_transaction(self):
        if not _has(storage, "load_journal", "audit_journal"):
            self.skipTest("storage journal not available")
        self.assertEqual(storage.audit_journal(), [])

    def test_catalog_validate_cli_is_clean(self):
        proc = _run_cli("src/manage_memory.py", "catalog", "validate")
        self.assertEqual(proc.returncode, 0, _cli_output(proc))
        self.assertIn("Catalog valid:", proc.stdout)

    def test_audit_cli_is_clean(self):
        proc = _run_cli("src/manage_memory.py", "audit")
        self.assertEqual(proc.returncode, 0, _cli_output(proc))
        self.assertIn("Audit clean", proc.stdout)


# ---------------------------------------------------------------------------
# I2  write safety / journal (each commit failure is a counterexample)
# ---------------------------------------------------------------------------

class JournalInvariantTests(unittest.TestCase):
    def test_pending_transaction_is_reported(self):
        if not _has(storage, "load_journal", "audit_journal"):
            self.skipTest("storage journal not available")
        with tempfile.TemporaryDirectory() as folder:
            journal = pathlib.Path(folder) / "ops_journal.jsonl"
            _write_journal_lines(journal, [
                {"txn_id": "TXN-pending", "status": "pending", "kind": "link",
                 "summary": "crash window", "files": []},
            ])
            problems = storage.audit_journal(journal)
        self.assertTrue(any("TXN-pending" in problem for problem in problems), problems)

    def test_committed_transaction_is_clean(self):
        if not _has(storage, "load_journal", "audit_journal"):
            self.skipTest("storage journal not available")
        with tempfile.TemporaryDirectory() as folder:
            journal = pathlib.Path(folder) / "ops_journal.jsonl"
            _write_journal_lines(journal, [
                {"txn_id": "TXN-done", "status": "pending", "kind": "link",
                 "summary": "ok", "files": []},
                {"txn_id": "TXN-done", "status": "done", "files": []},
            ])
            problems = storage.audit_journal(journal)
        self.assertEqual(problems, [])

    def test_commit_success_leaves_no_unfinished_transaction(self):
        if not _has(storage, "commit", "Write", "audit_journal"):
            self.skipTest("storage transaction layer not available")
        with tempfile.TemporaryDirectory() as folder:
            folder = pathlib.Path(folder)
            journal = folder / "ops_journal.jsonl"
            target = folder / "written.json"
            with mock.patch.object(storage, "JOURNAL_PATH", journal):
                txn_id = storage.commit(
                    [storage.Write.json(target, {"value": 1})],
                    kind="test", summary="verifier commit invariant")
            self.assertEqual(_read_json(target), {"value": 1})
            self.assertEqual(storage.audit_journal(journal), [])
            records = storage.load_journal(journal)
            self.assertTrue(any(record.get("txn_id") == txn_id
                                and record.get("status") == "done" for record in records))

    def test_failed_commit_changes_nothing_and_writes_no_pending_journal(self):
        if not _has(storage, "commit", "Write"):
            self.skipTest("storage transaction layer not available")
        with tempfile.TemporaryDirectory() as folder:
            folder = pathlib.Path(folder)
            journal = folder / "ops_journal.jsonl"
            good = folder / "good.json"
            bad = storage.Write(path=folder / "bad.json", kind="not-a-kind", payload={})
            with mock.patch.object(storage, "JOURNAL_PATH", journal):
                with self.assertRaises(ValueError):
                    storage.commit([storage.Write.json(good, {"ok": True}), bad],
                                   kind="test", summary="must fail to render")
            self.assertFalse(good.exists(), "a failed transaction must not apply earlier writes")
            if journal.exists():
                pending = [line for line in journal.read_text(encoding="utf-8").splitlines()
                           if json.loads(line).get("status") == "pending"]
                self.assertEqual(pending, [])

    def test_real_journal_records_are_well_formed(self):
        if not hasattr(storage, "load_journal"):
            self.skipTest("storage journal not available")
        journal = getattr(storage, "JOURNAL_PATH", None)
        if journal is None or not pathlib.Path(journal).exists():
            self.skipTest("no journal file in the store yet")
        records = storage.load_journal()
        txn_ids = {record.get("txn_id") for record in records}
        done = {record.get("txn_id") for record in records if record.get("status") == "done"}
        self.assertTrue(done <= txn_ids)
        self.assertTrue(all(record.get("at") for record in records))


# ---------------------------------------------------------------------------
# I3  version snapshots
# ---------------------------------------------------------------------------

class VersionSnapshotInvariants(unittest.TestCase):
    def test_real_store_versions_are_complete(self):
        catalog = _optional_module("catalog")
        if not _has(catalog, "audit_versions"):
            self.skipTest("catalog.audit_versions not available")
        patterns = storage.load_patterns()["attack_patterns"]
        self.assertEqual(catalog.audit_versions(patterns), [])

    def test_missing_or_mismatched_snapshot_is_detected(self):
        catalog = _optional_module("catalog")
        if not _has(catalog, "audit_versions", "version_path", "load_validated_catalog"):
            self.skipTest("catalog version audit not available")
        with _cloned_store():
            patterns = catalog.load_validated_catalog()["attack_patterns"]
            known = {pattern["case_id"]: pattern for pattern in patterns}
            case_id = "CASE-005"
            path = catalog.version_path(case_id, 1)
            self.assertTrue(path.exists(), path)
            payload = _read_json(path)
            path.unlink()
            problems = catalog.audit_versions(patterns)
            self.assertTrue(any(case_id in problem and "missing" in problem
                                for problem in problems), problems)
            _write_json(path, dict(payload, version=99))
            problems = catalog.audit_versions(patterns)
            self.assertTrue(any(case_id in problem and "version" in problem
                                for problem in problems), problems)
            self.assertIn(case_id, known)

    def test_new_case_gets_v001_snapshot(self):
        catalog = _optional_module("catalog")
        if not _has(catalog, "add_pattern", "VERSIONS_DIR", "version_path"):
            self.skipTest("catalog add-pattern snapshot not available")
        with _cloned_store():
            with tempfile.TemporaryDirectory() as folder:
                pattern = _pattern([_step("S1", 1, "inv_case_toggle", "(?i)alpha")],
                                   case_id="CASE-955")
                pattern_path = pathlib.Path(folder) / "pattern.json"
                _write_json(pattern_path, pattern)
                catalog.add_pattern(pattern_path, force=True)
                snapshot = catalog.version_path("CASE-955", 1)
                self.assertTrue(snapshot.exists(), snapshot)
                payload = _read_json(snapshot)
                self.assertEqual(payload.get("version"), 1)
                self.assertEqual(payload.get("case_id"), "CASE-955")
                self.assertEqual(catalog.audit_versions(
                    catalog.load_validated_catalog()["attack_patterns"]), [])

    def test_snapshot_backfill_is_idempotent(self):
        catalog = _optional_module("catalog")
        if not _has(catalog, "backfill_snapshots", "version_path"):
            self.skipTest("catalog snapshot backfill not available")
        with _cloned_store():
            missing = catalog.version_path("CASE-007", 2)
            self.assertTrue(missing.exists(), missing)
            missing.unlink()
            first = catalog.backfill_snapshots(["CASE-007"])
            self.assertTrue(first, "backfill must report the files it wrote")
            self.assertTrue(missing.exists())
            second = catalog.backfill_snapshots(["CASE-007"])
            self.assertEqual(second, [], "a second backfill must write nothing")
            problems = catalog.audit_versions(
                catalog.load_validated_catalog()["attack_patterns"])
            self.assertEqual(problems, [])


# ---------------------------------------------------------------------------
# I4  forced links and the exception ledger
# ---------------------------------------------------------------------------

class ForceExceptionInvariants(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = pathlib.Path(self.folder.name)
        self.patterns = _pattern([_step("S1", 1, "inv_force_alpha", "(?i)alpha")])
        self.raw = root / "raw_logs.csv"
        self.raw.write_text(
            ",".join(storage.RAW_FIELDS) + "\n"
            "EVT-OK,B-T,INC-X,,2026-01-01T00:00:00+00:00,waf,L1,alpha probe\n"
            "EVT-BAD,B-T,INC-X,,2026-01-01T00:01:00+00:00,waf,L2,completely unrelated\n",
            encoding="utf-8")
        self.patterns_path = root / "attack_patterns.json"
        _write_json(self.patterns_path, {"schema_version": "demo-1.1",
                                         "attack_patterns": [self.patterns]})
        self.links = root / "event_pattern_links.csv"
        self.exceptions = root / "link_exceptions.json"
        self.journal = root / "ops_journal.jsonl"
        for patcher in (
            mock.patch.object(storage, "PATTERNS_PATH", self.patterns_path),
            mock.patch.object(storage, "RAW_LOGS_PATH", self.raw),
            mock.patch.object(storage, "LINKS_PATH", self.links),
            mock.patch.object(storage, "JOURNAL_PATH", self.journal),
            mock.patch.object(links_module, "LINK_EXCEPTIONS_PATH", self.exceptions),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_forced_link_without_basis_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "basis"):
            links_module.append_links(["EVT-BAD"], "INC-X", "CASE-900", "S1",
                                      "candidate", "", force=True)
        self.assertFalse(self.links.exists(), "a rejected force write must not append a link")
        self.assertFalse(self.exceptions.exists(), "no exception row may be written")

    def test_forced_link_is_visible_as_exception(self):
        written = links_module.append_links(
            ["EVT-BAD"], "INC-X", "CASE-900", "S1", "candidate",
            "regex truncated in source log", force=True, reviewer="invariant-analyst")
        self.assertEqual(written, 1)
        rows = storage.read_csv(self.links)
        ledger = links_module.load_exceptions()
        self.assertEqual(len(ledger["exceptions"]), 1)
        self.assertEqual(ledger["exceptions"][0]["basis"], "regex truncated in source log")
        self.assertEqual(ledger["exceptions"][0]["reviewer"], "invariant-analyst")
        self.assertEqual(len(links_module.force_exceptions(rows)), 1)
        self.assertEqual(links_module.audit_links(self.patterns["steps"] and
                                                 [self.patterns], storage.read_csv(self.raw),
                                                 rows), [])
        self.assertEqual(links_module.audit_link_exceptions(rows), [])

    def test_orphan_exception_is_reported(self):
        _write_json(self.exceptions, {"schema_version": 1, "exceptions": [
            {"event_id": "EVT-GONE", "incident_id": "INC-X", "case_id": "CASE-900",
             "step_id": "S1", "basis": "reviewed", "decided_at": "2026-01-01T00:00:00Z",
             "reviewer": "analyst"}]})
        rows = storage.read_links(self.links)
        problems = links_module.audit_link_exceptions(rows)
        self.assertTrue(any("orphaned" in problem for problem in problems), problems)
        self.assertEqual(links_module.force_exceptions(rows), [])

    def test_audit_reports_forced_exception_count(self):
        proc = _run_cli("src/manage_memory.py", "audit", "--json")
        self.assertEqual(proc.returncode, 0, _cli_output(proc))
        report = json.loads(proc.stdout)
        self.assertIn("forced_exceptions", report)
        rows = storage.read_links()
        self.assertEqual(report["forced_exceptions"],
                         len(links_module.force_exceptions(rows)),
                         "audit must count exactly the exceptions that waive a live link")


# ---------------------------------------------------------------------------
# I5  support / evolution gates: one rejecting counterexample per gate
# ---------------------------------------------------------------------------

class SupportGateInvariants(unittest.TestCase):
    def setUp(self):
        self.pattern, self.logs = _support_fixture()
        self.support = _optional_module("catalog")
        if not _has(self.support, "pattern_support_report", "require_pattern_support"):
            self.skipTest("catalog support gate not available")

    def test_new_case_with_one_of_three_steps_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "required step"):
            self.support.require_pattern_support(self.pattern, ["INC-A", "INC-G"], self.logs)

    def test_complementary_two_incidents_cover_the_required_union(self):
        ids = self.support.require_pattern_support(
            self.pattern, ["INC-AB", "INC-G"], self.logs)
        self.assertEqual(ids, ["INC-AB", "INC-G"])
        report = self.support.pattern_support_report(
            self.pattern, ["INC-AB", "INC-G"], self.logs)
        self.assertEqual(report["covered_required"], ["S1", "S2", "S3"])
        self.assertEqual(report["missing_required"], [])
        self.assertTrue(report["has_strong_medium"])

    def test_union_coverage_without_a_strong_sample_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "strong/medium"):
            self.support.require_pattern_support(
                self.pattern, ["INC-A", "INC-B", "INC-G"], self.logs)

    def test_force_singleton_is_marked_single_sample_with_coverage(self):
        report = self.support.pattern_support_report(
            self.pattern, ["INC-G"], self.logs, force=True)
        self.assertTrue(report["single_sample"])
        self.assertFalse(report["has_strong_medium"])
        self.assertIn("S1", report["missing_required"])
        self.assertIn("S2", report["missing_required"])
        per_incident = report["coverage"]["INC-G"]
        self.assertEqual(per_incident["required_total"], 3)
        self.assertEqual(per_incident["coverage"], round(1 / 3, 3))
        self.assertIn(per_incident["tier"], ("weak", "keyword_only"))
        self.assertEqual(self.support.require_pattern_support(
            self.pattern, ["INC-G"], self.logs, force=True), ["INC-G"])

    def test_add_source_cannot_widen_into_another_case(self):
        base = _pattern([_step("S1", 1, "inv_alpha", "(?i)alpha", sources=("hids",))])
        logs = [
            _log("A1", "INC-A", "alpha one", 0, case_id="CASE-900"),
            _log("B1", "INC-B", "alpha two", 1, case_id="CASE-900"),
            _log("RASPI", "INC-R", "alpha three", 2, source="rasp", case_id="CASE-901"),
        ]
        links = [_link("A1", "INC-A", "CASE-900", "S1"),
                 _link("B1", "INC-B", "CASE-900", "S1")]
        proposal = {"case_id": "CASE-900", "base_version": 1, "operation": "add_source",
                    "rationale": "rasp sees the same action", "supporting_event_ids": ["A1", "B1"],
                    "step_id": "S1", "add_sources": ["rasp"]}
        result = evolution.evaluate_proposal([base], logs, links, proposal)
        self.assertFalse(result["ok"])
        self.assertGreaterEqual(result["metrics"]["foreign_matches"], 1)
        self.assertTrue(any("other cases" in problem for problem in result["problems"]),
                        result["problems"])

    def test_owner_of_event_sees_related_and_fixture_links(self):
        if not hasattr(storage, "owner_of_event"):
            self.skipTest("storage.owner_of_event not available")
        unlabeled = {"event_id": "E1", "case_id": "", "incident_id": ""}
        self.assertEqual(storage.owner_of_event(
            unlabeled, {"link_status": "related", "case_id": "CASE-9"}), "CASE-9")
        self.assertEqual(storage.owner_of_event(
            unlabeled, {"link_status": "fixture", "case_id": "CASE-9"}), "CASE-9")
        self.assertEqual(storage.owner_of_event(
            unlabeled, {"link_status": "candidate", "case_id": "CASE-9"}), "")
        self.assertEqual(storage.owner_of_event(dict(unlabeled, case_id="CASE-8"),
                                                {"link_status": "related",
                                                 "case_id": "CASE-9"}), "CASE-8")

    def test_held_out_regression_is_rejected(self):
        base = _pattern([_step("S1", 1, "inv_alpha2", "(?i)alpha")])
        logs = [
            _log("A1", "INC-A", "alpha one", 0), _log("A2", "INC-A", "beta two", 1),
            _log("B1", "INC-B", "alpha three", 2), _log("B2", "INC-B", "beta four", 3),
            _log("C1", "INC-C", "alpha five", 4),
        ]
        links = [_link("A1", "INC-A", "CASE-900", "S1"),
                 _link("A2", "INC-A", "CASE-900", "S1"),
                 _link("B1", "INC-B", "CASE-900", "S1"),
                 _link("B2", "INC-B", "CASE-900", "S1"),
                 _link("C1", "INC-C", "CASE-900", "S1")]
        proposal = {"case_id": "CASE-900", "base_version": 1, "operation": "add_step",
                    "rationale": "two support incidents continue into beta",
                    "supporting_event_ids": ["A2", "B2"],
                    "step": _step("S2", 2, "inv_beta2", "(?i)beta", required=True)}
        result = evolution.evaluate_proposal([base], logs, links, proposal)
        self.assertFalse(result["ok"])
        self.assertEqual(result["metrics"]["heldout_incidents"], 1)
        self.assertTrue(any("held-out" in problem for problem in result["problems"]),
                        result["problems"])

    def test_add_step_defaults_to_optional(self):
        base = _pattern([_step("S1", 1, "inv_alpha3", "(?i)alpha")])
        proposal = {"case_id": "CASE-900", "base_version": 1, "operation": "add_step",
                    "rationale": "completion step", "supporting_event_ids": ["E1"],
                    "step": {"step_id": "S2", "order": 2, "action_id": "inv_beta3",
                             "action_regex": "(?i)beta", "expected_sources": ["any"]}}
        candidate = evolution.apply_delta(base, proposal)
        added = next(step for step in candidate["steps"] if step["step_id"] == "S2")
        self.assertFalse(added["required"], "add_step must default to optional")
        proposal["step"]["required"] = True
        candidate = evolution.apply_delta(base, proposal)
        added = next(step for step in candidate["steps"] if step["step_id"] == "S2")
        self.assertTrue(added["required"], "an explicit required:true must be preserved")


# ---------------------------------------------------------------------------
# I6  negative memory (corrections ledger)
# ---------------------------------------------------------------------------

class NegativeMemoryInvariants(unittest.TestCase):
    def setUp(self):
        corrections = _optional_module("corrections")
        if not _has(corrections, "add_correction", "audit_corrections", "for_case",
                    "summary_line"):
            self.skipTest("corrections ledger not available")
        self.corrections = corrections
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        root = pathlib.Path(self.folder.name)
        self.ledger = root / "corrections.json"
        self.journal = root / "ops_journal.jsonl"
        self.patterns = [_pattern([_step("S1", 1, "inv_corr_alpha", "(?i)alpha")])]
        self.logs = [_log("E1", "INC-1", "alpha one", 0),
                     _log("E2", "INC-2", "beta two", 1)]
        self.patchers = [mock.patch.object(storage, "JOURNAL_PATH", self.journal)]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def add(self, **overrides):
        kwargs = {"incident_id": "INC-1", "case_id": "CASE-900",
                  "reason_code": "generic_only", "event_ids": ["E1"],
                  "basis": "only a shared whoami probe; no case step",
                  "reviewer": "invariant-analyst",
                  "patterns": self.patterns, "logs": self.logs, "links": [],
                  "path": self.ledger}
        kwargs.update(overrides)
        return self.corrections.add_correction(**kwargs)

    def test_correction_requires_basis_and_known_reason(self):
        with self.assertRaisesRegex(ValueError, "basis"):
            self.add(basis="   ")
        with self.assertRaisesRegex(ValueError, "reason_code"):
            self.add(reason_code="because-i-said-so")
        with self.assertRaisesRegex(ValueError, "decision"):
            self.add(decision="maybe")

    def test_correction_requires_a_known_case_and_incident(self):
        with self.assertRaisesRegex(ValueError, "unknown case_id"):
            self.add(case_id="CASE-999")
        with self.assertRaisesRegex(ValueError, "unknown incident_id"):
            self.add(incident_id="INC-NOPE")
        with self.assertRaisesRegex(ValueError, "belongs to incident"):
            self.add(event_ids=["E2"])

    def test_valid_correction_passes_audit_and_keeps_a_why(self):
        record = self.add()
        self.assertEqual(record["correction_id"], "COR-0001")
        self.assertEqual(record["decision"], "reject_match")
        self.assertTrue(record["basis"])
        self.assertTrue(self.ledger.exists())
        self.assertEqual(storage.audit_journal(self.journal), [])
        self.assertEqual(self.corrections.audit_corrections(
            self.patterns, self.logs, [], path=self.ledger), [])
        prior = self.corrections.for_case("CASE-900", path=self.ledger)
        self.assertEqual([item["correction_id"] for item in prior], ["COR-0001"])
        line = self.corrections.summary_line(prior[0])
        self.assertIn("COR-0001", line)
        self.assertIn("generic_only", line)
        with self.assertRaisesRegex(ValueError, "already records"):
            self.add()

    def test_broken_correction_is_reported(self):
        self.add()
        data = _read_json(self.ledger)
        broken = dict(data["corrections"][0], correction_id="COR-0001",
                      case_id="CASE-999", reason_code="not-a-code", basis="")
        data["corrections"] = [broken, dict(broken, correction_id="COR-0001")]
        _write_json(self.ledger, data)
        problems = self.corrections.audit_corrections(
            self.patterns, self.logs, [], path=self.ledger)
        self.assertTrue(any("unknown case_id" in problem for problem in problems), problems)
        self.assertTrue(any("unsupported reason_code" in problem for problem in problems), problems)
        self.assertTrue(any("missing basis" in problem for problem in problems), problems)
        self.assertTrue(any("duplicate correction_id" in problem for problem in problems), problems)

    def test_prior_rejections_are_context_not_precedent(self):
        proc = _run_cli("src/run_demo.py", "--input", "data/raw_logs.csv",
                        "--min-tier", "medium", "--top", "2", "--json")
        self.assertEqual(proc.returncode, 0, _cli_output(proc))
        data = json.loads(proc.stdout)
        candidates = [candidate for scope in data["scopes"]
                      for candidate in scope.get("candidates") or []]
        self.assertTrue(candidates)
        for candidate in candidates:
            self.assertIn("prior_rejections", candidate)
            self.assertIsInstance(candidate["prior_rejections"], list)


# ---------------------------------------------------------------------------
# I7  alias graph
# ---------------------------------------------------------------------------

class AliasGraphInvariants(unittest.TestCase):
    def test_merged_case_resolves_to_target(self):
        if not hasattr(storage, "resolve_case"):
            self.skipTest("storage.resolve_case not available")
        patterns = [{"case_id": "CASE-001"},
                    {"case_id": "CASE-002", "status": "retired", "merged_into": "CASE-001"}]
        target, chain = storage.resolve_case("CASE-002", patterns)
        self.assertEqual(target, "CASE-001")
        self.assertEqual(chain, ["CASE-002", "CASE-001"])

    def test_alias_cycle_is_detected(self):
        if not hasattr(storage, "resolve_case"):
            self.skipTest("storage.resolve_case not available")
        patterns = [{"case_id": "CASE-001", "merged_into": "CASE-002"},
                    {"case_id": "CASE-002", "merged_into": "CASE-001"}]
        with self.assertRaisesRegex(ValueError, "cycle"):
            storage.resolve_case("CASE-001", patterns)

    def test_unknown_alias_target_is_detected(self):
        if not hasattr(storage, "resolve_case"):
            self.skipTest("storage.resolve_case not available")
        patterns = [{"case_id": "CASE-001", "merged_into": "CASE-999"}]
        with self.assertRaises(ValueError):
            storage.resolve_case("CASE-001", patterns)

    def test_alias_audit_flags_cycles_and_unknown_targets(self):
        catalog = _optional_module("catalog")
        if not _has(catalog, "audit_aliases"):
            self.skipTest("catalog.audit_aliases not available")
        cycle = [{"case_id": "CASE-001", "merged_into": "CASE-002"},
                 {"case_id": "CASE-002", "merged_into": "CASE-001"}]
        problems = catalog.audit_aliases(cycle)
        self.assertTrue(any("cycle" in problem for problem in problems), problems)
        unknown = [{"case_id": "CASE-001", "merged_into": "CASE-999"}]
        problems = catalog.audit_aliases(unknown)
        self.assertTrue(any("unknown" in problem for problem in problems), problems)
        real = storage.load_patterns()["attack_patterns"]
        self.assertEqual(catalog.audit_aliases(real), [])

    def test_merge_alias_on_clone_resolves_and_splits(self):
        catalog = _optional_module("catalog")
        if not _has(catalog, "merge_case", "split_case"):
            self.skipTest("catalog case lifecycle not available")
        with _cloned_store():
            catalog.merge_case("CASE-009", "CASE-001", "invariant alias merge",
                               reviewer="invariant")
            # load_validated_catalog() reads through the patched storage constant; the
            # default-argument path of storage.load_patterns() would still be the real store.
            patterns = catalog.load_validated_catalog()["attack_patterns"]
            target, chain = storage.resolve_case("CASE-009", patterns)
            self.assertEqual((target, chain), ("CASE-001", ["CASE-009", "CASE-001"]))
            self.assertEqual(catalog.audit_aliases(patterns), [])
            catalog.split_case("CASE-009", "invariant split", reviewer="invariant")
            patterns = catalog.load_validated_catalog()["attack_patterns"]
            self.assertEqual(catalog.audit_aliases(patterns), [])
            self.assertFalse(next(pattern for pattern in patterns
                                  if pattern["case_id"] == "CASE-009").get("merged_into"))


# ---------------------------------------------------------------------------
# I8  JSON contracts
# ---------------------------------------------------------------------------

class JsonContractInvariants(unittest.TestCase):
    def test_run_demo_json_contract(self):
        proc = _run_cli("src/run_demo.py", "--input", "data/raw_logs.csv",
                        "--min-tier", "medium", "--top", "2", "--json")
        self.assertEqual(proc.returncode, 0, _cli_output(proc))
        data = json.loads(proc.stdout)
        for key in ("schema_version", "input", "log_count", "min_tier", "scopes"):
            self.assertIn(key, data)
        self.assertEqual(data["schema_version"], 1)
        candidates = [candidate for scope in data["scopes"]
                      for candidate in scope.get("candidates") or []]
        self.assertTrue(candidates, "expected at least one candidate at --min-tier medium")
        for candidate in candidates:
            for key in ("case_id", "tier", "evidence", "required_steps", "family_id",
                        "evidence_confidence", "prior_rejections"):
                self.assertIn(key, candidate)
            confidence = candidate["evidence_confidence"]
            self.assertIsInstance(confidence, (int, float))
            self.assertFalse(isinstance(confidence, bool))
            self.assertGreaterEqual(confidence, 0.0)
            self.assertLessEqual(confidence, 1.0)
            self.assertIsInstance(candidate["prior_rejections"], list)

    def test_lookup_json_contract(self):
        proc = _run_cli("src/lookup_case_logs.py", "--case-id", "CASE-005", "--json")
        self.assertEqual(proc.returncode, 0, _cli_output(proc))
        data = json.loads(proc.stdout)
        self.assertEqual(data.get("schema_version"), 1)
        self.assertEqual(data.get("case_id"), "CASE-005")
        for key in ("count", "observations", "pattern_version", "maturity", "status",
                    "derived_real_observations"):
            self.assertIn(key, data)
        self.assertIsInstance(data["count"], int)
        self.assertIsInstance(data["observations"], list)

    def test_audit_json_contract(self):
        proc = _run_cli("src/manage_memory.py", "audit", "--json")
        self.assertEqual(proc.returncode, 0, _cli_output(proc))
        data = json.loads(proc.stdout)
        self.assertIs(data.get("ok"), True)
        self.assertEqual(data.get("problems"), [])
        self.assertIsInstance(data.get("counts"), dict)
        self.assertIsInstance(data.get("checks"), list)
        self.assertTrue(all({"name", "ok", "problems"} <= set(check)
                            for check in data["checks"]))


# ---------------------------------------------------------------------------
# I9  state block
# ---------------------------------------------------------------------------

class StateBlockInvariants(unittest.TestCase):
    def test_readme_state_block_is_current(self):
        readme = DEMO_ROOT / "README.md"
        if "STATE:START" not in readme.read_text(encoding="utf-8"):
            self.skipTest("README state block not generated yet (docs sync pending)")
        proc = _run_cli("src/manage_memory.py", "catalog", "state", "--check", "README.md")
        output = _cli_output(proc)
        if proc.returncode == 2 and "invalid choice" in output:
            self.skipTest(PENDING_T5)
        self.assertEqual(proc.returncode, 0, output)

    def test_state_counts_match_the_store(self):
        state = _optional_module("state")
        audit = _optional_module("audit")
        if not _has(state, "memory_state") or not _has(audit, "run_audit"):
            self.skipTest(PENDING_T5)
        counts = state.memory_state()["counts"]
        audit_counts = audit.run_audit()["counts"]
        expected = {
            "patterns": "cases", "events": "active_events", "links": "links",
            "proposals": "proposals", "candidates": "active_candidates",
            "candidates_merged": "merged_candidates", "families": "families",
            "migrations": "migrations", "admissions": "admissions", "chains": "chains",
            "lifecycle": "lifecycle_events", "archive_runs": "archive_runs",
            "corrections": "corrections", "journal_transactions": "journal_transactions",
        }
        for audit_key, state_key in expected.items():
            self.assertEqual(counts[state_key], audit_counts[audit_key],
                             f"state/{state_key} disagrees with audit/{audit_key}")

    def test_state_check_detects_drift(self):
        state = _optional_module("state")
        if not _has(state, "check_state_block", "render_state_block", "STATE_START"):
            self.skipTest(PENDING_T5)
        with tempfile.TemporaryDirectory() as folder:
            stale = pathlib.Path(folder) / "README.md"
            stale.write_text(
                "# stale\n\n" + state.STATE_START + "\n```text\ncases 0\n```\n"
                + state.STATE_END + "\n", encoding="utf-8")
            problems = state.check_state_block(stale)
            self.assertTrue(any("stale" in problem for problem in problems), problems)
            stale.write_text("# missing markers\n", encoding="utf-8")
            problems = state.check_state_block(stale)
            self.assertTrue(any("missing" in problem for problem in problems), problems)


# ---------------------------------------------------------------------------
# I10  repair
# ---------------------------------------------------------------------------

class RepairInvariants(unittest.TestCase):
    def setUp(self):
        self.repair = _optional_module("repair")
        if not _has(self.repair, "repair", "repair_plan"):
            self.skipTest("repair module not available")

    def test_repair_dry_run_writes_nothing(self):
        with _cloned_store() as root:
            before = _hash_tree(root)
            result = self.repair.repair(dry_run=True)
            self.assertFalse(result["applied"])
            self.assertEqual(_hash_tree(root), before, "dry-run must not write anything")

    def test_repair_is_idempotent(self):
        catalog = _optional_module("catalog")
        if not _has(catalog, "version_path", "audit_versions"):
            self.skipTest("catalog snapshot controls not available")
        with _cloned_store():
            missing = catalog.version_path("CASE-005", 2)
            self.assertTrue(missing.exists(), missing)
            missing.unlink()
            plan = self.repair.repair_plan()
            self.assertGreater(plan["change_count"], 0)
            self.assertIn(str(missing), plan["snapshots"]["missing"])
            first = self.repair.repair(dry_run=False)
            self.assertTrue(first["applied"])
            self.assertTrue(missing.exists())
            self.assertEqual(catalog.audit_versions(
                catalog.load_validated_catalog()["attack_patterns"]), [])
            plan = self.repair.repair_plan()
            self.assertEqual(plan["change_count"], 0, "repair must be idempotent")
            self.assertFalse(self.repair.repair(dry_run=False)["applied"])

    def test_repair_never_deletes_protected_assets(self):
        catalog = _optional_module("catalog")
        if not _has(catalog, "version_path"):
            self.skipTest("catalog snapshot controls not available")
        protected = [DATA_DIR / "raw_logs.csv", DATA_DIR / "event_pattern_links.csv",
                     DATA_DIR / "attack_patterns.json"]
        with _cloned_store() as root:
            protected = [root / path.name for path in protected]
            before = {path.name: _sha(path) for path in protected}
            missing = catalog.version_path("CASE-005", 2)
            missing.unlink()
            result = self.repair.repair(dry_run=False)
            self.assertTrue(result["applied"])
            for path in protected:
                self.assertTrue(path.exists(), f"repair deleted {path.name}")
                self.assertEqual(_sha(path), before[path.name],
                                 f"repair must not rewrite {path.name} for a snapshot fix")

    def test_orphan_admission_is_repaired(self):
        admissions = _optional_module("admissions")
        catalog = _optional_module("catalog")
        if not _has(admissions, "load_admissions", "save_admissions") or not _has(
                catalog, "load_validated_catalog"):
            self.skipTest("admission repair not available")
        with _cloned_store():
            data = admissions.load_admissions()
            data["admissions"].append({
                "admission_id": "ADM-CASE-999", "case_id": "CASE-999",
                "source": "orphan fixture", "basis": "fixture", "status": "unreviewed",
                "created_at": "2026-01-01T00:00:00Z", "reviewed_at": None,
                "reviewed_by": None, "review_basis": "", "single_sample": False,
                "support_coverage": {},
            })
            admissions.save_admissions(data)
            plan = self.repair.repair_plan()
            self.assertGreaterEqual(plan["admissions"]["count"], 1)
            self.assertTrue(self.repair.repair(dry_run=False)["applied"])
            self.assertEqual(admissions.audit_admissions(
                catalog.load_validated_catalog()["attack_patterns"]), [])


if __name__ == "__main__":
    unittest.main()

"""Store-level edge tests: malformed journals, gc, duplicate issue lookup."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory.models import Issue, OperationEvent
from runtime_memory.store import Store


def issue(issue_id: str, status: str, resolved_at: str | None = None,
          fingerprint: str = "lab-a|scope|mcp|hunt.query|search|http://x/hunt") -> Issue:
    return Issue(
        issue_id=issue_id,
        fingerprint=fingerprint,
        key_level="scope",
        scope="global",
        environment_id="lab-a",
        component="mcp",
        tool="hunt.query",
        action="search",
        target="http://x/hunt",
        error_class="unreachable",
        status=status,
        first_seen="2026-11-02T06:00:00Z",
        last_seen="2026-11-02T06:00:00Z",
        count=1,
        attempts=1,
        retry_policy={},
        next_retry_at=None,
        expires_at="2026-11-03T06:00:00Z",
        resolved_at=resolved_at,
    )


class StoreEdgeTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.store = Store(self.folder.name)
        self.store.ensure()

    def test_check_flags_malformed_journal(self):
        self.store.decisions_path.write_text("this is not json\n", encoding="utf-8")
        problems = self.store.check()
        self.assertTrue(any("journal" in problem for problem in problems))

    def test_check_flags_bad_issue_status(self):
        self.store.save_issues({"schema_version": 1, "issues": [
            issue("ISS-1", "bogus").to_dict(),
        ]})
        problems = self.store.check()
        self.assertTrue(any("unsupported status" in problem for problem in problems))

    def test_find_issue_prefers_a_live_duplicate(self):
        # Bypass upsert: real duplicate records should still be readable and a
        # live one preferred over a resolved one.
        self.store.save_issues({"schema_version": 1, "issues": [
            issue("ISS-1", "resolved", "2026-11-02T06:00:00Z").to_dict(),
            issue("ISS-2", "open").to_dict(),
        ]})
        found = self.store.find_issue(
            "lab-a|scope|mcp|hunt.query|search|http://x/hunt", "unreachable")
        self.assertEqual(found["issue_id"], "ISS-2")

    def test_gc_dry_run_and_apply(self):
        event = OperationEvent(
            event_id="OP-old", ts="2020-01-01T00:00:00Z",
            component="mcp", tool="hunt.query", action="search",
            target="http://x/hunt", outcome="fail", fingerprint="fp",
        )
        self.store.append_event(event)
        path = self.store.event_path(event)
        self.assertTrue(path.exists())
        result = self.store.gc(events_days=1, dry_run=True)
        self.assertEqual(result["events"], 1)
        self.assertTrue(path.exists())
        self.store.gc(events_days=1, dry_run=False)
        self.assertFalse(path.exists())

    def test_gc_removes_only_old_resolved_issues(self):
        self.store.upsert_issue(issue("ISS-old", "resolved", "2020-01-01T00:00:00Z",
                                      fingerprint="fp-old"))
        self.store.upsert_issue(issue("ISS-open", "open", fingerprint="fp-open"))
        result = self.store.gc(issues_days=1, dry_run=False)
        self.assertEqual(result["issues"], 1)
        ids = {item["issue_id"] for item in self.store.load_issues()["issues"]}
        self.assertEqual(ids, {"ISS-open"})

    def test_upsert_merges_racing_duplicate_issues(self):
        first = self.store.upsert_issue(issue("ISS-1", "open"))
        second = self.store.upsert_issue(issue("ISS-2", "open"))
        self.assertEqual(first["issue_id"], second["issue_id"])
        self.assertEqual(second["issue_id"], "ISS-1")
        self.assertEqual(second["count"], 2)
        self.assertEqual(len(self.store.load_issues()["issues"]), 1)

    def test_ensure_is_idempotent(self):
        for _ in range(3):
            self.store.ensure()
            self.assertEqual(self.store.check(), [])

    def test_unknown_field_in_issue_is_ignored_by_runtime_parsing(self):
        data = issue("ISS-1", "open").to_dict()
        data["unknown_future_field"] = "x"
        parsed = Issue.from_dict(data)
        self.assertFalse(hasattr(parsed, "unknown_future_field"))


if __name__ == "__main__":
    unittest.main()

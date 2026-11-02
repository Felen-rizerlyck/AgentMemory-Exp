"""CLI smoke tests (stdlib argparse, no subprocess)."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory.cli import main


def run_cli(*args: str) -> tuple[int, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main(list(args))
    return code, stdout.getvalue(), stderr.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = self.folder.name

    def test_check_on_fresh_store(self):
        code, out, _ = run_cli("--root", self.root, "check")
        self.assertEqual(code, 0)
        self.assertIn("clean", out)

    def test_record_then_issues_and_report(self):
        base = ["--root", self.root, "record", "--component", "mcp",
                "--tool", "hunt.query", "--action", "search",
                "--target", "10.7.194.120:22196",
                "--args", '{"q":"dns"}', "--outcome", "fail",
                "--error-class", "unreachable"]
        code, out, _ = run_cli(*base)
        self.assertEqual(code, 0)
        self.assertIn("Recorded failure", out)
        code, out, _ = run_cli("--root", self.root, "issues", "--json")
        self.assertEqual(code, 0)
        issues = json.loads(out)["issues"]
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["status"], "cooldown")
        code, out, _ = run_cli("--root", self.root, "report", "--json")
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertEqual(report["events"]["failures"], 1)

    def test_preflight_json_and_resolve(self):
        run_cli("--root", self.root, "record", "--component", "mcp",
                "--tool", "hunt.query", "--action", "search",
                "--target", "10.7.194.120:22196", "--outcome", "fail",
                "--error-class", "unreachable")
        code, out, _ = run_cli(
            "--root", self.root, "preflight", "--component", "mcp",
            "--tool", "hunt.query", "--action", "search",
            "--target", "10.7.194.120:22196", "--json")
        self.assertEqual(code, 0)
        decision = json.loads(out)
        self.assertEqual(decision["action"], "block")
        issue_id = decision["issue_id"]
        code, out, _ = run_cli("--root", self.root, "resolve", issue_id,
                               "--basis", "endpoint restored")
        self.assertEqual(code, 0)
        code, out, _ = run_cli(
            "--root", self.root, "preflight", "--component", "mcp",
            "--tool", "hunt.query", "--action", "search",
            "--target", "10.7.194.120:22196", "--json")
        self.assertEqual(json.loads(out)["action"], "allow")

    def test_state_and_policy(self):
        code, out, _ = run_cli("--root", self.root, "state", "--json")
        self.assertEqual(code, 0)
        state = json.loads(out)
        self.assertIn("issues_by_status", state)
        code, out, _ = run_cli("--root", self.root, "policy", "--json")
        self.assertEqual(code, 0)
        self.assertIn("classes", json.loads(out))

    def test_gc_dry_run(self):
        code, out, _ = run_cli("--root", self.root, "gc", "--json")
        self.assertEqual(code, 0)
        result = json.loads(out)
        self.assertEqual(result["dry_run"], 1)

    def test_unknown_issue_exits_two(self):
        code, _, err = run_cli("--root", self.root, "issue", "ISS-missing")
        self.assertEqual(code, 2)
        self.assertIn("unknown issue", err)


if __name__ == "__main__":
    unittest.main()

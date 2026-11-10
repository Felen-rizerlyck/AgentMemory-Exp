"""Edge-case tests: false blocks, stale recovery, Retry-After, probing, budgets."""
from __future__ import annotations

import datetime as dt
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory.models import OperationRequest
from runtime_memory.policy import Policy, default_policy
from runtime_memory.report import build_report
from runtime_memory.runtime import RuntimeMemory
from runtime_memory.timeutil import iso, parse_iso


class Clock:
    def __init__(self):
        self.now = dt.datetime(2026, 11, 2, 6, 0, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += dt.timedelta(seconds=seconds)


def make(case, enforce=False, overrides=None, budgets=None,
         policy_overrides=None):
    folder = tempfile.TemporaryDirectory()
    case.addCleanup(folder.cleanup)
    data = default_policy()
    data["enforce"] = enforce
    for error_class, values in (overrides or {}).items():
        data["classes"][error_class].update(values)
    if budgets:
        data["budgets"].update(budgets)
    if policy_overrides:
        data.update(policy_overrides)
    clock = Clock()
    return RuntimeMemory(folder.name, policy=Policy(data), clock=clock), clock


def req(**overrides):
    values = dict(component="mcp", tool="hunt.query", action="search",
                  target="http://10.7.194.120:22196/hunt/sse",
                  args={"q": "dns"}, scope="global", environment_id="lab-a",
                  run_id="edge-run")
    values.update(overrides)
    return OperationRequest(**values)


def fail(runtime, request, error_class="unreachable", **kwargs):
    return runtime.postflight(request, "fail", error_class=error_class,
                              **kwargs)


class EdgeCaseTests(unittest.TestCase):
    def test_shadow_block_then_success_is_a_false_block(self):
        runtime, _ = make(self)
        fail(runtime, req())
        decision = runtime.preflight(req())
        self.assertEqual(decision.action, "block")
        runtime.postflight(req(), "ok", decision=decision)
        report = build_report(runtime.store, now=runtime.clock())
        self.assertEqual(report["shadow"]["would_block"], 1)
        self.assertEqual(report["shadow"]["false_blocks"], 1)

    def test_auth_remains_blocked_until_expiry_then_stale_probe_resolves(self):
        runtime, clock = make(self)
        issue = fail(runtime, req(), error_class="auth")
        self.assertEqual(issue["status"], "open")
        self.assertEqual(runtime.preflight(req()).action, "block")
        clock.advance(86401)
        stale_probe = runtime.preflight(req())
        self.assertEqual(stale_probe.action, "probe")
        self.assertEqual(runtime.store.get_issue(issue["issue_id"])["status"], "stale")
        runtime.postflight(req(), "ok")
        resolved = runtime.store.get_issue(issue["issue_id"])
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(runtime.preflight(req()).action, "allow")

    def test_environment_isolation(self):
        runtime, _ = make(self)
        fail(runtime, req(environment_id="lab-a"))
        other = runtime.preflight(req(environment_id="lab-b"))
        self.assertEqual(other.action, "allow")

    def test_scope_isolation(self):
        runtime, _ = make(self)
        fail(runtime, req(scope="session"))
        self.assertEqual(runtime.preflight(req(scope="global")).action, "allow")
        self.assertEqual(runtime.preflight(req(scope="session")).action, "block")

    def test_model_note_does_not_change_status(self):
        runtime, _ = make(self)
        issue = fail(runtime, req())
        before = runtime.store.get_issue(issue["issue_id"])
        updated = runtime.add_note(issue["issue_id"], "looks like DNS issue",
                                   author="model")
        self.assertEqual(updated["status"], before["status"])
        self.assertEqual(updated["next_retry_at"], before["next_retry_at"])
        self.assertEqual(updated["notes"][0]["author"], "model")

    def test_retry_after_larger_than_ttl_extends_expiry(self):
        runtime, clock = make(self)
        issue = fail(runtime, req(),
                     error_class="rate_limit", retry_after_s=7200)
        next_retry = parse_iso(issue["next_retry_at"])
        expires = parse_iso(issue["expires_at"])
        self.assertIsNotNone(next_retry)
        self.assertIsNotNone(expires)
        self.assertGreaterEqual(expires, next_retry)
        # The issue must still be blocked at 1h (TTL) and probe only at 2h.
        clock.advance(3601)
        self.assertEqual(runtime.preflight(req()).action, "block")
        clock.advance(3600)
        self.assertEqual(runtime.preflight(req()).action, "probe")

    def test_probing_without_started_at_recovers(self):
        runtime, _ = make(self)
        issue = fail(runtime, req())
        broken = dict(issue)
        broken["status"] = "probing"
        broken["probe_started_at"] = None
        broken["next_retry_at"] = iso(runtime.clock() - dt.timedelta(seconds=1))
        runtime.store.upsert_issue(broken)
        decision = runtime.preflight(req())
        self.assertEqual(decision.action, "probe")
        self.assertEqual(runtime.store.get_issue(issue["issue_id"])["status"], "open")

    def test_probe_in_flight_blocks(self):
        runtime, _ = make(self, enforce=True)
        issue = fail(runtime, req())
        broken = dict(issue)
        broken["status"] = "probing"
        broken["probe_started_at"] = iso(runtime.clock())
        broken["next_retry_at"] = iso(runtime.clock() - dt.timedelta(seconds=1))
        runtime.store.upsert_issue(broken)
        decision = runtime.preflight(req())
        self.assertEqual(decision.action, "block")
        self.assertIn("probe", decision.reason)

    def test_per_run_budget_block_has_no_issue(self):
        runtime, _ = make(self, budgets={"max_attempts_per_call_key_per_run": 1})
        fail(runtime, req())
        decision = runtime.preflight(req())
        self.assertEqual(decision.action, "block")
        self.assertEqual(decision.issue_id, "")
        self.assertIn("run budget", decision.reason)

    def test_invalid_args_does_not_block_a_sibling_query(self):
        runtime, _ = make(self)
        fail(runtime, req(args={"q": "bad"}), error_class="invalid_args")
        self.assertEqual(runtime.preflight(req(args={"q": "good"})).action, "allow")
        self.assertEqual(runtime.preflight(req(args={"q": "bad"})).action, "block")

    def test_read_only_preflight_does_not_mutate(self):
        runtime, clock = make(self, enforce=True)
        issue = fail(runtime, req())
        clock.advance(901)
        before_decisions = len(runtime.store.read_decisions())
        decision = runtime.preflight(req(), record=False)
        self.assertEqual(decision.action, "probe")
        self.assertEqual(len(runtime.store.read_decisions()), before_decisions)
        self.assertEqual(runtime.store.get_issue(issue["issue_id"])["status"], "cooldown")

    def test_unknown_error_class_falls_back_to_scope(self):
        runtime, _ = make(self)
        issue = fail(runtime, req(), error_class="something_new")
        self.assertEqual(issue["key_level"], "scope")
        self.assertEqual(issue["error_class"], "something_new")
        self.assertEqual(runtime.preflight(req()).action, "block")

    def test_expired_issue_probe_success_resolves(self):
        runtime, clock = make(self)
        issue = fail(runtime, req())
        clock.advance(86401)
        decision = runtime.preflight(req())
        self.assertEqual(decision.action, "probe")
        runtime.postflight(req(), "ok", decision=decision)
        self.assertEqual(runtime.store.get_issue(issue["issue_id"])["status"], "resolved")

    def test_session_identity_isolation(self):
        runtime, _ = make(self)
        fail(runtime, req(scope="session", session_id="s1"))
        self.assertEqual(
            runtime.preflight(req(scope="session", session_id="s2")).action, "allow")
        self.assertEqual(
            runtime.preflight(req(scope="session", session_id="s1")).action, "block")

    def test_agent_identity_isolation(self):
        runtime, _ = make(self)
        fail(runtime, req(scope="agent", agent_id="a1"))
        self.assertEqual(
            runtime.preflight(req(scope="agent", agent_id="a2")).action, "allow")
        self.assertEqual(
            runtime.preflight(req(scope="agent", agent_id="a1")).action, "block")

    def test_global_issue_is_resolved_by_session_success(self):
        runtime, _ = make(self)
        issue = fail(runtime, req(scope="global", session_id="s1"))
        runtime.postflight(req(scope="session", session_id="s1"), "ok")
        self.assertEqual(
            runtime.store.get_issue(issue["issue_id"])["status"], "resolved")
        self.assertEqual(
            runtime.preflight(req(scope="session", session_id="s2")).action, "allow")

    def test_cross_scope_failures_are_not_merged(self):
        runtime, _ = make(self)
        global_issue = fail(runtime, req(scope="global", session_id="s1"))
        session_issue = fail(runtime, req(scope="session", session_id="s1"))
        self.assertNotEqual(global_issue["issue_id"], session_issue["issue_id"])
        self.assertEqual(global_issue["count"], 1)
        self.assertEqual(session_issue["count"], 1)

    def test_stale_issue_blocks_when_probe_after_expiry_is_false(self):
        runtime, clock = make(self, policy_overrides={"probe_after_expiry": False})
        issue = fail(runtime, req())
        clock.advance(86401)
        decision = runtime.preflight(req())
        self.assertEqual(decision.action, "block")
        self.assertIn("manual probe", decision.reason)
        self.assertEqual(
            runtime.store.get_issue(issue["issue_id"])["status"], "stale")

    def test_notes_and_workaround_are_redacted(self):
        runtime, _ = make(self)
        issue = fail(runtime, req())
        updated = runtime.add_note(issue["issue_id"], "password=hunter2")
        self.assertNotIn("hunter2", updated["notes"][0]["text"])
        updated = runtime.set_workaround(issue["issue_id"],
                                         "use token=abc123 for the backup")
        self.assertNotIn("abc123", updated["workaround"])

    def test_target_and_decision_do_not_store_url_credentials(self):
        runtime, _ = make(self)
        target = "https://alice:s3cr3t@host.example/hunt?token=abc123"
        issue = fail(runtime, req(target=target), error_class="auth")
        self.assertNotIn("alice", issue["target"])
        self.assertNotIn("s3cr3t", issue["target"])
        self.assertNotIn("abc123", issue["target"])
        event = runtime.store.read_events()[-1]
        self.assertNotIn("s3cr3t", event["target"])
        decision = runtime.preflight(req(target=target))
        self.assertNotIn("s3cr3t", decision.reason)


if __name__ == "__main__":
    unittest.main()

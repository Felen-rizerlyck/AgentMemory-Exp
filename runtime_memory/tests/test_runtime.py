"""Core state-machine and shadow/enforce tests."""
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


class FakeClock:
    def __init__(self, start=None):
        self.now = start or dt.datetime(2026, 11, 2, 6, 0, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += dt.timedelta(seconds=seconds)


def make_runtime(case, enforce=False, overrides=None, budgets=None):
    folder = tempfile.TemporaryDirectory()
    case.addCleanup(folder.cleanup)
    data = default_policy()
    data["enforce"] = enforce
    for error_class, values in (overrides or {}).items():
        data["classes"][error_class].update(values)
    if budgets:
        data["budgets"].update(budgets)
    clock = FakeClock()
    runtime = RuntimeMemory(folder.name, policy=Policy(data), clock=clock)
    return runtime, clock


def request(**overrides) -> OperationRequest:
    values = dict(component="mcp", tool="hunt.query", action="search",
                  target="10.7.194.120:22196", args={"q": "dns tunnel"},
                  scope="global", environment_id="lab-a", run_id="run-1")
    values.update(overrides)
    return OperationRequest(**values)


def fail(runtime, req, error_class="unreachable", decision=None):
    return runtime.postflight(req, "fail", error_class=error_class,
                              decision=decision, duration_ms=30000)


class IssueLifecycleTests(unittest.TestCase):
    def test_first_failure_creates_cooldown_and_blocks(self):
        runtime, _ = make_runtime(self)
        issue = fail(runtime, request())
        self.assertEqual(issue["status"], "cooldown")
        self.assertEqual(issue["count"], 1)
        decision = runtime.preflight(request())
        self.assertEqual(decision.action, "block")
        self.assertEqual(decision.issue_id, issue["issue_id"])
        self.assertIsNotNone(decision.blocked_until)

    def test_same_run_retries_do_not_open_issue(self):
        runtime, _ = make_runtime(self)
        fail(runtime, request())
        issue = fail(runtime, request())
        self.assertEqual(issue["status"], "cooldown")
        self.assertEqual(issue["count"], 2)
        self.assertEqual(len(issue["source_event_ids"]), 2)
        self.assertEqual(issue["evidence_run_ids"], ["run-1"])

    def test_independent_run_failure_opens_issue(self):
        runtime, _ = make_runtime(self)
        fail(runtime, request(run_id="run-1"))
        issue = fail(runtime, request(run_id="run-2"))
        self.assertEqual(issue["status"], "open")
        self.assertEqual(issue["evidence_run_ids"], ["run-1", "run-2"])

    def test_retry_window_opens_a_probe_then_success_resolves(self):
        runtime, clock = make_runtime(self, enforce=True)
        issue = fail(runtime, request())
        clock.advance(901)
        decision = runtime.preflight(request())
        self.assertEqual(decision.action, "probe")
        self.assertEqual(runtime.store.get_issue(issue["issue_id"])["status"], "probing")
        runtime.postflight(request(), "ok")
        resolved = runtime.store.get_issue(issue["issue_id"])
        self.assertEqual(resolved["status"], "resolved")
        self.assertEqual(resolved["resolution"], "fixed")
        self.assertEqual(runtime.preflight(request()).action, "allow")

    def test_failed_probe_reopens_issue(self):
        runtime, clock = make_runtime(self, enforce=True)
        issue = fail(runtime, request())
        clock.advance(901)
        decision = runtime.preflight(request())
        self.assertEqual(decision.action, "probe")
        updated = fail(runtime, request(), decision=decision)
        self.assertEqual(updated["status"], "cooldown")
        self.assertEqual(updated["count"], 2)
        self.assertEqual(updated["attempts"], 2)

    def test_expiry_marks_issue_stale_and_allows_probe(self):
        runtime, clock = make_runtime(self)
        issue = fail(runtime, request())
        clock.advance(86401)
        decision = runtime.preflight(request())
        self.assertEqual(decision.action, "probe")
        self.assertEqual(runtime.store.get_issue(issue["issue_id"])["status"], "stale")

    def test_non_retryable_auth_blocks_with_zero_attempts(self):
        runtime, _ = make_runtime(self)
        issue = fail(runtime, request(), error_class="auth")
        self.assertEqual(issue["status"], "open")
        self.assertIsNone(issue["next_retry_at"])
        decision = runtime.preflight(request())
        self.assertEqual(decision.action, "block")
        self.assertEqual(decision.attempts_left, 0)

    def test_attempt_budget_continues_with_slow_probes(self):
        runtime, clock = make_runtime(
            self, enforce=True,
            budgets={"max_attempts_per_call_key_per_run": 99},
        )
        for _ in range(3):
            fail(runtime, request())
        clock.advance(901)
        probe = runtime.preflight(request())
        self.assertEqual(probe.action, "probe")
        self.assertEqual(probe.attempts_left, 1)
        fail(runtime, request(), decision=probe)
        clock.advance(901)
        slow_probe = runtime.preflight(request())
        self.assertEqual(slow_probe.action, "probe")
        self.assertIn("slow recovery probe", slow_probe.reason)
        self.assertEqual(slow_probe.attempts_left, 0)

    def test_per_run_budget_blocks_before_issue_budget(self):
        runtime, _ = make_runtime(
            self,
            overrides={"unreachable": {"base_s": 0, "max_attempts": 99}},
            budgets={"max_attempts_per_call_key_per_run": 1},
        )
        fail(runtime, request(run_id="run-budget"))
        decision = runtime.preflight(request(run_id="run-budget"))
        self.assertEqual(decision.action, "block")
        self.assertIn("run budget", decision.reason)

    def test_success_resolves_scope_issue(self):
        runtime, _ = make_runtime(self)
        issue = fail(runtime, request())
        runtime.postflight(request(), "ok")
        self.assertEqual(runtime.store.get_issue(issue["issue_id"])["status"], "resolved")
        self.assertEqual(runtime.preflight(request()).action, "allow")

    def test_mitigated_issue_expires_to_stale(self):
        runtime, clock = make_runtime(self)
        issue = fail(runtime, request())
        runtime.resolve(issue["issue_id"], "workaround: use local pcap",
                        resolution="mitigated")
        self.assertEqual(runtime.preflight(request()).action, "allow_with_hint")
        clock.advance(86401)
        decision = runtime.preflight(request())
        self.assertEqual(decision.action, "probe")
        self.assertEqual(runtime.store.get_issue(issue["issue_id"])["status"], "stale")

    def test_session_issue_does_not_block_global_scope(self):
        runtime, _ = make_runtime(self)
        fail(runtime, request(scope="session"))
        self.assertEqual(runtime.preflight(request(scope="global")).action, "allow")
        self.assertEqual(runtime.preflight(request(scope="session")).action, "block")

    def test_global_issue_blocks_session_scope(self):
        runtime, _ = make_runtime(self)
        fail(runtime, request(scope="global"))
        self.assertEqual(runtime.preflight(request(scope="session")).action, "block")

    def test_call_level_issue_does_not_block_another_query(self):
        runtime, _ = make_runtime(self)
        fail(runtime, request(args={"q": "one"}), error_class="timeout")
        other = runtime.preflight(request(args={"q": "two"}))
        self.assertEqual(other.action, "allow")
        same = runtime.preflight(request(args={"q": "one"}))
        self.assertIn(same.action, ("block", "probe"))

    def test_unsupported_outcome_is_rejected(self):
        runtime, _ = make_runtime(self)
        with self.assertRaisesRegex(ValueError, "unsupported outcome"):
            runtime.postflight(request(), "maybe")

    def test_postflight_rejects_a_call_blocked_by_enforce(self):
        runtime, _ = make_runtime(self, enforce=True)
        fail(runtime, request())
        decision = runtime.preflight(request())
        self.assertEqual(decision.action, "block")
        with self.assertRaisesRegex(ValueError, "blocked call"):
            runtime.postflight(request(), "ok", decision=decision)

    def test_check_is_clean_after_transitions(self):
        runtime, clock = make_runtime(self)
        fail(runtime, request())
        clock.advance(901)
        runtime.preflight(request())
        runtime.postflight(request(), "ok")
        self.assertEqual(runtime.store.check(), [])


class ShadowTests(unittest.TestCase):
    def test_shadow_records_would_block_but_does_not_prevent_call(self):
        runtime, _ = make_runtime(self, enforce=False)
        fail(runtime, request())
        decision = runtime.preflight(request())
        self.assertEqual(decision.action, "block")
        self.assertTrue(decision.shadow)
        event = runtime.postflight(request(), "fail", error_class="unreachable",
                                   decision=decision)
        self.assertIsNotNone(event)
        events = runtime.store.read_events()
        self.assertTrue(events[-1]["would_block"])
        report = build_report(runtime.store)
        self.assertEqual(report["shadow"]["would_block"], 1)
        self.assertEqual(report["shadow"]["false_blocks"], 0)
        self.assertEqual(report["shadow"]["confirmed_blocks"], 1)

    def test_shadow_false_block_is_measured_when_call_succeeds(self):
        runtime, _ = make_runtime(self, enforce=False)
        fail(runtime, request())
        decision = runtime.preflight(request())
        self.assertEqual(decision.action, "block")
        runtime.postflight(request(), "ok", decision=decision)
        report = build_report(runtime.store)
        self.assertEqual(report["shadow"]["would_block"], 1)
        self.assertEqual(report["shadow"]["false_blocks"], 1)

    def test_enforce_blocks_and_records_no_second_event(self):
        runtime, _ = make_runtime(self, enforce=True)
        fail(runtime, request())
        decision = runtime.preflight(request())
        self.assertEqual(decision.action, "block")
        self.assertFalse(decision.shadow)
        report = build_report(runtime.store)
        self.assertEqual(report["enforce"]["blocked_calls"], 1)
        self.assertEqual(report["events"]["total"], 1)

    def test_override_allows_one_probe_and_is_logged(self):
        runtime, clock = make_runtime(self, enforce=True)
        fail(runtime, request())
        decision = runtime.preflight(request(), allow_probe=True,
                                     override_basis="operator asked for a probe",
                                     human_override=True)
        self.assertEqual(decision.action, "probe")
        self.assertTrue(decision.override)
        self.assertEqual(len(runtime.store.read_overrides()), 1)
        runtime.postflight(request(), "ok", decision=decision)
        self.assertEqual(runtime.preflight(request()).action, "allow")

    def test_override_requires_basis(self):
        runtime, _ = make_runtime(self, enforce=True)
        fail(runtime, request())
        with self.assertRaisesRegex(ValueError, "override_basis"):
            runtime.preflight(request(), allow_probe=True, human_override=True)

    def test_model_override_is_rejected(self):
        runtime, _ = make_runtime(self, enforce=True)
        fail(runtime, request(), error_class="auth")
        with self.assertRaisesRegex(ValueError, "human_override"):
            runtime.preflight(request(), allow_probe=True,
                              override_basis="model wants to try")

    def test_read_only_preflight_does_not_persist(self):
        runtime, clock = make_runtime(self, enforce=True)
        issue = fail(runtime, request())
        clock.advance(901)
        before = len(runtime.store.read_decisions())
        decision = runtime.preflight(request(), record=False)
        self.assertEqual(decision.action, "probe")
        self.assertEqual(len(runtime.store.read_decisions()), before)
        self.assertEqual(runtime.store.get_issue(issue["issue_id"])["status"], "cooldown")


class ManualAndReportTests(unittest.TestCase):
    def test_resolve_and_note_do_not_reopen(self):
        runtime, _ = make_runtime(self)
        issue = fail(runtime, request())
        resolved = runtime.resolve(issue["issue_id"], "endpoint restored")
        self.assertEqual(resolved["status"], "resolved")
        runtime.add_note(issue["issue_id"], "checked twice", author="analyst")
        after = runtime.store.get_issue(issue["issue_id"])
        self.assertEqual(after["status"], "resolved")
        self.assertEqual(after["notes"][0]["author"], "analyst")

    def test_workaround_is_returned_without_changing_status(self):
        runtime, _ = make_runtime(self)
        issue = fail(runtime, request())
        updated = runtime.set_workaround(issue["issue_id"], "use local pcap")
        self.assertEqual(updated["status"], issue["status"])
        self.assertEqual(updated["workaround"], "use local pcap")
        decision = runtime.preflight(request())
        self.assertIn("use local pcap", decision.alternatives)

    def test_ignore_sets_resolution_ignored(self):
        runtime, _ = make_runtime(self)
        issue = fail(runtime, request(), error_class="internal")
        ignored = runtime.ignore(issue["issue_id"], "false alarm")
        self.assertEqual(ignored["status"], "resolved")
        self.assertEqual(ignored["resolution"], "ignored")

    def test_event_attempt_matches_issue_counter(self):
        runtime, _ = make_runtime(self)
        for _ in range(3):
            fail(runtime, request())
        events = runtime.store.read_events()
        self.assertEqual([event["attempt"] for event in events], [1, 2, 3])

    def test_success_after_retry_uses_the_next_attempt_number(self):
        runtime, clock = make_runtime(
            self, enforce=True,
            budgets={"max_attempts_per_call_key_per_run": 99},
        )
        for _ in range(3):
            fail(runtime, request())
        clock.advance(901)
        probe = runtime.preflight(request())
        self.assertEqual(probe.action, "probe")
        runtime.postflight(request(), "ok", decision=probe)
        events = runtime.store.read_events()
        self.assertEqual(events[-1]["attempt"], 4)
        issue = runtime.store.find_issue(
            events[-1]["fingerprint"], "unreachable", include_resolved=True)
        self.assertEqual(issue["attempts"], 4)

    def test_ids_use_the_injected_clock(self):
        runtime, _ = make_runtime(self)
        issue = fail(runtime, request())
        self.assertTrue(issue["issue_id"].startswith("ISS-20261102T0600"))
        self.assertTrue(runtime.store.read_events()[-1]["event_id"].startswith("OP-20261102T0600"))

    def test_duplicate_attempts_are_reported(self):
        runtime, _ = make_runtime(self)
        for _ in range(3):
            fail(runtime, request())
        report = build_report(runtime.store)
        self.assertEqual(report["duplicate_attempts"], 2)
        self.assertEqual(report["issues"]["by_status"]["open"], 0)
        self.assertEqual(report["issues"]["by_status"]["cooldown"], 1)

    def test_report_json_serializable(self):
        runtime, _ = make_runtime(self)
        fail(runtime, request())
        import json
        json.dumps(build_report(runtime.store))


if __name__ == "__main__":
    unittest.main()

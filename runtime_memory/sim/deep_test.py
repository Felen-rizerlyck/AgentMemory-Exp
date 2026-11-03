#!/usr/bin/env python3
"""Deep behavioural test matrix for the runtime-memory prototype.

This is a *test/report* harness, not part of the algorithm.  It imports the
public package from ``runtime_memory/src`` and exercises it with fake clocks and
temporary data directories.  It never writes to ``runtime_memory/data`` and it
does not modify any source file.

Run from ``runtime_memory/``::

    python sim/deep_test.py

The default output directory is ``sim/runs/deep-2026-11-03/``; use ``--out`` to
choose another one and ``--force`` to overwrite it.  The output contains
``report.json`` (machine-readable checks) and ``summary.md`` (human-readable).

The checks are grouped as:

* ``mode``      shadow / enforce / probe / override / manual operations
* ``state``     cooldown -> open -> probing -> stale / resolved, TTL and budgets
* ``scope``     environment / session / agent / global sharing semantics
* ``identity``  fingerprints, key levels, argument normalisation
* ``classify``  exception -> error_class mapping
* ``security``  redaction of messages and targets
* ``store``     multi-process writes, corrupt journals, garbage collection
* ``report``    shadow/enforce metrics
* ``audit``     override and block traceability

Checks that deviate from ``docs/RUNTIME_MEMORY_DESIGN.md`` or the README are
reported as ``FINDING`` (behaviour probably needs a decision/fix).  Design
features that are simply absent are reported as ``GAP``.  Robustness crashes
are ``CRASH``.  Nothing here is fixed automatically: the assignment explicitly
asks for testing and a report, not for an algorithm change.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import inspect
import json
import multiprocessing as mp
import os
import platform
import shutil
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory import OperationRequest, Policy, RuntimeMemory  # noqa: E402
from runtime_memory.classify import classify_exception  # noqa: E402
from runtime_memory.fingerprint import (call_fingerprint,  # noqa: E402
                                        normalize_target, scope_fingerprint)
from runtime_memory.models import Issue  # noqa: E402
from runtime_memory.policy import default_policy  # noqa: E402
from runtime_memory.redact import redact  # noqa: E402
from runtime_memory.report import build_report  # noqa: E402
from runtime_memory.store import Store, append_jsonl  # noqa: E402
from runtime_memory.timeutil import iso, parse_iso  # noqa: E402

DEFAULT_OUT = ROOT / "sim" / "runs" / "deep-2026-11-03"
START = dt.datetime(2026, 11, 2, 6, 0, tzinfo=dt.timezone.utc)


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------

class Clock:
    """Fake UTC clock used by every deterministic check."""

    def __init__(self, start: dt.datetime = START):
        self.now = start

    def __call__(self) -> dt.datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += dt.timedelta(seconds=seconds)


def request(**overrides: Any) -> OperationRequest:
    values: dict[str, Any] = dict(
        component="mcp", tool="hunt.query", action="search",
        target="http://10.7.194.120:22196/hunt/sse",
        args={"q": "dns tunnel"},
        scope="global", environment_id="lab-a",
        session_id="s1", run_id="",
    )
    values.update(overrides)
    return OperationRequest(**values)


def make_runtime(root: str, *, enforce: bool = False, clock: Clock | None = None,
                 mutate: Callable[[dict[str, Any]], None] | None = None
                 ) -> RuntimeMemory:
    data = copy.deepcopy(default_policy())
    data["enforce"] = enforce
    if mutate is not None:
        mutate(data)
    return RuntimeMemory(root, policy=Policy(data), clock=clock or Clock())


def issue_of(runtime: RuntimeMemory, *, key_level: str | None = None) -> dict[str, Any]:
    issues = runtime.store.list_issues()
    if key_level is not None:
        issues = [item for item in issues if item.get("key_level") == key_level]
    return issues[0]


def result(check_id: str, category: str, title: str, status: str,
           severity: str, expected: str, observed: str,
           evidence: Any = None) -> dict[str, Any]:
    return {
        "id": check_id,
        "category": category,
        "title": title,
        "status": status,
        "severity": severity,
        "expected": expected,
        "observed": observed,
        "evidence": evidence,
    }


def as_finding(check_id: str, category: str, title: str, expected: str,
               observed: str, evidence: Any = None,
               severity: str = "medium") -> dict[str, Any]:
    return result(check_id, category, title, "FINDING", severity,
                  expected, observed, evidence)


def as_gap(check_id: str, category: str, title: str, expected: str,
           observed: str, evidence: Any = None,
           severity: str = "low") -> dict[str, Any]:
    return result(check_id, category, title, "GAP", severity,
                  expected, observed, evidence)


def as_pass(check_id: str, category: str, title: str, expected: str,
            observed: str, evidence: Any = None) -> dict[str, Any]:
    return result(check_id, category, title, "PASS", "info",
                  expected, observed, evidence)


def as_crash(check_id: str, category: str, title: str, expected: str,
             observed: str, evidence: Any = None,
             severity: str = "medium") -> dict[str, Any]:
    return result(check_id, category, title, "CRASH", severity,
                  expected, observed, evidence)


# ---------------------------------------------------------------------------
# mode: shadow / enforce / probe / manual operations
# ---------------------------------------------------------------------------

def check_shadow_mode() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-shadow-") as root:
        clock = Clock()
        runtime = make_runtime(root, clock=clock)
        req = request()
        runtime.postflight(req, "fail",
                          error=ConnectionRefusedError("connect refused"))
        decision = runtime.preflight(req)
        runtime.postflight(req, "ok", decision=decision)
        events = runtime.store.read_events()
        report = build_report(runtime.store, now=clock.now)
        ok_event = next((item for item in events if item["outcome"] == "ok"), {})
        observed = {
            "decision": decision.action,
            "shadow": decision.shadow,
            "events": len(events),
            "would_block_on_ok_event": ok_event.get("would_block"),
            "shadow_report": report["shadow"],
        }
        ok = (decision.action == "block" and decision.shadow
              and len(events) == 2 and ok_event.get("would_block") is True
              and report["shadow"]["would_block"] == 1
              and report["shadow"]["false_blocks"] == 1)
        if ok:
            return as_pass("mode.shadow", "mode",
                           "shadow records block but still executes the call",
                           "decision block, 2 events, would_block=true, "
                           "shadow false_blocks=1", str(observed), observed)
        return as_finding("mode.shadow", "mode",
                          "shadow records block but still executes the call",
                          "decision block, 2 events, would_block=true, "
                          "shadow false_blocks=1", str(observed), observed)


def check_enforce_mode() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-enforce-") as root:
        clock = Clock()
        runtime = make_runtime(root, enforce=True, clock=clock)
        req = request()
        runtime.postflight(req, "fail",
                          error=ConnectionRefusedError("connect refused"))
        decision = runtime.preflight(req)
        raised = False
        try:
            runtime.postflight(req, "ok", decision=decision)
        except ValueError:
            raised = True
        events = runtime.store.read_events()
        observed = {
            "decision": decision.action,
            "postflight_for_block_raises": raised,
            "events": [(item["outcome"], item["would_block"]) for item in events],
        }
        if decision.action == "block" and raised and len(events) == 1:
            return as_pass("mode.enforce", "mode",
                           "enforce mode refuses postflight for a blocked call",
                           "block; postflight raises; only the real failure event "
                           "is stored", str(observed), observed)
        return as_finding("mode.enforce", "mode",
                          "enforce mode refuses postflight for a blocked call",
                          "block; postflight raises; only the real failure event "
                          "is stored", str(observed), observed)


def check_enforce_probe_in_flight() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-probe-") as root:
        clock = Clock()
        runtime = make_runtime(root, enforce=True, clock=clock)
        req = request()
        runtime.postflight(req, "fail",
                          error=ConnectionRefusedError("connect refused"))
        clock.advance(901)
        first = runtime.preflight(req)
        second = runtime.preflight(req)
        issue = issue_of(runtime)
        observed = {
            "first": first.action,
            "second": second.action,
            "second_reason": second.reason,
            "issue_status": issue["status"],
            "probe_started_at": bool(issue.get("probe_started_at")),
        }
        if (first.action == "probe" and issue["status"] == "probing"
                and second.action == "block" and "probe" in second.reason):
            return as_pass("mode.probe_in_flight", "mode",
                           "a second preflight while a probe is in flight blocks",
                           "first probe, issue=probing, second block",
                           str(observed), observed)
        return as_finding("mode.probe_in_flight", "mode",
                          "a second preflight while a probe is in flight blocks",
                          "first probe, issue=probing, second block",
                          str(observed), observed)


def check_probe_success_and_failure() -> tuple[dict[str, Any], dict[str, Any]]:
    success_result: dict[str, Any]
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-probe-ok-") as root:
        clock = Clock()
        runtime = make_runtime(root, enforce=True, clock=clock)
        req = request()
        runtime.postflight(req, "fail",
                          error=ConnectionRefusedError("connect refused"))
        clock.advance(901)
        decision = runtime.preflight(req)
        runtime.postflight(req, "ok", decision=decision)
        issue = issue_of(runtime)
        after = runtime.preflight(req)
        observed = {"decision": decision.action, "status": issue["status"],
                    "next_preflight": after.action}
        success_result = (
            as_pass("mode.probe_ok", "mode",
                    "a successful probe resolves the issue",
                    "probe -> resolved -> allow", str(observed), observed)
            if issue["status"] == "resolved" and after.action == "allow"
            else as_finding("mode.probe_ok", "mode",
                            "a successful probe resolves the issue",
                            "probe -> resolved -> allow", str(observed), observed)
        )

    with tempfile.TemporaryDirectory(prefix="rtmem-deep-probe-fail-") as root:
        clock = Clock()
        runtime = make_runtime(root, enforce=True, clock=clock)
        req = request()
        runtime.postflight(req, "fail",
                          error=ConnectionRefusedError("connect refused"))
        clock.advance(901)
        decision = runtime.preflight(req)
        runtime.postflight(req, "fail",
                          error=ConnectionRefusedError("still refused"),
                          decision=decision)
        issue = issue_of(runtime)
        observed = {"decision": decision.action, "status": issue["status"],
                    "count": issue["count"], "attempts": issue["attempts"]}
        failure_result = (
            as_pass("mode.probe_fail", "mode",
                    "a failed probe reopens the issue and increments the backoff",
                    "open, count=2, attempts=2", str(observed), observed)
            if issue["status"] == "open" and issue["count"] == 2
            and issue["attempts"] == 2
            else as_finding("mode.probe_fail", "mode",
                            "a failed probe reopens the issue and increments "
                            "the backoff", "open, count=2, attempts=2",
                            str(observed), observed)
        )
    return success_result, failure_result


def check_manual_operations() -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-resolve-") as root:
        runtime = make_runtime(root)
        req = request()
        issue = runtime.postflight(req, "fail",
                                   error=ConnectionRefusedError("connect refused"))
        runtime.resolve(issue["issue_id"], "endpoint restored", reviewer="analyst")
        after_resolve = runtime.preflight(req)
        runtime.postflight(req, "fail",
                          error=ConnectionRefusedError("connect refused"))
        reopened = issue_of(runtime)
        runtime.ignore(reopened["issue_id"], "false alarm", reviewer="analyst")
        issue_after_ignore = runtime.store.get_issue(reopened["issue_id"])
        observed = {"after_resolve": after_resolve.action,
                    "after_new_failure": reopened["status"],
                    "after_ignore": issue_after_ignore["status"],
                    "ignore_resolution": issue_after_ignore["resolution"]}
        manual_result = (
            as_pass("mode.manual", "mode",
                    "resolve allows the call and a new failure reopens the issue",
                    "allow; reopen; ignore -> resolved", str(observed), observed)
            if after_resolve.action == "allow" and reopened["status"] in ("cooldown", "open")
            and issue_after_ignore["status"] == "resolved"
            and issue_after_ignore["resolution"] == "ignored"
            else as_finding("mode.manual", "mode",
                            "resolve allows the call and a new failure reopens "
                            "the issue", "allow; reopen; ignore -> resolved",
                            str(observed), observed)
        )

    with tempfile.TemporaryDirectory(prefix="rtmem-deep-mitigated-") as root:
        runtime = make_runtime(root)
        req = request()
        issue = runtime.postflight(req, "fail",
                                   error=ConnectionRefusedError("connect refused"))
        runtime.set_workaround(issue["issue_id"], "use local pcap")
        runtime.resolve(issue["issue_id"], "workaround available",
                        resolution="mitigated")
        decision = runtime.preflight(req)
        observed = {"decision": decision.action,
                    "alternatives": decision.alternatives,
                    "issue_status": runtime.store.get_issue(issue["issue_id"])["status"]}
        hint_result = (
            as_pass("mode.mitigated", "mode",
                    "a mitigated issue yields allow_with_hint and the workaround",
                    "allow_with_hint + alternatives", str(observed), observed)
            if decision.action == "allow_with_hint" and decision.alternatives
            else as_finding("mode.mitigated", "mode",
                            "a mitigated issue yields allow_with_hint and the "
                            "workaround", "allow_with_hint + alternatives",
                            str(observed), observed)
        )
    return manual_result, hint_result


def check_workaround_only() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-workaround-") as root:
        runtime = make_runtime(root)
        req = request()
        issue = runtime.postflight(req, "fail",
                                   error=ConnectionRefusedError("connect refused"))
        runtime.set_workaround(issue["issue_id"], "use local pcap")
        decision = runtime.preflight(req)
        status = runtime.store.get_issue(issue["issue_id"])["status"]
        observed = {"status": status, "decision": decision.action,
                    "alternatives": decision.alternatives}
        if status == "mitigated" and decision.action == "allow_with_hint":
            return as_pass("mode.workaround_only", "mode",
                           "recording a workaround transitions to mitigated",
                           "mitigated + allow_with_hint", str(observed), observed)
        return as_finding(
            "mode.workaround_only", "mode",
            "recording a workaround transitions to mitigated",
            "set_workaround should make the issue mitigated (design §7.2 / "
            "README_CN §3.3) and preflight should return allow_with_hint",
            str(observed), observed, severity="low")


def check_override() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-override-") as root:
        clock = Clock()
        runtime = make_runtime(root, enforce=True, clock=clock)
        req = request()
        runtime.postflight(req, "fail", error_class="auth")
        blocked = runtime.preflight(req)
        forced = runtime.preflight(req, allow_probe=True,
                                   override_basis="model wants to retry")
        issue = issue_of(runtime)
        observed = {"blocked": blocked.action, "override": forced.action,
                    "override_reason": forced.reason,
                    "issue_status": issue["status"],
                    "overrides": len(runtime.store.read_overrides())}
        auth_result = (
            as_finding(
                "mode.override_auth", "mode",
                "model override bypasses a non-retryable auth block",
                "auth is non-retryable and should require a human/operator "
                "decision (design §7.3, §9.3); a model override should not be "
                "enough",
                str(observed), observed, severity="high")
            if forced.action == "probe" and issue["status"] == "probing"
            else as_pass("mode.override_auth", "mode",
                         "model override does not bypass non-retryable auth",
                         "auth block remains authoritative", str(observed), observed)
        )
        audit_result = (
            as_pass("mode.override_audit", "mode",
                    "every override is recorded in overrides.jsonl",
                    "one override record with basis", str(observed), observed)
            if len(runtime.store.read_overrides()) == 1
            else as_finding("mode.override_audit", "mode",
                            "every override is recorded in overrides.jsonl",
                            "one override record with basis", str(observed), observed)
        )

    with tempfile.TemporaryDirectory(prefix="rtmem-deep-override-budget-") as root:
        runtime = make_runtime(
            root, mutate=lambda data: data["budgets"].update(
                max_attempts_per_call_key_per_run=1))
        req = request(run_id="budget-run")
        runtime.postflight(req, "fail",
                          error=ConnectionRefusedError("connect refused"))
        blocked = runtime.preflight(req)
        forced = runtime.preflight(req, allow_probe=True,
                                   override_basis="try anyway")
        observed = {"blocked": blocked.action, "blocked_reason": blocked.reason,
                    "blocked_issue_id": blocked.issue_id,
                    "override": forced.action, "override_reason": forced.reason,
                    "override_issue_id": forced.issue_id}
        budget_result = (
            as_finding(
                "mode.override_budget", "mode",
                "model override bypasses the per-run hard budget",
                "the per-run budget is described as a hard guard; an override "
                "should not turn its block into a probe",
                str(observed), observed, severity="high")
            if blocked.action == "block" and "run budget" in blocked.reason
            and forced.action == "probe"
            else as_pass("mode.override_budget", "mode",
                         "model override does not bypass the per-run budget",
                         "run-budget block remains authoritative",
                         str(observed), observed)
        )
    return auth_result, budget_result, audit_result


# ---------------------------------------------------------------------------
# state machine, TTL and budgets
# ---------------------------------------------------------------------------

def check_state_machine() -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-state-") as root:
        clock = Clock()
        runtime = make_runtime(root, clock=clock)
        req = request()
        first = runtime.postflight(req, "fail",
                                   error=ConnectionRefusedError("connect refused"))
        second = runtime.postflight(req, "fail", error_class="unreachable")
        observed = {"first_status": first["status"], "first_count": first["count"],
                    "second_status": second["status"], "second_count": second["count"]}
        state_result = (
            as_pass("state.cooldown_open", "state",
                    "the first failure creates cooldown, the second opens the issue",
                    "cooldown count=1; open count=2", str(observed), observed)
            if first["status"] == "cooldown" and first["count"] == 1
            and second["status"] == "open" and second["count"] == 2
            else as_finding("state.cooldown_open", "state",
                            "the first failure creates cooldown, the second "
                            "opens the issue", "cooldown count=1; open count=2",
                            str(observed), observed)
        )

    with tempfile.TemporaryDirectory(prefix="rtmem-deep-window-") as root:
        clock = Clock()
        runtime = make_runtime(root, clock=clock)
        req = request()
        runtime.postflight(req, "fail", error=ConnectionRefusedError("connect refused"))
        before = runtime.preflight(req)
        clock.advance(901)
        after = runtime.preflight(req)
        observed = {"before": before.action, "after": after.action}
        window_result = (
            as_pass("state.retry_window", "state",
                    "preflight blocks before next_retry_at and probes after it",
                    "block -> probe", str(observed), observed)
            if before.action == "block" and after.action == "probe"
            else as_finding("state.retry_window", "state",
                            "preflight blocks before next_retry_at and probes "
                            "after it", "block -> probe", str(observed), observed)
        )
    return state_result, window_result


def check_retry_after_and_auth() -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-retry-after-") as root:
        clock = Clock()
        runtime = make_runtime(root, clock=clock)
        req = request()
        issue = runtime.postflight(req, "fail", error_class="rate_limit",
                                   retry_after_s=7200)
        next_retry = parse_iso(issue["next_retry_at"])
        expires = parse_iso(issue["expires_at"])
        clock.advance(3601)
        at_one_hour = runtime.preflight(req)
        clock.advance(3600)
        at_two_hours = runtime.preflight(req)
        observed = {
            "next_retry_at": issue["next_retry_at"],
            "expires_at": issue["expires_at"],
            "at_one_hour": at_one_hour.action,
            "at_two_hours": at_two_hours.action,
            "delta_s": int((next_retry - START).total_seconds()) if next_retry else None,
            "expiry_after_retry": expires >= next_retry if expires and next_retry else None,
        }
        retry_after_result = (
            as_pass("state.retry_after", "state",
                    "Retry-After wins over the class backoff and extends expiry",
                    "next_retry=+7200s, block at +1h, probe at +2h",
                    str(observed), observed)
            if observed["delta_s"] == 7200 and observed["expiry_after_retry"]
            and at_one_hour.action == "block" and at_two_hours.action == "probe"
            else as_finding("state.retry_after", "state",
                            "Retry-After wins over the class backoff and extends "
                            "expiry", "next_retry=+7200s, block at +1h, probe "
                            "at +2h", str(observed), observed)
        )

    with tempfile.TemporaryDirectory(prefix="rtmem-deep-auth-") as root:
        clock = Clock()
        runtime = make_runtime(root, clock=clock)
        req = request()
        issue = runtime.postflight(req, "fail", error_class="auth")
        immediate = runtime.preflight(req)
        clock.advance(86401)
        stale = runtime.preflight(req)
        observed = {"initial_status": issue["status"],
                    "immediate": immediate.action,
                    "stale": stale.action,
                    "status": runtime.store.get_issue(issue["issue_id"])["status"]}
        auth_result = (
            as_pass("state.auth_stale", "state",
                    "non-retryable auth blocks until TTL, then allows one probe",
                    "open/block; stale/probe", str(observed), observed)
            if issue["status"] == "open" and immediate.action == "block"
            and stale.action == "probe"
            else as_finding("state.auth_stale", "state",
                            "non-retryable auth blocks until TTL, then allows "
                            "one probe", "open/block; stale/probe",
                            str(observed), observed)
        )
    return retry_after_result, auth_result


def check_probe_recovery() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-recovery-") as root:
        clock = Clock()
        runtime = make_runtime(root, clock=clock)
        req = request()
        issue = runtime.postflight(req, "fail",
                                   error=ConnectionRefusedError("connect refused"))
        broken = dict(issue)
        broken["status"] = "probing"
        broken["probe_started_at"] = None
        broken["next_retry_at"] = iso(clock.now - dt.timedelta(seconds=1))
        runtime.store.upsert_issue(broken)
        decision = runtime.preflight(req)
        status = runtime.store.get_issue(issue["issue_id"])["status"]
        observed = {"decision": decision.action, "status": status}
        if decision.action == "probe" and status == "open":
            return as_pass("state.abandoned_probe", "state",
                           "an abandoned probe without probe_started_at recovers",
                           "probe; issue back to open", str(observed), observed)
        return as_finding("state.abandoned_probe", "state",
                          "an abandoned probe without probe_started_at recovers",
                          "probe; issue back to open", str(observed), observed)


def check_attempt_budget() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-budget-") as root:
        clock = Clock()
        runtime = make_runtime(
            root, clock=clock, mutate=lambda data: (
                data["budgets"].update(max_attempts_per_call_key_per_run=99,
                                       max_failures_per_component_per_run=99)))
        req = request()
        failures = 0
        last = None
        for _ in range(6):
            last = runtime.preflight(req)
            if last.action == "block":
                break
            runtime.postflight(req, "fail",
                               error=ConnectionRefusedError("connect refused"))
            failures += 1
            clock.advance(901)
        issue = issue_of(runtime)
        observed = {"failures": failures, "attempts": issue["attempts"],
                    "block_reason": last.reason if last else None}
        # README: max_attempts counts retries *after* the initial failure, so
        # 3 failures + a final blocked preflight is attempts=3 and a 4th failure
        # is still allowed before the budget blocks on attempt 4.
        if failures == 4 and issue["attempts"] == 4 and last \
                and "attempt budget exhausted" in last.reason:
            return as_pass("state.attempt_budget", "state",
                           "the issue-level attempt budget eventually blocks",
                           "3 retries after the initial failure (4 calls) then "
                           "block", str(observed), observed)
        return as_finding("state.attempt_budget", "state",
                          "the issue-level attempt budget eventually blocks",
                          "3 retries after the initial failure (4 calls) then "
                          "block", str(observed), observed)


def check_per_class_run_budget() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-class-budget-") as root:
        clock = Clock()
        runtime = make_runtime(
            root, clock=clock, mutate=lambda data: (
                data["budgets"].update(max_attempts_per_call_key_per_run=99,
                                       max_failures_per_component_per_run=99)))
        req = request(run_id="one-run")
        failures = 0
        for _ in range(6):
            decision = runtime.preflight(req)
            if decision.action == "block":
                break
            runtime.postflight(req, "fail",
                               error=ConnectionRefusedError("connect refused"))
            failures += 1
            clock.advance(901)
        issue = issue_of(runtime)
        observed = {"class_max_attempts_per_run": 1,
                    "failures_in_single_run": failures,
                    "issue_attempts": issue["attempts"]}
        if failures <= 1:
            return as_pass("state.per_class_run_budget", "state",
                           "the class-level max_attempts_per_run is enforced",
                           "at most 1 unreachable failure in one run",
                           str(observed), observed)
        return as_gap(
            "state.per_class_run_budget", "state",
            "the class-level max_attempts_per_run is not enforced",
            "policy.classes.unreachable.max_attempts_per_run=1 should cap "
            "failures in one run",
            str(observed), observed, severity="medium")


def check_probe_after_expiry_config() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-expiry-") as root:
        clock = Clock()
        runtime = make_runtime(
            root, clock=clock,
            mutate=lambda data: data["defaults"].update(probe_after_expiry=False))
        req = request()
        runtime.postflight(req, "fail", error_class="auth")
        clock.advance(86401)
        decision = runtime.preflight(req)
        observed = {"configured_probe_after_expiry": False,
                    "decision": decision.action, "reason": decision.reason}
        if decision.action != "probe":
            return as_pass("state.probe_after_expiry", "state",
                           "probe_after_expiry=false prevents a stale probe",
                           "no probe after expiry", str(observed), observed)
        return as_gap(
            "state.probe_after_expiry", "state",
            "probe_after_expiry=false is ignored",
            "policy.defaults.probe_after_expiry should be honoured",
            str(observed), observed, severity="low")


def check_read_only_preflight() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-readonly-") as root:
        clock = Clock()
        runtime = make_runtime(root, clock=clock)
        req = request()
        issue = runtime.postflight(req, "fail",
                                   error=ConnectionRefusedError("connect refused"))
        clock.advance(86401)
        before = runtime.store.get_issue(issue["issue_id"])["status"]
        decision = runtime.preflight(req, record=False)
        after = runtime.store.get_issue(issue["issue_id"])["status"]
        observed = {"status_before": before, "decision": decision.action,
                    "status_after": after,
                    "decisions": len(runtime.store.read_decisions())}
        if before == after:
            return as_pass("state.read_only", "state",
                           "record=False is a read-only inspection",
                           "no persisted issue state change", str(observed), observed)
        return as_finding(
            "state.read_only", "state",
            "record=False still persists an issue state refresh",
            "record=False should not mutate the store (docstring: read-only "
            "inspection)",
            str(observed), observed, severity="low")


def check_mitigated_after_expiry() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-mitigated-expired-") as root:
        clock = Clock()
        runtime = make_runtime(root, clock=clock)
        req = request()
        issue = runtime.postflight(req, "fail",
                                   error=ConnectionRefusedError("connect refused"))
        clock.advance(86401)
        runtime.preflight(req)  # refresh -> stale
        mitigated = runtime.resolve(issue["issue_id"], "use local pcap",
                                    resolution="mitigated")
        decision = runtime.preflight(req)
        status = runtime.store.get_issue(issue["issue_id"])["status"]
        observed = {"status_after_resolve": mitigated["status"],
                    "expires_at": mitigated["expires_at"],
                    "next_decision": decision.action,
                    "status_after_next_preflight": status}
        if status == "mitigated":
            return as_pass("state.mitigated_expired", "state",
                           "a mitigated issue stays mitigated after TTL",
                           "mitigated remains active", str(observed), observed)
        return as_finding(
            "state.mitigated_expired", "state",
            "mitigating an already-expired issue is immediately undone",
            "resolve(..., resolution='mitigated') should remain mitigated "
            "until it is re-checked or a new failure occurs",
            str(observed), observed, severity="medium")


def check_jitter() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-jitter-") as root:
        clock = Clock()
        runtime = make_runtime(root, clock=clock)
        req = request()
        delays: list[int] = []
        for _ in range(3):
            issue = runtime.postflight(req, "fail", error_class="timeout")
            stamp = parse_iso(issue["next_retry_at"])
            delays.append(int((stamp - clock.now).total_seconds()) if stamp else -1)
        observed = {"delays_s": delays, "expected_without_jitter": [30, 60, 120]}
        if any(abs(delay - base) > max(1, int(base * 0.2))
               for delay, base in zip(delays, [30, 60, 120])):
            return as_pass("state.jitter", "state",
                           "exponential backoff includes jitter",
                           "delays vary by ±20% around 30/60/120",
                           str(observed), observed)
        return as_gap(
            "state.jitter", "state",
            "exponential backoff has no jitter",
            "design §10.2 calls for ±20% jitter to avoid synchronised retries",
            str(observed), observed, severity="low")


# ---------------------------------------------------------------------------
# scope / isolation
# ---------------------------------------------------------------------------

def check_scope_isolation() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-env-") as root:
        runtime = make_runtime(root)
        runtime.postflight(request(environment_id="lab-a"), "fail",
                          error=ConnectionRefusedError("connect refused"))
        other = runtime.preflight(request(environment_id="lab-b"))
        observed = {"lab_a_failure": True, "lab_b": other.action}
        env_result = (
            as_pass("scope.environment", "scope",
                    "environment_id isolates issues",
                    "lab-b is allowed", str(observed), observed)
            if other.action == "allow"
            else as_finding("scope.environment", "scope",
                            "environment_id isolates issues",
                            "lab-b is allowed", str(observed), observed)
        )

    with tempfile.TemporaryDirectory(prefix="rtmem-deep-session-") as root:
        runtime = make_runtime(root)
        runtime.postflight(
            request(scope="session", session_id="session-a", run_id="run-a"),
            "fail", error=ConnectionRefusedError("connect refused"))
        other = runtime.preflight(
            request(scope="session", session_id="session-b", run_id="run-b"))
        observed = {"failure_session": "session-a",
                    "other_session": "session-b",
                    "decision": other.action, "reason": other.reason}
        session_result = (
            as_pass("scope.session", "scope",
                    "session-scope issues are isolated to one session",
                    "session-b is allowed", str(observed), observed)
            if other.action == "allow"
            else as_finding(
                "scope.session", "scope",
                "a session-scope issue blocks every other session",
                "design §13: 'session 只在本 run 生效'; session-a must not "
                "block session-b",
                str(observed), observed, severity="high")
        )

    with tempfile.TemporaryDirectory(prefix="rtmem-deep-agent-") as root:
        runtime = make_runtime(root)
        runtime.postflight(
            request(scope="agent", session_id="agent-a", run_id="run-a"),
            "fail", error=ConnectionRefusedError("connect refused"))
        other = runtime.preflight(
            request(scope="agent", session_id="agent-b", run_id="run-b"))
        observed = {"decision": other.action, "reason": other.reason}
        agent_result = (
            as_pass("scope.agent", "scope",
                    "agent-scope issues are isolated to one agent",
                    "agent-b is allowed", str(observed), observed)
            if other.action == "allow"
            else as_finding(
                "scope.agent", "scope",
                "an agent-scope issue blocks every other agent",
                "design §13: 'agent' means one Agent; agent-a must not block "
                "agent-b",
                str(observed), observed, severity="high")
        )
    return env_result, session_result, agent_result


def check_global_resolution() -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-global-") as root:
        clock = Clock()
        runtime = make_runtime(root, enforce=True, clock=clock)
        global_req = request(scope="global", run_id="")
        runtime.postflight(global_req, "fail",
                          error=ConnectionRefusedError("connect refused"))
        clock.advance(901)
        session_req = request(scope="session", session_id="s2", run_id="")
        probe = runtime.preflight(session_req)
        runtime.postflight(session_req, "ok")
        issue = issue_of(runtime)
        observed = {"probe": probe.action, "issue_scope": issue["scope"],
                    "status_after_session_success": issue["status"]}
        global_result = (
            as_pass("scope.global_resolution", "scope",
                    "a session success can resolve or mitigate a global issue",
                    "the global issue is not left probing after a successful "
                    "session call", str(observed), observed)
            if issue["status"] == "resolved"
            else as_finding(
                "scope.global_resolution", "scope",
                "a successful session call cannot resolve a global issue",
                "design §7.3: another scope's success may mitigate; at minimum "
                "a genuine success must not leave the issue stuck in probing",
                str(observed), observed, severity="medium")
        )

    with tempfile.TemporaryDirectory(prefix="rtmem-deep-mixed-") as root:
        runtime = make_runtime(root)
        runtime.postflight(request(scope="global"), "fail",
                          error=ConnectionRefusedError("connect refused"))
        runtime.postflight(request(scope="session", session_id="s2"), "fail",
                          error=ConnectionRefusedError("connect refused"))
        issues = runtime.store.list_issues()
        observed = {"issue_count": len(issues),
                    "scopes": [item["scope"] for item in issues],
                    "counts": [item["count"] for item in issues]}
        mixed_result = (
            as_pass("scope.mixed", "scope",
                    "global and session failures with the same fingerprint stay "
                    "in separate issues",
                    "two issues (global, session)", str(observed), observed)
            if len(issues) == 2
            else as_finding(
                "scope.mixed", "scope",
                "a session failure updates the global issue record",
                "scope is part of issue ownership; the same operation failing "
                "in session s2 should not increment the global issue",
                str(observed), observed, severity="medium")
        )
    return global_result, mixed_result


def check_cross_environment_mitigation() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-crossenv-") as root:
        runtime = make_runtime(root)
        runtime.postflight(request(environment_id="lab-a"), "fail",
                          error=ConnectionRefusedError("connect refused"))
        runtime.postflight(request(environment_id="lab-b"), "ok")
        status = issue_of(runtime)["status"]
        observed = {"lab_a_issue_status": status}
        if status == "mitigated":
            return as_pass("scope.cross_env_mitigation", "scope",
                           "another environment's success mitigates the issue",
                           "mitigated", str(observed), observed)
        return as_gap(
            "scope.cross_env_mitigation", "scope",
            "another environment's success does not mitigate the issue",
            "design §7.2: 'open --other environment success--> mitigated'",
            str(observed), observed, severity="low")


# ---------------------------------------------------------------------------
# identity: fingerprints, key levels, malformed input
# ---------------------------------------------------------------------------

def check_fingerprints() -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-fp-") as root:
        observed = {
            "query_ignored": scope_fingerprint(request(target="http://h/a?x=1"))
            == scope_fingerprint(request(target="http://h/a?x=2")),
            "second_segment_ignored": scope_fingerprint(request(target="http://h/a/b"))
            == scope_fingerprint(request(target="http://h/a/c")),
            "secret_args_same": call_fingerprint(request(args={"token": "a"}))
            == call_fingerprint(request(args={"token": "b"})),
            "volatile_args_same": call_fingerprint(request(args={"q": "x", "ts": 1}))
            == call_fingerprint(request(args={"q": "x"})),
            "userinfo_stripped": normalize_target("https://user:pass@h/a/b")
            == "https://h/a",
        }
        ok = all(observed.values())
        if ok:
            return (as_pass("identity.normalise", "identity",
                            "target and argument normalisation is stable",
                            "volatile/query/secret/userinfo differences do not "
                            "change the key", str(observed), observed),
                    _check_key_levels())
        return (as_finding("identity.normalise", "identity",
                           "target and argument normalisation is stable",
                           "volatile/query/secret/userinfo differences do not "
                           "change the key", str(observed), observed),
                _check_key_levels())


def _check_key_levels() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-keylevel-") as root:
        runtime = make_runtime(root)
        runtime.postflight(request(args={"q": "bad"}), "fail",
                          error=TimeoutError("slow"))
        other = runtime.preflight(request(args={"q": "good"}))
        same = runtime.preflight(request(args={"q": "bad"}))
        observed = {"other_args": other.action, "same_args": same.action}
        if other.action == "allow" and same.action == "block":
            return as_pass("identity.key_level", "identity",
                           "call-level failures only block the same arguments",
                           "different args allow; same args block",
                           str(observed), observed)
        return as_finding("identity.key_level", "identity",
                          "call-level failures only block the same arguments",
                          "different args allow; same args block",
                          str(observed), observed)


def check_malformed_input() -> tuple[dict[str, Any], dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for check_id, title, bad_request, expected_exc in (
        ("identity.bad_port", "a malformed URL port does not crash preflight",
         request(target="http://host:99999/x"), ValueError),
        ("identity.non_json_args", "non-JSON argument values do not crash preflight",
         request(args={"blob": b"abc"}), TypeError),
    ):
        with tempfile.TemporaryDirectory(prefix="rtmem-deep-badinput-") as root:
            runtime = make_runtime(root)
            try:
                runtime.preflight(bad_request)
                observed = {"exception": None}
                results.append(as_finding(
                    check_id, "identity", title,
                    "preflight returns a decision (or a documented validation "
                    "error), never an uncaught exception",
                    "no exception raised; target/args were accepted",
                    observed, severity="low"))
            except expected_exc as exc:
                observed = {"exception": type(exc).__name__, "message": str(exc)}
                results.append(as_crash(
                    check_id, "identity", title,
                    "preflight returns a decision (or a documented validation "
                    "error), never an uncaught exception",
                    f"{type(exc).__name__}: {exc}",
                    observed, severity="medium"))
            except Exception as exc:  # noqa: BLE001
                observed = {"exception": type(exc).__name__, "message": str(exc)}
                results.append(as_crash(
                    check_id, "identity", title,
                    "preflight returns a decision (or a documented validation "
                    "error), never an uncaught exception",
                    f"{type(exc).__name__}: {exc}",
                    observed, severity="medium"))
    return results[0], results[1]


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------

def check_classification() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    class HttpError(Exception):
        def __init__(self, status: int):
            super().__init__(f"HTTP {status}")
            self.status = status

    known = {
        "ConnectionRefusedError": classify_exception(ConnectionRefusedError()),
        "TimeoutError": classify_exception(TimeoutError()),
        "PermissionError": classify_exception(PermissionError()),
        "json.JSONDecodeError": classify_exception(json.JSONDecodeError("x", "y", 0)),
        "HTTP 401": classify_exception(HttpError(401)),
        "HTTP 403": classify_exception(HttpError(403)),
        "HTTP 404": classify_exception(HttpError(404)),
        "HTTP 429": classify_exception(HttpError(429)),
    }
    expected_known = {
        "ConnectionRefusedError": "unreachable", "TimeoutError": "timeout",
        "PermissionError": "permission", "json.JSONDecodeError": "schema",
        "HTTP 401": "auth", "HTTP 403": "auth", "HTTP 404": "not_found",
        "HTTP 429": "rate_limit",
    }
    if known == expected_known:
        known_result = as_pass("classify.known", "classify",
                               "known exception types map to the documented class",
                               "see expected mapping", str(known), known)
    else:
        known_result = as_finding("classify.known", "classify",
                                  "known exception types map to the documented class",
                                  str(expected_known), str(known), known)

    observed = {"HTTP 500": classify_exception(HttpError(500)),
                "HTTP 503": classify_exception(HttpError(503)),
                "OSError(errno=101)": classify_exception(OSError(101, "Network is unreachable")),
                "OSError(errno=111)": classify_exception(OSError(111, "Connection refused"))}
    if observed["HTTP 500"] == "internal" and observed["HTTP 503"] == "internal" \
            and observed["OSError(errno=101)"] == "unreachable" \
            and observed["OSError(errno=111)"] == "unreachable":
        server_result = as_pass("classify.server_errors", "classify",
                                "5xx and errno-based network errors are classified",
                                "5xx -> internal; errno 101/111 -> unreachable",
                                str(observed), observed)
    else:
        server_result = as_finding(
            "classify.server_errors", "classify",
            "5xx and errno-based network errors fall back to unknown",
            "design §8.5: 5xx -> internal; OSError(errno=101/111) -> "
            "unreachable", str(observed), observed, severity="medium")

    signature = inspect.signature(RuntimeMemory.postflight)
    has_context = "context" in signature.parameters
    value_error = classify_exception(ValueError("bad arg"))
    observed = {"context_parameter": has_context,
                "ValueError_without_context": value_error,
                "ValueError_with_args_context": classify_exception(
                    ValueError("bad arg"), {"source": "args"})}
    if has_context:
        args_result = as_pass("classify.invalid_args", "classify",
                              "postflight can pass the argument context to the classifier",
                              "context parameter available", str(observed), observed)
    else:
        args_result = as_gap(
            "classify.invalid_args", "classify",
            "postflight cannot pass the argument context to the classifier",
            "the classifier supports context['source']='args' -> invalid_args, "
            "but postflight has no context parameter, so a plain ValueError "
            "becomes unknown", str(observed), observed, severity="medium")
    return known_result, server_result, args_result


# ---------------------------------------------------------------------------
# security / redaction
# ---------------------------------------------------------------------------

def check_redaction() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any],
                               dict[str, Any]]:
    samples = {
        "Authorization: Bearer abc123": "Authorization: Bearer [REDACTED]",
        "Cookie: session=abc123": "Cookie: [REDACTED]",
        "password=hunter2 token=tok-abc": "password=[REDACTED] token=[REDACTED]",
        "https://user:hunter2@10.0.0.1/x": "https://user:[REDACTED]@10.0.0.1/x",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----":
            "[REDACTED PRIVATE KEY]",
    }
    actual = {text: redact(text) for text in samples}
    if actual == samples:
        common_result = as_pass("security.redaction", "security",
                                "header, URL, password and private-key redaction works",
                                "all samples redacted", actual, actual)
    else:
        common_result = as_finding("security.redaction", "security",
                                   "header, URL, password and private-key redaction works",
                                   str(samples), str(actual), actual)

    json_samples = [
        '{"password": "hunter2", "token": "tok-abc", "api_key": "AK-123"}',
        '{"Authorization": "Bearer abc123"}',
    ]
    leaked = {text: redact(text) for text in json_samples}
    if all("hunter2" not in text and "tok-abc" not in text and "AK-123" not in text
           and "abc123" not in text for text in leaked.values()):
        json_result = as_pass("security.redaction_json", "security",
                              "JSON-formatted secrets are redacted",
                              "no secret remains in message_redacted",
                              leaked, leaked)
    else:
        json_result = as_finding(
            "security.redaction_json", "security",
            "JSON-formatted secrets are not redacted",
            "error messages often contain JSON; password/token/api_key and "
            "quoted Authorization values must be redacted before storage",
            str(leaked), leaked, severity="high")

    with tempfile.TemporaryDirectory(prefix="rtmem-deep-target-") as root:
        runtime = make_runtime(root)
        target = "https://user:hunter2@10.0.0.1/hunt"
        issue = runtime.postflight(request(target=target), "fail",
                                   error=ConnectionRefusedError("connect refused"))
        decision = runtime.preflight(request(target=target))
        report = build_report(runtime.store, now=runtime.clock())
        leaked_target = "hunter2" in json.dumps({
            "issue": issue["target"],
            "decision": decision.reason,
            "report": report["top_open_issues"][0]["target"],
        })
        observed = {"issue_target": issue["target"],
                    "decision_reason": decision.reason,
                    "report_target": report["top_open_issues"][0]["target"]}
        if leaked_target:
            target_result = as_finding(
                "security.target_credentials", "security",
                "URL userinfo credentials leak through the raw target field",
                "credentials must not appear in issue.target, decision.reason "
                "or report.top_open_issues",
                str(observed), observed, severity="high")
        else:
            target_result = as_pass("security.target_credentials", "security",
                                    "URL userinfo credentials do not leak",
                                    "no credentials in target/reason/report",
                                    str(observed), observed)

    long_text = "x" * 600
    shortened = redact(long_text)
    if len(shortened) <= 501 and shortened.endswith("…"):
        limit_result = as_pass("security.message_limit", "security",
                               "message_redacted is truncated",
                               "<= 500 chars plus an ellipsis",
                               {"length": len(shortened)})
    else:
        limit_result = as_finding("security.message_limit", "security",
                                  "message_redacted is truncated",
                                  "<= 500 chars plus an ellipsis",
                                  {"length": len(shortened)})
    return common_result, json_result, target_result, limit_result


# ---------------------------------------------------------------------------
# store: concurrency, corrupt journals, gc
# ---------------------------------------------------------------------------

def _mp_worker(root: str, policy_data: dict[str, Any], barrier: Any,
               start_iso: str) -> None:
    """Record one failure after all workers are ready (spawn-safe top-level)."""
    clock_now = dt.datetime.fromisoformat(start_iso)
    try:
        runtime = RuntimeMemory(root, policy=Policy(policy_data),
                                clock=lambda: clock_now)
        barrier.wait(timeout=30)
        runtime.postflight(request(run_id="concurrent"), "fail",
                          error=ConnectionRefusedError("connect refused"))
    except BaseException as exc:  # noqa: BLE001 - report to the parent process
        error_file = Path(root) / f"worker-error-{os.getpid()}.json"
        error_file.write_text(json.dumps({
            "type": type(exc).__name__,
            "message": str(exc),
        }, ensure_ascii=False), encoding="utf-8")


def check_multiprocess_consistency() -> dict[str, Any]:
    ctx = mp.get_context("spawn")
    rounds: list[dict[str, Any]] = []
    workers = 4
    policy_data = copy.deepcopy(default_policy())
    policy_data["enforce"] = False
    for round_no in range(3):
        with tempfile.TemporaryDirectory(prefix="rtmem-deep-mp-") as root:
            barrier = ctx.Barrier(workers)
            procs = [
                ctx.Process(target=_mp_worker,
                            args=(root, policy_data, barrier,
                                  "2026-11-02T06:00:00+00:00"))
                for _ in range(workers)
            ]
            for proc in procs:
                proc.start()
            for proc in procs:
                proc.join(timeout=30)
            for proc in procs:
                if proc.is_alive():
                    proc.terminate()
                    proc.join(timeout=5)
            errors: list[dict[str, Any]] = []
            for error_path in Path(root).glob("worker-error-*.json"):
                try:
                    errors.append(json.loads(error_path.read_text(encoding="utf-8")))
                except Exception as exc:  # noqa: BLE001
                    errors.append({"type": "read-error", "message": str(exc)})
            issues_path = Path(root) / "issues.json"
            try:
                issues = json.loads(issues_path.read_text(encoding="utf-8"))["issues"]
            except Exception as exc:  # noqa: BLE001
                rounds.append({"round": round_no, "errors": errors,
                               "issues_json_error": str(exc)})
                continue
            events = []
            for path in (Path(root) / "events").glob("*.jsonl"):
                events.extend(line for line in
                              path.read_text(encoding="utf-8").splitlines() if line)
            rounds.append({
                "round": round_no,
                "errors": errors,
                "events": len(events),
                "issue_records": len(issues),
                "issue_counts": [item.get("count") for item in issues],
                "issue_attempts": [item.get("attempts") for item in issues],
                "sum_counts": sum(int(item.get("count") or 0) for item in issues),
            })
    bad = [item for item in rounds
           if item.get("errors") or item.get("events") != workers
           or item.get("issue_records") != 1
           or item.get("sum_counts") != workers]
    if not bad:
        return as_pass("store.multiprocess", "store",
                       "concurrent record() calls aggregate into one issue",
                       "4 events -> 1 issue, count=4", str(rounds), rounds)
    has_lock_error = any(
        error.get("type") in ("PermissionError", "FileExistsError", "TimeoutError")
        for item in rounds for error in item.get("errors", []))
    if has_lock_error:
        return as_finding(
            "store.multiprocess", "store",
            "concurrent record() calls crash on the file lock and/or lose counts",
            "4 events -> 1 issue, count=4; the README calls the JSONL lock "
            "cross-platform and the lock should wait, not raise an uncaught "
            "OSError",
            str(rounds), rounds, severity="high")
    return as_finding(
        "store.multiprocess", "store",
        "concurrent record() calls create duplicate live issues",
        "4 events -> exactly one issue record with count=4; duplicate live "
        "records split the evidence and make find_issue ambiguous. The store "
        "is documented as single-writer, but the README claims the JSONL lock "
        "prevents interleaved lines and issues.json is atomic, so readers "
        "should not observe duplicate live issues",
        str(rounds), rounds, severity="medium")


def check_lock_contention() -> dict[str, Any]:
    """Stress the JSONL lock with threads (same-process, low concurrency).

    The README calls the lock "cross-platform"; on Windows ``os.open`` with
    ``O_CREAT|O_EXCL`` can raise ``PermissionError`` (Access Denied) instead of
    ``FileExistsError`` when two threads create/unlink the same lock file at
    the same time.  ``file_lock`` only catches ``FileExistsError``, so one
    thread crashes and its JSONL line is lost.
    """
    workers = 8
    per_worker = 10
    rounds = 10
    errors: list[dict[str, Any]] = []
    observed_rounds: list[dict[str, Any]] = []
    for round_no in range(rounds):
        with tempfile.TemporaryDirectory(prefix="rtmem-deep-lock-") as root:
            path = Path(root) / "events.jsonl"
            barrier = threading.Barrier(workers)

            def append_many(index: int) -> None:
                try:
                    barrier.wait(timeout=10)
                    for item in range(per_worker):
                        append_jsonl(path, {"thread": index, "item": item})
                except BaseException as exc:  # noqa: BLE001
                    errors.append({"round": round_no,
                                   "type": type(exc).__name__,
                                   "message": str(exc)})

            threads = [threading.Thread(target=append_many, args=(index,))
                       for index in range(workers)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=30)
            lines = (path.read_text(encoding="utf-8").splitlines()
                     if path.exists() else [])
            observed_rounds.append({"round": round_no, "lines": len(lines),
                                    "expected": workers * per_worker})
            if errors:
                break
    if errors:
        return as_finding(
            "store.lock_contention", "store",
            "the JSONL file lock can raise an uncaught PermissionError on "
            "Windows",
            "file_lock should treat Access Denied / FileExists as contention "
            "and retry until its timeout; a thread must not crash",
            f"errors={errors}; rounds={observed_rounds}",
            {"errors": errors, "rounds": observed_rounds}, severity="high")
    return as_pass("store.lock_contention", "store",
                   "the JSONL file lock handles Windows contention",
                   "no thread crashes and every line is appended",
                   f"not reproduced in {rounds} burst rounds",
                   {"rounds": observed_rounds})


def check_non_retryable_classes() -> tuple[dict[str, Any], dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for error_class, check_id, label in (
        ("schema", "state.schema", "schema"),
        ("invalid_args", "state.invalid_args", "invalid_args"),
    ):
        with tempfile.TemporaryDirectory(prefix=f"rtmem-deep-{error_class}-") as root:
            runtime = make_runtime(root)
            bad_request = request(args={"q": "bad"})
            runtime.postflight(bad_request, "fail", error_class=error_class)
            bad = runtime.preflight(bad_request)
            good = runtime.preflight(request(args={"q": "good"}))
            issue = issue_of(runtime)
            observed = {"status": issue["status"],
                        "bad_args": bad.action, "good_args": good.action,
                        "retryable": issue["retry_policy"].get("retryable")}
            if bad.action == "block" and good.action == "allow" \
                    and issue["status"] == "open" \
                    and issue["retry_policy"].get("retryable") is False:
                results.append(as_pass(
                    check_id, "state",
                    f"{label} failures block only the bad call and are not retried",
                    "bad args block; good args allow; status open; retryable=false",
                    str(observed), observed))
            else:
                results.append(as_finding(
                    check_id, "state",
                    f"{label} failures block only the bad call and are not retried",
                    "bad args block; good args allow; status open; retryable=false",
                    str(observed), observed))
    return results[0], results[1]


def check_note() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-note-") as root:
        runtime = make_runtime(root)
        issue = runtime.postflight(request(), "fail",
                                   error=ConnectionRefusedError("connect refused"))
        before = runtime.store.get_issue(issue["issue_id"])
        updated = runtime.add_note(issue["issue_id"], "looks like a DNS issue",
                                   author="model")
        observed = {"status_same": updated["status"] == before["status"],
                    "next_retry_same": updated["next_retry_at"] == before["next_retry_at"],
                    "author": updated["notes"][0]["author"]}
        if observed["status_same"] and observed["next_retry_same"] \
                and observed["author"] == "model":
            return as_pass("mode.note", "mode",
                           "a model note never changes status or next_retry_at",
                           "note stored; status/next_retry unchanged",
                           str(observed), observed)
        return as_finding("mode.note", "mode",
                          "a model note never changes status or next_retry_at",
                          "note stored; status/next_retry unchanged",
                          str(observed), observed)


def check_policy_load() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-policy-") as root:
        data = copy.deepcopy(default_policy())
        data["enforce"] = True
        data["classes"]["unreachable"]["base_s"] = 1
        data["classes"]["unreachable"]["max_s"] = 1
        (Path(root) / "policy.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        runtime = RuntimeMemory(root)  # no policy argument: load policy.json
        req = request()
        runtime.postflight(req, "fail",
                          error=ConnectionRefusedError("connect refused"))
        decision = runtime.preflight(req)
        observed = {"action": decision.action, "shadow": decision.shadow,
                    "enforce": runtime.policy.enforce,
                    "base_s": runtime.policy.class_rule("unreachable")["base_s"]}
        if decision.action == "block" and decision.shadow is False \
                and runtime.policy.enforce is True:
            return as_pass("mode.policy_load", "mode",
                           "enforce mode is loaded from data/policy.json",
                           "block is authoritative; shadow=false",
                           str(observed), observed)
        return as_finding("mode.policy_load", "mode",
                          "enforce mode is loaded from data/policy.json",
                          "block is authoritative; shadow=false",
                          str(observed), observed)


def check_default_profile_ignored() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-defaults-") as root:
        clock = Clock()
        runtime = make_runtime(
            root, clock=clock,
            mutate=lambda data: data["defaults"].update(
                cooldown_s=1, issue_ttl_s=1))
        req = request()
        issue = runtime.postflight(req, "fail",
                                   error=ConnectionRefusedError("connect refused"))
        retry = parse_iso(issue["next_retry_at"])
        expiry = parse_iso(issue["expires_at"])
        retry_delta = int((retry - clock.now).total_seconds()) if retry else None
        expiry_delta = int((expiry - clock.now).total_seconds()) if expiry else None
        observed = {"defaults": {"cooldown_s": 1, "issue_ttl_s": 1},
                    "next_retry_delta_s": retry_delta,
                    "expires_delta_s": expiry_delta}
        if retry_delta == 1 and expiry_delta == 1:
            return as_pass("state.defaults", "state",
                           "policy.defaults overrides the class values",
                           "cooldown/TTL from defaults", str(observed), observed)
        return as_gap(
            "state.defaults", "state",
            "policy.defaults is not used for cooldown/TTL",
            "policy.defaults.cooldown_s and issue_ttl_s should affect the "
            "default backoff/TTL; the class values win and the defaults keys "
            "are dead configuration",
            str(observed), observed, severity="low")


def check_atomic_issues_json() -> dict[str, Any]:
    # The multi-process check's temp roots are gone; do a direct sanity check
    # that a concurrent-style write leaves a parseable JSON document.
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-atomic-") as root:
        clock = Clock()
        runtime = make_runtime(root, clock=clock)
        for _ in range(20):
            runtime.postflight(request(), "fail",
                              error=ConnectionRefusedError("connect refused"))
        try:
            data = json.loads((Path(root) / "issues.json").read_text(encoding="utf-8"))
            observed = {"issues": len(data.get("issues", [])),
                        "schema_version": data.get("schema_version")}
            return as_pass("store.atomic_json", "store",
                           "issues.json remains a complete JSON document",
                           "parseable snapshot after repeated writes",
                           str(observed), observed)
        except Exception as exc:  # noqa: BLE001
            return as_crash("store.atomic_json", "store",
                            "issues.json remains a complete JSON document",
                            "parseable snapshot after repeated writes",
                            f"{type(exc).__name__}: {exc}")


def check_corrupt_event_journal() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-corrupt-") as root:
        store = Store(root)
        store.ensure()
        (store.events_dir / "2026-11.jsonl").write_text(
            "not json\n", encoding="utf-8")
        runtime = RuntimeMemory(root, policy=Policy(default_policy()),
                                clock=Clock())
        observed: dict[str, str] = {}
        try:
            runtime.report()
            observed["report"] = "ok"
        except Exception as exc:  # noqa: BLE001
            observed["report"] = f"{type(exc).__name__}: {exc}"
        try:
            runtime.preflight(request(run_id="x"))
            observed["preflight_with_run"] = "ok"
        except Exception as exc:  # noqa: BLE001
            observed["preflight_with_run"] = f"{type(exc).__name__}: {exc}"
        try:
            observed["preflight_without_run"] = runtime.preflight(
                request(run_id="")).action
        except Exception as exc:  # noqa: BLE001
            observed["preflight_without_run"] = f"{type(exc).__name__}: {exc}"
        observed["check"] = store.check()
        if observed["report"] == "ok" and observed["preflight_with_run"] == "ok":
            return as_pass("store.corrupt_events", "store",
                           "a corrupt event journal does not break preflight/report",
                           "graceful handling or a documented check error",
                           str(observed), observed)
        return as_finding(
            "store.corrupt_events", "store",
            "a corrupt event journal raises from report and budgeted preflight",
            "check() reports the journal problem; report/preflight should "
            "return a controlled error instead of an uncaught ValueError",
            str(observed), observed, severity="medium")


def check_check_invariants() -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-check-") as root:
        store = Store(root)
        store.ensure()
        bad = Issue(
            issue_id="ISS-no-expiry", fingerprint="fp", key_level="scope",
            scope="global", environment_id="lab-a", component="mcp",
            tool="hunt.query", action="search", target="http://x/hunt",
            error_class="unreachable", status="open", first_seen=iso(START),
            last_seen=iso(START), count=1, attempts=1, retry_policy={},
            next_retry_at=None, expires_at=None,
        )
        store.upsert_issue(bad)
        problems = store.check()
        if any("expires_at" in problem for problem in problems):
            invariants_result = as_pass("audit.expires_at", "audit",
                                        "check() enforces the expires_at invariant",
                                        "a missing expires_at is reported",
                                        str(problems), problems)
        else:
            invariants_result = as_finding(
                "audit.expires_at", "audit",
                "check() does not enforce the expires_at invariant",
                "design §16.3 invariant 4: expires_at always exists; check() "
                "should report an issue without it",
                str(problems), problems, severity="low")

    with tempfile.TemporaryDirectory(prefix="rtmem-deep-dupe-") as root:
        store = Store(root)
        store.ensure()
        live = bad
        resolved = Issue(**{**bad.to_dict(), "issue_id": "ISS-resolved",
                            "status": "resolved", "resolved_at": iso(START),
                            "expires_at": "2026-11-03T06:00:00Z"})
        store.upsert_issue(resolved)
        store.upsert_issue(live)
        found = store.find_issue("fp", "unreachable")
        if found and found["issue_id"] == "ISS-no-expiry":
            dupe_result = as_pass("store.find_live", "store",
                                  "find_issue prefers the live duplicate",
                                  "ISS-no-expiry", str(found["issue_id"]))
        else:
            dupe_result = as_finding("store.find_live", "store",
                                     "find_issue prefers the live duplicate",
                                     "ISS-no-expiry", str(found))
    return invariants_result, dupe_result


def check_gc() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-gc-") as root:
        store = Store(root)
        store.ensure()
        old_event = {
            "event_id": "OP-old", "ts": "2020-01-01T00:00:00Z",
            "component": "mcp", "tool": "hunt.query", "action": "search",
            "target": "http://x/hunt", "outcome": "fail", "fingerprint": "fp",
        }
        append_jsonl(store.events_dir / "2020-01.jsonl", old_event)
        old_issue = Issue(
            issue_id="ISS-old", fingerprint="fp", key_level="scope",
            scope="global", environment_id="lab-a", component="mcp",
            tool="hunt.query", action="search", target="http://x/hunt",
            error_class="unreachable", status="resolved",
            first_seen="2020-01-01T00:00:00Z", last_seen="2020-01-01T00:00:00Z",
            count=1, attempts=1, retry_policy={}, next_retry_at=None,
            expires_at="2020-01-02T00:00:00Z",
            resolved_at="2020-01-01T00:00:00Z",
        )
        store.upsert_issue(old_issue)
        append_jsonl(store.decisions_path, {"action": "block"})
        append_jsonl(store.overrides_path, {"basis": "old"})
        result = store.gc(events_days=1, issues_days=1, dry_run=False)
        observed = {
            "gc": result,
            "old_event_file_exists": (store.events_dir / "2020-01.jsonl").exists(),
            "old_issue_exists": store.get_issue("ISS-old") is not None,
            "decisions": len(store.read_decisions()),
            "overrides": len(store.read_overrides()),
        }
        if (not observed["old_event_file_exists"]
                and not observed["old_issue_exists"]
                and observed["decisions"] == 1 and observed["overrides"] == 1):
            return as_pass("store.gc", "store",
                           "gc deletes old events/resolved issues and keeps audit logs",
                           "old data gone; audit logs retained", str(observed), observed)
        return as_finding("store.gc", "store",
                          "gc deletes old events/resolved issues and keeps audit logs",
                          "old data gone; audit logs retained", str(observed), observed)


# ---------------------------------------------------------------------------
# report metrics
# ---------------------------------------------------------------------------

def check_report_linking() -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-report-") as root:
        clock = Clock()
        runtime = make_runtime(root, clock=clock)
        req = request()
        runtime.postflight(req, "fail",
                          error=ConnectionRefusedError("connect refused"))
        decision = runtime.preflight(req)
        runtime.postflight(req, "ok")  # CLI-style: no decision passed
        report = build_report(runtime.store, now=clock.now)
        observed = {"decision": decision.action,
                    "would_block": report["shadow"]["would_block"],
                    "false_blocks": report["shadow"]["false_blocks"],
                    "false_block_rate_present": "false_block_rate" in report["shadow"]}
        if report["shadow"]["false_blocks"] == 1:
            link_result = as_pass("report.link", "report",
                                  "shadow false blocks are measured without an "
                                  "explicit decision argument",
                                  "false_blocks=1", str(observed), observed)
        else:
            link_result = as_finding(
                "report.link", "report",
                "shadow false blocks require the caller to pass the decision",
                "a shadow block followed by a successful call should count as "
                "a false block even when the caller only records the outcome",
                str(observed), observed, severity="medium")
        if observed["false_block_rate_present"]:
            rate_result = as_pass("report.rate", "report",
                                  "report exposes false_block_rate",
                                  "rate present", str(observed), observed)
        else:
            rate_result = as_gap("report.rate", "report",
                                 "report exposes counts but not false_block_rate",
                                 "design §15.1 defines false_block_rate; the "
                                 "report has would_block/false_blocks but no rate",
                                 str(observed), observed, severity="low")
    return link_result, rate_result


def check_report_metrics() -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-probe-rate-") as root:
        clock = Clock()
        runtime = make_runtime(root, enforce=True, clock=clock)
        req = request()
        runtime.postflight(req, "fail",
                          error=ConnectionRefusedError("connect refused"))
        clock.advance(901)
        decision = runtime.preflight(req)
        runtime.postflight(req, "ok", decision=decision)
        report = build_report(runtime.store, now=clock.now)
        observed = {"probes": report["probes"],
                    "enforce_blocked": report["enforce"]["blocked_calls"]}
        if report["probes"]["attempts"] == 1 and report["probes"]["success"] == 1 \
                and report["probes"]["success_rate"] == 1.0:
            rate_result = as_pass("report.probe_rate", "report",
                                  "probe success rate is reported",
                                  "1/1 -> rate 1.0", str(observed), observed)
        else:
            rate_result = as_finding("report.probe_rate", "report",
                                     "probe success rate is reported",
                                     "1/1 -> rate 1.0", str(observed), observed)

    with tempfile.TemporaryDirectory(prefix="rtmem-deep-dup-run-") as root:
        clock = Clock()
        runtime = make_runtime(root, clock=clock)
        runtime.postflight(request(run_id="run-1"), "fail",
                          error=ConnectionRefusedError("connect refused"))
        runtime.postflight(request(run_id="run-2"), "fail",
                          error=ConnectionRefusedError("connect refused"))
        report = build_report(runtime.store, now=clock.now)
        observed = {"duplicate_attempts": report["duplicate_attempts"],
                    "note": "two failures in distinct runs"}
        if report["duplicate_attempts"] == 0:
            dup_result = as_pass("report.duplicate_scope", "report",
                                 "duplicate_attempts is scoped to a run",
                                 "distinct runs do not count as duplicates",
                                 str(observed), observed)
        else:
            dup_result = as_gap(
                "report.duplicate_scope", "report",
                "duplicate_attempts is not scoped to a run",
                "design §15.1 defines duplicate_attempts 'in run'; the report "
                "counts repeats across all runs",
                str(observed), observed, severity="low")
    return rate_result, dup_result


def check_audit_traceability() -> tuple[dict[str, Any], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-audit-") as root:
        runtime = make_runtime(
            root, mutate=lambda data: data["budgets"].update(
                max_attempts_per_call_key_per_run=1))
        req = request(run_id="budget-audit")
        runtime.postflight(req, "fail",
                          error=ConnectionRefusedError("connect refused"))
        decision = runtime.preflight(req)
        overrides = len(runtime.store.read_overrides())
        observed = {"decision": decision.action, "issue_id": decision.issue_id,
                    "reason": decision.reason}
        if decision.action == "block" and decision.issue_id:
            trace_result = as_pass("audit.block_issue", "audit",
                                   "every block can be traced to an issue",
                                   "block carries an issue_id",
                                   str(observed), observed)
        else:
            trace_result = as_finding(
                "audit.block_issue", "audit",
                "a run-budget block has no issue_id",
                "design §16.3 invariant 3: every block is traceable to "
                "issue_id + policy_version + source events; a budget block is "
                "a hard block but carries no issue id",
                str(observed), observed, severity="medium")

        runtime.postflight(req, "fail", error=ConnectionRefusedError("x"))
        runtime.preflight(req, allow_probe=True, override_basis="operator")
        override_count = len(runtime.store.read_overrides())
        if override_count == 1:
            override_result = as_pass("audit.override", "audit",
                                      "overrides are audited",
                                      "one override record", str(override_count))
        else:
            override_result = as_finding("audit.override", "audit",
                                         "overrides are audited",
                                         "one override record", str(override_count))
    return trace_result, override_result


def check_reopen_after_resolve() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-deep-reopen-") as root:
        runtime = make_runtime(root)
        req = request()
        issue = runtime.postflight(req, "fail",
                                   error=ConnectionRefusedError("connect refused"))
        runtime.resolve(issue["issue_id"], "fixed", resolution="fixed")
        again = runtime.postflight(req, "fail",
                                   error=ConnectionRefusedError("connect refused"))
        observed = {"issue_id_reused": again["issue_id"] == issue["issue_id"],
                    "status": again["status"], "count": again["count"]}
        if again["status"] in ("cooldown", "open") and again["count"] == 1:
            return as_pass("audit.reopen", "audit",
                           "a resolved issue can be reopened by a new failure",
                           "new live issue (same id) with count=1",
                           str(observed), observed)
        return as_finding("audit.reopen", "audit",
                          "a resolved issue can be reopened by a new failure",
                          "new live issue (same id) with count=1",
                          str(observed), observed)


def check_rebuild_api() -> dict[str, Any]:
    if hasattr(RuntimeMemory, "rebuild_issues"):
        return as_pass("audit.rebuild", "audit",
                       "rebuild_issues is available",
                       "method exists", "present")
    return as_gap("audit.rebuild", "audit",
                  "rebuild_issues is not implemented",
                  "design §11.6 proposes rebuilding issues from events; the "
                  "prototype has no rebuild method",
                  "method absent", "absent", severity="info")


# ---------------------------------------------------------------------------
# registry / reporting
# ---------------------------------------------------------------------------

def run_all_checks() -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []

    def add(*items: dict[str, Any] | tuple[dict[str, Any], ...]) -> None:
        for item in items:
            if isinstance(item, tuple):
                checks.extend(item)
            else:
                checks.append(item)

    add(check_shadow_mode(), check_enforce_mode(),
        check_enforce_probe_in_flight())
    add(check_policy_load())
    add(check_note())
    add(check_probe_success_and_failure())
    add(check_manual_operations())
    add(check_workaround_only())
    add(check_override())
    add(check_state_machine())
    add(check_non_retryable_classes())
    add(check_retry_after_and_auth())
    add(check_probe_recovery())
    add(check_attempt_budget())
    add(check_per_class_run_budget())
    add(check_probe_after_expiry_config())
    add(check_default_profile_ignored())
    add(check_read_only_preflight())
    add(check_mitigated_after_expiry())
    add(check_jitter())
    add(check_scope_isolation())
    add(check_global_resolution())
    add(check_cross_environment_mitigation())
    add(check_fingerprints())
    add(check_malformed_input())
    add(check_classification())
    add(check_redaction())
    add(check_multiprocess_consistency())
    add(check_lock_contention())
    add(check_atomic_issues_json())
    add(check_corrupt_event_journal())
    add(check_check_invariants())
    add(check_gc())
    add(check_report_linking())
    add(check_report_metrics())
    add(check_audit_traceability())
    add(check_reopen_after_resolve())
    add(check_rebuild_api())
    return checks


def build_summary(checks: list[dict[str, Any]], *, out: Path,
                  plan_found: bool = False) -> str:
    try:
        out_label = out.relative_to(ROOT.parent).as_posix()
    except ValueError:
        out_label = str(out)
    plan_path = ROOT.parent / "docs" / "RUNTIME_MEMORY_TEST_PLAN.md"
    by_status: dict[str, int] = {}
    by_category: dict[str, dict[str, int]] = {}
    for item in checks:
        by_status[item["status"]] = by_status.get(item["status"], 0) + 1
        category = by_category.setdefault(item["category"], {})
        category[item["status"]] = category.get(item["status"], 0) + 1
    lines = [
        "# Runtime memory deep test matrix",
        "",
        f"- generated: {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')}",
        f"- harness: `sim/deep_test.py`",
        f"- out: `{out_label}`",
        f"- checks: {len(checks)}",
        f"- status: " + ", ".join(f"{key}={value}" for key, value in sorted(by_status.items())),
        "",
    ]
    if plan_found:
        lines += [
            f"> The requested plan `{plan_path.name}` exists; this matrix is",
            "> derived from `docs/RUNTIME_MEMORY_DESIGN.md` §16 (test plan),",
            "> §9.5 (interception matrix) and §15 (metrics), plus additional",
            "> robustness checks. Cross-check the two if their scopes differ.",
        ]
    else:
        lines += [
            "> Note: the requested `docs/RUNTIME_MEMORY_TEST_PLAN.md` does not exist",
            "> in this repository (not in the working tree, any remote branch or git",
            "> history). This matrix is derived from `docs/RUNTIME_MEMORY_DESIGN.md`",
            "> §16 (test plan), §9.5 (interception matrix), §15 (metrics) and the",
            "> runtime-memory READMEs, plus additional robustness checks.",
        ]
    lines += [
        "",
        "## Checks",
        "",
        "| # | id | category | status | severity | title |",
        "|---|---|---|---|---|---|",
    ]
    for index, item in enumerate(checks, start=1):
        lines.append(
            f"| {index} | `{item['id']}` | {item['category']} | "
            f"**{item['status']}** | {item['severity']} | {item['title']} |")
    lines += ["", "## Categories", "",
              "| category | pass | finding | gap | crash |", "|---|---|---|---|---|"]
    for category in sorted(by_category):
        row = by_category[category]
        lines.append(f"| {category} | {row.get('PASS', 0)} | {row.get('FINDING', 0)} | "
                     f"{row.get('GAP', 0)} | {row.get('CRASH', 0)} |")
    lines += ["", "## Non-pass detail", ""]
    for item in checks:
        if item["status"] == "PASS":
            continue
        lines += [
            f"### {item['id']} ({item['status']}, {item['severity']})",
            "",
            f"**{item['title']}**",
            "",
            f"- expected: {item['expected']}",
            f"- observed: {item['observed']}",
        ]
        if item.get("evidence") is not None:
            evidence = json.dumps(item["evidence"], ensure_ascii=False,
                                  indent=2, default=str)
            lines += ["", "```json", evidence, "```"]
        lines.append("")
    lines += [
        "## Reproduce",
        "",
        "```powershell",
        "cd runtime_memory",
        "python sim/deep_test.py --force",
        "```",
        "",
        "The harness uses fake clocks and temporary data directories; it does",
        "not write to `runtime_memory/data` and does not modify the algorithm.",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help="output directory (default: sim/runs/deep-2026-11-03)")
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing output directory")
    args = parser.parse_args(argv)
    out = Path(args.out)
    if out.exists():
        if not args.force:
            parser.error(f"{out} already exists; pass --force")
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    checks = run_all_checks()
    totals: dict[str, int] = {}
    for item in checks:
        totals[item["status"]] = totals.get(item["status"], 0) + 1
    plan_path = ROOT.parent / "docs" / "RUNTIME_MEMORY_TEST_PLAN.md"
    plan_found = plan_path.exists()
    report = {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "harness": "sim/deep_test.py",
        "python": sys.version,
        "platform": platform.platform(),
        "requested_test_plan": {
            "path": "docs/RUNTIME_MEMORY_TEST_PLAN.md",
            "found": plan_found,
            "fallback": [] if plan_found else [
                "docs/RUNTIME_MEMORY_DESIGN.md §16",
                "docs/RUNTIME_MEMORY_DESIGN.md §9.5",
                "docs/RUNTIME_MEMORY_DESIGN.md §15",
                "runtime_memory/README.md and README_CN.md",
            ],
        },
        "totals": totals,
        "checks": checks,
    }
    (out / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "summary.md").write_text(
        build_summary(checks, out=out, plan_found=plan_found), encoding="utf-8")
    print(f"checks={len(checks)} " +
          " ".join(f"{key}={value}" for key, value in sorted(totals.items())))
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

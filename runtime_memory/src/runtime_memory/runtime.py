"""Runtime-memory core: preflight, postflight, issue aggregation.

The prototype is deliberately small and file-based.  It is *not* wired into
demo/ or the attack-detection harness; a caller can use it as a library or via
``src/manage_runtime_memory.py``.
"""
from __future__ import annotations

import datetime as dt
from typing import Any, Callable

from .classify import classify_exception, diagnosis_for
from .fingerprint import (call_fingerprint, fingerprint_for, scope_fingerprint)
from .models import (ACTIVE_STATUSES, FAILURE_OUTCOMES, OUTCOMES, Decision,
                     Issue, OperationEvent, OperationRequest)
from .policy import Policy
from .redact import redact
from .store import DEFAULT_DATA_DIR, Store
from .timeutil import iso, new_id, parse_iso, utcnow


class RuntimeMemory:
    def __init__(self, root: Any = None, policy: Policy | dict | None = None,
                 clock: Callable[[], dt.datetime] | None = None):
        self.store = Store(root or DEFAULT_DATA_DIR)
        self.store.ensure()
        if isinstance(policy, Policy):
            self.policy = policy
        elif isinstance(policy, dict):
            self.policy = Policy(policy)
        else:
            self.policy = Policy.load(self.store.policy_path)
        self.clock = clock or utcnow
        self._refresh_issues(self.clock())

    # -- issue maintenance ------------------------------------------------
    def _expired(self, issue: dict[str, Any], now: dt.datetime) -> bool:
        expires_at = parse_iso(issue.get("expires_at"))
        return expires_at is not None and now >= expires_at

    def _refresh_issues(self, now: dt.datetime) -> list[dict[str, Any]]:
        data = self.store.load_issues()
        changed = False
        for issue in data["issues"]:
            status = issue.get("status")
            if status == "probing":
                started = parse_iso(issue.get("probe_started_at"))
                if started is None or \
                        (now - started).total_seconds() > self.policy.probe_timeout_s:
                    issue["status"] = "stale" if self._expired(issue, now) else "open"
                    issue["probe_started_at"] = None
                    changed = True
            if issue.get("status") in ("cooldown", "open", "mitigated") \
                    and self._expired(issue, now):
                issue["status"] = "stale"
                changed = True
        if changed:
            self.store.save_issues(data)
        return data["issues"]

    def _decide(self, issues: list[dict[str, Any]], now: dt.datetime,
                request: OperationRequest) -> Decision:
        if not issues:
            return Decision.allow(scope_fingerprint(request),
                                  shadow=not self.policy.enforce,
                                  policy_version=self.policy.version)
        ranked: list[tuple[int, float, dict[str, Any], str]] = []
        for issue in issues:
            status = issue.get("status")
            retry_policy = issue.get("retry_policy") or {}
            attempts = int(issue.get("attempts", 0) or 0)
            max_attempts = int(retry_policy.get("max_attempts", 3) or 0)
            retryable = bool(retry_policy.get("retryable", True))
            next_at = parse_iso(issue.get("next_retry_at"))
            if status == "mitigated":
                ranked.append((1, float(issue.get("confidence", 0) or 0), issue,
                               "workaround available"))
            elif status == "probing":
                ranked.append((3, float(issue.get("confidence", 0) or 0), issue,
                               "probe already in flight"))
            elif status == "stale":
                ranked.append((2, float(issue.get("confidence", 0) or 0), issue,
                               "stale issue; one probe allowed"))
            elif not retryable:
                ranked.append((3, float(issue.get("confidence", 0) or 0), issue,
                               "non-retryable error class"))
            elif attempts > max_attempts:
                ranked.append((3, float(issue.get("confidence", 0) or 0), issue,
                               "attempt budget exhausted"))
            elif next_at is None:
                ranked.append((3, float(issue.get("confidence", 0) or 0), issue,
                               "no retry window recorded"))
            elif now >= next_at:
                ranked.append((2, float(issue.get("confidence", 0) or 0), issue,
                               "retry window open"))
            else:
                ranked.append((3, float(issue.get("confidence", 0) or 0), issue,
                               "blocked until retry window"))
        ranked.sort(key=lambda item: (item[0], item[1], item[2].get("count", 0)),
                    reverse=True)
        rank, _, issue, reason = ranked[0]
        action = {1: "allow_with_hint", 2: "probe", 3: "block"}[rank]
        retry_policy = issue.get("retry_policy") or {}
        max_attempts = int(retry_policy.get("max_attempts", 0) or 0)
        attempts = int(issue.get("attempts", 0) or 0)
        workaround = str(issue.get("workaround") or "").strip()
        return Decision(
            action=action,
            fingerprint=str(issue.get("fingerprint") or ""),
            issue_id=str(issue.get("issue_id") or ""),
            reason=f"{reason}: {issue.get('error_class')} @ {issue.get('target')} "
                   f"({issue.get('count')} failure(s))",
            blocked_until=issue.get("next_retry_at") if action == "block" else None,
            # max_attempts counts retries after the initial failure, so the
            # first attempt after a retry window is still allowed.
            attempts_left=max(0, max_attempts + 1 - attempts),
            alternatives=[workaround] if workaround else [],
            confidence=float(issue.get("confidence", 0) or 0),
            expires_at=issue.get("expires_at"),
            policy_version=self.policy.version,
            shadow=not self.policy.enforce,
        )

    # -- preflight --------------------------------------------------------
    def _run_budget_decision(self, request: OperationRequest) -> Decision | None:
        """Per-run hard budget, independent of issue state.

        A single run can burn attempts even when the issue-level budget is not
        exhausted; this cap is the in-session guard.
        """
        if not request.run_id:
            return None
        budgets = self.policy.budgets
        failures = [event for event in self.store.read_events()
                    if event.get("run_id") == request.run_id
                    and event.get("outcome") in FAILURE_OUTCOMES
                    and event.get("scope") in ("global", request.scope)]
        call_key = call_fingerprint(request)
        operation_keys = {scope_fingerprint(request), call_key}
        call_failures = [event for event in failures
                         if event.get("fingerprint") in operation_keys]
        if len(call_failures) >= budgets["max_attempts_per_call_key_per_run"]:
            return Decision(
                action="block",
                fingerprint=call_key,
                reason=f"run budget exhausted: {len(call_failures)} failure(s) "
                       f"for this operation in {request.run_id}",
                attempts_left=0,
                policy_version=self.policy.version,
                shadow=not self.policy.enforce,
            )
        component_failures = [event for event in failures
                              if event.get("component") == request.component]
        if len(component_failures) >= budgets["max_failures_per_component_per_run"]:
            return Decision(
                action="block",
                fingerprint=scope_fingerprint(request),
                reason=f"run budget exhausted: {len(component_failures)} failure(s) "
                       f"for component {request.component} in {request.run_id}",
                attempts_left=0,
                policy_version=self.policy.version,
                shadow=not self.policy.enforce,
            )
        return None

    def preflight(self, request: OperationRequest, *, allow_probe: bool = False,
                  override_basis: str = "", record: bool = True) -> Decision:
        """Return a decision.

        ``record=False`` is a read-only inspection: it does not append a
        decision, does not log an override, and does not move an issue into
        ``probing``.  Use it for dashboards/"what would happen" without
        polluting the trace.
        """
        request.args = request.args or {}
        now = self.clock()
        self._refresh_issues(now)
        keys = [scope_fingerprint(request), call_fingerprint(request)]
        issues = [
            issue for issue in self.store.find_issues(keys, statuses=ACTIVE_STATUSES)
            if issue.get("scope") in ("global", request.scope)
        ]
        decision = self._run_budget_decision(request) or self._decide(issues, now, request)
        if decision.action == "block" and allow_probe:
            if not override_basis.strip():
                raise ValueError("allow_probe requires a non-empty override_basis")
            if record:
                self.store.append_override({
                    "ts": iso(now),
                    "component": request.component,
                    "tool": request.tool,
                    "action": request.action,
                    "target": request.target,
                    "scope": request.scope,
                    "environment_id": request.environment_id,
                    "session_id": request.session_id,
                    "run_id": request.run_id,
                    "issue_id": decision.issue_id,
                    "fingerprint": decision.fingerprint,
                    "basis": override_basis.strip(),
                    "shadow": not self.policy.enforce,
                })
            decision = Decision(
                action="probe",
                fingerprint=decision.fingerprint,
                issue_id=decision.issue_id,
                reason=f"override: {override_basis.strip()}",
                attempts_left=decision.attempts_left,
                alternatives=decision.alternatives,
                confidence=decision.confidence,
                expires_at=decision.expires_at,
                policy_version=self.policy.version,
                shadow=not self.policy.enforce,
                override=True,
                override_basis=override_basis.strip(),
            )
        if decision.action != "allow" and record:
            decision.decision_id = new_id("DEC", now)
            self.store.append_decision(self._decision_record(request, decision, now))
        if decision.action == "probe" and self.policy.enforce and record:
            issue = self.store.get_issue(decision.issue_id)
            if issue is not None:
                issue["status"] = "probing"
                issue["probe_started_at"] = iso(now)
                self.store.upsert_issue(issue)
        return decision

    def _decision_record(self, request: OperationRequest, decision: Decision,
                         now: dt.datetime) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "decision_id": decision.decision_id,
            "ts": iso(now),
            "component": request.component,
            "tool": request.tool,
            "action": request.action,
            "target": request.target,
            "scope": request.scope,
            "environment_id": request.environment_id,
            "session_id": request.session_id,
            "run_id": request.run_id,
            "scope_fingerprint": scope_fingerprint(request),
            "call_fingerprint": call_fingerprint(request),
            "decision": decision.action,
            "action": decision.action,
            "issue_id": decision.issue_id,
            "reason": decision.reason,
            "blocked_until": decision.blocked_until,
            "attempts_left": decision.attempts_left,
            "alternatives": decision.alternatives,
            "confidence": decision.confidence,
            "expires_at": decision.expires_at,
            "policy_version": decision.policy_version,
            "shadow": decision.shadow,
            "override": decision.override,
            "override_basis": decision.override_basis,
        }

    # -- postflight -------------------------------------------------------
    def postflight(self, request: OperationRequest, outcome: str, *,
                   error: BaseException | None = None,
                   error_class: str = "", error_code: str = "", message: str = "",
                   duration_ms: int = 0, attempt: int = 0,
                   decision: Decision | None = None,
                   evidence_ref: str = "",
                   retry_after_s: int | None = None) -> dict[str, Any] | None:
        if outcome not in OUTCOMES:
            raise ValueError(f"unsupported outcome {outcome!r}; use {', '.join(OUTCOMES)}")
        if decision is not None and decision.action == "block" and not decision.shadow:
            raise ValueError("postflight called for a blocked call; skip the tool instead")
        request.args = request.args or {}
        now = self.clock()
        error_class = (error_class or "").strip()
        if outcome in FAILURE_OUTCOMES and not error_class:
            if outcome == "denied":
                error_class = "permission"
            else:
                error_class = classify_exception(error)
        retryable = self.policy.retryable(error_class) if error_class else False
        key_level = self.policy.key_level(error_class) if error_class else "scope"
        fingerprint = fingerprint_for(request, key_level) if error_class \
            else scope_fingerprint(request)
        event = OperationEvent(
            event_id=new_id("OP", now),
            ts=iso(now),
            component=request.component,
            tool=request.tool,
            action=request.action,
            target=request.target,
            outcome=outcome,
            scope=request.scope,
            environment_id=request.environment_id,
            session_id=request.session_id,
            run_id=request.run_id,
            error_class=error_class,
            error_code=error_code,
            message_redacted=redact(message or (str(error) if error else "")),
            duration_ms=int(duration_ms or 0),
            attempt=int(attempt or 0),
            retryable=retryable,
            fingerprint=fingerprint,
            key_level=key_level,
            decision_id=(decision.decision_id if decision else ""),
            would_block=bool(decision and decision.action == "block" and decision.shadow),
            evidence_ref=evidence_ref,
            author="harness",
            policy_version=self.policy.version,
        )
        if outcome == "ok":
            keys = [scope_fingerprint(request), call_fingerprint(request)]
            if attempt:
                event.attempt = int(attempt)
            else:
                active = [
                    item for item in self.store.find_issues(keys, statuses=ACTIVE_STATUSES)
                    if item.get("scope") in ("global", request.scope)
                ]
                event.attempt = max((int(item.get("attempts", 0) or 0)
                                     for item in active), default=0) + 1
            self.store.append_event(event)
            self._resolve_keys(keys, event.event_id, now, scope=request.scope,
                               attempt=event.attempt)
            return None
        issue = self.store.find_issue(fingerprint, error_class, include_resolved=True)
        if issue is None:
            issue = self._new_issue(request, error_class, fingerprint, key_level,
                                    event, now, retryable, decision, retry_after_s)
        else:
            issue = self._update_issue(issue, request, error_class, event, now,
                                       retryable, decision, retry_after_s)
        # Keep the trace attempt number aligned with the issue counter.
        event.attempt = int(attempt or issue.attempts)
        self.store.append_event(event)
        return self.store.upsert_issue(issue)

    def _expires_at(self, error_class: str, now: dt.datetime,
                    next_retry_at: str | None) -> str:
        """TTL must not expire before a server-imposed Retry-After window."""
        ttl_expiry = self.policy.expires_at(error_class, now)
        next_retry = parse_iso(next_retry_at)
        ttl_value = parse_iso(ttl_expiry)
        if next_retry is not None and ttl_value is not None and next_retry > ttl_value:
            return iso(next_retry)
        return ttl_expiry

    def _new_issue(self, request: OperationRequest, error_class: str,
                   fingerprint: str, key_level: str, event: OperationEvent,
                   now: dt.datetime, retryable: bool, decision: Decision | None,
                   retry_after_s: int | None) -> Issue:
        retry = self.policy.retry_record(error_class, 1, now, retry_after_s)
        return Issue(
            issue_id=new_id("ISS", now),
            fingerprint=fingerprint,
            key_level=key_level,
            scope=request.scope,
            environment_id=request.environment_id,
            component=request.component,
            tool=request.tool,
            action=request.action,
            target=request.target,
            error_class=error_class,
            status="cooldown" if retryable else "open",
            first_seen=iso(now),
            last_seen=iso(now),
            count=1,
            attempts=1,
            retry_policy=retry,
            next_retry_at=retry.get("next_retry_at"),
            expires_at=self._expires_at(error_class, now, retry.get("next_retry_at")),
            confidence=0.6,
            source_event_ids=[event.event_id],
            last_probe_event_id=event.event_id if decision and decision.action == "probe" else None,
            diagnosis=diagnosis_for(error_class),
        )

    def _update_issue(self, existing: dict[str, Any], request: OperationRequest,
                      error_class: str, event: OperationEvent, now: dt.datetime,
                      retryable: bool, decision: Decision | None,
                      retry_after_s: int | None) -> Issue:
        issue = Issue.from_dict(dict(existing))
        if issue.status in ("resolved", "mitigated"):
            issue.count = 1
            issue.attempts = 1
            issue.resolution = ""
            issue.resolved_at = None
            issue.resolved_basis = ""
        else:
            issue.count += 1
            issue.attempts += 1
        issue.status = "open" if (not retryable or issue.count >= 2) else "cooldown"
        issue.last_seen = iso(now)
        retry = self.policy.retry_record(error_class, issue.attempts, now, retry_after_s)
        issue.retry_policy = retry
        issue.next_retry_at = retry.get("next_retry_at")
        issue.expires_at = self._expires_at(error_class, now, retry.get("next_retry_at"))
        issue.confidence = min(0.95, 0.4 + 0.2 * issue.count)
        issue.diagnosis = diagnosis_for(error_class)
        issue.last_probe_event_id = event.event_id if decision and decision.action == "probe" \
            else issue.last_probe_event_id
        issue.probe_started_at = None
        issue.source_event_ids = list(issue.source_event_ids or []) + [event.event_id]
        issue.source_event_ids = issue.source_event_ids[-20:]
        return issue

    def _resolve_keys(self, keys: list[str], event_id: str,
                      now: dt.datetime, scope: str = "global",
                      attempt: int = 0) -> None:
        data = self.store.load_issues()
        changed = False
        for issue in data["issues"]:
            if issue.get("fingerprint") not in keys:
                continue
            if issue.get("scope") != scope:
                continue
            if issue.get("status") not in ACTIVE_STATUSES:
                continue
            issue["status"] = "resolved"
            issue["resolution"] = "fixed"
            issue["resolved_at"] = iso(now)
            issue["resolved_basis"] = f"success event {event_id}"
            issue["last_probe_event_id"] = event_id
            if attempt:
                issue["attempts"] = max(int(issue.get("attempts", 0) or 0), int(attempt))
            issue["source_event_ids"] = (list(issue.get("source_event_ids") or [])
                                         + [event_id])[-20:]
            changed = True
        if changed:
            self.store.save_issues(data)

    # -- manual operations ------------------------------------------------
    def resolve(self, issue_id: str, basis: str, reviewer: str = "human",
                resolution: str = "fixed") -> dict[str, Any]:
        if resolution not in ("fixed", "mitigated", "ignored"):
            raise ValueError("resolution must be fixed|mitigated|ignored")
        issue = self.store.get_issue(issue_id)
        if issue is None:
            raise ValueError(f"unknown issue_id {issue_id}")
        if not basis.strip():
            raise ValueError("basis must not be empty")
        issue["status"] = "mitigated" if resolution == "mitigated" else "resolved"
        issue["resolution"] = resolution
        issue["resolved_basis"] = basis.strip()
        issue["reviewer"] = reviewer
        issue["resolved_at"] = iso(self.clock())
        if resolution == "mitigated":
            issue["next_retry_at"] = None
        self.store.upsert_issue(issue)
        return issue

    def ignore(self, issue_id: str, basis: str, reviewer: str = "human") -> dict[str, Any]:
        return self.resolve(issue_id, basis, reviewer=reviewer, resolution="ignored")

    def set_workaround(self, issue_id: str, text: str,
                       reviewer: str = "human") -> dict[str, Any]:
        if not text.strip():
            raise ValueError("workaround must not be empty")
        issue = self.store.get_issue(issue_id)
        if issue is None:
            raise ValueError(f"unknown issue_id {issue_id}")
        issue["workaround"] = text.strip()
        issue["workaround_by"] = reviewer
        issue["workaround_at"] = iso(self.clock())
        self.store.upsert_issue(issue)
        return issue

    def add_note(self, issue_id: str, text: str, author: str = "model") -> dict[str, Any]:
        if not text.strip():
            raise ValueError("note must not be empty")
        issue = self.store.get_issue(issue_id)
        if issue is None:
            raise ValueError(f"unknown issue_id {issue_id}")
        issue.setdefault("notes", []).append({
            "ts": iso(self.clock()),
            "author": author,
            "text": text.strip(),
        })
        self.store.upsert_issue(issue)
        return issue

    # -- reporting --------------------------------------------------------
    def state(self) -> dict[str, Any]:
        return self.store.state(self.policy)

    def report(self, since=None):
        from .report import build_report
        return build_report(self.store, since=since, now=self.clock())

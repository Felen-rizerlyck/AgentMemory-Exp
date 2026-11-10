"""Shadow/enforce reporting for runtime memory."""
from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from typing import Any

from .store import Store
from .timeutil import parse_iso, utcnow

FAILURES = {"fail", "timeout", "denied"}


def parse_since(value: str | None, now: dt.datetime | None = None) -> dt.datetime | None:
    if not value:
        return None
    now = now or utcnow()
    text = str(value).strip().lower()
    try:
        if text.endswith("d"):
            return now - dt.timedelta(days=int(text[:-1]))
        if text.endswith("h"):
            return now - dt.timedelta(hours=int(text[:-1]))
        if text.endswith("m"):
            return now - dt.timedelta(minutes=int(text[:-1]))
        parsed = dt.datetime.fromisoformat(text.replace("z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed.astimezone(dt.timezone.utc)
    except ValueError as error:
        raise ValueError(f"invalid --since value {value!r}; use 7d/24h/30m or ISO 8601") from error


def build_report(store: Store, since: dt.datetime | None = None,
                 now: dt.datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    decisions = store.read_decisions(since)
    events = store.read_events(since)
    issues = store.load_issues()["issues"]

    event_by_decision = {
        event.get("decision_id"): event for event in events
        if event.get("decision_id")
    }
    shadow_decisions = [item for item in decisions if item.get("shadow")]
    decision_action = lambda item: item.get("decision", item.get("action"))
    block_decisions = [item for item in decisions if decision_action(item) == "block"]
    shadow_blocks = [item for item in shadow_decisions
                     if decision_action(item) == "block"]
    probe_decisions = [item for item in decisions if decision_action(item) == "probe"]
    hint_decisions = [item for item in decisions
                      if decision_action(item) == "allow_with_hint"]

    false_blocks = 0
    true_blocks = 0
    for decision in shadow_blocks:
        event = event_by_decision.get(decision.get("decision_id"))
        if not event:
            continue
        if event.get("outcome") == "ok":
            false_blocks += 1
        elif event.get("outcome") in FAILURES:
            true_blocks += 1

    probe_success = 0
    for decision in probe_decisions:
        event = event_by_decision.get(decision.get("decision_id"))
        if event and event.get("outcome") == "ok":
            probe_success += 1

    failure_events = [event for event in events if event.get("outcome") in FAILURES]
    by_fingerprint: dict[str, int] = defaultdict(int)
    for event in failure_events:
        by_fingerprint[str(event.get("fingerprint") or "")] += 1
    duplicate_attempts = sum(max(0, count - 1) for count in by_fingerprint.values())

    issues_by_status: Counter[str] = Counter(item.get("status", "unknown") for item in issues)
    open_issues = sorted(
        [item for item in issues if item.get("status") in
         ("cooldown", "open", "probing", "mitigated", "stale")],
        key=lambda item: str(item.get("last_seen", "")),
        reverse=True,
    )

    report = {
        "generated_at": now.isoformat().replace("+00:00", "Z"),
        "since": since.isoformat().replace("+00:00", "Z") if since else None,
        "events": {
            "total": len(events),
            "ok": sum(1 for event in events if event.get("outcome") == "ok"),
            "failures": len(failure_events),
            "by_outcome": dict(Counter(event.get("outcome", "unknown") for event in events)),
        },
        "decisions": {
            "total": len(decisions),
            "block": len(block_decisions),
            "shadow_block": len(shadow_blocks),
            "probe": len(probe_decisions),
            "hint": len(hint_decisions),
            "shadow_total": len(shadow_decisions),
            "enforce_total": len(decisions) - len(shadow_decisions),
        },
        "shadow": {
            "would_block": len(shadow_blocks),
            "false_blocks": false_blocks,
            "false_block_rate": round(false_blocks / (false_blocks + true_blocks), 3)
            if false_blocks + true_blocks else None,
            "confirmed_blocks": true_blocks,
        },
        "enforce": {
            "blocked_calls": len(block_decisions) - len(shadow_blocks),
        },
        "probes": {
            "attempts": len(probe_decisions),
            "success": probe_success,
            "success_rate": round(probe_success / len(probe_decisions), 3)
            if probe_decisions else None,
        },
        "duplicate_attempts": duplicate_attempts,
        "issues": {
            "total": len(issues),
            "by_status": {status: issues_by_status.get(status, 0)
                          for status in ("cooldown", "open", "probing", "mitigated",
                                         "resolved", "stale")},
            "stale_rate": round(issues_by_status.get("stale", 0) / len(issues), 3)
            if issues else None,
            "open": len(open_issues),
        },
        "top_open_issues": [
            {
                "issue_id": item.get("issue_id"),
                "status": item.get("status"),
                "error_class": item.get("error_class"),
                "component": item.get("component"),
                "tool": item.get("tool"),
                "target": item.get("target"),
                "count": item.get("count"),
                "next_retry_at": item.get("next_retry_at"),
                "workaround": item.get("workaround"),
            }
            for item in open_issues[:10]
        ],
    }
    return report


def format_text(report: dict[str, Any]) -> str:
    lines = [
        f"Runtime memory report (since {report.get('since') or 'all time'})",
        f"events: {report['events']['total']} "
        f"(ok={report['events']['ok']}, failures={report['events']['failures']})",
        f"decisions: {report['decisions']['total']} "
        f"(shadow={report['decisions']['shadow_total']}, "
        f"enforce={report['decisions']['enforce_total']})",
        f"shadow would-block: {report['shadow']['would_block']} "
        f"(false={report['shadow']['false_blocks']}, "
        f"confirmed={report['shadow']['confirmed_blocks']})",
        f"enforce blocked calls: {report['enforce']['blocked_calls']}",
        f"probes: {report['probes']['attempts']} "
        f"(success={report['probes']['success']}, "
        f"rate={report['probes']['success_rate']})",
        f"duplicate failure attempts: {report['duplicate_attempts']}",
        f"issues: {report['issues']['total']} "
        f"({', '.join(f'{key}={value}' for key, value in sorted(report['issues']['by_status'].items()))})",
    ]
    if report["top_open_issues"]:
        lines.append("open issues:")
        for issue in report["top_open_issues"]:
            lines.append(
                f"  {issue['issue_id']} {issue['status']} "
                f"{issue['component']}/{issue['tool']} {issue['target']} "
                f"error={issue['error_class']} count={issue['count']} "
                f"next_retry={issue['next_retry_at'] or '-'}"
            )
            if issue.get("workaround"):
                lines.append(f"    workaround: {issue['workaround']}")
    return "\n".join(lines)

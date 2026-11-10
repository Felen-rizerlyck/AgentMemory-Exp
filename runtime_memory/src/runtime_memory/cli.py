"""CLI for the runtime-memory prototype.

Run from runtime_memory/:

    python src/manage_runtime_memory.py check
    python src/manage_runtime_memory.py issues
    python src/manage_runtime_memory.py report --since 7d
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .models import OperationRequest, SCOPES
from .report import build_report, format_text, parse_since
from .runtime import RuntimeMemory
from .store import DEFAULT_DATA_DIR, Store


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def _request(args) -> OperationRequest:
    try:
        payload = json.loads(args.args or "{}")
    except json.JSONDecodeError as error:
        raise ValueError(f"--args is not valid JSON: {error}") from error
    if not isinstance(payload, dict):
        raise ValueError("--args must be a JSON object")
    return OperationRequest(
        component=args.component,
        tool=args.tool,
        action=args.action,
        target=args.target,
        args=payload,
        scope=args.scope,
        environment_id=args.environment,
        session_id=args.session_id,
        agent_id=getattr(args, "agent_id", ""),
        run_id=args.run_id,
    )


def _print_decision(decision) -> None:
    if decision.action == "allow":
        print(f"[allow] {decision.fingerprint}")
        return
    print(f"[{decision.action}] {decision.fingerprint}")
    if decision.decision_id:
        print(f"  decision_id: {decision.decision_id}")
    if decision.issue_id:
        print(f"  issue: {decision.issue_id}")
    if decision.shadow:
        print("  mode: shadow (advisory; caller may still execute)")
    if decision.reason:
        print(f"  reason: {decision.reason}")
    if decision.blocked_until:
        print(f"  blocked_until: {decision.blocked_until}")
    print(f"  attempts_left: {decision.attempts_left}  confidence: {decision.confidence}")
    if decision.expires_at:
        print(f"  expires_at: {decision.expires_at}")
    for alternative in decision.alternatives:
        print(f"  alternative: {alternative}")
    if decision.override:
        print(f"  override: {decision.override_basis}")


def _print_issue(issue: dict[str, Any]) -> None:
    print(f"{issue.get('issue_id')} [{issue.get('status')}] "
          f"{issue.get('component')}/{issue.get('tool')} @ {issue.get('target')}")
    print(f"  fingerprint: {issue.get('fingerprint')}")
    print(f"  error_class: {issue.get('error_class')}  diagnosis: {issue.get('diagnosis')}")
    print(f"  count: {issue.get('count')}  attempts: {issue.get('attempts')}  "
          f"confidence: {issue.get('confidence')}")
    print(f"  first_seen: {issue.get('first_seen')}  last_seen: {issue.get('last_seen')}")
    print(f"  next_retry_at: {issue.get('next_retry_at') or '-'}  "
          f"expires_at: {issue.get('expires_at') or '-'}")
    if issue.get("workaround"):
        print(f"  workaround: {issue.get('workaround')}")
    if issue.get("notes"):
        print("  notes:")
        for note in issue["notes"]:
            print(f"    [{note.get('author')}] {note.get('text')}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Runtime memory: operational issues, retry policy and preflight gate.")
    parser.add_argument("--root", default=str(DEFAULT_DATA_DIR),
                        help="data directory (default: runtime_memory/data)")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="validate policy, issues, events and decisions")
    brief = sub.add_parser("brief", help="show a compact tool-memory card")
    brief.add_argument("--limit", type=int, default=8)
    brief.add_argument("--json", action="store_true")
    state = sub.add_parser("state", help="show store state")
    state.add_argument("--json", action="store_true")

    issues = sub.add_parser("issues", help="list issues")
    issues.add_argument("--status", choices=["cooldown", "open", "probing",
                                             "mitigated", "resolved", "stale"])
    issues.add_argument("--active", action="store_true",
                        help="hide resolved issues")
    issues.add_argument("--json", action="store_true")

    issue = sub.add_parser("issue", help="show one issue")
    issue.add_argument("issue_id")
    issue.add_argument("--json", action="store_true")

    preflight = sub.add_parser("preflight", help="ask whether a tool call should run")
    preflight.add_argument("--component", required=True)
    preflight.add_argument("--tool", required=True)
    preflight.add_argument("--action", required=True)
    preflight.add_argument("--target", required=True)
    preflight.add_argument("--args", default="{}", help="JSON object")
    preflight.add_argument("--scope", choices=list(SCOPES), default="session")
    preflight.add_argument("--environment", default="default")
    preflight.add_argument("--session-id", default="")
    preflight.add_argument("--agent-id", default="")
    preflight.add_argument("--run-id", default="")
    preflight.add_argument("--probe", action="store_true",
                           help="operator-only: allow one probe when blocked "
                                "(requires --basis)")
    preflight.add_argument("--basis", default="")
    preflight.add_argument("--json", action="store_true")

    record = sub.add_parser("record", help="record a tool outcome")
    record.add_argument("--component", required=True)
    record.add_argument("--tool", required=True)
    record.add_argument("--action", required=True)
    record.add_argument("--target", required=True)
    record.add_argument("--args", default="{}", help="JSON object")
    record.add_argument("--scope", choices=list(SCOPES), default="session")
    record.add_argument("--environment", default="default")
    record.add_argument("--session-id", default="")
    record.add_argument("--agent-id", default="")
    record.add_argument("--run-id", default="")
    record.add_argument("--outcome", required=True,
                        choices=["ok", "fail", "timeout", "denied"])
    record.add_argument("--error-class", default="")
    record.add_argument("--error-code", default="")
    record.add_argument("--message", default="")
    record.add_argument("--duration-ms", type=int, default=0)
    record.add_argument("--attempt", type=int, default=0,
                        help="0 = derive from the issue counter")
    record.add_argument("--decision-id", default="")
    record.add_argument("--retry-after-s", type=int)
    record.add_argument("--evidence-ref", default="")
    record.add_argument("--json", action="store_true")

    resolve = sub.add_parser("resolve", help="mark an issue fixed/mitigated")
    resolve.add_argument("issue_id")
    resolve.add_argument("--basis", required=True)
    resolve.add_argument("--reviewer", default="human")
    resolve.add_argument("--resolution", choices=["fixed", "mitigated", "ignored"],
                         default="fixed")

    ignore = sub.add_parser("ignore", help="mark an issue as a false positive")
    ignore.add_argument("issue_id")
    ignore.add_argument("--basis", required=True)
    ignore.add_argument("--reviewer", default="human")

    note = sub.add_parser("note", help="append a note; never changes status")
    note.add_argument("issue_id")
    note.add_argument("--text", required=True)
    note.add_argument("--author", default="model")

    workaround = sub.add_parser("workaround", help="set an alternative path; does not change status")
    workaround.add_argument("issue_id")
    workaround.add_argument("--text", required=True)
    workaround.add_argument("--reviewer", default="human")

    report = sub.add_parser("report", help="shadow/enforce metrics")
    report.add_argument("--since", help="7d / 24h / 30m / ISO 8601")
    report.add_argument("--json", action="store_true")

    gc = sub.add_parser("gc", help="delete old event files and resolved issues")
    gc.add_argument("--events-days", type=int, default=30)
    gc.add_argument("--issues-days", type=int, default=90)
    gc.add_argument("--apply", action="store_true", help="actually delete (dry-run by default)")
    gc.add_argument("--json", action="store_true")

    policy = sub.add_parser("policy", help="show the effective policy")
    policy.add_argument("--json", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    root = Path(args.root)
    try:
        if args.command == "check":
            store = Store(root)
            store.ensure()
            problems = store.check()
            if problems:
                for problem in problems:
                    print(f"PROBLEM: {problem}")
                print(f"Runtime memory check failed with {len(problems)} problem(s).")
                return 1
            print("Runtime memory check clean.")
            return 0

        runtime = RuntimeMemory(root)
        if args.command == "brief":
            cards = runtime.brief(limit=args.limit)
            if args.json:
                print(_json({"issues": cards}))
            elif not cards:
                print("No active tool issues.")
            else:
                for item in cards:
                    print(f"- {item['tool']} @ {item['target']}: {item['status']} / "
                          f"{item['error']} ({item['independent_runs']} independent run(s)); "
                          f"retry={item['retry_at'] or 'when eligible'}")
                    if item["workaround"]:
                        print(f"  workaround: {item['workaround']}")
            return 0
        if args.command == "state":
            state = runtime.state()
            print(_json(state) if args.json else _format_state(state))
            return 0
        if args.command == "issues":
            issues = runtime.store.list_issues(status=args.status,
                                               include_resolved=not args.active)
            if args.json:
                print(_json({"schema_version": 1, "issues": issues}))
                return 0
            if not issues:
                print("No issues matched.")
                return 0
            for issue in issues:
                _print_issue(issue)
                print()
            return 0
        if args.command == "issue":
            issue = runtime.store.get_issue(args.issue_id)
            if issue is None:
                raise ValueError(f"unknown issue_id {args.issue_id}")
            if args.json:
                print(_json(issue))
            else:
                _print_issue(issue)
            return 0
        if args.command == "preflight":
            decision = runtime.preflight(
                _request(args), allow_probe=args.probe,
                override_basis=args.basis, human_override=args.probe)
            if args.json:
                print(_json(decision.to_dict()))
            else:
                _print_decision(decision)
            return 0
        if args.command == "record":
            issue = runtime.postflight(
                _request(args), args.outcome, error_class=args.error_class,
                error_code=args.error_code, message=args.message,
                duration_ms=args.duration_ms, attempt=args.attempt,
                decision_id=args.decision_id, retry_after_s=args.retry_after_s,
                evidence_ref=args.evidence_ref)
            if issue is None:
                print("Recorded ok; no issue.")
            elif args.json:
                print(_json(issue))
            else:
                print(f"Recorded failure -> {issue['issue_id']} [{issue['status']}]")
            return 0
        if args.command == "resolve":
            issue = runtime.resolve(args.issue_id, args.basis,
                                    reviewer=args.reviewer,
                                    resolution=args.resolution)
            _print_issue(issue)
            return 0
        if args.command == "ignore":
            issue = runtime.ignore(args.issue_id, args.basis, reviewer=args.reviewer)
            _print_issue(issue)
            return 0
        if args.command == "note":
            issue = runtime.add_note(args.issue_id, args.text, author=args.author)
            _print_issue(issue)
            return 0
        if args.command == "workaround":
            issue = runtime.set_workaround(args.issue_id, args.text,
                                           reviewer=args.reviewer)
            _print_issue(issue)
            return 0
        if args.command == "report":
            since = parse_since(args.since) if args.since else None
            report = build_report(runtime.store, since=since, now=runtime.clock())
            print(_json(report) if args.json else format_text(report))
            return 0
        if args.command == "gc":
            result = runtime.store.gc(events_days=args.events_days,
                                      issues_days=args.issues_days,
                                      dry_run=not args.apply)
            print(_json(result) if args.json else
                  f"gc: {result} (use --apply to delete)")
            return 0
        if args.command == "policy":
            policy = runtime.policy
            print(_json(policy.to_dict()) if args.json else
                  f"policy_version={policy.version} enforce={policy.enforce}")
            return 0
        parser.error(f"unknown command {args.command}")
    except (ValueError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    return 1


def _format_state(state: dict[str, Any]) -> str:
    statuses = ", ".join(f"{key}={value}" for key, value in
                         sorted(state["issues_by_status"].items()))
    return (f"root: {state['root']}\n"
            f"enforce: {state['enforce']}\n"
            f"events: {state['events']}  decisions: {state['decisions']}  "
            f"overrides: {state['overrides']}\n"
            f"issues: {state['issues']} ({statuses})\n"
            f"last_event_at: {state['last_event_at'] or '-'}")


if __name__ == "__main__":
    raise SystemExit(main())

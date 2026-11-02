#!/usr/bin/env python3
"""Small end-to-end demo for the runtime-memory prototype.

Default mode is shadow: every tool call still runs, but preflight decisions show
what *would* have been blocked.  ``--enforce`` skips blocked calls.

By default the demo uses a temporary data directory and never touches the
checked-in ``data/`` store.  Use ``--keep`` only when you explicitly want to
write to ``runtime_memory/data``.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from runtime_memory import OperationRequest, Policy, RuntimeMemory  # noqa: E402
from runtime_memory.policy import DEFAULT_POLICY  # noqa: E402
from runtime_memory.report import format_text  # noqa: E402
from runtime_memory.store import RUNTIME_ROOT  # noqa: E402


class FakeClock:
    def __init__(self, start: dt.datetime):
        self.now = start

    def __call__(self) -> dt.datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += dt.timedelta(seconds=seconds)


def main() -> int:
    parser = argparse.ArgumentParser(description="Runtime memory shadow/enforce demo")
    parser.add_argument("--shadow", action="store_true",
                        help="observe only, never block (default)")
    parser.add_argument("--enforce", action="store_true",
                        help="block calls instead of only observing")
    parser.add_argument("--keep", action="store_true",
                        help="write to runtime_memory/data instead of a temporary directory")
    args = parser.parse_args()
    if args.shadow and args.enforce:
        parser.error("use either --shadow or --enforce, not both")
    enforce = bool(args.enforce)

    root = RUNTIME_ROOT / "data" if args.keep else Path(tempfile.mkdtemp(prefix="rtmem-demo-"))
    policy_data = copy.deepcopy(DEFAULT_POLICY)
    policy_data["enforce"] = enforce
    clock = FakeClock(dt.datetime(2026, 11, 2, 6, 0, tzinfo=dt.timezone.utc))
    runtime = RuntimeMemory(root, policy=Policy(policy_data), clock=clock)
    if args.keep:
        from runtime_memory.store import atomic_write_json
        atomic_write_json(runtime.store.policy_path, runtime.policy.to_dict())

    request = OperationRequest(
        component="mcp", tool="hunt.query", action="search",
        target="10.7.194.120:22196", args={"q": "dns tunnel", "limit": 50},
        scope="global", environment_id="lab-a", run_id="demo-run",
    )

    mode = "enforce" if enforce else "shadow"
    print(f"runtime memory demo ({mode}); data={root}")
    print("scenario: hunt.query endpoint is unreachable; 3 attempted calls\n")

    calls = 0
    for attempt in range(1, 4):
        decision = runtime.preflight(request)
        print(f"attempt {attempt}: preflight -> {decision.action} "
              f"(issue={decision.issue_id or '-'}, "
              f"attempts_left={decision.attempts_left})")
        if decision.action == "block" and enforce:
            print("  call skipped by enforce gate\n")
            clock.advance(60)
            continue
        calls += 1
        issue = runtime.postflight(
            request, "fail", error=ConnectionRefusedError("connect refused"),
            duration_ms=30012, attempt=attempt, decision=decision,
        )
        print(f"  call executed; issue={issue['issue_id']} "
              f"status={issue['status']} count={issue['count']}")
        clock.advance(60)
        print()

    print(f"actual calls: {calls}")
    report = runtime.report()
    print()
    print(format_text(report))

    issues = runtime.store.list_issues()
    open_issue = next((item for item in issues if item["status"] != "resolved"), None)
    if open_issue is not None:
        print(f"\nsimulate operator fix: resolve {open_issue['issue_id']}")
        runtime.resolve(open_issue["issue_id"], "endpoint restored", reviewer="demo")
        decision = runtime.preflight(request)
        print(f"preflight after resolve -> {decision.action}")

    if args.keep:
        print(f"\nstate kept under {root}")
    else:
        shutil.rmtree(root, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

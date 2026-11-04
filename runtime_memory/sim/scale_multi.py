#!/usr/bin/env python3
"""T5 multi-issue scale probe.

Creates 100 distinct issues plus synthetic events and measures preflight,
report and check latency.  Run from ``runtime_memory/``::

    python sim/scale_multi.py --issues 100 --events 5000 --run-id exec-<UTC>-scale-multi
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory import OperationRequest, RuntimeMemory  # noqa: E402
from runtime_memory.models import Issue  # noqa: E402
from runtime_memory.policy import Policy, default_policy  # noqa: E402
from runtime_memory.store import atomic_write_json  # noqa: E402
from runtime_memory.timeutil import iso  # noqa: E402


class Clock:
    def __init__(self):
        self.now = dt.datetime(2026, 11, 2, 6, 0, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.now


def make_events(runtime: RuntimeMemory, count: int) -> None:
    path = runtime.store.events_dir / "2026-11.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for index in range(count):
            handle.write(json.dumps({
                "event_id": f"OP-{index}",
                "ts": "2026-11-02T06:00:00Z",
                "component": "mcp", "tool": "hunt.query", "action": "search",
                "target": "http://x/hunt", "outcome": "ok", "scope": "global",
                "environment_id": "lab-a", "run_id": "scale-multi",
                "fingerprint": "lab-a|scope|mcp|hunt.query|search|http://x/hunt",
                "error_class": "", "schema_version": 1,
            }, ensure_ascii=False) + "\n")


def make_issues(runtime: RuntimeMemory, count: int) -> None:
    now = iso(runtime.clock())
    for index in range(count):
        component = "mcp" if index % 2 == 0 else "parser"
        tool = "hunt.query" if index % 2 == 0 else "pcap.parse"
        action = "search" if index % 2 == 0 else "parse"
        target = f"http://10.0.0.{index + 1}/tool"
        issue = Issue(
            issue_id=f"ISS-{index:04d}",
            fingerprint=f"lab-a|scope|{component}|{tool}|{action}|{target}",
            key_level="scope", scope="global", environment_id="lab-a",
            component=component, tool=tool, action=action, target=target,
            error_class="unreachable", status="open",
            first_seen=now, last_seen=now, count=1, attempts=1,
            retry_policy={"retryable": True, "max_attempts": 3,
                          "max_attempts_per_run": 1, "mode": "fixed",
                          "base_s": 900, "max_s": 1800, "ttl_s": 86400},
            next_retry_at="2026-11-02T07:00:00Z",
            expires_at="2026-11-03T06:00:00Z",
        )
        runtime.store.upsert_issue(issue)


def main() -> int:
    parser = argparse.ArgumentParser(description="T5 multi-issue scale probe")
    parser.add_argument("--issues", type=int, default=100)
    parser.add_argument("--events", type=int, default=5000)
    parser.add_argument("--run-id", default="scale-multi-2026-11-03")
    parser.add_argument("--out", help="default sim/runs/<run-id>")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    out = Path(args.out) if args.out else ROOT / "sim" / "runs" / args.run_id
    if out.exists() and not args.force:
        parser.error(f"{out} exists; pass --force or a new --run-id")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    folder = tempfile.mkdtemp(prefix="rtmem-scale-multi-")
    runtime = RuntimeMemory(folder, policy=Policy(default_policy()), clock=Clock())
    make_events(runtime, args.events)
    make_issues(runtime, args.issues)
    runtime = RuntimeMemory(folder, policy=Policy(default_policy()), clock=Clock())

    request = OperationRequest(
        component="mcp", tool="hunt.query", action="search",
        target="http://x/hunt", args={"q": "x"}, scope="global",
        environment_id="lab-a", run_id="scale-multi",
    )
    request_no_run = OperationRequest(**{**request.to_dict(), "run_id": ""})

    start = time.perf_counter()
    for _ in range(20):
        runtime.preflight(request_no_run)
    preflight_no_run = (time.perf_counter() - start) / 20

    start = time.perf_counter()
    for _ in range(5):
        runtime.preflight(request)
    preflight_with_run = (time.perf_counter() - start) / 5

    start = time.perf_counter()
    runtime.report()
    report_s = time.perf_counter() - start

    start = time.perf_counter()
    problems = runtime.store.check()
    check_s = time.perf_counter() - start

    issues_path = runtime.store.issues_path
    events_path = runtime.store.events_dir / "2026-11.jsonl"
    row = {
        "issues": args.issues,
        "events": args.events,
        "preflight_no_run_ms": round(preflight_no_run * 1000, 2),
        "preflight_with_run_ms": round(preflight_with_run * 1000, 2),
        "report_ms": round(report_s * 1000, 2),
        "check_ms": round(check_s * 1000, 2),
        "issues_json_bytes": issues_path.stat().st_size,
        "events_bytes": events_path.stat().st_size,
        "check_problems": problems,
    }
    atomic_write_json(out / "metrics.json", {"schema_version": 1, "rows": [row]})
    lines = [
        "# T5 multi-issue scale probe",
        "",
        "| issues | events | preflight no run_id | preflight with run_id | "
        "report | check | issues.json | events |",
        "|---|---|---|---|---|---|---|---|",
        f"| {row['issues']} | {row['events']} | {row['preflight_no_run_ms']} ms | "
        f"{row['preflight_with_run_ms']} ms | {row['report_ms']} ms | "
        f"{row['check_ms']} ms | {row['issues_json_bytes']} B | "
        f"{row['events_bytes']} B |",
        "",
        f"check problems: {problems or 'none'}",
    ]
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    shutil.rmtree(folder, ignore_errors=True)
    print("\n".join(lines))
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

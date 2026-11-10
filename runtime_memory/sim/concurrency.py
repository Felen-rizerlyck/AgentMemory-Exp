#!/usr/bin/env python3
"""T6 concurrency, crash and partial-write probe.

Four checks:

1. two processes append 100 valid JSON lines each to the same events file;
2. two processes postflight the same issue at the same time;
3. an event is appended without updating issues.json (partial write);
4. a child process writes an event and is terminated before the issue update.

Run from ``runtime_memory/``::

    python sim/concurrency.py --run-id exec-<UTC>-concurrency
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import multiprocessing as mp
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory import OperationRequest, Policy, RuntimeMemory  # noqa: E402
from runtime_memory.models import OperationEvent  # noqa: E402
from runtime_memory.policy import default_policy  # noqa: E402
from runtime_memory.store import Store, append_jsonl  # noqa: E402
from runtime_memory.timeutil import iso  # noqa: E402


class FixedClock:
    def __init__(self):
        self.now = dt.datetime(2026, 11, 2, 6, 0, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.now


def _write_error(path: str, exc: BaseException) -> None:
    try:
        Path(path).write_text(json.dumps(
            {"type": type(exc).__name__, "message": str(exc)},
            ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def _append_worker(path: str, barrier: Any, count: int, error_path: str) -> None:
    try:
        barrier.wait(timeout=30)
        for index in range(count):
            append_jsonl(Path(path), {"index": index, "pid": os.getpid()})
    except BaseException as exc:  # noqa: BLE001
        _write_error(error_path, exc)


def _postflight_worker(root: str, barrier: Any, error_path: str) -> None:
    try:
        runtime = RuntimeMemory(root, policy=Policy(default_policy()),
                                clock=FixedClock())
        barrier.wait(timeout=30)
        request = OperationRequest(
            component="mcp", tool="hunt.query", action="search",
            target="http://10.7.194.120:22196/hunt",
            args={"q": "dns"}, scope="global", environment_id="lab-a",
            run_id="concurrent",
        )
        runtime.postflight(request, "fail",
                          error=ConnectionRefusedError("connect refused"))
    except BaseException as exc:  # noqa: BLE001
        _write_error(error_path, exc)


def _crash_worker(root: str, marker: str) -> None:
    store = Store(root)
    store.ensure()
    event = OperationEvent(
        event_id="OP-crash", ts=iso(FixedClock()()),
        component="mcp", tool="hunt.query", action="search",
        target="http://x/hunt", outcome="fail", fingerprint="fp",
    )
    store.append_event(event)
    Path(marker).write_text("ready", encoding="utf-8")
    time.sleep(30)


def _context():
    return mp.get_context("spawn")


def _run_append_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-conc-append-") as root:
        path = Path(root) / "events" / "2026-11.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        ctx = _context()
        barrier = ctx.Barrier(2)
        procs = [ctx.Process(target=_append_worker,
                             args=(str(path), barrier, 100,
                                   str(Path(root) / f"err-{index}.json")))
                 for index in range(2)]
        for proc in procs:
            proc.start()
        for proc in procs:
            proc.join(timeout=120)
        for proc in procs:
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=5)
        errors = []
        for error_path in Path(root).glob("err-*.json"):
            errors.append(json.loads(error_path.read_text(encoding="utf-8")))
        lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
        bad_lines = 0
        for line in lines:
            try:
                json.loads(line)
            except json.JSONDecodeError:
                bad_lines += 1
        ok = len(lines) == 200 and bad_lines == 0 and not errors
        return {"test": "concurrent_append", "expected_lines": 200,
                "actual_lines": len(lines), "bad_lines": bad_lines,
                "errors": errors, "status": "PASS" if ok else "FAIL"}


def _run_postflight_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-conc-post-") as root:
        ctx = _context()
        barrier = ctx.Barrier(2)
        procs = [ctx.Process(target=_postflight_worker,
                             args=(root, barrier, str(Path(root) / f"err-{i}.json")))
                 for i in range(2)]
        for proc in procs:
            proc.start()
        for proc in procs:
            proc.join(timeout=60)
        for proc in procs:
            if proc.is_alive():
                proc.terminate()
                proc.join(timeout=5)
        errors = []
        for error_path in Path(root).glob("err-*.json"):
            errors.append(json.loads(error_path.read_text(encoding="utf-8")))
        store = Store(root)
        issues = store.load_issues()["issues"]
        events = store.read_events()
        ok = (len(issues) == 1 and issues[0].get("count") == 2
              and len(events) == 2 and not errors)
        return {"test": "concurrent_postflight", "expected_issue_records": 1,
                "expected_aggregated_failures": 2,
                "issue_records": len(issues),
                "issue_counts": [item.get("count") for item in issues],
                "events": len(events), "errors": errors,
                "status": "PASS" if ok else "FAIL"}


def _run_partial_write_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-conc-partial-") as root:
        store = Store(root)
        store.ensure()
        append_jsonl(store.events_dir / "2026-11.jsonl", {
            "event_id": "OP-partial", "ts": "2026-11-02T06:00:00Z",
            "component": "mcp", "tool": "hunt.query", "action": "search",
            "target": "http://x/hunt", "outcome": "fail", "fingerprint": "fp",
        })
        problems = store.check()
        return {"test": "partial_write_event_without_issue",
                "check_problems": problems,
                "detected": bool(problems),
                "status": "GAP" if not problems else "PASS",
                "note": "plan T6: not detecting event-without-issue is a gap"}


def _run_crash_test() -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="rtmem-conc-crash-") as root:
        marker = Path(root) / "ready"
        ctx = _context()
        proc = ctx.Process(target=_crash_worker, args=(root, str(marker)))
        proc.start()
        deadline = time.time() + 20
        while not marker.exists() and time.time() < deadline:
            time.sleep(0.05)
        ready = marker.exists()
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=10)
        store = Store(root)
        problems = store.check()
        corrupt = 0
        for path in list((Path(root) / "events").glob("*.jsonl")):
            for line in path.read_text(encoding="utf-8").splitlines():
                try:
                    json.loads(line)
                except json.JSONDecodeError:
                    corrupt += 1
        orphaned = len(store.read_events()) > len(store.load_issues()["issues"])
        status = "FAIL" if corrupt else "GAP" if orphaned and not problems else "PASS"
        return {"test": "terminate_between_event_and_issue",
                "marker_seen": ready,
                "check_problems": problems,
                "corrupt_event_lines": corrupt,
                "event_count": len(store.read_events()),
                "issue_count": len(store.load_issues()["issues"]),
                "orphan_event_detected": bool(problems),
                "status": status}


def main() -> int:
    parser = argparse.ArgumentParser(description="T6 concurrency probe")
    parser.add_argument("--run-id", default="concurrency-2026-11-03")
    parser.add_argument("--out", help="default sim/runs/<run-id>")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    out = Path(args.out) if args.out else ROOT / "sim" / "runs" / args.run_id
    if out.exists() and not args.force:
        parser.error(f"{out} exists; pass --force or a new --run-id")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    results = [_run_append_test(), _run_postflight_test(),
               _run_partial_write_test(), _run_crash_test()]
    (out / "metrics.json").write_text(
        json.dumps({"schema_version": 1, "checks": results},
                   ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = ["# T6 concurrency / crash / partial write", "",
             "| test | status | observed |", "|---|---|---|"]
    for item in results:
        observed = {key: value for key, value in item.items()
                    if key not in ("test", "status")}
        lines.append(f"| {item['test']} | **{item['status']}** | "
                     f"`{json.dumps(observed, ensure_ascii=False)}` |")
    lines += ["", "Notes:",
              "- `concurrent_append`: 2 processes x 100 valid JSON lines.",
              "- `concurrent_postflight`: 2 processes record the same failure.",
              "- `partial_write_event_without_issue`: check() visibility.",
              "- `terminate_between_event_and_issue`: simulated crash after "
              "the event append, before the issue update."]
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    print(f"\nwrote {out}")
    return 1 if any(item["status"] == "FAIL" for item in results) else 0



if __name__ == "__main__":
    raise SystemExit(main())

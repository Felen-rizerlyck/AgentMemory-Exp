#!/usr/bin/env python3
"""Small scale/latency probe for the JSONL runtime-memory store.

Creates N synthetic events, then measures:
  - preflight without a run_id (no per-run budget scan)
  - preflight with a run_id (per-run budget scans events)
  - report
  - check
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory import OperationRequest, RuntimeMemory  # noqa: E402
from runtime_memory.policy import Policy, default_policy  # noqa: E402
from runtime_memory.store import atomic_write_json  # noqa: E402

SIZES = (1000, 5000, 20000)
OUT = ROOT / "sim" / "runs" / "scale-2026-11-03"


def make_events(path: Path, count: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for index in range(count):
            handle.write(json.dumps({
                "event_id": f"OP-{index}",
                "ts": "2026-11-03T06:00:00Z",
                "component": "mcp", "tool": "hunt.query", "action": "search",
                "target": "http://x/hunt", "outcome": "ok", "scope": "global",
                "environment_id": "lab-a", "run_id": "scale",
                "fingerprint": "lab-a|scope|mcp|hunt.query|search|http://x/hunt",
                "error_class": "", "schema_version": 1,
            }, ensure_ascii=False) + "\n")


def measure(size: int) -> dict:
    folder = tempfile.TemporaryDirectory(prefix="rtmem-scale-")
    runtime = RuntimeMemory(folder.name, policy=Policy(default_policy()))
    make_events(runtime.store.events_dir / "2026-11.jsonl", size)
    request = OperationRequest(
        component="mcp", tool="hunt.query", action="search",
        target="http://x/hunt", args={"q": "x"}, scope="global",
        environment_id="lab-a", run_id="scale",
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
    report = time.perf_counter() - start

    start = time.perf_counter()
    runtime.store.check()
    check = time.perf_counter() - start

    folder.cleanup()
    return {"size": size, "preflight_no_run_ms": round(preflight_no_run * 1000, 2),
            "preflight_with_run_ms": round(preflight_with_run * 1000, 2),
            "report_ms": round(report * 1000, 2),
            "check_ms": round(check * 1000, 2)}


def main() -> int:
    rows = [measure(size) for size in SIZES]
    OUT.mkdir(parents=True, exist_ok=True)
    atomic_write_json(OUT / "metrics.json", {"schema_version": 1, "rows": rows})
    lines = ["# Scale probe (synthetic JSONL events)", "",
             "| events | preflight no run_id | preflight with run_id | report | check |",
             "|---|---|---|---|---|"]
    for row in rows:
        lines.append(f"| {row['size']} | {row['preflight_no_run_ms']} ms | "
                     f"{row['preflight_with_run_ms']} ms | {row['report_ms']} ms | "
                     f"{row['check_ms']} ms |")
    lines += ["", "`preflight with run_id` includes the per-run budget scan over all events; "
              "`preflight no run_id` skips it."]
    (OUT / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines[:8]))
    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

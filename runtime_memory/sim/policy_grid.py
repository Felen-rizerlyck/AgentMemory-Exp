#!/usr/bin/env python3
"""T3: policy grid for runtime-memory (base_s x max_attempts x TTL).

This is a test/experiment script, not part of the algorithm.  It reuses the
Monte-Carlo shape of ``sim/workload.py`` but parameterises the retry policy and
runs only enforce mode, so each grid cell shows how many runs eventually succeed
before the attempt budget is exhausted.

Run from ``runtime_memory/``::

    python sim/policy_grid.py --seeds 30 --run-id exec-<UTC>-policy-grid

Outputs ``grid.csv``, ``metrics.json`` and ``summary.md`` under
``sim/runs/<run-id>/`` (or ``--out``).
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import random
import shutil
import statistics
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory import OperationRequest, Policy, RuntimeMemory  # noqa: E402
from runtime_memory.policy import default_policy  # noqa: E402
from runtime_memory.store import atomic_write_json  # noqa: E402
from runtime_memory.timeutil import parse_iso  # noqa: E402

INTERVAL_S = 60
HORIZON_S = 3600
MAX_CALLS = 60
MAX_DOWN_S = 1800

BASE_GRID = (60, 300, 900, 1800)
MAX_ATTEMPTS_GRID = (1, 3, 5, 10)
TTL_GRID = (3600, 86400)


class Clock:
    def __init__(self):
        self.now = dt.datetime(2026, 11, 2, 6, 0, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += dt.timedelta(seconds=seconds)


@dataclass
class GridResult:
    base_s: int
    max_attempts: int
    ttl_s: int
    seed: int
    down_s: int
    calls: int
    failures: int
    blocked: int
    success: bool
    success_at_s: int | None


def request(seed: int) -> OperationRequest:
    return OperationRequest(
        component="mcp", tool="hunt.query", action="search",
        target=f"http://10.7.194.{seed % 200 + 1}:22196/hunt",
        args={"q": "dns tunnel", "seed": seed},
        scope="global", environment_id="lab-a", run_id="",
    )


def policy_for(base_s: int, max_attempts: int, ttl_s: int) -> Policy:
    data = copy.deepcopy(default_policy())
    data["enforce"] = True
    rule = data["classes"]["unreachable"]
    rule["base_s"] = base_s
    rule["max_s"] = max(base_s, 1800)
    rule["max_attempts"] = max_attempts
    rule["ttl_s"] = ttl_s
    data["budgets"]["max_attempts_per_call_key_per_run"] = 99
    data["budgets"]["max_failures_per_component_per_run"] = 99
    return Policy(data)


def run_once(base_s: int, max_attempts: int, ttl_s: int, seed: int,
             down_s: int) -> GridResult:
    clock = Clock()
    folder = tempfile.mkdtemp(prefix="rtmem-grid-")
    runtime = RuntimeMemory(folder,
                            policy=policy_for(base_s, max_attempts, ttl_s),
                            clock=clock)
    req = request(seed)
    calls = failures = blocked = 0
    success = False
    success_at = None
    t = 0
    while t <= HORIZON_S and calls < MAX_CALLS:
        decision = runtime.preflight(req)
        if decision.action == "block":
            blocked += 1
            until = parse_iso(decision.blocked_until)
            if until is None:
                break  # attempt budget exhausted: no retry window
            wait = max(INTERVAL_S, int((until - clock.now).total_seconds()))
            t += wait
            clock.advance(wait)
            continue
        calls += 1
        ok = clock.now >= (dt.datetime(2026, 11, 2, 6, 0, tzinfo=dt.timezone.utc)
                           + dt.timedelta(seconds=down_s))
        if ok:
            runtime.postflight(req, "ok", decision=decision)
            success = True
            success_at = t
            break
        failures += 1
        runtime.postflight(req, "fail",
                           error=ConnectionRefusedError("connect refused"),
                           decision=decision)
        t += INTERVAL_S
        clock.advance(INTERVAL_S)
    shutil.rmtree(folder, ignore_errors=True)
    return GridResult(base_s, max_attempts, ttl_s, seed, down_s, calls,
                      failures, blocked, success, success_at)


def summarize(results: list[GridResult]) -> dict[str, Any]:
    def mean(values):
        return round(statistics.mean(values), 3) if values else None

    successes = [item.success_at_s for item in results if item.success_at_s is not None]
    return {
        "runs": len(results),
        "success_rate": round(sum(item.success for item in results) / len(results), 3)
        if results else None,
        "mean_calls": mean([item.calls for item in results]),
        "mean_failures": mean([item.failures for item in results]),
        "mean_blocked": mean([item.blocked for item in results]),
        "mean_false_blocks": 0.0,
        "mean_tts_s": mean(successes),
        "mean_duplicate_failures": round(
            sum(max(0, item.failures - 1) for item in results) / len(results), 3)
        if results else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="T3 policy grid")
    parser.add_argument("--seeds", type=int, default=30)
    parser.add_argument("--run-id", default="policy-grid-2026-11-03")
    parser.add_argument("--out", help="default sim/runs/<run-id>")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    out = Path(args.out) if args.out else ROOT / "sim" / "runs" / args.run_id
    if out.exists() and not args.force:
        parser.error(f"{out} exists; pass --force or a new --run-id")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    metrics: dict[str, Any] = {}
    rows: list[dict[str, Any]] = []
    for base_s in BASE_GRID:
        for max_attempts in MAX_ATTEMPTS_GRID:
            for ttl_s in TTL_GRID:
                label = f"enforce_b{base_s}_m{max_attempts}_ttl{ttl_s}"
                results = [
                    run_once(base_s, max_attempts, ttl_s, seed,
                             random.Random(seed).randint(0, MAX_DOWN_S))
                    for seed in range(args.seeds)
                ]
                summary = summarize(results)
                metrics[label] = {"base_s": base_s,
                                  "max_attempts": max_attempts,
                                  "ttl_s": ttl_s, **summary}
                row = {"base_s": base_s, "max_attempts": max_attempts,
                       "ttl_s": ttl_s, **summary}
                rows.append(row)
                print(f"{label}: success={summary['success_rate']} "
                      f"calls={summary['mean_calls']} "
                      f"blocked={summary['mean_blocked']}")

    atomic_write_json(out / "metrics.json", {
        "schema_version": 1,
        "parameters": {"seeds": args.seeds, "interval_s": INTERVAL_S,
                       "horizon_s": HORIZON_S, "max_down_s": MAX_DOWN_S,
                       "base_grid": list(BASE_GRID),
                       "max_attempts_grid": list(MAX_ATTEMPTS_GRID),
                       "ttl_grid": list(TTL_GRID)},
        "configs": metrics,
    })
    header = ["base_s", "max_attempts", "ttl_s", "success_rate",
              "mean_calls", "mean_failures", "mean_blocked",
              "mean_false_blocks", "mean_tts_s", "mean_duplicate_failures"]
    csv_lines = [",".join(header)]
    for row in rows:
        csv_lines.append(",".join(
            [str(row[key]) if row[key] is not None else "" for key in header]))
    (out / "grid.csv").write_text("\n".join(csv_lines) + "\n", encoding="utf-8")

    lines = [
        "# T3 policy grid (enforce only)",
        "",
        f"seeds per cell: {args.seeds}; down time uniform 0..{MAX_DOWN_S}s; "
        f"retry interval {INTERVAL_S}s; horizon {HORIZON_S}s.",
        "",
        "| base_s | max_attempts | ttl_s | success | mean calls | mean failures | "
        "mean blocked | mean TTS |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            f"| {row['base_s']} | {row['max_attempts']} | {row['ttl_s']} | "
            f"{row['success_rate']} | {row['mean_calls']} | "
            f"{row['mean_failures']} | {row['mean_blocked']} | "
            f"{row['mean_tts_s']} |")
    lines += ["", "Grid cells: 4 base x 4 max_attempts x 2 TTL = "
                  f"{len(rows)}. Raw table: `grid.csv`."]
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

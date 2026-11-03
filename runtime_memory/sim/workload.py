#!/usr/bin/env python3
"""Offline Monte-Carlo workload for runtime-memory policy evaluation.

No real tools.  Each seed simulates one endpoint that is down for a random
duration and an agent that retries every 60s.  We compare:

  baseline      no memory: call every 60s
  shadow_<base> preflight decisions recorded, calls still run
  enforce_<base> blocked calls skipped; agent waits until next_retry_at

Outputs a run directory with metrics.json, table.csv, summary.md.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import random
import statistics
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory import OperationRequest, Policy, RuntimeMemory  # noqa: E402
from runtime_memory.policy import default_policy  # noqa: E402
from runtime_memory.store import atomic_write_json  # noqa: E402
from runtime_memory.timeutil import iso, parse_iso  # noqa: E402

INTERVAL_S = 60
HORIZON_S = 1 * 3600
MAX_CALLS = 60
MAX_DOWN_S = 30 * 60


class Clock:
    def __init__(self):
        self.now = dt.datetime(2026, 11, 2, 6, 0, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += dt.timedelta(seconds=seconds)


@dataclass
class RunResult:
    mode: str
    base_s: int
    seed: int
    down_s: int
    calls: int
    failures: int
    blocked: int
    would_block: int
    false_blocks: int
    success: bool
    success_at_s: int | None


def request(seed: int) -> OperationRequest:
    return OperationRequest(
        component="mcp", tool="hunt.query", action="search",
        target=f"http://10.7.194.{seed % 200 + 1}:22196/hunt",
        args={"q": "dns tunnel", "seed": seed},
        scope="global", environment_id="lab-a", run_id="",  # no per-run budget
    )


def policy_for(base_s: int, enforce: bool) -> Policy:
    data = copy.deepcopy(default_policy())
    data["enforce"] = enforce
    rule = data["classes"]["unreachable"]
    rule["base_s"] = base_s
    rule["max_s"] = max(base_s, 1800)
    rule["max_attempts"] = 3
    data["budgets"]["max_attempts_per_call_key_per_run"] = 99
    data["budgets"]["max_failures_per_component_per_run"] = 99
    return Policy(data)


def run_once(mode: str, base_s: int, seed: int, down_s: int) -> RunResult:
    clock = Clock()
    enforce = mode == "enforce"
    runtime = None
    if mode != "baseline":
        root = tempfile.mkdtemp(prefix="rtmem-workload-")
        runtime = RuntimeMemory(root, policy=policy_for(base_s, enforce), clock=clock)
    req = request(seed)
    calls = failures = blocked = would_block = false_blocks = 0
    success_at = None
    t = 0
    iterations = 0
    while t <= HORIZON_S and calls < MAX_CALLS and iterations < 200:
        iterations += 1
        if mode == "baseline":
            decision = None
        else:
            decision = runtime.preflight(req)
            if decision.action == "block":
                if enforce:
                    blocked += 1
                    until = parse_iso(decision.blocked_until)
                    if until is None:
                        t += INTERVAL_S
                    else:
                        wait = int((until - clock.now).total_seconds())
                        t += max(INTERVAL_S, wait)
                        clock.advance(max(INTERVAL_S, wait))
                    continue
                would_block += 1
        ok = clock.now >= (dt.datetime(2026, 11, 2, 6, 0, tzinfo=dt.timezone.utc)
                           + dt.timedelta(seconds=down_s))
        calls += 1
        if ok:
            if decision is not None and decision.action == "block":
                false_blocks += 1
            success_at = t
            if decision is not None:
                runtime.postflight(req, "ok", decision=decision)
            break
        failures += 1
        if decision is not None:
            runtime.postflight(req, "fail",
                               error=ConnectionRefusedError("connect refused"),
                               error_class="unreachable", decision=decision)
        t += INTERVAL_S
        clock.advance(INTERVAL_S)
    return RunResult(mode, base_s, seed, down_s, calls, failures, blocked,
                     would_block, false_blocks, success_at is not None, success_at)


def summarize(results: list[RunResult]) -> dict[str, Any]:
    def mean(key: str):
        values = [getattr(item, key) for item in results]
        return round(statistics.mean(values), 3) if values else None

    def p95(key: str):
        values = sorted(getattr(item, key) for item in results
                        if getattr(item, key) is not None)
        if not values:
            return None
        return values[min(len(values) - 1, int(len(values) * 0.95))]

    successes = [item.success_at_s for item in results if item.success_at_s is not None]
    return {
        "runs": len(results),
        "success_rate": round(len(successes) / len(results), 3),
        "mean_calls": mean("calls"),
        "mean_failures": mean("failures"),
        "mean_blocked": mean("blocked"),
        "mean_would_block": mean("would_block"),
        "mean_false_blocks": mean("false_blocks"),
        "false_block_rate": round(
            sum(item.false_blocks for item in results)
            / max(1, sum(item.would_block for item in results)), 3),
        "mean_time_to_success_s": round(statistics.mean(successes), 1) if successes else None,
        "p95_time_to_success_s": p95("success_at_s"),
        "mean_duplicate_failures": round(
            sum(max(0, item.failures - 1) for item in results) / len(results), 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline Monte-Carlo workload")
    parser.add_argument("--seeds", type=int, default=80)
    parser.add_argument("--run-id", default="workload-2026-11-03")
    parser.add_argument("--out", help="default sim/runs/<run-id>")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    out = Path(args.out) if args.out else ROOT / "sim" / "runs" / args.run_id
    if out.exists() and not args.force:
        parser.error(f"{out} exists; pass --force or a new --run-id")
    out.mkdir(parents=True, exist_ok=True)

    configs: list[tuple[str, int]] = [("baseline", 0)]
    for base in (60, 300, 900, 1800):
        configs.append(("shadow", base))
        configs.append(("enforce", base))

    grouped: dict[str, list[RunResult]] = {}
    for mode, base in configs:
        label = mode if mode == "baseline" else f"{mode}_{base}"
        rows: list[RunResult] = []
        for seed in range(args.seeds):
            down_s = random.Random(seed).randint(0, MAX_DOWN_S)
            rows.append(run_once(mode, base, seed, down_s))
        grouped[label] = rows
        print(f"{label}: {summarize(rows)}")

    metrics = {label: summarize(rows) for label, rows in grouped.items()}
    atomic_write_json(out / "metrics.json",
                      {"schema_version": 1, "configs": metrics,
                       "parameters": {"seeds": args.seeds, "interval_s": INTERVAL_S,
                                      "horizon_s": HORIZON_S, "max_down_s": MAX_DOWN_S}})
    with (out / "runs.jsonl").open("w", encoding="utf-8") as handle:
        for label, rows in grouped.items():
            for row in rows:
                handle.write(json.dumps({"config": label, **asdict(row)},
                                        ensure_ascii=False) + "\n")

    header = ["config", "success_rate", "mean_calls", "mean_failures",
              "mean_blocked", "mean_would_block", "false_block_rate",
              "mean_time_to_success_s", "p95_time_to_success_s",
              "mean_duplicate_failures"]
    lines = [",".join(header)]
    for label in metrics:
        row = metrics[label]
        lines.append(",".join([label] + [str(row.get(key)) for key in header[1:]]))
    (out / "table.csv").write_text("\n".join(lines) + "\n", encoding="utf-8")

    summary = ["# Offline workload: recovery time vs retry window", "",
               f"seeds per config: {args.seeds}; down time uniform 0..{MAX_DOWN_S}s; "
               f"retry interval {INTERVAL_S}s; horizon {HORIZON_S}s.", "",
               "| config | success | calls | failures | blocked | would_block | false_block_rate | mean TTS | p95 TTS |",
               "|---|---|---|---|---|---|---|---|---|"]
    for label, row in metrics.items():
        summary.append(
            f"| {label} | {row['success_rate']} | {row['mean_calls']} | "
            f"{row['mean_failures']} | {row['mean_blocked']} | {row['mean_would_block']} | "
            f"{row['false_block_rate']} | {row['mean_time_to_success_s']} | "
            f"{row['p95_time_to_success_s']} |")
    summary += ["", "Notes:",
                "- baseline has no memory: call every 60s.",
                "- shadow records decisions but always calls.",
                "- enforce skips blocked calls and waits for next_retry_at.",
                "- false_block_rate = false_blocks / would_block in shadow.",
                "- mean_blocked counts block decisions/preflights, not distinct calls; "
                "a long outage can produce repeated blocked preflights.",
                "- per-seed raw rows: runs.jsonl; per-config metrics: metrics.json."]
    (out / "summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

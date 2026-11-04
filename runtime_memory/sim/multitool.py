#!/usr/bin/env python3
"""T4: multi-tool workload and alternative paths.

The experiment has two parts:

1. deterministic cross-tool checks (unrelated tool not blocked, same
   target/scope shares an issue, call-level args are isolated, workaround is
   exposed in ``Decision.alternatives``);
2. a small 3-tool task simulation for baseline / shadow / enforce with an
   obedient (uses alternatives) and a naive (ignores block) agent.

Only the public runtime-memory API is used.  No core code is modified.

Run from ``runtime_memory/``::

    python sim/multitool.py --seeds 30 --run-id exec-<UTC>-multitool
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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory import OperationRequest, Policy, RuntimeMemory  # noqa: E402
from runtime_memory.policy import default_policy  # noqa: E402
from runtime_memory.store import atomic_write_json  # noqa: E402

INTERVAL_S = 60
HORIZON_S = 900
ALTERNATIVE_P = 0.7

# component, tool, action, target, args
TOOLS = [
    ("mcp", "hunt.query", "search", "http://mcp.lab-a/hunt", {"q": "dns"}),
    ("siem", "search", "query", "http://siem.lab-a:9200", {"index": "edr"}),
    ("parser", "pcap.parse", "parse", "/data/pcap",
     {"path": "/data/pcap/case-bad.pcap"}),
    ("parser", "pcap.parse", "parse", "/data/pcap",
     {"path": "/data/pcap/case-good.pcap"}),
    ("file", "read", "read", "/data/notes", {"path": "/data/notes/a.txt"}),
    ("shell", "run", "exec", "host-01", {"cmd": "id"}),
    ("model", "complete", "generate", "http://model.lab-a:11434",
     {"prompt_id": "summarize"}),
    ("web", "fetch", "get", "https://example.test/report", {"url": "report"}),
    ("dns", "resolve", "lookup", "8.8.8.8", {"name": "example.test"}),
    ("archive", "zip", "pack", "/data/out", {"path": "/data/out/a.zip"}),
]
TASK_TOOL_INDEXES = (0, 1, 2)


def make_request(tool_index: int, *, scope: str = "global",
                 environment: str = "lab-a", run_id: str = "") -> OperationRequest:
    component, tool, action, target, args = TOOLS[tool_index]
    return OperationRequest(component=component, tool=tool, action=action,
                            target=target, args=dict(args), scope=scope,
                            environment_id=environment, run_id=run_id)


class Clock:
    def __init__(self):
        self.now = dt.datetime(2026, 11, 2, 6, 0, tzinfo=dt.timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += dt.timedelta(seconds=seconds)


@dataclass
class Run:
    config: str
    seed: int
    task_success: bool
    calls: int
    failures: int
    blocked: int
    would_block: int
    false_blocks: int
    tts_s: int | None
    tool_successes: dict[str, bool] = field(default_factory=dict)


def policy_for(enforce: bool) -> Policy:
    data = copy.deepcopy(default_policy())
    data["enforce"] = enforce
    data["budgets"]["max_attempts_per_call_key_per_run"] = 99
    data["budgets"]["max_failures_per_component_per_run"] = 99
    return Policy(data)


def cross_tool_checks() -> dict[str, Any]:
    folder = tempfile.mkdtemp(prefix="rtmem-multitool-checks-")
    runtime = RuntimeMemory(folder, policy=policy_for(enforce=False), clock=Clock())
    # Fail mcp (scope), siem (scope) and parser bad path (call level).
    runtime.postflight(make_request(0), "fail",
                       error=ConnectionRefusedError("connect refused"))
    runtime.postflight(make_request(1), "fail", error_class="rate_limit")
    runtime.postflight(make_request(2), "fail", error_class="schema")
    mcp_issue = next(item for item in runtime.store.list_issues()
                     if item.get("tool") == "hunt.query")
    runtime.set_workaround(mcp_issue["issue_id"], "use cached hunt results")
    checks = {
        "unrelated_tool_allowed": runtime.preflight(make_request(4)).action == "allow",
        "same_scope_blocked": runtime.preflight(OperationRequest(
            component="mcp", tool="hunt.query", action="search",
            target="http://mcp.lab-a/hunt", args={"q": "other"},
            scope="global", environment_id="lab-a")).action == "block",
        "call_level_args_isolated": runtime.preflight(make_request(3)).action == "allow",
        "workaround_in_alternatives": (
            "use cached hunt results"
            in runtime.preflight(make_request(0), record=False).alternatives),
        "same_component_other_tool_allowed": runtime.preflight(
            make_request(5)).action == "allow",
    }
    shutil.rmtree(folder, ignore_errors=True)
    return {"checks": checks, "all_pass": all(checks.values())}


def run_once(config: str, seed: int, down_mcp: int, down_siem: int,
             parser_good: bool) -> Run:
    baseline = config == "baseline"
    enforce = config.startswith("enforce")
    obedient = config in ("enforce_obedient", "shadow")
    runtime = None
    folder = None
    if not baseline:
        folder = tempfile.mkdtemp(prefix="rtmem-multitool-")
        runtime = RuntimeMemory(folder, policy=policy_for(enforce), clock=Clock())
    rng = random.Random(seed * 1009 + 17)
    calls = failures = blocked = would_block = false_blocks = 0
    tts = None
    task_success = False
    tool_successes: dict[str, bool] = {}

    for t in range(0, HORIZON_S + 1, INTERVAL_S):
        round_ok = True
        for index in TASK_TOOL_INDEXES:
            scope = "global" if index in (0, 1) else "session"
            request = make_request(index, scope=scope, run_id=f"seed-{seed}")
            decision = None
            if not baseline:
                decision = runtime.preflight(request)
            if decision is not None and decision.action == "block":
                blocked += 1
                if not enforce:
                    would_block += 1
                    # shadow still calls the original tool
                    pass
                elif obedient:
                    # treat the alternative as a different call; it does not
                    # update the original issue
                    alt_ok = rng.random() < ALTERNATIVE_P
                    tool_successes[f"{index}:alt"] = alt_ok
                    round_ok = round_ok and alt_ok
                    continue
                else:
                    # enforce + naive: the gateway skips the call; no
                    # alternative is used, so the task loses this tool
                    tool_successes[f"{index}:skipped"] = False
                    round_ok = False
                    continue

            calls += 1
            if index == 0:
                ok = t >= down_mcp
            elif index == 1:
                ok = t >= down_siem
            else:
                ok = parser_good
            tool_successes[str(index)] = ok
            if not baseline:
                runtime.postflight(request, "ok" if ok else "fail",
                                   error=None if ok else
                                   ConnectionRefusedError("tool failed"),
                                   decision=decision)
            if ok:
                if decision is not None and decision.action == "block":
                    false_blocks += 1
            else:
                failures += 1
                round_ok = False
        if round_ok:
            task_success = True
            tts = t
            break
        if runtime is not None:
            runtime.clock.advance(INTERVAL_S)

    if folder:
        shutil.rmtree(folder, ignore_errors=True)
    return Run(config, seed, task_success, calls, failures, blocked,
               would_block, false_blocks, tts, tool_successes)


def summarize(rows: list[Run]) -> dict[str, Any]:
    def mean(values):
        return round(statistics.mean(values), 3) if values else None

    successes = [row.tts_s for row in rows if row.tts_s is not None]
    return {
        "runs": len(rows),
        "task_success_rate": round(
            sum(row.task_success for row in rows) / len(rows), 3) if rows else None,
        "mean_calls": mean([row.calls for row in rows]),
        "mean_failures": mean([row.failures for row in rows]),
        "mean_blocked": mean([row.blocked for row in rows]),
        "mean_would_block": mean([row.would_block for row in rows]),
        "mean_false_blocks": mean([row.false_blocks for row in rows]),
        "mean_tts_s": mean(successes),
        "mean_duplicate_failures": round(
            sum(max(0, row.failures - 1) for row in rows) / len(rows), 3)
        if rows else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="T4 multi-tool workload")
    parser.add_argument("--seeds", type=int, default=30)
    parser.add_argument("--run-id", default="multitool-2026-11-03")
    parser.add_argument("--out", help="default sim/runs/<run-id>")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()
    out = Path(args.out) if args.out else ROOT / "sim" / "runs" / args.run_id
    if out.exists() and not args.force:
        parser.error(f"{out} exists; pass --force or a new --run-id")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    checks = cross_tool_checks()
    configs = ("baseline", "shadow", "enforce_obedient", "enforce_naive")
    grouped: dict[str, list[Run]] = {}
    for config in configs:
        rows = []
        for seed in range(args.seeds):
            rng = random.Random(seed)
            down_mcp = rng.randint(0, 1800)
            down_siem = rng.randint(0, 900)
            parser_good = seed % 2 == 0
            rows.append(run_once(config, seed, down_mcp, down_siem, parser_good))
        grouped[config] = rows
        print(f"{config}: {summarize(rows)}")

    metrics = {config: summarize(rows) for config, rows in grouped.items()}
    metrics["cross_tool_checks"] = checks
    metrics["comparisons"] = {
        "obedient_not_below_baseline": (
            metrics["enforce_obedient"]["task_success_rate"]
            >= metrics["baseline"]["task_success_rate"]),
        "naive_worse_than_obedient": (
            metrics["enforce_naive"]["task_success_rate"]
            < metrics["enforce_obedient"]["task_success_rate"]),
    }
    atomic_write_json(out / "metrics.json", {
        "schema_version": 1,
        "parameters": {"seeds": args.seeds, "interval_s": INTERVAL_S,
                       "horizon_s": HORIZON_S, "alternative_p": ALTERNATIVE_P},
        "configs": metrics,
    })
    with (out / "runs.jsonl").open("w", encoding="utf-8") as handle:
        for config, rows in grouped.items():
            for row in rows:
                handle.write(json.dumps({"config": config, **row.__dict__},
                                        ensure_ascii=False) + "\n")

    lines = [
        "# T4 multi-tool / alternative workload",
        "",
        f"seeds per config: {args.seeds}; 3 needed tools; alternatives succeed "
        f"with p={ALTERNATIVE_P}.",
        "",
        "| config | task success | calls | failures | blocked | "
        "mean false blocks | mean TTS |",
        "|---|---|---|---|---|---|---|",
    ]
    for config, summary in metrics.items():
        if not isinstance(summary, dict) or "task_success_rate" not in summary:
            continue
        lines.append(
            f"| {config} | {summary['task_success_rate']} | "
            f"{summary['mean_calls']} | {summary['mean_failures']} | "
            f"{summary['mean_blocked']} | {summary['mean_false_blocks']} | "
            f"{summary['mean_tts_s']} |")
    lines += ["", "## Cross-tool checks", "",
              "```json",
              json.dumps(checks, ensure_ascii=False, indent=2),
              "```",
              "", "## Comparisons", "",
              "```json",
              json.dumps(metrics["comparisons"], ensure_ascii=False, indent=2),
              "```"]
    (out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

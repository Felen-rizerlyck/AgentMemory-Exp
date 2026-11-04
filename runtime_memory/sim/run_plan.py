#!/usr/bin/env python3
"""Execute the runtime-memory offline test plan (T0-T8) and write the report.

This is the runner for ``docs/RUNTIME_MEMORY_TEST_PLAN.md``.  It runs the
existing baseline commands plus the T3-T8 experiment scripts, captures raw
stdout/stderr, and writes:

    sim/runs/exec-<UTC>/EXECUTOR_REPORT.md
    sim/runs/exec-<UTC>/results.json
    sim/runs/exec-<UTC>/raw/*.stdout.txt / *.stderr.txt

It never modifies the runtime-memory source, tests or data.  T9 is covered by
T4's scripted obedient/naive agents; T10 is optional and reported as NOT_RUN.

Run from ``runtime_memory/``::

    python sim/run_plan.py
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def run_command(name: str, command: list[str], raw_dir: Path,
                timeout: int = 600) -> dict[str, Any]:
    raw_dir.mkdir(parents=True, exist_ok=True)
    started = time.perf_counter()
    status = "PASS"
    stdout = stderr = ""
    exit_code: int | None = None
    try:
        completed = subprocess.run(
            command, cwd=str(ROOT), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout)
        exit_code = completed.returncode
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        if exit_code != 0:
            status = "FAIL"
    except subprocess.TimeoutExpired as exc:
        status = "TIMEOUT"
        stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
    except OSError as exc:
        status = "ERROR"
        stderr = str(exc)
    duration = round(time.perf_counter() - started, 2)
    (raw_dir / f"{name}.stdout.txt").write_text(stdout, encoding="utf-8")
    (raw_dir / f"{name}.stderr.txt").write_text(stderr, encoding="utf-8")
    tail = (stdout or stderr).strip().splitlines()[-5:]
    return {
        "id": name,
        "command": " ".join(command),
        "exit_code": exit_code,
        "duration_s": duration,
        "status": status,
        "notes": " | ".join(tail),
        "stdout_tail": tail,
        "stderr_tail": stderr.strip().splitlines()[-5:],
    }


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Run T0-T8 of the offline test plan")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    parser.add_argument("--run-id", default=f"exec-{stamp}")
    parser.add_argument("--out", help="default sim/runs/<run-id>")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--t3-seeds", type=int, default=10,
                        help="T3 seeds per cell (plan default 30; 10 keeps "
                             "the run inside the 10-minute T3 budget)")
    parser.add_argument("--skip-100k", action="store_true")
    args = parser.parse_args()
    out = Path(args.out) if args.out else ROOT / "sim" / "runs" / args.run_id
    if out.exists() and not args.force:
        parser.error(f"{out} exists; pass --force or a new --run-id")
    if out.exists():
        import shutil
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    raw = out / "raw"

    started_at = now_iso()
    git_status = subprocess.run(["git", "status", "--short"], cwd=str(ROOT.parent),
                                capture_output=True, text=True).stdout.strip()
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                            cwd=str(ROOT.parent), capture_output=True,
                            text=True).stdout.strip()
    tests: list[dict[str, Any]] = []

    # T0 baseline ---------------------------------------------------------
    tests.append(run_command(
        "T0.1", [PY, "-m", "unittest", "discover", "-s", "tests"], raw))
    tests.append(run_command(
        "T0.2", [PY, "scripts/verify_runtime_memory.py"], raw))
    tests.append(run_command(
        "T0.3", [PY, "src/manage_runtime_memory.py", "check"], raw))
    issues_json = load_json(ROOT / "data" / "issues.json")

    # T1 edge tests -------------------------------------------------------
    tests.append(run_command(
        "T1.1", [PY, "-m", "unittest", "discover", "-s", "tests",
                 "-p", "test_edge_cases.py", "-v"], raw))
    tests.append(run_command(
        "T1.2", [PY, "-m", "unittest", "discover", "-s", "tests",
                 "-p", "test_store_edge.py", "-v"], raw))
    tests.append(run_command(
        "T1.3", [PY, "sim/deep_test.py", "--out", str(out / "deep"),
                 "--force"], raw))

    # T2 workload ---------------------------------------------------------
    tests.append(run_command(
        "T2", [PY, "sim/workload.py", "--seeds", "30",
               "--run-id", f"{args.run_id}-workload",
               "--out", str(out / "workload")], raw))

    # T3 policy grid ------------------------------------------------------
    tests.append(run_command(
        "T3", [PY, "sim/policy_grid.py", "--seeds", str(args.t3_seeds),
               "--run-id", f"{args.run_id}-policy-grid",
               "--out", str(out / "policy-grid")], raw))

    # T4 multitool --------------------------------------------------------
    tests.append(run_command(
        "T4", [PY, "sim/multitool.py", "--seeds", "30",
               "--run-id", f"{args.run_id}-multitool",
               "--out", str(out / "multitool")], raw))

    # T5 scale ------------------------------------------------------------
    tests.append(run_command(
        "T5a", [PY, "sim/scale.py", "--sizes", "1000,5000,20000",
                "--run-id", f"{args.run_id}-scale",
                "--out", str(out / "scale")], raw))
    tests.append(run_command(
        "T5b", [PY, "sim/scale_multi.py", "--issues", "100",
                "--events", "5000", "--run-id", f"{args.run_id}-scale-multi",
                "--out", str(out / "scale-multi")], raw))
    if not args.skip_100k:
        tests.append(run_command(
            "T5c", [PY, "sim/scale.py", "--sizes", "100000",
                    "--run-id", f"{args.run_id}-scale-100k",
                    "--out", str(out / "scale-100k")], raw))

    # T6 concurrency ------------------------------------------------------
    tests.append(run_command(
        "T6", [PY, "sim/concurrency.py",
               "--run-id", f"{args.run_id}-concurrency",
               "--out", str(out / "concurrency")], raw))

    # T7 retention --------------------------------------------------------
    tests.append(run_command(
        "T7", [PY, "sim/retention.py", "--days", "90",
               "--run-id", f"{args.run_id}-retention",
               "--out", str(out / "retention")], raw))

    # T8 redaction fuzz ---------------------------------------------------
    tests.append(run_command(
        "T8", [PY, "sim/redaction_fuzz.py", "--messages", "1000",
               "--run-id", f"{args.run_id}-redaction",
               "--out", str(out / "redaction")], raw))

    finished_at = now_iso()
    metrics = {
        "workload": load_json(out / "workload" / "metrics.json"),
        "policy_grid": load_json(out / "policy-grid" / "metrics.json"),
        "multitool": load_json(out / "multitool" / "metrics.json"),
        "scale": load_json(out / "scale" / "metrics.json"),
        "scale_multi": load_json(out / "scale-multi" / "metrics.json"),
        "scale_100k": load_json(out / "scale-100k" / "metrics.json"),
        "concurrency": load_json(out / "concurrency" / "metrics.json"),
        "retention": load_json(out / "retention" / "metrics.json"),
        "redaction": load_json(out / "redaction" / "metrics.json"),
        "deep": load_json(out / "deep" / "report.json"),
    }

    def set_test_status(test_id: str, status: str, note: str) -> None:
        for test in tests:
            if test["id"] == test_id:
                test["status"] = status
                test["notes"] = (note + " | " + test["notes"]).strip(" |")
                return

    # The command exits 0 even when an experiment detects a failure; promote
    # the internal verdict for T6/T8 so the summary table is not misleading.
    concurrency_checks = (metrics.get("concurrency") or {}).get("checks", [])
    if any(item.get("status") == "FAIL" for item in concurrency_checks):
        set_test_status("T6", "FAIL", "concurrency checks failed")
    elif any(item.get("status") == "GAP" for item in concurrency_checks):
        set_test_status("T6", "PARTIAL", "concurrency gap detected")
    redaction = metrics.get("redaction") or {}
    if redaction.get("json_pattern_leaks") or redaction.get("target_userinfo_leaks"):
        set_test_status(
            "T8", "FAIL",
            f"plan-pattern leaks={redaction.get('plan_pattern_leaks')}; "
            f"json leaks={redaction.get('json_pattern_leaks')}; "
            f"target leaks={redaction.get('target_userinfo_leaks')}")

    anomalies = build_anomalies(metrics)
    results = {
        "schema_version": 1,
        "run_id": args.run_id,
        "commit": commit,
        "python": platform.python_version(),
        "started_at": started_at,
        "finished_at": finished_at,
        "git_status": git_status,
        "issues_json": issues_json,
        "tests": tests,
        "metrics": metrics,
        "anomalies": anomalies,
        "not_run": [
            {"id": "T9", "reason": "optional; T4 already runs scripted "
                                  "obedient and naive agents"},
            {"id": "T10", "reason": "optional ablation; not run in this pass"},
        ],
    }
    (out / "results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    report = build_report(results, out)
    (out / "EXECUTOR_REPORT.md").write_text(report, encoding="utf-8")
    print(f"run_id={args.run_id} out={out}")
    for test in tests:
        print(f"{test['id']:5} {test['status']:7} {test['duration_s']:6.2f}s")
    print(f"anomalies={len(anomalies)}")
    return 0


def build_anomalies(metrics: dict[str, Any]) -> list[dict[str, Any]]:
    anomalies: list[dict[str, Any]] = []
    redaction = metrics.get("redaction") or {}
    if redaction.get("json_pattern_leaks"):
        anomalies.append({
            "severity": "P0", "test": "T8",
            "file": "runtime_memory/src/runtime_memory/redact.py",
            "description": "JSON-formatted secrets are not redacted",
            "evidence": f"json_pattern_leaks={redaction['json_pattern_leaks']}; "
                        f"storage_message_leaks="
                        f"{redaction.get('storage_message_leaks')}",
        })
    if redaction.get("target_userinfo_leaks"):
        anomalies.append({
            "severity": "P0", "test": "T8",
            "file": "runtime_memory/src/runtime_memory/runtime.py",
            "description": "URL userinfo credentials are persisted in "
                           "issue.target / report",
            "evidence": f"target_userinfo_leaks="
                        f"{redaction['target_userinfo_leaks']}",
        })
    concurrency = metrics.get("concurrency") or {}
    for item in concurrency.get("checks", []):
        if item.get("status") == "FAIL":
            anomalies.append({
                "severity": "P0", "test": "T6",
                "file": "runtime_memory/src/runtime_memory/store.py",
                "description": f"{item.get('test')} failed under concurrency",
                "evidence": json.dumps(
                    {key: value for key, value in item.items()
                     if key not in ("test", "status")}, ensure_ascii=False)[:500],
            })
        elif item.get("status") == "GAP":
            anomalies.append({
                "severity": "P2", "test": "T6",
                "file": "runtime_memory/src/runtime_memory/store.py",
                "description": f"{item.get('test')} is not detected by check()",
                "evidence": json.dumps(
                    {key: value for key, value in item.items()
                     if key not in ("test", "status")}, ensure_ascii=False)[:500],
            })
    deep = metrics.get("deep") or {}
    for check in deep.get("checks", []):
        if check.get("status") not in ("FINDING", "CRASH"):
            continue
        severity = "P0" if check.get("severity") == "high" else \
            "P1" if check.get("severity") == "medium" else "P2"
        anomalies.append({
            "severity": severity, "test": "T1.3",
            "file": "runtime_memory/src/runtime_memory/runtime.py",
            "description": f"{check.get('id')}: {check.get('title')}",
            "evidence": str(check.get("observed"))[:500],
        })
    return anomalies


def build_report(results: dict[str, Any], out: Path) -> str:
    metrics = results["metrics"]
    lines = [
        f"# Executor report — {results['run_id']}",
        "",
        "## Environment",
        "",
        f"- python: {results['python']}",
        f"- commit: {results['commit']}",
        f"- git status: {results['git_status'] or 'clean'}",
        f"- started: {results['started_at']}",
        f"- finished: {results['finished_at']}",
        f"- data/issues.json: `{json.dumps(results['issues_json'], ensure_ascii=False)}`",
        "",
        "## Baseline",
        "",
        "| check | command | exit | status | seconds |",
        "|---|---|---|---|---|",
    ]
    for test in results["tests"][:3]:
        lines.append(f"| {test['id']} | `{test['command']}` | "
                     f"{test['exit_code']} | **{test['status']}** | "
                     f"{test['duration_s']} |")
    lines += ["", "## Results", "",
              "| ID | purpose | command | exit | status | seconds | notes |",
              "|---|---|---|---|---|---|---|"]
    purposes = {
        "T0.1": "baseline unit tests", "T0.2": "verification matrix",
        "T0.3": "store check", "T1.1": "edge cases",
        "T1.2": "store edge cases", "T1.3": "59-check deep matrix",
        "T2": "Monte-Carlo workload", "T3": "policy grid",
        "T4": "multi-tool / alternatives", "T5a": "scale 1k/5k/20k",
        "T5b": "multi-issue scale", "T5c": "scale 100k",
        "T6": "concurrency / crash", "T7": "retention / gc",
        "T8": "redaction fuzz",
    }
    for test in results["tests"]:
        lines.append(f"| {test['id']} | {purposes.get(test['id'], '')} | "
                     f"`{test['command']}` | {test['exit_code']} | "
                     f"**{test['status']}** | {test['duration_s']} | "
                     f"{test['notes'].replace('|', '/')} |")

    lines += ["", "## Metrics", ""]
    workload = metrics.get("workload") or {}
    if workload.get("configs"):
        lines += ["### T2 workload", "",
                  "| config | success | calls | failures | blocked | "
                  "false_rate | mean TTS |", "|---|---|---|---|---|---|---|"]
        for label, row in workload["configs"].items():
            lines.append(f"| {label} | {row.get('success_rate')} | "
                         f"{row.get('mean_calls')} | {row.get('mean_failures')} | "
                         f"{row.get('mean_blocked')} | "
                         f"{row.get('false_block_rate')} | "
                         f"{row.get('mean_time_to_success_s')} |")
    grid = metrics.get("policy_grid") or {}
    if grid.get("configs"):
        lines += ["", "### T3 policy grid (summary)", "",
                  f"{len(grid['configs'])} cells; raw `grid.csv` in "
                  f"`{out / 'policy-grid'}`.", ""]
        def success(item: tuple[str, dict[str, Any]]) -> float:
            value = item[1].get("success_rate")
            return value if value is not None else -1.0

        best = max(grid["configs"].items(), key=success)
        worst = min(grid["configs"].items(), key=success)
        lines += [f"- best: `{best[0]}` success={best[1].get('success_rate')}",
                  f"- worst: `{worst[0]}` success={worst[1].get('success_rate')}"]
    for key, title in (("multitool", "T4 multi-tool"),
                       ("scale", "T5 scale"),
                       ("scale_multi", "T5 multi-issue"),
                       ("concurrency", "T6 concurrency"),
                       ("retention", "T7 retention"),
                       ("redaction", "T8 redaction")):
        data = metrics.get(key)
        if not data:
            continue
        lines += ["", f"### {title}", "", "```json",
                  json.dumps(data, ensure_ascii=False, indent=2)[:6000],
                  "```"]
    lines += ["", "## Anomalies", "",
              "| severity | test | file | description | evidence |",
              "|---|---|---|---|---|"]
    for anomaly in results["anomalies"]:
        lines.append(f"| {anomaly['severity']} | {anomaly['test']} | "
                     f"{anomaly['file']} | {anomaly['description']} | "
                     f"`{anomaly['evidence'][:300]}` |")
    lines += ["", "## Not run", "",
              "| ID | reason |", "|---|---|"]
    for item in results["not_run"]:
        lines.append(f"| {item['id']} | {item['reason']} |")
    lines += ["", "## Verdict", "",
              "- T0/T1 baseline and edge tests: see table.",
              "- T2-T8: see per-test status and metrics above.",
              "- Any FAIL/TIMEOUT is a finding, not something this runner fixes.",
              "- T9 is covered by T4's scripted obedient/naive agents; T10 is "
              "optional and not run.",
              "- No core source, tests or data were modified by the runner."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())

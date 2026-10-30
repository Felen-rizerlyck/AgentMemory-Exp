#!/usr/bin/env python3
"""One-click verification matrix for the attack-memory demo.

A reviewer should be able to trust a change after running exactly this command
from ``demo/``::

    python scripts/verify_demo.py

The matrix runs, in order:

* ``compileall`` over ``src/``, ``tests/`` and ``scripts/``;
* the full ``unittest discover -s tests`` suite (test count may not regress
  below the recorded baseline).  By default the suite runs in a throwaway copy
  of ``demo/`` so an un-migrated test cannot pollute the real store; the copy's
  data store is hashed before/after and any test write is reported as a suite
  isolation failure.  Use ``--real-unittest`` for final acceptance on the real
  tree (the outer data guard then proves the real store was untouched);
* ``catalog validate`` and ``audit`` (the two store trust gates);
* ``catalog state --check README.md`` (documentation drift gate);
* ``run_demo`` and ``lookup_case_logs`` samples, text and ``--json``;
* ``audit --json``, ``catalog state``, ``catalog repair --dry-run`` and
  ``catalog corrections`` as read-only probes of the new command surface;
* a journal/leftover-temp-file invariant check over ``demo/data``.

Every check reports PASS/FAIL with its wall time.  The matrix itself is
read-only: it hashes every file under ``demo/data`` before the run and after
each check, and fails the check that mutated the store (this is how an
un-isolated test that writes real data gets caught).  The exit code is 0 only
when every selected required check passes.

Usage::

    python scripts/verify_demo.py                 # full matrix (baseline + new)
    python scripts/verify_demo.py --group baseline  # legacy gates only
    python scripts/verify_demo.py --group new       # new-semantics gates only
    python scripts/verify_demo.py --json          # machine-readable report
    python scripts/verify_demo.py --no-data-guard # skip the data mutation guard
    python scripts/verify_demo.py --verbose       # full output of failing checks
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timezone

DEMO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DATA_DIR = DEMO_ROOT / "data"
PYTHON = sys.executable
BASELINE_TEST_COUNT = 100
GROUPS = ("all", "baseline", "new")
UNITTEST_MODE = "sandbox"  # "sandbox" (copy of demo/) or "real" (final acceptance)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _short(text: str, limit: int = 40) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _tail(text: str, lines: int = 25) -> str:
    rows = [row for row in text.splitlines() if row.strip()]
    return "\n".join(rows[-lines:]) if rows else "(no output)"


def _python_version() -> str:
    return f"Python {sys.version.split()[0]}"


def _run_cmd(argv: list[str], timeout: float,
             cwd: pathlib.Path | None = None) -> tuple[subprocess.CompletedProcess, float, str]:
    """Run one subprocess (default: from demo/), decode as UTF-8, and time it."""
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("PYTHONUTF8", "1")
    started = time.perf_counter()
    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd or DEMO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        raise
    except FileNotFoundError as error:
        raise RuntimeError(f"cannot start {argv[0]!r}: {error}") from error
    duration = time.perf_counter() - started
    output = proc.stdout + ("\n" + proc.stderr if proc.stderr else "")
    return proc, duration, output


def _json_from(proc: subprocess.CompletedProcess, output: str) -> tuple[dict | None, list[str]]:
    """Parse JSON from a CLI probe and return (data, problems)."""
    if proc.returncode != 0:
        return None, [f"exit code {proc.returncode}", _tail(output, 12)]
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as error:
        return None, [f"stdout is not valid JSON ({error})", _tail(output, 12)]
    if not isinstance(data, dict):
        return None, [f"top-level JSON is {type(data).__name__}, expected object"]
    return data, []


# ---------------------------------------------------------------------------
# demo/data mutation guard
# ---------------------------------------------------------------------------

def hash_data_store(root: pathlib.Path | None = None) -> dict[str, str]:
    """Content hash of every file in a data store (paths relative, posix style)."""
    root = pathlib.Path(root) if root is not None else DATA_DIR
    if not root.exists():
        return {}
    snapshot: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        snapshot[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
    return snapshot


def diff_snapshots(before: dict[str, str], after: dict[str, str]) -> list[str]:
    changed = []
    for path in sorted(set(before) | set(after)):
        if before.get(path) != after.get(path):
            changed.append(path)
    return changed


def check_journal() -> tuple[bool, str]:
    """No fs write may leave an unfinished transaction or a machine-local path behind."""
    journal = DATA_DIR / "ops_journal.jsonl"
    if not journal.exists():
        return True, "no ops_journal.jsonl (no transactional writes recorded yet)"
    pending: dict[str, dict] = {}
    done: set[str] = set()
    records = 0
    problems: list[str] = []
    try:
        lines = journal.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        return False, f"cannot read {journal.name}: {error}"

    def check_path(raw: str, number: int) -> None:
        # The retained journal is provenance: file names must be repo-relative. An
        # absolute temp path would leak the machine and cannot be replayed elsewhere.
        if not raw:
            problems.append(f"line {number}: journal file entry has no path")
        elif pathlib.Path(raw).is_absolute() or "/tmp/" in raw or "\\Temp\\" in raw:
            problems.append(f"line {number}: journal contains a machine-local path {raw!r}")

    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        records += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            problems.append(f"line {number}: invalid JSON ({error})")
            continue
        status = record.get("status")
        txn_id = record.get("txn_id")
        if status == "done":
            done.add(txn_id)
        elif status == "pending":
            pending[txn_id] = record
        elif status != "failed":
            problems.append(f"line {number}: unknown status {status!r}")
        for item in record.get("files") or []:
            if isinstance(item, dict):
                check_path(str(item.get("path") or ""), number)
            else:
                check_path(str(item), number)
    orphaned = [txn for txn in pending if txn not in done]
    for txn_id in orphaned:
        record = pending[txn_id]
        problems.append(
            f"unfinished transaction {txn_id} ({record.get('kind')}: {record.get('summary')})"
        )
    if problems:
        return False, "; ".join(problems)
    return True, (f"{records} journal record(s), no unfinished transaction, "
                  f"all file paths repo-relative ({len(done)} committed)")


def check_no_temp_files() -> tuple[bool, str]:
    """No partially written temp file may be left in the data store."""
    leftovers = [
        path.relative_to(DEMO_ROOT).as_posix()
        for path in DATA_DIR.rglob("*")
        if path.is_file() and (path.name.endswith(".tmp") or path.name.startswith(".tmp"))
    ]
    if leftovers:
        return False, "leftover temp file(s): " + ", ".join(leftovers[:10])
    return True, "no leftover *.tmp files under data/"


# ---------------------------------------------------------------------------
# Check definitions
# ---------------------------------------------------------------------------

@dataclass
class Check:
    name: str
    group: str  # "baseline" or "new"
    run: object  # Callable[[float], tuple[bool, str]]
    required: bool = True
    command: str = ""


@dataclass
class Result:
    name: str
    group: str
    status: str
    duration_s: float
    detail: str
    command: str


def _cli_check(name: str, group: str, argv: list[str], *, contains: tuple[str, ...] = (),
               not_contains: tuple[str, ...] = (), required: bool = True) -> Check:
    display = ["python" if item == PYTHON else item for item in argv]
    command = " ".join(display)

    def run(timeout: float) -> tuple[bool, str]:
        proc, _duration, output = _run_cmd(argv, timeout)
        problems: list[str] = []
        if proc.returncode != 0:
            problems.append(f"exit code {proc.returncode}")
        for token in contains:
            if token not in output:
                problems.append(f"missing expected output {token!r}")
        for token in not_contains:
            if token in output:
                problems.append(f"unexpected output {token!r}")
        if "Traceback (most recent call last)" in output:
            problems.append("python traceback in output")
        if problems:
            return False, "; ".join(problems) + "\n" + _tail(output)
        return True, _short(" ".join(output.split()), 110)

    return Check(name=name, group=group, run=run, required=required, command=command)


def _check_compileall(timeout: float) -> tuple[bool, str]:
    argv = [PYTHON, "-m", "compileall", "-q", "src", "tests", "scripts"]
    proc, _duration, output = _run_cmd(argv, timeout)
    if proc.returncode != 0:
        return False, f"compileall exit code {proc.returncode}\n{_tail(output)}"
    return True, "src/, tests/ and scripts/ compile"


def _check_unittest(timeout: float) -> tuple[bool, str]:
    """Run the suite; in sandbox mode on a throwaway copy and verify test isolation."""
    mode = UNITTEST_MODE
    if mode == "sandbox":
        with tempfile.TemporaryDirectory(prefix="verify-demo-suite-") as folder:
            sandbox = pathlib.Path(folder) / "demo"
            shutil.copytree(
                DEMO_ROOT,
                sandbox,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.tmp"),
            )
            before = hash_data_store(sandbox / "data")
            proc, _duration, output = _run_cmd(
                [PYTHON, "-m", "unittest", "discover", "-s", "tests"], timeout, cwd=sandbox)
            after = hash_data_store(sandbox / "data")
            polluted = [f"data/{path}" for path in diff_snapshots(before, after)]
        return _unittest_verdict(proc, output, polluted, mode)
    proc, _duration, output = _run_cmd(
        [PYTHON, "-m", "unittest", "discover", "-s", "tests"], timeout)
    return _unittest_verdict(proc, output, [], mode)


def _unittest_verdict(proc: subprocess.CompletedProcess, output: str,
                      polluted: list[str], mode: str) -> tuple[bool, str]:
    match = re.search(r"Ran (\d+) tests? in ([0-9.]+)s", output)
    suffix = " [sandbox copy]" if mode == "sandbox" else " [real tree]"
    problems: list[str] = []
    if polluted:
        # Put the isolation failure first: it is the root cause a reviewer must see.
        problems.append("suite is NOT hermetic: it wrote its own data store: "
                        + ", ".join(polluted[:10]))
    if proc.returncode != 0 or "FAILED (" in output or not re.search(r"^OK", output, re.MULTILINE):
        detail = f"unittest exit code {proc.returncode}"
        if match:
            detail += f", ran {match.group(1)} tests in {match.group(2)}s"
        problems.append(detail)
    if match is None:
        problems.append("could not parse 'Ran N tests' from unittest output")
        count, reported = 0, "?"
    else:
        count, reported = int(match.group(1)), match.group(2)
        if count < BASELINE_TEST_COUNT:
            problems.append(f"test count regressed: {count} < baseline {BASELINE_TEST_COUNT}; "
                            "do not delete tests to make the suite green")
    if problems:
        return False, "; ".join(problems) + "\n" + _tail(output)
    skipped = re.search(r"OK \(skipped=(\d+)\)", output)
    skip_note = f", {skipped.group(1)} skipped" if skipped else ""
    hermetic = "hermetic" if mode == "sandbox" else "real tree unchanged"
    return True, (f"{count} test(s) OK in {reported}s{skip_note} (baseline {BASELINE_TEST_COUNT}); "
                  f"{hermetic}{suffix}")


def _check_run_demo_json(timeout: float) -> tuple[bool, str]:
    argv = [PYTHON, "src/run_demo.py", "--input", "data/raw_logs.csv",
            "--min-tier", "medium", "--top", "2", "--json"]
    proc, _duration, output = _run_cmd(argv, timeout)
    data, problems = _json_from(proc, output)
    if data is None:
        return False, "; ".join(problems)
    if data.get("schema_version") != 1:
        problems.append(f"schema_version is {data.get('schema_version')!r}, expected integer 1")
    for key in ("input", "log_count", "min_tier", "scopes"):
        if key not in data:
            problems.append(f"missing top-level field {key!r}")
    scopes = data.get("scopes")
    if not isinstance(scopes, list) or not scopes:
        problems.append("scopes must be a non-empty list")
        scopes = []
    scope_required = ("scope_type", "scope_id", "log_count", "hosts", "reviewed_links",
                      "hidden_below_min_tier", "family_matches", "candidates")
    candidate_required = ("case_id", "tier", "matched_steps", "required_steps", "total_steps",
                          "evidence", "family_id", "version", "weak_kind", "shape",
                          "order_ok", "order_assessable", "source_fit_ratio", "keyword_score",
                          "mitre", "unobserved_required_steps")
    candidates_seen = 0
    for scope in scopes:
        if not isinstance(scope, dict):
            problems.append("scope is not an object")
            continue
        for key in scope_required:
            if key not in scope:
                problems.append(f"scope {scope.get('scope_id')!r}: missing {key!r}")
        for candidate in scope.get("candidates") or []:
            candidates_seen += 1
            for key in candidate_required:
                if key not in candidate:
                    problems.append(f"candidate {candidate.get('case_id')!r}: missing {key!r}")
            if not isinstance(candidate.get("evidence"), list):
                problems.append(f"candidate {candidate.get('case_id')!r}: evidence must be a list")
            confidence = candidate.get("evidence_confidence")
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
                problems.append(f"candidate {candidate.get('case_id')!r}: missing numeric "
                                "evidence_confidence")
            elif not 0.0 <= float(confidence) <= 1.0:
                problems.append(f"candidate {candidate.get('case_id')!r}: evidence_confidence "
                                f"{confidence!r} is outside [0, 1]")
            prior = candidate.get("prior_rejections")
            if not isinstance(prior, list):
                problems.append(f"candidate {candidate.get('case_id')!r}: missing prior_rejections list")
    if candidates_seen == 0:
        problems.append("no candidate found at --min-tier medium; retrieval contract untested")
    if problems:
        return False, "; ".join(problems[:12]) + "\n" + _tail(output, 12)
    return True, (f"schema_version=1, {len(scopes)} scope(s), {candidates_seen} candidate(s); "
                  "evidence_confidence + prior_rejections present")


def _check_lookup_json(timeout: float) -> tuple[bool, str]:
    argv = [PYTHON, "src/lookup_case_logs.py", "--case-id", "CASE-005", "--json"]
    proc, _duration, output = _run_cmd(argv, timeout)
    data, problems = _json_from(proc, output)
    if data is None:
        return False, "; ".join(problems)
    if data.get("schema_version") != 1:
        problems.append(f"schema_version is {data.get('schema_version')!r}, expected integer 1")
    if data.get("case_id") != "CASE-005":
        problems.append(f"case_id is {data.get('case_id')!r}, expected 'CASE-005'")
    for key in ("count", "observations", "pattern_version", "maturity", "status",
                "derived_real_observations"):
        if key not in data:
            problems.append(f"missing top-level field {key!r}")
    if not isinstance(data.get("observations"), list):
        problems.append("observations must be a list")
    if isinstance(data.get("count"), bool) or not isinstance(data.get("count"), int):
        problems.append("count must be an integer")
    if problems:
        return False, "; ".join(problems[:12]) + "\n" + _tail(output, 12)
    return True, f"schema_version=1, {data.get('count')} observation(s) for CASE-005"


def _check_audit_json(timeout: float) -> tuple[bool, str]:
    argv = [PYTHON, "src/manage_memory.py", "audit", "--json"]
    proc, _duration, output = _run_cmd(argv, timeout)
    data, problems = _json_from(proc, output)
    if data is None:
        return False, "; ".join(problems)
    if data.get("ok") is not True:
        problems.append(f"ok is {data.get('ok')!r}, expected true")
        problems.extend(str(item) for item in (data.get("problems") or [])[:8])
    if not isinstance(data.get("problems"), list):
        problems.append("problems must be a list")
    if not isinstance(data.get("counts"), dict) or not data.get("counts"):
        problems.append("counts must be a non-empty object")
    if "warnings" in data and not isinstance(data["warnings"], list):
        problems.append("warnings must be a list when present")
    if "schema_version" in data and data["schema_version"] != 1:
        problems.append(f"schema_version is {data['schema_version']!r}, expected 1")
    if problems:
        return False, "; ".join(problems[:12]) + "\n" + _tail(output, 12)
    return True, f"ok=true, {len(data.get('counts') or {})} count section(s), problems=0"


def build_checks() -> list[Check]:
    checks = [
        Check("compileall", "baseline", _check_compileall,
              command="python -m compileall -q src tests scripts"),
        Check("unittest discover", "baseline", _check_unittest,
              command="python -m unittest discover -s tests"),
        _cli_check("catalog validate", "baseline",
                   [PYTHON, "src/manage_memory.py", "catalog", "validate"],
                   contains=("Catalog valid:",)),
        _cli_check("audit", "baseline",
                   [PYTHON, "src/manage_memory.py", "audit"],
                   contains=("Audit clean",)),
        _cli_check("run_demo sample", "baseline",
                   [PYTHON, "src/run_demo.py", "--input", "data/raw_logs.csv",
                    "--min-tier", "medium", "--top", "2"],
                   contains=("Input: data/raw_logs.csv", "INC-CASE-001-001", "CASE-008",
                             "independent scopes:", "Agent review required"),
                   not_contains=("Traceback (most recent call last)",)),
        _cli_check("lookup sample", "baseline",
                   [PYTHON, "src/lookup_case_logs.py", "--case-id", "CASE-005"],
                   contains=("CASE-005", "stored observation(s)", "status=confirmed"),
                   not_contains=("Traceback (most recent call last)",)),
        # ---- new-semantics gates (T1-T5); expected to fail until integration ----
        _cli_check("catalog state --check README.md", "new",
                   [PYTHON, "src/manage_memory.py", "catalog", "state", "--check", "README.md"]),
        _cli_check("catalog state", "new",
                   [PYTHON, "src/manage_memory.py", "catalog", "state"]),
        _cli_check("catalog repair (dry run)", "new",
                   [PYTHON, "src/manage_memory.py", "catalog", "repair"],
                   not_contains=("Traceback (most recent call last)",)),
        _cli_check("catalog corrections", "new",
                   [PYTHON, "src/manage_memory.py", "catalog", "corrections"],
                   not_contains=("Traceback (most recent call last)",)),
        Check("audit --json contract", "new", _check_audit_json,
              command="python src/manage_memory.py audit --json"),
        Check("run_demo --json contract", "new", _check_run_demo_json,
              command="python src/run_demo.py ... --json"),
        Check("lookup --json contract", "new", _check_lookup_json,
              command="python src/lookup_case_logs.py --case-id CASE-005 --json"),
        Check("journal has no unfinished transaction", "new",
              lambda _timeout: check_journal(),
              command="inspect data/ops_journal.jsonl"),
        Check("no leftover temp files in data/", "baseline",
              lambda _timeout: check_no_temp_files(),
              command="scan data/ for *.tmp"),
    ]
    return checks


# ---------------------------------------------------------------------------
# Runner / report
# ---------------------------------------------------------------------------

def run_checks(selected: list[Check], timeout: float, guard: bool) -> tuple[list[Result], dict]:
    results: list[Result] = []
    guard_state: dict = {"enabled": guard, "initial_files": 0, "mutated_files": []}
    snapshot = hash_data_store() if guard else {}
    guard_state["initial_files"] = len(snapshot)
    print(f"== attack-memory verification matrix ==\nroot:  {DEMO_ROOT}\n"
          f"python: {_python_version()}\n"
          f"suite: {UNITTEST_MODE} mode\n")
    for index, check in enumerate(selected, start=1):
        before = snapshot if guard else None
        started = time.perf_counter()
        try:
            ok, detail = check.run(timeout)
        except subprocess.TimeoutExpired:
            ok, detail = False, f"timed out after {timeout:.0f}s"
        except Exception:  # a broken check must not take the matrix down
            ok, detail = False, "check raised:\n" + traceback.format_exc(limit=3)
        duration = time.perf_counter() - started
        if guard:
            current = hash_data_store()
            changed = [f"data/{path}" for path in diff_snapshots(before, current)]
            if changed:
                ok = False
                detail = ("DEMO/DATA WAS MUTATED by this check: " + ", ".join(changed[:8])
                          + "\n" + detail)
                guard_state["mutated_files"].extend(changed)
                guard_state["mutated_files"] = sorted(set(guard_state["mutated_files"]))
            snapshot = current  # attribute a mutation to the check that caused it, once
        status = "PASS" if ok else "FAIL"
        results.append(Result(check.name, check.group, status, duration, detail, check.command))
        print(f"[{status}] {index:2d}. {check.name:<40} {duration:6.2f}s")
        if not ok:
            for line in detail.splitlines():
                print(f"        {line}")
    total = sum(result.duration_s for result in results)
    passed = sum(1 for result in results if result.status == "PASS")
    failed = [result for result in results if result.status != "PASS"]
    print(f"\nSummary: {len(results)} check(s), {passed} PASS, {len(failed)} FAIL "
          f"in {total:.2f}s")
    if guard:
        if guard_state["mutated_files"]:
            print("DATA GUARD: FAIL - demo/data changed: "
                  + ", ".join(guard_state["mutated_files"]))
        else:
            print(f"DATA GUARD: clean - demo/data unchanged "
                  f"({guard_state['initial_files']} file(s) hashed)")
    if failed:
        print("FAILED: " + "; ".join(result.name for result in failed))
    return results, guard_state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the attack-memory verification matrix read-only.")
    parser.add_argument("--group", choices=GROUPS, default="all",
                        help="which check groups to run (default: all)")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="print a machine-readable report instead of the table")
    parser.add_argument("--no-data-guard", action="store_false", dest="guard",
                        help="skip the demo/data mutation guard")
    parser.add_argument("--real-unittest", action="store_true",
                        help="run the suite in the real tree (final acceptance; default: sandbox copy)")
    parser.add_argument("--timeout", type=float, default=300.0,
                        help="per-check timeout in seconds (default: 300)")
    parser.add_argument("--verbose", action="store_true",
                        help="print the full output captured for failing checks")
    parser.add_argument("--list", action="store_true", dest="list_checks",
                        help="list the checks without running them")
    args = parser.parse_args(argv)

    global UNITTEST_MODE
    UNITTEST_MODE = "real" if args.real_unittest else "sandbox"

    all_checks = build_checks()
    selected = [check for check in all_checks
                if args.group == "all" or check.group == args.group]
    if args.list_checks:
        for check in selected:
            print(f"{check.group:<8} {check.name}  [{check.command}]")
        return 0
    if not selected:
        parser.error(f"no checks in group {args.group!r}")

    started_at = datetime.now(timezone.utc).isoformat()
    results, guard_state = run_checks(selected, args.timeout, args.guard)
    failed = [result for result in results if result.status != "PASS"]
    status = "PASS" if not failed else "FAIL"

    if args.as_json:
        report = {
            "root": str(DEMO_ROOT),
            "python": _python_version(),
            "started_at": started_at,
            "status": status,
            "group": args.group,
            "unittest_mode": UNITTEST_MODE,
            "checks": [
                {"name": result.name, "group": result.group, "status": result.status,
                 "duration_s": round(result.duration_s, 3), "command": result.command,
                 "detail": result.detail}
                for result in results
            ],
            "summary": {
                "total": len(results),
                "passed": len(results) - len(failed),
                "failed": len(failed),
                "duration_s": round(sum(result.duration_s for result in results), 3),
            },
            "data_guard": guard_state,
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
    elif args.verbose and failed:
        print("\n== full output of failing checks ==")
        for result in failed:
            print(f"\n--- {result.name} [{result.command}]\n{result.detail}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())

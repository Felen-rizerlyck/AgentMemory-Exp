#!/usr/bin/env python3
"""Execute docs/RUNTIME_MEMORY_SIMPLE_TEST_GUIDE_2026-11-10.md.

The guide is CLI-driven and uses an isolated ``--root``.  This script runs the
T0-T8 cases from the repository root, captures every command and JSON result,
and archives the evidence under ``sim/simple-guide-2026-11-10/``.  It does not
modify runtime-memory source, tests or ``runtime_memory/data``.

Run from the repository root::

    python runtime_memory/sim/simple_guide_2026-11-10.py
"""
from __future__ import annotations

import datetime as dt
import json
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]          # runtime_memory/
REPO = ROOT.parent
CLI = ROOT / "src" / "manage_runtime_memory.py"
COMMON = [
    "--component", "mcp", "--tool", "demo.query", "--action", "search",
    "--scope", "global", "--environment", "test",
    "--args", '{"q":"health"}',
]


class GuideRunner:
    def __init__(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="runtime-memory-simple-check-"))
        self.commands: list[dict[str, Any]] = []
        self.cases: list[dict[str, Any]] = []
        self.policy: dict[str, Any] = {}

    def _run(self, case: str, args: list[str]) -> dict[str, Any]:
        command = [sys.executable, str(CLI), "--root", str(self.root), *args]
        started = time.perf_counter()
        completed = subprocess.run(
            command, cwd=str(REPO), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=120)
        record = {
            "case": case,
            "command": " ".join(str(item) for item in command),
            "args": args,
            "exit_code": completed.returncode,
            "duration_s": round(time.perf_counter() - started, 3),
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }
        self.commands.append(record)
        return record

    def run(self, case: str, args: list[str]) -> dict[str, Any]:
        record = self._run(case, args)
        if record["exit_code"] != 0:
            raise RuntimeError(
                f"{case}: command failed ({record['exit_code']}): "
                f"{record['command']}\n{record['stderr']}")
        return record

    def run_json(self, case: str, args: list[str]) -> Any:
        record = self.run(case, args)
        try:
            return json.loads(record["stdout"])
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"{case}: expected JSON, got:\n{record['stdout']}\n"
                f"stderr:\n{record['stderr']}") from exc

    def record_failure(self, target: str, run_id: str) -> dict[str, Any]:
        return self.run("record", [
            "record", *COMMON, "--target", target, "--run-id", run_id,
            "--outcome", "fail", "--error-class", "unreachable",
            "--message", "simulated connection failure",
        ])

    def issues(self, case: str, *, active: bool = False) -> list[dict[str, Any]]:
        args = ["issues", "--json"]
        if active:
            args.insert(1, "--active")
        data = self.run_json(case, args)
        return data.get("issues", [])

    def issue(self, case: str, issue_id: str) -> dict[str, Any]:
        return self.run_json(case, ["issue", issue_id, "--json"])

    def preflight(self, case: str, target: str, run_id: str, *,
                  probe: bool = False, basis: str = "") -> dict[str, Any]:
        args = ["preflight", *COMMON, "--target", target,
                "--run-id", run_id, "--json"]
        if probe:
            args += ["--probe", "--basis", basis or "operator probe"]
        return self.run_json(case, args)

    def add_case(self, case_id: str, title: str, status: str,
                 expected: str, observed: Any, evidence: Any = None) -> None:
        self.cases.append({
            "id": case_id, "title": title, "status": status,
            "expected": expected, "observed": observed, "evidence": evidence,
        })


def wait_until(iso_text: str) -> None:
    stamp = dt.datetime.fromisoformat(iso_text.replace("Z", "+00:00"))
    now = dt.datetime.now(dt.timezone.utc)
    delay = max(0.0, (stamp - now).total_seconds() + 0.2)
    if delay > 0:
        time.sleep(min(delay, 10.0))


def write_archive(runner: GuideRunner, cases: list[dict[str, Any]],
                  archive: Path, report: dict[str, Any]) -> None:
    if archive.exists():
        archive = archive.with_name(archive.name + "-2")
    archive.mkdir(parents=True)
    (archive / "evidence").mkdir()
    (archive / "data").mkdir()
    shutil.copy2(runner.root / "policy.json", archive / "policy.json")
    for name in ("issues.json", "decisions.jsonl", "overrides.jsonl"):
        source = runner.root / name
        if source.exists():
            shutil.copy2(source, archive / "data" / name)
    if (runner.root / "events").exists():
        shutil.copytree(runner.root / "events", archive / "data" / "events")
    (archive / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (archive / "evidence" / "commands.jsonl").write_text(
        "\n".join(json.dumps(item, ensure_ascii=False)
                  for item in runner.commands) + "\n", encoding="utf-8")
    (archive / "results.json").write_text(
        json.dumps(cases, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Runtime Memory 简单效果测试报告（2026-11-10）",
        "",
        f"- 执行日期：{report['executed_at']}",
        f"- Python：{report['python']}",
        f"- commit：{report['commit']}",
        f"- 测试目录（已清理/保留见备注）：`{runner.root}`",
        f"- 临时 policy：`policy.json`（enforce=false，unreachable base=2s/max=3s/max_attempts=1/ttl=60s）",
        "",
        "## 汇总",
        "",
        "| ID | 结果 | 观察 | 证据 |",
        "|---|---|---|---|",
    ]
    for case in cases:
        lines.append(
            f"| {case['id']} | **{case['status']}** | "
            f"{str(case['observed'])[:300]} | "
            f"`evidence/commands.jsonl` / `data/` |")
    lines += ["", "## 说明", "",
              "- 按 guide 使用临时 `--root`，未读写 `runtime_memory/data`、`sim/runs` 或 demo 数据。",
              "- 所有 outcome 由 CLI `record` 模拟，未调用真实工具/网络。",
              "- 测试结果是小样本功能检查，不代表生产效果。",
              ""]
    (archive / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    runner = GuideRunner()
    executed_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                            cwd=str(REPO), capture_output=True, text=True).stdout.strip()
    base_policy = json.loads((ROOT / "data" / "policy.json").read_text(
        encoding="utf-8"))
    base_policy["enforce"] = False
    base_policy["classes"]["unreachable"].update({
        "key_level": "scope", "retryable": True, "mode": "exponential",
        "base_s": 2, "max_s": 3, "max_attempts": 1, "ttl_s": 60,
    })
    runner.policy = base_policy
    (runner.root / "policy.json").write_text(
        json.dumps(base_policy, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")

    try:
        # T0: isolation and initial state.
        check = runner.run("T0", ["check"])
        brief = runner.run("T0", ["brief"])
        state = runner.run_json("T0", ["state", "--json"])
        t0_ok = (check["stdout"].strip().endswith("clean.")
                 and "No active tool issues." in brief["stdout"]
                 and state["events"] == 0 and state["issues"] == 0)
        runner.add_case("T0", "隔离与初始状态",
                        "PASS" if t0_ok else "FAIL",
                        "check clean；brief 无活动问题；events/issues=0",
                        {"check": check["stdout"].strip(),
                         "brief": brief["stdout"].strip(),
                         "state": state})

        # T1: first failure is remembered.
        runner.record_failure("case-one", "run-A")
        issues = runner.issues("T1", active=True)
        issue = next(item for item in issues if item.get("target") == "case-one")
        issue_id = issue["issue_id"]
        t1_ok = (issue["status"] == "cooldown" and issue["count"] == 1
                 and issue.get("evidence_run_ids") == ["run-A"]
                 and bool(issue.get("next_retry_at")))
        runner.add_case("T1", "首次失败可记忆",
                        "PASS" if t1_ok else "FAIL",
                        "cooldown, count=1, evidence_run_ids=[run-A], next_retry_at 存在",
                        {k: issue.get(k) for k in
                         ("issue_id", "status", "count", "evidence_run_ids",
                          "next_retry_at")})

        # T2: same-run retries do not upgrade.
        runner.record_failure("case-one", "run-A")
        runner.record_failure("case-one", "run-A")
        issue = runner.issue("T2", issue_id)
        t2_ok = (issue["status"] == "cooldown"
                 and issue["count"] >= 3
                 and set(issue.get("evidence_run_ids") or []) == {"run-A"})
        runner.add_case("T2", "同一 run 的重试不升级",
                        "PASS" if t2_ok else "FAIL",
                        "cooldown，count 增加，evidence_run_ids 仍只有 run-A",
                        {k: issue.get(k) for k in
                         ("status", "count", "evidence_run_ids", "next_retry_at")})

        # T3: a second independent run upgrades.
        runner.record_failure("case-one", "run-B")
        issue = runner.issue("T3", issue_id)
        t3_ok = (issue["status"] == "open"
                 and {"run-A", "run-B"}.issubset(
                     set(issue.get("evidence_run_ids") or [])))
        runner.add_case("T3", "跨 run 的重复故障升级",
                        "PASS" if t3_ok else "FAIL",
                        "open，evidence_run_ids 含 run-A 与 run-B",
                        {k: issue.get(k) for k in
                         ("status", "count", "evidence_run_ids", "next_retry_at")})

        # T4: block during cooldown, shadow decision.
        runner.record_failure("case-cooldown", "run-T4")
        decision = runner.preflight("T4", "case-cooldown", "check-T4")
        t4_ok = (decision.get("action") == "block"
                 and decision.get("shadow") is True
                 and "retry" in str(decision.get("reason", "")).lower())
        runner.add_case("T4", "冷却期内拦截建议",
                        "PASS" if t4_ok else "FAIL",
                        "block；shadow=true；reason 含等待重试窗口",
                        decision)

        # T5: wait for next_retry_at, then probe despite max_attempts.
        wait_until(issue["next_retry_at"])
        decision = runner.preflight("T5", "case-one", "check-T5")
        t5_ok = decision.get("action") == "probe"
        runner.add_case("T5", "预算耗尽后仍可探测",
                        "PASS" if t5_ok else "FAIL",
                        "退避时间到后返回 probe",
                        decision)
        if not t5_ok:
            raise RuntimeError(f"T5 expected probe, got {decision}")

        # T6: a successful probe resolves the issue.
        runner.run("T6", [
            "record", *COMMON, "--target", "case-one", "--run-id", "run-C",
            "--outcome", "ok", "--decision-id", decision["decision_id"],
        ])
        resolved = runner.issue("T6", issue_id)
        after = runner.preflight("T6", "case-one", "check-T6")
        t6_ok = (resolved["status"] == "resolved"
                 and not resolved.get("next_retry_at")
                 and not resolved.get("probe_started_at")
                 and after.get("action") == "allow")
        runner.add_case("T6", "探测成功自动解除",
                        "PASS" if t6_ok else "FAIL",
                        "resolved；next_retry_at/probe_started_at 为空；后续 allow",
                        {"issue": {k: resolved.get(k) for k in
                                   ("status", "next_retry_at", "probe_started_at")},
                         "next_preflight": after})

        # T7: compact brief card.
        runner.record_failure("case-brief", "run-BRIEF")
        brief_text = runner.run("T7", ["brief"])
        brief_json = runner.run_json("T7", ["brief", "--json"])
        candidates = [item for item in brief_json.get("issues", [])
                      if item.get("target") == "case-brief"]
        t7_ok = bool(candidates) and all(
            key in candidates[0] for key in
            ("tool", "target", "status", "error", "independent_runs", "retry_at"))
        runner.add_case("T7", "精简记忆卡片",
                        "PASS" if t7_ok else "FAIL",
                        "brief 输出工具/目标/状态/错误/独立 run 数/重试时间",
                        {"text": brief_text["stdout"].strip(),
                         "json": brief_json})

        # T8: structure and audit self-check.
        check = runner.run("T8", ["check"])
        report = runner.run_json("T8", ["report", "--json"])
        events = [json.loads(line) for line in
                  (runner.root / "events" / "2026-11.jsonl").read_text(
                      encoding="utf-8").splitlines() if line.strip()]
        decisions = [json.loads(line) for line in
                     (runner.root / "decisions.jsonl").read_text(
                         encoding="utf-8").splitlines() if line.strip()]
        linked = any(event.get("decision_id") == decision["decision_id"]
                     for event in events)
        t8_ok = (check["stdout"].strip().endswith("clean.")
                 and events and decisions and linked)
        runner.add_case("T8", "结构与审计自检",
                        "PASS" if t8_ok else "FAIL",
                        "check clean；events/decisions 非空；decision_id 关联",
                        {"check": check["stdout"].strip(),
                         "report": {key: report.get(key) for key in
                                    ("events", "decisions", "issues")},
                         "event_count": len(events),
                         "decision_count": len(decisions),
                         "decision_linked": linked})

    except Exception as exc:  # noqa: BLE001
        runner.add_case("RUNNER", "执行异常", "FAIL",
                        "所有 case 完成", f"{type(exc).__name__}: {exc}")
        print(f"ERROR: {exc}")
        raise
    finally:
        failed = any(case["status"] != "PASS" for case in runner.cases)
        report = {
            "schema_version": 1,
            "executed_at": executed_at,
            "python": platform.python_version(),
            "commit": commit,
            "policy": base_policy,
            "test_root": str(runner.root),
            "test_root_kept": failed,
            "cases": runner.cases,
            "commands": runner.commands,
        }
        archive = ROOT / "sim" / "simple-guide-2026-11-10"
        write_archive(runner, runner.cases, archive, report)
        (archive / "data" / "issues.json")
        if not failed:
            shutil.rmtree(runner.root, ignore_errors=True)
        print(f"archive: {archive}")
        for case in runner.cases:
            print(f"{case['id']:3} {case['status']:4} {case['title']}")
        print(f"test_root_kept={failed} ({runner.root})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

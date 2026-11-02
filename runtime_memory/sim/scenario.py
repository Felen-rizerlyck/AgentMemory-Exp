#!/usr/bin/env python3
"""Deterministic 'restricted lab' scenario for the runtime-memory prototype.

Run from runtime_memory/:

    python sim/scenario.py --run-id sim-2026-11-02

The scenario simulates one analyst/agent session against a restricted lab:

  A. shadow phase: an MCP hunt endpoint is unreachable, SIEM is rate-limited,
     one pcap is malformed, a shell command is denied, and the model API times
     out once.  All calls still execute; preflight decisions are recorded.
  B. enforce phase: the MCP call is blocked until its retry window, then one
     probe succeeds; a different pcap path is allowed while the bad one stays
     blocked; the shell permission issue is blocked.
  C. new session: memory persists; resolved issues allow, unresolved ones block.

It writes a complete run under sim/runs/<run-id>:

    data/events/*.jsonl   actual operation traces
    data/issues.json      aggregated issues
    data/decisions.jsonl  preflight decisions
    narrative.log         step-by-step story
    summary.md            counts + shadow/enforce comparison
    records.md            sample records (event/issue/decision)
    report.json           machine-readable metrics
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import shutil
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory import OperationRequest, Policy, RuntimeMemory  # noqa: E402
from runtime_memory.policy import default_policy  # noqa: E402
from runtime_memory.store import atomic_write_json  # noqa: E402
from runtime_memory.timeutil import iso  # noqa: E402


class FakeClock:
    def __init__(self, start: dt.datetime):
        self.now = start

    def __call__(self) -> dt.datetime:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += dt.timedelta(seconds=seconds)


class Scenario:
    def __init__(self, run_id: str, out: Path):
        self.run_id = run_id
        self.out = out
        self.data = out / "data"
        self.clock = FakeClock(dt.datetime(2026, 11, 2, 6, 0, tzinfo=dt.timezone.utc))
        self.lines: list[str] = []
        self.events: list[dict[str, Any]] = []
        self.decisions: list[dict[str, Any]] = []
        self.policies: list[dict[str, Any]] = []
        self.executed = 0
        self.blocked = 0
        self.failures = 0

    # -- helpers ---------------------------------------------------------
    def log(self, message: str) -> None:
        stamp = self.clock.now.strftime("%H:%M:%S")
        line = f"[{stamp}] {message}"
        self.lines.append(line)
        print(line)

    def runtime(self, enforce: bool) -> RuntimeMemory:
        data = copy.deepcopy(default_policy())
        data["enforce"] = enforce
        runtime = RuntimeMemory(self.data, policy=Policy(data), clock=self.clock)
        # Keep the on-disk policy consistent with the phase actually used.
        atomic_write_json(runtime.store.policy_path, data)
        self.policies.append({
            "phase": len(self.policies) + 1,
            "enforce": enforce,
            "policy_version": data["policy_version"],
            "at": iso(self.clock.now),
        })
        return runtime

    def request(self, *, component: str, tool: str, action: str,
                target: str, args: dict[str, Any], scope: str = "global",
                run_id: str | None = None) -> OperationRequest:
        return OperationRequest(
            component=component, tool=tool, action=action, target=target,
            args=args, scope=scope, environment_id="lab-a",
            session_id="sim-session-01", run_id=run_id or self.run_id,
        )

    def step(self, runtime: RuntimeMemory, label: str, request: OperationRequest,
             outcome: str, *, enforce: bool, error: BaseException | None = None,
             error_class: str = "", duration_ms: int = 0) -> dict[str, Any]:
        decision = runtime.preflight(request)
        self.decisions.append(decision.to_dict())
        self.log(f"{label}: preflight={decision.action} "
                 f"issue={decision.issue_id or '-'} "
                 f"shadow={decision.shadow}")
        result = {"label": label, "decision": decision.action,
                  "executed": True, "outcome": outcome}
        if decision.action == "block" and enforce:
            self.blocked += 1
            result["executed"] = False
            self.log(f"  SKIPPED by enforce gate; alternatives={decision.alternatives}")
            return result
        self.executed += 1
        if outcome != "ok":
            self.failures += 1
        issue = runtime.postflight(request, outcome, error=error,
                                   error_class=error_class,
                                   duration_ms=duration_ms,
                                   decision=decision)
        if issue:
            self.log(f"  executed -> {outcome}; issue={issue['issue_id']} "
                     f"status={issue['status']} count={issue['count']}")
        else:
            self.log(f"  executed -> {outcome}; no issue")
        return result

    def issue_for(self, runtime: RuntimeMemory, tool: str) -> dict[str, Any] | None:
        for issue in runtime.store.list_issues():
            if issue.get("tool") == tool and issue.get("status") != "resolved":
                return issue
        return None

    # -- scenario --------------------------------------------------------
    def run(self) -> dict[str, Any]:
        self.out.mkdir(parents=True, exist_ok=True)

        # A. shadow phase -------------------------------------------------
        self.log("=== A. shadow phase (calls still execute) ===")
        shadow = self.runtime(enforce=False)
        mcp = self.request(
            component="mcp", tool="hunt.query", action="search",
            target="http://10.7.194.120:22196/hunt/sse",
            args={"q": "dns tunnel", "limit": 50},
        )
        for attempt in range(1, 4):
            self.step(shadow, f"mcp hunt attempt {attempt}", mcp, "fail",
                      enforce=False,
                      error=ConnectionRefusedError("connect refused"),
                      error_class="unreachable", duration_ms=30012)
            self.clock.advance(60)

        mcp_issue = self.issue_for(shadow, "hunt.query")
        if mcp_issue:
            shadow.set_workaround(
                mcp_issue["issue_id"],
                "use local pcap or cached hunt results until endpoint is restored",
                reviewer="analyst",
            )
            self.log(f"workaround recorded on {mcp_issue['issue_id']}")

        siem = self.request(
            component="siem", tool="search", action="query",
            target="http://siem.lab-a:9200", args={"index": "edr"},
        )
        for attempt in range(1, 3):
            self.step(shadow, f"siem search attempt {attempt}", siem, "fail",
                      enforce=False, error=RuntimeError("429 Too Many Requests"),
                      error_class="rate_limit", duration_ms=120)
            self.clock.advance(60)

        pcap_bad = self.request(
            component="parser", tool="pcap.parse", action="parse",
            target="/data/pcap", args={"path": "/data/pcap/case-001.pcap"},
        )
        pcap_good = self.request(
            component="parser", tool="pcap.parse", action="parse",
            target="/data/pcap", args={"path": "/data/pcap/case-002.pcap"},
        )
        self.step(shadow, "pcap case-001", pcap_bad, "fail",
                  enforce=False, error=ValueError("truncated pcap header"),
                  error_class="schema", duration_ms=15)
        self.clock.advance(60)
        self.step(shadow, "pcap case-002", pcap_good, "ok",
                  enforce=False, duration_ms=18)
        self.clock.advance(60)

        shell = self.request(
            component="shell", tool="run", action="exec", target="host-01",
            args={"cmd": "cat /etc/shadow"},
        )
        self.step(shadow, "shell permission probe", shell, "fail",
                  enforce=False, error=PermissionError("denied"),
                  error_class="permission", duration_ms=5)
        self.clock.advance(60)

        model = self.request(
            component="model", tool="complete", action="generate",
            target="http://ollama.lab-a:11434", args={"prompt_id": "summarize-1"},
        )
        self.step(shadow, "model completion", model, "fail",
                  enforce=False, error=TimeoutError("upstream timeout"),
                  error_class="timeout", duration_ms=30000)
        self.clock.advance(31)
        self.step(shadow, "model completion retry", model, "ok", enforce=False,
                  duration_ms=4200)

        self.log(f"shadow totals: executed={self.executed} "
                 f"blocked={self.blocked} failures={self.failures}")

        # B. enforce phase -------------------------------------------------
        # A new run id, so the per-run budget from phase A does not mask the
        # issue-level retry window we want to demonstrate here.
        self.log("=== B. enforce phase (blocked calls are skipped) ===")
        b_run = f"{self.run_id}-b"
        mcp_b = replace(mcp, run_id=b_run)
        siem_b = replace(siem, run_id=b_run)
        pcap_bad_b = replace(pcap_bad, run_id=b_run)
        pcap_good_b = replace(pcap_good, run_id=b_run)
        shell_b = replace(shell, run_id=b_run)
        enforce = self.runtime(enforce=True)
        self.step(enforce, "mcp hunt blocked", mcp_b, "fail", enforce=True,
                  error=ConnectionRefusedError("connect refused"),
                  error_class="unreachable", duration_ms=0)
        self.clock.advance(901)
        self.step(enforce, "mcp hunt probe", mcp_b, "ok", enforce=True,
                  duration_ms=21000)

        siem_before = self._issue_status(enforce, "search")
        self.clock.advance(121)
        self.step(enforce, "siem probe", siem_b, "ok", enforce=True,
                  duration_ms=800)
        self.log(f"siem issue before probe: {siem_before}")

        self.step(enforce, "pcap case-001 blocked", pcap_bad_b, "fail",
                  enforce=True, error=ValueError("truncated pcap header"),
                  error_class="schema")
        self.step(enforce, "pcap case-002 allowed", pcap_good_b, "ok",
                  enforce=True, duration_ms=18)
        self.step(enforce, "shell blocked", shell_b, "fail", enforce=True,
                  error=PermissionError("denied"), error_class="permission")

        # C. new session ---------------------------------------------------
        self.log("=== C. new session (memory persists) ===")
        c_run = f"{self.run_id}-c"
        fresh = self.runtime(enforce=True)
        for label, req in (("mcp", mcp), ("siem", siem),
                           ("pcap case-001", pcap_bad), ("pcap case-002", pcap_good),
                           ("shell", shell), ("model", model)):
            decision = fresh.preflight(replace(req, run_id=c_run), record=False)
            self.decisions.append(decision.to_dict())
            self.log(f"fresh preflight {label}: {decision.action} "
                     f"issue={decision.issue_id or '-'}")

        report = fresh.report()
        atomic_write_json(self.out / "report.json", report)
        atomic_write_json(self.out / "policies.json",
                          {"schema_version": 1, "phases": self.policies})
        self.write_narrative()
        self.write_records(fresh)
        self.write_summary(report)
        return report

    def _issue_status(self, runtime: RuntimeMemory, tool: str) -> str:
        issue = self.issue_for(runtime, tool)
        return issue["status"] if issue else "-"

    # -- artifacts -------------------------------------------------------
    def write_narrative(self) -> None:
        (self.out / "narrative.log").write_text("\n".join(self.lines) + "\n",
                                                encoding="utf-8")

    def write_records(self, runtime: RuntimeMemory) -> None:
        events = runtime.store.read_events()
        issues = runtime.store.list_issues()
        decisions = runtime.store.read_decisions()
        samples = {
            "event_first_failure": events[0] if events else {},
            "event_retry_failure": next(
                (e for e in events if e.get("outcome") != "ok"
                 and int(e.get("attempt", 1)) > 1), {}),
            "event_success": next((e for e in events if e.get("outcome") == "ok"), {}),
            "issue_open": next((i for i in issues if i.get("status") != "resolved"), {}),
            "issue_resolved": next((i for i in issues if i.get("status") == "resolved"), {}),
            "decision_block": next((d for d in decisions if d.get("action") == "block"), {}),
            "decision_probe": next((d for d in decisions if d.get("action") == "probe"), {}),
        }
        lines = [
            "# Sample runtime-memory records",
            "",
            "These are actual records produced by `sim/scenario.py`.",
            "",
        ]
        for name, record in samples.items():
            lines += [f"## {name}", "", "```json",
                      json.dumps(record, ensure_ascii=False, indent=2), "```", ""]
        (self.out / "records.md").write_text("\n".join(lines), encoding="utf-8")

    def write_summary(self, report: dict[str, Any]) -> None:
        lines = [
            "# Simulated restricted-lab run",
            "",
            f"- run_id: `{self.run_id}`",
            f"- phase A: shadow (calls execute, decisions recorded)",
            f"- phase B: enforce (blocked calls skipped)",
            f"- phase C: new session (memory persists)",
            "",
            "## Execution",
            "",
            f"- actual calls: {self.executed}",
            f"- blocked calls: {self.blocked}",
            f"- failures: {self.failures}",
            "",
            "## Report",
            "",
            "```text",
            json.dumps(report, ensure_ascii=False, indent=2),
            "```",
            "",
            "## What to look at",
            "",
            "- `data/events/*.jsonl`: one line per actual tool call, with "
            "`fingerprint`, `error_class`, `would_block` and `decision_id`.",
            "- `data/issues.json`: aggregated issues; note `scope` vs `call` "
            "fingerprints and the `workaround` / `next_retry_at` fields.",
            "- `data/decisions.jsonl`: every non-allow block/probe/hint decision, "
            "including shadow decisions. Allowed calls are only in events.",
            "- `policies.json`: the shadow/enforce policy used in each phase "
            "(the final `data/policy.json` reflects the last phase).",
            "- `records.md`: a small sample of each record type.",
            "- `narrative.log`: the story with timestamps.",
        ]
        (self.out / "summary.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the restricted-lab simulation")
    parser.add_argument("--run-id", default="sim-2026-11-02")
    parser.add_argument("--out", help="output directory; default sim/runs/<run-id>")
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing output directory")
    args = parser.parse_args()
    out = Path(args.out) if args.out else ROOT / "sim" / "runs" / args.run_id
    if out.exists() and not args.force:
        parser.error(f"{out} already exists; pass --force or use a new --run-id")
    if out.exists():
        shutil.rmtree(out)
    scenario = Scenario(args.run_id, out)
    report = scenario.run()
    print(f"\nrun written to {out}")
    print(f"actual calls={scenario.executed} blocked={scenario.blocked} "
          f"failures={scenario.failures}")
    print(f"shadow would_block={report['shadow']['would_block']} "
          f"false_blocks={report['shadow']['false_blocks']} "
          f"duplicate_attempts={report['duplicate_attempts']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

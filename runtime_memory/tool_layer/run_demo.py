"""Run an end-to-end local tool + runtime-memory demonstration."""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory import Policy, RuntimeMemory, default_policy  # noqa: E402
from gateway import MemoryGateway, ToolBlocked, ToolCallError  # noqa: E402
from server import ToolState, make_server  # noqa: E402


def set_mode(base_url: str, mode: str) -> None:
    body = json.dumps({"mode": mode}).encode("utf-8")
    request = Request(f"{base_url}/admin/mode", data=body,
                      headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=2) as response:
        response.read()


def main() -> int:
    parser = argparse.ArgumentParser(description="Local runtime-memory tool-layer demo")
    parser.add_argument("--data-root", help="keep runtime-memory data at this path")
    args = parser.parse_args()

    temporary = None
    if args.data_root:
        data_root = Path(args.data_root).resolve()
    else:
        temporary = tempfile.TemporaryDirectory(prefix="runtime-memory-tool-layer-")
        data_root = Path(temporary.name)

    config = default_policy()
    config["enforce"] = False
    config["budgets"]["max_attempts_per_call_key_per_run"] = 20
    config["budgets"]["max_failures_per_component_per_run"] = 50
    config["classes"]["unreachable"].update(
        {"mode": "fixed", "base_s": 1, "max_s": 1,
         "max_attempts": 1, "ttl_s": 30})
    memory = RuntimeMemory(data_root, policy=Policy(config))

    state = ToolState()
    server = make_server(state=state)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    gateway = MemoryGateway(memory, base_url)
    steps: list[dict] = []

    try:
        steps.append({"step": "healthy_call", "outcome": "success",
                      "result": gateway.call_search("baseline", run_id="run-healthy")["result"]})

        set_mode(base_url, "unavailable")
        for run_id in ("run-A", "run-A", "run-B"):
            try:
                gateway.call_search("transient-outage", run_id=run_id)
            except ToolCallError as error:
                steps.append({"step": "simulated_outage", "run_id": run_id,
                              "outcome": "recorded_failure",
                              "error_class": error.error_class})

        issues = memory.store.list_issues(include_resolved=False)
        issue = next(item for item in issues if item.get("error_class") == "unreachable")
        steps.append({"step": "evidence_gate", "status": issue["status"],
                      "evidence_run_ids": issue.get("evidence_run_ids", [])})

        memory.policy.data["enforce"] = True
        call_count_before = state.snapshot()["calls"]
        enforce_result = {"step": "enforce_gate", "outcome": "unexpected_call"}
        try:
            gateway.call_search("enforce-check", run_id="run-enforce-check")
        except ToolBlocked as blocked:
            enforce_result = {"step": "enforce_gate", "outcome": "blocked_before_tool",
                              "decision": blocked.decision}
        enforce_result["backend_calls_before"] = call_count_before
        enforce_result["backend_calls_after"] = state.snapshot()["calls"]
        steps.append(enforce_result)

        next_retry = issue.get("next_retry_at")
        from runtime_memory.timeutil import parse_iso  # local optional utility
        retry_time = parse_iso(next_retry)
        if retry_time:
            delay = max(0.0, (retry_time - memory.clock()).total_seconds())
            time.sleep(delay + 0.05)

        memory.policy.data["enforce"] = False
        set_mode(base_url, "success")
        recovery = gateway.call_search("recovered", run_id="run-recovery")
        steps.append({"step": "recovery_probe", "outcome": "success",
                      "decision": recovery["decision"]})
        steps.append({"step": "final_issue", "issue": memory.store.get_issue(issue["issue_id"])})
        steps.append({"step": "final_report", "report": memory.report()})

        print(json.dumps({"data_root": str(data_root), "steps": steps,
                          "backend": state.snapshot(),
                          "check": memory.store.check()}, ensure_ascii=False, indent=2))
        return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        if temporary:
            temporary.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())

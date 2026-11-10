"""Small adapter that puts RuntimeMemory around an actual HTTP tool call."""
from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any

from runtime_memory import OperationRequest, RuntimeMemory


class ToolBlocked(RuntimeError):
    def __init__(self, decision: dict[str, Any]):
        super().__init__(decision.get("reason") or "tool call blocked")
        self.decision = decision


class ToolCallError(RuntimeError):
    def __init__(self, error_class: str, message: str,
                 decision_id: str = ""):
        super().__init__(message)
        self.error_class = error_class
        self.decision_id = decision_id


class MemoryGateway:
    """Execute one named HTTP tool with preflight and postflight recording."""

    def __init__(self, memory: RuntimeMemory, base_url: str,
                 timeout_s: float = 0.5):
        self.memory = memory
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s

    def call_search(self, query: str, *, run_id: str,
                    session_id: str = "local-test-session") -> dict[str, Any]:
        request = OperationRequest(
            component="local_http",
            tool="search",
            action="search",
            target=self.base_url,
            args={"query": query},
            scope="session",
            environment_id="local-test",
            session_id=session_id,
            run_id=run_id,
        )
        decision = self.memory.preflight(request)
        if decision.action == "block" and not decision.shadow:
            raise ToolBlocked(decision.to_dict())

        body = json.dumps({"query": query}).encode("utf-8")
        http_request = urllib.request.Request(
            f"{self.base_url}/tools/search", data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        started = time.monotonic()
        try:
            with urllib.request.urlopen(http_request, timeout=self.timeout_s) as response:
                result = json.loads(response.read().decode("utf-8"))
            self.memory.postflight(
                request, "ok", duration_ms=int((time.monotonic() - started) * 1000),
                decision=decision)
            return {"result": result, "decision": decision.to_dict()}
        except urllib.error.HTTPError as error:
            status = int(error.code)
            error_class = {401: "auth", 403: "permission", 404: "not_found",
                           429: "rate_limit", 503: "unreachable"}.get(status, "unknown")
            message = error.read().decode("utf-8", errors="replace")
            self.memory.postflight(
                request, "fail", error_class=error_class, error_code=str(status),
                message=message, duration_ms=int((time.monotonic() - started) * 1000),
                decision=decision, retry_after_s=1 if status == 429 else None)
            raise ToolCallError(error_class, message, decision.decision_id) from error
        except (TimeoutError, socket.timeout) as error:
            self.memory.postflight(
                request, "timeout", error_class="timeout", message=str(error),
                duration_ms=int((time.monotonic() - started) * 1000),
                decision=decision)
            raise ToolCallError("timeout", str(error), decision.decision_id) from error
        except urllib.error.URLError as error:
            reason = error.reason
            if isinstance(reason, (TimeoutError, socket.timeout)):
                error_class = "timeout"
                outcome = "timeout"
            elif isinstance(reason, OSError):
                error_class = "unreachable"
                outcome = "fail"
            else:
                error_class = "unknown"
                outcome = "fail"
            self.memory.postflight(
                request, outcome, error_class=error_class, message=str(error),
                duration_ms=int((time.monotonic() - started) * 1000),
                decision=decision)
            raise ToolCallError(error_class, str(error), decision.decision_id) from error

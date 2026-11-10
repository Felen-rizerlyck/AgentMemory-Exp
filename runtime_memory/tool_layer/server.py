"""Local HTTP tool backend with controllable operational failure modes.

This is a real local service used to exercise the tool boundary. It uses only
the Python standard library and is deliberately kept outside src/ and tests/.
"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class ToolState:
    def __init__(self) -> None:
        self.mode = "success"
        self.calls = 0
        self.lock = threading.Lock()

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return {"mode": self.mode, "calls": self.calls}

    def set_mode(self, mode: str) -> None:
        if mode not in {"success", "unavailable", "timeout", "rate_limit", "auth"}:
            raise ValueError(f"unsupported mode: {mode}")
        with self.lock:
            self.mode = mode

    def begin_call(self) -> str:
        with self.lock:
            self.calls += 1
            return self.mode


def make_server(host: str = "127.0.0.1", port: int = 0,
                state: ToolState | None = None) -> ThreadingHTTPServer:
    tool_state = state or ToolState()

    class Handler(BaseHTTPRequestHandler):
        server_version = "RuntimeMemoryTool/1.0"

        def _send(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send(200, {"ok": True, **tool_state.snapshot()})
                return
            if self.path == "/admin/state":
                self._send(200, tool_state.snapshot())
                return
            self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, {"error": "invalid_json"})
                return

            if self.path == "/admin/mode":
                try:
                    tool_state.set_mode(str(payload.get("mode", "")))
                except ValueError as error:
                    self._send(400, {"error": str(error)})
                    return
                self._send(200, tool_state.snapshot())
                return

            if self.path != "/tools/search":
                self._send(404, {"error": "not_found"})
                return

            mode = tool_state.begin_call()
            if mode == "unavailable":
                self._send(503, {"error": "service_unavailable", "retryable": True})
            elif mode == "timeout":
                time.sleep(2.0)
                self._send(200, {"results": [], "delayed": True})
            elif mode == "rate_limit":
                self._send(429, {"error": "rate_limited", "retry_after_s": 1})
            elif mode == "auth":
                self._send(401, {"error": "unauthorized"})
            else:
                query = str(payload.get("query", ""))
                self._send(200, {
                    "query": query,
                    "results": [f"local-result:{query}"],
                    "source": "local-test-tool",
                })

        def log_message(self, fmt: str, *args: Any) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.tool_state = tool_state  # type: ignore[attr-defined]
    return server

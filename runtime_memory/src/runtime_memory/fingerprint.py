"""Stable operation fingerprints.

Two levels are used:

* ``scope``: environment + component/tool/action/target.  Used for transport,
  auth, rate-limit and service-level failures, where every query to the same
  endpoint should share one issue.
* ``call``: scope + a hash of the normalized arguments.  Used for schema,
  argument and data-level failures, where one bad query must not condemn the
  whole endpoint.

The error class is deliberately *not* part of the key: a preflight has to look
up known issues before it knows what error the next call will produce.  The
issue record stores ``error_class`` as an attribute instead.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path, PureWindowsPath
from urllib.parse import urlsplit

from .models import OperationRequest

VOLATILE_ARG_KEYS = {
    "timestamp", "ts", "nonce", "request_id", "trace_id", "span_id",
    "session_id", "run_id",
}
SECRET_ARG_KEYS = {
    "token", "access_token", "refresh_token", "password", "passwd", "pwd",
    "secret", "api_key", "apikey", "authorization", "cookie", "client_secret",
}


def _safe(value: str) -> str:
    return (value or "").strip().replace("|", "%7C").replace(" ", "_")


def normalize_target(target: str, component: str = "") -> str:
    """Reduce a target to the coordinate that should own an issue.

    URLs keep scheme/host/port plus the first path segment (so one MCP endpoint
    is not confused with another path on the same host).  Files keep their
    parent directory; shell/host targets keep the host string.
    """
    raw = (target or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        parts = urlsplit(raw)
        host = (parts.hostname or "").lower()
        port = f":{parts.port}" if parts.port else ""
        segments = [segment for segment in parts.path.split("/") if segment]
        first = f"/{segments[0]}" if segments else ""
        return f"{parts.scheme.lower()}://{host}{port}{first}"
    if re.match(r"^[A-Za-z]:[\\/]", raw):
        parent = PureWindowsPath(raw).parent.as_posix().rstrip("/")
        return parent or "/"
    if component == "file" or raw.startswith("/"):
        parent = Path(raw).parent.as_posix().rstrip("/")
        return parent or "/"
    return raw.split("?", 1)[0].split("#", 1)[0].strip().lower()


def normalize_args(args: dict | None) -> dict:
    """Drop volatile/secret keys and sort nested structures deterministically."""
    if not args:
        return {}

    def clean(value):
        if isinstance(value, dict):
            result = {}
            for key in sorted(value):
                lowered = str(key).lower()
                if lowered in VOLATILE_ARG_KEYS:
                    continue
                if lowered in SECRET_ARG_KEYS:
                    result[str(key)] = "[REDACTED]"
                else:
                    result[str(key)] = clean(value[key])
            return result
        if isinstance(value, (list, tuple)):
            return [clean(item) for item in value]
        if isinstance(value, str):
            return value.strip()
        return value

    return clean(args)


def args_hash(args: dict | None) -> str:
    payload = normalize_args(args)
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()[:16]


def _key_part(value: str) -> str:
    return _safe(value.casefold())


def scope_fingerprint(request: OperationRequest) -> str:
    parts = [
        _key_part(request.environment_id),
        "scope",
        _key_part(request.component),
        _key_part(request.tool),
        _key_part(request.action),
        _safe(normalize_target(request.target, request.component)),
    ]
    return "|".join(parts)


def call_fingerprint(request: OperationRequest) -> str:
    parts = [
        _key_part(request.environment_id),
        "call",
        _key_part(request.component),
        _key_part(request.tool),
        _key_part(request.action),
        _safe(normalize_target(request.target, request.component)),
        "args:" + args_hash(request.args),
    ]
    return "|".join(parts)


def fingerprint_for(request: OperationRequest, key_level: str) -> str:
    if key_level == "call":
        return call_fingerprint(request)
    return scope_fingerprint(request)


def scope_identity(request: OperationRequest) -> str:
    """Return the identity that owns a non-global issue.

    ``global`` issues have no identity. ``session`` issues are owned by the
    session id; ``agent`` issues by agent id (falling back to session id for
    older callers that do not set an agent id).
    """
    if request.scope == "global":
        return ""
    if request.scope == "agent":
        return (request.agent_id or request.session_id or "").strip()
    return (request.session_id or "").strip()

"""Exception-to-error-class mapping.

Classify from the exception type, HTTP status and call context, not from
free-text keywords alone.  Misclassifying ``invalid_args`` as ``unreachable``
would block a healthy endpoint for the wrong reason.
"""
from __future__ import annotations

import asyncio
import json
import socket

try:  # optional, only for callers that use a schema library
    from jsonschema import ValidationError as _JsonSchemaError  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    _JsonSchemaError = ()  # type: ignore


def classify_exception(exc: BaseException | None, context: dict | None = None) -> str:
    context = context or {}
    if exc is None:
        return context.get("error_class") or "unknown"
    if isinstance(exc, (ConnectionRefusedError, socket.gaierror, ConnectionResetError)):
        return "unreachable"
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return "timeout"
    if isinstance(exc, (PermissionError,)):
        return "permission"
    if isinstance(exc, (FileNotFoundError,)):
        return "not_found"
    if isinstance(exc, (json.JSONDecodeError,)):
        return "schema"
    if _JsonSchemaError and isinstance(exc, _JsonSchemaError):
        return "schema"
    status = getattr(exc, "status", None) or getattr(exc, "status_code", None) \
        or context.get("http_status")
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None
    if status in (401, 403):
        return "auth"
    if status == 429:
        return "rate_limit"
    if status == 404:
        return "not_found"
    if status is not None and 400 <= status < 500:
        return "invalid_args"
    if isinstance(exc, (TypeError, ValueError)) and context.get("source") == "args":
        return "invalid_args"
    return "unknown"


def diagnosis_for(error_class: str) -> str:
    if error_class in ("auth", "permission"):
        return "permission"
    if error_class in ("schema", "invalid_args"):
        return "model_usage"
    if error_class in ("not_found",):
        return "data"
    if error_class in ("unreachable", "timeout", "rate_limit", "internal"):
        return "environment"
    return "unknown"

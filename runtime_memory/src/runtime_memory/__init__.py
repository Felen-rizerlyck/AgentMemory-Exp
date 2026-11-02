"""Runtime memory: an independent B+Shadow prototype.

This package is intentionally separate from ``demo/``.  It records operational
tool/environment issues, aggregates them into retryable issues, and offers a
preflight gate that can run in shadow (recommend-only) or enforce mode.
"""
from __future__ import annotations

from .models import Decision, Issue, OperationEvent, OperationRequest
from .policy import Policy, default_policy
from .runtime import RuntimeMemory
from .store import DEFAULT_DATA_DIR, Store

__all__ = [
    "Decision",
    "Issue",
    "OperationEvent",
    "OperationRequest",
    "Policy",
    "RuntimeMemory",
    "Store",
    "DEFAULT_DATA_DIR",
    "default_policy",
]
__version__ = "0.1.0"

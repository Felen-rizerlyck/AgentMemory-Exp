"""Dataclasses for runtime-memory requests, events, issues and decisions.

The shapes here are intentionally close to the design document:
docs/RUNTIME_MEMORY_DESIGN.md, sections 5-7.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any

STATUSES = ("cooldown", "open", "probing", "mitigated", "resolved", "stale")
ACTIVE_STATUSES = ("cooldown", "open", "probing", "mitigated", "stale")
OUTCOMES = ("ok", "fail", "timeout", "denied")
FAILURE_OUTCOMES = ("fail", "timeout", "denied")
ACTIONS = ("allow", "allow_with_hint", "probe", "block")
KEY_LEVELS = ("scope", "call")
SCOPES = ("global", "session", "agent")


def _filtered(cls, data: dict[str, Any]):
    allowed = {item.name for item in fields(cls)}
    return cls(**{key: value for key, value in data.items() if key in allowed})


@dataclass
class OperationRequest:
    component: str
    tool: str
    action: str
    target: str
    args: dict[str, Any] = field(default_factory=dict)
    scope: str = "session"
    environment_id: str = "default"
    session_id: str = ""
    run_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class OperationEvent:
    event_id: str
    ts: str
    component: str
    tool: str
    action: str
    target: str
    outcome: str
    scope: str = "session"
    environment_id: str = "default"
    session_id: str = ""
    run_id: str = ""
    error_class: str = ""
    error_code: str = ""
    message_redacted: str = ""
    duration_ms: int = 0
    attempt: int = 1
    retryable: bool = False
    fingerprint: str = ""
    key_level: str = ""
    decision_id: str = ""
    would_block: bool = False
    evidence_ref: str = ""
    author: str = "harness"
    policy_version: str = ""
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "OperationEvent":
        return _filtered(cls, data)


@dataclass
class Issue:
    issue_id: str
    fingerprint: str
    key_level: str
    scope: str
    environment_id: str
    component: str
    tool: str
    action: str
    target: str
    error_class: str
    status: str
    first_seen: str
    last_seen: str
    count: int = 1
    attempts: int = 1
    retry_policy: dict[str, Any] = field(default_factory=dict)
    next_retry_at: str | None = None
    expires_at: str | None = None
    workaround: str = ""
    confidence: float = 0.0
    source_event_ids: list[str] = field(default_factory=list)
    last_probe_event_id: str | None = None
    probe_started_at: str | None = None
    diagnosis: str = ""
    resolution: str = ""
    resolved_at: str | None = None
    resolved_basis: str = ""
    reviewer: str = ""
    notes: list[dict[str, Any]] = field(default_factory=list)
    related_incident_id: str | None = None
    related_case_id: str | None = None
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Issue":
        return _filtered(cls, data)


@dataclass
class Decision:
    action: str
    fingerprint: str = ""
    issue_id: str = ""
    reason: str = ""
    blocked_until: str | None = None
    attempts_left: int = 0
    alternatives: list[str] = field(default_factory=list)
    confidence: float = 0.0
    expires_at: str | None = None
    policy_version: str = ""
    shadow: bool = False
    decision_id: str = ""
    override: bool = False
    override_basis: str = ""
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def allow(cls, fingerprint: str = "", shadow: bool = False,
              policy_version: str = "") -> "Decision":
        return cls(action="allow", fingerprint=fingerprint, shadow=shadow,
                   policy_version=policy_version)

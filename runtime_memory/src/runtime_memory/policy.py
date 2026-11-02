"""Retry policy: error class -> key level, retryability, backoff and TTL."""
from __future__ import annotations

import copy
import datetime as dt
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .timeutil import iso

DEFAULT_POLICY: dict[str, Any] = {
    "schema_version": 1,
    "policy_version": "2026-11-02.1",
    "enforce": False,
    "probe_timeout_s": 300,
    "defaults": {
        "cooldown_s": 300,
        "issue_ttl_s": 86400,
        "max_attempts_per_run": 3,
        "probe_after_expiry": True,
    },
    "budgets": {
        "max_attempts_per_call_key_per_run": 3,
        "max_failures_per_component_per_run": 10,
        "max_blocked_calls_per_run": 50,
    },
    "classes": {
        "unreachable": {
            "key_level": "scope", "retryable": True, "mode": "fixed",
            "base_s": 900, "max_s": 1800, "max_attempts": 3,
            "max_attempts_per_run": 1, "ttl_s": 86400,
        },
        "timeout": {
            "key_level": "call", "retryable": True, "mode": "exponential",
            "base_s": 30, "max_s": 300, "max_attempts": 3,
            "max_attempts_per_run": 3, "ttl_s": 3600,
        },
        "rate_limit": {
            "key_level": "scope", "retryable": True, "mode": "exponential",
            "base_s": 60, "max_s": 300, "max_attempts": 3,
            "max_attempts_per_run": 3, "ttl_s": 3600,
        },
        "auth": {
            "key_level": "scope", "retryable": False, "mode": "none",
            "base_s": 0, "max_s": 0, "max_attempts": 0,
            "max_attempts_per_run": 0, "ttl_s": 86400,
        },
        "permission": {
            "key_level": "scope", "retryable": False, "mode": "none",
            "base_s": 0, "max_s": 0, "max_attempts": 0,
            "max_attempts_per_run": 0, "ttl_s": 86400,
        },
        "schema": {
            "key_level": "call", "retryable": False, "mode": "none",
            "base_s": 0, "max_s": 0, "max_attempts": 0,
            "max_attempts_per_run": 0, "ttl_s": 86400,
        },
        "not_found": {
            "key_level": "call", "retryable": False, "mode": "none",
            "base_s": 0, "max_s": 0, "max_attempts": 0,
            "max_attempts_per_run": 0, "ttl_s": 3600,
        },
        "invalid_args": {
            "key_level": "call", "retryable": False, "mode": "none",
            "base_s": 0, "max_s": 0, "max_attempts": 0,
            "max_attempts_per_run": 0, "ttl_s": 3600,
        },
        "internal": {
            "key_level": "scope", "retryable": True, "mode": "fixed",
            "base_s": 60, "max_s": 600, "max_attempts": 1,
            "max_attempts_per_run": 1, "ttl_s": 3600,
        },
        "unknown": {
            "key_level": "scope", "retryable": True, "mode": "fixed",
            "base_s": 60, "max_s": 600, "max_attempts": 1,
            "max_attempts_per_run": 1, "ttl_s": 3600,
        },
    },
}

_REQUIRED_CLASS_FIELDS = ("key_level", "retryable", "mode", "max_attempts", "ttl_s")


def default_policy() -> dict[str, Any]:
    return copy.deepcopy(DEFAULT_POLICY)


@dataclass
class Policy:
    data: dict[str, Any] = field(default_factory=default_policy)

    @classmethod
    def load(cls, path: Path | str) -> "Policy":
        target = Path(path)
        if not target.exists():
            return cls(default_policy())
        loaded = json.loads(target.read_text(encoding="utf-8-sig"))
        if not isinstance(loaded, dict):
            raise ValueError(f"{target}: policy must be a JSON object")
        return cls(loaded)

    @property
    def version(self) -> str:
        return str(self.data.get("policy_version", "unknown"))

    @property
    def enforce(self) -> bool:
        return bool(self.data.get("enforce", False))

    @property
    def probe_timeout_s(self) -> int:
        return int(self.data.get("probe_timeout_s", 300))

    @property
    def budgets(self) -> dict[str, int]:
        merged = copy.deepcopy(DEFAULT_POLICY["budgets"])
        merged.update(self.data.get("budgets") or {})
        return {key: int(value) for key, value in merged.items()}

    def class_rule(self, error_class: str) -> dict[str, Any]:
        base = {
            "key_level": "scope",
            "retryable": False,
            "mode": "none",
            "base_s": 0,
            "max_s": 0,
            "max_attempts": 1,
            "max_attempts_per_run": 1,
            "ttl_s": 3600,
        }
        classes = self.data.get("classes") or {}
        rule = classes.get(error_class) or classes.get("unknown") or {}
        base.update(rule)
        return base

    def key_level(self, error_class: str) -> str:
        level = self.class_rule(error_class).get("key_level", "scope")
        return level if level in ("scope", "call") else "scope"

    def retryable(self, error_class: str) -> bool:
        return bool(self.class_rule(error_class).get("retryable", False))

    def ttl_s(self, error_class: str) -> int:
        return int(self.class_rule(error_class).get("ttl_s", 3600))

    def next_retry_at(self, error_class: str, attempts: int,
                      now: dt.datetime, retry_after_s: int | None = None) -> str | None:
        rule = self.class_rule(error_class)
        if not rule.get("retryable"):
            return None
        if retry_after_s is not None:
            delay = max(0, int(retry_after_s))
        else:
            mode = rule.get("mode", "fixed")
            base = int(rule.get("base_s", 0) or 0)
            maximum = int(rule.get("max_s", 0) or 0)
            if mode == "exponential":
                delay = base * (2 ** max(0, attempts - 1))
            elif mode == "fixed":
                delay = base
            else:
                return None
            if maximum:
                delay = min(delay, maximum)
        return iso(now + dt.timedelta(seconds=max(0, delay)))

    def expires_at(self, error_class: str, now: dt.datetime) -> str:
        return iso(now + dt.timedelta(seconds=self.ttl_s(error_class)))

    def retry_record(self, error_class: str, attempts: int, now: dt.datetime,
                     retry_after_s: int | None = None) -> dict[str, Any]:
        rule = self.class_rule(error_class)
        return {
            "key_level": self.key_level(error_class),
            "retryable": self.retryable(error_class),
            "mode": rule.get("mode", "none"),
            "base_s": int(rule.get("base_s", 0) or 0),
            "max_s": int(rule.get("max_s", 0) or 0),
            "max_attempts": int(rule.get("max_attempts", 0) or 0),
            "max_attempts_per_run": int(rule.get("max_attempts_per_run", 1) or 1),
            "ttl_s": self.ttl_s(error_class),
            "next_retry_at": self.next_retry_at(error_class, attempts, now, retry_after_s),
        }

    def validate(self) -> list[str]:
        problems: list[str] = []
        if not isinstance(self.data, dict):
            return ["policy must be a JSON object"]
        if not isinstance(self.data.get("enforce"), bool):
            problems.append("policy.enforce must be a boolean")
        classes = self.data.get("classes")
        if not isinstance(classes, dict) or not classes:
            problems.append("policy.classes must be a non-empty object")
            return problems
        for name, rule in classes.items():
            if not isinstance(rule, dict):
                problems.append(f"policy.classes.{name} must be an object")
                continue
            for field_name in _REQUIRED_CLASS_FIELDS:
                if field_name not in rule:
                    problems.append(f"policy.classes.{name} missing {field_name}")
            if rule.get("key_level") not in ("scope", "call"):
                problems.append(f"policy.classes.{name}.key_level must be scope|call")
            if rule.get("mode") not in ("none", "fixed", "exponential"):
                problems.append(f"policy.classes.{name}.mode must be none|fixed|exponential")
            if not isinstance(rule.get("retryable"), bool):
                problems.append(f"policy.classes.{name}.retryable must be boolean")
            for numeric in ("base_s", "max_s", "max_attempts", "max_attempts_per_run", "ttl_s"):
                if not isinstance(rule.get(numeric, 0), int):
                    problems.append(f"policy.classes.{name}.{numeric} must be an integer")
        if "unknown" not in classes:
            problems.append("policy.classes.unknown is required as a fallback")
        return problems

    def to_dict(self) -> dict[str, Any]:
        return copy.deepcopy(self.data)

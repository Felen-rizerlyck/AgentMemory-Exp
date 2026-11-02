"""Redaction for error messages before they are persisted or shown to a model."""
from __future__ import annotations

import re

_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"),
     r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:password|passwd|pwd|token|secret|api[_-]?key|"
                r"client_secret)\s*[=:]\s*)['\"]?[^\s'\";,]+"),
     r"\1[REDACTED]"),
    (re.compile(r"(?i)(cookie\s*:\s*)[^\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(://[^/\s:@]+:)[^@\s]+@"), r"\1[REDACTED]@"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                re.S), "[REDACTED PRIVATE KEY]"),
]


def redact(message: str | None, limit: int = 500) -> str:
    text = str(message or "")
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    text = " ".join(text.split())
    if limit and len(text) > limit:
        text = text[:limit] + "…"
    return text

"""Redaction for error messages and URL targets before persistence."""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SECRET_KEYS = (
    "password", "passwd", "pwd", "token", "access_token", "refresh_token",
    "secret", "client_secret", "api_key", "apikey", "authorization", "cookie",
)

_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+"),
     r"\1[REDACTED]"),
    # JSON form: {"password": "value", "token": "value"}
    (re.compile(
        r'(?i)("(?:' + "|".join(_SECRET_KEYS) + r')"\s*:\s*")(?:\\.|[^"\\])*(")'),
     r"\1[REDACTED]\2"),
    # Query-string form: ?token=value&password=value (inside URLs in messages)
    (re.compile(
        r'(?i)([?&](?:' + "|".join(_SECRET_KEYS) + r')=)[^&\s]+'),
     r"\1[REDACTED]"),
    # Key=value / key: value form
    (re.compile(
        r"(?i)((?:password|passwd|pwd|token|secret|api[_-]?key|"
        r"client_secret)\s*[=:]\s*)['\"]?[^\s'\";,]+"),
     r"\1[REDACTED]"),
    (re.compile(r"(?i)(cookie\s*:\s*)[^\n]+"), r"\1[REDACTED]"),
    # URL userinfo: https://user:pass@host
    (re.compile(r"(?i)(://[^/\s:@]+:)[^@\s]+@"), r"\1[REDACTED]@"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                re.S), "[REDACTED PRIVATE KEY]"),
]
_SENSITIVE_QUERY_KEYS = {key.casefold() for key in _SECRET_KEYS}


def redact(message: str | None, limit: int = 500) -> str:
    text = str(message or "")
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    text = " ".join(text.split())
    if limit and len(text) > limit:
        text = text[:limit] + "…"
    return text


def redact_target(target: str | None) -> str:
    """Redact credentials embedded in a target.

    Stored targets are shown in decisions/reports, so URL userinfo and known
    secret query parameters must never survive.  Non-URL targets are passed
    through the normal message redaction (without truncation).
    """
    raw = str(target or "")
    if "://" not in raw:
        return redact(raw, limit=0)
    parts = urlsplit(raw)
    netloc = parts.netloc
    if "@" in netloc:
        _, host = netloc.rsplit("@", 1)
        netloc = "[REDACTED]@" + host
    query = ""
    if parts.query:
        pairs = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            if key.casefold() in _SENSITIVE_QUERY_KEYS:
                pairs.append((key, "[REDACTED]"))
            else:
                pairs.append((key, value))
        query = urlencode(pairs, doseq=True).replace("%5BREDACTED%5D", "[REDACTED]")
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))

"""Small time/id helpers shared by the runtime-memory prototype."""
from __future__ import annotations

import datetime as dt
import uuid


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso(value: dt.datetime | None = None) -> str:
    value = value or utcnow()
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def new_id(prefix: str, now: dt.datetime | None = None) -> str:
    stamp = (now or utcnow()).strftime("%Y%m%dT%H%M%S")
    return f"{prefix}-{stamp}-{uuid.uuid4().hex[:6].upper()}"

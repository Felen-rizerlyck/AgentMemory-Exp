"""Case lifecycle ledger: alias merge, split, retire and reactivate.

A merge is deliberately conservative: the source becomes a retired alias of the
target; links and steps are not rewritten. This keeps the existing evidence and
makes the operation reversible.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import storage

LIFECYCLE_PATH = storage.DATA_DIR / "case_lifecycle.json"
ACTIONS = ("merge", "split", "retire", "reactivate")


def _empty() -> dict:
    return {"schema_version": 1, "events": []}


def load_lifecycle(path: Path | str | None = None) -> dict:
    target = Path(path) if path is not None else LIFECYCLE_PATH
    if not target.exists():
        return _empty()
    data = json.loads(target.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("events"), list):
        raise ValueError(f"{target}: lifecycle ledger must contain an events list")
    return data


def save_lifecycle(data: dict, path: Path | str | None = None) -> None:
    target = Path(path) if path is not None else LIFECYCLE_PATH
    storage.atomic_write_json(target, data)


def build_record(action: str, case_id: str, basis: str, reviewer: str = "agent",
                 target: str = "", candidate_ids: list[str] | None = None,
                 data: dict | None = None) -> tuple[dict, dict]:
    """Append one lifecycle event to a loaded ledger *without* saving it.

    Returning the ledger lets callers commit patterns + candidates + lifecycle in one
    transaction, so a merge/split cannot leave a half-applied store behind.
    """
    if action not in ACTIONS:
        raise ValueError(f"unsupported lifecycle action: {action}")
    ledger = data if data is not None else _empty()
    if not isinstance(ledger, dict) or not isinstance(ledger.get("events"), list):
        raise ValueError("lifecycle ledger must contain an events list")
    event = {
        "event_id": f"LIF-{len(ledger['events']) + 1:04d}",
        "action": action,
        "case_id": case_id,
        "target": target,
        "basis": basis,
        "reviewer": reviewer,
        "candidate_ids": sorted(candidate_ids or []),
        "created_at": _now_iso(),
    }
    ledger["events"].append(event)
    return ledger, event


def record(action: str, case_id: str, basis: str, reviewer: str = "agent",
           target: str = "", candidate_ids: list[str] | None = None,
           path: Path | str | None = None) -> dict:
    data = load_lifecycle(path)
    data, event = build_record(action, case_id, basis, reviewer, target=target,
                               candidate_ids=candidate_ids, data=data)
    save_lifecycle(data, path)
    return event


def latest_merge(case_id: str, path: Path | str | None = None,
                 data: dict | None = None) -> dict | None:
    ledger = data if data is not None else load_lifecycle(path)
    for event in reversed(ledger["events"]):
        if event.get("action") == "merge" and event.get("case_id") == case_id:
            return event
    return None


def audit_lifecycle(patterns: list[dict], path: Path | str | None = None) -> list[str]:
    problems: list[str] = []
    data = load_lifecycle(path)
    by_case = {pattern["case_id"]: pattern for pattern in patterns}
    latest: dict[str, dict] = {}
    seen_ids: set[str] = set()
    for event in data["events"]:
        event_id = event.get("event_id")
        if not event_id or event_id in seen_ids:
            problems.append(f"lifecycle: duplicate or missing event_id {event_id!r}")
            continue
        seen_ids.add(event_id)
        action = event.get("action")
        if action not in ACTIONS:
            problems.append(f"{event_id}: unsupported action {action!r}")
            continue
        case_id = event.get("case_id")
        if case_id not in by_case:
            problems.append(f"{event_id}: unknown case_id {case_id!r}")
            continue
        latest[case_id] = event
    for case_id, event in latest.items():
        pattern = by_case[case_id]
        action = event["action"]
        status = pattern.get("status", "active")
        if action == "merge":
            target = event.get("target")
            target_pattern = by_case.get(target)
            if target_pattern is None:
                problems.append(f"{event['event_id']}: target {target!r} does not exist")
            elif target_pattern.get("status") == "retired":
                problems.append(f"{event['event_id']}: target {target} is retired")
            elif target_pattern.get("family_id") != pattern.get("family_id"):
                problems.append(f"{event['event_id']}: source and target are in different families")
            if status != "retired" or pattern.get("merged_into") != target:
                problems.append(f"{event['event_id']}: {case_id} should be retired into {target}")
        elif action == "split":
            if status != "active" or pattern.get("merged_into"):
                problems.append(f"{event['event_id']}: {case_id} should be active with no merged_into")
        elif action == "retire":
            if status != "retired" or pattern.get("merged_into"):
                problems.append(f"{event['event_id']}: {case_id} should be retired without merged_into")
        elif action == "reactivate":
            if status != "active":
                problems.append(f"{event['event_id']}: {case_id} should be active")
    return problems


def _now_iso() -> str:
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

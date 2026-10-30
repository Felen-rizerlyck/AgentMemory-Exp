"""Negative memory: the reviewed ledger of "this is *not* that case".

A link says *how* an event relates to a case. A correction says *why a match was
rejected*: which prior decision it overturns, which evidence was insufficient, and on
whose authority. Keeping that decision in a ledger is the difference between a memory
that only remembers successes and one that remembers the boundaries it has already
tested. Corrections are never deleted; a later review appends a new record.

Ledger shape (``demo/data/corrections.json``)::

    {
      "schema_version": 1,
      "corrections": [
        {"correction_id": "COR-0001", "incident_id": "INC-...", "case_id": "CASE-005",
         "decision": "reject_match", "reason_code": "generic_only",
         "event_ids": ["EVT-..."], "basis": "only a shared whoami probe",
         "reviewer": "analyst", "decided_at": "...Z", "created_at": "...Z"}
      ]
    }
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from . import storage

CORRECTIONS_PATH = storage.DATA_DIR / "corrections.json"
PATTERNS_PATH = storage.PATTERNS_PATH
RAW_LOGS_PATH = storage.RAW_LOGS_PATH
LINKS_PATH = storage.LINKS_PATH

# A rejected match is the common case; reject_case covers "this incident is not this
# case at all", which still belongs in the same auditable ledger.
DECISIONS = ("reject_match", "reject_case")
REASON_CODES = ("generic_only", "source_mismatch", "incomplete_chain", "wrong_family",
                "insufficient_evidence", "other")


def _empty_store() -> dict:
    return {"schema_version": 1, "corrections": []}


def load_corrections(path: Path | str | None = None) -> dict:
    """Load the ledger; a missing file is an empty ledger, a malformed one is an error."""
    target = Path(path) if path is not None else CORRECTIONS_PATH
    data = storage.load_json(target, None)
    if data is None:
        return _empty_store()
    if not isinstance(data, dict) or not isinstance(data.get("corrections"), list):
        raise ValueError(f"{target}: correction store must contain a corrections list")
    version = data.get("schema_version", 1)
    if isinstance(version, bool) or not isinstance(version, int) or version < 1:
        raise ValueError(f"{target}: schema_version must be a positive integer")
    return data


def _next_id(corrections: list[dict]) -> str:
    used = {correction.get("correction_id") for correction in corrections}
    index = 1
    while f"COR-{index:04d}" in used:
        index += 1
    return f"COR-{index:04d}"


def _patterns(patterns: list[dict] | None) -> list[dict]:
    if patterns is not None:
        return patterns
    return storage.load_patterns(Path(PATTERNS_PATH))["attack_patterns"]


def _logs(logs: list[dict[str, str]] | None) -> list[dict[str, str]]:
    if logs is not None:
        return logs
    path = Path(RAW_LOGS_PATH)
    return storage.read_csv(path) if path.exists() else []


def _links(links: list[dict[str, str]] | None) -> list[dict[str, str]]:
    if links is not None:
        return links
    path = Path(LINKS_PATH)
    return storage.read_csv(path) if path.exists() else []


def _incident_ids(logs: list[dict[str, str]], links: list[dict[str, str]]) -> set[str]:
    """An incident exists as a raw-log label or as a reviewed/related link."""
    ids = {(row.get("incident_id") or "").strip() for row in logs}
    ids |= {(row.get("incident_id") or "").strip() for row in links}
    ids.discard("")
    return ids


def _validate_target(incident_id: str, case_id: str, event_ids: list[str],
                     patterns: list[dict], logs: list[dict[str, str]],
                     links: list[dict[str, str]]) -> None:
    case_ids = {pattern.get("case_id") for pattern in patterns}
    if case_id not in case_ids:
        raise ValueError(f"unknown case_id: {case_id}")
    if incident_id not in _incident_ids(logs, links):
        raise ValueError(f"unknown incident_id: {incident_id}")
    rows_by_id = {row.get("event_id"): row for row in logs}
    missing = [event_id for event_id in event_ids if event_id not in rows_by_id]
    if missing:
        raise ValueError(f"Unknown event_id(s): {', '.join(sorted(missing))}")
    for event_id in event_ids:
        labeled = (rows_by_id[event_id].get("incident_id") or "").strip()
        if labeled and labeled != incident_id:
            raise ValueError(
                f"{event_id} belongs to incident {labeled}, not {incident_id}; "
                "record the correction against the right incident")


def _duplicate(corrections: list[dict], record: dict) -> dict | None:
    for existing in corrections:
        if (existing.get("incident_id") == record["incident_id"]
                and existing.get("case_id") == record["case_id"]
                and existing.get("decision") == record["decision"]
                and existing.get("reason_code") == record["reason_code"]
                and sorted(existing.get("event_ids") or []) == record["event_ids"]):
            return existing
    return None


def add_correction(incident_id: str, case_id: str, reason_code: str,
                   event_ids: list[str] | None = None, decision: str = "reject_match",
                   basis: str = "", reviewer: str = "agent",
                   *, patterns: list[dict] | None = None, logs: list[dict[str, str]] | None = None,
                   links: list[dict[str, str]] | None = None,
                   path: Path | str | None = None) -> dict:
    """Record one reviewed rejection; requires a reason, a basis and an existing target."""
    incident_id = (incident_id or "").strip()
    case_id = (case_id or "").strip()
    reason_code = (reason_code or "").strip()
    decision = (decision or "").strip()
    basis = (basis or "").strip()
    reviewer = (reviewer or "agent").strip() or "agent"
    if not incident_id:
        raise ValueError("correction incident_id must not be empty")
    if not case_id:
        raise ValueError("correction case_id must not be empty")
    if decision not in DECISIONS:
        raise ValueError(f"unsupported decision {decision!r}; expected one of {', '.join(DECISIONS)}")
    if reason_code not in REASON_CODES:
        raise ValueError(
            f"unsupported reason_code {reason_code!r}; expected one of {', '.join(REASON_CODES)}")
    if not basis:
        raise ValueError("correction basis must not be empty: say why the match is rejected")
    events = sorted({(event or "").strip() for event in event_ids or []} - {""})

    data = load_corrections(path)
    corrections = data["corrections"]
    _validate_target(incident_id, case_id, events, _patterns(patterns), _logs(logs),
                     _links(links))
    stamp = storage.now_iso()
    record = {
        "correction_id": _next_id(corrections),
        "incident_id": incident_id,
        "case_id": case_id,
        "decision": decision,
        "reason_code": reason_code,
        "event_ids": events,
        "basis": basis,
        "reviewer": reviewer,
        "decided_at": stamp,
        "created_at": stamp,
    }
    duplicate = _duplicate(corrections, record)
    if duplicate is not None:
        raise ValueError(
            f"correction {duplicate.get('correction_id')} already records this exact rejection")
    updated = copy.deepcopy(data)
    updated["corrections"].append(record)
    target = Path(path) if path is not None else CORRECTIONS_PATH
    storage.commit([storage.Write.json(target, updated)], kind="correction",
                   summary=f"record correction {record['correction_id']}: "
                           f"{decision} {case_id} <- {incident_id} ({reason_code})",
                   basis=basis)
    return copy.deepcopy(record)


def list_corrections(case_id: str | None = None, incident_id: str | None = None,
                     path: Path | str | None = None) -> list[dict]:
    items = load_corrections(path)["corrections"]
    if case_id is not None:
        wanted = (case_id or "").strip()
        items = [item for item in items if (item.get("case_id") or "").strip() == wanted]
    if incident_id is not None:
        wanted = (incident_id or "").strip()
        items = [item for item in items if (item.get("incident_id") or "").strip() == wanted]
    return copy.deepcopy(items)


def for_case(case_id: str, incident_id: str | None = None,
             path: Path | str | None = None) -> list[dict]:
    """Prior rejections relevant to a case (optionally narrowed to one incident).

    This is the read path used before recalling a case as a precedent: a prior
    correction is not a precedent, it is a boundary already tested.
    """
    if not (case_id or "").strip():
        return []
    return list_corrections(case_id=case_id, incident_id=incident_id, path=path)


def summary_line(correction: dict) -> str:
    """One stable, human-readable line for CLI output and diagnostics."""
    correction_id = correction.get("correction_id") or "COR-????"
    decision = correction.get("decision") or "reject_match"
    return (f"{correction_id} {decision} {correction.get('case_id') or '-'} <- "
            f"{correction.get('incident_id') or '-'} "
            f"reason={correction.get('reason_code') or '-'} "
            f"basis={correction.get('basis') or '-'} "
            f"reviewer={correction.get('reviewer') or '-'} "
            f"at={correction.get('decided_at') or '-'}")


def audit_corrections(patterns: list[dict], logs: list[dict[str, str]],
                      links: list[dict[str, str]] | None = None,
                      path: Path | str | None = None) -> list[str]:
    """Check that every correction still points at a real case, incident and event.

    The ledger is a claim about the world; if the world moved (or a record was written
    by hand), the claim must start failing loudly instead of being silently recalled.
    """
    try:
        data = load_corrections(path)
    except (ValueError, json.JSONDecodeError) as error:
        return [f"corrections: {error}"]
    links = _links(links)
    problems: list[str] = []
    case_ids = {pattern.get("case_id") for pattern in patterns}
    incident_ids = _incident_ids(logs, links)
    rows_by_id = {row.get("event_id"): row for row in logs}
    seen_ids: set[str] = set()
    seen_records: set[tuple] = set()
    for number, correction in enumerate(data["corrections"], start=1):
        label = f"correction line {number}"
        if not isinstance(correction, dict):
            problems.append(f"{label}: record must be a JSON object")
            continue
        correction_id = (correction.get("correction_id") or "").strip()
        if not correction_id:
            problems.append(f"{label}: missing correction_id")
        elif correction_id in seen_ids:
            problems.append(f"{label}: duplicate correction_id {correction_id!r}")
        seen_ids.add(correction_id)
        incident_id = (correction.get("incident_id") or "").strip()
        case_id = (correction.get("case_id") or "").strip()
        if not incident_id:
            problems.append(f"{label}: missing incident_id")
        elif incident_id not in incident_ids:
            problems.append(f"{label}: unknown incident_id {incident_id!r}")
        if not case_id:
            problems.append(f"{label}: missing case_id")
        elif case_id not in case_ids:
            problems.append(f"{label}: unknown case_id {case_id!r}")
        decision = (correction.get("decision") or "").strip()
        if decision not in DECISIONS:
            problems.append(f"{label}: unsupported decision {decision!r}")
        reason_code = (correction.get("reason_code") or "").strip()
        if reason_code not in REASON_CODES:
            problems.append(f"{label}: unsupported reason_code {reason_code!r}")
        basis = (correction.get("basis") or "").strip()
        if not basis:
            problems.append(f"{label}: missing basis (a rejection needs a stated reason)")
        if not (correction.get("reviewer") or "").strip():
            problems.append(f"{label}: missing reviewer")
        if not (correction.get("decided_at") or "").strip():
            problems.append(f"{label}: missing decided_at")
        events = correction.get("event_ids") or []
        if not isinstance(events, list) or any(not isinstance(event_id, str) or not event_id.strip()
                                               for event_id in events):
            problems.append(f"{label}: event_ids must be a list of non-empty strings")
            events = []
        missing_events = [event_id for event_id in events if event_id not in rows_by_id]
        if missing_events:
            problems.append(f"{label}: unknown event_id(s) {', '.join(sorted(missing_events))}")
        for event_id in events:
            row = rows_by_id.get(event_id) or {}
            labeled = (row.get("incident_id") or "").strip()
            if labeled and incident_id and labeled != incident_id:
                problems.append(
                    f"{label}: event {event_id} belongs to incident {labeled}, not {incident_id}")
        key = (incident_id, case_id, decision, reason_code, tuple(sorted(events)))
        if key in seen_records:
            problems.append(f"{label}: duplicate correction for {case_id} <- {incident_id}")
        seen_records.add(key)
    return problems

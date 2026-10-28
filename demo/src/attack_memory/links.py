"""Reviewed links, labels, and derived counts."""
from __future__ import annotations

import re

from . import families as family_store
from . import storage
from .catalog import load_validated_catalog, now_iso
from .storage import (LINK_FIELDS, LINK_STATUSES, append_csv, latest_link_by_event, read_csv,
                      read_links, update_event_labels, validate_event_labels)


def _event_content(event_id: str, rows_by_id: dict[str, dict[str, str]]) -> str:
    return rows_by_id[event_id].get("content") or ""


def append_links(event_ids: list[str], incident_id: str, case_id: str,
                 step_id: str = "", status: str = "confirmed", basis: str = "",
                 force: bool = False) -> int:
    if status not in LINK_STATUSES:
        raise ValueError(f"Unsupported link status: {status}")
    patterns = load_validated_catalog()["attack_patterns"]
    pattern = next((p for p in patterns if p["case_id"] == case_id), None)
    if pattern is None:
        raise ValueError(f"Unknown case_id: {case_id}")
    step = None
    if step_id:
        step = next((s for s in pattern["steps"] if s["step_id"] == step_id), None)
        if step is None:
            step = family_store.step_for_case(case_id, step_id, patterns)
            if step is None:
                raise ValueError(f"Unknown step_id for {case_id}: {step_id}")
            if status != "related":
                raise ValueError(f"{case_id}/{step_id} is a family step; only related links are allowed")
    elif status != "related":
        raise ValueError("step_id is required unless the status is related")
    rows_by_id = {row.get("event_id", ""): row for row in read_csv(storage.RAW_LOGS_PATH)}
    missing = set(event_ids) - set(rows_by_id)
    if missing:
        raise ValueError(f"Unknown event_id(s): {', '.join(sorted(missing))}")
    if step is not None:
        regex = re.compile(step["action_regex"])
        not_matching = [event_id for event_id in event_ids
                        if regex.search(_event_content(event_id, rows_by_id)) is None]
        if not_matching and not force:
            raise ValueError(
                f"event(s) {', '.join(sorted(not_matching))} do not match {case_id}/{step_id} action_regex; "
                "check the step choice, or pass --force with a basis that explains the exception"
            )
    if status == "confirmed":
        validate_event_labels(set(event_ids), case_id, incident_id)
    decided_at = now_iso()
    rows = [{"event_id": event_id, "incident_id": incident_id, "case_id": case_id,
             "step_id": step_id, "action_id": step["action_id"] if step else "",
             "link_status": status, "link_basis": basis, "decided_at": decided_at}
            for event_id in event_ids]
    append_csv(storage.LINKS_PATH, LINK_FIELDS, rows)
    if status in {"confirmed", "rejected"}:
        try:
            update_event_labels(set(event_ids), case_id, incident_id, status)
        except Exception:
            raise RuntimeError(
                "The reviewed link row was appended but the raw-log labels were not updated. "
                "Fix the reported error and rerun the same command; the link history is append-only."
            )
    return len(rows)


def audit_links(patterns: list[dict], logs: list[dict[str, str]],
                links: list[dict[str, str]]) -> list[str]:
    """Check that every reviewed link still points at an event that contains its step."""
    problems: list[str] = []
    known_events = {row.get("event_id", ""): row for row in logs}
    case_ids = {pattern["case_id"] for pattern in patterns}
    steps = {(pattern["case_id"], step["step_id"]): (pattern, step)
             for pattern in patterns for step in pattern["steps"]}
    family_data = family_store.load_families()
    family_steps = {}
    for pattern in patterns:
        for step in family_store.family_steps(family_data, pattern.get("family_id")):
            family_steps[(pattern["case_id"], step["step_id"])] = step
    for number, link in enumerate(links, start=2):
        event_id = (link.get("event_id") or "").strip()
        case_id = (link.get("case_id") or "").strip()
        step_id = (link.get("step_id") or "").strip()
        status = (link.get("link_status") or "").strip()
        if status not in LINK_STATUSES:
            problems.append(f"link line {number}: unsupported status {status!r}")
        row = known_events.get(event_id)
        if row is None:
            problems.append(f"link line {number}: unknown event_id {event_id!r}")
            continue
        if status == "related" and not step_id:
            if case_id not in case_ids:
                problems.append(f"link line {number}: related link names unknown case_id {case_id!r}")
            continue
        pair = steps.get((case_id, step_id))
        is_family_step = False
        if pair is None:
            step = family_steps.get((case_id, step_id))
            if step is None:
                problems.append(f"link line {number}: unknown {case_id}/{step_id} step")
                continue
            if status not in ("related", "rejected"):
                problems.append(
                    f"link line {number}: {case_id}/{step_id} is a family step; only related links are allowed")
            is_family_step = True
        else:
            _, step = pair
        if link.get("action_id") != step["action_id"]:
            problems.append(
                f"link line {number}: action_id {link.get('action_id')!r} does not match "
                f"{case_id}/{step_id} ({step['action_id']})"
            )
        if re.search(step["action_regex"], row.get("content") or "") is None and status != "rejected":
            problems.append(
                f"link line {number}: event {event_id} content does not contain "
                f"{case_id}/{step_id} action_regex; the recorded step is wrong"
            )
        if status == "confirmed":
            incident_id = (link.get("incident_id") or "").strip()
            if ((row.get("case_id") or "").strip() != case_id
                    or (row.get("incident_id") or "").strip() != incident_id):
                problems.append(f"link line {number}: event {event_id} labels do not match its confirmed link")
    return problems


def derived_observations(links: list[dict[str, str]], case_id: str) -> tuple[int, int]:
    """Return (distinct confirmed real incidents, fixture link count) for one case."""
    incidents = {(link.get("incident_id") or "").strip() for link in links
                 if (link.get("case_id") or "").strip() == case_id
                 and (link.get("link_status") or "").strip() == "confirmed"}
    incidents.discard("")
    fixtures = sum(1 for link in links
                   if (link.get("case_id") or "").strip() == case_id
                   and (link.get("link_status") or "").strip() == "fixture")
    return len(incidents), fixtures


def confirmed_pairs(links: list[dict[str, str]]) -> set[tuple[str, str]]:
    pairs = set()
    for link in links:
        if (link.get("link_status") or "").strip() != "confirmed":
            continue
        incident = (link.get("incident_id") or "").strip()
        case_id = (link.get("case_id") or "").strip()
        if incident and case_id:
            pairs.add((incident, case_id))
    return pairs


def support_pairs(links: list[dict[str, str]]) -> set[tuple[str, str]]:
    """Confirmed and related incidents both count as evidence for pattern evolution."""
    pairs = set()
    for link in links:
        if (link.get("link_status") or "").strip() not in ("confirmed", "related"):
            continue
        incident = (link.get("incident_id") or "").strip()
        case_id = (link.get("case_id") or "").strip()
        if incident and case_id:
            pairs.add((incident, case_id))
    return pairs


def related_incidents(links: list[dict[str, str]], case_id: str) -> set[str]:
    """Incidents associated with a case only through a related link."""
    related = {(link.get("incident_id") or "").strip() for link in links
               if (link.get("link_status") or "").strip() == "related"
               and (link.get("case_id") or "").strip() == case_id}
    confirmed = {incident for incident, case in confirmed_pairs(links) if case == case_id}
    related.discard("")
    return related - confirmed

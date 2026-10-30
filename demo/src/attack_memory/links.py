"""Reviewed links, force exceptions, labels, and derived counts.

A forced link is a *reviewed exception*: the operator decided the step is right even
though the detector regex does not match. The link row alone cannot say that, and a
store that silently fails audit after a legitimate review is worse than one that
refuses the write. So the exception lives in an append-only-on-write sidecar ledger
(``data/link_exceptions.json``) and audit stays honest: exceptions are exempted *and*
counted, never hidden.
"""
from __future__ import annotations

import pathlib
import re

from . import families as family_store
from . import storage
from .catalog import load_validated_catalog
from .storage import LINK_FIELDS, LINK_STATUSES, validate_event_labels

LINK_EXCEPTIONS_PATH = storage.DATA_DIR / "link_exceptions.json"
EXCEPTION_SCHEMA_VERSION = 1
EXCEPTION_KEY_FIELDS = ("event_id", "incident_id", "case_id", "step_id")


def _empty_exceptions() -> dict:
    return {"schema_version": EXCEPTION_SCHEMA_VERSION, "exceptions": []}


def load_exceptions(path: pathlib.Path | str | None = None) -> dict:
    """Load the force-exception ledger; a missing file is an empty ledger."""
    target = pathlib.Path(path) if path is not None else LINK_EXCEPTIONS_PATH
    data = storage.load_json(target, _empty_exceptions())
    if not isinstance(data, dict) or not isinstance(data.get("exceptions"), list):
        raise ValueError(f"{target}: link exception ledger must contain an exceptions list")
    return data


def exception_key(record: dict) -> tuple[str, str, str, str]:
    """Identity of one reviewed exception; decided_at is stored but not part of the key."""
    return tuple((record.get(field) or "").strip() for field in EXCEPTION_KEY_FIELDS)


def _accepted_keys(data: dict) -> set[tuple[str, str, str, str]]:
    """Only a reviewed exception with a written basis may waive an audit problem."""
    return {exception_key(record) for record in data["exceptions"]
            if (record.get("basis") or "").strip()}


def force_exceptions(links: list[dict[str, str]]) -> list[dict]:
    """Exceptions that currently waive a real link row: the visible forced count.

    An exception without a matching non-rejected link row is *not* counted here; it is
    an orphan and ``audit_link_exceptions`` reports it instead.
    """
    data = load_exceptions()
    accepted = _accepted_keys(data)
    keyed_links = {exception_key(link): link for link in links}
    waiving: list[dict] = []
    for record in data["exceptions"]:
        key = exception_key(record)
        if key not in accepted:
            continue
        link = keyed_links.get(key)
        if link is None:
            continue
        if (link.get("link_status") or "").strip() == "rejected":
            continue
        waiving.append(record)
    return waiving


def audit_link_exceptions(links: list[dict[str, str]]) -> list[str]:
    """Every exception must point at a live reviewed link row and carry a basis."""
    problems: list[str] = []
    data = load_exceptions()
    keyed_links = {exception_key(link): link for link in links}
    seen: set[tuple[str, str, str, str]] = set()
    for number, record in enumerate(data["exceptions"], start=1):
        key = exception_key(record)
        label = "/".join(part or "-" for part in key)
        if not (record.get("basis") or "").strip():
            problems.append(f"exception #{number} ({label}): missing basis")
        if key in seen:
            problems.append(f"exception #{number} ({label}): duplicate exception key")
        seen.add(key)
        link = keyed_links.get(key)
        if link is None:
            problems.append(
                f"exception #{number} ({label}): no matching link row; "
                "the exception is orphaned and should be removed"
            )
            continue
        if (link.get("link_status") or "").strip() == "rejected":
            problems.append(
                f"exception #{number} ({label}): link is rejected, "
                "so the exception is unused"
            )
    return problems


def _mismatching_events(event_ids: list[str], regex: re.Pattern,
                        rows_by_id: dict[str, dict[str, str]]) -> list[str]:
    return [event_id for event_id in event_ids
            if regex.search(rows_by_id[event_id].get("content") or "") is None]


def append_links(event_ids: list[str], incident_id: str, case_id: str,
                 step_id: str = "", status: str = "confirmed", basis: str = "",
                 force: bool = False,
                 reviewer: str = "analyst") -> int:
    """Append reviewed links, exceptions and derived labels in one transaction."""
    if status not in LINK_STATUSES:
        raise ValueError(f"Unsupported link status: {status}")
    patterns = load_validated_catalog()["attack_patterns"]
    pattern = next((item for item in patterns if item["case_id"] == case_id), None)
    if pattern is None:
        raise ValueError(f"Unknown case_id: {case_id}")
    step = None
    if step_id:
        step = next((item for item in pattern["steps"] if item["step_id"] == step_id), None)
        if step is None:
            step = family_store.step_for_case(case_id, step_id, patterns)
            if step is None:
                raise ValueError(f"Unknown step_id for {case_id}: {step_id}")
            if status != "related":
                raise ValueError(f"{case_id}/{step_id} is a family step; only related links are allowed")
    elif status != "related":
        raise ValueError("step_id is required unless the status is related")
    rows_by_id = {row.get("event_id", ""): row for row in storage.read_csv(storage.RAW_LOGS_PATH)}
    missing = set(event_ids) - set(rows_by_id)
    if missing:
        raise ValueError(f"Unknown event_id(s): {', '.join(sorted(missing))}")
    not_matching: list[str] = []
    if step is not None:
        not_matching = _mismatching_events(event_ids, re.compile(step["action_regex"]), rows_by_id)
        if not_matching and not force:
            raise ValueError(
                f"event(s) {', '.join(sorted(not_matching))} do not match {case_id}/{step_id} "
                "action_regex; check the step choice, or pass --force with a reviewed --basis"
            )
        if not_matching and force and not (basis or "").strip():
            raise ValueError(
                "a forced link needs a non-empty --basis explaining the reviewed exception; "
                "an unexplained exception would make audit trust without evidence"
            )
    if status == "confirmed":
        validate_event_labels(set(event_ids), case_id, incident_id)

    decided_at = storage.now_iso()
    link_rows = [{"event_id": event_id, "incident_id": incident_id, "case_id": case_id,
                  "step_id": step_id, "action_id": step["action_id"] if step else "",
                  "link_status": status, "link_basis": basis, "decided_at": decided_at}
                 for event_id in event_ids]
    writes = [storage.Write.csv_append(storage.LINKS_PATH, LINK_FIELDS, link_rows)]

    # A rejected link is already exempt from the step-regex replay, so it does not need
    # (or get) an exception; writing one would create a permanently unused record.
    exception_rows: list[dict] = []
    if not_matching and force and status != "rejected":
        exception_rows = [{"event_id": event_id, "incident_id": incident_id,
                           "case_id": case_id, "step_id": step_id,
                           "decided_at": decided_at, "basis": basis.strip(),
                           "reviewer": reviewer or "analyst"}
                          for event_id in not_matching]
        ledger = load_exceptions()
        existing = {exception_key(record) for record in ledger["exceptions"]}
        for record in exception_rows:
            if exception_key(record) not in existing:
                ledger["exceptions"].append(record)
                existing.add(exception_key(record))
        writes.append(storage.Write.json(LINK_EXCEPTIONS_PATH, ledger))

    if status in {"confirmed", "rejected"}:
        # Labels are a derived cache of the reviewed links: rebuild them in the same
        # transaction so a crash cannot leave "link says confirmed, event says unlabelled".
        fieldnames, current_rows = storage._read_csv_strict(storage.RAW_LOGS_PATH)
        new_rows, changed = storage.apply_label_changes(
            current_rows, set(event_ids), case_id, incident_id, status)
        if changed:
            writes.append(storage.Write.csv_replace(storage.RAW_LOGS_PATH, fieldnames, new_rows))

    storage.commit(
        writes, kind="link_append",
        summary=(f"{status} link(s) {case_id}/{step_id or '-'} "
                 f"for incident {incident_id} ({len(event_ids)} event(s))"
                 + (f", {len(exception_rows)} force exception(s)" if exception_rows else "")),
        basis=basis,
    )
    return len(link_rows)


def audit_links(patterns: list[dict], logs: list[dict[str, str]],
                links: list[dict[str, str]],
                exceptions: dict | None = None) -> list[str]:
    """Check that every reviewed link still points at an event that contains its step.

    A force exception with a non-empty basis exempts the exact link row it names; the
    count is surfaced separately via :func:`force_exceptions`, never swallowed.
    """
    problems: list[str] = []
    accepted = _accepted_keys(exceptions if exceptions is not None else load_exceptions())
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
            if exception_key(link) not in accepted:
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

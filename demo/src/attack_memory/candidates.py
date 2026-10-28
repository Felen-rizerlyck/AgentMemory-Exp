"""Staging area for techniques that are not cases yet.

A candidate is one behavioural signature with one or more incidents. One incident
makes it `provisional`; a second independent incident makes it `promotable`.
Promotion still requires an authored, schema-valid pattern: this module only
tracks the evidence and the state, it does not invent a pattern.
"""
from __future__ import annotations

import copy
import datetime as dt
import json
from pathlib import Path

from . import storage

CANDIDATES_PATH = storage.DATA_DIR / "case_candidates.json"
CANDIDATE_STATUSES = ("provisional", "promotable", "promoted", "rejected", "merged")
MIN_PROMOTION_INCIDENTS = 2


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _empty_store() -> dict:
    return {"schema_version": 1, "candidates": []}


def load_candidates(path: Path | str | None = None) -> dict:
    target = Path(path) if path is not None else CANDIDATES_PATH
    if not target.exists():
        return _empty_store()
    data = json.loads(target.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("candidates"), list):
        raise ValueError(f"{target}: candidate store must contain a candidates list")
    return data


def save_candidates(data: dict, path: Path | str | None = None) -> None:
    target = Path(path) if path is not None else CANDIDATES_PATH
    storage.atomic_write_json(target, data)


def _next_id(candidates: list[dict]) -> str:
    used = {candidate.get("candidate_id") for candidate in candidates}
    index = 1
    while f"CAND-{index:04d}" in used:
        index += 1
    return f"CAND-{index:04d}"


def candidate_level(incident_count: int) -> str:
    if incident_count >= MIN_PROMOTION_INCIDENTS:
        return "promotable"
    if incident_count == 1:
        return "provisional"
    return "rejected"


def _refresh_status(candidate: dict) -> None:
    if candidate.get("status") in ("promoted", "merged"):
        return
    candidate["status"] = candidate_level(len(candidate.get("incidents") or []))


def get_candidate(candidate_id: str, path: Path | str | None = None) -> dict:
    for candidate in load_candidates(path)["candidates"]:
        if candidate.get("candidate_id") == candidate_id:
            return candidate
    raise ValueError(f"unknown candidate: {candidate_id}")


def upsert_candidate(signature: str, label: str, incident_id: str, event_ids: list[str],
                     source_batch: str = "", family_id: str = "",
                     path: Path | str | None = None) -> dict:
    """Add or merge one incident into the candidate with this signature."""
    signature = (signature or "").strip()
    incident_id = (incident_id or "").strip()
    if not signature:
        raise ValueError("candidate signature must not be empty")
    if not incident_id:
        raise ValueError("candidate incident_id must not be empty")
    events = sorted({(event or "").strip() for event in event_ids} - {""})
    if not events:
        raise ValueError(f"candidate {signature}: incident {incident_id} has no event IDs")
    data = load_candidates(path)
    candidates = data["candidates"]
    candidate = next((item for item in candidates
                      if item.get("signature") == signature and item.get("status") != "merged"), None)
    stamp = now_iso()
    if candidate is None:
        candidate = {
            "candidate_id": _next_id(candidates),
            "signature": signature,
            "label": label or signature,
            "family_id": family_id or "",
            "status": "provisional",
            "incidents": [],
            "created_at": stamp,
            "updated_at": stamp,
            "promoted_case_id": None,
        }
        candidates.append(candidate)
    if family_id:
        candidate["family_id"] = family_id
    merged = next((item for item in candidate["incidents"]
                   if item.get("incident_id") == incident_id), None)
    if merged is None:
        candidate["incidents"].append({
            "incident_id": incident_id,
            "event_ids": events,
            "source_batch": source_batch,
            "first_seen": stamp,
        })
    else:
        merged["event_ids"] = events
        merged["source_batch"] = source_batch or merged.get("source_batch", "")
    if not candidate.get("label"):
        candidate["label"] = label or signature
    candidate["updated_at"] = stamp
    _refresh_status(candidate)
    save_candidates(data, path)
    return copy.deepcopy(candidate)


def mark_promoted(candidate_id: str, case_id: str, path: Path | str | None = None) -> dict:
    data = load_candidates(path)
    candidate = next((item for item in data["candidates"]
                      if item.get("candidate_id") == candidate_id), None)
    if candidate is None:
        raise ValueError(f"unknown candidate: {candidate_id}")
    if candidate.get("status") == "promoted":
        raise ValueError(f"{candidate_id} is already promoted to {candidate.get('promoted_case_id')}")
    candidate["status"] = "promoted"
    candidate["promoted_case_id"] = case_id
    candidate["updated_at"] = now_iso()
    save_candidates(data, path)
    return copy.deepcopy(candidate)


def list_candidates(status: str | None = None, path: Path | str | None = None,
                    include_merged: bool = False) -> list[dict]:
    items = load_candidates(path)["candidates"]
    if status:
        items = [item for item in items if item.get("status") == status]
    elif not include_merged:
        items = [item for item in items if item.get("status") != "merged"]
    return items


def merge_candidates(primary_id: str, alias_id: str, basis: str,
                     path: Path | str | None = None) -> dict:
    """Merge an alias into a primary within the same family and signature_key."""
    data = load_candidates(path)
    by_id = {item.get("candidate_id"): item for item in data["candidates"]}
    primary = by_id.get(primary_id)
    alias = by_id.get(alias_id)
    if primary is None:
        raise ValueError(f"unknown primary candidate: {primary_id}")
    if alias is None:
        raise ValueError(f"unknown alias candidate: {alias_id}")
    if primary_id == alias_id:
        raise ValueError("cannot merge a candidate into itself")
    if primary.get("status") in ("merged", "rejected"):
        raise ValueError(f"{primary_id} is {primary.get('status')} and cannot be a merge primary")
    if alias.get("status") in ("merged", "promoted"):
        raise ValueError(f"{alias_id} is {alias.get('status')} and cannot be merged")
    if (primary.get("family_id") or "") != (alias.get("family_id") or ""):
        raise ValueError("candidates must share a family before merging")
    primary_key = primary.get("signature_key")
    alias_key = alias.get("signature_key")
    if primary_key and alias_key and primary_key != alias_key:
        raise ValueError("candidates have different signature_key values")
    if not primary_key and not alias_key and primary.get("signature") != alias.get("signature"):
        raise ValueError("candidates have different legacy signatures")

    incidents = {item["incident_id"]: item for item in primary.get("incidents") or []}
    alias_incidents = []
    for incident in alias.get("incidents") or []:
        incident_id = incident["incident_id"]
        alias_incidents.append(incident_id)
        if incident_id not in incidents:
            incidents[incident_id] = copy.deepcopy(incident)
        else:
            union = set(incidents[incident_id].get("event_ids") or []) | set(incident.get("event_ids") or [])
            incidents[incident_id]["event_ids"] = sorted(union)
    primary["incidents"] = list(incidents.values())
    primary["merged_from"] = sorted(set(primary.get("merged_from") or []) | {alias_id})
    primary["aliases"] = sorted(set(primary.get("aliases") or []) | {alias_id})
    terms = list(primary.get("signature_terms") or [])
    for term in alias.get("signature_terms") or []:
        if term not in terms:
            terms.append(term)
    primary["signature_terms"] = terms
    if primary.get("status") == "promoted":
        pending = list(primary.get("pending_case_links") or [])
        for incident_id in alias_incidents:
            if incident_id not in pending:
                pending.append(incident_id)
        primary["pending_case_links"] = pending
    else:
        _refresh_status(primary)
    primary["updated_at"] = now_iso()
    alias["status"] = "merged"
    alias["merged_into"] = primary_id
    alias["merged_basis"] = basis
    alias["merged_at"] = now_iso()
    save_candidates(data, path)
    return copy.deepcopy(primary)


def split_candidate(primary_id: str, alias_id: str, basis: str,
                    path: Path | str | None = None) -> dict:
    """Undo a merge; the alias keeps its own incident records."""
    data = load_candidates(path)
    by_id = {item.get("candidate_id"): item for item in data["candidates"]}
    primary = by_id.get(primary_id)
    alias = by_id.get(alias_id)
    if primary is None or alias is None:
        raise ValueError("unknown primary or alias candidate")
    if alias.get("merged_into") != primary_id:
        raise ValueError(f"{alias_id} is not merged into {primary_id}")
    if primary.get("status") == "promoted":
        raise ValueError("cannot split a promoted cluster; link the incident to the case instead")
    alias_ids = {incident["incident_id"] for incident in alias.get("incidents") or []}
    primary["incidents"] = [incident for incident in primary.get("incidents") or []
                            if incident["incident_id"] not in alias_ids]
    primary["merged_from"] = [item for item in primary.get("merged_from") or [] if item != alias_id]
    primary["aliases"] = [item for item in primary.get("aliases") or [] if item != alias_id]
    primary["pending_case_links"] = [item for item in primary.get("pending_case_links") or []
                                     if item not in alias_ids]
    _refresh_status(primary)
    primary["updated_at"] = now_iso()
    alias["status"] = candidate_level(len(alias.get("incidents") or []))
    alias["merged_into"] = None
    alias["merged_basis"] = ""
    alias["merged_at"] = None
    alias["split_basis"] = basis
    alias["updated_at"] = now_iso()
    save_candidates(data, path)
    return copy.deepcopy(primary)


def counts(path: Path | str | None = None) -> dict[str, int]:
    result = {status: 0 for status in CANDIDATE_STATUSES}
    for item in load_candidates(path)["candidates"]:
        result[item.get("status", "provisional")] = result.get(item.get("status", "provisional"), 0) + 1
    return result


def audit_candidates(patterns: list[dict], path: Path | str | None = None,
                     family_ids: set[str] | None = None) -> list[str]:
    """Cheap consistency checks; the candidate's evidence rows are checked by add_pattern."""
    problems: list[str] = []
    data = load_candidates(path)
    seen_ids: set[str] = set()
    case_ids = {pattern["case_id"] for pattern in patterns}
    by_id = {item.get("candidate_id"): item for item in data["candidates"]}
    for candidate in data["candidates"]:
        cid = candidate.get("candidate_id")
        if not cid or cid in seen_ids:
            problems.append(f"candidate: duplicate or missing candidate_id {cid!r}")
            continue
        seen_ids.add(cid)
        family_id = candidate.get("family_id")
        if family_id and family_ids is not None and family_id not in family_ids:
            problems.append(f"{cid}: unknown family_id {family_id!r}")
        incidents = candidate.get("incidents") or []
        incident_ids = {item.get("incident_id") for item in incidents}
        status = candidate.get("status")
        if status == "merged":
            target = by_id.get(candidate.get("merged_into"))
            if target is None:
                problems.append(f"{cid}: merged_into points at a missing candidate")
                continue
            if target.get("status") == "merged":
                problems.append(f"{cid}: merged_into points at another merged candidate")
            if cid not in (target.get("merged_from") or []):
                problems.append(f"{cid}: merged_into target does not list it in merged_from")
            target_incidents = {item.get("incident_id") for item in target.get("incidents") or []}
            if not incident_ids <= target_incidents:
                problems.append(f"{cid}: merged incidents are missing from {target.get('candidate_id')}")
            continue
        expected = candidate_level(len(incidents))
        if status == "promoted":
            case_id = candidate.get("promoted_case_id")
            if case_id not in case_ids:
                problems.append(f"{cid}: promoted to missing case {case_id!r}")
            pending = set(candidate.get("pending_case_links") or [])
            if not pending <= incident_ids:
                problems.append(f"{cid}: pending_case_links contains an unknown incident")
        elif status != expected:
            problems.append(f"{cid}: status={status} but {len(incidents)} incident(s) "
                            f"imply {expected}")
        aliases = candidate.get("aliases") or []
        merged_from = candidate.get("merged_from") or []
        if set(aliases) != set(merged_from):
            problems.append(f"{cid}: aliases and merged_from disagree")
        for alias_id in aliases:
            alias = by_id.get(alias_id)
            if alias is None:
                problems.append(f"{cid}: alias {alias_id} does not exist")
            elif alias.get("merged_into") != cid:
                problems.append(f"{cid}: alias {alias_id} does not point back")
        for incident in incidents:
            if not incident.get("event_ids"):
                problems.append(f"{cid}: incident {incident.get('incident_id')!r} has no event IDs")
    return problems

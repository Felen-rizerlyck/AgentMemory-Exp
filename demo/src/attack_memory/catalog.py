"""Pattern catalog, versions, support coverage, and new-case admission.

Two promises live here:

* a *new case* needs required-step evidence union across independent incidents, and at
  least one incident that is strong/medium on its own (or an explicit reviewed force);
* every accepted version has an immutable snapshot, starting with ``v001`` at creation,
  so rollback never has to invent history.
"""
from __future__ import annotations

import copy
import json
import pathlib
from collections import defaultdict

from . import admissions as admission_store
from . import candidates as candidate_store
from . import lifecycle as lifecycle_store
from . import storage
from .retrieval import build_action_index, extract_log_actions, match_pattern
from .storage import (latest_link_by_event, load_patterns, read_csv, read_links,
                      validate_pattern)

VERSIONS_DIR = storage.DATA_DIR / "pattern_versions"
MIN_SUPPORT_INCIDENTS = 2
MATURITY_REPEATED = 2
MATURITY_VALIDATED = 3
MIN_STRONG_TIERS = ("strong", "medium")
# Review markers are administrative state, not pattern content: keeping them out of
# snapshots lets a review happen without turning v001 into "different content".
SNAPSHOT_VOLATILE_FIELDS = ("review_status", "reviewed_at", "reviewed_by")


def maturity(incident_count: int) -> str:
    if incident_count >= MATURITY_VALIDATED:
        return "validated"
    if incident_count >= MATURITY_REPEATED:
        return "repeated"
    return "single_sample"


def now_iso() -> str:
    """Kept for backwards-compatible imports; the implementation lives in storage."""
    return storage.now_iso()


def pattern_version(pattern: dict) -> int:
    return int(pattern.get("version", 1))


def version_path(case_id: str, version: int) -> pathlib.Path:
    return VERSIONS_DIR / case_id / f"v{version:03d}.json"


def load_validated_catalog() -> dict:
    """Validate each pattern and the cross-pattern action library before any write."""
    data = load_patterns(storage.PATTERNS_PATH)
    build_action_index(data["attack_patterns"])
    return data


# ---------------------------------------------------------------------------
# Version snapshots
# ---------------------------------------------------------------------------

def snapshot_payload(pattern: dict, version: int | None = None) -> dict:
    """Immutable snapshot content: pattern data minus administrative review markers."""
    data = copy.deepcopy(pattern)
    for field in SNAPSHOT_VOLATILE_FIELDS:
        data.pop(field, None)
    data["version"] = pattern_version(pattern) if version is None else version
    return data


def version_snapshot(pattern: dict, version: int | None = None) -> tuple[pathlib.Path, dict]:
    """Return (path, payload) and refuse to overwrite a snapshot with new history."""
    target_version = pattern_version(pattern) if version is None else version
    path = version_path(pattern["case_id"], target_version)
    data = snapshot_payload(pattern, target_version)
    if path.exists():
        existing = storage.load_json(path)
        existing_version = existing.get("version") if isinstance(existing, dict) else None
        if not isinstance(existing_version, int) or isinstance(existing_version, bool):
            existing_version = target_version
        if snapshot_payload(existing, existing_version) != data:
            raise ValueError(
                f"version snapshot {path} exists with different content; "
                "refusing to rewrite history"
            )
    return path, data


def write_version_snapshot(pattern: dict) -> pathlib.Path:
    path, data = version_snapshot(pattern)
    if not path.exists():
        storage.atomic_write_json(path, data)
    return path


# ---------------------------------------------------------------------------
# New-case support gate
# ---------------------------------------------------------------------------

def _match_ready(pattern: dict) -> dict:
    """Normalize optional step fields so the retrieval matcher can judge evidence."""
    data = copy.deepcopy(pattern)
    data.setdefault("case_id", "CASE-000")
    data.setdefault("name", data["case_id"])
    data.setdefault("summary", "")
    data.setdefault("mitre", [])
    data.setdefault("retrieval", {})
    steps = data.get("steps") or []
    if not isinstance(steps, list):
        return data
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            continue
        step.setdefault("step_id", f"S{index}")
        step.setdefault("order", index)
        step.setdefault("action_id", f"{data['case_id']}-action-{index}")
        step.setdefault("expected_sources", ["any"])
        step.setdefault("required", True)
    return data


def group_events_by_incident(logs: list[dict[str, str]],
                             links: list[dict[str, str]] | None = None,
                             incident_ids: set[str] | None = None) -> dict[str, list[dict[str, str]]]:
    """All events owned by an incident, including unlabeled ones owned by a reviewed link."""
    latest = latest_link_by_event(links or [])
    wanted = set(incident_ids) if incident_ids is not None else None
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in logs:
        owners: set[str] = set()
        direct = (row.get("incident_id") or "").strip()
        if direct:
            owners.add(direct)
        link = latest.get((row.get("event_id") or "").strip()) or {}
        if (link.get("link_status") or "").strip() in ("confirmed", "related", "fixture"):
            incident = (link.get("incident_id") or "").strip()
            if incident:
                owners.add(incident)
        for incident in owners:
            if wanted is None or incident in wanted:
                grouped[incident].append(row)
    if wanted is not None:
        for incident in wanted:
            grouped.setdefault(incident, [])
    return dict(grouped)


def pattern_support_report(pattern: dict, supporting_incident_ids: list[str] | None,
                           logs: list[dict[str, str]], force: bool = False,
                           events_by_incident: dict[str, list[dict[str, str]]] | None = None) -> dict:
    """Deterministic evidence report for a new case; raises when the gate rejects it.

    The gate is *required-step union coverage across independent incidents* plus *at
    least one incident that is strong/medium by itself*. ``force`` is the reviewed
    exception: it may waive weak coverage, but the admission records the partial
    observation (``single_sample`` + per-incident coverage) instead of hiding it.
    """
    ids = sorted({(item or "").strip() for item in (supporting_incident_ids or [])} - {""})
    match_ready = _match_ready(pattern)
    required_ids = [step["step_id"] for step in match_ready["steps"]
                    if step.get("required", True)]
    if not force and len(ids) < MIN_SUPPORT_INCIDENTS:
        raise ValueError(
            f"a new pattern needs at least {MIN_SUPPORT_INCIDENTS} supporting incidents; "
            "pass --supporting-incident-ids, or --force for a reviewed singleton"
        )
    if not ids:
        return {
            "incidents": [], "coverage": {}, "covered_required": [],
            "required_steps": required_ids, "missing_required": list(required_ids),
            "has_strong_medium": False, "single_sample": True,
        }
    by_incident = (events_by_incident if events_by_incident is not None
                   else group_events_by_incident(logs))
    unknown = [incident for incident in ids if not by_incident.get(incident)]
    if unknown:
        raise ValueError(f"unknown or unlabeled incident(s): {', '.join(unknown)}")
    index = build_action_index([match_ready])
    coverage: dict[str, dict] = {}
    covered_union: set[str] = set()
    for incident in ids:
        rows = by_incident[incident]
        result = match_pattern(match_ready, rows, extract_log_actions(rows, index))
        covered = {entry["step_id"] for entry in result["evidence"]
                   if entry.get("required", True)}
        covered_union |= covered
        coverage[incident] = {
            "covered_required": sorted(covered),
            "required_total": len(required_ids),
            "coverage": (round(len(covered) / len(required_ids), 3) if required_ids else 0.0),
            "tier": result["tier"],
        }
    no_match = [incident for incident in ids if not coverage[incident]["covered_required"]]
    if no_match:
        raise ValueError(
            f"no event of incident(s) {', '.join(no_match)} matches the new pattern's steps; "
            "the pattern is not supported by that incident"
        )
    missing = [step_id for step_id in required_ids if step_id not in covered_union]
    has_strong_medium = any(coverage[incident]["tier"] in MIN_STRONG_TIERS
                            for incident in ids)
    if not force:
        if missing:
            raise ValueError(
                f"required step(s) {', '.join(missing)} have no supporting event; "
                "stage the technique as a candidate, add the missing evidence, or "
                "pass --force for a reviewed singleton"
            )
        if not has_strong_medium:
            raise ValueError(
                "no supporting incident reaches strong/medium tier on its own; "
                "the case is a partial observation, so stage it as a candidate first"
            )
    return {
        "incidents": ids,
        "coverage": coverage,
        "covered_required": sorted(covered_union),
        "required_steps": required_ids,
        "missing_required": missing,
        "has_strong_medium": has_strong_medium,
        "single_sample": bool(force and (len(ids) < MIN_SUPPORT_INCIDENTS
                                         or missing or not has_strong_medium)),
    }


def require_pattern_support(pattern: dict, supporting_incident_ids: list[str] | None,
                            logs: list[dict[str, str]], force: bool = False,
                            events_by_incident: dict[str, list[dict[str, str]]] | None = None) -> list[str]:
    """Compatibility wrapper: validate support and return the accepted incident IDs."""
    report = pattern_support_report(pattern, supporting_incident_ids, logs, force=force,
                                    events_by_incident=events_by_incident)
    return report["incidents"]


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------

def _build_pattern_writes(pattern: dict, supporting_incident_ids: list[str] | None,
                          logs: list[dict[str, str]], force: bool,
                          events_by_incident: dict[str, list[dict[str, str]]] | None,
                          source: str) -> tuple[str, list[storage.Write], dict]:
    """Validate a new pattern and render every file effect, without touching disk."""
    validate_pattern(pattern)
    data = load_validated_catalog()
    case_id = pattern["case_id"]
    if any(item["case_id"] == case_id for item in data["attack_patterns"]):
        raise ValueError(f"case_id already exists: {case_id}")
    if pattern.get("version") not in (None, 1):
        raise ValueError(f"{case_id}: a new pattern must start at version 1")
    report = pattern_support_report(pattern, supporting_incident_ids, logs, force=force,
                                    events_by_incident=events_by_incident)
    pattern = copy.deepcopy(pattern)
    pattern["version"] = 1
    admission = admission_store.build_admission(
        case_id, source=source, basis="experimental auto-add; awaiting review", support=report)
    stamp = storage.now_iso()
    provenance = dict(pattern.get("provenance") or {})
    provenance.setdefault("created_at", stamp)
    provenance.setdefault("source", source)
    provenance["updated_at"] = stamp
    provenance["admission_id"] = admission["admission_id"]
    pattern["provenance"] = provenance
    pattern["review_status"] = "unreviewed"
    pattern["admission_id"] = admission["admission_id"]
    data["attack_patterns"].append(pattern)
    # Raises on a shared action_id with a different regex or generic flag.
    build_action_index(data["attack_patterns"])
    admission_data = admission_store.load_admissions()
    admission_store.insert_admission(admission_data, admission)
    snapshot_path, snapshot_data = version_snapshot(pattern)
    writes = [
        storage.Write.json(storage.PATTERNS_PATH, data),
        storage.Write.json(admission_store.ADMISSIONS_PATH, admission_data),
        storage.Write.json(snapshot_path, snapshot_data),
    ]
    return case_id, writes, report


def add_pattern(pattern_file, supporting_incident_ids: list[str] | None = None,
                force: bool = False, events_by_incident: dict[str, list[dict[str, str]]] | None = None,
                source: str = "catalog_add") -> str:
    pattern = json.loads(pathlib.Path(pattern_file).read_text(encoding="utf-8-sig"))
    logs = read_csv(storage.RAW_LOGS_PATH)
    case_id, writes, report = _build_pattern_writes(
        pattern, supporting_incident_ids, logs, force, events_by_incident, source)
    storage.commit(
        writes, kind="catalog_add",
        summary=(f"add {case_id} v001 ({len(report['incidents'])} support incident(s), "
                 f"single_sample={report['single_sample']})"),
        basis=source,
    )
    return case_id


def add_pattern_from_candidate(candidate_id: str, pattern_file,
                               force: bool = False) -> tuple[str, dict]:
    """Promote a staged candidate: the whole incident (not just staged events) is evidence."""
    candidate = candidate_store.get_candidate(candidate_id)
    if candidate.get("status") == "promoted":
        raise ValueError(f"{candidate_id} is already promoted to {candidate.get('promoted_case_id')}")
    if candidate.get("status") == "merged":
        raise ValueError(f"{candidate_id} is merged into {candidate.get('merged_into')}; promote the primary")
    if candidate.get("status") == "rejected":
        raise ValueError(f"{candidate_id} was rejected; stage it again with a reviewed signature")
    incidents = [item["incident_id"] for item in candidate.get("incidents") or []]
    if len(incidents) < candidate_store.MIN_PROMOTION_INCIDENTS and not force:
        raise ValueError(
            f"{candidate_id} has {len(incidents)} incident(s); promotion needs "
            f"{candidate_store.MIN_PROMOTION_INCIDENTS}, or --force for a reviewed singleton"
        )
    logs = read_csv(storage.RAW_LOGS_PATH)
    links = read_links(storage.LINKS_PATH)
    rows_by_id = {row["event_id"]: row for row in logs}
    missing = [event_id for item in candidate.get("incidents") or []
               for event_id in item.get("event_ids") or [] if event_id not in rows_by_id]
    if missing:
        raise ValueError(f"{candidate_id}: unknown event ID(s) {', '.join(missing[:5])}")
    # Coverage is judged on every event the incident owns; staged event IDs are only the
    # lower bound the reviewer explicitly looked at.
    events_by_incident = group_events_by_incident(logs, links, set(incidents))
    for item in candidate.get("incidents") or []:
        incident = item["incident_id"]
        seen = {row["event_id"] for row in events_by_incident.get(incident, [])}
        for event_id in item.get("event_ids") or []:
            if event_id not in seen:
                events_by_incident.setdefault(incident, []).append(rows_by_id[event_id])
                seen.add(event_id)
    pattern = json.loads(pathlib.Path(pattern_file).read_text(encoding="utf-8-sig"))
    source = f"candidate:{candidate_id}"
    case_id, writes, report = _build_pattern_writes(
        pattern, incidents, logs, force, events_by_incident, source)
    candidates_data = candidate_store.load_candidates()
    promoted = None
    for item in candidates_data["candidates"]:
        if item.get("candidate_id") != candidate_id:
            continue
        if item.get("status") == "promoted":
            raise ValueError(f"{candidate_id} is already promoted to {item.get('promoted_case_id')}")
        item["status"] = "promoted"
        item["promoted_case_id"] = case_id
        item["updated_at"] = storage.now_iso()
        promoted = copy.deepcopy(item)
    if promoted is None:
        raise ValueError(f"unknown candidate: {candidate_id}")
    writes.append(storage.Write.json(candidate_store.CANDIDATES_PATH, candidates_data))
    storage.commit(
        writes, kind="candidate_promote",
        summary=(f"promote {candidate_id} to {case_id} v001 "
                 f"({report['incidents']} incident(s), single_sample={report['single_sample']})"),
        basis=source,
    )
    return case_id, promoted


# ---------------------------------------------------------------------------
# Review / lifecycle (catalog content changes)
# ---------------------------------------------------------------------------

def review_case(case_id: str, basis: str, reviewer: str = "human") -> dict:
    """Human review of an auto-added case: clear the marker, keep the admission id."""
    data = load_validated_catalog()
    pattern = next((item for item in data["attack_patterns"] if item["case_id"] == case_id), None)
    if pattern is None:
        raise ValueError(f"unknown case_id: {case_id}")
    if pattern.get("review_status") != "unreviewed":
        raise ValueError(f"{case_id} is not awaiting review")
    record = admission_store.review_admission(case_id, basis, reviewer=reviewer)
    pattern.pop("review_status", None)
    pattern["reviewed_at"] = record["reviewed_at"]
    pattern["reviewed_by"] = reviewer
    storage.atomic_write_json(storage.PATTERNS_PATH, data)
    return record


def active_patterns(patterns: list[dict]) -> list[dict]:
    return [pattern for pattern in patterns if pattern.get("status", "active") != "retired"]


def retire_case(case_id: str, basis: str, reviewer: str = "agent") -> dict:
    data = load_validated_catalog()
    pattern = next((item for item in data["attack_patterns"] if item["case_id"] == case_id), None)
    if pattern is None:
        raise ValueError(f"unknown case_id: {case_id}")
    if pattern.get("status") == "retired":
        raise ValueError(f"{case_id} is already retired")
    if pattern.get("merged_into"):
        raise ValueError(f"{case_id} is merged into {pattern['merged_into']}; split it first")
    pattern["status"] = "retired"
    pattern["retired_at"] = now_iso()
    pattern["retired_basis"] = basis
    pattern["retired_by"] = reviewer
    storage.atomic_write_json(storage.PATTERNS_PATH, data)
    return {"case_id": case_id, "status": "retired",
            "event": lifecycle_store.record("retire", case_id, basis, reviewer)}


def reactivate_case(case_id: str, basis: str, reviewer: str = "agent") -> dict:
    data = load_validated_catalog()
    pattern = next((item for item in data["attack_patterns"] if item["case_id"] == case_id), None)
    if pattern is None:
        raise ValueError(f"unknown case_id: {case_id}")
    if pattern.get("status") != "retired":
        raise ValueError(f"{case_id} is not retired")
    if pattern.get("merged_into"):
        raise ValueError(f"{case_id} is merged into {pattern['merged_into']}; use split")
    pattern["status"] = "active"
    pattern.pop("retired_at", None)
    pattern.pop("retired_basis", None)
    pattern.pop("retired_by", None)
    storage.atomic_write_json(storage.PATTERNS_PATH, data)
    return {"case_id": case_id, "status": "active",
            "event": lifecycle_store.record("reactivate", case_id, basis, reviewer)}


def merge_case(source_id: str, target_id: str, basis: str, reviewer: str = "agent") -> dict:
    data = load_validated_catalog()
    source = next((item for item in data["attack_patterns"] if item["case_id"] == source_id), None)
    target = next((item for item in data["attack_patterns"] if item["case_id"] == target_id), None)
    if source is None or target is None:
        raise ValueError("unknown source or target case")
    if source_id == target_id:
        raise ValueError("cannot merge a case into itself")
    if source.get("status") == "retired":
        raise ValueError(f"{source_id} is already retired")
    if target.get("status") == "retired":
        raise ValueError(f"target {target_id} is retired")
    if (source.get("family_id") or "") != (target.get("family_id") or ""):
        raise ValueError("merge requires the same family")
    candidates = candidate_store.load_candidates()
    candidate_ids = [item["candidate_id"] for item in candidates["candidates"]
                     if item.get("promoted_case_id") == source_id]
    for item in candidates["candidates"]:
        if item.get("promoted_case_id") == source_id:
            item["promoted_case_id"] = target_id
    source["status"] = "retired"
    source["merged_into"] = target_id
    source["merged_at"] = now_iso()
    source["merged_basis"] = basis
    source["retired_at"] = now_iso()
    source["retired_basis"] = basis
    source["retired_by"] = reviewer
    lifecycle_data = lifecycle_store.load_lifecycle()
    lifecycle_data, event = lifecycle_store.build_record(
        "merge", source_id, basis, reviewer, target=target_id,
        candidate_ids=candidate_ids, data=lifecycle_data)
    storage.commit(
        [
            storage.Write.json(storage.PATTERNS_PATH, data),
            storage.Write.json(candidate_store.CANDIDATES_PATH, candidates),
            storage.Write.json(lifecycle_store.LIFECYCLE_PATH, lifecycle_data),
        ],
        kind="merge_case",
        summary=f"merge {source_id} into {target_id}",
        basis=basis,
    )
    return {"case_id": source_id, "target": target_id, "status": "retired",
            "candidate_ids": candidate_ids, "event": event}


def split_case(case_id: str, basis: str, reviewer: str = "agent") -> dict:
    data = load_validated_catalog()
    pattern = next((item for item in data["attack_patterns"] if item["case_id"] == case_id), None)
    if pattern is None:
        raise ValueError(f"unknown case_id: {case_id}")
    target = pattern.get("merged_into")
    if not target:
        raise ValueError(f"{case_id} is not merged")
    lifecycle_data = lifecycle_store.load_lifecycle()
    merge_event = lifecycle_store.latest_merge(case_id, data=lifecycle_data)
    candidate_ids = (merge_event or {}).get("candidate_ids") or []
    candidates = candidate_store.load_candidates()
    for item in candidates["candidates"]:
        if item.get("candidate_id") in candidate_ids and item.get("promoted_case_id") == target:
            item["promoted_case_id"] = case_id
    pattern["status"] = "active"
    pattern.pop("merged_into", None)
    pattern.pop("merged_at", None)
    pattern.pop("merged_basis", None)
    pattern.pop("retired_at", None)
    pattern.pop("retired_basis", None)
    pattern.pop("retired_by", None)
    lifecycle_data, event = lifecycle_store.build_record(
        "split", case_id, basis, reviewer, target=target,
        candidate_ids=candidate_ids, data=lifecycle_data)
    storage.commit(
        [
            storage.Write.json(storage.PATTERNS_PATH, data),
            storage.Write.json(candidate_store.CANDIDATES_PATH, candidates),
            storage.Write.json(lifecycle_store.LIFECYCLE_PATH, lifecycle_data),
        ],
        kind="split_case",
        summary=f"split {case_id} from {target}",
        basis=basis,
    )
    return {"case_id": case_id, "target": target, "status": "active",
            "candidate_ids": candidate_ids, "event": event}


# ---------------------------------------------------------------------------
# Audits: versions, aliases, snapshot backfill
# ---------------------------------------------------------------------------

def audit_versions(patterns: list[dict]) -> list[str]:
    """Every case must have an immutable snapshot for each version 1..current."""
    problems: list[str] = []
    for pattern in patterns:
        case_id = pattern["case_id"]
        current = pattern_version(pattern)
        for number in range(1, current + 1):
            path = version_path(case_id, number)
            if not path.exists():
                problems.append(f"{case_id}: missing v{number:03d} snapshot")
                continue
            try:
                snapshot = json.loads(path.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError) as error:
                problems.append(f"{case_id}: v{number:03d} snapshot is unreadable ({error})")
                continue
            if not isinstance(snapshot, dict):
                problems.append(f"{case_id}: v{number:03d} snapshot is not an object")
                continue
            if snapshot.get("version", 1) != number:
                problems.append(
                    f"{case_id}: v{number:03d} snapshot records version "
                    f"{snapshot.get('version')!r}")
            if (snapshot.get("case_id") or "") != case_id:
                problems.append(
                    f"{case_id}: v{number:03d} snapshot case_id is "
                    f"{(snapshot.get('case_id') or '<missing>')!r}")
    return problems


def audit_aliases(patterns: list[dict]) -> list[str]:
    """``merged_into`` must point at a known case and never form a cycle."""
    problems: list[str] = []
    case_ids = {pattern["case_id"] for pattern in patterns}
    for pattern in patterns:
        case_id = pattern["case_id"]
        target = (pattern.get("merged_into") or "").strip()
        if not target:
            continue
        if target not in case_ids:
            problems.append(f"{case_id}: merged_into unknown case {target}")
            continue
        try:
            resolved, chain = storage.resolve_case(case_id, patterns)
        except ValueError as error:
            problems.append(f"{case_id}: {error}")
            continue
        if resolved == case_id:
            problems.append(f"{case_id}: merged_into resolves back to itself")
        elif len(chain) < 2:  # defensive: resolve_case always appends the target
            problems.append(f"{case_id}: alias chain does not advance")
    return problems


def backfill_snapshots(case_ids: list[str] | None = None) -> list[str]:
    """Write missing version snapshots from the current catalog; idempotent.

    Backfilled snapshots are *baselines*, not historical replays: the current pattern
    content is written under each missing version number and the transaction journal
    records that basis.
    """
    patterns = load_validated_catalog()["attack_patterns"]
    if case_ids:
        wanted = {case_id for case_id in case_ids if case_id}
        known = {pattern["case_id"] for pattern in patterns}
        unknown = sorted(wanted - known)
        if unknown:
            raise ValueError(f"unknown case_id(s): {', '.join(unknown)}")
        patterns = [pattern for pattern in patterns if pattern["case_id"] in wanted]
    writes: list[storage.Write] = []
    written: list[str] = []
    for pattern in patterns:
        for number in range(1, pattern_version(pattern) + 1):
            path = version_path(pattern["case_id"], number)
            if path.exists():
                continue
            writes.append(storage.Write.json(path, snapshot_payload(pattern, number)))
            written.append(str(path))
    if writes:
        storage.commit(
            writes, kind="snapshot_backfill",
            summary=f"backfill {len(writes)} missing version snapshot(s)",
            basis=("baseline backfill: current content is written under the missing "
                   "version numbers, not a historical replay"),
        )
    return written

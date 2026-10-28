"""Pattern catalog, versions, and new-case admission."""
from __future__ import annotations

import datetime as dt
import json
import re
from collections import defaultdict

from . import admissions as admission_store
from . import candidates as candidate_store
from . import storage
from .retrieval import build_action_index
from .storage import atomic_write_json, load_patterns, read_csv, validate_pattern

VERSIONS_DIR = storage.DATA_DIR / "pattern_versions"
MIN_SUPPORT_INCIDENTS = 2
MATURITY_REPEATED = 2
MATURITY_VALIDATED = 3


def maturity(incident_count: int) -> str:
    if incident_count >= MATURITY_VALIDATED:
        return "validated"
    if incident_count >= MATURITY_REPEATED:
        return "repeated"
    return "single_sample"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def pattern_version(pattern: dict) -> int:
    return int(pattern.get("version", 1))


def version_path(case_id: str, version: int):
    return VERSIONS_DIR / case_id / f"v{version:03d}.json"


def load_validated_catalog() -> dict:
    """Validate each pattern and the cross-pattern action library before any write."""
    data = load_patterns(storage.PATTERNS_PATH)
    build_action_index(data["attack_patterns"])
    return data


def require_pattern_support(pattern: dict, supporting_incident_ids: list[str] | None,
                            logs: list[dict[str, str]], force: bool = False,
                            events_by_incident: dict[str, list[dict[str, str]]] | None = None) -> list[str]:
    """A new case needs at least two incidents, and each must match at least one of its steps."""
    ids = sorted({(item or "").strip() for item in (supporting_incident_ids or [])} - {""})
    if not force and len(ids) < MIN_SUPPORT_INCIDENTS:
        raise ValueError(
            f"a new pattern needs at least {MIN_SUPPORT_INCIDENTS} supporting incidents; "
            "pass --supporting-incident-ids, or --force for a reviewed singleton"
        )
    if not ids:
        return []
    if events_by_incident is None:
        by_incident: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in logs:
            incident = (row.get("incident_id") or "").strip()
            if incident:
                by_incident[incident].append(row)
    else:
        by_incident = events_by_incident
    unknown = [incident for incident in ids if incident not in by_incident]
    if unknown:
        raise ValueError(f"unknown or unlabeled incident(s): {', '.join(unknown)}")
    regexes = [re.compile(step["action_regex"]) for step in pattern["steps"]]
    unmatched = [incident for incident in ids
                 if not any(regex.search(row.get("content") or "")
                            for row in by_incident[incident] for regex in regexes)]
    if unmatched:
        raise ValueError(
            f"no event of incident(s) {', '.join(unmatched)} matches the new pattern's steps; "
            "the pattern is not supported by that incident"
        )
    return ids


def add_pattern(pattern_file, supporting_incident_ids: list[str] | None = None,
                force: bool = False, events_by_incident: dict[str, list[dict[str, str]]] | None = None,
                source: str = "catalog_add") -> str:
    pattern = json.loads(pattern_file.read_text(encoding="utf-8-sig"))
    validate_pattern(pattern)
    data = load_validated_catalog()
    if any(item["case_id"] == pattern["case_id"] for item in data["attack_patterns"]):
        raise ValueError(f"case_id already exists: {pattern['case_id']}")
    require_pattern_support(pattern, supporting_incident_ids, read_csv(storage.RAW_LOGS_PATH), force=force,
                            events_by_incident=events_by_incident)
    pattern["version"] = pattern.get("version", 1)
    data["attack_patterns"].append(pattern)
    # Raises on a shared action_id with a different regex or generic flag.
    build_action_index(data["attack_patterns"])
    admission = admission_store.record_admission(pattern["case_id"], source=source,
                                                 basis="experimental auto-add; awaiting review")
    pattern["review_status"] = "unreviewed"
    pattern["admission_id"] = admission["admission_id"]
    atomic_write_json(storage.PATTERNS_PATH, data)
    return pattern["case_id"]


def add_pattern_from_candidate(candidate_id: str, pattern_file, force: bool = False) -> tuple[str, dict]:
    """Promote a staged candidate with an authored pattern; the candidate supplies the incidents."""
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
    rows_by_id = {row["event_id"]: row for row in read_csv(storage.RAW_LOGS_PATH)}
    missing = [event_id for item in candidate.get("incidents") or []
               for event_id in item.get("event_ids") or [] if event_id not in rows_by_id]
    if missing:
        raise ValueError(f"{candidate_id}: unknown event ID(s) {', '.join(missing[:5])}")
    events_by_incident = {
        item["incident_id"]: [rows_by_id[event_id] for event_id in item.get("event_ids") or []]
        for item in candidate.get("incidents") or []
    }
    case_id = add_pattern(pattern_file, incidents, force=force,
                          events_by_incident=events_by_incident,
                          source=f"candidate:{candidate_id}")
    candidate_store.mark_promoted(candidate_id, case_id)
    return case_id, candidate


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
    atomic_write_json(storage.PATTERNS_PATH, data)
    return record


def write_version_snapshot(pattern: dict):
    version = pattern_version(pattern)
    data = dict(pattern)
    data.setdefault("version", version)
    path = version_path(pattern["case_id"], version)
    if path.exists():
        existing = json.loads(path.read_text(encoding="utf-8-sig"))
        if existing != data:
            raise ValueError(f"version snapshot {path} exists with different content; refusing to rewrite history")
        return path
    atomic_write_json(path, data)
    return path

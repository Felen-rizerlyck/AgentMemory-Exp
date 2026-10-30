"""New-case admissions: experimental auto-add with a visible pending-review marker.

Experiment mode: the model may add a case directly; it is recorded here and the
pattern carries `review_status: "unreviewed"`. Deployment mode: a human runs
`catalog review-case`, which flips the ledger to reviewed and removes the marker.
The marker is never removed automatically.

Each admission also records *how strong* the evidence was, so a reviewer sees
"1/3 required steps, single sample" instead of a bare "added".
"""
from __future__ import annotations

import pathlib

from . import storage

ADMISSIONS_PATH = storage.DATA_DIR / "case_admissions.json"
STATUSES = ("unreviewed", "reviewed")


def _empty() -> dict:
    return {"schema_version": 1, "admissions": []}


def load_admissions(path: pathlib.Path | str | None = None) -> dict:
    target = pathlib.Path(path) if path is not None else ADMISSIONS_PATH
    if not target.exists():
        return _empty()
    data = storage.load_json(target)
    if not isinstance(data, dict) or not isinstance(data.get("admissions"), list):
        raise ValueError(f"{target}: admission ledger must contain an admissions list")
    return data


def save_admissions(data: dict, path: pathlib.Path | str | None = None) -> None:
    target = pathlib.Path(path) if path is not None else ADMISSIONS_PATH
    storage.atomic_write_json(target, data)


def get_admission(case_id: str, path: pathlib.Path | str | None = None) -> dict | None:
    for record in load_admissions(path)["admissions"]:
        if record.get("case_id") == case_id:
            return record
    return None


def build_admission(case_id: str, source: str, basis: str = "",
                    support: dict | None = None) -> dict:
    """Pure admission record; the caller commits it with the pattern in one transaction."""
    record = {
        "admission_id": f"ADM-{case_id}",
        "case_id": case_id,
        "source": source,
        "basis": basis,
        "status": "unreviewed",
        "created_at": storage.now_iso(),
        "reviewed_at": None,
        "reviewed_by": None,
        "review_basis": "",
        "single_sample": bool((support or {}).get("single_sample")),
        "support_coverage": {},
    }
    if support:
        record["support_coverage"] = {
            "required_steps": list(support.get("required_steps") or []),
            "covered_required": list(support.get("covered_required") or []),
            "missing_required": list(support.get("missing_required") or []),
            "has_strong_medium": bool(support.get("has_strong_medium")),
            "per_incident": dict(support.get("coverage") or {}),
        }
    return record


def insert_admission(data: dict, record: dict) -> dict:
    """Validate and append one record to a loaded ledger; returns the record."""
    case_id = record.get("case_id")
    existing = next((item for item in data["admissions"]
                     if item.get("case_id") == case_id), None)
    if existing is not None:
        if existing.get("status") == "unreviewed":
            return existing
        raise ValueError(f"{case_id} already has a reviewed admission")
    data["admissions"].append(record)
    return record


def record_admission(case_id: str, source: str, basis: str = "",
                     path: pathlib.Path | str | None = None,
                     support: dict | None = None) -> dict:
    data = load_admissions(path)
    existing = next((item for item in data["admissions"]
                     if item.get("case_id") == case_id), None)
    if existing is not None:
        if existing.get("status") == "unreviewed":
            return existing
        raise ValueError(f"{case_id} already has a reviewed admission")
    record = build_admission(case_id, source, basis, support=support)
    insert_admission(data, record)
    save_admissions(data, path)
    return record


def review_admission(case_id: str, basis: str, reviewer: str = "human",
                     path: pathlib.Path | str | None = None) -> dict:
    data = load_admissions(path)
    record = next((item for item in data["admissions"]
                   if item.get("case_id") == case_id), None)
    if record is None:
        raise ValueError(f"no admission for {case_id}")
    if record.get("status") == "reviewed":
        raise ValueError(f"{case_id} admission is already reviewed")
    record["status"] = "reviewed"
    record["reviewed_at"] = storage.now_iso()
    record["reviewed_by"] = reviewer
    record["review_basis"] = basis
    save_admissions(data, path)
    return record


def orphan_admissions(patterns: list[dict] | None = None,
                      path: pathlib.Path | str | None = None) -> list[dict]:
    """Admission records whose case no longer exists (e.g. a failed multi-file add)."""
    if patterns is None:
        from .catalog import load_validated_catalog
        patterns = load_validated_catalog()["attack_patterns"]
    known = {pattern["case_id"] for pattern in patterns}
    return [record for record in load_admissions(path)["admissions"]
            if (record.get("case_id") or "") not in known]


def repair_orphans(apply: bool = False, patterns: list[dict] | None = None,
                   path: pathlib.Path | str | None = None) -> list[dict]:
    """Report (and optionally delete) admissions whose case is missing.

    Only the ledger row is removed; patterns, links and raw logs are never touched.
    """
    orphans = orphan_admissions(patterns, path)
    reports = [{
        "admission_id": record.get("admission_id"),
        "case_id": record.get("case_id"),
        "status": record.get("status"),
        "source": record.get("source"),
        "action": "remove" if apply else "report",
    } for record in orphans]
    if not (apply and orphans):
        return reports
    if patterns is None:
        from .catalog import load_validated_catalog
        patterns = load_validated_catalog()["attack_patterns"]
    known = {pattern["case_id"] for pattern in patterns}
    target = pathlib.Path(path) if path is not None else ADMISSIONS_PATH
    data = load_admissions(target)
    data["admissions"] = [record for record in data["admissions"]
                          if (record.get("case_id") or "") in known]
    storage.commit(
        [storage.Write.json(target, data)], kind="repair_admissions",
        summary=f"remove {len(orphans)} orphan admission(s)",
        basis="orphan admission: case no longer exists",
    )
    return reports


def _validate_support_coverage(record: dict, admission_id: str) -> list[str]:
    problems: list[str] = []
    single = record.get("single_sample")
    if "single_sample" in record and not isinstance(single, bool):
        problems.append(f"{admission_id}: single_sample must be true or false")
    coverage = record.get("support_coverage")
    if coverage is None:
        return problems
    if not isinstance(coverage, dict):
        problems.append(f"{admission_id}: support_coverage must be an object")
        return problems
    for key in ("required_steps", "covered_required", "missing_required"):
        value = coverage.get(key)
        if value is not None and (not isinstance(value, list)
                                  or not all(isinstance(item, str) and item.strip() for item in value)):
            problems.append(f"{admission_id}: support_coverage.{key} must be a list of step IDs")
    per_incident = coverage.get("per_incident")
    if per_incident is not None:
        if not isinstance(per_incident, dict):
            problems.append(f"{admission_id}: support_coverage.per_incident must be an object")
        else:
            for incident, item in per_incident.items():
                if not isinstance(item, dict):
                    problems.append(
                        f"{admission_id}: support_coverage.per_incident[{incident}] must be an object")
                elif "coverage" in item and not isinstance(item["coverage"], (int, float)):
                    problems.append(
                        f"{admission_id}: support_coverage.per_incident[{incident}].coverage "
                        "must be a number")
    has_strong = coverage.get("has_strong_medium")
    if "has_strong_medium" in coverage and not isinstance(has_strong, bool):
        problems.append(f"{admission_id}: support_coverage.has_strong_medium must be true or false")
    return problems


def audit_admissions(patterns: list[dict], path: pathlib.Path | str | None = None) -> list[str]:
    problems: list[str] = []
    data = load_admissions(path)
    pattern_by_case = {pattern["case_id"]: pattern for pattern in patterns}
    seen_cases: set[str] = set()
    seen_ids: set[str] = set()
    for record in data["admissions"]:
        case_id = record.get("case_id")
        admission_id = record.get("admission_id")
        if not case_id or case_id in seen_cases:
            problems.append(f"admission: duplicate or missing case_id {case_id!r}")
            continue
        if not admission_id or admission_id in seen_ids:
            problems.append(f"admission: duplicate or missing admission_id {admission_id!r}")
            continue
        seen_cases.add(case_id)
        seen_ids.add(admission_id)
        problems += _validate_support_coverage(record, admission_id)
        pattern = pattern_by_case.get(case_id)
        if pattern is None:
            problems.append(f"{admission_id}: case {case_id} does not exist")
            continue
        status = record.get("status")
        if status not in STATUSES:
            problems.append(f"{admission_id}: unsupported status {status!r}")
        elif status == "unreviewed":
            if pattern.get("review_status") != "unreviewed":
                problems.append(f"{admission_id}: case {case_id} is unreviewed in the ledger "
                                "but has no review_status marker")
            if pattern.get("admission_id") != admission_id:
                problems.append(f"{admission_id}: case {case_id} admission_id does not match")
        elif pattern.get("review_status"):
            problems.append(f"{admission_id}: case {case_id} is reviewed but still marked "
                            f"{pattern.get('review_status')!r}")
        if pattern.get("admission_id") != admission_id:
            problems.append(f"{admission_id}: case {case_id} admission_id does not match")

    for case_id, pattern in pattern_by_case.items():
        marker = pattern.get("review_status")
        if marker and marker != "unreviewed":
            problems.append(f"{case_id}: unsupported review_status {marker!r}")
        if marker == "unreviewed" and case_id not in seen_cases:
            problems.append(f"{case_id}: unreviewed marker has no admission record")
        if pattern.get("admission_id") and case_id not in seen_cases:
            problems.append(f"{case_id}: admission_id has no ledger record")
    return problems

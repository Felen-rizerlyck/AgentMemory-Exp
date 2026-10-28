"""New-case admissions: experimental auto-add with a visible pending-review marker.

Experiment mode: the model may add a case directly; it is recorded here and the
pattern carries `review_status: "unreviewed"`. Deployment mode: a human runs
`catalog review-case`, which flips the ledger to reviewed and removes the marker.
The marker is never removed automatically.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import storage

ADMISSIONS_PATH = storage.DATA_DIR / "case_admissions.json"
STATUSES = ("unreviewed", "reviewed")


def _empty() -> dict:
    return {"schema_version": 1, "admissions": []}


def load_admissions(path: Path | str | None = None) -> dict:
    target = Path(path) if path is not None else ADMISSIONS_PATH
    if not target.exists():
        return _empty()
    data = json.loads(target.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("admissions"), list):
        raise ValueError(f"{target}: admission ledger must contain an admissions list")
    return data


def save_admissions(data: dict, path: Path | str | None = None) -> None:
    target = Path(path) if path is not None else ADMISSIONS_PATH
    storage.atomic_write_json(target, data)


def get_admission(case_id: str, path: Path | str | None = None) -> dict | None:
    for record in load_admissions(path)["admissions"]:
        if record.get("case_id") == case_id:
            return record
    return None


def record_admission(case_id: str, source: str, basis: str = "",
                     path: Path | str | None = None) -> dict:
    data = load_admissions(path)
    existing = next((item for item in data["admissions"]
                     if item.get("case_id") == case_id), None)
    if existing is not None:
        if existing.get("status") == "unreviewed":
            return existing
        raise ValueError(f"{case_id} already has a reviewed admission")
    record = {
        "admission_id": f"ADM-{case_id}",
        "case_id": case_id,
        "source": source,
        "basis": basis,
        "status": "unreviewed",
        "created_at": _now_iso(),
        "reviewed_at": None,
        "reviewed_by": None,
        "review_basis": "",
    }
    data["admissions"].append(record)
    save_admissions(data, path)
    return record


def review_admission(case_id: str, basis: str, reviewer: str = "human",
                     path: Path | str | None = None) -> dict:
    data = load_admissions(path)
    record = next((item for item in data["admissions"]
                   if item.get("case_id") == case_id), None)
    if record is None:
        raise ValueError(f"no admission for {case_id}")
    if record.get("status") == "reviewed":
        raise ValueError(f"{case_id} admission is already reviewed")
    record["status"] = "reviewed"
    record["reviewed_at"] = _now_iso()
    record["reviewed_by"] = reviewer
    record["review_basis"] = basis
    save_admissions(data, path)
    return record


def audit_admissions(patterns: list[dict], path: Path | str | None = None) -> list[str]:
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


def _now_iso() -> str:
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

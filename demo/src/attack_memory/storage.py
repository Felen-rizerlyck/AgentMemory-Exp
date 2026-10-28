"""Relative-path storage helpers and schema checks for the demo."""
from __future__ import annotations

import csv
import json
import pathlib
import re
import tempfile
from typing import Any

DEMO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DATA_DIR = DEMO_ROOT / "data"
PATTERNS_PATH = DATA_DIR / "attack_patterns.json"
RAW_LOGS_PATH = DATA_DIR / "raw_logs.csv"
LINKS_PATH = DATA_DIR / "event_pattern_links.csv"
RAW_FIELDS = ["event_id", "batch_id", "incident_id", "case_id", "timestamp", "source", "log_id", "content"]
LINK_FIELDS = ["event_id", "incident_id", "case_id", "step_id", "action_id", "link_status", "link_basis",
               "decided_at"]
LINK_STATUSES = ("candidate", "confirmed", "rejected", "fixture", "related")
MITRE_ID = re.compile(r"T\d{4}(?:\.\d{3})?")


def resolve_demo_path(value: str | pathlib.Path) -> pathlib.Path:
    """Resolve a user-supplied relative path from the demo root."""
    path = pathlib.Path(value)
    if path.is_absolute():
        raise ValueError("Please use a path relative to the demo directory.")
    resolved = (DEMO_ROOT / path).resolve()
    if not resolved.is_relative_to(DEMO_ROOT):
        raise ValueError("Path must stay inside the demo directory.")
    return resolved


def load_patterns(path: pathlib.Path = PATTERNS_PATH) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("attack_patterns"), list):
        raise ValueError("attack_patterns.json must be an object with an attack_patterns list")
    seen: set[str] = set()
    for pattern in data["attack_patterns"]:
        validate_pattern(pattern)
        if pattern["case_id"] in seen:
            raise ValueError(f"Duplicate case_id: {pattern['case_id']}")
        seen.add(pattern["case_id"])
    return data


def _require_text(value: Any, field: str, case_id: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{case_id}: {field} must be a non-empty string")
    return value


def _require_string_list(value: Any, field: str, case_id: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{case_id}: {field} must be a non-empty list of strings")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{case_id}: {field} must contain non-empty strings only")
    return value


def validate_pattern(pattern: dict[str, Any]) -> None:
    """Reject patterns that would silently match everything or never match at all."""
    if not isinstance(pattern, dict):
        raise ValueError("Each attack pattern must be a JSON object")
    required = ("case_id", "name", "summary", "steps", "mitre", "retrieval")
    missing = [key for key in required if key not in pattern]
    if missing:
        raise ValueError(f"Pattern missing required fields: {', '.join(missing)}")
    case_id = _require_text(pattern["case_id"], "case_id", "<unknown>")
    if not re.fullmatch(r"CASE-\d{3,}", case_id):
        raise ValueError(f"Invalid case_id: {case_id}")
    _require_text(pattern["name"], "name", case_id)
    _require_text(pattern["summary"], "summary", case_id)

    mitre = pattern["mitre"]
    if not isinstance(mitre, list) or not all(isinstance(item, str) and MITRE_ID.fullmatch(item) for item in mitre):
        raise ValueError(f"{case_id}: mitre must be a list of ATT&CK IDs such as T1190 or T1059.004")

    retrieval = pattern["retrieval"]
    if not isinstance(retrieval, dict):
        raise ValueError(f"{case_id}: retrieval must be an object")
    if "keywords" in retrieval:
        _require_string_list(retrieval["keywords"], "retrieval.keywords", case_id)
    if "pattern_probes" in retrieval:
        _require_string_list(retrieval["pattern_probes"], "retrieval.pattern_probes", case_id)
    for probe in retrieval.get("pattern_probes", []):
        compiled = re.compile(probe)
        if compiled.search("") is not None:
            raise ValueError(f"{case_id}: retrieval probe matches every log: {probe!r}")

    steps = pattern["steps"]
    if not isinstance(steps, list) or not steps:
        raise ValueError(f"{case_id} must define at least one step")
    step_ids: set[str] = set()
    action_ids: set[str] = set()
    orders: list[int] = []
    required_flags: list[bool] = []
    for step in steps:
        if not isinstance(step, dict):
            raise ValueError(f"{case_id}: each step must be a JSON object")
        for field in ("step_id", "order", "action_id", "action_regex", "expected_sources"):
            if field not in step:
                raise ValueError(f"{case_id} step missing {field}")
        step_id = _require_text(step["step_id"], "step_id", case_id)
        if step_id in step_ids:
            raise ValueError(f"Duplicate step_id in {case_id}: {step_id}")
        step_ids.add(step_id)
        action_id = _require_text(step["action_id"], "action_id", case_id)
        if action_id in action_ids:
            raise ValueError(f"{case_id}: duplicate action_id {action_id}; one step per action definition")
        action_ids.add(action_id)
        regex = _require_text(step["action_regex"], "action_regex", case_id)
        if len(regex.strip()) < 3:
            raise ValueError(f"{case_id}/{step_id}: action_regex is too short to be meaningful")
        compiled = re.compile(regex)
        if compiled.search("") is not None:
            raise ValueError(f"{case_id}/{step_id}: action_regex matches the empty string, so it would match every log")
        sources = _require_string_list(step["expected_sources"], "expected_sources", case_id)
        if "generic" in step and not isinstance(step["generic"], bool):
            raise ValueError(f"{case_id}/{step_id}: generic must be true or false")
        if "required" in step and not isinstance(step["required"], bool):
            raise ValueError(f"{case_id}/{step_id}: required must be true or false")
        required_flags.append(bool(step.get("required", True)))
        orders.append(int(step["order"]))
    if orders != sorted(orders) or len(orders) != len(set(orders)):
        raise ValueError(f"{case_id} step order must be unique and ascending")
    if not any(required_flags):
        raise ValueError(f"{case_id} must keep at least one required step")

    family_id = pattern.get("family_id")
    if family_id is not None and (not isinstance(family_id, str) or not family_id.strip()):
        raise ValueError(f"{case_id}: family_id must be a non-empty string")
    if "pattern_scope" in pattern and not isinstance(pattern["pattern_scope"], dict):
        raise ValueError(f"{case_id}: pattern_scope must be an object")
    if "negative_and_unknown_evidence" in pattern and not isinstance(pattern["negative_and_unknown_evidence"], dict):
        raise ValueError(f"{case_id}: negative_and_unknown_evidence must be an object")
    provenance = pattern.get("provenance")
    if provenance is not None and not isinstance(provenance, dict):
        raise ValueError(f"{case_id}: provenance must be an object")

    version = pattern.get("version")
    if version is not None and (isinstance(version, bool) or not isinstance(version, int) or version < 1):
        raise ValueError(f"{case_id}: version must be a positive integer")
    supersedes = pattern.get("supersedes")
    if supersedes is not None and (isinstance(supersedes, bool) or not isinstance(supersedes, int) or supersedes < 1):
        raise ValueError(f"{case_id}: supersedes must be a positive integer")
    if "updated_at" in pattern and not isinstance(pattern["updated_at"], str):
        raise ValueError(f"{case_id}: updated_at must be an ISO 8601 string")


def _read_csv_strict(path: pathlib.Path) -> tuple[list[str], list[dict[str, str]]]:
    """Read a CSV and reject ragged rows instead of letting None reach the retrieval layer."""
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows: list[dict[str, str]] = []
        for number, row in enumerate(reader, start=2):
            if None in row:
                raise ValueError(f"{path.name} line {number} has more values than the header declares")
            if any(value is None for value in row.values()):
                raise ValueError(f"{path.name} line {number} has fewer values than the header declares")
            rows.append(row)
        return fieldnames, rows


def read_csv(path: pathlib.Path) -> list[dict[str, str]]:
    return _read_csv_strict(path)[1]


def append_csv(path: pathlib.Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    """Append rows in the declared column order, refusing to append to a different header."""
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not path.exists() or path.stat().st_size == 0
    if not needs_header:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            existing = next(csv.reader(handle), None)
        if existing != fields:
            raise ValueError(
                f"{path.name} header {existing} does not match expected fields {fields}; "
                "refusing to append misaligned rows"
            )
    # Emit a BOM only when creating a file; utf-8-sig in append mode can add a BOM mid-file.
    encoding = "utf-8-sig" if needs_header else "utf-8"
    with path.open("a", encoding=encoding, newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        if needs_header:
            writer.writeheader()
        writer.writerows(rows)


def read_links(path: pathlib.Path = LINKS_PATH) -> list[dict[str, str]]:
    return read_csv(path) if path.exists() else []


def latest_link_by_event(links: list[dict[str, str]]) -> dict[str, dict[str, str]]:
    """Rows are append-only history; timestamps order them, file order breaks ties."""
    latest: dict[str, tuple[tuple[str, int], dict[str, str]]] = {}
    for index, row in enumerate(links):
        event_id = (row.get("event_id") or "").strip()
        if not event_id:
            continue
        key = ((row.get("decided_at") or "").strip(), index)
        if event_id not in latest or key >= latest[event_id][0]:
            latest[event_id] = (key, row)
    return {event_id: row for event_id, (_, row) in latest.items()}


def validate_event_labels(event_ids: set[str], case_id: str, incident_id: str) -> None:
    """Preflight label changes before appending the corresponding audit relation."""
    rows = read_csv(RAW_LOGS_PATH)
    by_id = {row.get("event_id", ""): row for row in rows}
    missing = event_ids - set(by_id)
    if missing:
        raise ValueError(f"Unknown event_id(s): {', '.join(sorted(missing))}")
    for event_id in event_ids:
        row = by_id[event_id]
        current_case = (row.get("case_id") or "").strip()
        current_incident = (row.get("incident_id") or "").strip()
        if current_case and current_case != case_id:
            raise ValueError(f"{event_id} already has case_id {current_case}; review the existing label first")
        if current_incident and current_incident != incident_id:
            raise ValueError(f"{event_id} already has incident_id {current_incident}; review the existing label first")


def update_event_labels(event_ids: set[str], case_id: str, incident_id: str, status: str) -> None:
    """Update only analysis-label columns, preserving every other column and the line endings."""
    raw = RAW_LOGS_PATH.read_bytes()
    has_bom = raw.startswith(b"\xef\xbb\xbf")
    newline = "\r\n" if b"\r\n" in raw else "\n"
    fieldnames, rows = _read_csv_strict(RAW_LOGS_PATH)
    found: set[str] = set()
    changed = False
    for row in rows:
        event_id = row.get("event_id", "")
        if event_id not in event_ids:
            continue
        found.add(event_id)
        current_case = (row.get("case_id") or "").strip()
        current_incident = (row.get("incident_id") or "").strip()
        if status == "confirmed":
            if current_case != case_id or current_incident != incident_id:
                row["case_id"] = case_id
                row["incident_id"] = incident_id
                changed = True
        elif status == "rejected":
            if current_case == case_id and current_incident == incident_id:
                row["case_id"] = ""
                row["incident_id"] = ""
                changed = True
            elif not current_case and current_incident == incident_id:
                # An ingestion-only incident label can be withdrawn without a stand-in confirmation.
                row["incident_id"] = ""
                changed = True
    if found != event_ids:
        raise ValueError(f"Unknown event_id(s): {', '.join(sorted(event_ids - found))}")
    if not changed:
        return
    with tempfile.NamedTemporaryFile("w", encoding="utf-8-sig" if has_bom else "utf-8",
                                     newline="", dir=RAW_LOGS_PATH.parent,
                                     suffix=".tmp", delete=False) as handle:
        tmp = pathlib.Path(handle.name)
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore",
                                lineterminator=newline)
        writer.writeheader()
        writer.writerows(rows)
    tmp.replace(RAW_LOGS_PATH)


def atomic_write_json(path: pathlib.Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", dir=path.parent,
                                     suffix=".tmp", delete=False) as handle:
        tmp = pathlib.Path(handle.name)
        json.dump(data, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    tmp.replace(path)

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
LINK_FIELDS = ["event_id", "incident_id", "case_id", "step_id", "action_id", "link_status", "link_basis"]


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
    if not isinstance(data.get("attack_patterns"), list):
        raise ValueError("attack_patterns.json must contain an attack_patterns list")
    seen: set[str] = set()
    for pattern in data["attack_patterns"]:
        validate_pattern(pattern)
        if pattern["case_id"] in seen:
            raise ValueError(f"Duplicate case_id: {pattern['case_id']}")
        seen.add(pattern["case_id"])
    return data


def validate_pattern(pattern: dict[str, Any]) -> None:
    required = ("case_id", "name", "summary", "steps", "mitre", "retrieval")
    missing = [key for key in required if key not in pattern]
    if missing:
        raise ValueError(f"Pattern missing required fields: {', '.join(missing)}")
    if not re.fullmatch(r"CASE-\d{3,}", str(pattern["case_id"])):
        raise ValueError(f"Invalid case_id: {pattern['case_id']}")
    if not pattern["steps"]:
        raise ValueError(f"{pattern['case_id']} must define at least one step")
    step_ids: set[str] = set()
    orders: list[int] = []
    for step in pattern["steps"]:
        for field in ("step_id", "order", "action_id", "action_regex", "expected_sources"):
            if field not in step:
                raise ValueError(f"{pattern['case_id']} step missing {field}")
        if step["step_id"] in step_ids:
            raise ValueError(f"Duplicate step_id in {pattern['case_id']}: {step['step_id']}")
        step_ids.add(step["step_id"])
        orders.append(int(step["order"]))
        re.compile(step["action_regex"])
    if orders != sorted(orders) or len(orders) != len(set(orders)):
        raise ValueError(f"{pattern['case_id']} step order must be unique and ascending")
    for probe in pattern["retrieval"].get("pattern_probes", []):
        re.compile(probe)


def read_csv(path: pathlib.Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def append_csv(path: pathlib.Path, fields: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not path.exists() or path.stat().st_size == 0
    # Emit a BOM only when creating a file; utf-8-sig in append mode can add a BOM mid-file.
    encoding = "utf-8-sig" if needs_header else "utf-8"
    with path.open("a", encoding=encoding, newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        if needs_header:
            writer.writeheader()
        writer.writerows(rows)


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
    """Update only analysis-label columns; original event payload fields remain untouched."""
    rows = read_csv(RAW_LOGS_PATH)
    found: set[str] = set()
    for row in rows:
        event_id = row.get("event_id", "")
        if event_id not in event_ids:
            continue
        found.add(event_id)
        current_case = (row.get("case_id") or "").strip()
        if status == "confirmed":
            row["case_id"] = case_id
            row["incident_id"] = incident_id
        elif status == "rejected" and current_case == case_id:
            row["case_id"] = ""
            row["incident_id"] = ""
    if found != event_ids:
        raise ValueError(f"Unknown event_id(s): {', '.join(sorted(event_ids - found))}")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8-sig", newline="", dir=RAW_LOGS_PATH.parent,
                                     suffix=".tmp", delete=False) as handle:
        tmp = pathlib.Path(handle.name)
        writer = csv.DictWriter(handle, fieldnames=RAW_FIELDS, extrasaction="ignore")
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

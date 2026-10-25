"""Validate/add attack patterns and append reviewed event-to-pattern links."""
from __future__ import annotations

import argparse
import json

from .storage import (LINK_FIELDS, LINKS_PATH, PATTERNS_PATH, RAW_LOGS_PATH,
                      append_csv, atomic_write_json, load_patterns, read_csv,
                      resolve_demo_path, update_event_labels, validate_event_labels,
                      validate_pattern)


def add_pattern(pattern_file) -> str:
    pattern = json.loads(pattern_file.read_text(encoding="utf-8-sig"))
    validate_pattern(pattern)
    data = load_patterns()
    if any(item["case_id"] == pattern["case_id"] for item in data["attack_patterns"]):
        raise ValueError(f"case_id already exists: {pattern['case_id']}")
    data["attack_patterns"].append(pattern)
    atomic_write_json(PATTERNS_PATH, data)
    return pattern["case_id"]


def append_links(event_ids: list[str], incident_id: str, case_id: str,
                 step_id: str, status: str, basis: str) -> int:
    patterns = load_patterns()["attack_patterns"]
    pattern = next((p for p in patterns if p["case_id"] == case_id), None)
    if pattern is None:
        raise ValueError(f"Unknown case_id: {case_id}")
    step = next((s for s in pattern["steps"] if s["step_id"] == step_id), None)
    if step is None:
        raise ValueError(f"Unknown step_id for {case_id}: {step_id}")
    known_events = {row.get("event_id") for row in read_csv(RAW_LOGS_PATH)}
    missing = set(event_ids) - known_events
    if missing:
        raise ValueError(f"Unknown event_id(s): {', '.join(sorted(missing))}")
    if status == "confirmed":
        validate_event_labels(set(event_ids), case_id, incident_id)
    rows = [{"event_id": event_id, "incident_id": incident_id, "case_id": case_id,
             "step_id": step_id, "action_id": step["action_id"],
             "link_status": status, "link_basis": basis} for event_id in event_ids]
    append_csv(LINKS_PATH, LINK_FIELDS, rows)
    if status in {"confirmed", "rejected"}:
        update_event_labels(set(event_ids), case_id, incident_id, status)
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate/add a pattern or append reviewed event links.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate", help="Validate the current attack pattern catalog")
    add = sub.add_parser("add-pattern", help="Add one JSON pattern after review")
    add.add_argument("--input", required=True, help="Pattern JSON relative to demo/")
    link = sub.add_parser("link-events", help="Append reviewed event-to-case-step links")
    link.add_argument("--event-ids", required=True, help="Comma-separated event IDs")
    link.add_argument("--incident-id", required=True)
    link.add_argument("--case-id", required=True)
    link.add_argument("--step-id", required=True)
    link.add_argument("--status", default="confirmed", choices=["candidate", "confirmed", "rejected", "fixture"])
    link.add_argument("--basis", required=True, help="Short evidence/rationale for the link")
    args = parser.parse_args()
    if args.command == "validate":
        data = load_patterns()
        print(f"Catalog valid: {len(data['attack_patterns'])} pattern(s).")
    elif args.command == "add-pattern":
        case_id = add_pattern(resolve_demo_path(args.input))
        print(f"Added {case_id} to data/attack_patterns.json")
    else:
        ids = [item.strip() for item in args.event_ids.split(",") if item.strip()]
        count = append_links(ids, args.incident_id, args.case_id, args.step_id, args.status, args.basis)
        print(f"Appended {count} reviewed link(s) to data/event_pattern_links.csv")


if __name__ == "__main__":
    main()

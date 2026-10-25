"""Append normalized CSV observations without assigning attack labels."""
from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import uuid

from .storage import RAW_FIELDS, RAW_LOGS_PATH, append_csv, read_csv, resolve_demo_path


def ingest(source: pathlib.Path, destination: pathlib.Path = RAW_LOGS_PATH) -> int:
    incoming = read_csv(source)
    if not incoming:
        return 0
    required = {"timestamp", "source", "log_id", "content"}
    missing = required - set(incoming[0])
    if missing:
        raise ValueError(f"Input CSV missing columns: {', '.join(sorted(missing))}")
    existing_ids = {row.get("event_id", "") for row in read_csv(destination)} if destination.exists() else set()
    batch_id = "BATCH-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    appended: list[dict[str, str]] = []
    for row in incoming:
        event_id = row.get("event_id") or f"EVT-{uuid.uuid4().hex[:12].upper()}"
        if event_id in existing_ids:
            raise ValueError(f"event_id already exists; refusing duplicate append: {event_id}")
        existing_ids.add(event_id)
        appended.append({
            "event_id": event_id, "batch_id": row.get("batch_id") or batch_id,
            "incident_id": row.get("incident_id", ""), "case_id": "",
            "timestamp": row["timestamp"], "source": row["source"].casefold(),
            "log_id": row["log_id"], "content": row["content"],
        })
    append_csv(destination, RAW_FIELDS, appended)
    return len(appended)


def main() -> None:
    parser = argparse.ArgumentParser(description="Append a normalized log CSV into the demo raw log store.")
    parser.add_argument("--input", required=True, help="Input CSV path relative to demo/")
    args = parser.parse_args()
    count = ingest(resolve_demo_path(args.input))
    print(f"Appended {count} events to data/raw_logs.csv; case labels remain unassigned.")


if __name__ == "__main__":
    main()

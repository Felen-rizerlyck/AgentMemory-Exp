"""Append normalized CSV observations without assigning attack labels."""
from __future__ import annotations

import argparse
import datetime as dt
import pathlib
import uuid

from .storage import RAW_FIELDS, RAW_LOGS_PATH, append_csv, read_csv, resolve_demo_path


def ingest(source: pathlib.Path, destination: pathlib.Path = RAW_LOGS_PATH,
           allow_incident_id: bool = False) -> tuple[int, int]:
    """Append rows; return (appended, incident labels withheld).

    A supplied incident_id is not evidence. Unless the caller states that the batch
    was already reviewed, it is withheld so the rows stay in their own batch scope.
    """
    incoming = read_csv(source)
    if not incoming:
        return 0, 0
    required = ("timestamp", "source", "log_id", "content")
    missing = [field for field in required if field not in incoming[0]]
    if missing:
        raise ValueError(f"Input CSV missing columns: {', '.join(missing)}")
    existing_ids = {row.get("event_id", "") for row in read_csv(destination)} if destination.exists() else set()
    batch_id = "BATCH-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    appended: list[dict[str, str]] = []
    withheld = 0
    for row in incoming:
        for field in ("timestamp", "source", "log_id"):
            if not (row.get(field) or "").strip():
                raise ValueError(f"Input row is missing {field}: {row}")
        event_id = row.get("event_id") or f"EVT-{uuid.uuid4().hex[:12].upper()}"
        if event_id in existing_ids:
            raise ValueError(f"event_id already exists; refusing duplicate append: {event_id}")
        existing_ids.add(event_id)
        incident_id = (row.get("incident_id") or "").strip()
        if incident_id and not allow_incident_id:
            incident_id = ""
            withheld += 1
        appended.append({
            "event_id": event_id, "batch_id": row.get("batch_id") or batch_id,
            "incident_id": incident_id, "case_id": "",
            "timestamp": row["timestamp"], "source": row["source"].casefold(),
            "log_id": row["log_id"], "content": row["content"],
        })
    append_csv(destination, RAW_FIELDS, appended)
    return len(appended), withheld


def main() -> None:
    parser = argparse.ArgumentParser(description="Append a normalized log CSV into the demo raw log store.")
    parser.add_argument("--input", required=True, help="Input CSV path relative to demo/")
    parser.add_argument("--allow-incident-id", action="store_true",
                        help="Keep a supplied incident_id; use only for an already reviewed known incident")
    args = parser.parse_args()
    count, withheld = ingest(resolve_demo_path(args.input), allow_incident_id=args.allow_incident_id)
    print(f"Appended {count} events to data/raw_logs.csv; case labels remain unassigned.")
    if withheld:
        print(f"Withheld {withheld} supplied incident_id value(s) so the rows stay unassigned; "
              "use --allow-incident-id only for a batch you have already correlated.")


if __name__ == "__main__":
    main()

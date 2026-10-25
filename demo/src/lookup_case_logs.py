"""Fetch previously labeled CSV observations after a case candidate is selected."""
from __future__ import annotations

import argparse
import json

from attack_memory.storage import RAW_LOGS_PATH, read_csv


def main() -> None:
    parser = argparse.ArgumentParser(description="Look up stored observations by case_id and optional incident_id.")
    parser.add_argument("--case-id", required=True, help="Pattern ID, e.g. CASE-008")
    parser.add_argument("--incident-id", help="Optionally restrict to one concrete incident")
    parser.add_argument("--json", action="store_true", help="Print matching rows as JSON")
    args = parser.parse_args()
    rows = [row for row in read_csv(RAW_LOGS_PATH)
            if row.get("case_id", "").strip() == args.case_id
            and (not args.incident_id or row.get("incident_id", "").strip() == args.incident_id)]
    if args.json:
        print(json.dumps({"case_id": args.case_id, "incident_id": args.incident_id,
                          "count": len(rows), "observations": rows}, ensure_ascii=False, indent=2))
        return
    print(f"{args.case_id}: {len(rows)} stored observation(s)")
    for row in rows:
        print(f"{row.get('timestamp', '')} [{row.get('source', '')}] "
              f"{row.get('incident_id', '')} {row.get('log_id', '')} | {row.get('content', '')}")


if __name__ == "__main__":
    main()

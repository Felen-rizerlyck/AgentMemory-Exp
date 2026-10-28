"""Stage the 91 unclassified units from the applied 1001-1140 run as candidates.

Reads the applied decision report and the real demo raw logs, then upserts one
candidate per distinct technique signature. Idempotent: re-running merges the
same incident instead of creating a duplicate.
"""
from __future__ import annotations

import csv
import json
import pathlib
import sys
from collections import Counter, defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
REPORTS = ROOT / "eval" / "ingest_applied_1001_1140"
sys.path.insert(0, str(DEMO / "src"))

from attack_memory import candidates, storage  # noqa: E402

FAMILY_BY_FORM = {
    "F1": "web-exploit",
    "F2": "web-exploit",
    "F3": "host-persistence",
    "F4": "web-exploit",
    "FA": "ransomware",
    "FB": "domain-identity",
    "FC": "supply-chain",
}


def main() -> None:
    rows = list(csv.DictReader((REPORTS / "decision_report.csv").open(encoding="utf-8-sig")))
    logs = storage.read_csv(storage.RAW_LOGS_PATH)
    by_batch: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in logs:
        batch = (row.get("batch_id") or "").strip()
        if batch.startswith("SIM-B-"):
            by_batch[batch].append(row)

    before = candidates.counts()
    staged = 0
    for row in rows:
        if row["decision"] != "unclassified":
            continue
        unit = row["unit"]
        batch = f"SIM-B-{unit}"
        event_ids = [item["event_id"] for item in by_batch.get(batch, [])]
        if not event_ids:
            raise SystemExit(f"no events for batch {batch}")
        signature = f"{row['form']}::{row['technique']}"
        candidates.upsert_candidate(
            signature=signature,
            label=row["technique"],
            incident_id=f"SIM-INC-{unit}",
            event_ids=event_ids,
            source_batch=batch,
            family_id=FAMILY_BY_FORM.get(row["form"], ""),
        )
        staged += 1

    after = candidates.counts()
    summary = {
        "staged_units": staged,
        "before": before,
        "after": after,
        "candidate_count": sum(after.values()),
        "promotable": after.get("promotable", 0),
        "note": "each technique signature appears once in this dataset, so all are provisional",
        "candidates_path": str(candidates.CANDIDATES_PATH),
    }
    (REPORTS / "candidates_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"staged_units={staged} candidates={summary['candidate_count']} statuses={after}")
    print(f"store: {candidates.CANDIDATES_PATH}")


if __name__ == "__main__":
    main()

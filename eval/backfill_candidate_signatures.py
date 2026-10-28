"""Step 1: backfill deterministic signature features for staged candidates.

Only adds `signature_key` / `signature_terms`; never changes status, incidents or
promotion state. Run again safely.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
REPORTS = ROOT / "eval" / "ingest_applied_1001_1140"
sys.path.insert(0, str(DEMO / "src"))

from attack_memory import candidates, signatures, storage  # noqa: E402


def main() -> None:
    data = candidates.load_candidates()
    rows_by_id = {row["event_id"]: row for row in storage.read_csv(storage.RAW_LOGS_PATH)}
    for candidate in data["candidates"]:
        event_ids = [event_id for incident in candidate.get("incidents") or []
                     for event_id in incident.get("event_ids") or []]
        rows = [rows_by_id[event_id] for event_id in event_ids if event_id in rows_by_id]
        features = signatures.extract_features(
            candidate.get("label") or "",
            [row.get("content") or "" for row in rows],
            [row.get("source") or "" for row in rows],
            candidate.get("family_id") or "unclassified",
        )
        candidate["signature_key"] = features["signature_key"]
        candidate["signature_terms"] = features["signature_terms"]
        candidate["signature_features"] = {
            "cves": features["cves"],
            "products": features["products"],
            "actions": features["actions"],
            "primary_product": features["primary_product"],
            "primary_action": features["primary_action"],
            "sources": features["sources"],
            "label_used": features["label_used"],
        }
    candidates.save_candidates(data)
    groups = signatures.group_candidates(data["candidates"])
    duplicates = [group for group in groups if len(group["candidates"]) > 1]
    summary = {
        "candidates": len(data["candidates"]),
        "signature_groups": len(groups),
        "duplicate_groups": len(duplicates),
        "duplicate_members": sum(len(group["candidates"]) for group in duplicates),
        "groups": [{
            "signature_key": group["signature_key"],
            "terms": group["terms"],
            "candidates": [item["candidate_id"] for item in group["candidates"]],
            "labels": [item["label"] for item in group["candidates"]],
        } for group in groups],
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "signature_groups.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"candidates={summary['candidates']} groups={summary['signature_groups']} "
          f"duplicate_groups={summary['duplicate_groups']} members={summary['duplicate_members']}")
    for group in duplicates:
        print(" ", group["signature_key"], [item["candidate_id"] for item in group["candidates"]],
              "|", group["candidates"][0]["label"][:60])


if __name__ == "__main__":
    main()

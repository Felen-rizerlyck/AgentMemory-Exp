"""Step 2: merge duplicate signature groups into reviewable clusters.

Same family + same signature_key only. A group with a promoted member keeps the
promoted candidate as primary and records the new incidents as pending_case_links;
other groups become promotable. Idempotent: already-merged aliases are skipped.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
REPORTS = ROOT / "eval" / "ingest_applied_1001_1140"
sys.path.insert(0, str(DEMO / "src"))

from attack_memory import candidates, signatures  # noqa: E402


def main() -> None:
    data = candidates.load_candidates()
    groups = signatures.group_candidates(
        [item for item in data["candidates"] if item.get("status") != "merged"])
    before = candidates.counts()
    merged = []
    for group in groups:
        members = group["candidates"]
        if len(members) < 2:
            continue
        promoted = [item for item in members if item.get("status") == "promoted"]
        primary = promoted[0] if promoted else min(members, key=lambda item: item["candidate_id"])
        for alias in members:
            if alias["candidate_id"] == primary["candidate_id"]:
                continue
            candidates.merge_candidates(
                primary["candidate_id"], alias["candidate_id"],
                f"step 2: duplicate signature_key {group['signature_key']}")
            merged.append({"primary": primary["candidate_id"],
                           "alias": alias["candidate_id"],
                           "signature_key": group["signature_key"]})
    after = candidates.counts()
    summary = {
        "before": before,
        "after": after,
        "merges": merged,
        "active_candidates": len(candidates.list_candidates()),
        "merged_aliases": len(candidates.list_candidates(status="merged")),
        "promotable": after.get("promotable", 0),
        "promoted_pending_links": [
            {"candidate_id": item["candidate_id"],
             "case_id": item.get("promoted_case_id"),
             "pending": item.get("pending_case_links") or []}
            for item in candidates.list_candidates()
            if item.get("status") == "promoted" and item.get("pending_case_links")
        ],
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "merge_groups.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"before={before}")
    print(f"after={after}")
    print(f"active={summary['active_candidates']} merged_aliases={summary['merged_aliases']} "
          f"promotable={summary['promotable']}")
    for item in merged:
        print(" ", item["primary"], "<-", item["alias"], item["signature_key"])
    for item in summary["promoted_pending_links"]:
        print(" pending", item)


if __name__ == "__main__":
    main()

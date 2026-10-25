"""Analyze one CSV batch against the local attack-pattern catalog."""
from __future__ import annotations

import argparse
import json
from collections import defaultdict

from attack_memory.retrieval import build_action_index, retrieve
from attack_memory.storage import load_patterns, read_csv, resolve_demo_path


def partition_logs(logs: list[dict[str, str]]) -> list[tuple[str, str, list[dict[str, str]]]]:
    """Never combine known incidents; unknown rows are scoped to their source batch."""
    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for log in logs:
        incident_id = (log.get("incident_id") or "").strip()
        batch_id = (log.get("batch_id") or "").strip()
        key = ("incident", incident_id) if incident_id else ("unassigned batch", batch_id or "UNASSIGNED")
        groups[key].append(log)
    return [(kind, identifier, rows) for (kind, identifier), rows in sorted(groups.items())]


def main() -> None:
    parser = argparse.ArgumentParser(description="Retrieve attack-pattern candidates for a CSV log batch.")
    parser.add_argument("--input", default="data/raw_logs.csv", help="CSV path relative to demo/")
    parser.add_argument("--json", action="store_true", help="Print the full structured candidate evidence")
    parser.add_argument("--top", type=int, default=5, help="Maximum candidates to display")
    parser.add_argument("--incident-id", help="Analyze only this known incident ID")
    args = parser.parse_args()
    logs = read_csv(resolve_demo_path(args.input))
    catalog = load_patterns()["attack_patterns"]
    action_index = build_action_index(catalog)
    groups = partition_logs(logs)
    if args.incident_id:
        groups = [group for group in groups if group[0] == "incident" and group[1] == args.incident_id]
        if not groups:
            parser.error(f"incident_id not found in input: {args.incident_id}")
    output = []
    for kind, identifier, group_logs in groups:
        results = retrieve(catalog, group_logs, action_index)[:max(args.top, 0)]
        output.append({"scope_type": kind, "scope_id": identifier, "log_count": len(group_logs),
                       "candidates": results})
    if args.json:
        print(json.dumps({"input": args.input, "log_count": len(logs), "scopes": output}, ensure_ascii=False, indent=2))
        return
    print(f"Input: {args.input} | logs: {len(logs)} | independent scopes: {len(output)}")
    for group in output:
        print(f"\n== {group['scope_type']}: {group['scope_id']} | {group['log_count']} logs ==")
        if group["scope_type"] == "unassigned batch":
            print("   Scope is a batch-level candidate only; it is not proof that all rows are one incident.")
        if not group["candidates"]:
            print("   No pattern candidate; retain as unclassified evidence and review before adding a pattern.")
            continue
        for item in group["candidates"]:
            print(f"   [{item['case_id']}] {item['name']} — {item['shape']} "
                  f"{item['matched_steps']}/{item['total_steps']} ({item['tier']})")
            order_text = "consistent" if item["order_ok"] else "reversed/unknown"
            if not item["order_assessable"]:
                order_text = "unassessable"
            print(f"      order={order_text} · source fit={item['source_fit_ratio']:.0%} · "
                  f"keyword score={item['keyword_score']} · MITRE={','.join(item['mitre'])}")
            for evidence in item["evidence"]:
                generic = " [generic]" if evidence["generic"] else ""
                print(f"      {evidence['step_id']} {evidence['label']}{generic}: "
                      f"events={','.join(evidence['event_ids'])} sources={','.join(evidence['sources'])}")
            if item["before_steps"]:
                print("      unobserved prefix steps: " + ", ".join(item["before_steps"]))
            if item["gap_steps"]:
                print("      internal gaps: " + ", ".join(item["gap_steps"]))
            if item["predict_next"]:
                prediction = item["predict_next"]
                print(f"      next-step hypothesis: {prediction['label']} "
                      f"[expected source: {'/'.join(prediction['expected_sources'])}]")
            if item["source_mismatches"]:
                print(f"      source mismatches: {len(item['source_mismatches'])} (review; not proof of unrelated activity)")
            if item["keyword_details"]:
                print("      lexical signals: " + "; ".join(item["keyword_details"][:8]))
    print("\nAgent review required: ranking order is not probability; candidates do not assign final case labels.")


if __name__ == "__main__":
    main()

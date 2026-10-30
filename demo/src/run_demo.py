"""Analyze one CSV batch against the local attack-pattern catalog."""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict

from attack_memory import corrections, families
from attack_memory.diagnostics import step_statistics
from attack_memory.retrieval import TIER_RANK, build_action_index, retrieve
from attack_memory.storage import (RAW_LOGS_PATH, latest_link_by_event, load_patterns, read_csv,
                                   read_links, resolve_demo_path)

SCHEMA_VERSION = 1
EVIDENCE_CONFIDENCE_NOTE = (
    "evidence_confidence = matched_required / required_steps × historical linked/matched "
    "step precision over the stored corpus (1.0 when a case has no historical matches). "
    "It is a deterministic evidence ratio, not a probability; tier remains the primary rank."
)

HOST_RE = re.compile(r"(?i)\bhost=([^\s,\"';]+)")


def log_host(log: dict[str, str]) -> str:
    match = HOST_RE.search(log.get("content") or "")
    return match.group(1).casefold() if match else ""


def log_event_id(log: dict[str, str]) -> str:
    return log.get("event_id") or log.get("log_id") or ""


def partition_logs(logs: list[dict[str, str]]) -> list[tuple[str, str, list[dict[str, str]]]]:
    """Known incidents stay whole; unlabeled rows are scoped by batch and then by host.

    Aligning rows from different hosts would let one batch fabricate an ordered chain
    that never existed on any single host.
    """
    groups: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for log in logs:
        incident_id = (log.get("incident_id") or "").strip()
        if incident_id:
            groups[("incident", incident_id)].append(log)
            continue
        batch_id = (log.get("batch_id") or "").strip() or "UNASSIGNED"
        host = log_host(log)
        if host:
            groups[("unassigned host", f"{batch_id} @ {host}")].append(log)
        else:
            groups[("unassigned batch", batch_id)].append(log)
    return [(kind, identifier, rows) for (kind, identifier), rows in sorted(groups.items())]


def scope_hosts(rows: list[dict[str, str]]) -> list[str]:
    return sorted({host for log in rows if (host := log_host(log))})


def scope_review_state(rows: list[dict[str, str]], latest: dict[str, dict[str, str]]) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for log in rows:
        link = latest.get(log_event_id(log))
        if link is not None:
            counts[(link.get("link_status") or "unknown").strip() or "unknown"] += 1
    return dict(sorted(counts.items()))


def filter_candidates(results: list[dict], min_tier: str) -> list[dict]:
    """Keep results at or above min_tier; keyword_only is lexical, not a candidate."""
    floor = TIER_RANK[min_tier]
    return [result for result in results if TIER_RANK[result["tier"]] >= floor]


def case_historical_precision(patterns: list[dict], logs: list[dict[str, str]],
                              links: list[dict[str, str]]) -> dict[str, float | None]:
    """Case-level linked/matched step precision over the stored corpus.

    Reuses :func:`diagnostics.step_statistics` (its fixture-as-linked convention included)
    and aggregates per case so a candidate can show how often its steps historically
    matched rows that were actually reviewed. Cases with no historical match report None.
    """
    matched: Counter[str] = Counter()
    linked: Counter[str] = Counter()
    for stat in step_statistics(patterns, logs, links):
        matched[stat["case_id"]] += stat["matched"]
        linked[stat["case_id"]] += stat["linked"]
    return {case_id: (round(linked[case_id] / total, 3) if total else None)
            for case_id, total in matched.items()}


def evidence_confidence(result: dict, precision: float | None) -> float:
    """Required-step coverage × historical link precision; missing history counts as 1.0.

    This is an evidence ratio, not a calibrated probability, and never changes the tier.
    """
    required_total = result["required_steps"]
    required_ratio = result["matched_required_steps"] / required_total if required_total else 0.0
    return round(required_ratio * (1.0 if precision is None else precision), 3)


def prior_rejections_for(case_id: str, incident_id: str | None = None) -> list[dict]:
    """Prior reviewed rejections for a case, annotated with their summary line."""
    return [{**correction, "summary": corrections.summary_line(correction)}
            for correction in corrections.for_case(case_id, incident_id=incident_id)]


def main() -> None:
    parser = argparse.ArgumentParser(description="Retrieve attack-pattern candidates for a CSV log batch.")
    parser.add_argument("--input", default="data/raw_logs.csv", help="CSV path relative to demo/")
    parser.add_argument("--json", action="store_true", help="Print the full structured candidate evidence")
    parser.add_argument("--top", type=int, default=5, help="Maximum candidates to display")
    parser.add_argument("--min-tier", default="weak", choices=["keyword_only", "weak", "medium", "strong"],
                        help="Hide candidates below this evidence tier (default: weak)")
    parser.add_argument("--incident-id", help="Analyze only this known incident ID")
    args = parser.parse_args()
    input_path = resolve_demo_path(args.input)
    logs = read_csv(input_path)
    catalog = load_patterns()["attack_patterns"]
    action_index = build_action_index(catalog)
    family_data = families.load_families()
    links = read_links()
    latest = latest_link_by_event(links)
    # Historical precision always refers to the stored corpus, not to a fresh batch that
    # has no review history yet. Reuse the input rows when they are that corpus.
    history_logs = logs if input_path == RAW_LOGS_PATH else read_csv(RAW_LOGS_PATH)
    precision_by_case = case_historical_precision(catalog, history_logs, links)
    groups = partition_logs(logs)
    if args.incident_id:
        groups = [group for group in groups if group[0] == "incident" and group[1] == args.incident_id]
        if not groups:
            parser.error(f"incident_id not found in input: {args.incident_id}")
    output = []
    rejection_cache: dict[tuple[str, str | None], list[dict]] = {}
    for kind, identifier, group_logs in groups:
        full_results = retrieve(catalog, group_logs, action_index)
        results = filter_candidates(full_results, args.min_tier)[:max(args.top, 0)]
        scope_incident = identifier if kind == "incident" else None
        for item in results:
            precision = precision_by_case.get(item["case_id"])
            item["historical_precision"] = precision
            item["evidence_confidence"] = evidence_confidence(item, precision)
            rejection_key = (item["case_id"], scope_incident)
            if rejection_key not in rejection_cache:
                rejection_cache[rejection_key] = prior_rejections_for(*rejection_key)
            item["prior_rejections"] = rejection_cache[rejection_key]
        family_matches = []
        family_scope = {results[0]["family_id"]} if results else None
        for family in family_data["families"]:
            if family_scope is not None and family["family_id"] not in family_scope:
                continue
            evidence = families.family_evidence(family, group_logs)
            if evidence:
                family_matches.append({"family_id": family["family_id"], "evidence": evidence})
        output.append({"scope_type": kind, "scope_id": identifier, "log_count": len(group_logs),
                       "hosts": scope_hosts(group_logs),
                       "reviewed_links": scope_review_state(group_logs, latest),
                       "hidden_below_min_tier": len(full_results) - len(
                           filter_candidates(full_results, args.min_tier)),
                       "family_matches": family_matches,
                       "candidates": results})
    if args.json:
        print(json.dumps({"schema_version": SCHEMA_VERSION,
                          "evidence_confidence_note": EVIDENCE_CONFIDENCE_NOTE,
                          "input": args.input, "log_count": len(logs), "min_tier": args.min_tier,
                          "scopes": output}, ensure_ascii=False, indent=2))
        return
    print(f"Input: {args.input} | logs: {len(logs)} | independent scopes: {len(output)}")
    for group in output:
        header = f"\n== {group['scope_type']}: {group['scope_id']} | {group['log_count']} logs"
        if group["hosts"]:
            header += " | hosts=" + ",".join(group["hosts"])
        if group["reviewed_links"]:
            header += " | reviewed " + ",".join(f"{k}={v}" for k, v in group["reviewed_links"].items())
        print(header + " ==")
        reviewed = group["reviewed_links"]
        if reviewed and set(reviewed) == {"fixture"}:
            print("   Every reviewed link in this scope is a synthetic fixture; not a real-world observation.")
        if group["scope_type"] == "unassigned host":
            print("   Scope is one host inside an unlabeled batch; other hosts are separate scopes.")
            print("   It is still a candidate scope, not proof that these rows are one incident.")
        elif group["scope_type"] == "unassigned batch":
            print("   Scope is a batch-level candidate only; it is not proof that all rows are one incident.")
        if group["family_matches"]:
            print("   Family-level evidence (context only; not a case conclusion):")
            for match in group["family_matches"]:
                for evidence in match["evidence"]:
                    print(f"      {match['family_id']}/{evidence['step_id']} {evidence['label']} "
                          f"[family]: events={','.join(evidence['event_ids'])} "
                          f"sources={','.join(evidence['sources'])}")
        if not group["candidates"]:
            if group["hidden_below_min_tier"]:
                print(f"   No candidate at or above --min-tier {args.min_tier}; "
                      f"{group['hidden_below_min_tier']} weaker candidate(s) hidden.")
                print("   Do not recall this case as a precedent; treat the rows as unclassified evidence.")
            else:
                print("   No pattern candidate; retain as unclassified evidence and review before adding a pattern.")
            continue
        if group["hidden_below_min_tier"]:
            print(f"   {group['hidden_below_min_tier']} candidate(s) below --min-tier {args.min_tier} hidden.")
        for item in group["candidates"]:
            optional_total = item["total_steps"] - item["required_steps"]
            required_note = ""
            if optional_total:
                required_note = (f", {item['matched_required_steps']}/{item['required_steps']} required"
                                 f", {optional_total} optional")
            tier_note = item["tier"] if not item["weak_kind"] else f"{item['tier']}: {item['weak_kind']}"
            print(f"   [{item['case_id']} v{item['version']}] {item['name']} — {item['shape']} "
                  f"{item['matched_steps']}/{item['total_steps']} aligned, "
                  f"{item['detected_steps']}/{item['total_steps']} detected"
                  f"{required_note} ({tier_note}) · family={item['family_id']}"
                  + (" · UNREVIEWED" if item.get("review_status") == "unreviewed" else ""))
            if item["weak_kind"]:
                print(f"      weak kind={item['weak_kind']}; read the recall policy before using this "
                      "case as a precedent")
            order_text = "consistent" if item["order_ok"] else "reversed/unknown"
            if not item["order_assessable"]:
                order_text = "unassessable"
            confidence_note = (f"evidence confidence={item['evidence_confidence']:.2f} "
                               "(not a probability)")
            if item["historical_precision"] is not None and item["historical_precision"] < 0.5:
                confidence_note += f"; low historical precision {item['historical_precision']:.0%}"
            print(f"      order={order_text} · source fit={item['source_fit_ratio']:.0%} · "
                  f"{confidence_note} · keyword score={item['keyword_score']} · "
                  f"MITRE={','.join(item['mitre'])}")
            if item["prior_rejections"]:
                print("      prior rejections (boundaries already tested; not precedents):")
                for rejection in item["prior_rejections"]:
                    print(f"         {rejection['summary']}")
            for evidence in item["evidence"]:
                markers = ""
                if evidence["generic"]:
                    markers += " [generic]"
                if not evidence["required"]:
                    markers += " [optional]"
                aligned = evidence["aligned_event_id"] or "none"
                print(f"      {evidence['step_id']} {evidence['label']}{markers}: "
                      f"events={','.join(evidence['event_ids'])} "
                      f"sources={','.join(evidence['sources'])} aligned={aligned}")
            if item["unaligned_detections"]:
                print(f"      detections not used by alignment: {len(item['unaligned_detections'])}")
                for detection in item["unaligned_detections"]:
                    print(f"         {detection['event_id']} -> {detection['step_id']} ({detection['reason']})")
            if item["before_steps"]:
                print("      unobserved prefix steps: " + ", ".join(item["before_steps"]))
            if item["gap_steps"]:
                print("      alignment gaps: " + ", ".join(item["gap_steps"]))
            if item["unobserved_required_steps"]:
                print("      required steps with no detection: "
                      + ", ".join(item["unobserved_required_steps"]))
            if item["unobserved_optional_steps"]:
                print("      optional steps not observed: "
                      + ", ".join(item["unobserved_optional_steps"]))
            if item["predict_next"]:
                prediction = item["predict_next"]
                print(f"      next-step hypothesis: {prediction['label']} "
                      f"[expected source: {'/'.join(prediction['expected_sources'])}]")
            if item["source_mismatches"]:
                print(f"      source mismatches: {len(item['source_mismatches'])} "
                      "(review; not proof of unrelated activity)")
            if item["keyword_details"]:
                print("      lexical signals: " + "; ".join(item["keyword_details"][:8]))
            caveat = (item.get("pattern_scope") or {}).get("variant_note")
            if caveat:
                print(f"      pattern caveat: {caveat}")
            provenance = item.get("provenance") or {}
            if provenance:
                print(f"      provenance: status={provenance.get('evidence_status', 'unknown')}")
            not_observed = (item.get("negative_and_unknown_evidence") or {}).get("not_observed") or []
            if not_observed:
                print("      not observed (unknown, not absent): " + ", ".join(not_observed))
    print("\nAgent review required: ranking order is not probability; candidates do not assign final case labels.")


if __name__ == "__main__":
    main()

"""Evaluate the demo's 8-case memory against dataset units 1001-1140.

Each unit is fed as one isolated incident (never mixed with other units). The memory is
exactly demo/data/attack_patterns.json; nothing is ingested or written back to demo/.

Run from the workspace root:
    python eval/dataset_1001_1140_retrieval.py
    python eval/dataset_1001_1140_retrieval.py --detail 1001,1021,1013
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections import Counter, defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
sys.path.insert(0, str(DEMO / "src"))

from attack_memory.retrieval import build_action_index, retrieve  # noqa: E402
from attack_memory.storage import load_patterns  # noqa: E402

DATASET = ROOT / "dataset"
SOURCES = ("parsed_1001_1080.json", "parsed_1081_1140.json")
RESULTS_DIR = ROOT / "eval" / "results"
ACTION_TIERS = ("strong", "medium", "weak")


def load_units() -> list[dict]:
    units: list[dict] = []
    for name in SOURCES:
        units.extend(json.loads((DATASET / name).read_text(encoding="utf-8")))
    units.sort(key=lambda unit: unit["unit"])
    for unit in units:
        unit["form"] = unit.get("form") or unit.get("family") or "?"
    expected = list(range(1001, 1141))
    if [unit["unit"] for unit in units] != expected:
        raise SystemExit("unit ids are not exactly 1001..1140")
    return units


def rows_for(unit: dict) -> list[dict[str, str]]:
    return [{
        "event_id": f"U{unit['unit']}-{entry['n']}",
        "batch_id": f"B{unit['unit']}",
        "incident_id": f"INC-{unit['unit']}",
        "case_id": "",
        "timestamp": entry["ts"],
        "source": entry["source"],
        "log_id": entry["log_id"],
        "content": entry["content"],
    } for entry in unit["entries"]]


def unmatched_lines(pattern: dict, rows: list[dict[str, str]]) -> list[str]:
    regexes = [re.compile(step["action_regex"]) for step in pattern["steps"]]
    return [row["event_id"] for row in rows
            if not any(regex.search(row["content"]) for regex in regexes)]


def simplify(result: dict) -> dict:
    return {
        "case_id": result["case_id"],
        "tier": result["tier"],
        "weak_kind": result.get("weak_kind"),
        "version": result.get("version", 1),
        "matched": result["matched_steps"],
        "required": result["required_steps"],
        "matched_required": result["matched_required_steps"],
        "detected": result["detected_steps"],
        "shape": result["shape"],
        "order_ok": result["order_ok"],
        "order_assessable": result["order_assessable"],
        "source_fit": result["source_fit_ratio"],
        "keyword": result["keyword_score"],
        "steps": [evidence["step_id"] for evidence in result["evidence"]],
        "evidence": [{
            "step_id": evidence["step_id"],
            "label": evidence["label"],
            "required": evidence["required"],
            "event_ids": evidence["event_ids"],
            "sources": evidence["sources"],
            "aligned": evidence["aligned_event_id"],
        } for evidence in result["evidence"]],
        "unaligned": [{"event_id": detection["event_id"], "step_id": detection["step_id"],
                       "reason": detection["reason"]}
                      for detection in result["unaligned_detections"]],
        "mismatches": [{"event_id": mismatch["event_id"], "step_id": mismatch["step_id"],
                        "observed_source": mismatch["observed_source"]}
                       for mismatch in result["source_mismatches"]],
        "extra_detections": len(result["unaligned_detections"]),
        "unobserved_required": result["unobserved_required_steps"],
        "unobserved_optional": result["unobserved_optional_steps"],
    }


def evaluate(units: list[dict], patterns: list[dict]) -> list[dict]:
    index = build_action_index(patterns)
    by_case = {pattern["case_id"]: pattern for pattern in patterns}
    records = []
    for unit in units:
        rows = rows_for(unit)
        results = retrieve(patterns, rows, index)
        simplified = [simplify(result) for result in results]
        top = simplified[0] if simplified else None
        record = {
            "unit": unit["unit"],
            "form": unit["form"],
            "file": unit["file"],
            "technique": unit["technique"],
            "sources": unit["source_sequence"],
            "line_count": len(rows),
            "candidates": simplified,
            "top1": top["case_id"] if top else None,
            "top1_tier": top["tier"] if top else None,
            "any_candidate": bool(simplified),
            "any_action_evidence": bool(top and top["tier"] in ACTION_TIERS),
            "medium_or_better": bool(top and top["tier"] in ("strong", "medium")),
            "unexplained_for_top1": (len(unmatched_lines(by_case[top["case_id"]], rows))
                                     if top else len(rows)),
        }
        records.append(record)
    return records


def line_level(units: list[dict], patterns: list[dict]) -> dict:
    index = build_action_index(patterns)
    tiers: Counter = Counter()
    top1: Counter = Counter()
    action_lines = 0
    total = 0
    for unit in units:
        for row in rows_for(unit):
            total += 1
            results = retrieve(patterns, [row], index)
            if not results:
                tiers["none"] += 1
                top1["<none>"] += 1
                continue
            tiers[results[0]["tier"]] += 1
            top1[results[0]["case_id"]] += 1
            if results[0]["tier"] in ACTION_TIERS:
                action_lines += 1
    return {"total": total, "action_lines": action_lines,
            "tiers": dict(tiers), "top1": dict(top1)}


def describe(record: dict, unit: dict, patterns: list[dict]) -> str:
    lines = [f"### unit {unit['unit']} · {unit['form']} · {unit['technique']}",
             f"    sources: {' -> '.join(unit['source_sequence'])} | {len(unit['entries'])} lines"]
    if not record["candidates"]:
        lines.append("    no candidate")
        return "\n".join(lines)
    by_case = {pattern["case_id"]: pattern for pattern in patterns}
    rows = rows_for(unit)
    for position, candidate in enumerate(record["candidates"][:3], start=1):
        pattern = by_case[candidate["case_id"]]
        required_total = candidate["required"]
        lines.append(
            f"    #{position} [{candidate['case_id']}] {pattern['name']} — {candidate['tier']} "
            f"{candidate['shape']} | required {candidate['matched_required']}/{required_total} "
            f"| aligned {candidate['matched']}/{len(pattern['steps'])} "
            f"| order={'consistent' if candidate['order_ok'] else ('unassessable' if not candidate['order_assessable'] else 'reversed')} "
            f"| source_fit={candidate['source_fit']:.0%} | keyword={candidate['keyword']}")
        for evidence in candidate["evidence"]:
            marker = "" if evidence["required"] else " [optional]"
            lines.append(f"        {evidence['step_id']} {evidence['label']}{marker}: "
                         f"events={','.join(evidence['event_ids'])} "
                         f"sources={','.join(evidence['sources'])} "
                         f"aligned={evidence['aligned'] or '-'}")
        for detection in candidate["unaligned"]:
            lines.append(f"        extra detection: {detection['event_id']} -> "
                         f"{detection['step_id']} ({detection['reason']})")
        for mismatch in candidate["mismatches"]:
            lines.append(f"        source mismatch: {mismatch['event_id']} -> {mismatch['step_id']} "
                         f"from {mismatch['observed_source']}")
        if candidate["extra_detections"]:
            lines.append(f"        extra detections not used by alignment: {candidate['extra_detections']}")
        if candidate["unobserved_required"]:
            lines.append(f"        unobserved required: {', '.join(candidate['unobserved_required'])}")
        if candidate["unobserved_optional"]:
            lines.append(f"        unobserved optional: {', '.join(candidate['unobserved_optional'])}")
        missed = unmatched_lines(pattern, rows)
        if missed:
            lines.append(f"        lines this pattern cannot explain: {', '.join(missed)}")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the demo memory on dataset units 1001-1140.")
    parser.add_argument("--detail", help="Comma-separated unit ids to print in full")
    parser.add_argument("--out", default=str(RESULTS_DIR / "dataset_1001_1140_retrieval.json"))
    args = parser.parse_args()

    units = load_units()
    patterns = load_patterns()["attack_patterns"]
    records = evaluate(units, patterns)
    lines = line_level(units, patterns)

    top1 = Counter(record["top1"] for record in records)
    top1_tier = Counter(record["top1_tier"] for record in records)
    per_form: dict[str, Counter] = defaultdict(Counter)
    for record in records:
        bucket = per_form[record["form"]]
        bucket["units"] += 1
        bucket[record["top1_tier"] or "none"] += 1
        if record["medium_or_better"]:
            bucket["medium_or_better"] += 1
    case_candidates: Counter = Counter()
    for record in records:
        for candidate in record["candidates"]:
            case_candidates[candidate["case_id"]] += 1

    weak_steps: Counter = Counter()
    for record in records:
        if record["top1_tier"] == "weak" and record["candidates"]:
            for evidence in record["candidates"][0]["evidence"]:
                weak_steps[f"{record['top1']}/{evidence['step_id']}"] += 1
    keyword_cases: Counter = Counter(record["top1"] for record in records
                                     if record["top1_tier"] == "keyword_only")
    weak_kinds: Counter = Counter(record["candidates"][0]["weak_kind"] for record in records
                                  if record["top1_tier"] == "weak")

    summary = {
        "units": len(records),
        "lines": lines["total"],
        "units_with_any_candidate": sum(record["any_candidate"] for record in records),
        "units_with_action_evidence": sum(record["any_action_evidence"] for record in records),
        "units_medium_or_better": sum(record["medium_or_better"] for record in records),
        "units_strong": sum(record["top1_tier"] == "strong" for record in records),
        "top1_cases": dict(top1),
        "top1_tiers": dict(top1_tier),
        "case_candidate_counts": dict(case_candidates),
        "weak_step_counts": dict(weak_steps.most_common(15)),
        "weak_kind_counts": dict(weak_kinds),
        "keyword_only_cases": dict(keyword_cases),
        "per_form": {form: dict(counter) for form, counter in sorted(per_form.items())},
        "line_level": lines,
    }
    payload = {"summary": summary, "units": records}
    path = pathlib.Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"units={summary['units']} lines={summary['lines']}")
    print(f"units with any candidate      : {summary['units_with_any_candidate']}")
    print(f"units with action evidence    : {summary['units_with_action_evidence']}")
    print(f"units medium-or-better (top1) : {summary['units_medium_or_better']}")
    print(f"units strong (top1)           : {summary['units_strong']}")
    print(f"top1 tier distribution        : {dict(top1_tier)}")
    print(f"top1 case distribution        : {dict(top1)}")
    print("\nper form (units / strong / medium / weak / keyword_only / none / medium+):")
    for form, counter in summary["per_form"].items():
        print(f"  {form:<3} units={counter['units']:<3} strong={counter.get('strong', 0):<2} "
              f"medium={counter.get('medium', 0):<2} weak={counter.get('weak', 0):<2} "
              f"keyword={counter.get('keyword_only', 0):<2} none={counter.get('none', 0):<2} "
              f"medium+={counter['medium_or_better']}")
    print(f"\nline level: {lines['action_lines']}/{lines['total']} lines have action evidence; "
          f"tiers={lines['tiers']}")
    print(f"line top1: {lines['top1']}")
    print(f"\nweak top-1 units by matched step: {summary['weak_step_counts']}")
    print(f"weak kind distribution: {summary['weak_kind_counts']}")
    print(f"keyword-only top-1 cases: {summary['keyword_only_cases']}")

    medium_units = [record for record in records if record["medium_or_better"]]
    if medium_units:
        print("\nunits reaching medium or strong:")
        for record in medium_units:
            top = record["candidates"][0]
            print(f"  {record['unit']} [{record['form']}] {top['case_id']} {top['tier']} "
                  f"{top['matched_required']}/{top['required']} required — {record['technique']}")

    if args.detail:
        wanted = {int(item) for item in args.detail.split(",") if item.strip()}
        by_unit = {unit["unit"]: unit for unit in units}
        print()
        for unit_id in sorted(wanted):
            if unit_id in by_unit:
                record = next(item for item in records if item["unit"] == unit_id)
                print(describe(record, by_unit[unit_id], patterns))
                print()
    print(f"\ndetails written to {path}")


if __name__ == "__main__":
    main()

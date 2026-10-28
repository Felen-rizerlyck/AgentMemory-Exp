"""Apply the 1001-1140 ingestion + classification to the real demo memory (one-off).

Unlike eval/simulate_ingest_1001_1140.py this does not use a sandbox: it writes
demo/data/raw_logs.csv, event_pattern_links.csv, attack_patterns.json,
pattern_versions/ and pattern_proposals.json. A backup was taken beforehand.

Run from the workspace root:
    python eval/apply_ingest_1001_1140.py
"""
from __future__ import annotations

import csv
import json
import pathlib
import re
import sys
from collections import Counter, defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
REPORTS = ROOT / "eval" / "ingest_applied_1001_1140"
sys.path.insert(0, str(DEMO / "src"))
sys.path.insert(0, str(ROOT / "eval"))

import simulate_ingest_1001_1140 as sim  # noqa: E402
import attack_memory.ingest as ingest_module  # noqa: E402
import attack_memory.manage as manage  # noqa: E402
import attack_memory.storage as storage  # noqa: E402
from attack_memory.retrieval import build_action_index, retrieve  # noqa: E402


def write_incoming(units: list[dict]) -> pathlib.Path:
    REPORTS.mkdir(parents=True, exist_ok=True)
    path = REPORTS / "incoming_1001_1140.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["event_id", "batch_id", "timestamp",
                                                    "source", "log_id", "content"])
        writer.writeheader()
        for unit in units:
            for entry in unit["entries"]:
                writer.writerow({
                    "event_id": f"SIM-{unit['unit']}-{entry['n']}",
                    "batch_id": f"SIM-B-{unit['unit']}",
                    "timestamp": entry["ts"],
                    "source": entry["source"],
                    "log_id": entry["log_id"],
                    "content": entry["content"],
                })
    return path


def link_family_step(manage_module, units, by_batch, case_id, step_id, regex, form, anchor):
    for unit in units:
        if unit["form"] != form or unit["unit"] == anchor:
            continue
        ids = [row["event_id"] for row in by_batch[f"SIM-B-{unit['unit']}"]
               if re.search(regex, row["content"])]
        if ids:
            manage_module.append_links(ids, f"SIM-INC-{unit['unit']}", case_id, step_id,
                                       "related",
                                       f"applied unit {unit['unit']}: instantiates {case_id}/{step_id}")


def main() -> None:
    if storage.RAW_LOGS_PATH.parent.parent != DEMO:
        raise SystemExit(f"not the real demo: {storage.RAW_LOGS_PATH}")
    existing = storage.read_csv(storage.RAW_LOGS_PATH)
    if any((row.get("event_id") or "").startswith("SIM-") for row in existing):
        raise SystemExit("SIM- events already exist; refusing to ingest twice")

    units = sim.load_units()
    incoming = write_incoming(units)
    links_before = len(storage.read_links(storage.LINKS_PATH))
    appended, withheld = ingest_module.ingest(incoming)

    catalog = manage.load_validated_catalog()
    patterns = catalog["attack_patterns"]
    patterns_before = len(patterns)
    index = build_action_index(patterns)
    logs = storage.read_csv(storage.RAW_LOGS_PATH)
    by_batch: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in logs:
        batch = (row.get("batch_id") or "").strip()
        if batch.startswith("SIM-B-"):
            by_batch[batch].append(row)

    records = []
    decisions: Counter = Counter()
    for unit in units:
        rows = by_batch[f"SIM-B-{unit['unit']}"]
        results = retrieve(patterns, rows, index)
        top = results[0] if results else None
        incident = f"SIM-INC-{unit['unit']}"
        decision = "unclassified"
        case_id = ""
        step_id = ""
        if top is not None and top["tier"] in ("strong", "medium"):
            for evidence in top["evidence"]:
                manage.append_links(
                    evidence["event_ids"], incident, top["case_id"], evidence["step_id"],
                    "confirmed",
                    f"applied unit {unit['unit']}: {top['tier']} chain matched "
                    f"{top['case_id']}/{evidence['step_id']}")
            decision, case_id = "confirmed_existing", top["case_id"]
        elif unit["form"] == "FA" and unit["unit"] != 1081:
            manage.append_links([row["event_id"] for row in rows], incident, "CASE-005", "",
                                "related", f"applied unit {unit['unit']}: FA ransomware family")
            decision, case_id = "related_family", "CASE-005"
        elif unit["form"] == "FC" and unit["unit"] != 1121:
            manage.append_links([row["event_id"] for row in rows], incident, "CASE-007", "",
                                "related", f"applied unit {unit['unit']}: FC supply-chain family")
            decision, case_id = "related_family", "CASE-007"
        elif top is not None and top["tier"] == "weak" and top["weak_kind"] in ("prefix", "tail"):
            for evidence in top["evidence"]:
                manage.append_links(
                    evidence["event_ids"], incident, top["case_id"], evidence["step_id"],
                    "related",
                    f"applied unit {unit['unit']}: weak {top['weak_kind']} shares "
                    f"{top['case_id']}/{evidence['step_id']}")
                step_id = evidence["step_id"]
            decision, case_id = "related_step", top["case_id"]
        decisions[decision] += 1
        records.append({"unit": unit["unit"], "form": unit["form"],
                        "technique": unit["technique"], "line_count": len(rows),
                        "top1": top["case_id"] if top else "",
                        "tier": top["tier"] if top else "none",
                        "weak_kind": (top or {}).get("weak_kind") or "",
                        "decision": decision, "case_id": case_id, "step_id": step_id})

    logs = storage.read_csv(storage.RAW_LOGS_PATH)
    links = storage.read_links(storage.LINKS_PATH)

    proposals = []
    fa_events = [row["event_id"] for unit in units if unit["form"] == "FA" and unit["unit"] != 1081
                 for row in by_batch[f"SIM-B-{unit['unit']}"]
                 if re.search(sim.FA_STEP_REGEX, row["content"])]
    fa_step = {"step_id": "S9", "order": 9, "action_id": "fa_recovery_or_encrypt_variant",
               "label": "恢复能力破坏/批量加密变体（FA 家族）", "action_regex": sim.FA_STEP_REGEX,
               "expected_sources": ["hids"], "generic": True, "required": False}
    proposals.append(sim.propose_family_step(
        manage, patterns, logs, links, "CASE-005", fa_step, fa_events,
        "FA ransomware variants share destruction/encryption stages beyond the canonical chain"))
    catalog = manage.load_validated_catalog()
    patterns = catalog["attack_patterns"]
    if proposals[-1].get("accepted_version"):
        link_family_step(manage, units, by_batch, "CASE-005", "S9", sim.FA_STEP_REGEX, "FA", 1081)
    links = storage.read_links(storage.LINKS_PATH)

    fc_events = [row["event_id"] for unit in units if unit["form"] == "FC" and unit["unit"] != 1121
                 for row in by_batch[f"SIM-B-{unit['unit']}"]
                 if re.search(sim.FC_STEP_REGEX, row["content"])]
    fc_step = {"step_id": "S4", "order": 4, "action_id": "fc_ci_execution_variant",
               "label": "CI 构建期执行/凭据访问变体（FC 家族）", "action_regex": sim.FC_STEP_REGEX,
               "expected_sources": ["hids"], "generic": True, "required": False}
    proposals.append(sim.propose_family_step(
        manage, patterns, logs, links, "CASE-007", fc_step, fc_events,
        "FC supply-chain variants share build-time execution and CI credential access"))
    catalog = manage.load_validated_catalog()
    patterns = catalog["attack_patterns"]
    if proposals[-1].get("accepted_version"):
        link_family_step(manage, units, by_batch, "CASE-007", "S4", sim.FC_STEP_REGEX, "FC", 1121)
    links = storage.read_links(storage.LINKS_PATH)

    audit_issues = manage.audit_problems(patterns, logs, links, manage.load_proposals())

    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / "audit_after_apply.txt").write_text(
        "\n".join(audit_issues) + ("\n" if audit_issues else "clean\n"), encoding="utf-8")
    (REPORTS / "proposals.json").write_text(
        json.dumps(proposals, ensure_ascii=False, indent=2), encoding="utf-8")
    with (REPORTS / "decision_report.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)

    related_counts = {pattern["case_id"]: len(manage.related_incidents(links, pattern["case_id"]))
                      for pattern in patterns}
    versions = {pattern["case_id"]: manage.pattern_version(pattern) for pattern in patterns
                if manage.pattern_version(pattern) > 1}
    summary = {
        "rows_added": appended, "incident_ids_withheld": withheld,
        "links_before": links_before, "links_after": len(links),
        "decisions": dict(decisions), "patterns_before": patterns_before,
        "patterns_after": len(patterns), "new_cases_created": len(patterns) - patterns_before,
        "versions_after": versions, "related_incidents": related_counts,
        "accepted_proposals": [{"case_id": item["case_id"], "step_id": item["step_id"],
                                "version": item["accepted_version"]}
                               for item in proposals if item.get("accepted_version")],
        "proposals": proposals,
        "audit_problems": audit_issues,
        "raw_logs": str(storage.RAW_LOGS_PATH), "links": str(storage.LINKS_PATH),
        "patterns": str(storage.PATTERNS_PATH),
    }
    (REPORTS / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"rows_added={appended} links {links_before}->{len(links)}")
    print(f"decisions: {dict(decisions)}")
    print(f"patterns {patterns_before}->{len(patterns)}; versions {versions}")
    print(f"related incidents: {related_counts}")
    print(f"accepted: {summary['accepted_proposals']}")
    print(f"audit problems: {len(audit_issues)}")
    print(f"reports: {REPORTS}")


if __name__ == "__main__":
    main()

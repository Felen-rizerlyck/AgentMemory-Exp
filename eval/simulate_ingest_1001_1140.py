"""Simulate ingesting dataset units 1001-1140 with variant association and gated evolution.

Policy (the skill's deterministic part):
  strong / medium        -> confirmed links to the matched case
  weak prefix/tail       -> related link to the matched step (hypothesis, no case label)
  FA / FC family unit    -> related association to CASE-005 / CASE-007 (no step, no label)
  anything weaker        -> unclassified, not a case

Then two reviewed family-level steps are proposed and accepted through the gate, and the
`add-pattern` guard is exercised to show a singleton cannot become a new case.

Run from the workspace root:
    python eval/simulate_ingest_1001_1140.py
"""
from __future__ import annotations

import csv
import json
import pathlib
import re
import shutil
import sys
from collections import Counter, defaultdict

ROOT = pathlib.Path(__file__).resolve().parents[1]
SIM_DIR = ROOT / "eval" / "ingest_simulation_1001_1140"
SANDBOX = SIM_DIR / "demo"
DATASET = ROOT / "dataset"
SOURCES = ("parsed_1001_1080.json", "parsed_1081_1140.json")

FA_STEP_REGEX = (r"(?i)vssadmin|wbadmin|bcdedit|wevtutil|delete\s+catalog|shred|gpg|"
                 r"openssl\s+enc|cipher\s+/e|rm\s+-rf\s+/backup")
FC_STEP_REGEX = (r"(?i)setup\.py|pip install|npm i\b|mvn\b|docker|kubectl|terraform|"
                 r"gem (?:build|push)|ci_job_token|runner|agent\.env|\.git-credentials|"
                 r"id_rsa|sha256sum|nslookup|git push")


def prepare_sandbox() -> None:
    if SIM_DIR.exists():
        shutil.rmtree(SIM_DIR)
    SIM_DIR.mkdir(parents=True)
    shutil.copytree(ROOT / "demo", SANDBOX)


def load_units() -> list[dict]:
    units: list[dict] = []
    for name in SOURCES:
        units.extend(json.loads((DATASET / name).read_text(encoding="utf-8")))
    units.sort(key=lambda unit: unit["unit"])
    for unit in units:
        unit["form"] = unit.get("form") or unit.get("family") or "?"
    if [unit["unit"] for unit in units] != list(range(1001, 1141)):
        raise SystemExit("unit ids are not exactly 1001..1140")
    return units


def write_incoming(units: list[dict]) -> pathlib.Path:
    path = SIM_DIR / "incoming_1001_1140.csv"
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


def propose_family_step(manage, patterns: list[dict], logs: list[dict], links: list[dict],
                        case_id: str, step: dict, event_ids: list[str],
                        rationale: str) -> dict:
    proposal = {"case_id": case_id, "base_version": 1, "operation": "add_step",
                "rationale": rationale, "supporting_event_ids": event_ids, "step": step}
    evaluation = manage.evaluate_proposal(patterns, logs, links, proposal)
    record = {"case_id": case_id, "step_id": step["step_id"], "ok": evaluation["ok"],
              "problems": evaluation["problems"], "metrics": evaluation["metrics"],
              "proposal_id": None, "status": None}
    if evaluation["ok"]:
        created, _ = manage.create_proposal(proposal)
        record["proposal_id"] = created["proposal_id"]
        record["status"] = created["status"]
        if created["status"] == "ready":
            accepted = manage.accept_proposal(created["proposal_id"],
                                              f"simulation: {rationale}", auto=True)
            record["accepted_version"] = accepted["new_version"]
    return record


def main() -> None:
    prepare_sandbox()
    sys.path.insert(0, str(SANDBOX / "src"))

    import attack_memory.ingest as ingest_module  # noqa: E402
    import attack_memory.manage as manage  # noqa: E402
    import attack_memory.storage as storage  # noqa: E402
    from attack_memory.retrieval import build_action_index, retrieve  # noqa: E402

    if storage.RAW_LOGS_PATH.parent.parent != SANDBOX:
        raise SystemExit(f"not sandboxed: {storage.RAW_LOGS_PATH}")

    links_before = len(storage.read_links(storage.LINKS_PATH))
    units = load_units()
    incoming = write_incoming(units)
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
    decision_counts: Counter = Counter()
    for unit in units:
        rows = by_batch.get(f"SIM-B-{unit['unit']}") or []
        results = retrieve(patterns, rows, index)
        top = results[0] if results else None
        incident = f"SIM-INC-{unit['unit']}"
        decision = "unclassified"
        related_case = ""
        related_step = ""
        linked_events = 0

        if top is not None and top["tier"] in ("strong", "medium"):
            for evidence in top["evidence"]:
                linked_events += manage.append_links(
                    evidence["event_ids"], incident, top["case_id"], evidence["step_id"],
                    "confirmed",
                    f"simulation unit {unit['unit']}: {top['tier']} chain matched "
                    f"{top['case_id']}/{evidence['step_id']}")
            decision, related_case = "confirmed_existing", top["case_id"]
        elif unit["form"] == "FA" and unit["unit"] != 1081:
            linked_events += manage.append_links(
                [row["event_id"] for row in rows], incident, "CASE-005", "", "related",
                f"simulation unit {unit['unit']}: FA ransomware family, different tooling")
            decision, related_case = "related_family", "CASE-005"
        elif unit["form"] == "FC" and unit["unit"] != 1121:
            linked_events += manage.append_links(
                [row["event_id"] for row in rows], incident, "CASE-007", "", "related",
                f"simulation unit {unit['unit']}: FC supply-chain family, different technique")
            decision, related_case = "related_family", "CASE-007"
        elif top is not None and top["tier"] == "weak" and top["weak_kind"] in ("prefix", "tail"):
            for evidence in top["evidence"]:
                linked_events += manage.append_links(
                    evidence["event_ids"], incident, top["case_id"], evidence["step_id"],
                    "related",
                    f"simulation unit {unit['unit']}: weak {top['weak_kind']} shares "
                    f"{top['case_id']}/{evidence['step_id']}")
                related_step = evidence["step_id"]
            decision, related_case = "related_step", top["case_id"]
        decision_counts[decision] += 1
        records.append({
            "unit": unit["unit"], "form": unit["form"], "technique": unit["technique"],
            "sources": "->".join(unit["source_sequence"]), "line_count": len(rows),
            "top1": top["case_id"] if top else "", "tier": top["tier"] if top else "none",
            "weak_kind": (top or {}).get("weak_kind") or "",
            "decision": decision, "case_id": related_case, "step_id": related_step,
            "linked_events": linked_events,
        })

    logs = storage.read_csv(storage.RAW_LOGS_PATH)
    links = storage.read_links(storage.LINKS_PATH)

    # Two reviewed family-level enrichments, each supported by many related incidents.
    proposals = []
    fa_events = [row["event_id"] for unit in units if unit["form"] == "FA" and unit["unit"] != 1081
                 for row in by_batch[f"SIM-B-{unit['unit']}"]
                 if re.search(FA_STEP_REGEX, row["content"])]
    fa_step = {"step_id": "S9", "order": 9, "action_id": "fa_recovery_or_encrypt_variant",
               "label": "恢复能力破坏/批量加密变体（FA 家族）", "action_regex": FA_STEP_REGEX,
               "expected_sources": ["hids"], "generic": True, "required": False}
    proposals.append(propose_family_step(
        manage, patterns, logs, links, "CASE-005", fa_step, fa_events,
        "FA ransomware variants share destruction/encryption stages beyond the canonical chain"))
    catalog = manage.load_validated_catalog()
    patterns = catalog["attack_patterns"]
    index = build_action_index(patterns)
    links = storage.read_links(storage.LINKS_PATH)
    if proposals[-1].get("accepted_version"):
        for unit in units:
            if unit["form"] != "FA" or unit["unit"] == 1081:
                continue
            ids = [row["event_id"] for row in by_batch[f"SIM-B-{unit['unit']}"]
                   if re.search(FA_STEP_REGEX, row["content"])]
            if ids:
                manage.append_links(ids, f"SIM-INC-{unit['unit']}", "CASE-005", "S9", "related",
                                    f"simulation unit {unit['unit']}: instantiates CASE-005/S9")

    fc_events = [row["event_id"] for unit in units if unit["form"] == "FC" and unit["unit"] != 1121
                 for row in by_batch[f"SIM-B-{unit['unit']}"]
                 if re.search(FC_STEP_REGEX, row["content"])]
    fc_step = {"step_id": "S4", "order": 4, "action_id": "fc_ci_execution_variant",
               "label": "CI 构建期执行/凭据访问变体（FC 家族）", "action_regex": FC_STEP_REGEX,
               "expected_sources": ["hids"], "generic": True, "required": False}
    proposals.append(propose_family_step(
        manage, patterns, logs, links, "CASE-007", fc_step, fc_events,
        "FC supply-chain variants share build-time execution and CI credential access"))
    catalog = manage.load_validated_catalog()
    patterns = catalog["attack_patterns"]
    if proposals[-1].get("accepted_version"):
        for unit in units:
            if unit["form"] != "FC" or unit["unit"] == 1121:
                continue
            ids = [row["event_id"] for row in by_batch[f"SIM-B-{unit['unit']}"]
                   if re.search(FC_STEP_REGEX, row["content"])]
            if ids:
                manage.append_links(ids, f"SIM-INC-{unit['unit']}", "CASE-007", "S4", "related",
                                    f"simulation unit {unit['unit']}: instantiates CASE-007/S4")
    links = storage.read_links(storage.LINKS_PATH)

    # Anti-fragmentation guard: a singleton cannot become a new case.
    guard_pattern = {"steps": [{"action_regex": r"(?i)[a-z]"}]}
    guard = {}
    try:
        manage.require_pattern_support(guard_pattern, ["INC-CASE-001-001"], logs)
        guard["singleton"] = "unexpectedly allowed"
    except ValueError as error:
        guard["singleton"] = str(error)
    guard["two_incidents"] = manage.require_pattern_support(
        guard_pattern, ["INC-CASE-001-001", "INC-CASE-002-001"], logs)

    audit_issues = manage.audit_problems(patterns, logs, links, manage.load_proposals())
    (SIM_DIR / "audit_after_ingest.txt").write_text(
        "\n".join(audit_issues) + ("\n" if audit_issues else "clean\n"), encoding="utf-8")
    (SIM_DIR / "proposals.json").write_text(
        json.dumps(proposals, ensure_ascii=False, indent=2), encoding="utf-8")

    with (SIM_DIR / "decision_report.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)

    related_counts = {pattern["case_id"]: len(manage.related_incidents(links, pattern["case_id"]))
                      for pattern in patterns}
    versions = {pattern["case_id"]: manage.pattern_version(pattern) for pattern in patterns
                if manage.pattern_version(pattern) > 1}
    accepted = [item for item in proposals if item.get("accepted_version")]
    summary = {
        "units": len(units),
        "rows_added": appended,
        "incident_ids_withheld": withheld,
        "links_before": links_before,
        "links_after": len(links),
        "decisions": dict(decision_counts),
        "patterns_before": patterns_before,
        "patterns_after": len(patterns),
        "new_cases_created": len(patterns) - patterns_before,
        "versions_after": versions,
        "related_incidents": related_counts,
        "accepted_proposals": [{"case_id": item["case_id"], "step_id": item["step_id"],
                                "version": item["accepted_version"]} for item in accepted],
        "proposals": proposals,
        "guard": guard,
        "audit_problems": audit_issues,
        "unclassified_units": decision_counts.get("unclassified", 0),
        "family_units_attached": decision_counts.get("related_family", 0),
        "step_variants_attached": decision_counts.get("related_step", 0),
        "naive_new_cases_counterfactual": len(units) - decision_counts.get("confirmed_existing", 0),
        "sandbox_data": str(SANDBOX / "data"),
    }
    (SIM_DIR / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"units={summary['units']} rows_added={summary['rows_added']} "
          f"links {summary['links_before']}->{summary['links_after']}")
    print(f"decisions: {summary['decisions']}")
    print(f"patterns {summary['patterns_before']} -> {summary['patterns_after']} "
          f"(new cases {summary['new_cases_created']})")
    print(f"versions after: {summary['versions_after']}")
    print(f"related incidents: {summary['related_incidents']}")
    print(f"accepted proposals: {summary['accepted_proposals']}")
    print(f"anti-fragmentation counterfactual (one case per unconfirmed unit): "
          f"{summary['naive_new_cases_counterfactual']}")
    print(f"audit problems after ingest: {len(audit_issues)}")
    for problem in audit_issues[:8]:
        print(f"  - {problem}")
    for proposal in proposals:
        print(f"  proposal {proposal['case_id']}/{proposal['step_id']}: "
              f"ok={proposal['ok']} status={proposal['status']} "
              f"version={proposal.get('accepted_version')}")
        for problem in proposal["problems"]:
            print(f"    BLOCKED: {problem}")
    print(f"guard singleton: {guard['singleton'][:90]}")
    print(f"guard two incidents: {guard['two_incidents']}")
    print(f"sandbox memory: {SIM_DIR / 'demo' / 'data'}")
    print(f"reports: {SIM_DIR / 'summary.json'}, {SIM_DIR / 'decision_report.csv'}")


if __name__ == "__main__":
    main()

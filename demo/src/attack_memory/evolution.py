"""Evolution proposals: deterministic gate, versions, accept/reject/rollback."""
from __future__ import annotations

import copy
import datetime as dt
import json
import re
from collections import defaultdict

from . import storage
from .catalog import (MIN_SUPPORT_INCIDENTS, load_validated_catalog, maturity, now_iso,
                      pattern_version, version_path, write_version_snapshot)
from .links import confirmed_pairs, derived_observations, related_incidents, support_pairs
from .retrieval import build_action_index, extract_log_actions, match_pattern, retrieve
from .storage import (atomic_write_json, latest_link_by_event, read_csv, read_links,
                      update_event_labels, validate_pattern)

PROPOSALS_PATH = storage.DATA_DIR / "pattern_proposals.json"
OPERATIONS = ("add_step", "extend_step", "add_source", "set_required")
AUTO_OPERATIONS = frozenset({"add_step", "extend_step", "add_source"})


def load_proposals(path=None) -> list[dict]:
    path = path or PROPOSALS_PATH
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("proposals"), list):
        raise ValueError("pattern_proposals.json must be an object with a proposals list")
    return data["proposals"]


def save_proposals(path, proposals: list[dict]) -> None:
    atomic_write_json(path, {"schema_version": 1, "proposals": proposals})


def new_proposal_id(existing: list[dict]) -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"PROP-{stamp}"
    if all(item.get("proposal_id") != base for item in existing):
        return base
    counter = 2
    while any(item.get("proposal_id") == f"{base}-{counter}" for item in existing):
        counter += 1
    return f"{base}-{counter}"


def validate_proposal(proposal: dict) -> None:
    if not isinstance(proposal, dict):
        raise ValueError("proposal must be a JSON object")
    for field in ("case_id", "base_version", "operation", "rationale", "supporting_event_ids"):
        if field not in proposal:
            raise ValueError(f"proposal missing {field}")
    if proposal["operation"] not in OPERATIONS:
        raise ValueError(f"unsupported operation {proposal['operation']!r}; use one of {', '.join(OPERATIONS)}")
    if not isinstance(proposal["base_version"], int) or isinstance(proposal["base_version"], bool) \
            or proposal["base_version"] < 1:
        raise ValueError("base_version must be a positive integer")
    for field in ("case_id", "rationale"):
        if not isinstance(proposal[field], str) or not proposal[field].strip():
            raise ValueError(f"{field} must be a non-empty string")
    events = proposal["supporting_event_ids"]
    if not isinstance(events, list) or not events or not all(isinstance(e, str) and e.strip() for e in events):
        raise ValueError("supporting_event_ids must be a non-empty list of event IDs")
    operation = proposal["operation"]
    if operation == "add_step":
        step = proposal.get("step")
        if not isinstance(step, dict):
            raise ValueError("add_step requires a step object")
        for field in ("step_id", "order", "action_id", "action_regex", "expected_sources"):
            if field not in step:
                raise ValueError(f"proposed step missing {field}")
    else:
        if not isinstance(proposal.get("step_id"), str) or not proposal["step_id"].strip():
            raise ValueError(f"{operation} requires step_id")
    if operation == "extend_step":
        regex = proposal.get("action_regex")
        if not isinstance(regex, str) or not regex.strip():
            raise ValueError("extend_step requires action_regex")
        re.compile(regex)
    if operation == "add_source":
        sources = proposal.get("add_sources")
        if not isinstance(sources, list) or not sources or not all(isinstance(s, str) and s.strip() for s in sources):
            raise ValueError("add_source requires a non-empty add_sources list")
    if operation == "set_required" and not isinstance(proposal.get("required"), bool):
        raise ValueError("set_required requires required: true|false")
    if "author" in proposal and proposal["author"] not in ("agent", "human"):
        raise ValueError("author must be agent or human")


def apply_delta(pattern: dict, proposal: dict) -> dict:
    operation = proposal["operation"]
    candidate = copy.deepcopy(pattern)
    steps = candidate["steps"]
    if operation == "add_step":
        step = copy.deepcopy(proposal["step"])
        step.setdefault("required", True)
        if any(item["step_id"] == step["step_id"] for item in steps):
            raise ValueError(f"duplicate step_id {step['step_id']}")
        if any(item["action_id"] == step["action_id"] for item in steps):
            raise ValueError(f"duplicate action_id {step['action_id']}")
        steps.append(step)
        steps.sort(key=lambda item: int(item["order"]))
    else:
        target = next((item for item in steps if item["step_id"] == proposal["step_id"]), None)
        if target is None:
            raise ValueError(f"unknown step_id {proposal['step_id']} in {candidate['case_id']}")
        if operation == "extend_step":
            target["action_regex"] = proposal["action_regex"]
        elif operation == "add_source":
            current = list(target.get("expected_sources") or [])
            for source in proposal["add_sources"]:
                if source.casefold() not in {item.casefold() for item in current}:
                    current.append(source)
            target["expected_sources"] = current
        elif operation == "set_required":
            target["required"] = proposal["required"]
    return candidate


def _case_metrics(pattern: dict, rows_by_incident: dict[str, list[dict[str, str]]],
                  incidents: set[str]) -> tuple[float, int]:
    """Source-compatible required coverage and strong count across a case's incidents."""
    index = build_action_index([pattern])
    required_total = sum(1 for step in pattern["steps"] if step.get("required", True))
    coverages: list[float] = []
    strong = 0
    for incident in sorted(incidents):
        rows = rows_by_incident.get(incident) or []
        if not rows:
            continue
        result = match_pattern(pattern, rows, extract_log_actions(rows, index))
        covered = {entry["step_id"] for entry in result["evidence"] if entry.get("required", True)}
        coverages.append(len(covered) / required_total if required_total else 0.0)
        if result["tier"] == "strong":
            strong += 1
    return (sum(coverages) / len(coverages) if coverages else 0.0), strong


def evaluate_proposal(patterns: list[dict], logs: list[dict[str, str]],
                      links: list[dict[str, str]], proposal: dict) -> dict:
    """Deterministic gate: evidence, support, pollution and shadow regression checks."""
    problems: list[str] = []
    metrics: dict = {}
    case_id = proposal["case_id"]
    base = next((pattern for pattern in patterns if pattern["case_id"] == case_id), None)
    if base is None:
        return {"ok": False, "problems": [f"unknown case_id {case_id}"], "metrics": {},
                "candidate": None, "auto_eligible": False}
    version = pattern_version(base)
    if proposal["base_version"] != version:
        problems.append(f"stale proposal: base_version={proposal['base_version']} but {case_id} is at v{version}")
    try:
        candidate = apply_delta(base, proposal)
        candidate["version"] = version + 1
        candidate["supersedes"] = version
        candidate["updated_at"] = now_iso()
        validate_pattern(candidate)
        catalog = [candidate if pattern["case_id"] == case_id else pattern for pattern in patterns]
        build_action_index(catalog)
    except ValueError as error:
        return {"ok": False, "problems": [str(error)], "metrics": {},
                "candidate": None, "auto_eligible": False}

    operation = proposal["operation"]
    known_events = {(row.get("event_id") or ""): row for row in logs}
    latest = latest_link_by_event(links)

    def resolve_incident(row: dict[str, str]) -> str:
        """Related units carry no case label, so fall back to their reviewed link."""
        direct = (row.get("incident_id") or "").strip()
        if direct:
            return direct
        link = latest.get(row.get("event_id") or "") or {}
        if (link.get("link_status") or "").strip() in ("candidate", "confirmed", "related", "fixture"):
            return (link.get("incident_id") or "").strip()
        return ""

    supporting: list[dict[str, str]] = []
    for event_id in proposal["supporting_event_ids"]:
        row = known_events.get(event_id)
        if row is None:
            problems.append(f"unknown supporting event {event_id}")
        else:
            supporting.append(row)

    support_incidents = sorted({resolve_incident(row) for row in supporting} - {""})
    confirmed_incidents = {incident for incident, case in confirmed_pairs(links) if case == case_id}
    case_support = {incident for incident, case in support_pairs(links) if case == case_id}
    unknown_incidents = [incident for incident in support_incidents if incident not in case_support]
    if unknown_incidents:
        problems.append(
            f"supporting incident(s) not confirmed or related for {case_id}: "
            f"{', '.join(unknown_incidents)}"
        )
    if len(support_incidents) < MIN_SUPPORT_INCIDENTS:
        problems.append(
            f"need at least {MIN_SUPPORT_INCIDENTS} independent incidents, found {len(support_incidents)}"
        )
    metrics["support_incidents"] = len(support_incidents)
    metrics["support_events"] = len(supporting)
    metrics["confirmed_incidents"] = len(confirmed_incidents)
    metrics["related_incidents"] = len(related_incidents(links, case_id))
    metrics["maturity"] = maturity(len(confirmed_incidents))

    target_id = proposal["step"]["step_id"] if operation == "add_step" else proposal["step_id"]
    target = next((step for step in candidate["steps"] if step["step_id"] == target_id), None)
    if target is None:
        problems.append(f"step {target_id} is not present after the delta")
        return {"ok": False, "problems": problems, "metrics": metrics,
                "candidate": None, "auto_eligible": False}
    regex = re.compile(target["action_regex"])

    if operation == "set_required" and proposal["required"] is False:
        observed_incidents = set()
        for row in logs:
            incident = (row.get("incident_id") or "").strip()
            if incident in confirmed_incidents and regex.search(row.get("content") or ""):
                observed_incidents.add(incident)
        metrics["observed_incidents"] = len(observed_incidents)
        metrics["confirmed_incidents"] = len(confirmed_incidents)
        if confirmed_incidents and observed_incidents == confirmed_incidents:
            problems.append(
                f"cannot demote {target_id}: it is observed in every confirmed incident, "
                "so demotion only weakens the canonical chain"
            )
    else:
        not_matching = [row.get("event_id") for row in supporting
                        if regex.search(row.get("content") or "") is None]
        if not_matching:
            problems.append(
                f"supporting event(s) do not match the proposed step: {', '.join(not_matching)}"
            )
    if operation == "add_source":
        allowed = {str(source).casefold() for source in target.get("expected_sources") or []}
        wrong_source = [row.get("event_id") for row in supporting
                        if (row.get("source") or "").casefold() not in allowed]
        if wrong_source:
            problems.append(f"supporting event(s) have an unexpected source: {', '.join(wrong_source)}")

    if operation in ("add_step", "extend_step"):
        foreign = [row.get("event_id") for row in logs
                   if regex.search(row.get("content") or "")
                   and (row.get("case_id") or "").strip() not in ("", case_id)]
        metrics["foreign_matches"] = len(foreign)
        if foreign:
            problems.append(f"proposed step regex also matches other cases: {', '.join(foreign[:5])}")

    if operation == "extend_step":
        previous = next((step for step in base["steps"] if step["step_id"] == target_id), None)
        old_regex = re.compile(previous["action_regex"]) if previous else None
        narrowing = [row.get("event_id") for row in logs
                     if old_regex is not None and old_regex.search(row.get("content") or "")
                     and not regex.search(row.get("content") or "")]
        metrics["narrowing"] = len(narrowing)
        if narrowing:
            problems.append(f"new regex no longer matches {len(narrowing)} event(s) (narrowing needs human review)")

    rows_by_incident: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in logs:
        incident = resolve_incident(row)
        if incident:
            rows_by_incident[incident].append(row)
    current_index = build_action_index(patterns)
    candidate_index = build_action_index(catalog)
    top1_changes = []
    for incident, rows in rows_by_incident.items():
        before = retrieve(patterns, rows, current_index)
        after = retrieve(catalog, rows, candidate_index)
        before_top = before[0]["case_id"] if before else None
        after_top = after[0]["case_id"] if after else None
        if before_top == after_top:
            continue
        allowed = incident in support_incidents and after_top == case_id and before_top != case_id
        if not allowed:
            top1_changes.append({"incident_id": incident, "before": before_top, "after": after_top})
    metrics["top1_changes"] = top1_changes
    if top1_changes:
        problems.append("top-1 changed for " + ", ".join(
            f"{change['incident_id']} ({change['before']}->{change['after']})" for change in top1_changes))

    before_coverage, before_strong = _case_metrics(base, rows_by_incident, confirmed_incidents)
    after_coverage, after_strong = _case_metrics(candidate, rows_by_incident, confirmed_incidents)
    metrics.update({
        "coverage_before": round(before_coverage, 3), "coverage_after": round(after_coverage, 3),
        "strong_before": before_strong, "strong_after": after_strong,
    })
    if after_strong < before_strong:
        problems.append(
            f"strong incidents would drop from {before_strong} to {after_strong}; mark the step optional"
        )
    if after_coverage + 1e-9 < before_coverage:
        problems.append(
            f"required coverage would drop from {before_coverage:.2f} to {after_coverage:.2f}"
        )

    auto_eligible = (not problems and operation in AUTO_OPERATIONS
                     and metrics.get("foreign_matches", 0) == 0
                     and metrics.get("narrowing", 0) == 0
                     and len(case_support) >= MIN_SUPPORT_INCIDENTS)
    return {"ok": not problems, "problems": problems, "metrics": metrics,
            "candidate": candidate, "catalog": catalog, "auto_eligible": auto_eligible}


def create_proposal(payload: dict) -> tuple[dict, dict]:
    validate_proposal(payload)
    patterns = load_validated_catalog()["attack_patterns"]
    logs = read_csv(storage.RAW_LOGS_PATH)
    links = read_links(storage.LINKS_PATH)
    evaluation = evaluate_proposal(patterns, logs, links, payload)
    proposals = load_proposals(PROPOSALS_PATH)
    proposal = dict(payload)
    proposal.update({
        "proposal_id": new_proposal_id(proposals),
        "status": "ready" if evaluation["ok"] else "candidate",
        "created_at": now_iso(),
        "metrics": evaluation["metrics"],
        "auto_eligible": evaluation["auto_eligible"],
    })
    proposals.append(proposal)
    save_proposals(PROPOSALS_PATH, proposals)
    return proposal, evaluation


def accept_proposal(proposal_id: str, basis: str, auto: bool = False) -> dict:
    catalog = load_validated_catalog()
    patterns = catalog["attack_patterns"]
    logs = read_csv(storage.RAW_LOGS_PATH)
    links = read_links(storage.LINKS_PATH)
    proposals = load_proposals(PROPOSALS_PATH)
    proposal = next((item for item in proposals if item.get("proposal_id") == proposal_id), None)
    if proposal is None:
        raise ValueError(f"unknown proposal_id {proposal_id}")
    if proposal.get("status") == "accepted":
        raise ValueError(f"{proposal_id} was already accepted")
    if proposal.get("status") == "rejected":
        raise ValueError(f"{proposal_id} was rejected; submit a new proposal instead")
    evaluation = evaluate_proposal(patterns, logs, links, proposal)
    if not evaluation["ok"]:
        raise ValueError("proposal no longer passes the gate: " + "; ".join(evaluation["problems"]))
    if auto and not evaluation["auto_eligible"]:
        raise ValueError("proposal is not eligible for --auto; accept it explicitly with a basis")
    case_id = proposal["case_id"]
    base = next(pattern for pattern in patterns if pattern["case_id"] == case_id)
    old_version = pattern_version(base)
    current_snapshot = write_version_snapshot(base)
    candidate = evaluation["candidate"]
    new_version = pattern_version(candidate)
    new_snapshot = write_version_snapshot(candidate)
    catalog["attack_patterns"] = evaluation["catalog"]
    atomic_write_json(storage.PATTERNS_PATH, catalog)
    proposal.update({
        "status": "accepted",
        "decided_at": now_iso(),
        "decision_basis": basis,
        "new_version": new_version,
        "auto": bool(auto),
        "metrics": evaluation["metrics"],
    })
    save_proposals(PROPOSALS_PATH, proposals)
    return {"case_id": case_id, "old_version": old_version, "new_version": new_version,
            "proposal": proposal, "snapshots": [str(current_snapshot), str(new_snapshot)]}


def reject_proposal(proposal_id: str, basis: str) -> dict:
    proposals = load_proposals(PROPOSALS_PATH)
    proposal = next((item for item in proposals if item.get("proposal_id") == proposal_id), None)
    if proposal is None:
        raise ValueError(f"unknown proposal_id {proposal_id}")
    if proposal.get("status") == "accepted":
        raise ValueError(f"{proposal_id} was already accepted; use rollback to revert the pattern")
    if proposal.get("status") == "rejected":
        raise ValueError(f"{proposal_id} was already rejected")
    proposal.update({"status": "rejected", "decided_at": now_iso(), "decision_basis": basis})
    save_proposals(PROPOSALS_PATH, proposals)
    return proposal


def rollback_pattern(case_id: str, to_version: int, basis: str) -> dict:
    catalog = load_validated_catalog()
    patterns = catalog["attack_patterns"]
    current = next((pattern for pattern in patterns if pattern["case_id"] == case_id), None)
    if current is None:
        raise ValueError(f"unknown case_id {case_id}")
    current_version = pattern_version(current)
    if current_version == to_version:
        raise ValueError(f"{case_id} is already at v{to_version}")
    path = version_path(case_id, to_version)
    if not path.exists():
        raise ValueError(f"no snapshot for {case_id} v{to_version} at {path}")
    restored = json.loads(path.read_text(encoding="utf-8-sig"))
    restored.setdefault("version", to_version)
    validate_pattern(restored)
    catalog["attack_patterns"] = [restored if pattern["case_id"] == case_id else pattern
                                  for pattern in patterns]
    build_action_index(catalog["attack_patterns"])
    write_version_snapshot(current)
    atomic_write_json(storage.PATTERNS_PATH, catalog)
    return {"case_id": case_id, "from_version": current_version, "to_version": to_version,
            "basis": basis, "pattern": restored}


def audit_proposals(proposals: list[dict]) -> list[str]:
    problems: list[str] = []
    for proposal in proposals:
        if proposal.get("status") != "accepted":
            continue
        version = proposal.get("new_version")
        if not isinstance(version, int):
            problems.append(f"{proposal.get('proposal_id')}: accepted proposal has no new_version")
            continue
        if not version_path(proposal["case_id"], version).exists():
            problems.append(f"{proposal.get('proposal_id')}: accepted version snapshot v{version:03d} is missing")
    return problems

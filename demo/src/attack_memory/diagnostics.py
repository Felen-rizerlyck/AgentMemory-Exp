"""Maturity, per-step diagnostics, and audit aggregation."""
from __future__ import annotations

import re
from collections import Counter, defaultdict

from . import evolution, storage
from .catalog import load_validated_catalog, maturity, pattern_version
from .evolution import audit_proposals
from .links import audit_links, confirmed_pairs, derived_observations, related_incidents
from .retrieval import build_action_index, extract_log_actions, match_pattern
from .storage import latest_link_by_event, read_csv, read_links


def step_statistics(patterns: list[dict], logs: list[dict[str, str]],
                    links: list[dict[str, str]]) -> list[dict]:
    """Per-step breadth vs reviewed use, used to spot ambiguous or over-broad regexes."""
    latest = latest_link_by_event(links)
    stats = []
    for pattern in patterns:
        case_id = pattern["case_id"]
        for step in pattern["steps"]:
            regex = re.compile(step["action_regex"])
            matched = [row for row in logs if regex.search(row.get("content") or "")]
            linked, foreign = [], []
            for row in matched:
                link = latest.get(row.get("event_id") or "") or {}
                if ((link.get("case_id") or "") == case_id
                        and (link.get("step_id") or "") == step["step_id"]
                        and (link.get("link_status") or "") != "rejected"):
                    linked.append(row["event_id"])
                if (row.get("case_id") or "").strip() not in ("", case_id):
                    foreign.append(row["event_id"])
            stats.append({
                "case_id": case_id, "step_id": step["step_id"],
                "required": bool(step.get("required", True)),
                "matched": len(matched), "linked": len(linked),
                "ambiguity": len(matched) - len(linked), "foreign": len(foreign),
                "precision": round(len(linked) / len(matched), 3) if matched else None,
            })
    return stats


def unexplained_events(patterns: list[dict], logs: list[dict[str, str]],
                       links: list[dict[str, str]]) -> dict[str, dict[str, list[str]]]:
    """Confirmed events of a case that none of its steps can explain: draft-step candidates."""
    incidents_by_case: dict[str, set[str]] = defaultdict(set)
    for incident, case_id in confirmed_pairs(links):
        incidents_by_case[case_id].add(incident)
    result: dict[str, dict[str, list[str]]] = {}
    for pattern in patterns:
        regexes = [re.compile(step["action_regex"]) for step in pattern["steps"]]
        found: dict[str, list[str]] = defaultdict(list)
        for row in logs:
            incident = (row.get("incident_id") or "").strip()
            if incident not in incidents_by_case[pattern["case_id"]]:
                continue
            content = row.get("content") or ""
            if any(regex.search(content) for regex in regexes):
                continue
            found[incident].append(row.get("event_id") or "")
        result[pattern["case_id"]] = dict(found)
    return result


def audit_problems(patterns: list[dict], logs: list[dict[str, str]], links: list[dict[str, str]],
                   proposals: list[dict]) -> list[str]:
    """Deprecated compatibility shim; the CLI now uses :func:`attack_memory.audit.run_audit`."""
    from .evolution import audit_proposals
    from .links import audit_links
    return audit_links(patterns, logs, links) + audit_proposals(proposals)


def diagnostic_lines(case_id: str | None = None) -> list[str]:
    patterns = load_validated_catalog()["attack_patterns"]
    logs = read_csv(storage.RAW_LOGS_PATH)
    links = read_links(storage.LINKS_PATH)
    stats = step_statistics(patterns, logs, links)
    unexplained = unexplained_events(patterns, logs, links)
    lines: list[str] = []
    for pattern in patterns:
        if case_id and pattern["case_id"] != case_id:
            continue
        confirmed, fixtures = derived_observations(links, pattern["case_id"])
        related = len(related_incidents(links, pattern["case_id"]))
        lines.append(f"{pattern['case_id']} v{pattern_version(pattern)} "
                     f"family={pattern.get('family_id', '-')}  maturity={maturity(confirmed)}  "
                     f"confirmed_incidents={confirmed}  related_incidents={related}  fixtures={fixtures}")
        for stat in stats:
            if stat["case_id"] != pattern["case_id"]:
                continue
            flag = "required" if stat["required"] else "optional"
            note = ""
            if stat["ambiguity"]:
                note += f"  <-- {stat['ambiguity']} extra match(es)"
            if stat["foreign"]:
                note += f"  <-- {stat['foreign']} other-case match(es)"
            lines.append(f"  {stat['step_id']:<3} {flag:<8} matched={stat['matched']:<3} "
                         f"linked={stat['linked']:<3} ambiguity={stat['ambiguity']}{note}")
        found = unexplained.get(pattern["case_id"]) or {}
        if found:
            for incident, events in sorted(found.items()):
                lines.append(f"  unexplained in {incident}: {', '.join(events)}")
        else:
            lines.append("  unexplained: none")
        lines.append("")
    return lines

"""Fetch stored observations together with their review status after a case candidate is selected."""
from __future__ import annotations

import argparse
import json

from attack_memory.catalog import maturity, pattern_version
from attack_memory.links import derived_observations
from attack_memory.storage import (LINK_STATUSES, RAW_LOGS_PATH, latest_link_by_event, load_patterns,
                                   read_csv, read_links, resolve_case)

SCHEMA_VERSION = 1


def _text(row: dict[str, str], field: str) -> str:
    return (row.get(field) or "").strip()


def select_observations(rows: list[dict[str, str]], latest: dict[str, dict[str, str]], *,
                        case_id: str | None = None, incident_id: str | None = None,
                        step_id: str | None = None, exclude_incident: str | None = None,
                        include_fixtures: bool = False, include_related: bool = False,
                        status: str | None = None,
                        alias_case_id: str | None = None) -> tuple[list[tuple[dict[str, str], str]], int]:
    """Return (selected (row, latest status) pairs, hidden fixture count).

    Step filtering reads the latest reviewed link, so a recalled example can be narrowed
    to the step that actually matched instead of dumping the whole case. Related rows are
    joined through the link table because they deliberately carry no case label.
    ``alias_case_id`` adds a merged-away label to the same lookup so its evidence is not
    orphaned by the alias merge.
    """
    case_labels = {label for label in (case_id, alias_case_id) if label}
    scoped: list[dict[str, str]] = []
    for row in rows:
        link = latest.get(_text(row, "event_id")) or {}
        if exclude_incident and _text(row, "incident_id") == exclude_incident:
            continue
        if incident_id and _text(row, "incident_id") != incident_id:
            continue
        if step_id and _text(link, "step_id") != step_id:
            continue
        if case_labels:
            label_match = _text(row, "case_id") in case_labels
            fixture_match = (include_fixtures and _text(link, "link_status") == "fixture"
                             and _text(link, "case_id") in case_labels)
            related_match = (include_related and _text(link, "link_status") == "related"
                             and _text(link, "case_id") in case_labels)
            if not label_match and not fixture_match and not related_match:
                continue
        scoped.append(row)

    hidden = 0
    selected: list[tuple[dict[str, str], str]] = []
    for row in scoped:
        link = latest.get(_text(row, "event_id")) or {}
        row_status = _text(link, "link_status")
        if row_status == "fixture" and not include_fixtures:
            hidden += 1
            continue
        if status and row_status != status:
            continue
        selected.append((row, row_status))
    return selected, hidden


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Look up stored observations by case/incident/step, with review status.")
    parser.add_argument("--case-id", help="Pattern ID, e.g. CASE-008")
    parser.add_argument("--incident-id", help="Optionally restrict to one concrete incident")
    parser.add_argument("--step-id", help="Only rows whose latest link is this pattern step, e.g. S4")
    parser.add_argument("--exclude-incident", help="Skip this incident, e.g. the one being judged")
    parser.add_argument("--status", choices=list(LINK_STATUSES),
                        help="Only show rows whose latest reviewed link has this status")
    parser.add_argument("--include-fixtures", action="store_true",
                        help="Include synthetic validation rows (hidden by default)")
    parser.add_argument("--include-related", action="store_true",
                        help="Include rows associated through a related link (no case label)")
    parser.add_argument("--json", action="store_true", help="Print matching rows as JSON")
    args = parser.parse_args()
    if not args.case_id and not args.incident_id:
        parser.error("pass --case-id, --incident-id, or both")

    rows = read_csv(RAW_LOGS_PATH)
    links = read_links()
    latest = latest_link_by_event(links)

    pattern = None
    display_pattern = None
    resolved_id = None
    alias_of = None
    if args.case_id:
        patterns = load_patterns()["attack_patterns"]
        pattern = next((item for item in patterns if item["case_id"] == args.case_id), None)
        if pattern is None:
            parser.error(f"unknown case_id {args.case_id}")
        # A merged case keeps its links and labels; follow the alias so its evidence is
        # recalled through the surviving case instead of being orphaned.
        resolved_id, _chain = resolve_case(args.case_id, patterns)
        alias_of = args.case_id if resolved_id != args.case_id else None
        display_pattern = next(item for item in patterns if item["case_id"] == resolved_id)
        known_steps = {step["step_id"] for item in (pattern, display_pattern)
                       for step in item["steps"]}
        if args.step_id and args.step_id not in known_steps:
            parser.error(f"{args.case_id} has no step {args.step_id}")

    selected, hidden = select_observations(
        rows, latest, case_id=resolved_id, incident_id=args.incident_id,
        step_id=args.step_id, exclude_incident=args.exclude_incident,
        include_fixtures=args.include_fixtures,
        include_related=args.include_related or args.status == "related",
        status=args.status, alias_case_id=alias_of)

    derived = fixtures = None
    if args.case_id:
        # Count the alias's confirmed links under the resolved case, without re-labelling
        # the append-only link history or double-counting the target's own links.
        union_links = links
        if alias_of:
            union_links = [{**link, "case_id": resolved_id}
                           if _text(link, "case_id") == alias_of else link for link in links]
        derived, fixtures = derived_observations(union_links, resolved_id)
    version = None
    maturity_name = None
    family = None
    review_status = None
    pattern_status = None
    if display_pattern is not None:
        version = pattern_version(display_pattern)
        maturity_name = maturity(derived or 0)
        family = display_pattern.get("family_id")
        review_status = display_pattern.get("review_status")
        pattern_status = display_pattern.get("status", "active")

    if args.json:
        print(json.dumps({
            "schema_version": SCHEMA_VERSION,
            "case_id": args.case_id, "incident_id": args.incident_id,
            "step_id": args.step_id, "excluded_incident": args.exclude_incident,
            "alias_of": alias_of, "resolved_case_id": resolved_id,
            "pattern_version": version, "maturity": maturity_name, "family_id": family,
            "review_status": review_status, "status": pattern_status,
            "count": len(selected), "fixture_rows_hidden": hidden,
            "derived_real_observations": derived,
            "observations": [{**row, "link_status": status} for row, status in selected],
        }, ensure_ascii=False, indent=2))
        return

    label = resolved_id or args.incident_id
    if resolved_id and version is not None:
        label = f"{resolved_id} v{version} ({maturity_name}"
        label += f", {family})" if family else ")"
        if review_status == "unreviewed":
            label += " [UNREVIEWED]"
        if pattern_status == "retired":
            label += " [RETIRED]"
        if alias_of:
            label += f" [alias of {alias_of}]"
    if args.step_id:
        label += f" step={args.step_id}"
    if args.exclude_incident:
        label += f" excluding={args.exclude_incident}"
    summary = f"{label}: {len(selected)} stored observation(s)"
    if hidden:
        summary += f"; {hidden} fixture row(s) hidden (use --include-fixtures)"
    print(summary)
    if alias_of:
        print(f"followed alias: {alias_of} -> {resolved_id} "
              "(observations from both case labels; links were not rewritten)")
    if resolved_id and derived is not None:
        alias_note = f", alias counted under {resolved_id}" if alias_of else ""
        print(f"derived real observations={derived} "
              f"(confirmed links{alias_note}, fixtures ignored)")
    for row, status in selected:
        print(f"{row.get('timestamp', '')} [{row.get('source', '')}] "
              f"{row.get('event_id', '')} status={status or 'unlinked'} "
              f"{row.get('incident_id', '')} {row.get('log_id', '')} | {row.get('content', '')}")


if __name__ == "__main__":
    main()

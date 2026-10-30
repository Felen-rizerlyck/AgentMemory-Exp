"""Command-line interface for the attack-memory demo.

The parser defines the command surface; one handler function per verb keeps the
behaviour readable and testable. Business rules live in the ``attack_memory``
modules, never in the CLI.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib
import json
import sys
from typing import Any, Callable

from . import (admissions as admission_store,
               audit as audit_report,
               candidates as candidate_store,
               chains as chain_store,
               families as family_store,
               lifecycle as lifecycle_store,
               migrations as migration_store,
               retention as retention_store,
               signatures as signature_store,
               state as state_store,
               storage)
from .catalog import (add_pattern, add_pattern_from_candidate,
                      load_validated_catalog, merge_case, reactivate_case,
                      retire_case, review_case, split_case)
from .diagnostics import diagnostic_lines
from .evolution import (PROPOSALS_PATH, accept_proposal, create_proposal,
                        load_proposals, reject_proposal, rollback_pattern)
from .links import append_links
from .storage import (LINK_STATUSES, LINKS_PATH, RAW_LOGS_PATH, read_csv, read_links,
                      resolve_demo_path)

Handler = Callable[[argparse.Namespace, argparse.ArgumentParser], None]


# ---------------------------------------------------------------------------
# Module loading for commands whose module may not be in every build
# ---------------------------------------------------------------------------

def _load_module(name: str, purpose: str = "") -> Any:
    try:
        return importlib.import_module(f".{name}", __package__)
    except ImportError as error:
        detail = f" ({purpose})" if purpose else ""
        raise SystemExit(f"ERROR: module '{name}' is not available{detail}: {error}") from error


def _print_lines(lines: list[str]) -> None:
    for line in lines:
        print(line)


# ---------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------

def _cmd_catalog_validate(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    report = audit_report.run_validation()
    _print_lines(audit_report.format_validation_lines(report))
    if not report["ok"]:
        raise SystemExit(1)


def _cmd_catalog_candidates(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    items = candidate_store.list_candidates(args.status)
    if args.family:
        items = [item for item in items if (item.get("family_id") or "") == args.family]
    totals = candidate_store.counts()
    print(f"{len(items)} candidate(s): " + ", ".join(
        f"{status}={totals[status]}" for status in candidate_store.CANDIDATE_STATUSES))
    if args.by_group:
        _print_candidate_groups(signature_store.group_candidates(items))
        return
    for item in items:
        extra = ""
        if item.get("aliases"):
            extra += f" aliases={','.join(item['aliases'])}"
        if item.get("pending_case_links"):
            extra += f" pending_case_links={len(item['pending_case_links'])}"
        print(f"  {item['candidate_id']}  {item['status']:<11}  "
              f"family={item.get('family_id') or '-':<16}  "
              f"incidents={len(item['incidents'])}  {item['label']}{extra}")


def _print_candidate_groups(groups: list[dict[str, Any]]) -> None:
    ungrouped = [group for group in groups if (group.get("signature_key") or "ungrouped") == "ungrouped"]
    keyed = [group for group in groups if group not in ungrouped]
    duplicates = [group for group in keyed if len(group["candidates"]) > 1]
    print(f"  {len(keyed)} signature group(s), "
          f"{len(duplicates)} duplicate group(s), "
          f"{sum(len(group['candidates']) for group in duplicates)} grouped member(s)"
          + (f"; ungrouped={sum(len(group['candidates']) for group in ungrouped)}"
             if ungrouped else ""))
    for group in groups:
        key = group.get("signature_key") or "ungrouped"
        source = group.get("signature_source") or ("terms" if key != "ungrouped" else "fallback")
        terms = [str(term) for term in group.get("terms") or []]
        print(f"  [{key}] source={source} terms={','.join(terms[:8]) or '-'}")
        for item in group["candidates"]:
            extra = f" aliases={','.join(item['aliases'])}" if item.get("aliases") else ""
            print(f"      {item['candidate_id']}  {item['status']:<11}  "
                  f"{item['label']}{extra}")


def _cmd_catalog_merge(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if getattr(args, "allow_ungrouped", False):
        candidate = candidate_store.merge_candidates(
            args.primary, args.alias, args.basis, allow_ungrouped=True)
    else:
        candidate = candidate_store.merge_candidates(args.primary, args.alias, args.basis)
    print(f"Merged {args.alias} into {candidate['candidate_id']}: "
          f"status={candidate['status']}, incidents={len(candidate['incidents'])}.")


def _cmd_catalog_split(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    candidate = candidate_store.split_candidate(args.primary, args.alias, args.basis)
    print(f"Split {args.alias} out of {candidate['candidate_id']}: "
          f"primary_status={candidate['status']}, incidents={len(candidate['incidents'])}.")


def _cmd_catalog_lifecycle(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    events = lifecycle_store.load_lifecycle()["events"]
    if args.case_id:
        events = [event for event in events if event.get("case_id") == args.case_id]
    print(f"{len(events)} lifecycle event(s)")
    for event in events:
        print(f"  {event.get('event_id')}  {event.get('action'):<11}  "
              f"{event.get('case_id')} -> {event.get('target') or '-'}")


def _cmd_catalog_retention(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    as_of = dt.date.fromisoformat(args.as_of) if args.as_of else dt.date.today()
    report = retention_store.build_report(
        load_validated_catalog()["attack_patterns"],
        read_csv(RAW_LOGS_PATH), read_links(LINKS_PATH),
        candidate_store.list_candidates(include_merged=True),
        load_proposals(PROPOSALS_PATH),
        chain_store.load_chains()["chains"],
        as_of=as_of,
        variant_days=args.variant_days,
        candidate_days=args.candidate_days,
        unclassified_days=args.unclassified_days,
        data_dir=storage.DATA_DIR,
    )
    if args.json:
        payload: dict[str, Any] = {"report": report}
        if args.apply:
            payload["apply"] = retention_store.apply_report(
                report, data_dir=storage.DATA_DIR,
                max_active_bytes=args.max_active_bytes,
                archive_max_days=args.archive_max_days)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return
    _print_lines(retention_store.format_lines(report))
    if args.apply:
        result = retention_store.apply_report(
            report, data_dir=storage.DATA_DIR,
            max_active_bytes=args.max_active_bytes,
            archive_max_days=args.archive_max_days)
        print(f"APPLY archived {result['archived_incidents']} incident(s), "
              f"{result['archived_events']} event(s), {result['archived_links']} link(s), "
              f"{result['removed_candidates']} candidate(s) -> {result['archive_dir']}")
        print(f"  tombstone summaries={result['incident_summaries']} "
              f"referenced={result['tombstones']} active_bytes={result['active_bytes']}")
        if result.get("cap_selected"):
            print(f"  cap-selected: {', '.join(result['cap_selected'])}")
        if result.get("pruned"):
            print(f"  pruned: {result['pruned']}")


def _cmd_catalog_retire(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    result = retire_case(args.case_id, args.basis, reviewer=args.reviewer)
    print(f"Retired {result['case_id']} ({result['event']['event_id']}).")


def _cmd_catalog_reactivate(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    result = reactivate_case(args.case_id, args.basis, reviewer=args.reviewer)
    print(f"Reactivated {result['case_id']} ({result['event']['event_id']}).")


def _cmd_catalog_merge_case(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    result = merge_case(args.source, args.target, args.basis, reviewer=args.reviewer)
    print(f"Merged {result['case_id']} into {result['target']}; "
          f"source retired ({result['event']['event_id']}).")


def _cmd_catalog_split_case(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    result = split_case(args.case_id, args.basis, reviewer=args.reviewer)
    print(f"Split {result['case_id']} from {result['target']}; source active again.")


def _cmd_catalog_chains(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    data = load_validated_catalog()
    logs = read_csv(RAW_LOGS_PATH)
    links = read_links(LINKS_PATH)
    if args.rebuild:
        chain_store.build_chains(data["attack_patterns"], logs, links)
    chains = chain_store.load_chains()["chains"]
    unexplained = sum(1 for chain in chains for event in chain["events"]
                      if event.get("stage_kind") == "unclassified")
    print(f"{len(chains)} chain(s), {unexplained} unclassified event(s)")
    for chain in chains:
        missing = sum(1 for event in chain["events"]
                      if event.get("stage_kind") == "unclassified")
        print(f"  {chain['incident_id']}  case={chain.get('case_id') or '-':<16} "
              f"events={len(chain['events']):<2} unclassified={missing}")


def _cmd_catalog_chain(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    chain = next((item for item in chain_store.load_chains()["chains"]
                  if item["incident_id"] == args.incident_id), None)
    if chain is None:
        parser.error(f"unknown incident chain: {args.incident_id}")
    print(f"{chain['incident_id']}  case={chain.get('case_id') or '-'}  "
          f"events={len(chain['events'])}")
    for event in chain["events"]:
        print(f"  {event.get('timestamp', '')} [{event.get('source', '')}] "
              f"{event.get('event_id', '')} stage={event.get('stage')} "
              f"kind={event.get('stage_kind')} label={event.get('label')}")
    if args.summarize:
        summary = chain_store.summarize_chain(chain, read_csv(RAW_LOGS_PATH))
        print("  stage sequence: " + " -> ".join(summary["sequence"]))
        print(f"  unexplained segments: {summary['unexplained_segments']}")
        for suggestion in summary["suggestions"]:
            print(f"    segment {suggestion['segment']}: "
                  f"events={','.join(suggestion['event_ids'])} "
                  f"suggested={suggestion['suggested_label']}")


def _cmd_catalog_families(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    data = load_validated_catalog()
    family_data = family_store.load_families()
    counts = family_store.counts(family_data, data["attack_patterns"],
                                 candidate_store.list_candidates())
    print(f"{len(family_data['families'])} family(ies), "
          f"{len(data['attack_patterns'])} case(s), "
          f"{len(candidate_store.list_candidates())} candidate(s)")
    for family_id, row in counts.items():
        print(f"  {family_id:<18} cases={row['cases']:<2} retired={row.get('retired', 0):<2} "
              f"candidates={row['candidates']:<3} steps={row.get('steps', 0):<2} {row['name']}")


def _cmd_catalog_migrations(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    data = load_validated_catalog()
    records = migration_store.load_migrations()["migrations"]
    problems = migration_store.audit_migrations(data["attack_patterns"])
    print(f"{len(records)} migration(s)")
    for record in records:
        print(f"  {record.get('migration_id')}  {record.get('case_id')}  "
              f"v{record.get('from_version')}->{record.get('to_version')}  "
              f"{record.get('kind')}  {record.get('step_id')} -> {record.get('family_id')}")
    for problem in problems:
        print(f"  PROBLEM: {problem}")
    if problems:
        raise SystemExit(1)


def _cmd_catalog_admissions(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    data = load_validated_catalog()
    records = admission_store.load_admissions()["admissions"]
    problems = admission_store.audit_admissions(data["attack_patterns"])
    print(f"{len(records)} admission(s)")
    for record in records:
        print(f"  {record.get('admission_id')}  {record.get('case_id')}  "
              f"{record.get('status'):<11}  {record.get('source')}")
    for problem in problems:
        print(f"  PROBLEM: {problem}")
    if problems:
        raise SystemExit(1)


def _cmd_catalog_review_case(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    record = review_case(args.case_id, args.basis, reviewer=args.reviewer)
    print(f"Reviewed {args.case_id}; marker removed, admission {record['admission_id']} is reviewed.")


def _cmd_catalog_stage(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    event_ids = [item.strip() for item in args.event_ids.split(",") if item.strip()]
    candidate = candidate_store.upsert_candidate(
        args.signature, args.label, args.incident_id, event_ids, args.source_batch,
        args.family_id)
    print(f"{candidate['candidate_id']} is {candidate['status']} "
          f"({len(candidate['incidents'])} incident(s)).")


def _cmd_catalog_add(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.from_candidate and args.supporting_incident_ids:
        parser.error("use --from-candidate or --supporting-incident-ids, not both")
    if args.from_candidate:
        case_id, candidate = add_pattern_from_candidate(
            args.from_candidate, resolve_demo_path(args.input), force=args.force)
        print(f"Promoted {candidate['candidate_id']} to {case_id} "
              f"({len(candidate['incidents'])} incident(s), unreviewed).")
        return
    supporting = [item.strip() for item in (args.supporting_incident_ids or "").split(",")
                  if item.strip()]
    case_id = add_pattern(resolve_demo_path(args.input), supporting, force=args.force)
    print(f"Added {case_id} to data/attack_patterns.json (unreviewed).")


def _cmd_catalog_state(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    state = state_store.memory_state()
    if args.check:
        target = resolve_demo_path(args.check)
        problems = state_store.check_state_block(target)
        for problem in problems:
            print(f"  PROBLEM: {problem}")
        if problems:
            raise SystemExit(1)
        print(f"State block is in sync: {args.check}")
        return
    if args.json:
        print(json.dumps(state, ensure_ascii=False, indent=2))
        return
    print(state_store.render_state_block(state))


def _cmd_catalog_repair(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    repair = _load_module("repair", "safe self-healing")
    result = repair.repair(dry_run=not args.apply)
    lines = result.get("lines") or []
    _print_lines(lines)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif not lines:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    if not result.get("ok", True):
        raise SystemExit(1)


def _cmd_catalog_snapshot(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    catalog = _load_module("catalog", "version snapshots")
    backfill = getattr(catalog, "backfill_snapshots", None) or getattr(catalog, "snapshot_backfill", None)
    if backfill is None:
        raise SystemExit("ERROR: catalog.backfill_snapshots is not available")
    case_ids = None if args.all else [args.case_id]
    written = backfill(case_ids)
    print(f"Snapshots written: {len(written)}")
    for path in written:
        print(f"  {path}")


def _cmd_catalog_corrections(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    corrections = _load_module("corrections", "negative memory")
    rows = corrections.list_corrections(case_id=args.case_id, incident_id=args.incident_id)
    print(f"{len(rows)} correction(s)")
    for row in rows:
        print(f"  {corrections.summary_line(row)}")


def _cmd_catalog_correction(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if args.correction_action != "add":
        parser.error(f"unsupported correction action: {args.correction_action}")
    corrections = _load_module("corrections", "negative memory")
    event_ids = [item.strip() for item in (args.event_ids or "").split(",") if item.strip()]
    record = corrections.add_correction(
        args.incident_id, args.case_id, args.reason_code,
        event_ids=event_ids or None, decision=args.decision,
        basis=args.basis, reviewer=args.reviewer)
    print(f"Recorded {record['correction_id']} ({record['decision']}) for {record['case_id']} "
          f"reason={record['reason_code']}.")


# ---------------------------------------------------------------------------
# review
# ---------------------------------------------------------------------------

def _cmd_review_stage(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    chain = chain_store.review_stage(
        args.incident_id, args.event_id, args.stage, args.label, args.basis,
        order=args.order)
    print(f"Annotated {args.event_id} in {chain['incident_id']} as {args.stage}.")


def _cmd_review_link(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    ids = [item.strip() for item in args.event_ids.split(",") if item.strip()]
    if not ids:
        parser.error("--event-ids must contain at least one event ID")
    count = append_links(ids, args.incident_id, args.case_id, args.step_id,
                         args.status, args.basis, force=args.force)
    print(f"Appended {count} {args.status} link(s).")


def _cmd_review_associate(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    ids = [item.strip() for item in args.event_ids.split(",") if item.strip()]
    if not ids:
        parser.error("--event-ids must contain at least one event ID")
    count = append_links(ids, args.incident_id, args.case_id, args.step_id or "",
                         "related", args.basis)
    print(f"Associated {count} event(s) with {args.case_id} as related (no labels changed).")


# ---------------------------------------------------------------------------
# evolve
# ---------------------------------------------------------------------------

def _cmd_evolve_propose(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    payload = json.loads(resolve_demo_path(args.input).read_text(encoding="utf-8-sig"))
    proposal, evaluation = create_proposal(payload)
    print(f"Recorded {proposal['proposal_id']} as {proposal['status']} "
          f"(auto_eligible={evaluation['auto_eligible']}).")
    for key in ("support_incidents", "support_events", "coverage_before", "coverage_after",
                "strong_before", "strong_after", "heldout_incidents",
                "heldout_strong_after", "foreign_matches", "narrowing"):
        if key in evaluation["metrics"]:
            print(f"  {key}={evaluation['metrics'][key]}")
    for problem in evaluation["problems"]:
        print(f"  BLOCKED: {problem}")


def _cmd_evolve_list(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    items = load_proposals(PROPOSALS_PATH)
    if args.case_id:
        items = [item for item in items if item.get("case_id") == args.case_id]
    if args.status:
        items = [item for item in items if item.get("status") == args.status]
    if not items:
        print("No proposal matched the filter.")
    for item in items:
        print(f"{item.get('proposal_id')}  {item.get('case_id')}  {item.get('operation')}  "
              f"v{item.get('base_version')}->{item.get('new_version', '?')}  "
              f"{item.get('status')}  auto={item.get('auto_eligible', False)}")


def _cmd_evolve_accept(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    result = accept_proposal(args.proposal_id, args.basis, auto=args.auto)
    print(f"Accepted {args.proposal_id}: {result['case_id']} "
          f"v{result['old_version']} -> v{result['new_version']}")
    for snapshot in result["snapshots"]:
        print(f"  snapshot: {snapshot}")
    proposal = result["proposal"]
    if proposal["operation"] == "reorder_steps":
        print("Next: re-run retrieval; the step order changed, no new links are needed.")
    else:
        step_id = (proposal["step"]["step_id"] if proposal["operation"] == "add_step"
                   else proposal["step_id"])
        print(f"Next: link the supporting events to {step_id} with `review link`, then audit.")


def _cmd_evolve_reject(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    proposal = reject_proposal(args.proposal_id, args.basis)
    print(f"Rejected {proposal['proposal_id']} ({proposal['case_id']}).")


def _cmd_evolve_rollback(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    result = rollback_pattern(args.case_id, args.to, args.basis)
    print(f"Rolled back {result['case_id']}: v{result['from_version']} -> v{result['to_version']}")
    print("Re-run audit: links reviewed against the newer version may need review.")


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------

def _cmd_audit(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    report = audit_report.run_audit()
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _print_lines(audit_report.format_audit_lines(report))
        if args.verbose:
            print("\n".join(diagnostic_lines(args.case_id)))
    if not report["ok"]:
        raise SystemExit(1)


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Attack-memory catalog, review, evolution and audit CLI.")
    groups = parser.add_subparsers(dest="group", required=True)

    catalog = groups.add_parser("catalog", help="Validate, stage, add or promote a pattern")
    catalog_sub = catalog.add_subparsers(dest="action", required=True)
    catalog_sub.add_parser("validate", help="Validate the catalog and the shared action library")
    candidate_list = catalog_sub.add_parser("candidates", help="List staged technique candidates")
    candidate_list.add_argument("--status", choices=list(candidate_store.CANDIDATE_STATUSES))
    candidate_list.add_argument("--family")
    candidate_list.add_argument("--by-group", action="store_true", dest="by_group",
                                help="Group by deterministic signature_key (no merge)")
    merge_cmd = catalog_sub.add_parser("merge", help="Merge a duplicate candidate into a primary")
    merge_cmd.add_argument("--primary", required=True)
    merge_cmd.add_argument("--alias", required=True)
    merge_cmd.add_argument("--basis", required=True)
    merge_cmd.add_argument("--allow-ungrouped", action="store_true", dest="allow_ungrouped",
                           help="Allow merging candidates without a deterministic signature_key")
    split_cmd = catalog_sub.add_parser("split", help="Undo a candidate merge")
    split_cmd.add_argument("--primary", required=True)
    split_cmd.add_argument("--alias", required=True)
    split_cmd.add_argument("--basis", required=True)
    lifecycle_cmd = catalog_sub.add_parser("lifecycle", help="List case lifecycle events")
    lifecycle_cmd.add_argument("--case-id")
    retention_cmd = catalog_sub.add_parser("retention", help="Incident retention report or apply")
    retention_cmd.add_argument("--variant-days", type=int, default=180)
    retention_cmd.add_argument("--candidate-days", type=int, default=150)
    retention_cmd.add_argument("--unclassified-days", type=int, default=90)
    retention_cmd.add_argument("--as-of", help="YYYY-MM-DD; default today")
    retention_cmd.add_argument("--apply", action="store_true", help="Archive expired incidents")
    retention_cmd.add_argument("--max-active-bytes", type=int, default=0,
                               help="0 disables; archive oldest eligible incidents until under cap")
    retention_cmd.add_argument("--archive-max-days", type=int, default=365,
                               help="0 disables; delete whole archive groups older than this")
    retention_cmd.add_argument("--json", action="store_true")
    retire_cmd = catalog_sub.add_parser("retire", help="Retire a case (keeps its history)")
    retire_cmd.add_argument("--case-id", required=True)
    retire_cmd.add_argument("--basis", required=True)
    retire_cmd.add_argument("--reviewer", default="agent")
    reactivate_cmd = catalog_sub.add_parser("reactivate", help="Reactivate a retired case")
    reactivate_cmd.add_argument("--case-id", required=True)
    reactivate_cmd.add_argument("--basis", required=True)
    reactivate_cmd.add_argument("--reviewer", default="agent")
    merge_case_cmd = catalog_sub.add_parser("merge-case", help="Merge a case into an alias")
    merge_case_cmd.add_argument("--source", required=True)
    merge_case_cmd.add_argument("--target", required=True)
    merge_case_cmd.add_argument("--basis", required=True)
    merge_case_cmd.add_argument("--reviewer", default="agent")
    split_case_cmd = catalog_sub.add_parser("split-case", help="Undo a case alias merge")
    split_case_cmd.add_argument("--case-id", required=True)
    split_case_cmd.add_argument("--basis", required=True)
    split_case_cmd.add_argument("--reviewer", default="agent")
    stage = catalog_sub.add_parser("stage", help="Stage one incident under a candidate signature")
    stage.add_argument("--signature", required=True, help="Behavioural signature, e.g. F1::Spring4Shell")
    stage.add_argument("--label", default="", help="Human-readable technique name")
    stage.add_argument("--family-id", default="", help="Optional family, e.g. web-exploit")
    stage.add_argument("--incident-id", required=True)
    stage.add_argument("--event-ids", required=True, help="Comma-separated event IDs")
    stage.add_argument("--source-batch", default="")
    catalog_sub.add_parser("families", help="List the family taxonomy")
    catalog_sub.add_parser("migrations", help="List reviewed schema migrations")
    chains_cmd = catalog_sub.add_parser("chains", help="List incident chains (or rebuild with --rebuild)")
    chains_cmd.add_argument("--rebuild", action="store_true")
    chain_cmd = catalog_sub.add_parser("chain", help="Show one incident chain")
    chain_cmd.add_argument("--incident-id", required=True)
    chain_cmd.add_argument("--summarize", action="store_true")
    catalog_sub.add_parser("admissions", help="List new-case admissions and review status")
    review_case_cmd = catalog_sub.add_parser("review-case", help="Clear an unreviewed marker after review")
    review_case_cmd.add_argument("--case-id", required=True)
    review_case_cmd.add_argument("--basis", required=True)
    review_case_cmd.add_argument("--reviewer", default="human")
    add = catalog_sub.add_parser("add", help="Add one JSON pattern after review")
    add.add_argument("--input", required=True, help="Pattern JSON relative to demo/")
    add.add_argument("--supporting-incident-ids",
                     help="Comma-separated incidents that support the new case")
    add.add_argument("--from-candidate",
                     help="Promote this candidate; its incidents become the support set")
    add.add_argument("--force", action="store_true", help="Add a reviewed singleton")
    state_cmd = catalog_sub.add_parser("state", help="Print memory state or check the README state block")
    state_cmd.add_argument("--json", action="store_true")
    state_cmd.add_argument("--check", metavar="PATH", help="Verify a markdown file's generated block")
    repair_cmd = catalog_sub.add_parser("repair", help="Re-derive safe state after a partial write")
    repair_cmd.add_argument("--apply", action="store_true", help="Apply repairs (default: dry run)")
    repair_cmd.add_argument("--json", action="store_true")
    snapshot_cmd = catalog_sub.add_parser("snapshot", help="Write missing version snapshots")
    snapshot_cmd.add_argument("--case-id")
    snapshot_cmd.add_argument("--all", action="store_true")
    corrections_cmd = catalog_sub.add_parser("corrections", help="List the negative-memory ledger")
    corrections_cmd.add_argument("--case-id")
    corrections_cmd.add_argument("--incident-id")
    correction_cmd = catalog_sub.add_parser("correction", help="Manage the negative-memory ledger")
    correction_sub = correction_cmd.add_subparsers(dest="correction_action", required=True)
    correction_add = correction_sub.add_parser("add", help="Record a reviewed rejection")
    correction_add.add_argument("--incident-id", required=True)
    correction_add.add_argument("--case-id", required=True)
    correction_add.add_argument("--reason-code", required=True,
                                choices=["generic_only", "source_mismatch", "incomplete_chain",
                                         "wrong_family", "insufficient_evidence", "other"])
    correction_add.add_argument("--event-ids", help="Comma-separated evidence event IDs")
    correction_add.add_argument("--decision", default="reject_match",
                                choices=["reject_match", "reject_case"])
    correction_add.add_argument("--basis", required=True)
    correction_add.add_argument("--reviewer", default="agent")

    review = groups.add_parser("review", help="Record reviewed links")
    review_sub = review.add_subparsers(dest="action", required=True)
    link = review_sub.add_parser("link", help="Append event-to-case-step links")
    link.add_argument("--event-ids", required=True, help="Comma-separated event IDs")
    link.add_argument("--incident-id", required=True)
    link.add_argument("--case-id", required=True)
    link.add_argument("--step-id", required=True)
    link.add_argument("--status", default="confirmed", choices=list(LINK_STATUSES))
    link.add_argument("--basis", required=True)
    link.add_argument("--force", action="store_true",
                      help="Record a link even when the event does not match the step regex")
    associate = review_sub.add_parser("associate",
                                      help="Associate a variant without confirming its chain")
    associate.add_argument("--event-ids", required=True, help="Comma-separated event IDs")
    associate.add_argument("--incident-id", required=True)
    associate.add_argument("--case-id", required=True)
    associate.add_argument("--step-id", help="Optional shared step, e.g. S3")
    associate.add_argument("--basis", required=True)
    stage = review_sub.add_parser("stage", help="Annotate a chain event independently of a case")
    stage.add_argument("--incident-id", required=True)
    stage.add_argument("--event-id", required=True)
    stage.add_argument("--stage", required=True)
    stage.add_argument("--label", default="")
    stage.add_argument("--order", type=int)
    stage.add_argument("--basis", required=True)

    evolve = groups.add_parser("evolve", help="Propose, accept, reject or roll back a pattern")
    evolve_sub = evolve.add_subparsers(dest="action", required=True)
    propose = evolve_sub.add_parser("propose", help="Evaluate and record a proposal")
    propose.add_argument("--input", required=True)
    listing = evolve_sub.add_parser("list", help="List proposals")
    listing.add_argument("--case-id")
    listing.add_argument("--status", choices=["candidate", "ready", "accepted", "rejected"])
    accept = evolve_sub.add_parser("accept", help="Accept a ready proposal")
    accept.add_argument("proposal_id")
    accept.add_argument("--basis", required=True)
    accept.add_argument("--auto", action="store_true",
                        help="Allow a completion-class proposal to be accepted without manual review")
    reject = evolve_sub.add_parser("reject", help="Reject a proposal")
    reject.add_argument("proposal_id")
    reject.add_argument("--basis", required=True)
    rollback = evolve_sub.add_parser("rollback", help="Restore a previous pattern version")
    rollback.add_argument("--case-id", required=True)
    rollback.add_argument("--to", type=int, required=True)
    rollback.add_argument("--basis", required=True)

    audit = groups.add_parser("audit", help="Cross-check links, labels and proposals")
    audit.add_argument("--verbose", action="store_true", help="Print per-step diagnostics")
    audit.add_argument("--case-id", help="Restrict --verbose to one case")
    audit.add_argument("--json", action="store_true", help="Machine-readable report")
    return parser


_HANDLERS: dict[tuple[str, str], Handler] = {
    ("catalog", "validate"): _cmd_catalog_validate,
    ("catalog", "candidates"): _cmd_catalog_candidates,
    ("catalog", "merge"): _cmd_catalog_merge,
    ("catalog", "split"): _cmd_catalog_split,
    ("catalog", "lifecycle"): _cmd_catalog_lifecycle,
    ("catalog", "retention"): _cmd_catalog_retention,
    ("catalog", "retire"): _cmd_catalog_retire,
    ("catalog", "reactivate"): _cmd_catalog_reactivate,
    ("catalog", "merge-case"): _cmd_catalog_merge_case,
    ("catalog", "split-case"): _cmd_catalog_split_case,
    ("catalog", "chains"): _cmd_catalog_chains,
    ("catalog", "chain"): _cmd_catalog_chain,
    ("catalog", "families"): _cmd_catalog_families,
    ("catalog", "migrations"): _cmd_catalog_migrations,
    ("catalog", "admissions"): _cmd_catalog_admissions,
    ("catalog", "review-case"): _cmd_catalog_review_case,
    ("catalog", "stage"): _cmd_catalog_stage,
    ("catalog", "add"): _cmd_catalog_add,
    ("catalog", "state"): _cmd_catalog_state,
    ("catalog", "repair"): _cmd_catalog_repair,
    ("catalog", "snapshot"): _cmd_catalog_snapshot,
    ("catalog", "corrections"): _cmd_catalog_corrections,
    ("catalog", "correction"): _cmd_catalog_correction,
    ("review", "link"): _cmd_review_link,
    ("review", "associate"): _cmd_review_associate,
    ("review", "stage"): _cmd_review_stage,
    ("evolve", "propose"): _cmd_evolve_propose,
    ("evolve", "list"): _cmd_evolve_list,
    ("evolve", "accept"): _cmd_evolve_accept,
    ("evolve", "reject"): _cmd_evolve_reject,
    ("evolve", "rollback"): _cmd_evolve_rollback,
    ("audit", "__audit__"): _cmd_audit,
}


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    key = (args.group, getattr(args, "action", None) or "__audit__")
    handler = _HANDLERS.get(key)
    if handler is None:
        parser.error(f"unsupported command: {' '.join(filter(None, [args.group, getattr(args, 'action', '') or '']))}")
    try:
        handler(args, parser)
    except (ValueError, RuntimeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(2) from error


if __name__ == "__main__":
    main()

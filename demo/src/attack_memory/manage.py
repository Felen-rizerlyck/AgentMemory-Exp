"""CLI for catalog, review, evolution and audit."""
from __future__ import annotations

import argparse
import datetime as dt
import json

from . import admissions as admission_store
from . import candidates as candidate_store
from . import chains as chain_store
from . import families as family_store
from . import lifecycle as lifecycle_store
from . import migrations as migration_store
from . import retention as retention_store
from . import signatures as signature_store
from . import storage
from .catalog import (VERSIONS_DIR, add_pattern, add_pattern_from_candidate,
                      load_validated_catalog, merge_case, pattern_version,
                      reactivate_case, require_pattern_support, retire_case, review_case,
                      split_case)
from .diagnostics import audit_problems, diagnostic_lines
from .evolution import (PROPOSALS_PATH, accept_proposal, create_proposal, evaluate_proposal,
                        load_proposals, reject_proposal, rollback_pattern)
from .links import append_links, audit_links, derived_observations, related_incidents, support_pairs
from .storage import (LINK_STATUSES, LINKS_PATH, PATTERNS_PATH, RAW_LOGS_PATH, read_csv, read_links,
                      resolve_demo_path)


def main() -> None:
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
    args = parser.parse_args()

    if args.group == "catalog":
        if args.action == "stage":
            event_ids = [item.strip() for item in args.event_ids.split(",") if item.strip()]
            candidate = candidate_store.upsert_candidate(
                args.signature, args.label, args.incident_id, event_ids, args.source_batch,
                args.family_id)
            print(f"{candidate['candidate_id']} is {candidate['status']} "
                  f"({len(candidate['incidents'])} incident(s)).")
        elif args.action == "candidates":
            items = candidate_store.list_candidates(args.status)
            if args.family:
                items = [item for item in items
                         if (item.get("family_id") or "") == args.family]
            totals = candidate_store.counts()
            print(f"{len(items)} candidate(s): " + ", ".join(
                f"{status}={totals[status]}" for status in candidate_store.CANDIDATE_STATUSES))
            if args.by_group:
                groups = signature_store.group_candidates(items)
                duplicates = [group for group in groups if len(group["candidates"]) > 1]
                print(f"  {len(groups)} signature group(s), "
                      f"{len(duplicates)} duplicate group(s), "
                      f"{sum(len(group['candidates']) for group in duplicates)} grouped member(s)")
                for group in groups:
                    print(f"  [{group['signature_key']}] terms={','.join(group['terms'][:8])}")
                    for item in group["candidates"]:
                        extra = f" aliases={','.join(item['aliases'])}" if item.get("aliases") else ""
                        print(f"      {item['candidate_id']}  {item['status']:<11}  "
                              f"{item['label']}{extra}")
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
        elif args.action == "merge":
            candidate = candidate_store.merge_candidates(args.primary, args.alias, args.basis)
            print(f"Merged {args.alias} into {candidate['candidate_id']}: "
                  f"status={candidate['status']}, incidents={len(candidate['incidents'])}.")
        elif args.action == "split":
            candidate = candidate_store.split_candidate(args.primary, args.alias, args.basis)
            print(f"Split {args.alias} out of {candidate['candidate_id']}: "
                  f"primary_status={candidate['status']}, "
                  f"incidents={len(candidate['incidents'])}.")
        elif args.action == "lifecycle":
            events = lifecycle_store.load_lifecycle()["events"]
            if args.case_id:
                events = [event for event in events if event.get("case_id") == args.case_id]
            print(f"{len(events)} lifecycle event(s)")
            for event in events:
                print(f"  {event.get('event_id')}  {event.get('action'):<11}  "
                      f"{event.get('case_id')} -> {event.get('target') or '-'}")
        elif args.action == "retention":
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
                if args.apply:
                    print(json.dumps({"report": report,
                                      "apply": retention_store.apply_report(
                                          report, data_dir=storage.DATA_DIR,
                                          max_active_bytes=args.max_active_bytes,
                                          archive_max_days=args.archive_max_days)},
                                     ensure_ascii=False, indent=2))
                else:
                    print(json.dumps(report, ensure_ascii=False, indent=2))
            else:
                print("\n".join(retention_store.format_lines(report)))
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
        elif args.action == "retire":
            result = retire_case(args.case_id, args.basis, reviewer=args.reviewer)
            print(f"Retired {result['case_id']} ({result['event']['event_id']}).")
        elif args.action == "reactivate":
            result = reactivate_case(args.case_id, args.basis, reviewer=args.reviewer)
            print(f"Reactivated {result['case_id']} ({result['event']['event_id']}).")
        elif args.action == "merge-case":
            result = merge_case(args.source, args.target, args.basis, reviewer=args.reviewer)
            print(f"Merged {result['case_id']} into {result['target']}; "
                  f"source retired ({result['event']['event_id']}).")
        elif args.action == "split-case":
            result = split_case(args.case_id, args.basis, reviewer=args.reviewer)
            print(f"Split {result['case_id']} from {result['target']}; source active again.")
        elif args.action == "chains":
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
        elif args.action == "chain":
            data = load_validated_catalog()
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
        elif args.action == "families":
            data = load_validated_catalog()
            family_data = family_store.load_families()
            counts = family_store.counts(family_data, data["attack_patterns"],
                                         candidate_store.list_candidates())
            print(f"{len(family_data['families'])} family(ies), "
                  f"{len(data['attack_patterns'])} case(s), "
                  f"{len(candidate_store.list_candidates())} candidate(s)")
            for fid, row in counts.items():
                print(f"  {fid:<18} cases={row['cases']:<2} retired={row.get('retired', 0):<2} "
                      f"candidates={row['candidates']:<3} steps={row.get('steps', 0):<2} {row['name']}")
        elif args.action == "migrations":
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
        elif args.action == "admissions":
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
        elif args.action == "review-case":
            record = review_case(args.case_id, args.basis, reviewer=args.reviewer)
            print(f"Reviewed {args.case_id}; marker removed, admission {record['admission_id']} is reviewed.")
        elif args.action == "validate":
            data = load_validated_catalog()
            steps = sum(len(pattern["steps"]) for pattern in data["attack_patterns"])
            optional = sum(1 for pattern in data["attack_patterns"] for step in pattern["steps"]
                           if not step.get("required", True))
            family_data = family_store.load_families()
            problems = family_store.validate_families(family_data, data["attack_patterns"])
            problems += migration_store.audit_migrations(data["attack_patterns"])
            problems += admission_store.audit_admissions(data["attack_patterns"])
            problems += chain_store.audit_chains(data["attack_patterns"], read_csv(RAW_LOGS_PATH))
            problems += lifecycle_store.audit_lifecycle(data["attack_patterns"])
            problems += retention_store.audit_archives()
            if problems:
                for problem in problems:
                    print(f"  PROBLEM: {problem}")
                raise SystemExit(1)
            print(f"Catalog valid: {len(data['attack_patterns'])} pattern(s), {steps} step(s), "
                  f"{optional} optional step(s), {len(family_data['families'])} family(ies), "
                  f"{len(migration_store.load_migrations()['migrations'])} migration(s), "
                  f"{len(admission_store.load_admissions()['admissions'])} admission(s), "
                  f"{len(chain_store.load_chains()['chains'])} chain(s), "
                  f"{len(lifecycle_store.load_lifecycle()['events'])} lifecycle event(s), "
                  f"{len(retention_store.load_tombstones()['runs'])} retention run(s).")
        else:
            if args.from_candidate and args.supporting_incident_ids:
                parser.error("use --from-candidate or --supporting-incident-ids, not both")
            if args.from_candidate:
                case_id, candidate = add_pattern_from_candidate(
                    args.from_candidate, resolve_demo_path(args.input), force=args.force)
                print(f"Promoted {candidate['candidate_id']} to {case_id} "
                      f"({len(candidate['incidents'])} incident(s), unreviewed).")
            else:
                supporting = [item.strip() for item in (args.supporting_incident_ids or "").split(",")
                              if item.strip()]
                case_id = add_pattern(resolve_demo_path(args.input), supporting, force=args.force)
                print(f"Added {case_id} to data/attack_patterns.json (unreviewed).")
    elif args.group == "review":
        if args.action == "stage":
            chain = chain_store.review_stage(
                args.incident_id, args.event_id, args.stage, args.label, args.basis,
                order=args.order)
            print(f"Annotated {args.event_id} in {chain['incident_id']} as {args.stage}.")
        else:
            ids = [item.strip() for item in args.event_ids.split(",") if item.strip()]
            if not ids:
                parser.error("--event-ids must contain at least one event ID")
            if args.action == "link":
                count = append_links(ids, args.incident_id, args.case_id, args.step_id,
                                     args.status, args.basis, force=args.force)
                print(f"Appended {count} {args.status} link(s).")
            else:
                count = append_links(ids, args.incident_id, args.case_id, args.step_id or "",
                                     "related", args.basis)
                print(f"Associated {count} event(s) with {args.case_id} as related (no labels changed).")
    elif args.group == "evolve":
        if args.action == "propose":
            payload = json.loads(resolve_demo_path(args.input).read_text(encoding="utf-8-sig"))
            proposal, evaluation = create_proposal(payload)
            print(f"Recorded {proposal['proposal_id']} as {proposal['status']} "
                  f"(auto_eligible={evaluation['auto_eligible']}).")
            for key in ("support_incidents", "support_events", "coverage_before", "coverage_after",
                        "strong_before", "strong_after", "foreign_matches", "narrowing"):
                if key in evaluation["metrics"]:
                    print(f"  {key}={evaluation['metrics'][key]}")
            for problem in evaluation["problems"]:
                print(f"  BLOCKED: {problem}")
        elif args.action == "list":
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
        elif args.action == "accept":
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
        elif args.action == "reject":
            proposal = reject_proposal(args.proposal_id, args.basis)
            print(f"Rejected {proposal['proposal_id']} ({proposal['case_id']}).")
        else:
            result = rollback_pattern(args.case_id, args.to, args.basis)
            print(f"Rolled back {result['case_id']}: v{result['from_version']} -> v{result['to_version']}")
            print("Re-run audit: links reviewed against the newer version may need review.")
    else:
        patterns = load_validated_catalog()["attack_patterns"]
        logs = read_csv(RAW_LOGS_PATH)
        links = read_links(LINKS_PATH)
        proposals = load_proposals(PROPOSALS_PATH)
        candidates = candidate_store.list_candidates()
        merged_count = candidate_store.counts().get("merged", 0)
        family_data = family_store.load_families()
        migrations = migration_store.load_migrations()["migrations"]
        admissions = admission_store.load_admissions()["admissions"]
        chains = chain_store.load_chains()["chains"]
        lifecycle = lifecycle_store.load_lifecycle()["events"]
        archive_runs = retention_store.load_tombstones()["runs"]
        problems = audit_problems(patterns, logs, links, proposals)
        problems += family_store.audit_families(family_data, patterns, candidates)
        problems += migration_store.audit_migrations(patterns)
        problems += admission_store.audit_admissions(patterns)
        problems += chain_store.audit_chains(patterns, logs)
        problems += lifecycle_store.audit_lifecycle(patterns)
        problems += retention_store.audit_archives()
        problems += candidate_store.audit_candidates(
            patterns, family_ids=family_store.family_ids(family_data))
        print(f"Audited {len(links)} link row(s) against {len(logs)} event(s), "
              f"{len(patterns)} pattern(s), {len(proposals)} proposal(s), "
              f"{len(candidates)} active candidate(s) (+{merged_count} merged), "
              f"{len(family_data['families'])} family(ies), {len(migrations)} migration(s), "
              f"{len(admissions)} admission(s), {len(chains)} chain(s), "
              f"{len(lifecycle)} lifecycle event(s) and {len(archive_runs)} archive run(s).")
        if args.verbose:
            print("\n".join(diagnostic_lines(args.case_id)))
        if problems:
            for problem in problems:
                print(f"  PROBLEM: {problem}")
            print(f"Audit failed with {len(problems)} problem(s).")
            raise SystemExit(1)
        print("Audit clean: links, labels, proposals, candidates, migrations, admissions, chains and lifecycle agree.")


if __name__ == "__main__":
    main()

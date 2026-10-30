"""Single source of truth for demo numbers and the generated README state block.

``catalog state`` renders this block; ``catalog state --check README.md`` fails when
the README block no longer matches the store, so documentation drift becomes a test
failure instead of a trust problem.
"""
from __future__ import annotations

import pathlib
import unittest
from typing import Any

from . import (admissions, candidates, chains, evolution, families, lifecycle,
               links, migrations, retention, storage)
from .catalog import load_validated_catalog

STATE_START = "<!-- STATE:START -->"
STATE_END = "<!-- STATE:END -->"
_STATUS_ORDER = ("provisional", "promotable", "promoted", "rejected")


def _corrections_count() -> int:
    try:
        from . import corrections
    except ImportError:
        return 0
    loader = getattr(corrections, "load_corrections", None)
    return len(loader().get("corrections") or []) if loader else 0


def _test_count() -> int | None:
    try:
        suite = unittest.TestLoader().discover(str(storage.DEMO_ROOT / "tests"),
                                               pattern="test_*.py")
        return suite.countTestCases()
    except Exception:
        return None


def _case_range(patterns: list[dict[str, Any]]) -> str:
    case_ids = sorted(pattern["case_id"] for pattern in patterns)
    if not case_ids:
        return "none"
    first, last = case_ids[0], case_ids[-1]
    contiguous = [f"CASE-{number:03d}" for number in
                  range(int(first.split("-")[1]), int(last.split("-")[1]) + 1)]
    if contiguous == case_ids:
        return f"{first}..{last}"
    return ", ".join(case_ids)


def _status_summary(active: list[dict[str, Any]]) -> str:
    counts = {status: 0 for status in candidates.CANDIDATE_STATUSES}
    for candidate in active:
        status = candidate.get("status") or "provisional"
        counts[status] = counts.get(status, 0) + 1
    parts = [f"{counts[status]} {status}" for status in _STATUS_ORDER if counts.get(status)]
    return ", ".join(parts)


def memory_state() -> dict[str, Any]:
    """Load the store once and produce both machine counts and the rendered lines."""
    patterns = load_validated_catalog()["attack_patterns"]
    logs = storage.read_csv(storage.RAW_LOGS_PATH)
    link_rows = storage.read_links(storage.LINKS_PATH)
    candidate_rows = candidates.load_candidates()["candidates"]
    active = [item for item in candidate_rows if item.get("status") != "merged"]
    merged = [item for item in candidate_rows if item.get("status") == "merged"]
    family_data = families.load_families()
    admission_rows = admissions.load_admissions()["admissions"]
    unreviewed = sum(1 for item in admission_rows if item.get("status") == "unreviewed")
    proposals = evolution.load_proposals(evolution.PROPOSALS_PATH)
    accepted = sum(1 for item in proposals if item.get("status") == "accepted")
    migration_rows = migrations.load_migrations()["migrations"]
    chain_rows = chains.load_chains()["chains"]
    unclassified = sum(1 for chain in chain_rows for event in chain["events"]
                       if event.get("stage_kind") == "unclassified")
    lifecycle_rows = lifecycle.load_lifecycle()["events"]
    archive_runs = retention.load_tombstones()["runs"]
    archived_events = sum(int(run.get("events") or 0) for run in archive_runs)
    link_statuses = {status: 0 for status in storage.LINK_STATUSES}
    for link in link_rows:
        status = (link.get("link_status") or "").strip()
        link_statuses[status] = link_statuses.get(status, 0) + 1
    steps = sum(len(pattern["steps"]) for pattern in patterns)
    optional = sum(1 for pattern in patterns for step in pattern["steps"]
                   if not step.get("required", True))
    corrections = _corrections_count()
    journal_records = storage.load_journal()
    unfinished = storage.audit_journal()
    test_count = _test_count()
    from .audit import run_audit
    audit_report = run_audit()

    counts = {
        "cases": len(patterns),
        "case_steps": steps,
        "optional_steps": optional,
        "families": len(family_data["families"]),
        "candidates": len(candidate_rows),
        "active_candidates": len(active),
        "merged_candidates": len(merged),
        "admissions": len(admission_rows),
        "unreviewed_admissions": unreviewed,
        "links": len(link_rows),
        "link_statuses": link_statuses,
        "active_events": len(logs),
        "archived_events": archived_events,
        "proposals": len(proposals),
        "accepted_proposals": accepted,
        "migrations": len(migration_rows),
        "chains": len(chain_rows),
        "unclassified_events": unclassified,
        "lifecycle_events": len(lifecycle_rows),
        "archive_runs": len(archive_runs),
        "corrections": corrections,
        "journal_transactions": len(journal_records),
        "unfinished_transactions": len(unfinished),
        "tests": test_count,
        "audit_ok": audit_report["ok"],
        "audit_problems": len(audit_report["problems"]),
    }
    lines = [
        f"cases                {counts['cases']} ({_case_range(patterns)})",
        f"case steps           {steps} ({optional} optional)",
        f"families             {counts['families']}",
        f"candidates           {len(candidate_rows)} records: {len(active)} active "
        f"({_status_summary(active)}) + {len(merged)} merged",
        f"admissions           {len(admission_rows)} ({unreviewed} unreviewed)",
        f"links                {len(link_rows)} ("
        + ", ".join(f"{status}={count}" for status, count in link_statuses.items()) + ")",
        f"raw events           {len(logs)} active (+{archived_events} archived)",
        f"proposals            {len(proposals)} ({accepted} accepted)",
        f"migrations           {len(migration_rows)}",
        f"chains               {len(chain_rows)} ({unclassified} unclassified events)",
        f"lifecycle            {len(lifecycle_rows)} event(s)",
        f"retention            {len(archive_runs)} archive run(s), {archived_events} archived event(s)",
        f"corrections          {corrections}",
        f"journal              {len(journal_records)} transaction(s), {len(unfinished)} unfinished",
        f"tests                {test_count if test_count is not None else '?'}",
        f"audit                {'clean' if audit_report['ok'] else str(len(audit_report['problems'])) + ' problem(s)'}",
    ]
    return {"counts": counts, "lines": lines}


def render_state_block(state: dict[str, Any] | None = None) -> str:
    state = state or memory_state()
    return "\n".join([STATE_START, "```text", *state["lines"], "```", STATE_END])


def check_state_block(path: pathlib.Path | str) -> list[str]:
    path = pathlib.Path(path)
    if not path.exists():
        return [f"state block target not found: {path}"]
    text = path.read_text(encoding="utf-8-sig")
    if STATE_START not in text or STATE_END not in text:
        return [f"{path.name}: missing {STATE_START} / {STATE_END} markers"]
    start = text.index(STATE_START)
    end = text.index(STATE_END, start) + len(STATE_END)
    actual = text[start:end]
    expected = render_state_block()
    if actual != expected:
        return [f"{path.name}: generated state block is stale; run `catalog state` "
                "and replace the block between the markers"]
    return []

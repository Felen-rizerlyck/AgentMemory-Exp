"""Single audit entry point: one report, every memory invariant.

The CLI never assembles checks itself. New invariants are added here once and both
``catalog validate`` (structural) and ``audit`` (full) pick them up.
"""
from __future__ import annotations

import importlib
from typing import Any

from . import (admissions, candidates, chains, evolution, families, lifecycle,
               links, migrations, retention, storage)
from .catalog import load_validated_catalog


def _optional_check(label: str, module_name: str, function_name: str,
                    warnings: list[str], *args: Any) -> list[str]:
    """Run a check that may not exist in every build without failing the audit."""
    try:
        module = importlib.import_module(f".{module_name}", __package__)
    except ImportError:
        warnings.append(f"{label}: module not available in this build")
        return []
    function = getattr(module, function_name, None)
    if function is None:
        warnings.append(f"{label}: check not implemented in this build")
        return []
    return list(function(*args) or [])


def _append_check(checks: list[dict[str, Any]], name: str,
                  problems: list[str]) -> None:
    problems = [str(problem) for problem in (problems or [])]
    checks.append({"name": name, "ok": not problems, "problems": problems})


def _corrections_count() -> int:
    try:
        module = importlib.import_module(".corrections", __package__)
    except ImportError:
        return 0
    loader = getattr(module, "load_corrections", None)
    if loader is None:
        return 0
    return len(loader().get("corrections") or [])


def _forced_exception_count(link_rows: list[dict[str, str]]) -> int:
    collect = getattr(links, "force_exceptions", None)
    if collect is None:
        return 0
    return len(collect(link_rows))


def run_audit() -> dict[str, Any]:
    """Full audit: load the store once, run every check, return one report."""
    patterns = load_validated_catalog()["attack_patterns"]
    logs = storage.read_csv(storage.RAW_LOGS_PATH)
    link_rows = storage.read_links(storage.LINKS_PATH)
    proposals = evolution.load_proposals(evolution.PROPOSALS_PATH)
    candidate_rows = candidates.list_candidates()
    merged_count = candidates.counts().get("merged", 0)
    family_data = families.load_families()
    migration_rows = migrations.load_migrations()["migrations"]
    admission_rows = admissions.load_admissions()["admissions"]
    chain_rows = chains.load_chains()["chains"]
    lifecycle_rows = lifecycle.load_lifecycle()["events"]
    archive_runs = retention.load_tombstones()["runs"]

    warnings: list[str] = []
    checks: list[dict[str, Any]] = []

    def add(name: str, problems: list[str]) -> None:
        _append_check(checks, name, problems)

    add("links", links.audit_links(patterns, logs, link_rows))
    add("link-exceptions", _optional_check(
        "link-exceptions", "links", "audit_link_exceptions", warnings, link_rows))
    add("proposals", evolution.audit_proposals(proposals))
    add("versions", _optional_check("versions", "catalog", "audit_versions", warnings, patterns))
    add("aliases", _optional_check("aliases", "catalog", "audit_aliases", warnings, patterns))
    add("families", families.audit_families(family_data, patterns, candidate_rows))
    add("migrations", migrations.audit_migrations(patterns))
    add("admissions", admissions.audit_admissions(patterns))
    add("chains", chains.audit_chains(patterns, logs))
    add("lifecycle", lifecycle.audit_lifecycle(patterns))
    add("retention", retention.audit_archives())
    add("candidates", candidates.audit_candidates(
        patterns, family_ids=families.family_ids(family_data)))
    add("corrections", _optional_check(
        "corrections", "corrections", "audit_corrections", warnings, patterns, logs))
    add("journal", storage.audit_journal())

    candidate_warnings = getattr(candidates, "candidate_warnings", None)
    if candidate_warnings is not None:
        warnings.extend(str(item) for item in candidate_warnings())

    problems = [f"{check['name']}: {problem}"
                for check in checks for problem in check["problems"]]
    counts = {
        "patterns": len(patterns),
        "events": len(logs),
        "links": len(link_rows),
        "proposals": len(proposals),
        "candidates": len(candidate_rows),
        "candidates_merged": merged_count,
        "families": len(family_data["families"]),
        "migrations": len(migration_rows),
        "admissions": len(admission_rows),
        "chains": len(chain_rows),
        "lifecycle": len(lifecycle_rows),
        "archive_runs": len(archive_runs),
        "corrections": _corrections_count(),
        "journal_transactions": len(storage.load_journal()),
    }
    return {
        "ok": not problems,
        "problems": problems,
        "warnings": warnings,
        "checks": checks,
        "counts": counts,
        "forced_exceptions": _forced_exception_count(link_rows),
    }


def run_validation() -> dict[str, Any]:
    """Structural validation: catalog, ledgers and cross-file references only."""
    patterns = load_validated_catalog()["attack_patterns"]
    logs = storage.read_csv(storage.RAW_LOGS_PATH)
    link_rows = storage.read_links(storage.LINKS_PATH)
    family_data = families.load_families()
    warnings: list[str] = []
    checks: list[dict[str, Any]] = []

    def add(name: str, problems: list[str]) -> None:
        _append_check(checks, name, problems)

    steps = sum(len(pattern["steps"]) for pattern in patterns)
    optional = sum(1 for pattern in patterns for step in pattern["steps"]
                   if not step.get("required", True))
    add("families", families.validate_families(family_data, patterns))
    add("migrations", migrations.audit_migrations(patterns))
    add("admissions", admissions.audit_admissions(patterns))
    add("chains", chains.audit_chains(patterns, logs))
    add("lifecycle", lifecycle.audit_lifecycle(patterns))
    add("retention", retention.audit_archives())
    add("versions", _optional_check("versions", "catalog", "audit_versions", warnings, patterns))
    add("aliases", _optional_check("aliases", "catalog", "audit_aliases", warnings, patterns))
    add("link-exceptions", _optional_check(
        "link-exceptions", "links", "audit_link_exceptions", warnings, link_rows))
    problems = [f"{check['name']}: {problem}"
                for check in checks for problem in check["problems"]]
    counts = {
        "patterns": len(patterns),
        "steps": steps,
        "optional_steps": optional,
        "families": len(family_data["families"]),
        "migrations": len(migrations.load_migrations()["migrations"]),
        "admissions": len(admissions.load_admissions()["admissions"]),
        "chains": len(chains.load_chains()["chains"]),
        "lifecycle": len(lifecycle.load_lifecycle()["events"]),
        "archive_runs": len(retention.load_tombstones()["runs"]),
    }
    return {"ok": not problems, "problems": problems, "warnings": warnings,
            "checks": checks, "counts": counts}


def format_audit_lines(report: dict[str, Any]) -> list[str]:
    counts = report["counts"]
    lines = [
        f"Audited {counts['links']} link row(s) against {counts['events']} event(s), "
        f"{counts['patterns']} pattern(s), {counts['proposals']} proposal(s), "
        f"{counts['candidates']} active candidate(s) (+{counts['candidates_merged']} merged), "
        f"{counts['families']} family(ies), {counts['migrations']} migration(s), "
        f"{counts['admissions']} admission(s), {counts['chains']} chain(s), "
        f"{counts['lifecycle']} lifecycle event(s), {counts['archive_runs']} archive run(s), "
        f"{counts['corrections']} correction(s) and {counts['journal_transactions']} transaction(s)."
    ]
    if report.get("forced_exceptions"):
        lines.append(f"Forced link exceptions: {report['forced_exceptions']} (reviewed, visible, gated).")
    for warning in report["warnings"]:
        lines.append(f"  WARNING: {warning}")
    if report["problems"]:
        lines.extend(f"  PROBLEM: {problem}" for problem in report["problems"])
        lines.append(f"Audit failed with {len(report['problems'])} problem(s).")
    else:
        lines.append(
            "Audit clean: links, exceptions, versions, proposals, candidates, families, "
            "migrations, admissions, chains, lifecycle, retention, corrections and journal agree."
        )
    return lines


def format_validation_lines(report: dict[str, Any]) -> list[str]:
    counts = report["counts"]
    lines = [
        f"Catalog valid: {counts['patterns']} pattern(s), {counts['steps']} step(s), "
        f"{counts['optional_steps']} optional step(s), {counts['families']} family(ies), "
        f"{counts['migrations']} migration(s), {counts['admissions']} admission(s), "
        f"{counts['chains']} chain(s), {counts['lifecycle']} lifecycle event(s), "
        f"{counts['archive_runs']} retention run(s)."
    ]
    for warning in report["warnings"]:
        lines.append(f"  WARNING: {warning}")
    if report["problems"]:
        lines.extend(f"  PROBLEM: {problem}" for problem in report["problems"])
    return lines

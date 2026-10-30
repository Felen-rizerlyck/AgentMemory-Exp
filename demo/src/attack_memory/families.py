"""Family registry: one taxonomy level above cases.

A family groups cases that share an attack surface or objective (web entry,
ransomware, domain identity, supply chain, host persistence). It does not
change retrieval tiers; it gives cases, candidates and audit a shared key.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import storage

FAMILIES_PATH = storage.DATA_DIR / "families.json"
DEFAULT_FAMILY = "unclassified"


def _empty() -> dict:
    return {"schema_version": 1, "families": []}


def load_families(path: Path | str | None = None) -> dict:
    target = Path(path) if path is not None else FAMILIES_PATH
    if not target.exists():
        return _empty()
    data = json.loads(target.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("families"), list):
        raise ValueError(f"{target}: family registry must contain a families list")
    return data


def save_families(data: dict, path: Path | str | None = None) -> None:
    target = Path(path) if path is not None else FAMILIES_PATH
    storage.atomic_write_json(target, data)


def family_ids(data: dict | None = None) -> set[str]:
    data = data or load_families()
    return {family.get("family_id") for family in data["families"] if family.get("family_id")}


def family_for_case(case_id: str, patterns: list[dict], data: dict | None = None) -> str:
    pattern = next((item for item in patterns if item["case_id"] == case_id), None)
    if pattern is not None and pattern.get("family_id"):
        return pattern["family_id"]
    data = data or load_families()
    for family in data["families"]:
        if case_id in (family.get("case_ids") or []):
            return family["family_id"]
    return DEFAULT_FAMILY


def family_steps(data: dict, family_id: str) -> list[dict]:
    family = next((item for item in data.get("families") or []
                   if item.get("family_id") == family_id), None)
    return list((family or {}).get("steps") or [])


def step_for_case(case_id: str, step_id: str, patterns: list[dict],
                  data: dict | None = None) -> dict | None:
    data = data or load_families()
    family_id = family_for_case(case_id, patterns, data)
    return next((step for step in family_steps(data, family_id)
                 if step.get("step_id") == step_id), None)


def family_evidence(family: dict, logs: list[dict[str, str]]) -> list[dict]:
    """Family-level detections, surfaced separately from case tier."""
    evidence: list[dict] = []
    for step in family.get("steps") or []:
        regex = re.compile(step["action_regex"])
        expected = step.get("expected_sources") or []
        rows = [row for row in logs
                if storage.source_fits(row.get("source") or "", expected)
                and regex.search(row.get("content") or "") is not None]
        if not rows:
            continue
        rows.sort(key=lambda row: row.get("timestamp") or "")
        evidence.append({
            "step_id": step["step_id"],
            "action_id": step["action_id"],
            "label": step.get("label", step["action_id"]),
            "generic": bool(step.get("generic", False)),
            "event_ids": [row.get("event_id") for row in rows],
            "sources": sorted({row.get("source") for row in rows}),
            "detections": [{"event_id": row.get("event_id"), "source": row.get("source"),
                            "timestamp": row.get("timestamp")} for row in rows],
        })
    return evidence


def validate_families(data: dict, patterns: list[dict]) -> list[str]:
    """Every case has exactly one family, and the registry and catalog agree."""
    problems: list[str] = []
    families = data.get("families") or []
    ids: set[str] = set()
    case_owner: dict[str, str] = {}
    for family in families:
        fid = (family.get("family_id") or "").strip()
        if not fid:
            problems.append("family: missing family_id")
            continue
        if fid in ids:
            problems.append(f"family: duplicate family_id {fid}")
            continue
        ids.add(fid)
        for case_id in family.get("case_ids") or []:
            if case_id in case_owner:
                problems.append(f"family {fid}: case {case_id} also listed in {case_owner[case_id]}")
                continue
            case_owner[case_id] = fid
        seen_steps: set[str] = set()
        seen_actions: dict[str, str] = {}
        for step in family.get("steps") or []:
            step_id = (step.get("step_id") or "").strip()
            if not step_id or step_id in seen_steps:
                problems.append(f"family {fid}: missing or duplicate step_id {step_id!r}")
                continue
            seen_steps.add(step_id)
            action_id = (step.get("action_id") or "").strip()
            regex = step.get("action_regex") or ""
            if not action_id:
                problems.append(f"family {fid}/{step_id}: missing action_id")
            if not isinstance(regex, str) or len(regex) < 3:
                problems.append(f"family {fid}/{step_id}: action_regex must be at least 3 characters")
            else:
                try:
                    re.compile(regex)
                except re.error as error:
                    problems.append(f"family {fid}/{step_id}: invalid action_regex ({error})")
                if re.fullmatch(r"\s*|\.\*", regex):
                    problems.append(f"family {fid}/{step_id}: action_regex matches everything")
            previous = seen_actions.get(action_id)
            if previous is not None and previous != regex:
                problems.append(f"family {fid}/{step_id}: action_id {action_id!r} redefines a regex")
            seen_actions[action_id] = regex
            sources = step.get("expected_sources")
            if (not isinstance(sources, list) or not sources
                    or any(not isinstance(source, str) or not source for source in sources)):
                problems.append(f"family {fid}/{step_id}: expected_sources must be a non-empty list")

    pattern_ids = {pattern["case_id"] for pattern in patterns}
    for pattern in patterns:
        case_id = pattern["case_id"]
        fid = (pattern.get("family_id") or "").strip()
        if not fid:
            problems.append(f"{case_id}: missing family_id")
            continue
        if fid not in ids:
            problems.append(f"{case_id}: unknown family_id {fid!r}")
            continue
        owner = case_owner.get(case_id)
        if owner is None:
            problems.append(f"{case_id}: not listed in family {fid!r} case_ids")
        elif owner != fid:
            problems.append(f"{case_id}: family_id={fid} but listed under {owner}")

    for case_id, fid in case_owner.items():
        if case_id not in pattern_ids:
            problems.append(f"family {fid}: case {case_id} does not exist in the catalog")
    return problems


def counts(data: dict, patterns: list[dict], candidates: list[dict] | None = None) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for family in data.get("families") or []:
        fid = family.get("family_id")
        result[fid] = {"name": family.get("name", fid), "cases": 0, "retired": 0,
                       "candidates": 0, "steps": len(family.get("steps") or [])}
    for pattern in patterns:
        fid = pattern.get("family_id") or DEFAULT_FAMILY
        row = result.setdefault(fid, {"name": fid, "cases": 0, "retired": 0,
                                      "candidates": 0, "steps": 0})
        row["cases"] += 1
        if pattern.get("status") == "retired":
            row["retired"] += 1
    for candidate in candidates or []:
        fid = candidate.get("family_id") or DEFAULT_FAMILY
        result.setdefault(fid, {"name": fid, "cases": 0, "retired": 0,
                                "candidates": 0, "steps": 0})["candidates"] += 1
    return result


def audit_families(data: dict, patterns: list[dict], candidates: list[dict] | None = None) -> list[str]:
    problems = validate_families(data, patterns)
    ids = family_ids(data)
    for candidate in candidates or []:
        fid = candidate.get("family_id")
        if fid and fid not in ids:
            problems.append(f"{candidate.get('candidate_id')}: unknown family_id {fid!r}")
    return problems

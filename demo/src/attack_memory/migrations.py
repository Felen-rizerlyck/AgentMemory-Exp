"""Append-only ledger for reviewed schema migrations that are not pattern proposals.

A migration moves a step or a field between layers (for example S9 from CASE-005
into the ransomware family). It is not a pattern-evolution proposal: the gate does
not apply a delta. The ledger makes the move auditable next to the v003 snapshots.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import catalog, families, storage

MIGRATIONS_PATH = storage.DATA_DIR / "pattern_migrations.json"
KINDS = ("move_step_to_family",)


def _empty() -> dict:
    return {"schema_version": 1, "migrations": []}


def load_migrations(path: Path | str | None = None) -> dict:
    target = Path(path) if path is not None else MIGRATIONS_PATH
    if not target.exists():
        return _empty()
    data = json.loads(target.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("migrations"), list):
        raise ValueError(f"{target}: migration ledger must contain a migrations list")
    return data


def save_migrations(data: dict, path: Path | str | None = None) -> None:
    target = Path(path) if path is not None else MIGRATIONS_PATH
    storage.atomic_write_json(target, data)


def migration_id(case_id: str, to_version: int) -> str:
    return f"MIG-{case_id}-v{to_version}"


def record_migration(case_id: str, from_version: int, to_version: int, kind: str,
                     step_id: str, family_id: str, basis: str,
                     path: Path | str | None = None) -> dict:
    if kind not in KINDS:
        raise ValueError(f"unsupported migration kind: {kind}")
    data = load_migrations(path)
    record_id = migration_id(case_id, to_version)
    if any(item.get("migration_id") == record_id for item in data["migrations"]):
        raise ValueError(f"migration already recorded: {record_id}")
    snapshot = catalog.version_path(case_id, to_version)
    if not snapshot.exists():
        raise ValueError(f"missing v{to_version:03d} snapshot for {case_id}")
    record = {
        "migration_id": record_id,
        "case_id": case_id,
        "from_version": from_version,
        "to_version": to_version,
        "kind": kind,
        "step_id": step_id,
        "family_id": family_id,
        "basis": basis,
        "decided_at": catalog.now_iso(),
        "snapshot": snapshot.relative_to(storage.DATA_DIR).as_posix(),
    }
    problems = audit_migrations_for_record(record, catalog.load_validated_catalog()["attack_patterns"])
    if problems:
        raise ValueError("; ".join(problems))
    data["migrations"].append(record)
    save_migrations(data, path)
    return record


def audit_migrations_for_record(record: dict, patterns: list[dict]) -> list[str]:
    problems: list[str] = []
    case_id = record.get("case_id")
    pattern = next((item for item in patterns if item["case_id"] == case_id), None)
    if pattern is None:
        return [f"{record.get('migration_id')}: unknown case_id {case_id!r}"]
    from_version = record.get("from_version")
    to_version = record.get("to_version")
    if (not isinstance(from_version, int) or not isinstance(to_version, int)
            or to_version != from_version + 1):
        problems.append(f"{record.get('migration_id')}: from_version/to_version must be consecutive")
    if catalog.pattern_version(pattern) < (to_version or 0):
        problems.append(f"{record.get('migration_id')}: catalog is older than v{to_version}")
    snapshot = storage.DATA_DIR / (record.get("snapshot") or "")
    if not record.get("snapshot") or not snapshot.exists():
        problems.append(f"{record.get('migration_id')}: snapshot is missing")
    kind = record.get("kind")
    if kind not in KINDS:
        problems.append(f"{record.get('migration_id')}: unsupported kind {kind!r}")
    if kind == "move_step_to_family":
        step_id = record.get("step_id")
        family_id = record.get("family_id")
        if any(step["step_id"] == step_id for step in pattern["steps"]):
            problems.append(f"{record.get('migration_id')}: step {step_id} is still in {case_id}")
        if pattern.get("family_id") != family_id:
            problems.append(f"{record.get('migration_id')}: case family {pattern.get('family_id')!r} "
                            f"does not match {family_id!r}")
        family = next((item for item in families.load_families()["families"]
                       if item.get("family_id") == family_id), None)
        if family is None:
            problems.append(f"{record.get('migration_id')}: unknown family {family_id!r}")
        elif not any(step.get("step_id") == step_id for step in family.get("steps") or []):
            problems.append(f"{record.get('migration_id')}: family {family_id} has no step {step_id}")
    return problems


def audit_migrations(patterns: list[dict], path: Path | str | None = None) -> list[str]:
    data = load_migrations(path)
    problems: list[str] = []
    seen: set[str] = set()
    for record in data["migrations"]:
        record_id = record.get("migration_id")
        if not record_id or record_id in seen:
            problems.append(f"migration: duplicate or missing migration_id {record_id!r}")
            continue
        seen.add(record_id)
        problems.extend(audit_migrations_for_record(record, patterns))
    return problems

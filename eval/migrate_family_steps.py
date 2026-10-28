"""Move CASE-005/S9 and CASE-007/S4 from case patterns into their family registry.

This is a reviewed schema migration, not a pattern-evolution proposal: the step is
not deleted, it becomes a family-level step; historical `related + step` links
remain auditable against the family step. Cases are bumped to v3 with snapshots.
"""
from __future__ import annotations

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEMO = ROOT / "demo"
sys.path.insert(0, str(DEMO / "src"))

from attack_memory import catalog, families, links, migrations, storage  # noqa: E402

MIGRATIONS = {"CASE-005": "S9", "CASE-007": "S4"}


def main() -> None:
    data = catalog.load_validated_catalog()
    patterns = data["attack_patterns"]
    changed = []
    for pattern in patterns:
        case_id = pattern["case_id"]
        step_id = MIGRATIONS.get(case_id)
        if not step_id:
            continue
        step = next((item for item in pattern["steps"] if item["step_id"] == step_id), None)
        if step is None:
            print(f"{case_id}: {step_id} already moved")
            continue
        if step.get("required", True):
            raise SystemExit(f"{case_id}/{step_id} is required; refusing to move it to a family")
        old_version = catalog.pattern_version(pattern)
        family_id = pattern.get("family_id")
        family = next((item for item in families.load_families()["families"]
                       if item.get("family_id") == family_id), None)
        if family is None:
            raise SystemExit(f"{case_id}: unknown family {family_id!r}")
        family_step = next((item for item in family.get("steps") or []
                            if item.get("step_id") == step_id), None)
        if family_step is None:
            raise SystemExit(f"{family_id}: family has no step {step_id}")
        pattern["steps"] = [item for item in pattern["steps"] if item["step_id"] != step_id]
        pattern["version"] = old_version + 1
        pattern["supersedes"] = old_version
        pattern["updated_at"] = catalog.now_iso()
        catalog.validate_pattern(pattern)
        changed.append({"case_id": case_id, "step_id": step_id,
                        "old_version": old_version, "new_version": pattern["version"]})

    if not changed:
        print("nothing to migrate")
        return
    catalog.build_action_index(patterns)
    storage.atomic_write_json(storage.PATTERNS_PATH, data)
    for item in changed:
        pattern = next(pattern for pattern in patterns if pattern["case_id"] == item["case_id"])
        path = catalog.write_version_snapshot(pattern)
        item["snapshot"] = str(path)
        try:
            migrations.record_migration(
                item["case_id"], item["old_version"], item["new_version"],
                "move_step_to_family", item["step_id"], pattern["family_id"],
                f"reviewed schema migration: move {item['step_id']} into {pattern['family_id']}")
        except ValueError as error:
            if "already recorded" not in str(error):
                raise

    logs = storage.read_csv(storage.RAW_LOGS_PATH)
    link_rows = storage.read_links(storage.LINKS_PATH)
    problems = links.audit_links(patterns, logs, link_rows)
    print(json.dumps({"changed": changed, "audit_problems": problems}, ensure_ascii=False, indent=2))
    if problems:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

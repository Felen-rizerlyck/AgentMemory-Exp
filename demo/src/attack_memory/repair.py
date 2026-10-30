"""Safe, idempotent repair for *derived* state: labels, snapshots, orphan admissions.

Repair only ever rebuilds caches that have an authoritative source:

* labels are derived from the latest reviewed link (links are append-only truth);
* missing version snapshots are backfilled from the current catalog as baselines;
* admissions whose case does not exist are removed.

It never deletes raw logs, links, cases, candidates or proposals, and every applied
repair is recorded in an append-only ledger inside the same transaction as the fix.
"""
from __future__ import annotations

import pathlib

from . import admissions as admission_store
from . import catalog as catalog_module
from . import storage

REPAIR_LOG_PATH = storage.DATA_DIR / "repair_log.json"
REPAIRABLE_STATUSES = ("confirmed", "rejected")


def _empty_log() -> dict:
    return {"schema_version": 1, "repairs": []}


def load_repair_log(path: pathlib.Path | str | None = None) -> dict:
    target = pathlib.Path(path) if path is not None else REPAIR_LOG_PATH
    data = storage.load_json(target, _empty_log())
    if not isinstance(data, dict) or not isinstance(data.get("repairs"), list):
        raise ValueError(f"{target}: repair log must contain a repairs list")
    return data


def _label_fixes() -> dict:
    """Re-derive labels for events whose latest link is terminal (confirmed/rejected)."""
    if not storage.RAW_LOGS_PATH.exists():
        return {"fieldnames": [], "rows": [], "changes": []}
    fieldnames, rows = storage._read_csv_strict(storage.RAW_LOGS_PATH)
    latest = storage.latest_link_by_event(storage.read_links(storage.LINKS_PATH))
    new_rows: list[dict[str, str]] = []
    changes: list[dict] = []
    for row in rows:
        event_id = row.get("event_id", "")
        link = latest.get(event_id) or {}
        status = (link.get("link_status") or "").strip()
        if status not in REPAIRABLE_STATUSES:
            new_rows.append(row)
            continue
        updated, changed = storage.apply_label_changes(
            [row], {event_id}, (link.get("case_id") or "").strip(),
            (link.get("incident_id") or "").strip(), status)
        if changed:
            after = updated[0]
            new_rows.append(after)
            changes.append({
                "event_id": event_id,
                "link_status": status,
                "before": {"case_id": row.get("case_id", ""),
                           "incident_id": row.get("incident_id", "")},
                "after": {"case_id": after.get("case_id", ""),
                          "incident_id": after.get("incident_id", "")},
            })
        else:
            new_rows.append(row)
    return {"fieldnames": fieldnames, "rows": new_rows, "changes": changes}


def _snapshot_fixes(patterns: list[dict]) -> list[tuple[pathlib.Path, dict]]:
    """Missing version snapshots, rendered as baseline payloads (never rewrites history)."""
    writes: list[tuple[pathlib.Path, dict]] = []
    for pattern in patterns:
        for number in range(1, catalog_module.pattern_version(pattern) + 1):
            path = catalog_module.version_path(pattern["case_id"], number)
            if path.exists():
                continue
            writes.append((path, catalog_module.snapshot_payload(pattern, number)))
    return writes


def _admission_fixes(patterns: list[dict]) -> tuple[dict, list[dict]]:
    data = admission_store.load_admissions()
    known = {pattern["case_id"] for pattern in patterns}
    orphans = [record for record in data["admissions"]
               if (record.get("case_id") or "") not in known]
    return data, orphans


def _collect() -> tuple[dict, dict]:
    patterns = catalog_module.load_validated_catalog()["attack_patterns"]
    labels = _label_fixes()
    snapshots = _snapshot_fixes(patterns)
    admissions_data, orphans = _admission_fixes(patterns)
    actions: list[dict] = []
    for change in labels["changes"]:
        actions.append({"kind": "label", "target": change["event_id"], "action": "update",
                        "before": change["before"], "after": change["after"]})
    for path, payload in snapshots:
        actions.append({"kind": "snapshot", "target": str(path), "action": "write",
                        "before": None, "after": {"version": payload.get("version")}})
    for record in orphans:
        actions.append({"kind": "admission", "target": record.get("admission_id"),
                        "action": "remove",
                        "before": {"case_id": record.get("case_id"),
                                   "status": record.get("status"),
                                   "source": record.get("source")},
                        "after": None})
    plan = {
        "labels": {"changes": labels["changes"], "count": len(labels["changes"])},
        "snapshots": {"missing": [str(path) for path, _ in snapshots],
                      "count": len(snapshots)},
        "admissions": {"orphans": [
            {"admission_id": record.get("admission_id"),
             "case_id": record.get("case_id"),
             "status": record.get("status")} for record in orphans],
            "count": len(orphans)},
        "actions": actions,
        "change_count": len(actions),
    }
    resources = {
        "patterns": patterns,
        "labels": labels,
        "snapshots": snapshots,
        "admissions_data": admissions_data,
        "orphans": orphans,
    }
    return plan, resources


def repair_plan() -> dict:
    """Read-only description of every safe fix repair would apply."""
    plan, _ = _collect()
    return plan


def _format_lines(plan: dict, dry_run: bool, applied: bool, txn_id: str | None) -> list[str]:
    counts = (plan["labels"]["count"], plan["snapshots"]["count"], plan["admissions"]["count"])
    if not plan["change_count"]:
        return ["Repair: nothing to repair (labels, snapshots and admissions are consistent)."]
    summary = (f"labels={counts[0]} snapshot(s)={counts[1]} "
               f"orphan admission(s)={counts[2]}")
    if dry_run:
        return [f"Repair plan (dry-run, nothing written): {summary}",
                *(f"  {action['kind']}: {action['target']}" for action in plan["actions"][:20]),
                "Next: run `catalog repair --apply` to apply these safe fixes."]
    if not applied:
        return [f"Repair: nothing applied ({summary})."]
    return [f"Repair applied in {txn_id}: {summary}",
            *(f"  {action['kind']}: {action['target']}" for action in plan["actions"][:20])]


def repair(dry_run: bool = True) -> dict:
    """Plan (``dry_run``) or apply the safe fixes in one journaled transaction."""
    try:
        plan, resources = _collect()
    except (OSError, ValueError) as error:
        # A corrupt store is exactly when repair must report instead of half-applying.
        return {"ok": False, "dry_run": bool(dry_run), "applied": False,
                "lines": [f"Repair failed: {error}"], "actions": [],
                "error": str(error)}
    result: dict = {
        "ok": True, "dry_run": bool(dry_run), "applied": False,
        "lines": [], "actions": plan["actions"],
        "labels": plan["labels"]["count"], "snapshots": plan["snapshots"]["count"],
        "admissions": plan["admissions"]["count"],
        "change_count": plan["change_count"], "repair_log": str(REPAIR_LOG_PATH),
    }
    if dry_run or not plan["change_count"]:
        result["lines"] = _format_lines(plan, dry_run, False, None)
        return result

    stamp = storage.now_iso()
    records: list[dict] = []
    writes: list[storage.Write] = []
    labels = resources["labels"]
    if plan["labels"]["count"]:
        writes.append(storage.Write.csv_replace(
            storage.RAW_LOGS_PATH, labels["fieldnames"], labels["rows"]))
    for path, payload in resources["snapshots"]:
        writes.append(storage.Write.json(path, payload))
    patterns = resources["patterns"]
    known = {pattern["case_id"] for pattern in patterns}
    if resources["orphans"]:
        admissions_data = resources["admissions_data"]
        admissions_data["admissions"] = [
            record for record in admissions_data["admissions"]
            if (record.get("case_id") or "") in known]
        writes.append(storage.Write.json(admission_store.ADMISSIONS_PATH, admissions_data))
    for index, action in enumerate(plan["actions"], start=1):
        if action["kind"] == "label":
            basis = "label is a derived cache of the latest reviewed link"
        elif action["kind"] == "snapshot":
            basis = ("baseline backfill: current catalog content written under a missing "
                     "version number, not a historical replay")
        else:
            basis = "orphan admission: the case no longer exists"
        records.append({
            "repair_id": f"REP-{stamp}-{index:03d}",
            "kind": action["kind"],
            "target": action["target"],
            "before": action["before"],
            "after": action["after"],
            "basis": basis,
            "at": stamp,
        })
    log_data = load_repair_log()
    log_data["repairs"].extend(records)
    writes.append(storage.Write.json(REPAIR_LOG_PATH, log_data))
    txn_id = storage.commit(
        writes, kind="repair",
        summary=(f"repair labels={plan['labels']['count']} "
                 f"snapshots={plan['snapshots']['count']} "
                 f"admissions={plan['admissions']['count']}"),
        basis="safe derived-state repair: labels from links, snapshots from catalog, "
              "orphan admissions removed",
    )
    result.update({"applied": True, "txn_id": txn_id,
                   "lines": _format_lines(plan, False, True, txn_id)})
    return result

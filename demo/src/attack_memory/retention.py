"""Incident-level retention: classification, dry-run report, archive and pruning.

The report never mutates data. Apply archives expired incidents into monthly gzip
segments and writes a bounded tombstone ledger (incident summaries, plus per-event
tombstones only for events still referenced by active links/chains/candidates/proposals).
"""
from __future__ import annotations

import csv
import datetime as dt
import gzip
import hashlib
import json
import shutil
from collections import defaultdict
from pathlib import Path

from . import candidates as candidate_store
from . import storage

DEFAULT_VARIANT_DAYS = 180
DEFAULT_CANDIDATE_DAYS = 150
DEFAULT_UNCLASSIFIED_DAYS = 90


def _date(value: str | None) -> dt.date | None:
    if not value:
        return None
    try:
        return dt.date.fromisoformat(value[:10])
    except ValueError:
        return None


def _age_days(last_event_at: str | None, as_of: dt.date) -> int | None:
    day = _date(last_event_at)
    return (as_of - day).days if day else None


def _size_info(data_dir: Path | str | None) -> dict:
    if data_dir is None:
        return {"bytes": {"raw": 0, "links": 0, "chains": 0, "candidates": 0,
                          "active": 0, "archive": 0, "data": 0},
                "files": {"active": 0, "archive": 0, "data": 0},
                "archive_runs": 0}
    root = Path(data_dir)
    active_paths = [root / "raw_logs.csv", root / "event_pattern_links.csv",
                    root / "incident_chains.json", root / "case_candidates.json"]
    sizes = {name: (path.stat().st_size if path.exists() else 0)
             for name, path in zip(("raw", "links", "chains", "candidates"), active_paths)}
    archive_files = [path for path in (root / "archive").rglob("*") if path.is_file()]
    data_files = [path for path in root.rglob("*") if path.is_file()]
    sizes["active"] = sum(sizes.values())
    sizes["archive"] = sum(path.stat().st_size for path in archive_files)
    sizes["data"] = sum(path.stat().st_size for path in data_files)
    return {"bytes": sizes,
            "files": {"active": sum(1 for path in active_paths if path.exists()),
                      "archive": len(archive_files), "data": len(data_files)},
            "archive_runs": len(load_tombstones(root)["runs"])}


def build_report(patterns: list[dict], logs: list[dict[str, str]],
                 links: list[dict[str, str]], candidates: list[dict] | None = None,
                 proposals: list[dict] | None = None,
                 chains: list[dict] | None = None,
                 as_of: dt.date | None = None,
                 variant_days: int = DEFAULT_VARIANT_DAYS,
                 candidate_days: int = DEFAULT_CANDIDATE_DAYS,
                 unclassified_days: int = DEFAULT_UNCLASSIFIED_DAYS,
                 data_dir: Path | str | None = None) -> dict:
    as_of = as_of or dt.date.today()
    latest = storage.latest_link_by_event(links)
    candidate_incidents: dict[str, list[str]] = defaultdict(list)
    candidate_status_by_incident: dict[str, set[str]] = defaultdict(set)
    candidate_by_event: dict[str, str] = {}
    for candidate in candidates or []:
        for incident in candidate.get("incidents") or []:
            incident_id = incident["incident_id"]
            candidate_incidents[incident_id].append(candidate["candidate_id"])
            candidate_status_by_incident[incident_id].add(candidate.get("status") or "provisional")
            for event_id in incident.get("event_ids") or []:
                candidate_by_event[event_id] = incident_id
    by_incident: dict[str, list[dict[str, str]]] = defaultdict(list)
    assigned_events: set[str] = set()
    for row in logs:
        event_id = (row.get("event_id") or "").strip()
        incident = (row.get("incident_id") or "").strip()
        link = latest.get(event_id) or {}
        if not incident and (link.get("link_status") or "") in ("confirmed", "related"):
            incident = (link.get("incident_id") or "").strip()
        if not incident:
            incident = candidate_by_event.get(event_id, "")
        if incident:
            by_incident[incident].append(row)
            assigned_events.add(event_id)
    unassigned = [{"event_id": row.get("event_id"), "batch_id": row.get("batch_id"),
                   "source": row.get("source"), "timestamp": row.get("timestamp")}
                  for row in logs if (row.get("event_id") or "") not in assigned_events]
    proposal_incidents: dict[str, list[str]] = defaultdict(list)
    event_incident = {row.get("event_id"): (row.get("incident_id") or "").strip()
                      for row in logs}
    for proposal in proposals or []:
        if proposal.get("status") not in ("candidate", "ready"):
            continue
        for event_id in proposal.get("supporting_event_ids") or []:
            incident = event_incident.get(event_id) or (latest.get(event_id) or {}).get("incident_id") or ""
            if incident:
                proposal_incidents[incident].append(proposal.get("proposal_id") or "?")
    annotated_incidents = {chain.get("incident_id") for chain in chains or []
                           if any(event.get("stage_kind") == "annotated"
                                  for event in chain.get("events") or [])}
    report_incidents = []
    class_counts: dict[str, int] = defaultdict(int)
    for incident, rows in sorted(by_incident.items()):
        incident_links = [link for link in latest.values()
                          if (link.get("incident_id") or "") == incident]
        statuses = [link.get("link_status") for link in incident_links]
        case_id = next((link.get("case_id") for link in incident_links
                        if link.get("link_status") == "confirmed"), "")
        if not case_id:
            case_id = next((link.get("case_id") for link in incident_links
                            if link.get("link_status") == "related"), "")
        if "fixture" in statuses:
            classification = "fixture"
        elif "confirmed" in statuses:
            classification = "anchor"
        elif incident in candidate_incidents:
            classification = "candidate"
        elif "related" in statuses:
            classification = "variant"
        else:
            classification = "unclassified"
        ttl = {"variant": variant_days, "candidate": candidate_days,
               "unclassified": unclassified_days}.get(classification)
        last_event_at = max((row.get("timestamp") or "" for row in rows), default="")
        age = _age_days(last_event_at, as_of)
        protected = []
        if classification in ("anchor", "fixture"):
            protected.append(classification)
        statuses_for_candidate = candidate_status_by_incident.get(incident, set())
        if statuses_for_candidate & {"promotable", "promoted", "merged"}:
            protected.append("candidate:" + ",".join(sorted(set(candidate_incidents[incident]))))
        if incident in proposal_incidents:
            protected.append("proposal:" + ",".join(sorted(set(proposal_incidents[incident]))))
        if incident in annotated_incidents:
            protected.append("annotated-chain")
        expired = bool(ttl is not None and not protected and age is not None and age >= ttl)
        class_counts[classification] += 1
        report_incidents.append({
            "incident_id": incident,
            "classification": classification,
            "case_id": case_id,
            "events": len(rows),
            "last_event_at": last_event_at,
            "age_days": age,
            "ttl_days": ttl,
            "candidate_ids": sorted(set(candidate_incidents.get(incident, []))),
            "candidate_statuses": sorted(statuses_for_candidate),
            "protected": protected,
            "expired": expired,
            "event_ids": [row.get("event_id") for row in rows if row.get("event_id")],
        })
    expired = [item for item in report_incidents if item["expired"]]
    protected = [item for item in report_incidents if item["protected"]]
    size_info = _size_info(data_dir)
    return {
        "as_of": as_of.isoformat(),
        "ttl_days": {"variant": variant_days, "candidate": candidate_days,
                     "unclassified": unclassified_days},
        "bytes": size_info["bytes"],
        "files": size_info["files"],
        "archive_runs": size_info["archive_runs"],
        "incidents": len(report_incidents),
        "events": sum(item["events"] for item in report_incidents),
        "raw_events": len(logs),
        "unassigned_events": len(unassigned),
        "unassigned": unassigned,
        "classes": dict(sorted(class_counts.items())),
        "expired_incidents": len(expired),
        "expirable_events": sum(item["events"] for item in expired),
        "protected_incidents": len(protected),
        "expired": expired,
        "protected": [
            {"incident_id": item["incident_id"], "classification": item["classification"],
             "reasons": item["protected"]}
            for item in protected
        ],
        "incidents_detail": report_incidents,
    }


def apply_report(report: dict, data_dir: Path | str | None = None,
                 max_active_bytes: int = 0, archive_max_days: int = 0) -> dict:
    """Archive expired incidents into monthly gzip segments; keep only referenced tombstones."""
    data_dir = Path(data_dir) if data_dir is not None else storage.DATA_DIR
    expired = {item["incident_id"]: dict(item) for item in report.get("expired") or []}
    cap_selected: list[str] = []
    if max_active_bytes and report.get("bytes", {}).get("active", 0) > max_active_bytes:
        projected = max(0, report.get("bytes", {}).get("active", 0)
                        - sum(max(512, (item.get("events") or 1) * 400)
                              for item in expired.values()))
        eligible = [item for item in report.get("incidents_detail") or []
                    if item["incident_id"] not in expired and not item.get("protected")
                    and item.get("classification") not in ("anchor", "fixture")]
        for item in sorted(eligible, key=lambda row: -(row.get("age_days") or 0)):
            expired[item["incident_id"]] = {**item, "cap_selected": True}
            cap_selected.append(item["incident_id"])
            projected -= max(512, (item.get("events") or 1) * 400)
            if projected <= max_active_bytes:
                break
    if not expired:
        pruned = prune_archives(data_dir, archive_max_days) if archive_max_days else {}
        return {"archived_incidents": 0, "archived_events": 0, "archived_links": 0,
                "removed_candidates": 0, "archive_dir": "", "tombstones": 0,
                "incident_summaries": 0, "cap_selected": [], "pruned": pruned,
                "active_bytes": _size_info(data_dir)["bytes"]["active"]}
    event_incident = {event_id: incident
                      for incident, item in expired.items()
                      for event_id in item.get("event_ids") or []}
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    month = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m")
    archive_dir = data_dir / "archive" / month
    archive_dir.mkdir(parents=True, exist_ok=True)

    raw_fields, raw_rows = _read_csv_rows(data_dir / "raw_logs.csv")
    archive_raw = [row for row in raw_rows if row.get("event_id") in event_incident]
    active_raw = [row for row in raw_rows if row.get("event_id") not in event_incident]
    link_fields, link_rows = _read_csv_rows(data_dir / "event_pattern_links.csv")
    archive_links = [row for row in link_rows if row.get("event_id") in event_incident]
    active_links = [row for row in link_rows if row.get("event_id") not in event_incident]
    chain_path = data_dir / "incident_chains.json"
    chain_data = json.loads(chain_path.read_text(encoding="utf-8")) if chain_path.exists() else {"schema_version": 1, "chains": []}
    archive_chains = [chain for chain in chain_data["chains"]
                      if chain.get("incident_id") in expired]
    active_chains = [chain for chain in chain_data["chains"]
                     if chain.get("incident_id") not in expired]
    candidate_path = data_dir / "case_candidates.json"
    candidate_data = json.loads(candidate_path.read_text(encoding="utf-8")) if candidate_path.exists() else {"schema_version": 1, "candidates": []}
    removed_candidates = []
    active_candidates = []
    for candidate in candidate_data["candidates"]:
        kept = [incident for incident in candidate.get("incidents") or []
                if incident.get("incident_id") not in expired]
        if not kept:
            removed_candidates.append(candidate)
            continue
        candidate["incidents"] = kept
        if candidate.get("status") not in ("promoted", "merged"):
            candidate["status"] = candidate_store.candidate_level(len(kept))
        active_candidates.append(candidate)

    _append_gzip_csv(archive_dir / "raw_logs.csv.gz", raw_fields, archive_raw)
    _append_gzip_csv(archive_dir / "event_pattern_links.csv.gz", link_fields, archive_links)
    _append_gzip_json(archive_dir / "incident_chains.json.gz", "chains", archive_chains)
    _append_gzip_json(archive_dir / "case_candidates.json.gz", "candidates", removed_candidates)
    manifest = {
        "run_id": stamp,
        "archived_at": _now_iso(),
        "incidents": sorted(expired),
        "events": len(archive_raw),
        "links": len(archive_links),
        "chains": len(archive_chains),
        "candidates": len(removed_candidates),
        "ttl_days": report.get("ttl_days") or {},
        "cap_selected": cap_selected,
    }
    manifest_path = archive_dir / f"manifest-{stamp}.json"
    counter = 1
    while manifest_path.exists():
        counter += 1
        manifest_path = archive_dir / f"manifest-{stamp}-{counter}.json"
    _write_json(manifest_path, manifest)

    _write_csv(data_dir / "raw_logs.csv", raw_fields, active_raw)
    _write_csv(data_dir / "event_pattern_links.csv", link_fields, active_links)
    _write_json(chain_path, {"schema_version": 1, "chains": active_chains})
    _write_json(candidate_path, {"schema_version": 1, "candidates": active_candidates})

    raw_by_id = {row.get("event_id"): row for row in archive_raw}
    summaries = _incident_summaries(expired, raw_by_id)
    referenced = _referenced_event_ids(data_dir, active_links, active_chains, active_candidates)
    referenced_tombstones = []
    for event_id, incident in sorted(event_incident.items()):
        if event_id not in referenced:
            continue
        item = expired[incident]
        row = raw_by_id.get(event_id) or {}
        referenced_tombstones.append({
            "event_id": event_id,
            "incident_id": incident,
            "case_id": item.get("case_id") or "",
            "reason": f"{item.get('classification')} age={item.get('age_days')}d ttl={item.get('ttl_days')}d",
            "archived_at": _now_iso(),
            "content_sha256": hashlib.sha256((row.get("content") or "").encode("utf-8")).hexdigest(),
        })
    tombstone_path = data_dir / "retention_tombstones.json"
    tombstone_data = _upgrade_tombstones(load_tombstones(data_dir))
    tombstone_data["runs"].append({
        "run_id": stamp,
        "archived_at": _now_iso(),
        "archive_dir": str(archive_dir.relative_to(data_dir)).replace("\\", "/"),
        "archive_layout": "monthly",
        "incident_summaries": summaries,
        "events": len(archive_raw),
        "links": len(archive_links),
        "chains": len(archive_chains),
        "candidates": [item["candidate_id"] for item in removed_candidates],
        "referenced_tombstones": referenced_tombstones,
        "cap_selected": cap_selected,
    })
    _write_json(tombstone_path, tombstone_data)
    pruned = prune_archives(data_dir, archive_max_days) if archive_max_days else {}
    return {"archived_incidents": len(expired), "archived_events": len(archive_raw),
            "archived_links": len(archive_links), "removed_candidates": len(removed_candidates),
            "archive_dir": str(archive_dir.relative_to(data_dir)).replace("\\", "/"),
            "tombstones": len(referenced_tombstones), "incident_summaries": len(summaries),
            "cap_selected": cap_selected, "pruned": pruned,
            "active_bytes": _size_info(data_dir)["bytes"]["active"]}


def load_tombstones(data_dir: Path | str | None = None) -> dict:
    data_dir = Path(data_dir) if data_dir is not None else storage.DATA_DIR
    path = data_dir / "retention_tombstones.json"
    if not path.exists():
        return {"schema_version": 2, "runs": []}
    return json.loads(path.read_text(encoding="utf-8-sig"))


def compact_archives(data_dir: Path | str | None = None) -> dict:
    """Move legacy per-run archives into the monthly gzip layout."""
    data_dir = Path(data_dir) if data_dir is not None else storage.DATA_DIR
    data = _upgrade_tombstones(load_tombstones(data_dir))
    moved = 0
    for run in data.get("runs") or []:
        if run.get("archive_layout") == "monthly":
            continue
        old_dir = data_dir / (run.get("archive_dir") or "")
        if not old_dir.exists():
            continue
        month = (run.get("archived_at") or "")[:7] or "unknown"
        monthly = data_dir / "archive" / month
        monthly.mkdir(parents=True, exist_ok=True)
        raw_fields, raw_rows = _read_csv_rows(old_dir / "raw_logs.csv")
        link_fields, link_rows = _read_csv_rows(old_dir / "event_pattern_links.csv")
        _append_gzip_csv(monthly / "raw_logs.csv.gz", raw_fields, raw_rows)
        _append_gzip_csv(monthly / "event_pattern_links.csv.gz", link_fields, link_rows)
        chain_path = old_dir / "incident_chains.json"
        if chain_path.exists():
            chains = json.loads(chain_path.read_text(encoding="utf-8")).get("chains") or []
            _append_gzip_json(monthly / "incident_chains.json.gz", "chains", chains)
        candidate_path = old_dir / "case_candidates.json"
        if candidate_path.exists():
            candidates = json.loads(candidate_path.read_text(encoding="utf-8")).get("candidates") or []
            _append_gzip_json(monthly / "case_candidates.json.gz", "candidates", candidates)
        old_manifest = old_dir / "manifest.json"
        manifest = json.loads(old_manifest.read_text(encoding="utf-8")) if old_manifest.exists() else {}
        manifest["run_id"] = run.get("run_id")
        _write_json(monthly / f"manifest-{run.get('run_id')}.json", manifest)
        shutil.rmtree(old_dir)
        run["archive_dir"] = str(monthly.relative_to(data_dir)).replace("\\", "/")
        run["archive_layout"] = "monthly"
        moved += 1
    if moved:
        _write_json(data_dir / "retention_tombstones.json", data)
    return {"moved_runs": moved}


def migrate_tombstones(data_dir: Path | str | None = None) -> dict:
    data_dir = Path(data_dir) if data_dir is not None else storage.DATA_DIR
    data = load_tombstones(data_dir)
    upgraded = _upgrade_tombstones(data)
    if upgraded != data:
        _write_json(data_dir / "retention_tombstones.json", upgraded)
    return upgraded


def prune_archives(data_dir: Path | str | None = None, max_days: int = 0,
                   as_of: dt.date | None = None) -> dict:
    if max_days <= 0:
        return {}
    data_dir = Path(data_dir) if data_dir is not None else storage.DATA_DIR
    as_of = as_of or dt.date.today()
    data = _upgrade_tombstones(load_tombstones(data_dir))
    groups: dict[str, list[dict]] = defaultdict(list)
    for run in data.get("runs") or []:
        groups[run.get("archive_dir") or ""].append(run)
    removed_runs = []
    removed_bytes = 0
    for archive_dir, runs in groups.items():
        dates = [_date(run.get("archived_at")) for run in runs]
        if not archive_dir or not dates or any(day is None for day in dates):
            continue
        if not all((as_of - day).days > max_days for day in dates):
            continue
        path = (data_dir / archive_dir).resolve()
        archive_root = (data_dir / "archive").resolve()
        if not path.is_relative_to(archive_root):
            continue
        if path.exists():
            removed_bytes += sum(item.stat().st_size for item in path.rglob("*") if item.is_file())
            shutil.rmtree(path)
        removed_runs.extend(runs)
    if removed_runs:
        keep = [run for run in data["runs"] if run not in removed_runs]
        data["runs"] = keep
        _write_json(data_dir / "retention_tombstones.json", data)
    return {"removed_runs": len(removed_runs), "removed_bytes": removed_bytes}


def audit_archives(data_dir: Path | str | None = None) -> list[str]:
    data_dir = Path(data_dir) if data_dir is not None else storage.DATA_DIR
    data = _upgrade_tombstones(load_tombstones(data_dir))
    problems = []
    seen_events = set()
    for run in data.get("runs") or []:
        archive = data_dir / (run.get("archive_dir") or "")
        if not run.get("archive_dir") or not archive.exists():
            problems.append(f"{run.get('run_id')}: archive directory is missing")
            continue
        layout = run.get("archive_layout") or "per-run"
        if layout == "monthly":
            names = ("raw_logs.csv.gz", "event_pattern_links.csv.gz",
                     "incident_chains.json.gz", "case_candidates.json.gz",
                     f"manifest-{run.get('run_id')}.json")
        else:
            names = ("raw_logs.csv", "event_pattern_links.csv", "incident_chains.json",
                     "case_candidates.json", "manifest.json")
        for name in names:
            if not (archive / name).exists():
                problems.append(f"{run.get('run_id')}: archive file {name} is missing")
        if not run.get("incident_summaries") and not run.get("tombstones"):
            problems.append(f"{run.get('run_id')}: no incident summaries")
        for tombstone in run.get("referenced_tombstones") or []:
            event_id = tombstone.get("event_id")
            if event_id in seen_events:
                problems.append(f"{run.get('run_id')}: duplicate tombstone for {event_id}")
            seen_events.add(event_id)
    return problems


def _upgrade_tombstones(data: dict) -> dict:
    if data.get("schema_version", 1) >= 2:
        return data
    for run in data.get("runs") or []:
        groups: dict[str, list[dict]] = defaultdict(list)
        for tombstone in run.get("tombstones") or []:
            groups[tombstone.get("incident_id") or "?"].append(tombstone)
        summaries = []
        for incident, tombstones in sorted(groups.items()):
            hashes = [item.get("content_sha256") or "" for item in tombstones]
            timestamps = [item.get("timestamp") or "" for item in tombstones]
            summaries.append({
                "incident_id": incident,
                "classification": (tombstones[0].get("reason") or "unknown").split()[0],
                "events": len(tombstones),
                "first_event_at": min(timestamps) if timestamps else "",
                "last_event_at": max(timestamps) if timestamps else "",
                "content_hash_root": hashlib.sha256("".join(sorted(hashes)).encode("utf-8")).hexdigest(),
            })
        run["incident_summaries"] = summaries
        run["referenced_tombstones"] = []
        run["archive_layout"] = run.get("archive_layout") or "per-run"
        run.pop("tombstones", None)
    data["schema_version"] = 2
    return data


def _incident_summaries(expired: dict[str, dict], raw_by_id: dict[str, dict]) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for event_id, row in raw_by_id.items():
        incident = next((incident for incident, item in expired.items()
                         if event_id in (item.get("event_ids") or [])), "")
        if incident:
            groups[incident].append(row)
    summaries = []
    for incident, rows in sorted(groups.items()):
        item = expired[incident]
        hashes = [hashlib.sha256((row.get("content") or "").encode("utf-8")).hexdigest()
                  for row in rows]
        timestamps = [row.get("timestamp") or "" for row in rows]
        summaries.append({
            "incident_id": incident,
            "classification": item.get("classification") or "unknown",
            "events": len(rows),
            "first_event_at": min(timestamps) if timestamps else "",
            "last_event_at": max(timestamps) if timestamps else "",
            "content_hash_root": hashlib.sha256("".join(sorted(hashes)).encode("utf-8")).hexdigest(),
            "case_id": item.get("case_id") or "",
        })
    return summaries


def _referenced_event_ids(data_dir: Path, active_links: list[dict], active_chains: list[dict],
                          active_candidates: list[dict]) -> set[str]:
    referenced = {row.get("event_id") for row in active_links if row.get("event_id")}
    for chain in active_chains:
        referenced.update(event.get("event_id") for event in chain.get("events") or []
                          if event.get("event_id"))
    for candidate in active_candidates:
        for incident in candidate.get("incidents") or []:
            referenced.update(incident.get("event_ids") or [])
    proposal_path = data_dir / "pattern_proposals.json"
    if proposal_path.exists():
        proposals = json.loads(proposal_path.read_text(encoding="utf-8-sig"))
        for proposal in proposals.get("proposals") or []:
            referenced.update(proposal.get("supporting_event_ids") or [])
    return referenced


def _read_csv_rows(path: Path) -> tuple[list[str], list[dict]]:
    if not path.exists():
        return [], []
    with path.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def _read_gzip_csv(path: Path) -> tuple[list[str], list[dict]]:
    if not path.exists():
        return [], []
    with gzip.open(path, "rt", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader.fieldnames or []), list(reader)


def _append_gzip_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _, existing = _read_gzip_csv(path)
    with gzip.open(path, "wt", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in existing + rows:
            writer.writerow(row)


def _append_gzip_json(path: Path, key: str, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = []
    if path.exists():
        with gzip.open(path, "rt", encoding="utf-8-sig") as handle:
            payload = json.load(handle)
        existing = payload.get(key) or []
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        json.dump({"schema_version": 1, key: existing + items}, handle,
                  ensure_ascii=False, indent=2)
        handle.write("\n")


def _write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def format_lines(report: dict) -> list[str]:
    lines = [
        f"as_of={report['as_of']}  incidents={report['incidents']}  "
        f"events={report['events']}/{report['raw_events']}  "
        f"unassigned={report['unassigned_events']}",
        "classes: " + ", ".join(f"{key}={value}" for key, value in report["classes"].items()),
        f"expired: {report['expired_incidents']} incident(s), "
        f"{report['expirable_events']} event(s)  |  protected: {report['protected_incidents']}",
        "ttl: " + ", ".join(f"{key}={value}d" for key, value in report["ttl_days"].items()),
        f"bytes: active={report['bytes']['active']} archive={report['bytes']['archive']} "
        f"data={report['bytes']['data']}  files: active={report['files']['active']} "
        f"archive={report['files']['archive']} data={report['files']['data']}  "
        f"archive_runs={report['archive_runs']}",
    ]
    for item in report["expired"]:
        lines.append(f"  EXPIRE {item['incident_id']}  {item['classification']}  "
                     f"events={item['events']} age={item['age_days']}d ttl={item['ttl_days']}d")
    for item in report["protected"]:
        lines.append(f"  KEEP   {item['incident_id']}  {item['classification']}  "
                     f"{', '.join(item['reasons'])}")
    for item in report["unassigned"]:
        lines.append(f"  UNASSIGNED {item['event_id']}  batch={item.get('batch_id') or '-'}  "
                     f"source={item.get('source') or '-'}")
    return lines

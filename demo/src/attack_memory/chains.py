"""Incident chains: ordered observations with stages, independent of a case.

A chain records every event of an incident in time order. An event may be covered by
a case step, a family step, an explicit annotation, or remain unclassified. This is
the Phase 3 layer that lets "behavior outside the pattern" be named without inventing
a case first.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

from . import families, signatures, storage

CHAINS_PATH = storage.DATA_DIR / "incident_chains.json"
STAGE_KINDS = ("case_step", "family_step", "annotated", "unclassified")


def _empty() -> dict:
    return {"schema_version": 1, "chains": []}


def load_chains(path: Path | str | None = None) -> dict:
    target = Path(path) if path is not None else CHAINS_PATH
    if not target.exists():
        return _empty()
    data = json.loads(target.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("chains"), list):
        raise ValueError(f"{target}: chain store must contain a chains list")
    return data


def save_chains(data: dict, path: Path | str | None = None) -> None:
    target = Path(path) if path is not None else CHAINS_PATH
    storage.atomic_write_json(target, data)


def _step_lookup(patterns: list[dict], family_data: dict) -> dict[tuple[str, str], dict]:
    lookup = {}
    for pattern in patterns:
        for step in pattern["steps"]:
            lookup[(pattern["case_id"], step["step_id"])] = {
                "kind": "case_step", "order": int(step.get("order", 99)),
                "label": step.get("label", step["step_id"]),
            }
        for step in families.family_steps(family_data, pattern.get("family_id")):
            lookup[(pattern["case_id"], step.get("step_id"))] = {
                "kind": "family_step", "order": int(step.get("order", 99)),
                "label": step.get("label", step.get("step_id")),
            }
    return lookup


def build_chains(patterns: list[dict], logs: list[dict[str, str]],
                 links: list[dict[str, str]], path: Path | str | None = None) -> dict:
    family_data = families.load_families()
    steps = _step_lookup(patterns, family_data)
    latest = storage.latest_link_by_event(links)
    previous = {chain["incident_id"]: chain for chain in load_chains(path)["chains"]}
    grouped: dict[str, list[dict[str, str]]] = {}
    case_by_incident: dict[str, str] = {}
    for row in logs:
        event_id = (row.get("event_id") or "").strip()
        incident = (row.get("incident_id") or "").strip()
        link = latest.get(event_id)
        if not incident and link and (link.get("link_status") or "") in ("confirmed", "related"):
            incident = (link.get("incident_id") or "").strip()
        if not incident:
            continue
        grouped.setdefault(incident, []).append(row)
        if link and link.get("case_id"):
            case_by_incident.setdefault(incident, link["case_id"])
    chains = []
    for incident, rows in grouped.items():
        rows = sorted(rows, key=lambda row: (row.get("timestamp") or "", row.get("event_id") or ""))
        old_events = {event.get("event_id"): event
                      for event in (previous.get(incident) or {}).get("events") or []}
        chain_events = []
        for row in rows:
            event_id = row.get("event_id") or ""
            old = old_events.get(event_id)
            if old and old.get("stage_kind") == "annotated":
                chain_events.append(copy.deepcopy(old))
                continue
            link = latest.get(event_id)
            stage = None
            if link:
                key = ((link.get("case_id") or ""), (link.get("step_id") or ""))
                stage = steps.get(key)
            if stage is None:
                chain_events.append({
                    "event_id": event_id, "timestamp": row.get("timestamp") or "",
                    "source": row.get("source") or "", "stage": "unknown",
                    "stage_kind": "unclassified", "label": "unclassified",
                    "stage_order": 99, "stage_basis": "",
                })
            else:
                chain_events.append({
                    "event_id": event_id, "timestamp": row.get("timestamp") or "",
                    "source": row.get("source") or "", "stage": link.get("step_id"),
                    "stage_kind": stage["kind"], "label": stage["label"],
                    "stage_order": stage["order"], "stage_basis": "",
                })
        chains.append({"incident_id": incident, "case_id": case_by_incident.get(incident, ""),
                       "events": chain_events, "updated_at": _now_iso()})
    chains.sort(key=lambda chain: chain["incident_id"])
    data = {"schema_version": 1, "chains": chains}
    save_chains(data, path)
    return data


def review_stage(incident_id: str, event_id: str, stage: str, label: str, basis: str,
                 order: int | None = None, path: Path | str | None = None) -> dict:
    data = load_chains(path)
    chain = next((item for item in data["chains"] if item["incident_id"] == incident_id), None)
    if chain is None:
        raise ValueError(f"unknown incident chain: {incident_id}")
    event = next((item for item in chain["events"] if item["event_id"] == event_id), None)
    if event is None:
        raise ValueError(f"{event_id} is not in chain {incident_id}")
    if not stage.strip():
        raise ValueError("stage must not be empty")
    if not basis.strip():
        raise ValueError("stage basis must not be empty")
    event.update({
        "stage": stage.strip(), "stage_kind": "annotated",
        "label": label.strip() or stage.strip(),
        "stage_order": int(order) if order is not None else event.get("stage_order", 99),
        "stage_basis": basis.strip(), "reviewed_at": _now_iso(),
    })
    chain["updated_at"] = _now_iso()
    save_chains(data, path)
    return copy.deepcopy(chain)


def summarize_chain(chain: dict, logs: list[dict[str, str]]) -> dict:
    rows = {row.get("event_id"): row for row in logs}
    sequence = []
    segments = []
    current = []
    for event in chain["events"]:
        stage = event.get("stage") or "unknown"
        sequence.append(stage)
        if event.get("stage_kind") == "unclassified":
            current.append(event)
        elif current:
            segments.append(current)
            current = []
    if current:
        segments.append(current)
    suggestions = []
    for index, segment in enumerate(segments, start=1):
        events = [rows.get(event["event_id"]) for event in segment
                  if event.get("event_id") in rows]
        contents = [row.get("content") or "" for row in events if row]
        sources = [row.get("source") or "" for row in events if row]
        features = signatures.extract_features("", contents, sources, chain.get("case_id") or "")
        suggestions.append({
            "segment": index,
            "event_ids": [event["event_id"] for event in segment],
            "actions": features["actions"],
            "suggested_label": " / ".join(features["actions"]) or "unclassified",
        })
    return {"incident_id": chain["incident_id"], "sequence": sequence,
            "unexplained_segments": len(segments), "suggestions": suggestions}


def audit_chains(patterns: list[dict], logs: list[dict[str, str]],
                 path: Path | str | None = None) -> list[str]:
    problems: list[str] = []
    data = load_chains(path)
    event_ids = {row.get("event_id") for row in logs}
    pattern_by_case = {pattern["case_id"]: pattern for pattern in patterns}
    seen_incidents = set()
    for chain in data["chains"]:
        incident = chain.get("incident_id")
        if not incident or incident in seen_incidents:
            problems.append(f"chain: duplicate or missing incident_id {incident!r}")
            continue
        seen_incidents.add(incident)
        seen_events = set()
        for event in chain.get("events") or []:
            event_id = event.get("event_id")
            if event_id in seen_events:
                problems.append(f"{incident}: duplicate event {event_id!r}")
            seen_events.add(event_id)
            if event_id not in event_ids:
                problems.append(f"{incident}: unknown event {event_id!r}")
            kind = event.get("stage_kind")
            if kind not in STAGE_KINDS:
                problems.append(f"{incident}/{event_id}: unsupported stage_kind {kind!r}")
            if kind == "annotated" and not event.get("stage_basis"):
                problems.append(f"{incident}/{event_id}: annotated stage has no basis")
            if kind in ("case_step", "family_step"):
                pattern = pattern_by_case.get(chain.get("case_id"))
                if pattern is None:
                    problems.append(f"{incident}/{event_id}: stage has no case")
                elif kind == "case_step" and event.get("stage") not in {
                        step["step_id"] for step in pattern["steps"]}:
                    problems.append(f"{incident}/{event_id}: unknown case step {event.get('stage')!r}")
    return problems


def _now_iso() -> str:
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

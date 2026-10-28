"""Rule-based action retrieval with a derived action -> pattern reverse index."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

TIER_RANK = {"strong": 3, "medium": 2, "weak": 1, "keyword_only": 0}
FAR_FUTURE = datetime.max.replace(tzinfo=timezone.utc)


def build_action_index(patterns: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build the action library: one authoritative definition per action_id.

    A shared action_id must mean the same detection rule everywhere. Otherwise the
    per-action rule union would let a pattern match rows its own regex rejects.
    """
    index: dict[str, dict[str, Any]] = {}
    for pattern in patterns:
        for step_no, step in enumerate(pattern["steps"]):
            action_id = step["action_id"]
            regex = step["action_regex"]
            entry = index.get(action_id)
            if entry is None:
                index[action_id] = {
                    "regex": re.compile(regex),
                    "source": regex,
                    "generic": bool(step.get("generic", False)),
                    "refs": [{"case_id": pattern["case_id"], "step_no": step_no}],
                }
                continue
            if entry["source"] != regex:
                raise ValueError(
                    f"Action {action_id} has conflicting action_regex across patterns "
                    f"({entry['source']!r} vs {regex!r}); give the variant its own action_id"
                )
            if entry["generic"] != bool(step.get("generic", False)):
                raise ValueError(f"Action {action_id} has conflicting generic flags across patterns")
            entry["refs"].append({"case_id": pattern["case_id"], "step_no": step_no})
    return index


def extract_log_actions(logs: list[dict[str, str]], action_index: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Match each unique action ID at most once per row and retain event/source provenance."""
    output: list[dict[str, Any]] = []
    for log in logs:
        content = log.get("content") or ""
        for action_id, entry in action_index.items():
            if not entry["regex"].search(content):
                continue
            output.append({
                "action_id": action_id,
                "event_id": log.get("event_id") or log.get("log_id", ""),
                "source": (log.get("source") or "").casefold(),
                "timestamp": log.get("timestamp", ""),
                "generic": entry["generic"],
                "log": log,
            })
    return output


def _event_time(row: dict[str, str]) -> datetime | None:
    raw = (row.get("timestamp") or "").strip()
    if not raw:
        return None
    try:
        value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    except ValueError:
        return None


def _sort_key(action: dict[str, Any]) -> tuple[bool, datetime, str, str]:
    """Chronological order, unparseable timestamps last, stable on event/action ID."""
    value = _event_time(action["log"])
    return (value is None, value or FAR_FUTURE, action["event_id"], action["action_id"])


def _expected_sources(step: dict[str, Any]) -> set[str]:
    return {str(source).casefold() for source in step.get("expected_sources") or []}


def _source_fits(source: str, expected: set[str]) -> bool:
    return not expected or "any" in expected or source in expected


def _keyword_score(pattern: dict[str, Any], text: str) -> tuple[int, list[str]]:
    lowered = text.casefold()
    score = 0
    details: list[str] = []
    seen: set[str] = set()
    retrieval = pattern.get("retrieval", {})
    for key in retrieval.get("keywords", []):
        token = str(key).casefold().strip()
        if token and token in lowered and token not in seen:
            score += 3
            seen.add(token)
            details.append(f"keyword +3: {key}")
    # Literal token match only: logs almost never contain a technique ID, so this
    # is a weak lexical hint, not ATT&CK inference.
    for technique in pattern.get("mitre", []):
        token = str(technique).casefold()
        if token and re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", lowered) and token not in seen:
            score += 2
            seen.add(token)
            details.append(f"MITRE token +2: {technique}")
    for probe in retrieval.get("pattern_probes", []):
        if re.search(probe, text, re.IGNORECASE):
            score += 4
            details.append(f"probe +4: {probe}")
    return score, details


def _align_sequence(pattern: dict[str, Any], actions: list[dict[str, Any]]) -> list[tuple[int, dict[str, Any]]]:
    """LCS-style temporal alignment used for shape/tier: one action supports at most one step."""
    steps = pattern["steps"]
    n, m = len(steps), len(actions)
    dp = [[0] * (m + 1) for _ in range(n + 1)]

    def compatible(step: dict[str, Any], action: dict[str, Any]) -> bool:
        if step["action_id"] != action["action_id"]:
            return False
        return _source_fits(action["source"], _expected_sources(step))

    for i in range(1, n + 1):
        for j in range(1, m + 1):
            best = max(dp[i - 1][j], dp[i][j - 1])
            if compatible(steps[i - 1], actions[j - 1]):
                best = max(best, dp[i - 1][j - 1] + 1)
            dp[i][j] = best

    aligned: list[tuple[int, dict[str, Any]]] = []
    i, j = n, m
    while i and j:
        if compatible(steps[i - 1], actions[j - 1]) and dp[i][j] == dp[i - 1][j - 1] + 1:
            aligned.append((i - 1, actions[j - 1]))
            i -= 1
            j -= 1
        elif dp[i - 1][j] >= dp[i][j - 1]:
            i -= 1
        else:
            j -= 1
    aligned.reverse()
    return aligned


def _shape(positions: list[int], total: int) -> str:
    if not positions:
        return "none"
    contiguous = all(b == a + 1 for a, b in zip(positions, positions[1:]))
    if contiguous and positions[0] == 0 and positions[-1] == total - 1:
        return "complete"
    if contiguous and positions[0] == 0:
        return "prefix"
    if contiguous:
        return "middle"
    return "gap"


def match_pattern(pattern: dict[str, Any], logs: list[dict[str, str]],
                  all_actions: list[dict[str, Any]], query_text: str | None = None) -> dict[str, Any]:
    steps = pattern["steps"]
    step_by_action = {step["action_id"]: pos for pos, step in enumerate(steps)}
    case_actions = [action for action in all_actions if action["action_id"] in step_by_action]
    case_actions.sort(key=_sort_key)

    # Detection is source-aware but not alignment-dependent: every hit stays visible.
    detected_by_step: dict[int, list[dict[str, Any]]] = {}
    mismatches: list[dict[str, Any]] = []
    hit_positions: set[int] = set()
    for action in case_actions:
        pos = step_by_action[action["action_id"]]
        hit_positions.add(pos)
        step = steps[pos]
        expected = _expected_sources(step)
        if _source_fits(action["source"], expected):
            detected_by_step.setdefault(pos, []).append(action)
        else:
            mismatches.append({"step_id": step["step_id"], "event_id": action["event_id"],
                               "observed_source": action["source"],
                               "expected_sources": sorted(expected)})
    for detections in detected_by_step.values():
        detections.sort(key=_sort_key)

    aligned = _align_sequence(pattern, case_actions)
    positions = [pos for pos, _ in aligned]
    aligned_event_by_position = {pos: action["event_id"] for pos, action in aligned}
    total = len(steps)
    required_positions = [pos for pos, step in enumerate(steps) if step.get("required", True)]
    required_set = set(required_positions)
    required_rank = {pos: rank for rank, pos in enumerate(required_positions)}
    required_total = len(required_positions)
    matched_count = len(positions)
    matched_required = sum(1 for pos in positions if pos in required_set)
    required_aligned = [required_rank[pos] for pos in positions if pos in required_set]
    # Shape and tier describe the required skeleton; an optional step may be absent.
    shape = _shape(required_aligned, required_total)
    matched_non_generic = sum(1 for pos in positions
                              if pos in required_set and not bool(steps[pos].get("generic", False)))
    if required_aligned:
        first_rank, last_rank = required_aligned[0], required_aligned[-1]
        before_steps = [steps[required_positions[rank]]["step_id"] for rank in range(first_rank)]
        gap_steps = [steps[required_positions[rank]]["step_id"]
                     for rank in range(first_rank, last_rank + 1) if rank not in required_aligned]
    else:
        before_steps, gap_steps = [], []

    unaligned: list[dict[str, Any]] = []
    for pos in sorted(detected_by_step):
        step = steps[pos]
        for action in detected_by_step[pos]:
            if aligned_event_by_position.get(pos) == action["event_id"]:
                continue
            reason = (f"extra_detection_for_{step['step_id']}"
                      if pos in aligned_event_by_position else "out_of_order")
            unaligned.append({"event_id": action["event_id"], "step_id": step["step_id"],
                              "action_id": action["action_id"], "source": action["source"],
                              "timestamp": action["timestamp"], "reason": reason})

    def _order(subset: dict[int, list[dict[str, Any]]]) -> tuple[bool, bool]:
        first_times: list[datetime] = []
        for pos in sorted(subset):
            values = [time for action in subset[pos]
                      if (time := _event_time(action["log"])) is not None]
            if values:
                first_times.append(min(values))
        assessable = bool(subset) and len(first_times) == len(subset)
        ok = all(a <= b for a, b in zip(first_times, first_times[1:])) if assessable else False
        return assessable, ok

    required_detected = {pos: detections for pos, detections in detected_by_step.items()
                         if pos in required_set}
    # strong is judged on the required skeleton; an optional step must not demote it.
    order_assessable, order_ok = _order(required_detected)

    source_ok_steps = len(detected_by_step)
    source_ratio = source_ok_steps / len(hit_positions) if hit_positions else 0.0
    text = query_text if query_text is not None else "\n".join(log.get("content") or "" for log in logs)
    kw_score, kw_details = _keyword_score(pattern, text)

    if matched_required == required_total and required_total and order_assessable and order_ok and matched_non_generic:
        tier = "strong"
    elif matched_non_generic >= 2:
        tier = "medium"
    elif matched_count or mismatches or unaligned:
        tier = "weak"
    elif kw_score:
        tier = "keyword_only"
    else:
        tier = "none"

    # A weak result is not one thing: a prefix may be an early-stage attack, while a
    # tail/generic/mismatch result is usually just one shared detector. Say which.
    if tier == "weak":
        if not detected_by_step:
            weak_kind = "mismatch_only" if mismatches else "unaligned_only"
        elif matched_non_generic == 0:
            weak_kind = "generic_only"
        elif not before_steps:
            weak_kind = "prefix"
        else:
            weak_kind = "tail"
    else:
        weak_kind = None

    evidence = [{
        "step_id": steps[pos]["step_id"],
        "action_id": steps[pos]["action_id"],
        "label": steps[pos].get("label", steps[pos]["action_id"]),
        "generic": bool(steps[pos].get("generic", False)),
        "required": bool(steps[pos].get("required", True)),
        "event_ids": [action["event_id"] for action in detected_by_step[pos]],
        "sources": sorted({action["source"] for action in detected_by_step[pos]}),
        "aligned_event_id": aligned_event_by_position.get(pos),
        "detections": [{"event_id": action["event_id"], "source": action["source"],
                        "timestamp": action["timestamp"]} for action in detected_by_step[pos]],
    } for pos in sorted(detected_by_step)]

    next_pos = positions[-1] + 1 if positions and positions[-1] + 1 < total else None
    return {
        "case_id": pattern["case_id"], "name": pattern["name"], "summary": pattern["summary"],
        "version": pattern.get("version", 1),
        "family_id": pattern.get("family_id", "unclassified"),
        "review_status": pattern.get("review_status"),
        "matched_steps": matched_count, "matched_required_steps": matched_required,
        "required_steps": required_total, "detected_steps": len(hit_positions),
        "total_steps": total,
        "shape": shape,
        "tier": tier, "weak_kind": weak_kind,
        "order_ok": order_ok, "order_assessable": order_assessable,
        "source_fit_ratio": round(source_ratio, 3),
        "evidence": evidence, "source_mismatches": mismatches,
        "unaligned_detections": unaligned,
        "keyword_score": kw_score, "keyword_details": kw_details,
        "mitre": pattern.get("mitre", []),
        "unobserved_steps": [steps[i]["step_id"] for i in range(total) if i not in hit_positions],
        "unobserved_required_steps": [steps[i]["step_id"] for i in required_positions
                                      if i not in hit_positions],
        "unobserved_optional_steps": [steps[i]["step_id"] for i in range(total)
                                      if i not in required_set and i not in hit_positions],
        "before_steps": before_steps,
        "gap_steps": gap_steps,
        "predict_next": ({"step_id": steps[next_pos]["step_id"],
                          "action_id": steps[next_pos]["action_id"],
                          "label": steps[next_pos].get("label", steps[next_pos]["action_id"]),
                          "expected_sources": steps[next_pos].get("expected_sources", [])}
                         if next_pos is not None else None),
        "matched_non_generic_steps": matched_non_generic,
        "pattern_scope": pattern.get("pattern_scope", {}),
        "negative_and_unknown_evidence": pattern.get("negative_and_unknown_evidence", {}),
        "provenance": pattern.get("provenance", {}),
    }


def retrieve(patterns: list[dict[str, Any]], logs: list[dict[str, str]],
             action_index: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    action_index = action_index or build_action_index(patterns)
    all_actions = extract_log_actions(logs, action_index)
    text = "\n".join(log.get("content") or "" for log in logs)
    indexed_cases = {ref["case_id"] for action in all_actions
                     for ref in action_index[action["action_id"]]["refs"]}
    results: list[dict[str, Any]] = []
    for pattern in patterns:
        # The action reverse index narrows action-derived candidates. Lexical fallback remains global.
        if pattern["case_id"] not in indexed_cases and not _keyword_score(pattern, text)[0]:
            continue
        result = match_pattern(pattern, logs, all_actions, text)
        if result["tier"] != "none":
            results.append(result)

    results.sort(key=lambda r: (-TIER_RANK[r["tier"]], -r["matched_non_generic_steps"],
                                -r["matched_steps"], -r["source_fit_ratio"],
                                -r["keyword_score"], r["case_id"]))
    return results

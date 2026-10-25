"""Rule-based action retrieval with a derived action -> pattern reverse index."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

TIER_RANK = {"strong": 3, "medium": 2, "weak": 1, "keyword_only": 0}


def build_action_index(patterns: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Build a runtime index; do not persist a second, potentially stale copy in JSON."""
    index: dict[str, dict[str, Any]] = {}
    for pattern in patterns:
        for step_no, step in enumerate(pattern["steps"]):
            aid = step["action_id"]
            entry = index.setdefault(aid, {"rules": [], "refs": [], "generic_values": set()})
            entry["refs"].append({"case_id": pattern["case_id"], "step_no": step_no})
            entry["generic_values"].add(bool(step.get("generic", False)))
            regex = step["action_regex"]
            if all(rule.pattern != regex for rule in entry["rules"]):
                entry["rules"].append(re.compile(regex))
    for aid, entry in index.items():
        if len(entry["generic_values"]) > 1:
            raise ValueError(f"Action {aid} has conflicting generic flags across patterns")
        entry["generic"] = next(iter(entry["generic_values"]))
        del entry["generic_values"]
    return index


def extract_log_actions(logs: list[dict[str, str]], action_index: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Match each unique action ID at most once per row and retain event/source provenance."""
    output: list[dict[str, Any]] = []
    for log in logs:
        content = log.get("content", "")
        for aid, entry in action_index.items():
            if any(regex.search(content) for regex in entry["rules"]):
                output.append({
                    "action_id": aid,
                    "event_id": log.get("event_id") or log.get("log_id", ""),
                    "source": log.get("source", "").casefold(),
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
    for technique in pattern.get("mitre", []):
        token = str(technique).casefold()
        if token and re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", lowered) and token not in seen:
            score += 2
            seen.add(token)
            details.append(f"MITRE +2: {technique}")
    for probe in retrieval.get("pattern_probes", []):
        if re.search(probe, text, re.IGNORECASE):
            score += 4
            details.append(f"probe +4: {probe}")
    return score, details


def _align_sequence(pattern: dict[str, Any], actions: list[dict[str, Any]]) -> list[tuple[int, dict[str, Any]]]:
    """LCS-style temporal alignment: one observed action detection supports at most one step."""
    steps = pattern["steps"]
    n, m = len(steps), len(actions)
    dp = [[0] * (m + 1) for _ in range(n + 1)]

    def compatible(step: dict[str, Any], action: dict[str, Any]) -> bool:
        if step["action_id"] != action["action_id"]:
            return False
        expected = {str(s).casefold() for s in step.get("expected_sources", [])}
        return not expected or action["source"] in expected or "any" in expected

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
                  all_actions: list[dict[str, Any]]) -> dict[str, Any]:
    step_ids = {step["action_id"] for step in pattern["steps"]}
    case_actions = [action for action in all_actions if action["action_id"] in step_ids]
    case_actions.sort(key=lambda a: (_event_time(a["log"]) is None,
                                    _event_time(a["log"]) or datetime.max.replace(tzinfo=timezone.utc),
                                    a["event_id"], a["action_id"]))

    # Track source-compatible and source-mismatched evidence per step.
    detected_by_step: dict[int, list[dict[str, Any]]] = {}
    mismatches: list[dict[str, Any]] = []
    signal_positions: set[int] = set()
    for i, step in enumerate(pattern["steps"]):
        expected = {str(s).casefold() for s in step.get("expected_sources", [])}
        for action in case_actions:
            if action["action_id"] != step["action_id"]:
                continue
            signal_positions.add(i)
            if not expected or action["source"] in expected or "any" in expected:
                detected_by_step.setdefault(i, []).append(action)
            else:
                mismatches.append({"step_id": step["step_id"], "event_id": action["event_id"],
                                   "observed_source": action["source"],
                                   "expected_sources": sorted(expected)})

    aligned = _align_sequence(pattern, case_actions)
    positions = [pos for pos, _ in aligned]
    total = len(pattern["steps"])
    matched_count = len(positions)
    shape = _shape(positions, total)
    matched_non_generic = sum(not bool(pattern["steps"][pos].get("generic", False)) for pos, _ in aligned)

    present_positions = sorted(detected_by_step)
    first_times: list[datetime] = []
    for pos in present_positions:
        values = [t for a in detected_by_step[pos] if (t := _event_time(a["log"])) is not None]
        if values:
            first_times.append(min(values))
    order_assessable = len(present_positions) > 0 and len(first_times) == len(present_positions)
    order_ok = all(a <= b for a, b in zip(first_times, first_times[1:])) if order_assessable else False

    source_ok_steps = sum(bool(detected_by_step.get(pos)) for pos in signal_positions)
    source_ratio = source_ok_steps / len(signal_positions) if signal_positions else 0.0
    query_text = "\n".join(log.get("content", "") for log in logs)
    kw_score, kw_details = _keyword_score(pattern, query_text)

    if matched_count == total and total and order_assessable and order_ok and matched_non_generic:
        tier = "strong"
    elif matched_non_generic >= 2:
        tier = "medium"
    elif matched_count or mismatches:
        tier = "weak"
    elif kw_score:
        tier = "keyword_only"
    else:
        tier = "none"

    evidence_by_position: dict[int, list[str]] = {}
    for pos, action in aligned:
        evidence_by_position.setdefault(pos, []).append(action["event_id"])
    evidence = [{"step_id": pattern["steps"][pos]["step_id"],
                 "action_id": pattern["steps"][pos]["action_id"],
                 "label": pattern["steps"][pos].get("label", pattern["steps"][pos]["action_id"]),
                 "event_ids": evidence_by_position.get(pos, []),
                 "sources": sorted({action["source"] for p, action in aligned if p == pos}),
                 "generic": bool(pattern["steps"][pos].get("generic", False))}
                for pos in positions]
    longest_run = run = 0
    previous = None
    for pos in positions:
        run = run + 1 if previous is not None and pos == previous + 1 else 1
        longest_run = max(longest_run, run)
        previous = pos
    next_pos = positions[-1] + 1 if positions and positions[-1] + 1 < total else None
    return {
        "case_id": pattern["case_id"], "name": pattern["name"], "summary": pattern["summary"],
        "matched_steps": matched_count, "total_steps": total, "shape": shape,
        "longest_run": longest_run,
        "tier": tier, "order_ok": order_ok, "order_assessable": order_assessable,
        "source_fit_ratio": round(source_ratio, 3),
        "evidence": evidence, "source_mismatches": mismatches,
        "keyword_score": kw_score, "keyword_details": kw_details,
        "mitre": pattern.get("mitre", []),
        "unobserved_steps": [pattern["steps"][i]["step_id"] for i in range(total) if i not in positions],
        "before_steps": [pattern["steps"][i]["step_id"] for i in range(positions[0])] if positions else [],
        "gap_steps": [pattern["steps"][i]["step_id"] for i in range(positions[0], positions[-1] + 1)
                      if i not in positions] if positions else [],
        "predict_next": ({"step_id": pattern["steps"][next_pos]["step_id"],
                          "action_id": pattern["steps"][next_pos]["action_id"],
                          "label": pattern["steps"][next_pos].get("label", pattern["steps"][next_pos]["action_id"]),
                          "expected_sources": pattern["steps"][next_pos].get("expected_sources", [])}
                         if next_pos is not None else None),
        "matched_non_generic_steps": matched_non_generic,
    }


def retrieve(patterns: list[dict[str, Any]], logs: list[dict[str, str]],
             action_index: dict[str, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    action_index = action_index or build_action_index(patterns)
    all_actions = extract_log_actions(logs, action_index)
    case_ids = {ref["case_id"] for action in all_actions
                for ref in action_index[action["action_id"]]["refs"]}
    results: list[dict[str, Any]] = []
    for pattern in patterns:
        # The action reverse index narrows action-derived candidates. Lexical fallback remains global.
        if pattern["case_id"] not in case_ids:
            lexical = _keyword_score(pattern, "\n".join(log.get("content", "") for log in logs))[0]
            if not lexical:
                continue
        result = match_pattern(pattern, logs, all_actions)
        if result["tier"] != "none":
            results.append(result)

    results.sort(key=lambda r: (-TIER_RANK[r["tier"]], -r["matched_non_generic_steps"],
                                -r["matched_steps"], -r["source_fit_ratio"],
                                -r["keyword_score"], r["case_id"]))
    return results

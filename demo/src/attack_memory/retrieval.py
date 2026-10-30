"""Rule-based action retrieval with a derived action -> pattern reverse index."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from .storage import source_fits

TIER_RANK = {"strong": 3, "medium": 2, "weak": 1, "keyword_only": 0}
FAR_FUTURE = datetime.max.replace(tzinfo=timezone.utc)


_LITERAL_SPECIAL = ".^$*+?{}[]()|"
_FLAG_OK = "ims"


def _has_top_level_alternation(source: str) -> bool:
    """True when ``|`` joins whole-pattern branches, which invalidates a prefix literal."""
    depth = 0
    in_class = False
    index = 0
    while index < len(source):
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if in_class:
            if char == "]":
                in_class = False
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            return True
        index += 1
    return False


def _leading_literal(source: str) -> str | None:
    """Return the mandatory case-folded literal prefix of a regex, or None.

    Only a leading run of plain or escaped literal characters after an optional inline
    flag group and ``^`` is accepted, and only when the pattern has no top-level
    alternation. Anything more complex returns None, so the value can only *narrow* the
    regex scan: every real match of the regex contains it.
    """
    if _has_top_level_alternation(source):
        return None
    index = 0
    if source.startswith("(?"):
        close = source.find(")", 2)
        if close == -1:
            return None
        flags = source[2:close]
        if not flags or any(char not in _FLAG_OK for char in flags):
            return None
        index = close + 1
    if index < len(source) and source[index] == "^":
        index += 1
    chars: list[str] = []
    while index < len(source):
        char = source[index]
        if char == "\\":
            if index + 1 >= len(source):
                return None
            escaped = source[index + 1]
            if escaped in "dDsSwWbBAZzG0123456789":
                break
            literal = {"n": "\n", "r": "\r", "t": "\t"}.get(escaped, escaped)
            if index + 2 < len(source) and source[index + 2] in "*+?{":
                break
            chars.append(literal)
            index += 2
            continue
        if char in _LITERAL_SPECIAL:
            break
        if index + 1 < len(source) and source[index + 1] in "*+?{":
            break
        chars.append(char)
        index += 1
    literal = "".join(chars)
    return literal.casefold() if len(literal) >= 3 else None


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
                    "literal": _leading_literal(regex),
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
    """Match each unique action ID at most once per row and retain event/source provenance.

    Detection depends only on the row content, so the regex scan is bound once per call and
    repeated content is matched once then reused. When an action regex has a provable
    mandatory literal prefix, that cheap substring check runs before the regex; it can only
    reject rows the regex would reject. The returned rows and their order are identical to
    a plain per-row scan.
    """
    searchers = [(action_id, entry["regex"].search, entry["generic"], entry.get("literal"))
                 for action_id, entry in action_index.items()]
    fold_content = any(literal for _, _, _, literal in searchers)
    hits_by_content: dict[str, list[tuple[str, bool]]] = {}
    output: list[dict[str, Any]] = []
    for log in logs:
        content = log.get("content") or ""
        hits = hits_by_content.get(content)
        if hits is None:
            folded = content.casefold() if fold_content else ""
            hits = [(action_id, generic) for action_id, search, generic, literal in searchers
                    if (literal is None or literal in folded) and search(content)]
            hits_by_content[content] = hits
        for action_id, generic in hits:
            output.append({
                "action_id": action_id,
                "event_id": log.get("event_id") or log.get("log_id", ""),
                "source": (log.get("source") or "").casefold(),
                "timestamp": log.get("timestamp", ""),
                "generic": generic,
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


@lru_cache(maxsize=None)
def _mitre_boundary_pattern(token: str) -> re.Pattern[str]:
    """Compiled literal-token matcher, cached per technique ID."""
    return re.compile(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])")


@lru_cache(maxsize=None)
def _probe_pattern(probe: str) -> re.Pattern[str]:
    """Compiled retrieval probe, cached so a repeated CLI run recompiles nothing."""
    return re.compile(probe, re.IGNORECASE)


@lru_cache(maxsize=None)
def _probe_prefix(probe: str) -> str | None:
    """Mandatory literal prefix of a probe, cached; used as a cheap negative filter."""
    return _leading_literal(probe)


def _keyword_score(pattern: dict[str, Any], text: str,
                   lowered: str | None = None) -> tuple[int, list[str]]:
    lowered = text.casefold() if lowered is None else lowered
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
        if (token and token not in seen and token in lowered
                and _mitre_boundary_pattern(token).search(lowered)):
            score += 2
            seen.add(token)
            details.append(f"MITRE token +2: {technique}")
    probes = retrieval.get("pattern_probes", [])
    # re.IGNORECASE is the expensive scan here; a mandatory literal prefix rejects most
    # text before it. Only taken when both sides are ASCII, where case folding and the
    # regex engine's ignore-case matching are exactly equivalent.
    ascii_text = text.isascii() if probes else False
    for probe in probes:
        if ascii_text:
            prefix = _probe_prefix(probe)
            if prefix is not None and prefix not in lowered:
                continue
        if _probe_pattern(probe).search(text):
            score += 4
            details.append(f"probe +4: {probe}")
    return score, details


def _align_sequence(pattern: dict[str, Any], actions: list[dict[str, Any]]) -> list[tuple[int, dict[str, Any]]]:
    """LCS-style temporal alignment used for shape/tier: one action supports at most one step."""
    steps = pattern["steps"]
    expected_by_pos = [_expected_sources(step) for step in steps]
    n, m = len(steps), len(actions)
    dp = [[0] * (m + 1) for _ in range(n + 1)]

    def compatible(step_pos: int, action: dict[str, Any]) -> bool:
        if steps[step_pos]["action_id"] != action["action_id"]:
            return False
        return source_fits(action["source"], expected_by_pos[step_pos])

    for i in range(1, n + 1):
        for j in range(1, m + 1):
            best = max(dp[i - 1][j], dp[i][j - 1])
            if compatible(i - 1, actions[j - 1]):
                best = max(best, dp[i - 1][j - 1] + 1)
            dp[i][j] = best

    aligned: list[tuple[int, dict[str, Any]]] = []
    i, j = n, m
    while i and j:
        if compatible(i - 1, actions[j - 1]) and dp[i][j] == dp[i - 1][j - 1] + 1:
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
                  all_actions: list[dict[str, Any]], query_text: str | None = None,
                  actions_by_id: dict[str, list[dict[str, Any]]] | None = None,
                  keyword: tuple[int, list[str]] | None = None) -> dict[str, Any]:
    """Score one pattern against a batch of rows.

    ``actions_by_id`` and ``keyword`` are optional pre-computed inputs used by
    :func:`retrieve` so it can build the reverse index and the lexical score once per
    batch instead of once per pattern. Callers that pass neither get exactly the same
    result as before (the old full-scan code path is kept below).
    """
    steps = pattern["steps"]
    step_by_action = {step["action_id"]: pos for pos, step in enumerate(steps)}
    if actions_by_id is None:
        case_actions = [action for action in all_actions if action["action_id"] in step_by_action]
    else:
        case_actions = [action for action_id in step_by_action
                        for action in actions_by_id.get(action_id, ())]
    case_actions.sort(key=_sort_key)

    # Detection is source-aware but not alignment-dependent: every hit stays visible.
    detected_by_step: dict[int, list[dict[str, Any]]] = {}
    mismatches: list[dict[str, Any]] = []
    hit_positions: set[int] = set()
    expected_by_pos = [_expected_sources(step) for step in steps]
    for action in case_actions:
        pos = step_by_action[action["action_id"]]
        hit_positions.add(pos)
        step = steps[pos]
        expected = expected_by_pos[pos]
        if source_fits(action["source"], expected):
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
    if keyword is not None:
        kw_score, kw_details = keyword
    else:
        text = (query_text if query_text is not None
                else "\n".join(log.get("content") or "" for log in logs))
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
    # Build the reverse index and the lower-cased corpus once per retrieval, not once per
    # pattern: both are pure functions of the batch and the catalog.
    actions_by_id: dict[str, list[dict[str, Any]]] = {}
    for action in all_actions:
        actions_by_id.setdefault(action["action_id"], []).append(action)
    indexed_cases: set[str] = set()
    for action_id in actions_by_id:
        indexed_cases.update(ref["case_id"] for ref in action_index[action_id]["refs"])
    lowered_text = text.casefold()
    results: list[dict[str, Any]] = []
    for pattern in patterns:
        if pattern.get("status") == "retired":
            continue
        keyword = _keyword_score(pattern, text, lowered_text)
        # The action reverse index narrows action-derived candidates. Lexical fallback remains global.
        if pattern["case_id"] not in indexed_cases and not keyword[0]:
            continue
        result = match_pattern(pattern, logs, all_actions, text,
                               actions_by_id=actions_by_id, keyword=keyword)
        if result["tier"] != "none":
            results.append(result)

    results.sort(key=lambda r: (-TIER_RANK[r["tier"]], -r["matched_non_generic_steps"],
                                -r["matched_steps"], -r["source_fit_ratio"],
                                -r["keyword_score"], r["case_id"]))
    return results

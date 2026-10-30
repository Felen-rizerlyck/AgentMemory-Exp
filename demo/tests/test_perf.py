"""Opt-in retrieval benchmark (skipped unless RUN_PERF is set).

Run from demo/:
    $env:RUN_PERF=1; python -m unittest tests.test_perf -v

Prints the measured baseline and enforces deliberately loose thresholds: the point is to
detect a regression, not to benchmark the host.
"""
from __future__ import annotations

import os
import pathlib
import random
import re
import sys
import time
import unittest

DEMO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(DEMO_ROOT / "src"))

from attack_memory.retrieval import TIER_RANK, build_action_index, extract_log_actions  # noqa: E402
from attack_memory.retrieval import match_pattern, retrieve  # noqa: E402
from attack_memory.storage import RAW_LOGS_PATH, load_patterns, read_csv  # noqa: E402
from run_demo import partition_logs  # noqa: E402

RUN_PERF = bool(os.environ.get("RUN_PERF"))
FIVE_K_THRESHOLD_SECONDS = 2.0
TWENTY_K_THRESHOLD_SECONDS = 8.0
REAL_CORPUS_THRESHOLD_SECONDS = 2.0


def best_seconds(callable_, repeats=3):
    callable_()  # warm up imports, regex caches and the content-hit cache
    samples = []
    for _ in range(repeats):
        started = time.perf_counter()
        callable_()
        samples.append(time.perf_counter() - started)
    return min(samples)


def old_style_extract(logs, action_index):
    """The pre-index scan: one regex search per row × action, no prefilter or cache."""
    output = []
    for log in logs:
        content = log.get("content") or ""
        for action_id, entry in action_index.items():
            if not entry["regex"].search(content):
                continue
            output.append({"action_id": action_id,
                           "event_id": log.get("event_id") or log.get("log_id", ""),
                           "source": (log.get("source") or "").casefold(),
                           "timestamp": log.get("timestamp", ""),
                           "generic": entry["generic"], "log": log})
    return output


def old_style_keyword_score(pattern, text):
    """The pre-optimization lexical scorer (no compiled-regex cache or prefix filter)."""
    lowered = text.casefold()
    score = 0
    details = []
    seen = set()
    retrieval = pattern.get("retrieval", {})
    for key in retrieval.get("keywords", []):
        token = str(key).casefold().strip()
        if token and token in lowered and token not in seen:
            score += 3
            seen.add(token)
            details.append(f"keyword +3: {key}")
    for technique in pattern.get("mitre", []):
        token = str(technique).casefold()
        if token and token not in seen and re.search(
                r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", lowered):
            score += 2
            seen.add(token)
            details.append(f"MITRE token +2: {technique}")
    for probe in retrieval.get("pattern_probes", []):
        if re.search(probe, text, re.IGNORECASE):
            score += 4
            details.append(f"probe +4: {probe}")
    return score, details


def old_style_retrieve(patterns, logs, action_index):
    """The pre-optimization retrieve pipeline, used as the before/after baseline."""
    actions = old_style_extract(logs, action_index)
    text = "\n".join(log.get("content") or "" for log in logs)
    indexed_cases = {ref["case_id"] for action in actions
                     for ref in action_index[action["action_id"]]["refs"]}
    results = []
    for pattern in patterns:
        if pattern.get("status") == "retired":
            continue
        if pattern["case_id"] not in indexed_cases and not old_style_keyword_score(pattern, text)[0]:
            continue
        result = match_pattern(pattern, logs, actions, text)
        if result["tier"] != "none":
            results.append(result)
    results.sort(key=lambda r: (-TIER_RANK[r["tier"]], -r["matched_non_generic_steps"],
                                -r["matched_steps"], -r["source_fit_ratio"],
                                -r["keyword_score"], r["case_id"]))
    return results


def synthetic_corpus(rows=5000, pattern_count=100, seed=42):
    """Rules with a mandatory literal, so both realistic paths (regex / prefilter) run."""
    rng = random.Random(seed)
    patterns = []
    for index in range(pattern_count):
        steps = [{
            "step_id": f"S{step + 1}", "order": step + 1,
            "action_id": f"act-{index:03d}-{step}", "label": f"step {index}/{step}",
            "action_regex": rf"(?i)tok{index:03d}_{step}",
            "expected_sources": ["hids"], "required": True,
        } for step in range(3)]
        patterns.append({
            "case_id": f"CASE-{100 + index:03d}", "name": f"synthetic case {index}",
            "summary": "perf fixture", "mitre": ["T0000"], "family_id": "web-exploit",
            "version": 1, "steps": steps,
            "retrieval": {"keywords": [f"tok{index:03d}_"],
                          "pattern_probes": [rf"tok{index:03d}_\d"]},
        })
    logs = []
    for number in range(rows):
        index = rng.randrange(pattern_count)
        step = rng.randrange(3)
        logs.append({"event_id": f"E{number}", "incident_id": f"INC-{number // 10}",
                     "timestamp": f"2026-01-01T00:{number % 60:02d}:00Z", "source": "hids",
                     "content": f"noise {number} tok{index:03d}_{step} padded content"})
    return patterns, logs, build_action_index(patterns)


@unittest.skipUnless(RUN_PERF, "set RUN_PERF=1 to run the retrieval benchmark")
class RetrievalPerfTests(unittest.TestCase):
    def test_real_corpus_565_rows_old_vs_new(self):
        patterns = load_patterns()["attack_patterns"]
        logs = read_csv(RAW_LOGS_PATH)
        index = build_action_index(patterns)
        scopes = [rows for _, _, rows in partition_logs(logs)]
        old_seconds = best_seconds(
            lambda: [old_style_retrieve(patterns, rows, index) for rows in scopes], repeats=3)
        new_seconds = best_seconds(
            lambda: [retrieve(patterns, rows, index) for rows in scopes], repeats=3)
        print(f"\nPERF real corpus: logs={len(logs)} patterns={len(patterns)} "
              f"actions={len(index)} scopes={len(scopes)}")
        print(f"  retrieve(all scopes): old={old_seconds * 1000:.1f}ms "
              f"new={new_seconds * 1000:.1f}ms speedup={old_seconds / new_seconds:.2f}x "
              f"threshold={REAL_CORPUS_THRESHOLD_SECONDS:.1f}s")
        self.assertEqual([result["case_id"] for result in retrieve(patterns, logs, index)],
                         [result["case_id"] for result in old_style_retrieve(patterns, logs, index)])
        self.assertLess(new_seconds, old_seconds)
        self.assertLess(new_seconds, REAL_CORPUS_THRESHOLD_SECONDS)

    def test_5k_rows_100_patterns_old_vs_new(self):
        patterns, logs, index = synthetic_corpus(rows=5000, pattern_count=100)
        old_seconds = best_seconds(
            lambda: old_style_retrieve(patterns, logs, index), repeats=2)
        new_seconds = best_seconds(
            lambda: retrieve(patterns, logs, index), repeats=2)
        self.assertEqual([result["case_id"] for result in old_style_retrieve(patterns, logs, index)],
                         [result["case_id"] for result in retrieve(patterns, logs, index)])
        self.assertEqual(len(retrieve(patterns, logs, index)), 100)
        print(f"\nPERF 5k rows/100 patterns/300 actions:")
        print(f"  retrieve: old={old_seconds:.3f}s new={new_seconds:.3f}s "
              f"speedup={old_seconds / new_seconds:.2f}x "
              f"threshold={FIVE_K_THRESHOLD_SECONDS:.1f}s")
        self.assertLess(new_seconds, FIVE_K_THRESHOLD_SECONDS)

    def test_5k_extract_log_actions_constant_factor(self):
        patterns, logs, index = synthetic_corpus(rows=5000, pattern_count=100)
        old_seconds = best_seconds(lambda: old_style_extract(logs, index), repeats=2)
        new_seconds = best_seconds(lambda: extract_log_actions(logs, index), repeats=2)
        old_hits = [(action["action_id"], action["event_id"])
                    for action in old_style_extract(logs, index)]
        new_hits = [(action["action_id"], action["event_id"])
                    for action in extract_log_actions(logs, index)]
        self.assertEqual(new_hits, old_hits)
        print(f"\nPERF 5k extract_log_actions: old={old_seconds:.3f}s new={new_seconds:.3f}s "
              f"speedup={old_seconds / new_seconds:.2f}x hits={len(new_hits)}")
        self.assertLess(new_seconds, old_seconds)

    def test_20k_rows_trend(self):
        patterns, logs, index = synthetic_corpus(rows=20000, pattern_count=100, seed=7)
        new_seconds = best_seconds(lambda: retrieve(patterns, logs, index), repeats=1)
        print(f"\nPERF 20k rows/100 patterns/300 actions: retrieve={new_seconds:.2f}s "
              f"threshold={TWENTY_K_THRESHOLD_SECONDS:.1f}s")
        self.assertEqual(len(retrieve(patterns, logs, index)), 100)
        self.assertLess(new_seconds, TWENTY_K_THRESHOLD_SECONDS)


if __name__ == "__main__":
    unittest.main()

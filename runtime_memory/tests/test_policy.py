"""Tests for retry policy defaults and validation."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory.policy import Policy, default_policy
from runtime_memory.timeutil import parse_iso, utcnow


class PolicyTests(unittest.TestCase):
    def test_defaults_validate(self):
        self.assertEqual(Policy(default_policy()).validate(), [])

    def test_unknown_class_falls_back(self):
        policy = Policy(default_policy())
        self.assertEqual(policy.key_level("does-not-exist"), "scope")
        self.assertTrue(policy.retryable("does-not-exist"))

    def test_transport_errors_are_scope_level_and_retryable(self):
        policy = Policy(default_policy())
        self.assertEqual(policy.key_level("unreachable"), "scope")
        self.assertTrue(policy.retryable("unreachable"))

    def test_argument_errors_are_call_level_and_not_retryable(self):
        policy = Policy(default_policy())
        self.assertEqual(policy.key_level("invalid_args"), "call")
        self.assertFalse(policy.retryable("invalid_args"))

    def test_exponential_backoff(self):
        policy = Policy(default_policy())
        now = utcnow()
        first = parse_iso(policy.next_retry_at("timeout", 1, now))
        second = parse_iso(policy.next_retry_at("timeout", 2, now))
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertGreater((second - now).total_seconds(),
                           (first - now).total_seconds())

    def test_non_retryable_has_no_next_retry(self):
        policy = Policy(default_policy())
        self.assertIsNone(policy.next_retry_at("auth", 1, utcnow()))

    def test_retry_record_contains_policy_metadata(self):
        record = Policy(default_policy()).retry_record("unreachable", 1, utcnow())
        self.assertEqual(record["key_level"], "scope")
        self.assertTrue(record["retryable"])
        self.assertEqual(record["max_attempts"], 3)
        self.assertIsNotNone(record["next_retry_at"])

    def test_invalid_policy_is_reported(self):
        data = default_policy()
        data["classes"]["unreachable"]["key_level"] = "bogus"
        problems = Policy(data).validate()
        self.assertTrue(any("key_level" in problem for problem in problems))

    def test_enforce_defaults_to_false(self):
        self.assertFalse(Policy(default_policy()).enforce)


if __name__ == "__main__":
    unittest.main()

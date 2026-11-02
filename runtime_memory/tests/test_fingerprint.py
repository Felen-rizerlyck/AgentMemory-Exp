"""Tests for stable fingerprints and redaction."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory.fingerprint import (args_hash, call_fingerprint, normalize_args,
                                        normalize_target, scope_fingerprint)
from runtime_memory.models import OperationRequest
from runtime_memory.redact import redact


def request(**overrides):
    values = dict(component="mcp", tool="hunt.query", action="search",
                  target="10.7.194.120:22196", args={"q": "dns tunnel"},
                  scope="global", environment_id="lab-a")
    values.update(overrides)
    return OperationRequest(**values)


class FingerprintTests(unittest.TestCase):
    def test_scope_key_ignores_arguments(self):
        left = scope_fingerprint(request(args={"q": "one"}))
        right = scope_fingerprint(request(args={"q": "two"}))
        self.assertEqual(left, right)

    def test_call_key_changes_with_arguments(self):
        left = call_fingerprint(request(args={"q": "one"}))
        right = call_fingerprint(request(args={"q": "two"}))
        self.assertNotEqual(left, right)

    def test_volatile_and_secret_arguments_do_not_split_call_key(self):
        left = call_fingerprint(request(args={"q": "x", "token": "a",
                                              "timestamp": "2026-01-01"}))
        right = call_fingerprint(request(args={"q": "x", "token": "b",
                                               "timestamp": "2026-02-02"}))
        self.assertEqual(left, right)

    def test_normalize_args_drops_volatile_and_redacts_secret(self):
        cleaned = normalize_args({"q": "x", "token": "secret", "nonce": 1,
                                  "nested": {"password": "p", "ok": True}})
        self.assertNotIn("nonce", cleaned)
        self.assertEqual(cleaned["token"], "[REDACTED]")
        self.assertEqual(cleaned["nested"]["password"], "[REDACTED]")

    def test_url_target_keeps_origin_and_first_path_segment(self):
        self.assertEqual(
            normalize_target("http://10.7.194.120:22196/hunt/sse?x=1", "mcp"),
            "http://10.7.194.120:22196/hunt",
        )

    def test_file_target_keeps_parent_directory(self):
        self.assertEqual(normalize_target(r"C:\data\pcap\case.pcap", "file"),
                         "C:/data/pcap")

    def test_pipe_in_component_is_escaped(self):
        key = scope_fingerprint(request(component="mcp|x"))
        self.assertNotIn("mcp|x", key)
        self.assertIn("%7C", key)

    def test_component_and_tool_are_case_insensitive(self):
        lower = scope_fingerprint(request(component="mcp", tool="hunt.query"))
        upper = scope_fingerprint(request(component="MCP", tool="Hunt.Query"))
        self.assertEqual(lower, upper)

    def test_args_hash_is_stable_for_key_order(self):
        self.assertEqual(args_hash({"a": 1, "b": 2}), args_hash({"b": 2, "a": 1}))


class RedactTests(unittest.TestCase):
    def test_bearer_token_is_redacted(self):
        text = redact("Authorization: Bearer abcdef123456")
        self.assertNotIn("abcdef123456", text)
        self.assertIn("[REDACTED]", text)

    def test_password_and_cookie_are_redacted(self):
        text = redact("password=hunter2 cookie: session=abc; other=1")
        self.assertNotIn("hunter2", text)
        self.assertNotIn("session=abc", text)

    def test_message_is_truncated(self):
        text = redact("x" * 800, limit=100)
        self.assertLessEqual(len(text), 101)


if __name__ == "__main__":
    unittest.main()

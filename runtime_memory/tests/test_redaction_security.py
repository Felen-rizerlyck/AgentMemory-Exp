"""Regression tests for secret redaction (T8 findings)."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from runtime_memory.redact import redact, redact_target


class RedactionSecurityTests(unittest.TestCase):
    def test_json_form_secrets_are_redacted(self):
        text = redact('{"password":"s3cr3t","token":"abc123","ok":"keep"}')
        self.assertNotIn("s3cr3t", text)
        self.assertNotIn("abc123", text)
        self.assertIn("keep", text)

    def test_url_userinfo_and_query_secrets_are_redacted(self):
        target = "https://alice:s3cr3t@host.example/path?token=abc123&x=1"
        safe = redact_target(target)
        self.assertNotIn("alice", safe)
        self.assertNotIn("s3cr3t", safe)
        self.assertNotIn("abc123", safe)
        self.assertIn("host.example", safe)
        self.assertIn("x=1", safe)

    def test_plain_key_value_forms_are_redacted(self):
        text = redact("Authorization: Bearer abc password=hunter2 token=xyz")
        self.assertNotIn("abc", text)
        self.assertNotIn("hunter2", text)
        self.assertNotIn("xyz", text)

    def test_safe_target_is_unchanged(self):
        self.assertEqual(redact_target("C:\\data\\case.pcap"), "C:\\data\\case.pcap")


if __name__ == "__main__":
    unittest.main()

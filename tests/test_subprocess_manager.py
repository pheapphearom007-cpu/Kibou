"""
Unit tests for core/subprocess_manager.py
"""

import sys
import unittest
from unittest.mock import patch

from core.subprocess_manager import CommandResult, SubprocessManager


class TestSubprocessManager(unittest.TestCase):
    """Test suite for secure subprocess invocation."""

    def test_missing_binary(self):
        """Verifies missing executables return clean error without throwing unhandled exceptions."""
        result = SubprocessManager.execute(["non_existent_binary_xyz_12345", "--version"])
        self.assertFalse(result.is_ok())
        self.assertEqual(result.returncode, 127)
        self.assertIn("was not found in system PATH", result.stderr)

    def test_empty_arguments(self):
        """Verifies handling of empty or None arguments."""
        result = SubprocessManager.execute([])
        self.assertFalse(result.is_ok())
        self.assertEqual(result.returncode, -1)

    def test_successful_command(self):
        """Test safe execution of standard system utility (python3 --version)."""
        result = SubprocessManager.execute([sys.executable, "--version"], timeout=10)
        self.assertTrue(result.is_ok())
        self.assertEqual(result.returncode, 0)
        self.assertTrue("Python" in result.stdout or "Python" in result.stderr)

    def test_timeout_handling(self):
        """Test timeout enforcement."""
        # Execute python script that sleeps for 5 seconds with a 1 second timeout
        result = SubprocessManager.execute(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            timeout=1
        )
        self.assertFalse(result.is_ok())
        self.assertTrue(result.timed_out)
        self.assertIn("timed out after 1 seconds", result.stderr)

    def test_stderr_capture(self):
        """Test separate stderr capture."""
        result = SubprocessManager.execute(
            [sys.executable, "-c", "import sys; sys.stderr.write('Custom Error Output\\n')"]
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Custom Error Output", result.stderr)


if __name__ == "__main__":
    unittest.main()

"""
Unit tests for core/logger.py
"""

import logging
import unittest
from core.logger import SanitizedFormatter


class TestLogger(unittest.TestCase):
    """Test suite for sanitized logging."""

    def test_secret_redaction(self):
        """Verify that passwords, tokens, and authorization headers are masked."""
        formatter = SanitizedFormatter("%(message)s")

        # Test API Key redaction
        rec1 = logging.LogRecord("test", logging.INFO, "", 0, "Query with api_key='abcdef1234567890'", (), None)
        msg1 = formatter.format(rec1)
        self.assertNotIn("abcdef1234567890", msg1)
        self.assertIn("[REDACTED]", msg1)

        # Test Password redaction
        rec2 = logging.LogRecord("test", logging.INFO, "", 0, "Failed password='supersecretpass'", (), None)
        msg2 = formatter.format(rec2)
        self.assertNotIn("supersecretpass", msg2)
        self.assertIn("[REDACTED]", msg2)

        # Test Bearer token redaction
        rec3 = logging.LogRecord("test", logging.INFO, "", 0, "Sending Authorization: Bearer abcdef1234567890", (), None)
        msg3 = formatter.format(rec3)
        self.assertNotIn("abcdef1234567890", msg3)
        self.assertIn("[REDACTED]", msg3)

    def test_benign_message_unaltered(self):
        """Verify normal operational messages are unaltered."""
        formatter = SanitizedFormatter("%(message)s")
        rec = logging.LogRecord("test", logging.INFO, "", 0, "Discovered port 80 open on 192.168.1.1", (), None)
        self.assertEqual(formatter.format(rec), "Discovered port 80 open on 192.168.1.1")


if __name__ == "__main__":
    unittest.main()

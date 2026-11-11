"""
Unit tests for core/validator.py
"""

import ipaddress
import unittest

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


class TestValidator(unittest.TestCase):
    """Test suite for security sanitization and target validation."""

    def test_contains_dangerous_characters(self):
        """Ensure dangerous shell metacharacters are properly flagged."""
        self.assertTrue(contains_dangerous_characters("192.168.1.1; rm -rf /"))
        self.assertTrue(contains_dangerous_characters("example.com | cat /etc/passwd"))
        self.assertTrue(contains_dangerous_characters("$(whoami)"))
        self.assertTrue(contains_dangerous_characters("`id`"))
        self.assertTrue(contains_dangerous_characters("10.0.0.1 && touch /tmp/test"))
        self.assertTrue(contains_dangerous_characters("test\nnewline"))
        self.assertFalse(contains_dangerous_characters("192.168.1.1"))
        self.assertFalse(contains_dangerous_characters("10.0.0.0/24"))
        self.assertFalse(contains_dangerous_characters("sub-domain.example.com"))

    def test_validate_ipv4_valid(self):
        """Test valid IPv4 address parsing."""
        ip = validate_ipv4("192.168.1.1")
        self.assertEqual(str(ip), "192.168.1.1")
        self.assertIsInstance(ip, ipaddress.IPv4Address)

        ip_loopback = validate_ipv4("127.0.0.1")
        self.assertEqual(str(ip_loopback), "127.0.0.1")

    def test_validate_ipv4_invalid(self):
        """Test invalid IPv4 addresses."""
        with self.assertRaises(ValidationError):
            validate_ipv4("256.100.0.1")
        with self.assertRaises(ValidationError):
            validate_ipv4("192.168.1.")
        with self.assertRaises(ValidationError):
            validate_ipv4("not-an-ip")
        with self.assertRaises(ValidationError):
            validate_ipv4("")
        with self.assertRaises(ValidationError):
            validate_ipv4("192.168.1.1;ls")

    def test_validate_cidr_valid(self):
        """Test valid CIDR network ranges."""
        net = validate_cidr("192.168.1.0/24")
        self.assertEqual(str(net), "192.168.1.0/24")

        # Non-strict CIDR where host bits are masked
        net_host = validate_cidr("10.0.0.55/16")
        self.assertEqual(str(net_host), "10.0.0.0/16")

    def test_validate_cidr_invalid(self):
        """Test malformed CIDR ranges."""
        with self.assertRaises(ValidationError):
            validate_cidr("192.168.1.0/33")
        with self.assertRaises(ValidationError):
            validate_cidr("192.168.1.0/-1")
        with self.assertRaises(ValidationError):
            validate_cidr("invalid/24")

    def test_validate_domain_valid(self):
        """Test valid domain names."""
        self.assertEqual(validate_domain("example.com"), "example.com")
        self.assertEqual(validate_domain("sub.domain.co.uk"), "sub.domain.co.uk")
        self.assertEqual(validate_domain("SCANME.NMAP.ORG"), "scanme.nmap.org")

    def test_validate_domain_invalid(self):
        """Test rejection of invalid or malicious domain inputs."""
        with self.assertRaises(ValidationError):
            validate_domain("-bad-domain.com")
        with self.assertRaises(ValidationError):
            validate_domain("domain..com")
        with self.assertRaises(ValidationError):
            validate_domain("example.com;cat /etc/shadow")
        with self.assertRaises(ValidationError):
            validate_domain("")

    def test_validate_target(self):
        """Test multi-type target validator."""
        t_type, t_val = validate_target("192.168.5.1")
        self.assertEqual(t_type, "ipv4")
        self.assertEqual(t_val, "192.168.5.1")

        t_type, t_val = validate_target("10.0.0.0/24")
        self.assertEqual(t_type, "cidr")
        self.assertEqual(t_val, "10.0.0.0/24")

        t_type, t_val = validate_target("scanme.nmap.org")
        self.assertEqual(t_type, "domain")
        self.assertEqual(t_val, "scanme.nmap.org")

        # Option injection prevention
        with self.assertRaises(ValidationError):
            validate_target("-oX /tmp/pwned")

    def test_validate_port_specification(self):
        """Test port validation."""
        self.assertEqual(validate_port_specification("80"), "80")
        self.assertEqual(validate_port_specification("80,443,8080"), "80,443,8080")
        self.assertEqual(validate_port_specification("1-1024"), "1-1024")
        self.assertEqual(validate_port_specification("all"), "1-65535")

        with self.assertRaises(ValidationError):
            validate_port_specification("0")
        with self.assertRaises(ValidationError):
            validate_port_specification("70000")
        with self.assertRaises(ValidationError):
            validate_port_specification("80-40")  # inverted range
        with self.assertRaises(ValidationError):
            validate_port_specification("http")

    def test_validate_interface_name(self):
        """Test network interface validation."""
        self.assertEqual(validate_interface_name("eth0"), "eth0")
        self.assertEqual(validate_interface_name("wlan0"), "wlan0")
        self.assertEqual(validate_interface_name("ens33"), "ens33")
        with self.assertRaises(ValidationError):
            validate_interface_name("eth0; rm -rf")

    def test_is_private_ip(self):
        """Test private IP detection."""
        self.assertTrue(is_private_ip("192.168.1.1"))
        self.assertTrue(is_private_ip("10.50.0.1"))
        self.assertTrue(is_private_ip("172.16.0.10"))
        self.assertTrue(is_private_ip("127.0.0.1"))
        self.assertFalse(is_private_ip("8.8.8.8"))
        self.assertFalse(is_private_ip("1.1.1.1"))


if __name__ == "__main__":
    unittest.main()

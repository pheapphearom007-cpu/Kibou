"""
Unit tests for core/dependency_manager.py and core/permission_manager.py
"""

import unittest
from unittest.mock import patch

from core.dependency_manager import DependencyManager
from core.permission_manager import PermissionManager


class TestDependenciesAndPermissions(unittest.TestCase):
    """Test suite for system dependencies and privilege verification."""

    def test_os_detection(self):
        """Test OS release detection logic."""
        os_info = DependencyManager.detect_os()
        self.assertIn("distro_id", os_info)
        self.assertIn("distro_name", os_info)
        self.assertIn("is_kali", os_info)
        self.assertIn("is_debian", os_info)
        self.assertIn("is_ubuntu", os_info)

    def test_check_all_dependencies(self):
        """Test registry of system tools."""
        deps = DependencyManager.check_all_dependencies()
        self.assertIn("nmap", deps)
        self.assertIn("curl", deps)
        self.assertIn("whois", deps)
        self.assertIn("dig", deps)
        self.assertIn("traceroute", deps)
        self.assertIn("arp-scan", deps)
        self.assertIn("searchsploit", deps)
        self.assertIn("whatweb", deps)

        # Check structure
        nmap_dep = deps["nmap"]
        self.assertEqual(nmap_dep.binary_name, "nmap")
        self.assertEqual(nmap_dep.package_name_debian, "nmap")

    def test_permission_manager_root_check(self):
        """Test privilege detection and recommendations."""
        summary = PermissionManager.get_system_privilege_summary()
        self.assertIn("is_root", summary)
        self.assertIn("status_label", summary)

        # Test module checks
        has_priv, msg = PermissionManager.check_module_privilege("quick_port_scan")
        self.assertTrue(has_priv)
        self.assertIn("Standard user privileges", msg)

        # Privilege for SYN scan
        with patch.object(PermissionManager, "is_root", return_value=False):
            has_priv_syn, msg_syn = PermissionManager.check_module_privilege("syn_scan")
            self.assertFalse(has_priv_syn)
            self.assertIn("Elevated privileges required", msg_syn)

        with patch.object(PermissionManager, "is_root", return_value=True):
            has_priv_syn, msg_syn = PermissionManager.check_module_privilege("syn_scan")
            self.assertTrue(has_priv_syn)


if __name__ == "__main__":
    unittest.main()

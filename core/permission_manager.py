"""
Privilege and Permission Management for Kibuo.

Checks Linux capabilities, effective user IDs (EUID), and guides the user
regarding least-privilege execution vs. privileged scanning techniques (SYN scans,
OS fingerprinting, raw socket ARP queries).
"""

import os
from typing import Dict, List, Tuple


class PermissionManager:
    """Evaluates and reports process privileges and security requirements."""

    # Modules that strictly or ideally require root privileges for raw socket operations
    ROOT_REQUIRING_MODULES: Dict[str, str] = {
        "arp_discovery": "ARP scanning (arp-scan / netdiscover) requires raw link-layer packet access.",
        "syn_scan": "TCP SYN scanning (nmap -sS) requires raw socket crafting (CAP_NET_RAW).",
        "os_detection": "OS fingerprinting (nmap -O) sends crafted probe packets requiring raw sockets.",
    }

    @staticmethod
    def is_root() -> bool:
        """Check if the current process is running with root/superuser privileges."""
        try:
            return os.geteuid() == 0
        except AttributeError:
            # Non-POSIX systems fallback
            return False

    @classmethod
    def check_module_privilege(cls, module_id: str) -> Tuple[bool, str]:
        """
        Check if the current user possesses sufficient privileges for a specific module.
        
        Returns:
            Tuple of (has_privilege: bool, explanation_or_recommendation: str)
        """
        is_admin = cls.is_root()
        if module_id in cls.ROOT_REQUIRING_MODULES:
            reason = cls.ROOT_REQUIRING_MODULES[module_id]
            if is_admin:
                return True, f"Privilege granted (running as root/euid 0). {reason}"
            else:
                return (
                    False,
                    f"Elevated privileges required: {reason}\n"
                    f"Recommendation: Run Kibuo with 'sudo' or use an unprivileged alternative "
                    f"(e.g., standard TCP connect scan '-sT' or Nmap ping discovery)."
                )
        return True, "Standard user privileges are sufficient for this operation."

    @classmethod
    def get_system_privilege_summary(cls) -> Dict[str, any]:
        """Return a structured summary of execution privileges."""
        is_admin = cls.is_root()
        uid = os.getuid() if hasattr(os, "getuid") else -1
        euid = os.geteuid() if hasattr(os, "geteuid") else -1
        
        return {
            "is_root": is_admin,
            "uid": uid,
            "euid": euid,
            "user": os.environ.get("USER", "unknown"),
            "status_label": "ROOT (Superuser)" if is_admin else "STANDARD (Least-Privilege)",
            "can_syn_scan": is_admin,
            "can_arp_scan": is_admin,
            "can_os_fingerprint": is_admin
        }

"""
Dependency and System Package Management for Kibuo.

Detects Linux distributions (Kali, Debian, Ubuntu), checks system PATH
for security tools, categorizes missing dependencies, provides package mapping,
and offers safe, interactive installation workflows.
"""

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class DependencyInfo:
    """Metadata describing a system dependency."""
    binary_name: str
    package_name_debian: str
    package_name_kali: str
    category: str
    description: str
    associated_modules: List[str]
    is_installed: bool = False
    path: Optional[str] = None


class DependencyManager:
    """Manages system dependencies, tool verification, and package installation."""

    SYSTEM_TOOLS: Dict[str, Dict[str, any]] = {
        "nmap": {
            "debian": "nmap",
            "kali": "nmap",
            "category": "Core Port & Service Scanning",
            "desc": "Network exploration tool and security / port scanner",
            "modules": ["[03] Quick Port Scan", "[04] Full Port Scan", "[05] OS Detection", "[06] SYN Scan", "[07] Vuln Assessment", "[14] Pipeline"]
        },
        "curl": {
            "debian": "curl",
            "kali": "curl",
            "category": "Web Reconnaissance",
            "desc": "Command line tool for transferring data with URLs",
            "modules": ["[11] Web Recon", "[14] Pipeline"]
        },
        "whois": {
            "debian": "whois",
            "kali": "whois",
            "category": "Domain OSINT",
            "desc": "Client for the whois directory service",
            "modules": ["[09] Whois & DNS", "[14] Pipeline"]
        },
        "dig": {
            "debian": "dnsutils",
            "kali": "dnsutils",
            "category": "DNS Reconnaissance",
            "desc": "DNS lookup utility (part of dnsutils/bind9-dnsutils)",
            "modules": ["[09] Whois & DNS", "[14] Pipeline"]
        },
        "traceroute": {
            "debian": "traceroute",
            "kali": "traceroute",
            "category": "Path Analysis",
            "desc": "Print the route packets trace to network host",
            "modules": ["[10] Traceroute", "[14] Pipeline"]
        },
        "arp-scan": {
            "debian": "arp-scan",
            "kali": "arp-scan",
            "category": "Network Discovery",
            "desc": "ARP scanning and fingerprinting tool",
            "modules": ["[01] ARP Discovery"]
        },
        "netdiscover": {
            "debian": "netdiscover",
            "kali": "netdiscover",
            "category": "Network Discovery",
            "desc": "Active/passive address reconnaissance using ARP",
            "modules": ["[01] ARP Discovery"]
        },
        "searchsploit": {
            "debian": "exploitdb",
            "kali": "exploitdb",
            "category": "Exploit Intelligence",
            "desc": "Command-line search tool for Exploit-DB",
            "modules": ["[12] Exploit Lookup", "[14] Pipeline"]
        },
        "whatweb": {
            "debian": "whatweb",
            "kali": "whatweb",
            "category": "Web Reconnaissance",
            "desc": "Next generation web scanner identifying websites technologies",
            "modules": ["[11] Web Recon", "[14] Pipeline"]
        },
        "nikto": {
            "debian": "nikto",
            "kali": "nikto",
            "category": "Web Reconnaissance",
            "desc": "Web server scanner for potential security vulnerabilities",
            "modules": ["[11] Web Recon"]
        },
        "enum4linux": {
            "debian": "enum4linux",
            "kali": "enum4linux",
            "category": "SMB Reconnaissance",
            "desc": "Tool for enumerating information from Windows and Samba systems",
            "modules": ["[13] SMB Discovery"]
        },
        "jq": {
            "debian": "jq",
            "kali": "jq",
            "category": "Utilities",
            "desc": "Command-line JSON processor",
            "modules": ["[08] IP Intelligence", "Formatting"]
        }
    }

    @classmethod
    def detect_os(cls) -> Dict[str, str]:
        """Detect Linux distribution and release details."""
        info = {
            "distro_id": "linux",
            "distro_name": "Linux",
            "version": "Unknown",
            "is_kali": False,
            "is_debian": False,
            "is_ubuntu": False
        }
        
        if os.path.exists("/etc/os-release"):
            try:
                with open("/etc/os-release", "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("ID="):
                            info["distro_id"] = line.split("=", 1)[1].strip('"').lower()
                        elif line.startswith("PRETTY_NAME="):
                            info["distro_name"] = line.split("=", 1)[1].strip('"')
                        elif line.startswith("VERSION_ID="):
                            info["version"] = line.split("=", 1)[1].strip('"')
            except Exception:
                pass
                
        distro_id = info["distro_id"]
        info["is_kali"] = ("kali" in distro_id)
        info["is_debian"] = ("debian" in distro_id)
        info["is_ubuntu"] = ("ubuntu" in distro_id)
        return info

    @classmethod
    def check_all_dependencies(cls) -> Dict[str, DependencyInfo]:
        """Check all registered dependencies and return status dictionary."""
        os_info = cls.detect_os()
        is_kali = os_info["is_kali"]
        results = {}

        for binary, meta in cls.SYSTEM_TOOLS.items():
            path = shutil.which(binary)
            pkg_name = meta["kali"] if is_kali else meta["debian"]
            
            results[binary] = DependencyInfo(
                binary_name=binary,
                package_name_debian=meta["debian"],
                package_name_kali=meta["kali"],
                category=meta["category"],
                description=meta["desc"],
                associated_modules=meta["modules"],
                is_installed=(path is not None),
                path=path
            )

        return results

    @classmethod
    def get_missing_dependencies(cls) -> List[DependencyInfo]:
        """Return list of missing dependencies."""
        all_deps = cls.check_all_dependencies()
        return [dep for dep in all_deps.values() if not dep.is_installed]

    @classmethod
    def get_install_command_for_missing(cls) -> Optional[List[str]]:
        """
        Generate safe apt-get install argument list for missing packages.
        """
        missing = cls.get_missing_dependencies()
        if not missing:
            return None
            
        os_info = cls.detect_os()
        is_kali = os_info["is_kali"]
        
        pkg_set = set()
        for dep in missing:
            pkg = dep.package_name_kali if is_kali else dep.package_name_debian
            pkg_set.add(pkg)
            
        # Standard argument array
        cmd = ["apt-get", "install", "-y"] + sorted(list(pkg_set))
        return cmd

    @classmethod
    def render_dependency_table(cls) -> None:
        """Render a formatted Rich table of all system dependencies and status."""
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.prompt import Confirm

        console = Console()
        deps = cls.check_all_dependencies()
        os_info = cls.detect_os()

        table = Table(title=f"System Dependencies ({os_info['distro_name']})", box=None)
        table.add_column("Binary", style="bold cyan", width=14)
        table.add_column("Package Name", style="yellow", width=14)
        table.add_column("Category", style="white", width=22)
        table.add_column("Status", width=14)
        table.add_column("System Path", style="dim")

        installed_count = 0
        for dep in deps.values():
            if dep.is_installed:
                installed_count += 1
                status_str = "[bold green]INSTALLED[/bold green]"
                path_str = dep.path or "Available"
            else:
                status_str = "[bold red]MISSING[/bold red]"
                path_str = f"apt install {dep.package_name_debian}"

            table.add_row(
                dep.binary_name,
                dep.package_name_kali if os_info["is_kali"] else dep.package_name_debian,
                dep.category,
                status_str,
                path_str
            )

        console.print(table)
        console.print()
        console.print(f"Summary: [bold green]{installed_count}[/bold green] of [bold]{len(deps)}[/bold] dependencies installed.")

    @classmethod
    def run_interactive_installer(cls) -> None:
        """Interactively prompt user to install missing dependencies via apt."""
        from rich.console import Console
        from rich.prompt import Confirm
        from core.permission_manager import PermissionManager

        console = Console()
        cls.render_dependency_table()

        missing = cls.get_missing_dependencies()
        if not missing:
            console.print("\n[bold green]All required and optional system dependencies are installed.[/bold green]")
            return

        os_info = cls.detect_os()
        is_root = PermissionManager.is_root()

        console.print()
        console.print(f"[bold yellow]Found {len(missing)} missing tool(s).[/bold yellow]")
        if not Confirm.ask("Would you like to install the missing packages now via apt?", default=False):
            console.print("[dim]Skipping package installation.[/dim]")
            return

        if not is_root:
            console.print(
                "[bold red]Cannot run apt-get without elevated privileges.[/bold red]\n"
                "Please run: [bold yellow]sudo python3 main.py[/bold yellow] or install manually using:\n"
            )
            cmd = cls.get_install_command_for_missing()
            if cmd:
                console.print(f"  [bold cyan]sudo {' '.join(cmd)}[/bold cyan]\n")
            return

        # Do not run apt update automatically without consent
        if Confirm.ask("Do you want to run 'apt-get update' before installing?", default=True):
            console.print("[dim]Updating package index...[/dim]")
            subprocess.run(["apt-get", "update"], check=False)

        cmd = cls.get_install_command_for_missing()
        if cmd:
            console.print(f"[bold cyan]Running: {' '.join(cmd)}[/bold cyan]")
            subprocess.run(cmd, check=False)
            console.print("[bold green]Installation process finished.[/bold green]")


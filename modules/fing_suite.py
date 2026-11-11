"""
Network Discovery & Monitoring Suite for Kibuo (Fing-Inspired Network Engine).

Coordinates all 10 network discovery, device monitoring, telemetry, and security
modules within a professional interactive submenu. Maintains an in-memory inventory
of discovered devices across submodules for seamless workflows.
"""

from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from core.logger import get_logger
from core.ui import (
    COLOR_BRAND, COLOR_BRAND_ALT, COLOR_INFO, COLOR_SUCCESS,
    COLOR_WARN, clear_screen, display_error, display_info,
    display_section_header, display_warning, pause_prompt, print_banner
)
from modules.device_discovery import run_device_discovery_module
from modules.device_identification import run_device_identification_module
from modules.device_monitor import run_device_monitor_module
from modules.ip_information import run_ip_information_module
from modules.mac_lookup import run_mac_information_module
from modules.network_dashboard import render_network_dashboard
from modules.network_scanner import run_network_scanner_module
from modules.report_export import run_report_export_module
from modules.security_check import run_security_check_module
from modules.speed_test import run_speed_test_module

logger = get_logger("kibuo.fing_suite")
console = Console()

FING_MENU_OPTIONS = [
    ("1", "Device Discovery", "Identify active devices, MACs, vendors & hostnames on subnet"),
    ("2", "Network Scanner", "Scan authorized local subnet with Nmap or socket engine"),
    ("3", "IP Address Information", "Audit local IP, IPv6, gateway, DNS & DHCP configuration"),
    ("4", "MAC Address Information", "IEEE OUI vendor lookup, local MAC search & Layer 2 guide"),
    ("5", "Device Identification", "Multi-factor heuristic categorization with confidence levels"),
    ("6", "Live Device Monitoring", "Track device status changes, online/offline events & last seen"),
    ("7", "Internet Speed Test", "Measure download/upload throughput (Mbps), latency & jitter"),
    ("8", "Network Security Check", "Audit unfamiliar devices, duplicate IPs & risky cleartext services"),
    ("9", "Network Information", "Single-screen consolidated telemetry & asset inventory dashboard"),
    ("10", "Export Network Report", "Export discovery findings to structured TXT, JSON, and CSV"),
    ("11", "Back to Main Menu", "Return to primary Kibuo reconnaissance menu"),
]


def render_fing_menu(device_count: int = 0) -> None:
    """Render the professional Fing-inspired submenu layout."""
    table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
    table.add_column("Number", style=f"bold {COLOR_BRAND}", width=6)
    table.add_column("Title", style="bold white", width=28)
    table.add_column("Description", style="dim white")

    for num, title, desc in FING_MENU_OPTIONS:
        if num == "11":
            num_style = COLOR_BRAND_ALT
            title_style = "bold yellow"
        else:
            num_style = COLOR_BRAND
            title_style = "bold white"

        table.add_row(
            f"[{num_style}][{num:>2}][/{num_style}]",
            f"[{title_style}]{title}[/{title_style}]",
            desc
        )

    inv_banner = f"Inventory Status: [bold green]{device_count}[/bold green] device(s) currently held in memory"
    panel = Panel(
        table,
        title=f"[bold {COLOR_BRAND_ALT}]NETWORK DISCOVERY & MONITORING SUITE[/bold {COLOR_BRAND_ALT}]",
        subtitle=inv_banner,
        border_style=COLOR_BRAND,
        padding=(1, 2)
    )
    console.print(panel)


def run_fing_suite_menu() -> None:
    """
    Main interactive dispatcher loop for Network Discovery & Monitoring module.
    """
    discovered_devices: List[Dict[str, Any]] = []
    last_scan_time: Optional[str] = None
    last_subnet: Optional[str] = None

    while True:
        try:
            clear_screen()
            print_banner(show_sysinfo=True)
            render_fing_menu(device_count=len(discovered_devices))
            console.print()

            choice = Prompt.ask(
                f"[bold {COLOR_BRAND}]Kibuo ❯ Network Discovery & Monitoring [1-11][/bold {COLOR_BRAND}]",
                default="1"
            ).strip().lower()

            if choice in ("11", "back", "b", "exit", "quit", "q", "0", "00"):
                break

            elif choice == "1":
                clear_screen()
                found = run_device_discovery_module()
                if found:
                    discovered_devices = found
                    from datetime import datetime
                    last_scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                pause_prompt()

            elif choice == "2":
                clear_screen()
                scanned = run_network_scanner_module()
                if scanned and not discovered_devices:
                    # Supplement device cache
                    for s in scanned:
                        discovered_devices.append({
                            "ip": s["ip"],
                            "mac": "N/A",
                            "hostname": "Unknown",
                            "vendor": "Unknown",
                            "status": "Online",
                            "open_ports": s.get("open_ports", [])
                        })
                pause_prompt()

            elif choice == "3":
                clear_screen()
                run_ip_information_module()
                pause_prompt()

            elif choice == "4":
                clear_screen()
                run_mac_information_module(discovered_devices)
                pause_prompt()

            elif choice == "5":
                clear_screen()
                run_device_identification_module(discovered_devices)
                pause_prompt()

            elif choice == "6":
                clear_screen()
                run_device_monitor_module(discovered_devices)
                pause_prompt()

            elif choice == "7":
                clear_screen()
                run_speed_test_module()
                pause_prompt()

            elif choice == "8":
                clear_screen()
                run_security_check_module(discovered_devices)
                pause_prompt()

            elif choice == "9":
                clear_screen()
                render_network_dashboard(discovered_devices, last_scan_time)
                pause_prompt()

            elif choice == "10":
                clear_screen()
                run_report_export_module(discovered_devices, last_subnet)
                pause_prompt()

            else:
                display_warning(f"Invalid option: '{choice}'. Select a number between 1 and 11.")
                pause_prompt()

        except KeyboardInterrupt:
            console.print("\n[dim]Returning to Network Discovery & Monitoring menu...[/dim]")
            time_pause = pause_prompt()
        except Exception as exc:
            logger.exception("Error in Network Discovery & Monitoring suite: %s", exc)
            display_error(f"Module error: {exc}")
            pause_prompt()

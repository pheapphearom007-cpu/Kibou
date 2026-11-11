"""
Network Information Dashboard for Kibuo (Fing-Inspired Network Engine).

Displays a consolidated single-screen operational status dashboard:
  • Network interface & physical link state
  • Local IPv4 addressing & CIDR subnet range
  • Gateway IP, MAC, and vendor
  • Primary & secondary DNS resolvers
  • Total discovered, active reachable, and unknown devices count
  • Internet uplink connectivity & round-trip latency
  • Scan session timestamp
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.logger import get_logger
from core.ui import (
    COLOR_BRAND, COLOR_BRAND_ALT, COLOR_INFO, COLOR_SUCCESS,
    COLOR_WARN, display_section_header
)
from modules.device_discovery import get_kernel_arp_table, probe_single_ip
from modules.ip_information import get_network_configuration
from modules.mac_lookup import get_vendor_for_mac
from modules.speed_test import check_internet_connectivity, measure_latency_and_jitter

logger = get_logger("kibuo.network_dashboard")
console = Console()


def render_network_dashboard(
    discovered_devices: Optional[List[Dict[str, Any]]] = None,
    last_scan_time: Optional[str] = None
) -> None:
    """
    Render comprehensive Fing-inspired network dashboard in terminal.
    """
    display_section_header("Network Information Dashboard", "Consolidated network overview, gateway telemetry & active asset statistics")

    # 1. Fetch system network configuration
    net_config = get_network_configuration()
    gateway_ip = net_config.get("gateway", "N/A")
    gateway_mac = "Unknown"
    gateway_vendor = "Unknown"

    if gateway_ip and gateway_ip != "N/A":
        # Resolve gateway MAC
        probe_single_ip(gateway_ip)
        arp_cache = get_kernel_arp_table()
        gateway_mac = arp_cache.get(gateway_ip, "Unknown")
        if gateway_mac != "Unknown":
            v_name, _ = get_vendor_for_mac(gateway_mac)
            gateway_vendor = v_name

    # 2. Check Internet Connectivity and Latency
    with console.status("[bold cyan]Probing uplink internet connectivity...[/bold cyan]"):
        is_internet_up = check_internet_connectivity()
        latency_str = "Offline"
        if is_internet_up:
            lat, _ = measure_latency_and_jitter(count=2)
            latency_str = f"{lat:.1f} ms"

    # 3. Analyze device counts
    devices = discovered_devices or []
    total_devices = len(devices)
    reachable_devices = sum(1 for d in devices if "Online" in d.get("status", ""))
    unknown_devices = sum(
        1 for d in devices
        if d.get("vendor") in ("Unknown Vendor", "Unknown Manufacturer", "Unknown", "")
    )

    scan_ts = last_scan_time or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build Layout Table
    dash_table = Table(show_header=False, box=None, padding=(0, 2))
    dash_table.add_column("Parameter", style="bold cyan", width=26)
    dash_table.add_column("Telemetry Value", style="white")

    dash_table.add_row("Network Interface", f"[bold white]{net_config['interface']}[/bold white] ({'UP' if net_config['is_up'] else 'DOWN'}, MTU {net_config['mtu']})")
    dash_table.add_row("Local IPv4 Address", f"[bold green]{net_config['ipv4']}[/bold green]")
    dash_table.add_row("Subnet (CIDR / Netmask)", f"{net_config['subnet_cidr']} (Mask: {net_config['netmask']})")
    dash_table.add_row("Default Gateway IP", f"[bold white]{gateway_ip}[/bold white]")
    gw_mac_disp = f"{gateway_mac} [yellow]({gateway_vendor})[/yellow]" if gateway_mac != "Unknown" else "N/A"
    dash_table.add_row("Default Gateway MAC", gw_mac_disp)
    dash_table.add_row("DNS Resolvers", ", ".join(net_config["dns_servers"][:2]))
    dash_table.add_row("DHCP Assignment", "Enabled (Dynamic)" if net_config["is_dhcp"] else "Static")
    dash_table.add_row("─" * 24, "─" * 40)

    # Asset Inventory Section
    dash_table.add_row("Discovered Local Devices", f"[bold {COLOR_BRAND}]{total_devices}[/bold {COLOR_BRAND}] device(s)")
    dash_table.add_row("Currently Reachable", f"[bold {COLOR_SUCCESS}]{reachable_devices}[/bold {COLOR_SUCCESS}] active")
    dash_table.add_row("Unclassified / Unknown", f"[bold {COLOR_WARN}]{unknown_devices}[/bold {COLOR_WARN}] device(s)")
    dash_table.add_row("─" * 24, "─" * 40)

    # Internet & Session Section
    inet_status = f"[bold green]ONLINE[/bold green] (Ping RTT: [bold cyan]{latency_str}[/bold cyan])" if is_internet_up else "[bold red]OFFLINE / UNREACHABLE[/bold red]"
    dash_table.add_row("Internet Connectivity", inet_status)
    dash_table.add_row("Last Assessment Timestamp", f"[dim]{scan_ts}[/dim]")

    panel = Panel(
        dash_table,
        title="[bold bright_yellow]KIBUO NETWORK TELEMETRY DASHBOARD[/bold bright_yellow]",
        border_style=COLOR_BRAND,
        padding=(1, 2)
    )
    console.print(panel)
    console.print()

"""
IP Address and Network Configuration Intelligence Module for Kibuo.

Inspects local IPv4, IPv6, default gateway, subnet masks, DNS servers,
DHCP allocation details, interface MTU and link operational status.
Public IP information is queried ONLY when explicitly authorized by the user.
"""

import ipaddress
import os
import re
import socket
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psutil
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core.logger import get_logger
from core.subprocess_manager import SubprocessManager
from core.ui import (
    COLOR_BRAND, COLOR_BRAND_ALT, COLOR_INFO, COLOR_SUCCESS,
    COLOR_WARN, display_error, display_info, display_section_header,
    display_success, display_warning
)

logger = get_logger("kibuo.ip_information")
console = Console()


def get_default_gateway_and_interface() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Retrieve default gateway IP, interface name, and protocol (e.g. 'dhcp' or 'static').
    Uses 'ip route show default' or /proc/net/route.
    """
    gateway_ip = None
    interface = None
    proto = None

    cmd_res = SubprocessManager.execute(["ip", "route", "show", "default"], timeout=4)
    if cmd_res.is_ok() and cmd_res.stdout:
        # e.g.: default via 192.168.100.1 dev wlp0s20f3 proto dhcp src 192.168.100.136 metric 600
        line = cmd_res.stdout.splitlines()[0]
        parts = line.split()
        if "via" in parts:
            idx = parts.index("via")
            if idx + 1 < len(parts):
                gateway_ip = parts[idx + 1]
        if "dev" in parts:
            idx = parts.index("dev")
            if idx + 1 < len(parts):
                interface = parts[idx + 1]
        if "proto" in parts:
            idx = parts.index("proto")
            if idx + 1 < len(parts):
                proto = parts[idx + 1]

    # Fallback to /proc/net/route if needed
    if not gateway_ip and os.path.exists("/proc/net/route"):
        try:
            with open("/proc/net/route", "r", encoding="utf-8") as f:
                for line in f.readlines()[1:]:
                    fields = line.strip().split()
                    if len(fields) >= 3 and fields[1] == "00000000":
                        interface = fields[0]
                        gw_hex = fields[2]
                        # Convert hex to IP
                        gw_bytes = bytes.fromhex(gw_hex)
                        gateway_ip = socket.inet_ntoa(gw_bytes[::-1])
                        break
        except Exception:
            pass

    return gateway_ip, interface, proto


def get_dns_servers() -> List[str]:
    """
    Retrieve configured DNS server IPs from resolvectl, systemd-resolve, or /etc/resolv.conf.
    """
    dns_servers = []

    # 1. Try resolvectl status for real upstream DNS
    cmd_res = SubprocessManager.execute(["resolvectl", "status"], timeout=4)
    if cmd_res.is_ok() and cmd_res.stdout:
        # Look for DNS Servers: 8.8.8.8 8.8.4.4 or Current DNS Server:
        for line in cmd_res.stdout.splitlines():
            if "DNS Servers:" in line or "Current DNS Server:" in line:
                parts = line.split(":", 1)[1].split()
                for p in parts:
                    clean_ip = p.strip()
                    if clean_ip and clean_ip not in dns_servers:
                        dns_servers.append(clean_ip)

    # 2. Check /etc/resolv.conf
    resolv_path = Path("/etc/resolv.conf")
    if resolv_path.exists():
        try:
            for line in resolv_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip_val = parts[1]
                        if ip_val not in dns_servers:
                            dns_servers.append(ip_val)
        except Exception:
            pass

    return dns_servers or ["127.0.0.53 (systemd-resolved)"]


def get_dhcp_details(interface: Optional[str] = None) -> Dict[str, Any]:
    """
    Check for active DHCP lease files and lease parameters.
    """
    details: Dict[str, Any] = {
        "is_dhcp": False,
        "lease_source": "Not detected",
        "lease_time": "Unknown"
    }

    # Check ip route proto flag
    _, _, proto = get_default_gateway_and_interface()
    if proto == "dhcp":
        details["is_dhcp"] = True
        details["lease_source"] = "Kernel IP Route (proto dhcp)"

    # Check NetworkManager internal lease files
    lease_dirs = [Path("/var/lib/NetworkManager"), Path("/var/lib/dhcp"), Path("/run/systemd/netif/leases")]
    for ldir in lease_dirs:
        if ldir.exists():
            for f in ldir.glob("*"):
                if interface and interface in f.name:
                    details["is_dhcp"] = True
                    details["lease_source"] = str(f)
                    break

    return details


def get_network_configuration() -> Dict[str, Any]:
    """
    Assemble complete local network configuration parameters.
    """
    gw_ip, primary_iface, proto = get_default_gateway_and_interface()
    dns_list = get_dns_servers()

    all_addrs = psutil.net_if_addrs()
    all_stats = psutil.net_if_stats()

    active_iface = primary_iface
    if not active_iface:
        # Pick first non-loopback interface that is up
        for name, stat in all_stats.items():
            if name != "lo" and stat.isup:
                active_iface = name
                break

    ipv4_addr = "N/A"
    ipv4_netmask = "N/A"
    ipv4_cidr = "N/A"
    ipv6_addr = "N/A"
    mac_addr = "N/A"
    is_up = False
    mtu = 1500
    speed_mb = 0

    if active_iface and active_iface in all_addrs:
        st = all_stats.get(active_iface)
        if st:
            is_up = st.isup
            mtu = st.mtu
            speed_mb = st.speed

        for snic in all_addrs[active_iface]:
            # socket.AF_INET = 2
            if snic.family == socket.AF_INET:
                ipv4_addr = snic.address
                ipv4_netmask = snic.netmask
                if ipv4_addr and ipv4_netmask:
                    try:
                        net = ipaddress.IPv4Network(f"{ipv4_addr}/{ipv4_netmask}", strict=False)
                        ipv4_cidr = str(net)
                    except Exception:
                        pass
            # socket.AF_INET6 = 10 (or 23 on Windows)
            elif snic.family in (socket.AF_INET6, 10, 23):
                if not snic.address.startswith("fe80"):
                    ipv6_addr = snic.address
                elif ipv6_addr == "N/A":
                    ipv6_addr = snic.address
            # MAC address (AF_PACKET = 17 on Linux)
            elif snic.family in (17, getattr(psutil, "AF_LINK", -1)):
                mac_addr = snic.address.upper()

    dhcp_info = get_dhcp_details(active_iface)

    return {
        "interface": active_iface or "Unknown",
        "is_up": is_up,
        "mtu": mtu,
        "speed_mb": speed_mb,
        "ipv4": ipv4_addr,
        "netmask": ipv4_netmask,
        "subnet_cidr": ipv4_cidr,
        "ipv6": ipv6_addr,
        "mac": mac_addr,
        "gateway": gw_ip or "N/A",
        "dns_servers": dns_list,
        "is_dhcp": dhcp_info["is_dhcp"],
        "dhcp_source": dhcp_info["lease_source"],
    }


def query_public_ip_info() -> Dict[str, Any]:
    """
    Query public IP and external ASN information via reputable API.
    Executed ONLY with explicit user authorization.
    """
    import json
    import urllib.request

    try:
        req = urllib.request.Request(
            "https://ipinfo.io/json",
            headers={"User-Agent": "Kibuo-Recon/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
            return {
                "public_ip": data.get("ip", "N/A"),
                "hostname": data.get("hostname", "N/A"),
                "city": data.get("city", "N/A"),
                "region": data.get("region", "N/A"),
                "country": data.get("country", "N/A"),
                "org": data.get("org", "N/A"),
                "timezone": data.get("timezone", "N/A"),
            }
    except Exception as exc:
        return {"error": str(exc), "public_ip": "Unable to reach public resolver"}


def run_ip_information_module() -> None:
    """
    Interactive execution handler for IP Address Information module.
    """
    display_section_header("IP Address & Network Configuration", "Local network stack, gateway, DNS, interface & DHCP audit")

    config = get_network_configuration()

    table = Table(title="Active Network Interface & IP Configuration", box=None)
    table.add_column("Network Parameter", style="bold cyan", width=24)
    table.add_column("Detected Configuration", style="white")

    table.add_row("Active Interface", f"[bold white]{config['interface']}[/bold white]")
    status_str = "[bold green]UP / OPERATIONAL[/bold green]" if config["is_up"] else "[bold red]DOWN[/bold red]"
    table.add_row("Interface Status", status_str)
    table.add_row("Hardware MAC", f"[bold yellow]{config['mac']}[/bold yellow]")
    table.add_row("MTU (Max Transmission Unit)", f"{config['mtu']} bytes")
    table.add_row("Local IPv4 Address", f"[bold green]{config['ipv4']}[/bold green]")
    table.add_row("Subnet Netmask", config["netmask"])
    table.add_row("Subnet CIDR Range", f"[bold cyan]{config['subnet_cidr']}[/bold cyan]")
    table.add_row("Local IPv6 Address", config["ipv6"])
    table.add_row("Default Gateway IP", f"[bold white]{config['gateway']}[/bold white]")
    table.add_row("Configured DNS Resolvers", ", ".join(config["dns_servers"]))
    dhcp_label = f"[bold green]Yes[/bold green] ({config['dhcp_source']})" if config["is_dhcp"] else "[yellow]Static / Manual[/yellow]"
    table.add_row("DHCP Configuration", dhcp_label)

    console.print(table)
    console.print()

    # Public IP check ONLY with explicit user confirmation
    console.print(f"[bold {COLOR_BRAND}]External Public IP Inspection:[/bold {COLOR_BRAND}]")
    console.print("[dim]Kibuo adheres to strict zero-leak principles and never queries external services without consent.[/dim]")
    
    if Confirm.ask("Would you like to query your external Public IP and ISP/ASN routing information?", default=False):
        with console.status(f"[bold {COLOR_BRAND}]Contacting external public address resolver...[/bold {COLOR_BRAND}]"):
            pub_info = query_public_ip_info()

        pub_table = Table(title="Public Internet Addressing & ISP Routing", box=None)
        pub_table.add_column("External Property", style="bold cyan", width=24)
        pub_table.add_column("Resolved Value", style="white")

        pub_table.add_row("Public IP Address", f"[bold green]{pub_info.get('public_ip', 'N/A')}[/bold green]")
        pub_table.add_row("Autonomous System (ISP)", pub_info.get("org", "N/A"))
        loc = f"{pub_info.get('city', '')}, {pub_info.get('region', '')}, {pub_info.get('country', '')}"
        pub_table.add_row("Geographic Region", loc.strip(", "))
        pub_table.add_row("Timezone", pub_info.get("timezone", "N/A"))

        console.print()
        console.print(pub_table)
    else:
        display_info("Public IP query skipped by user.")

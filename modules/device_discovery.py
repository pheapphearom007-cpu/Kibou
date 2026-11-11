"""
Device Discovery Module for Kibuo (Fing-Inspired Network Engine).

Identifies active devices connected to an authorized local network segment.
Resolves IP addresses, hardware MAC addresses, OUI manufacturers, hostnames,
and online availability status using multi-tier discovery (privileged ARP sweeps,
kernel neighbor cache inspection, and concurrent socket probing).
"""

import concurrent.futures
import ipaddress
import os
import re
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core.logger import get_logger
from core.permission_manager import PermissionManager
from core.report_generator import AssessmentSession
from core.subprocess_manager import SubprocessManager
from core.ui import (
    COLOR_BRAND, COLOR_BRAND_ALT, COLOR_INFO, COLOR_SUCCESS,
    COLOR_WARN, display_error, display_info, display_section_header,
    display_success, display_warning
)
from core.validator import ValidationError, is_private_subnet, validate_cidr
from modules.ip_information import get_network_configuration
from modules.mac_lookup import get_vendor_for_mac

logger = get_logger("kibuo.device_discovery")
console = Console()

COMMON_PROBE_PORTS = [80, 443, 22, 53, 445, 139, 8080, 631, 8008]


def resolve_hostname(ip: str, timeout: float = 0.8) -> str:
    """Safely resolve reverse DNS hostname with short timeout."""
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return "Unknown"
    finally:
        socket.setdefaulttimeout(original_timeout)


def probe_single_ip(ip: str) -> bool:
    """
    Lightweight probe: quickly attempts ICMP ping (1 packet) or TCP connect.
    Even if TCP connection is rejected or filtered, the kernel sends an ARP
    request on the local network which immediately populates /proc/net/arp.
    """
    # 1. Try quick ping
    ping_res = SubprocessManager.execute(["ping", "-c", "1", "-W", "1", ip], timeout=2)
    if ping_res.is_ok():
        return True

    # 2. Try TCP SYN probe on common port (80 or 443)
    for port in (80, 443, 53, 22):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.4)
                if sock.connect_ex((ip, port)) == 0:
                    return True
        except Exception:
            pass

    return False


def get_kernel_arp_table() -> Dict[str, str]:
    """Read kernel ARP neighbor cache from /proc/net/arp and 'ip neigh'."""
    arp_map: Dict[str, str] = {}

    arp_path = Path("/proc/net/arp")
    if arp_path.exists():
        try:
            for line in arp_path.read_text(encoding="utf-8").splitlines()[1:]:
                parts = line.split()
                if len(parts) >= 4:
                    ip_addr = parts[0]
                    mac_addr = parts[3].upper()
                    if mac_addr != "00:00:00:00:00:00":
                        arp_map[ip_addr] = mac_addr
        except Exception as exc:
            logger.debug("Could not read /proc/net/arp: %s", exc)

    # Supplement with 'ip -4 neigh show'
    cmd = SubprocessManager.execute(["ip", "-4", "neigh", "show"], timeout=3)
    if cmd.is_ok() and cmd.stdout:
        for line in cmd.stdout.splitlines():
            # e.g.: 192.168.100.1 dev wlp0s20f3 lladdr 9c:b2:e8:a7:9a:31 REACHABLE
            parts = line.split()
            if len(parts) >= 5 and "lladdr" in parts:
                idx = parts.index("lladdr")
                if idx + 1 < len(parts):
                    ip_candidate = parts[0]
                    mac_candidate = parts[idx + 1].upper()
                    if mac_candidate != "00:00:00:00:00:00":
                        arp_map[ip_candidate] = mac_candidate

    return arp_map


def discover_devices(
    subnet_cidr: str,
    interface: Optional[str] = None,
    max_hosts: int = 256
) -> Tuple[List[Dict[str, Any]], float]:
    """
    Execute robust multi-tier device discovery on the specified subnet.
    
    Returns:
        Tuple of (discovered_devices_list, duration_seconds)
    """
    start_time = time.time()
    discovered: Dict[str, Dict[str, Any]] = {}

    net = ipaddress.IPv4Network(subnet_cidr, strict=False)
    host_ips = [str(h) for h in net.hosts()][:max_hosts]

    # Include local host info from net config
    net_config = get_network_configuration()
    local_ip = net_config.get("ipv4")
    local_mac = net_config.get("mac")
    local_iface = net_config.get("interface")

    # Step 1: Check privileged tools (arp-scan / nmap)
    has_arp_scan = SubprocessManager.is_binary_available("arp-scan") and PermissionManager.is_root()
    has_nmap = SubprocessManager.is_binary_available("nmap")

    if has_arp_scan and interface:
        cmd = ["arp-scan", f"--interface={interface}", subnet_cidr]
        res = SubprocessManager.execute(cmd, timeout=30)
        if res.is_ok() and res.stdout:
            for line in res.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) >= 2:
                    ip_c = parts[0].strip()
                    mac_c = parts[1].strip().upper()
                    vendor_c = parts[2].strip() if len(parts) >= 3 else ""
                    if ip_c in host_ips or ip_c == local_ip:
                        discovered[ip_c] = {
                            "ip": ip_c,
                            "mac": mac_c,
                            "vendor": vendor_c,
                            "hostname": "Resolving...",
                            "status": "Online"
                        }

    # Step 2: Concurrent IP probe sweep to trigger network resolution & populate ARP table
    hosts_to_probe = [h for h in host_ips if h not in discovered and h != local_ip]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task(f"Scanning {subnet_cidr} for active hosts...", total=len(hosts_to_probe))

        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            future_to_ip = {executor.submit(probe_single_ip, ip): ip for ip in hosts_to_probe}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    is_online = future.result()
                    if is_online:
                        discovered[ip] = {
                            "ip": ip,
                            "mac": "Resolving...",
                            "vendor": "Resolving...",
                            "hostname": "Resolving...",
                            "status": "Online"
                        }
                except Exception:
                    pass
                progress.advance(task, 1)

    # Step 3: Read kernel ARP cache to capture MAC addresses of responding devices
    arp_cache = get_kernel_arp_table()
    for ip, mac in arp_cache.items():
        if ip in host_ips or ip in discovered:
            if ip not in discovered:
                discovered[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "vendor": "",
                    "hostname": "",
                    "status": "Online"
                }
            else:
                discovered[ip]["mac"] = mac

    # Step 4: Ensure local host device is always listed
    if local_ip and local_ip not in ("N/A", "127.0.0.1"):
        if local_ip not in discovered:
            discovered[local_ip] = {
                "ip": local_ip,
                "mac": local_mac if local_mac != "N/A" else "Local Interface",
                "vendor": "Local System Interface",
                "hostname": socket.gethostname(),
                "status": "Online (This Machine)"
            }
        else:
            discovered[local_ip]["status"] = "Online (This Machine)"
            if local_mac and local_mac != "N/A":
                discovered[local_ip]["mac"] = local_mac

    # Step 5: Resolve vendors and hostnames for all discovered hosts
    device_list: List[Dict[str, Any]] = []
    for ip, info in discovered.items():
        mac = info.get("mac", "Unknown")
        vendor = info.get("vendor", "")

        if not vendor or vendor in ("Resolving...", "Unknown Vendor"):
            resolved_vendor, _ = get_vendor_for_mac(mac)
            info["vendor"] = resolved_vendor

        hostname = info.get("hostname", "")
        if not hostname or hostname == "Resolving...":
            info["hostname"] = resolve_hostname(ip)

        device_list.append(info)

    # Sort numerically by IP
    def ip_sort_key(item):
        try:
            return socket.inet_aton(item["ip"])
        except Exception:
            return b"\x00"

    device_list.sort(key=ip_sort_key)
    duration = time.time() - start_time
    return device_list, duration


def run_device_discovery_module() -> List[Dict[str, Any]]:
    """
    Interactive execution handler for Device Discovery module.
    Returns the list of discovered devices so the suite can reuse it.
    """
    display_section_header("Device Discovery", "Identify active devices on authorized local network segment")

    net_config = get_network_configuration()
    default_cidr = net_config.get("subnet_cidr")
    default_iface = net_config.get("interface")

    if not default_cidr or default_cidr == "N/A":
        default_cidr = "192.168.1.0/24"

    console.print(f"[bold cyan]Detected Local Network:[/bold cyan] {default_cidr} on interface [bold white]{default_iface}[/bold white]")
    console.print()

    subnet_input = Prompt.ask(
        f"[bold {COLOR_BRAND}]Enter Target Subnet (CIDR format)[/bold {COLOR_BRAND}]",
        default=default_cidr
    ).strip()

    try:
        validated_cidr = str(validate_cidr(subnet_input))
    except ValidationError as err:
        display_error(str(err))
        return []

    # Defensive check: Warn on public subnet
    if not is_private_subnet(validated_cidr):
        display_warning(f"The specified subnet '{validated_cidr}' is a PUBLIC network range!")
        display_warning("Local device discovery via link-layer queries is only valid on authorized local networks.")
        if not Confirm.ask("Do you warrant you have explicit authorization to scan this network?", default=False):
            display_info("Scan cancelled.")
            return []

    console.print()
    display_info(f"Starting discovery on authorized subnet: [bold white]{validated_cidr}[/bold white]")

    devices, duration = discover_devices(validated_cidr, interface=default_iface)

    # Display scan completion statistics
    console.print()
    if devices:
        display_success(f"Discovery completed in {duration:.2f}s. Found {len(devices)} active device(s).")
        
        table = Table(title=f"Discovered Network Devices ({validated_cidr})", box=None)
        table.add_column("IP ADDRESS", style="bold green", width=18)
        table.add_column("MAC ADDRESS", style="bold cyan", width=20)
        table.add_column("HOSTNAME", style="yellow", width=26)
        table.add_column("VENDOR", style="white")
        table.add_column("STATUS", style="bold green", width=18)

        for dev in devices:
            table.add_row(
                dev["ip"],
                dev.get("mac", "Unknown"),
                dev.get("hostname", "Unknown")[:24],
                dev.get("vendor", "Unknown"),
                dev.get("status", "Active")
            )
        console.print(table)
    else:
        display_warning(f"No active devices responded on subnet {validated_cidr}.")

    console.print()
    # Save discovery in session reports
    session = AssessmentSession(target=validated_cidr, module_name="Device Discovery")
    session.write_json_artifact("device_discovery_hosts.json", devices)
    reports = session.finalize(
        status="Completed",
        summary_data={
            "subnet": validated_cidr,
            "device_count": len(devices),
            "duration": duration,
            "devices": devices
        },
        duration_seconds=duration
    )
    display_info(f"Discovery session report archived: {reports['report_txt']}")

    return devices

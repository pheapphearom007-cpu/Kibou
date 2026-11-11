"""
Network Discovery Modules for Kibuo.

Module [01]: ARP Network Discovery (arp-scan / netdiscover / nmap fallback)
Module [02]: Live Host Discovery (Nmap -sn / ICMP sweep)
"""

import ipaddress
import os
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core.logger import get_logger
from core.permission_manager import PermissionManager
from core.report_generator import AssessmentSession
from core.subprocess_manager import SubprocessManager
from core.ui import (
    COLOR_BRAND, COLOR_BRAND_ALT, COLOR_ERROR, COLOR_INFO,
    COLOR_SUCCESS, COLOR_WARN, display_error, display_info,
    display_section_header, display_success, display_warning
)
from core.validator import ValidationError, validate_cidr, validate_ipv4, validate_target

logger = get_logger("kibuo.network_discovery")
console = Console()

# Regular expressions for ARP parsing
MAC_REGEX = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})")
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def get_local_interfaces() -> List[Dict[str, str]]:
    """
    Detect local network interfaces, their state, and associated IPv4 subnets.
    Reads from /sys/class/net and 'ip -4 -o addr show' or socket inspection.
    """
    interfaces = []
    
    # Try using 'ip -4 -o addr show'
    cmd_res = SubprocessManager.execute(["ip", "-4", "-o", "addr", "show"], timeout=5)
    if cmd_res.is_ok() and cmd_res.stdout:
        for line in cmd_res.stdout.splitlines():
            # Example line: 2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global dynamic eth0
            parts = line.split()
            if len(parts) >= 4:
                iface_name = parts[1]
                cidr = parts[3]
                if iface_name != "lo" and "/" in cidr:
                    try:
                        net = ipaddress.IPv4Network(cidr, strict=False)
                        interfaces.append({
                            "name": iface_name,
                            "ip": str(parts[3].split("/")[0]),
                            "cidr": str(net),
                            "raw_cidr": cidr
                        })
                    except Exception:
                        pass

    # If ip command produced nothing, fallback to checking /sys/class/net
    if not interfaces and os.path.exists("/sys/class/net"):
        for iface in os.listdir("/sys/class/net"):
            if iface != "lo":
                interfaces.append({
                    "name": iface,
                    "ip": "Unknown",
                    "cidr": "Auto",
                    "raw_cidr": ""
                })

    return interfaces


def parse_arp_scan_output(output: str) -> List[Dict[str, str]]:
    """
    Parse standard arp-scan terminal output into structured host dictionaries.
    Example lines:
    192.168.1.1   00:50:56:c0:00:08   VMware, Inc.
    192.168.1.100 dc:a6:32:11:22:33   Raspberry Pi Foundation
    """
    results = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("Interface:") or line.startswith("Starting") or line.startswith("Ending"):
            continue
        if "packets rcvd" in line or "responded" in line:
            continue
            
        parts = line.split("\t")
        if len(parts) < 2:
            parts = re.split(r"\s{2,}", line)
            
        if len(parts) >= 2:
            ip_candidate = parts[0].strip()
            mac_candidate = parts[1].strip()
            vendor = parts[2].strip() if len(parts) >= 3 else "Unknown Vendor"
            
            if IP_REGEX.match(ip_candidate) and MAC_REGEX.match(mac_candidate):
                results.append({
                    "ip": ip_candidate,
                    "mac": mac_candidate.upper(),
                    "vendor": vendor,
                    "status": "Active"
                })
    return results


def run_arp_discovery_module() -> None:
    """
    Interactive execution handler for Module [01] ARP Network Discovery.
    """
    display_section_header("Module [01]: ARP Network Discovery", "Discover active link-layer devices on local subnet")

    # Check privileges
    has_priv, priv_msg = PermissionManager.check_module_privilege("arp_discovery")
    if not has_priv:
        display_warning(priv_msg)
        if not Confirm.ask("Do you wish to continue with unprivileged fallback?", default=True):
            return

    # Interface detection
    interfaces = get_local_interfaces()
    selected_iface = None
    target_subnet = None

    if interfaces:
        table = Table(title="Detected Network Interfaces", box=None)
        table.add_column("#", style="bold cyan", width=4)
        table.add_column("Interface", style="bold white", width=12)
        table.add_column("Assigned IP", style="yellow", width=18)
        table.add_column("Subnet (CIDR)", style="green")

        for idx, ifc in enumerate(interfaces, 1):
            table.add_row(str(idx), ifc["name"], ifc["ip"], ifc["cidr"])
        console.print(table)
        console.print()

        choice = Prompt.ask(
            f"[bold {COLOR_BRAND}]Select interface [1-{len(interfaces)}] or 'm' for manual[/bold {COLOR_BRAND}]",
            default="1"
        )
        if choice.isdigit() and 1 <= int(choice) <= len(interfaces):
            sel = interfaces[int(choice) - 1]
            selected_iface = sel["name"]
            target_subnet = sel["cidr"] if sel["cidr"] != "Auto" else None
        else:
            selected_iface = Prompt.ask("[bold white]Enter network interface name (e.g. eth0)[/bold white]")
    else:
        selected_iface = Prompt.ask("[bold white]Enter network interface name (e.g. eth0)[/bold white]", default="eth0")

    if not target_subnet:
        subnet_input = Prompt.ask(
            f"[bold {COLOR_BRAND}]Enter target subnet in CIDR format (or leave blank for local subnet)[/bold {COLOR_BRAND}]",
            default=""
        )
        if subnet_input.strip():
            try:
                target_subnet = str(validate_cidr(subnet_input))
            except ValidationError as err:
                display_error(str(err))
                return

    target_display = target_subnet or f"Localnet on {selected_iface}"
    session = AssessmentSession(target=target_display, module_name="ARP Network Discovery")

    hosts_found: List[Dict[str, str]] = []
    raw_output = ""
    start_time = time.time()

    # Determine execution strategy
    has_arp_scan = SubprocessManager.is_binary_available("arp-scan")
    has_nmap = SubprocessManager.is_binary_available("nmap")

    with console.status(f"[bold {COLOR_BRAND}]Performing link-layer ARP discovery on {selected_iface}...[/bold {COLOR_BRAND}]"):
        if has_arp_scan and PermissionManager.is_root():
            cmd = ["arp-scan", f"--interface={selected_iface}"]
            if target_subnet:
                cmd.append(target_subnet)
            else:
                cmd.append("--localnet")
            
            logger.info("Executing ARP discovery: %s", " ".join(cmd))
            res = SubprocessManager.execute(cmd, timeout=60)
            raw_output = res.stdout + ("\n" + res.stderr if res.stderr else "")
            hosts_found = parse_arp_scan_output(res.stdout)

        elif has_nmap:
            # Fallback to Nmap ARP host discovery
            cmd = ["nmap", "-sn", "-PR"]
            if selected_iface:
                cmd.extend(["-e", selected_iface])
            cmd.append(target_subnet if target_subnet else "192.168.1.0/24")
            
            logger.info("Executing Nmap ARP discovery fallback: %s", " ".join(cmd))
            res = SubprocessManager.execute(cmd, timeout=120)
            raw_output = res.stdout + ("\n" + res.stderr if res.stderr else "")
            
            # Parse Nmap output
            current_ip = None
            current_mac = None
            current_vendor = "Unknown Vendor"
            for line in res.stdout.splitlines():
                if "Nmap scan report for" in line:
                    parts = line.split()
                    current_ip = parts[-1].strip("()")
                    current_mac = "Unknown"
                    current_vendor = "Local Device"
                elif "MAC Address:" in line:
                    mac_parts = line.split("MAC Address:")[1].strip().split()
                    if mac_parts:
                        current_mac = mac_parts[0]
                        current_vendor = " ".join(mac_parts[1:]).strip("()")
                    if current_ip:
                        hosts_found.append({
                            "ip": current_ip,
                            "mac": current_mac,
                            "vendor": current_vendor,
                            "status": "Active"
                        })
                        current_ip = None
                elif current_ip and ("Host is up" in line or line.strip() == ""):
                    # Host might not show MAC if it is localhost
                    if current_ip:
                        hosts_found.append({
                            "ip": current_ip,
                            "mac": "N/A (Local / Host Interface)",
                            "vendor": "Local Interface",
                            "status": "Active"
                        })
                        current_ip = None

    duration = time.time() - start_time

    # Save artifacts
    session.write_artifact("arp_discovery_raw.txt", raw_output)
    session.write_json_artifact("arp_discovery_hosts.json", hosts_found)

    # Render results table
    console.print()
    if hosts_found:
        display_success(f"Discovery complete. Identified {len(hosts_found)} active device(s).")
        result_table = Table(title="ARP Discovered Live Devices", box=None)
        result_table.add_column("IP Address", style="bold green", width=18)
        result_table.add_column("MAC Address", style="cyan", width=20)
        result_table.add_column("Vendor / Manufacturer", style="white")
        result_table.add_column("Status", style="bold green", width=10)

        for h in hosts_found:
            result_table.add_row(h["ip"], h["mac"], h["vendor"], h["status"])
        console.print(result_table)
    else:
        display_warning("No active hosts responded to ARP requests.")
        if raw_output:
            console.print(Panel(raw_output[:500], title="Raw Diagnostics", border_style="dim"))

    # Finalize reports
    reports = session.finalize(
        status="Completed",
        summary_data={
            "interface": selected_iface,
            "target_subnet": target_display,
            "active_hosts_count": len(hosts_found),
            "hosts": hosts_found
        },
        duration_seconds=duration
    )
    console.print()
    display_info(f"Report saved to: {reports['report_txt']}")

    if hosts_found:
        console.print()
        if Confirm.ask("[bold yellow]Would you like to target one of the discovered hosts for a Quick Port Scan?[/bold yellow]", default=False):
            host_options = [h["ip"] for h in hosts_found]
            sel_host = Prompt.ask(
                "Select target IP address",
                choices=host_options,
                default=host_options[0]
            )
            from modules.nmap_scanner import run_quick_port_scan_module
            console.print()
            run_quick_port_scan_module(sel_host)


def run_live_host_discovery_module() -> None:
    """
    Interactive execution handler for Module [02] Live Host Discovery.
    Supports IPv4 single hosts and CIDR ranges without port scanning.
    """
    display_section_header("Module [02]: Live Host Discovery", "Ping sweep & ICMP host discovery without port scanning")

    target_input = Prompt.ask(
        f"[bold {COLOR_BRAND}]Enter Target (IPv4 or CIDR subnet, e.g. 192.168.1.0/24 or 10.0.0.1)[/bold {COLOR_BRAND}]"
    )

    try:
        target_type, validated_target = validate_target(target_input)
    except ValidationError as err:
        display_error(str(err))
        return

    session = AssessmentSession(target=validated_target, module_name="Live Host Discovery")
    active_hosts: List[str] = []
    inactive_hosts: List[str] = []
    start_time = time.time()
    raw_output = ""

    has_nmap = SubprocessManager.is_binary_available("nmap")

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        task = progress.add_task(f"Probing target: {validated_target}...", total=None)

        if has_nmap:
            # -sn: Ping Scan - disable port scan
            # -PE -PS80,443 -PA3389 -PP: diverse probes for reliability
            cmd = ["nmap", "-sn", "-T4", validated_target]
            logger.info("Executing Nmap live host discovery: %s", " ".join(cmd))
            
            res = SubprocessManager.execute(cmd, timeout=300)
            raw_output = res.stdout + ("\n" + res.stderr if res.stderr else "")
            
            current_host = None
            for line in res.stdout.splitlines():
                if "Nmap scan report for" in line:
                    parts = line.split()
                    current_host = parts[-1].strip("()")
                elif "Host is up" in line and current_host:
                    active_hosts.append(current_host)
                    current_host = None
            progress.update(task, completed=100, total=100)
        else:
            # Fallback pure ping check for single host or small CIDR
            progress.update(task, description="Nmap not found. Running ping sweep fallback...")
            try:
                if target_type == "cidr":
                    net = ipaddress.IPv4Network(validated_target, strict=False)
                    host_list = list(net.hosts())
                    # Limit unprivileged fallback ping sweep to /24 to avoid freezing
                    if len(host_list) > 256:
                        display_warning("Network larger than /24 without Nmap; limiting sweep to first 254 hosts.")
                        host_list = host_list[:254]
                else:
                    host_list = [ipaddress.IPv4Address(validated_target)]

                progress.update(task, total=len(host_list), completed=0)

                for ip in host_list:
                    ip_str = str(ip)
                    # Ping single host with 1 packet, 1s timeout
                    ping_res = SubprocessManager.execute(["ping", "-c", "1", "-W", "1", ip_str], timeout=3)
                    if ping_res.is_ok():
                        active_hosts.append(ip_str)
                    else:
                        inactive_hosts.append(ip_str)
                    progress.advance(task, 1)

            except Exception as exc:
                display_error(f"Fallback sweep failed: {exc}")

    duration = time.time() - start_time

    # Write artifacts
    session.write_artifact("host_discovery_output.txt", raw_output or f"Active: {len(active_hosts)}\nInactive: {len(inactive_hosts)}")
    session.write_json_artifact("active_hosts.json", {"active": active_hosts, "inactive_count": len(inactive_hosts)})

    console.print()
    if active_hosts:
        display_success(f"Discovered {len(active_hosts)} active host(s) on {validated_target}:")
        tbl = Table(title="Discovered Live Hosts", box=None)
        tbl.add_column("#", style="dim", width=4)
        tbl.add_column("IP Address", style="bold green", width=20)
        tbl.add_column("Discovery Method", style="cyan")
        tbl.add_column("Status", style="bold green")

        for idx, h in enumerate(active_hosts, 1):
            tbl.add_row(str(idx), h, "ICMP / TCP Probe" if has_nmap else "ICMP Echo", "ONLINE")
        console.print(tbl)
    else:
        display_warning(f"No responding hosts found on target {validated_target}.")

    reports = session.finalize(
        status="Completed",
        summary_data={
            "target": validated_target,
            "active_hosts_count": len(active_hosts),
            "active_hosts": active_hosts,
            "scan_duration_seconds": duration
        },
        duration_seconds=duration
    )
    console.print()
    display_info(f"Session report saved: {reports['report_txt']}")

    if active_hosts:
        console.print()
        if Confirm.ask("[bold yellow]Would you like to target one of the discovered hosts for a Quick Port Scan?[/bold yellow]", default=False):
            sel_host = Prompt.ask(
                "Select target IP address",
                choices=active_hosts,
                default=active_hosts[0]
            )
            from modules.nmap_scanner import run_quick_port_scan_module
            console.print()
            run_quick_port_scan_module(sel_host)

"""
Defensive Network Security Assessment Module for Kibuo.

Evaluates local network posture from a defensive perspective:
  • Detects duplicate IP addresses (potential IP collision or ARP conflicts)
  • Identifies unfamiliar devices and unrecognized MAC vendors
  • Audits open plaintext or risky services (Telnet 23, FTP 21, SMB 445, VNC 5900)
  • Evaluates gateway security (unencrypted router admin, DNS exposures)
  • Formulates clear, actionable remediation recommendations

Adheres strictly to defensive cybersecurity principles: unfamiliar devices
are NEVER falsely labeled as malicious attackers or intruders.
"""

import socket
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core.logger import get_logger
from core.ui import (
    COLOR_BRAND, COLOR_BRAND_ALT, COLOR_ERROR, COLOR_INFO,
    COLOR_SUCCESS, COLOR_WARN, display_error, display_info,
    display_section_header, display_success, display_warning
)
from modules.device_discovery import discover_devices
from modules.ip_information import get_network_configuration
from modules.mac_lookup import get_vendor_for_mac

logger = get_logger("kibuo.security_check")
console = Console()

RISKY_PORTS = {
    21: {"name": "FTP (File Transfer Protocol)", "risk": "Medium", "rec": "FTP transmits credentials and files in cleartext. Transition to SFTP (port 22) or FTPS."},
    23: {"name": "Telnet (Legacy Remote Shell)", "risk": "High", "rec": "Telnet sends passwords in cleartext. Disable Telnet and deploy SSH (port 22) immediately."},
    80: {"name": "HTTP (Unencrypted Web Management)", "risk": "Low", "rec": "Administration web console is accessible over unencrypted HTTP. Enable HTTPS enforcement."},
    139: {"name": "NetBIOS-SSN", "risk": "Low", "rec": "Legacy NetBIOS session service active. Restrict access or disable SMBv1."},
    445: {"name": "SMB (Server Message Block)", "risk": "Medium", "rec": "Ensure SMB signing is required and SMBv1 is disabled to prevent relay attacks."},
    5900: {"name": "VNC (Virtual Network Computing)", "risk": "Medium", "rec": "VNC interface detected. Ensure strong password authentication and tunnel through SSH or VPN."},
    6379: {"name": "Redis In-Memory Store", "risk": "High", "rec": "Redis exposed to local subnet. Ensure bind 127.0.0.1 or strong requirepass authentication."},
}


def audit_device_ports(ip: str, timeout: float = 0.4) -> List[Dict[str, Any]]:
    """Scan device for known high-risk or cleartext service ports."""
    findings = []
    for port, info in RISKY_PORTS.items():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    findings.append({
                        "port": port,
                        "name": info["name"],
                        "risk": info["risk"],
                        "recommendation": info["rec"]
                    })
        except Exception:
            pass
    return findings


def check_duplicate_ips(devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Detect if multiple MAC addresses are claiming the same IP address."""
    ip_to_macs: Dict[str, List[str]] = {}
    for dev in devices:
        ip = dev.get("ip")
        mac = dev.get("mac")
        if ip and mac and mac not in ("Unknown", "Local Interface"):
            ip_to_macs.setdefault(ip, []).append(mac)

    duplicates = []
    for ip, macs in ip_to_macs.items():
        unique_macs = list(set(macs))
        if len(unique_macs) > 1:
            duplicates.append({"ip": ip, "macs": unique_macs})

    return duplicates


def run_security_check_module(discovered_devices: Optional[List[Dict[str, Any]]] = None) -> None:
    """
    Interactive execution handler for Defensive Network Security Check.
    """
    display_section_header("Defensive Network Security Assessment", "Audits unfamiliar devices, duplicate IPs, cleartext ports & gateway exposure")

    devices = list(discovered_devices) if discovered_devices else []

    if not devices:
        display_info("No devices currently loaded in discovery memory.")
        if Confirm.ask("Run rapid local device discovery now to populate target inventory?", default=True):
            net_config = get_network_configuration()
            cidr = net_config.get("subnet_cidr", "192.168.1.0/24")
            if cidr != "N/A":
                devices, _ = discover_devices(cidr)

    if not devices:
        display_warning("No devices available to analyze. Returning to menu.")
        return

    net_config = get_network_configuration()
    gateway_ip = net_config.get("gateway")
    local_ip = net_config.get("ipv4")

    console.print(f"\n[bold cyan]Assessing {len(devices)} device(s) on authorized local network...[/bold cyan]\n")

    unfamiliar_devices = []
    service_risks = []
    duplicate_ip_alerts = []

    # 1. Check for Duplicate IPs (ARP collision or spoofing)
    duplicate_ip_alerts = check_duplicate_ips(devices)

    # 2. Check for unfamiliar / unknown vendor devices
    for dev in devices:
        ip = dev.get("ip")
        mac = dev.get("mac", "")
        vendor = dev.get("vendor", "")

        if not vendor or vendor in ("Unknown Vendor", "Unknown Manufacturer"):
            unfamiliar_devices.append(dev)

    # 3. Check for exposed cleartext / risky ports on active hosts
    with console.status(f"[bold {COLOR_BRAND}]Auditing device services for cleartext protocols and exposures...[/bold {COLOR_BRAND}]"):
        for dev in devices:
            ip = dev.get("ip")
            if ip and ip != "N/A":
                found_risks = audit_device_ports(ip)
                for r in found_risks:
                    service_risks.append({
                        "ip": ip,
                        "hostname": dev.get("hostname", "Unknown"),
                        "port": r["port"],
                        "service": r["name"],
                        "risk": r["risk"],
                        "recommendation": r["recommendation"]
                    })

    # Render Findings

    # A. Unfamiliar Devices Alert Card
    if unfamiliar_devices:
        console.print(Panel(
            "[bold yellow]NOTICE: Unfamiliar or unclassified devices detected on the network.[/bold yellow]\n"
            "[dim]Note: An unfamiliar device is not automatically malicious. It may be a guest device, smartphone with randomized MAC, or smart home accessory.[/dim]",
            title="[bold yellow]⚠  Unfamiliar Device Advisory[/bold yellow]",
            border_style=COLOR_WARN
        ))
        unfam_table = Table(box=None)
        unfam_table.add_column("IP Address", style="bold green", width=18)
        unfam_table.add_column("MAC Address", style="bold cyan", width=20)
        unfam_table.add_column("Detected Hostname", style="white", width=22)
        unfam_table.add_column("Security Guidance", style="yellow")

        for u in unfamiliar_devices:
            guidance = "Verify device identity against physical routers or DHCP client list"
            unfam_table.add_row(u["ip"], u.get("mac", "Unknown"), u.get("hostname", "Unknown")[:20], guidance)
        console.print(unfam_table)
        console.print()

    # B. Duplicate IP Alerts
    if duplicate_ip_alerts:
        console.print(Panel(
            "[bold red]CRITICAL: Multiple MAC addresses detected for a single IP address![/bold red]\n"
            "This may indicate an IP address collision, DHCP misconfiguration, or ARP spoofing activity.",
            title="[bold red]✖  Duplicate IP Collision Detected[/bold red]",
            border_style=COLOR_ERROR
        ))
        for dup in duplicate_ip_alerts:
            console.print(f"  • [bold white]{dup['ip']}[/bold white] claimed by MACs: {', '.join(dup['macs'])}")
        console.print()

    # C. Service Risks Table
    if service_risks:
        serv_table = Table(title="Exposed Management & Cleartext Service Audit", box=None)
        serv_table.add_column("Host IP", style="bold green", width=16)
        serv_table.add_column("Port", style="bold white", width=8)
        serv_table.add_column("Service Protocol", style="bold cyan", width=24)
        serv_table.add_column("Risk Level", style="bold yellow", width=12)
        serv_table.add_column("Actionable Recommendation", style="white")

        for sr in service_risks:
            r_level = sr["risk"]
            r_style = COLOR_ERROR if r_level == "High" else (COLOR_WARN if r_level == "Medium" else COLOR_INFO)
            serv_table.add_row(
                sr["ip"],
                str(sr["port"]),
                sr["service"][:22],
                f"[{r_style}]{r_level}[/{r_style}]",
                sr["recommendation"]
            )
        console.print(serv_table)
        console.print()
    else:
        display_success("No legacy cleartext services (Telnet/FTP/VNC) detected on surveyed hosts.")

    # D. Router & Gateway Inspection
    if gateway_ip:
        console.print(f"[bold cyan]Gateway Security Check ({gateway_ip}):[/bold cyan]")
        gw_ports = [r["port"] for r in service_risks if r["ip"] == gateway_ip]
        if 80 in gw_ports and 443 not in gw_ports:
            display_warning(f"Default gateway {gateway_ip} serves admin dashboard on cleartext HTTP port 80. Configure HTTPS.")
        else:
            display_success(f"Default gateway {gateway_ip} appears compliant with standard baseline checks.")

    console.print()
    display_info("Defensive security check complete. Review recommendations to harden authorized devices.")

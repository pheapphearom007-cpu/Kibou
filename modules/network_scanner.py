"""
Network Scanner Module for Kibuo (Fing-Inspired Network Engine).

Performs authorized local subnet scans, port detection, and active host mapping.
Seamlessly incorporates Nmap if available on the system and defaults to high-speed
concurrent Python socket/ICMP probing if Nmap is absent.

Strictly validates subnets and prevents accidental scanning of unauthorized
or public external networks.
"""

import concurrent.futures
import ipaddress
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core.logger import get_logger
from core.report_generator import AssessmentSession
from core.subprocess_manager import SubprocessManager
from core.ui import (
    COLOR_BRAND, COLOR_BRAND_ALT, COLOR_INFO, COLOR_SUCCESS,
    COLOR_WARN, display_error, display_info, display_section_header,
    display_success, display_warning
)
from core.validator import ValidationError, is_private_subnet, validate_cidr
from modules.ip_information import get_network_configuration

logger = get_logger("kibuo.network_scanner")
console = Console()


def scan_host_quick_ports(ip: str, timeout: float = 0.4) -> List[int]:
    """Check common management & service ports on an active host."""
    target_ports = [21, 22, 23, 53, 80, 139, 443, 445, 3389, 8080]
    open_ports = []
    for port in target_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports


def run_network_scanner_module() -> List[Dict[str, Any]]:
    """
    Interactive execution handler for Network Scanner module.
    """
    display_section_header("Local Network Scanner", "Authorized subnet host mapping, port sweeps, and active service discovery")

    # Step 1: Detect local interface, IP and subnet
    net_config = get_network_configuration()
    detected_iface = net_config.get("interface", "eth0")
    detected_ip = net_config.get("ipv4", "192.168.1.100")
    detected_cidr = net_config.get("subnet_cidr", "192.168.1.0/24")

    console.print(f"[bold cyan]Local Network Topology:[/bold cyan]")
    console.print(f"  • Active Interface : [bold white]{detected_iface}[/bold white]")
    console.print(f"  • Local IPv4 Host  : [bold green]{detected_ip}[/bold green]")
    console.print(f"  • Subnet Range     : [bold yellow]{detected_cidr}[/bold yellow]")
    console.print()

    # Step 2: Prompt for target subnet
    subnet_input = Prompt.ask(
        f"[bold {COLOR_BRAND}]Enter authorized subnet to scan (CIDR format)[/bold {COLOR_BRAND}]",
        default=detected_cidr if detected_cidr != "N/A" else "192.168.1.0/24"
    ).strip()

    try:
        validated_cidr = str(validate_cidr(subnet_input))
    except ValidationError as err:
        display_error(str(err))
        return []

    # Step 3: Prevent accidental scanning of public or unauthorized networks
    if not is_private_subnet(validated_cidr):
        display_warning(f"SECURITY POLICY ALERT: The target network '{validated_cidr}' is NOT a private local subnet!")
        display_warning("Scanning non-private / public networks without explicit written contracts is illegal.")
        console.print("[bold red]Confirmation required:[/bold red] To proceed, type [bold white]'I CONFIRM AUTHORIZATION'[/bold white] or press Enter to cancel.")
        user_conf = Prompt.ask("Your confirmation", default="").strip()
        if user_conf != "I CONFIRM AUTHORIZATION":
            display_info("Scan aborted by defensive policy enforcement.")
            return []

    # Step 4: Scan Execution
    start_time = time.time()
    session = AssessmentSession(target=validated_cidr, module_name="Network Scanner")
    has_nmap = SubprocessManager.is_binary_available("nmap")

    active_hosts: List[Dict[str, Any]] = []

    if has_nmap:
        display_info(f"Using Nmap scanning engine against {validated_cidr}...")
        cmd = ["nmap", "-sn", "-T4", validated_cidr]
        with console.status(f"[bold {COLOR_BRAND}]Running Nmap host sweep...[/bold {COLOR_BRAND}]"):
            res = SubprocessManager.execute(cmd, timeout=180)

        current_ip = None
        for line in res.stdout.splitlines():
            if "Nmap scan report for" in line:
                parts = line.split()
                current_ip = parts[-1].strip("()")
            elif "Host is up" in line and current_ip:
                active_hosts.append({
                    "ip": current_ip,
                    "method": "Nmap Ping Sweep",
                    "open_ports": []
                })
                current_ip = None
    else:
        display_info(f"Nmap not installed; deploying native multi-threaded socket probe...")
        net = ipaddress.IPv4Network(validated_cidr, strict=False)
        all_ips = [str(h) for h in net.hosts()][:256]

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Probing subnet hosts...", total=len(all_ips))

            def probe_host(ip):
                # Try ping
                p = SubprocessManager.execute(["ping", "-c", "1", "-W", "1", ip], timeout=2)
                if p.is_ok():
                    return ip
                # Fallback socket check
                for port in (80, 443, 22, 53, 445):
                    try:
                        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                            sock.settimeout(0.3)
                            if sock.connect_ex((ip, port)) == 0:
                                return ip
                    except Exception:
                        pass
                return None

            with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
                futures = {executor.submit(probe_host, ip): ip for ip in all_ips}
                for fut in concurrent.futures.as_completed(futures):
                    res_ip = fut.result()
                    if res_ip:
                        active_hosts.append({
                            "ip": res_ip,
                            "method": "ICMP / TCP Fallback",
                            "open_ports": []
                        })
                    progress.advance(task, 1)

    # Optional port scan on discovered hosts
    if active_hosts and Confirm.ask("\nCheck key management ports (21, 22, 23, 53, 80, 139, 443, 445, 3389, 8080) on discovered hosts?", default=True):
        with console.status(f"[bold {COLOR_BRAND}]Checking service ports on active hosts...[/bold {COLOR_BRAND}]"):
            for h in active_hosts:
                h["open_ports"] = scan_host_quick_ports(h["ip"])

    duration = time.time() - start_time

    # Render results table
    console.print()
    if active_hosts:
        display_success(f"Network scan finished in {duration:.2f}s. Discovered {len(active_hosts)} active host(s).")
        result_table = Table(title=f"Active Network Hosts ({validated_cidr})", box=None)
        result_table.add_column("Host IP", style="bold green", width=18)
        result_table.add_column("Discovery Engine", style="cyan", width=22)
        result_table.add_column("Open Service Ports", style="yellow")
        result_table.add_column("Link State", style="bold green")

        for h in active_hosts:
            ports_str = ", ".join(map(str, h["open_ports"])) if h["open_ports"] else "None detected"
            result_table.add_row(h["ip"], h["method"], ports_str, "ONLINE")
        console.print(result_table)
    else:
        display_warning(f"No responding hosts discovered on subnet {validated_cidr}.")

    reports = session.finalize(
        status="Completed",
        summary_data={
            "subnet": validated_cidr,
            "hosts_count": len(active_hosts),
            "hosts": active_hosts
        },
        duration_seconds=duration
    )
    console.print()
    display_info(f"Scan report written: {reports['report_txt']}")

    return active_hosts

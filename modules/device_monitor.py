"""
Live Device Monitoring Module for Kibuo (Fing-Inspired Network Engine).

Performs real-time state tracking of authorized local network hosts.
Monitors reachability transitions, logs online/offline events with timestamps,
avoids excessive network flooding through rate-limiting, and handles keyboard
interrupts (Ctrl+C) gracefully to return cleanly to menus.
"""

import socket
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

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

logger = get_logger("kibuo.device_monitor")
console = Console()


def check_host_reachable(ip: str, timeout: float = 0.5) -> bool:
    """
    Lightweight, low-overhead reachability check.
    Uses a 1-packet ping with 1s timeout, followed by a fast TCP probe if needed.
    """
    res = SubprocessManager.execute(["ping", "-c", "1", "-W", "1", ip], timeout=2)
    if res.is_ok():
        return True

    # Secondary check on port 80 / 443 / 53 / 22 in case ICMP is dropped
    for port in (80, 443, 53, 22):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((ip, port)) == 0:
                    return True
        except Exception:
            pass

    return False


def run_device_monitor_module(discovered_devices: Optional[List[Dict[str, Any]]] = None) -> None:
    """
    Interactive execution handler for Live Device Monitoring.
    """
    display_section_header("Live Device Monitoring", "Real-time state and connection transition tracker for local hosts")

    monitored_ips: List[str] = []

    # Check existing discovered devices
    if discovered_devices:
        monitored_ips = [dev["ip"] for dev in discovered_devices if dev.get("ip")]

    if not monitored_ips:
        display_warning("No active devices in memory to monitor.")
        user_input = Prompt.ask(
            "[bold white]Enter IP addresses to monitor (comma-separated, e.g. 192.168.100.1, 192.168.100.111)[/bold white]"
        ).strip()
        if not user_input:
            display_info("No targets entered. Returning to menu.")
            return
        monitored_ips = [ip.strip() for ip in user_input.split(",") if ip.strip()]

    # Configurable monitoring interval
    interval_str = Prompt.ask(
        f"[bold {COLOR_BRAND}]Enter monitoring interval in seconds (5-60)[/bold {COLOR_BRAND}]",
        default="10"
    ).strip()
    try:
        interval = max(3, min(300, int(interval_str)))
    except ValueError:
        interval = 10

    console.print()
    display_info(f"Monitoring [bold white]{len(monitored_ips)}[/bold white] host(s) every [bold white]{interval}s[/bold white].")
    console.print("[dim]Press Ctrl+C at any time to pause or exit monitoring safely.[/dim]\n")

    # Host tracking state
    # ip -> {"status": "Online"|"Offline", "last_seen": timestamp_str, "flips": int}
    state: Dict[str, Dict[str, Any]] = {}
    for ip in monitored_ips:
        state[ip] = {
            "status": "Unknown",
            "last_seen": "Never",
            "first_seen": datetime.now().strftime("%H:%M:%S"),
            "transitions": 0
        }

    iteration = 0
    try:
        while True:
            iteration += 1
            now_str = datetime.now().strftime("%H:%M:%S")

            for ip in monitored_ips:
                is_up = check_host_reachable(ip)
                prev_status = state[ip]["status"]

                if is_up:
                    state[ip]["last_seen"] = now_str
                    if prev_status != "Online":
                        state[ip]["status"] = "Online"
                        state[ip]["transitions"] += 1
                        console.print(f"[bold green][+] Device Online :[/bold green] [bold white]{ip:<16}[/bold white] [dim][*] Last Seen: {now_str}[/dim]")
                else:
                    if prev_status == "Online":
                        state[ip]["status"] = "Offline"
                        state[ip]["transitions"] += 1
                        console.print(f"[bold red][-] Device Offline:[/bold red] [bold white]{ip:<16}[/bold white] [dim][*] Last Seen: {state[ip]['last_seen']}[/dim]")
                    elif prev_status == "Unknown":
                        state[ip]["status"] = "Offline"

            # Sleep cleanly in small slices to respond swiftly to Ctrl+C
            for _ in range(interval * 2):
                time.sleep(0.5)

    except KeyboardInterrupt:
        console.print()
        display_warning("Monitoring paused by user (Ctrl+C).")

    # Display final status summary table
    console.print()
    table = Table(title="Live Device Monitoring Session Summary", box=None)
    table.add_column("Monitored IP", style="bold green", width=18)
    table.add_column("Current Status", style="white", width=14)
    table.add_column("Last Seen Timestamp", style="cyan", width=22)
    table.add_column("Status Changes", style="yellow")

    for ip, data in state.items():
        st = data["status"]
        st_style = "bold green" if st == "Online" else "bold red"
        table.add_row(
            ip,
            f"[{st_style}]{st}[/{st_style}]",
            data["last_seen"],
            str(data["transitions"])
        )

    console.print(table)
    console.print()

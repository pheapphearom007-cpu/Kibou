"""
Internet Speed and Network Latency Testing Module for Kibuo.

Measures download throughput, upload throughput, round-trip latency, and jitter.
Operates strictly with explicit user authorization, provides real-time progress
feedback, and formats all bandwidth calculations in standard Mbps.
"""

import re
import socket
import time
import urllib.request
from typing import Any, Dict, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core.logger import get_logger
from core.subprocess_manager import SubprocessManager
from core.ui import (
    COLOR_BRAND, COLOR_BRAND_ALT, COLOR_INFO, COLOR_SUCCESS,
    COLOR_WARN, display_error, display_info, display_section_header,
    display_success, display_warning
)

logger = get_logger("kibuo.speed_test")
console = Console()

SPEED_HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Kibuo-Network-Suite/1.0"}


def check_internet_connectivity() -> bool:
    """Verify outbound internet connectivity before starting tests."""
    for host, port in [("1.1.1.1", 53), ("8.8.8.8", 53), ("speed.cloudflare.com", 443)]:
        try:
            with socket.create_connection((host, port), timeout=2.5):
                return True
        except Exception:
            pass
    return False


def measure_latency_and_jitter(target_host: str = "1.1.1.1", count: int = 5) -> Tuple[float, float]:
    """
    Measure average round-trip latency (ms) and jitter (mdev in ms).
    Uses system ping statistics if available, falling back to HTTP connection timing.
    """
    cmd = ["ping", "-c", str(count), "-q", "-W", "2", target_host]
    res = SubprocessManager.execute(cmd, timeout=12)

    if res.is_ok() and "rtt min/avg/max/mdev" in res.stdout:
        # e.g.: rtt min/avg/max/mdev = 4.040/6.565/10.876/2.308 ms
        match = re.search(r"=\s*([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)\s*ms", res.stdout)
        if match:
            avg_latency = float(match.group(2))
            jitter = float(match.group(4))
            return avg_latency, jitter

    # Fallback to HTTP HEAD handshake measurement
    samples = []
    for _ in range(count):
        t0 = time.time()
        try:
            req = urllib.request.Request("https://1.1.1.1", headers=SPEED_HEADERS)
            with urllib.request.urlopen(req, timeout=3):
                pass
            samples.append((time.time() - t0) * 1000)
        except Exception:
            pass
        time.sleep(0.1)

    if samples:
        avg_lat = sum(samples) / len(samples)
        jitter_val = sum(abs(x - avg_lat) for x in samples) / len(samples)
        return avg_lat, jitter_val

    return 0.0, 0.0


def measure_download_speed(byte_target: int = 10000000) -> float:
    """
    Download a controlled byte stream from Cloudflare speed test CDN.
    Returns download speed in Mbps.
    """
    url = f"https://speed.cloudflare.com/__down?bytes={byte_target}"
    req = urllib.request.Request(url, headers=SPEED_HEADERS)

    start = time.time()
    with urllib.request.urlopen(req, timeout=15) as resp:
        content = resp.read()
    duration = time.time() - start

    if duration <= 0:
        return 0.0

    bytes_transferred = len(content)
    mbps = (bytes_transferred * 8) / (duration * 1_000_000)
    return mbps


def measure_upload_speed(payload_bytes: int = 2097152) -> float:
    """
    POST a temporary byte payload to speed test server to evaluate uplink throughput.
    Returns upload speed in Mbps.
    """
    url = "https://speed.cloudflare.com/__up"
    data = b"0" * payload_bytes
    req = urllib.request.Request(
        url,
        data=data,
        headers={**SPEED_HEADERS, "Content-Type": "application/octet-stream"},
        method="POST"
    )

    start = time.time()
    with urllib.request.urlopen(req, timeout=15) as resp:
        resp.read()
    duration = time.time() - start

    if duration <= 0:
        return 0.0

    mbps = (payload_bytes * 8) / (duration * 1_000_000)
    return mbps


def run_speed_test_module() -> Optional[Dict[str, Any]]:
    """
    Interactive execution handler for Internet Speed Test.
    """
    display_section_header("Internet Speed & Latency Test", "Evaluate bandwidth throughput (Mbps), latency (RTT), and jitter")

    console.print(f"[bold {COLOR_BRAND}]User Authorization & Data Transfer Notice:[/bold {COLOR_BRAND}]")
    console.print("  • Testing involves downloading and uploading temporary measurement chunks (~12 MB).")
    console.print("  • No user data or confidential system details are transmitted.")
    console.print("  • You may safely cancel or skip this test at any time.")
    console.print()

    if not Confirm.ask("[bold yellow]Do you authorize running the internet speed test?[/bold yellow]", default=True):
        display_info("Speed test cancelled by user.")
        return None

    # Step 1: Internet connectivity check
    with console.status("[bold cyan]Checking internet uplink connection...[/bold cyan]"):
        is_connected = check_internet_connectivity()

    if not is_connected:
        display_error("No active internet connection detected. Check your network gateway or DNS.")
        return None

    results: Dict[str, Any] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        # Step 2: Latency & Jitter
        task1 = progress.add_task("[yellow]Measuring latency and jitter (1.1.1.1)...", total=100)
        avg_latency, jitter = measure_latency_and_jitter()
        results["latency_ms"] = avg_latency
        results["jitter_ms"] = jitter
        progress.update(task1, completed=100)

        # Step 3: Download Test
        task2 = progress.add_task("[cyan]Measuring download throughput...", total=100)
        try:
            dl_mbps = measure_download_speed(byte_target=10_000_000)
            results["download_mbps"] = dl_mbps
        except Exception as exc:
            logger.warning("Download test failed: %s", exc)
            results["download_mbps"] = 0.0
        progress.update(task2, completed=100)

        # Step 4: Upload Test
        task3 = progress.add_task("[green]Measuring upload throughput...", total=100)
        try:
            ul_mbps = measure_upload_speed(payload_bytes=2_097_152)
            results["upload_mbps"] = ul_mbps
        except Exception as exc:
            logger.warning("Upload test failed: %s", exc)
            results["upload_mbps"] = 0.0
        progress.update(task3, completed=100)

    # Render summary card
    console.print()
    table = Table(title="Internet Speed Test Performance Briefing", box=None)
    table.add_column("Performance Metric", style="bold cyan", width=24)
    table.add_column("Measured Value", style="white")

    table.add_row("Ping Latency (RTT)", f"[bold white]{results['latency_ms']:.2f} ms[/bold white]")
    table.add_row("Connection Jitter", f"{results['jitter_ms']:.2f} ms")
    table.add_row("Download Throughput", f"[bold green]{results['download_mbps']:.2f} Mbps[/bold green]")
    table.add_row("Upload Throughput", f"[bold cyan]{results['upload_mbps']:.2f} Mbps[/bold cyan]")

    console.print(Panel(table, border_style=COLOR_SUCCESS, title="[bold bright_green]Speed Test Results[/bold bright_green]"))
    console.print()

    return results

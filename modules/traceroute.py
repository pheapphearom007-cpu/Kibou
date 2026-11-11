"""
Traceroute and Network Path Analysis Module for Kibuo.

Module [10]: Traceroute & Path Analysis
Traces packet transit hops, measures round-trip latency, handles unanswering nodes,
and exports structured routing path intelligence.
"""

import re
import socket
import time
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from core.logger import get_logger
from core.report_generator import AssessmentSession
from core.subprocess_manager import SubprocessManager
from core.ui import (
    COLOR_BRAND, COLOR_ERROR, COLOR_INFO, COLOR_SUCCESS,
    COLOR_WARN, display_error, display_info, display_section_header,
    display_success, display_warning
)
from core.validator import ValidationError, validate_target

logger = get_logger("kibuo.traceroute")
console = Console()

HOP_REGEX = re.compile(
    r"^\s*(\d+)\s+([a-zA-Z0-9_\-\.]+)?\s*(?:\(([0-9a-fA-F\.\:]+)\))?\s+([\d\.]+\s*ms|\*)"
)


def parse_traceroute_output(output: str) -> List[Dict[str, str]]:
    """
    Parse standard traceroute output into structured list of hops.
    """
    hops: List[Dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("traceroute") or line.startswith("traceroute to"):
            continue

        parts = line.split()
        if not parts:
            continue

        # Look for hop number at start
        hop_num_str = parts[0]
        if not hop_num_str.isdigit():
            continue

        hop_num = int(hop_num_str)
        rest = " ".join(parts[1:])

        if "*" in rest and ("ms" not in rest):
            hops.append({
                "hop": str(hop_num),
                "host": "*",
                "ip": "* (Request timed out / ICMP Filtered)",
                "rtt": "*"
            })
            continue

        # Find ms timings and IP
        ip_match = re.search(r"\(?(\b\d{1,3}(?:\.\d{1,3}){3}\b)\)?", rest)
        rtt_match = re.search(r"(\d+(?:\.\d+)?\s*ms)", rest)

        ip_addr = ip_match.group(1) if ip_match else parts[1]
        host = parts[1] if parts[1] != ip_addr else ""
        rtt = rtt_match.group(1) if rtt_match else "N/A"

        hops.append({
            "hop": str(hop_num),
            "host": host or "-",
            "ip": ip_addr,
            "rtt": rtt
        })

    return hops


def run_traceroute_module() -> None:
    """
    Interactive execution handler for Module [10] Traceroute & Path Analysis.
    """
    display_section_header("Module [10]: Traceroute & Path Analysis", "Route hop inspection and intermediate network latency analysis")

    target_input = Prompt.ask(f"[bold {COLOR_BRAND}]Enter Target Host (IPv4 or Domain, e.g. 8.8.8.8 or example.com)[/bold {COLOR_BRAND}]")
    try:
        _, validated_target = validate_target(target_input)
    except ValidationError as err:
        display_error(str(err))
        return

    session = AssessmentSession(target=validated_target, module_name="Traceroute Path Analysis")
    start_time = time.time()
    raw_output = ""
    hops: List[Dict[str, str]] = []

    has_traceroute = SubprocessManager.is_binary_available("traceroute")
    has_mtr = SubprocessManager.is_binary_available("mtr")
    has_nmap = SubprocessManager.is_binary_available("nmap")

    with console.status(f"[bold {COLOR_BRAND}]Tracing route hops to {validated_target} (max 30 hops)...[/bold {COLOR_BRAND}]"):
        if has_traceroute:
            # -m 30: max 30 hops, -w 2: 2s timeout, -q 1: 1 probe per hop for speed
            cmd = ["traceroute", "-m", "30", "-w", "2", "-q", "1", validated_target]
            res = SubprocessManager.execute(cmd, timeout=90)
            raw_output = res.stdout + ("\n" + res.stderr if res.stderr else "")
            hops = parse_traceroute_output(res.stdout)
        elif has_mtr:
            cmd = ["mtr", "--report", "--report-cycles", "1", "-n", validated_target]
            res = SubprocessManager.execute(cmd, timeout=60)
            raw_output = res.stdout
            # Parse mtr tabular output
            for line in res.stdout.splitlines()[2:]:
                parts = line.split()
                if len(parts) >= 2 and parts[0].isdigit():
                    hops.append({
                        "hop": parts[0],
                        "host": "-",
                        "ip": parts[1],
                        "rtt": f"{parts[-1]} ms" if len(parts) >= 7 else "N/A"
                    })
        elif has_nmap:
            # Fallback using nmap traceroute
            cmd = ["nmap", "-sn", "--traceroute", validated_target]
            res = SubprocessManager.execute(cmd, timeout=60)
            raw_output = res.stdout
            for line in res.stdout.splitlines():
                if line.strip().startswith("HOP") or "TRACEROUTE" in line:
                    continue
                parts = line.split()
                if len(parts) >= 3 and parts[0].isdigit():
                    hops.append({
                        "hop": parts[0],
                        "host": parts[-1] if len(parts) > 3 else "-",
                        "ip": parts[1],
                        "rtt": parts[2]
                    })
        else:
            display_error("Neither traceroute, mtr, nor nmap is installed.")
            display_info("Install traceroute via: sudo apt install traceroute")
            return

    duration = time.time() - start_time

    # Save artifacts
    session.write_artifact("traceroute_output.txt", raw_output)
    session.write_json_artifact("traceroute_hops.json", hops)

    console.print()
    if hops:
        display_success(f"Route trace completed ({len(hops)} hops traversed):")
        tbl = Table(title=f"Path Analysis: {validated_target}", box=None)
        tbl.add_column("Hop #", style="dim", width=6)
        tbl.add_column("IP Address / Hop Node", style="bold white", width=36)
        tbl.add_column("Hostname", style="cyan", width=28)
        tbl.add_column("Latency / RTT", style="bold green", width=16)

        for h in hops:
            ip_val = h["ip"]
            ip_style = "[yellow]* (Blocked / Filtered)[/yellow]" if "*" in ip_val else f"[bold white]{ip_val}[/bold white]"
            tbl.add_row(h["hop"], ip_style, h["host"], h["rtt"])

        console.print(tbl)
    else:
        display_warning("No traceroute hops were recorded.")

    reports = session.finalize(
        status="Completed",
        summary_data={
            "target": validated_target,
            "total_hops": len(hops),
            "hops": hops
        },
        duration_seconds=duration
    )
    console.print()
    display_info(f"Artifacts saved to: {reports['report_txt']}")

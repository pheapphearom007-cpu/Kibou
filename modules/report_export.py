"""
Network Report Exporter Module for Kibuo (Fing-Inspired Network Engine).

Exports network asset discovery, device classification, and telemetry results
into TXT, JSON, and CSV formats under reports/.
Prompts for user confirmation before committing sensitive network data to disk.
"""

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core.logger import get_logger
from core.report_generator import sanitize_filename
from core.ui import (
    COLOR_BRAND, COLOR_BRAND_ALT, COLOR_INFO, COLOR_SUCCESS,
    COLOR_WARN, display_error, display_info, display_section_header,
    display_success, display_warning
)
from modules.device_identification import classify_device
from modules.ip_information import get_network_configuration

logger = get_logger("kibuo.report_export")
console = Console()

REPORTS_DIR = Path("reports")


def generate_txt_report(
    metadata: Dict[str, Any],
    devices: List[Dict[str, Any]]
) -> str:
    """Generate professional plain-text network assessment briefing."""
    lines = [
        "=" * 78,
        "  KIBUO CYBERSECURITY TOOLKIT — NETWORK DISCOVERY REPORT",
        "=" * 78,
        f"Generated At    : {metadata.get('timestamp')}",
        f"Interface       : {metadata.get('interface')}",
        f"Target Subnet   : {metadata.get('subnet')}",
        f"Default Gateway : {metadata.get('gateway')}",
        f"DNS Servers     : {', '.join(metadata.get('dns', []))}",
        f"Total Devices   : {len(devices)}",
        "-" * 86,
        f"{'IP ADDRESS':<17} {'MAC ADDRESS':<19} {'CATEGORY (CONF)':<20} {'VENDOR':<28}",
        "-" * 86,
    ]

    for d in devices:
        cat_conf = f"{d.get('category', 'Unknown')} ({d.get('confidence', 'Low')})"
        lines.append(
            f"{d.get('ip', ''):<17} {d.get('mac', 'Unknown'):<19} {cat_conf:<20} {d.get('vendor', 'Unknown')[:28]:<28}"
        )
        if d.get("hostname") and d.get("hostname") != "Unknown":
            lines.append(f"   ↳ Hostname: {d.get('hostname')}")
        if d.get("evidence"):
            ev_str = "; ".join(d["evidence"][:2])
            lines.append(f"   ↳ Evidence: {ev_str}")

    lines.extend([
        "-" * 78,
        "DEFENSIVE NOTICE:",
        "This report contains authorized network discovery telemetry for internal auditing.",
        "=" * 78,
    ])
    return "\n".join(lines)


def export_network_report(
    discovered_devices: List[Dict[str, Any]],
    subnet: str,
    interface: str
) -> Dict[str, str]:
    """
    Export discovery findings to TXT, JSON, and CSV formats.
    
    Returns:
        Dict mapping format name to output file path.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = sanitize_filename(subnet)

    net_config = get_network_configuration()
    metadata = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "subnet": subnet,
        "interface": interface,
        "gateway": net_config.get("gateway", "N/A"),
        "dns": net_config.get("dns_servers", []),
        "device_count": len(discovered_devices)
    }

    # Ensure devices are enriched with classification
    enriched_devices = []
    for d in discovered_devices:
        enriched = dict(d)
        if "category" not in enriched:
            classified = classify_device(
                ip=d.get("ip", ""),
                mac=d.get("mac", ""),
                hostname=d.get("hostname", ""),
                vendor=d.get("vendor", ""),
                is_gateway=(d.get("ip") == net_config.get("gateway")),
                open_ports=d.get("open_ports", [])
            )
            enriched["category"] = classified["category"]
            enriched["confidence"] = classified["confidence"]
            enriched["evidence"] = classified["evidence"]
        enriched_devices.append(enriched)

    exported_files: Dict[str, str] = {}

    # 1. TXT Export
    txt_filename = f"{safe_target}_{ts}_network.txt"
    txt_path = REPORTS_DIR / txt_filename
    txt_content = generate_txt_report(metadata, enriched_devices)
    txt_path.write_text(txt_content, encoding="utf-8")
    exported_files["TXT"] = str(txt_path)

    # 2. JSON Export
    json_filename = f"{safe_target}_{ts}_network.json"
    json_path = REPORTS_DIR / json_filename
    json_payload = {
        "metadata": metadata,
        "devices": enriched_devices
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(json_payload, f, indent=2)
    exported_files["JSON"] = str(json_path)

    # 3. CSV Export
    csv_filename = f"{safe_target}_{ts}_network.csv"
    csv_path = REPORTS_DIR / csv_filename
    fieldnames = [
        "ip", "mac", "hostname", "vendor",
        "category", "confidence", "status", "last_seen"
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for dev in enriched_devices:
            writer.writerow({
                "ip": dev.get("ip", ""),
                "mac": dev.get("mac", ""),
                "hostname": dev.get("hostname", ""),
                "vendor": dev.get("vendor", ""),
                "category": dev.get("category", "Unknown Device"),
                "confidence": dev.get("confidence", "Low"),
                "status": dev.get("status", "Active"),
                "last_seen": metadata["timestamp"]
            })
    exported_files["CSV"] = str(csv_path)

    return exported_files


def run_report_export_module(
    discovered_devices: Optional[List[Dict[str, Any]]] = None,
    subnet: Optional[str] = None
) -> None:
    """
    Interactive execution handler for Report Export module.
    """
    display_section_header("Export Network Report", "Save discovery findings to structured TXT, JSON, and CSV formats")

    devices = list(discovered_devices) if discovered_devices else []
    if not devices:
        display_warning("No active device discovery findings in memory to export.")
        display_info("Please run [1. Device Discovery] or [2. Network Scanner] first.")
        return

    net_config = get_network_configuration()
    target_subnet = subnet or net_config.get("subnet_cidr", "192.168.1.0/24")
    target_iface = net_config.get("interface", "eth0")

    console.print(f"[bold cyan]Export Inventory Summary:[/bold cyan]")
    console.print(f"  • Subnet Scope    : [bold white]{target_subnet}[/bold white]")
    console.print(f"  • Device Findings : [bold green]{len(devices)} device(s)[/bold green]")
    console.print(f"  • Destination     : [yellow]reports/[/yellow]")
    console.print()

    # User confirmation before exporting sensitive internal topology
    if not Confirm.ask("Do you confirm exporting network telemetry to local disk (TXT, JSON, CSV)?", default=True):
        display_info("Export cancelled by user.")
        return

    with console.status(f"[bold {COLOR_BRAND}]Exporting network discovery reports...[/bold {COLOR_BRAND}]"):
        exported = export_network_report(devices, subnet=target_subnet, interface=target_iface)

    console.print()
    display_success("Network reports exported successfully:")
    for fmt, path_str in exported.items():
        console.print(f"  • [bold cyan]{fmt:<5}[/bold cyan] : [bold white]{path_str}[/bold white]")
    console.print()

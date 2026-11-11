"""
IP Intelligence and Geolocation OSINT Module for Kibuo.

Module [08]: IP Intelligence
Retrieves ASN, ISP, Geographic region, and approximate coordinates for public IPv4 addresses
via ip-api.com, with rate-limiting protection, private IP filtering, and privacy disclaimers.
"""

import json
import socket
import time
from typing import Any, Dict, Optional, Tuple

import requests
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

from core.logger import get_logger
from core.report_generator import AssessmentSession
from core.ui import (
    COLOR_BRAND, COLOR_ERROR, COLOR_INFO, COLOR_SUCCESS,
    COLOR_WARN, display_error, display_info, display_section_header,
    display_success, display_warning
)
from core.validator import ValidationError, is_private_ip, validate_target

logger = get_logger("kibuo.ip_intelligence")
console = Console()

API_ENDPOINT = "http://ip-api.com/json/{query}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"


def query_ip_intelligence(ip_or_domain: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Query public IP intelligence API for autonomous system, ISP, and approximate location.
    Handles network errors, rate limits (45 req/min on free ip-api tier), and private addresses.
    """
    resolved_ip = ip_or_domain
    
    # Resolve domain to IP if domain provided
    try:
        resolved_ip = socket.gethostbyname(ip_or_domain)
    except socket.gaierror as err:
        return {
            "status": "fail",
            "message": f"Could not resolve domain '{ip_or_domain}' to IPv4: {err}",
            "query": ip_or_domain
        }

    # Verify if private/RFC1918
    if is_private_ip(resolved_ip):
        return {
            "status": "private",
            "message": f"Address '{resolved_ip}' is a private, loopback, or link-local RFC1918 address.",
            "query": resolved_ip,
            "is_private": True
        }

    url = API_ENDPOINT.format(query=resolved_ip)
    try:
        response = requests.get(
            url,
            headers={"User-Agent": "Kibuo-Recon/1.0 (Security-Auditing)"},
            timeout=timeout
        )
        if response.status_code == 429:
            return {
                "status": "fail",
                "message": "Public API rate limit exceeded (ip-api.com allows max 45 queries/min).",
                "query": resolved_ip
            }
        if response.status_code != 200:
            return {
                "status": "fail",
                "message": f"API returned HTTP status {response.status_code}",
                "query": resolved_ip
            }
        data = response.json()
        data["resolved_from"] = ip_or_domain
        return data

    except requests.exceptions.Timeout:
        return {
            "status": "fail",
            "message": f"Connection timed out after {timeout} seconds connecting to intelligence API.",
            "query": resolved_ip
        }
    except requests.exceptions.RequestException as exc:
        return {
            "status": "fail",
            "message": f"Network error contacting intelligence provider: {str(exc)}",
            "query": resolved_ip
        }
    except Exception as exc:
        return {
            "status": "fail",
            "message": f"Unexpected error during intelligence query: {str(exc)}",
            "query": resolved_ip
        }


def run_ip_intelligence_module() -> None:
    """
    Interactive execution handler for Module [08] IP Intelligence.
    """
    display_section_header("Module [08]: IP Intelligence & Geolocation", "Autonomous System (ASN), ISP, and approximate geographic routing")

    target_input = Prompt.ask(f"[bold {COLOR_BRAND}]Enter Public IPv4 Address or Domain (e.g. 1.1.1.1 or cloudflare.com)[/bold {COLOR_BRAND}]")
    try:
        target_type, validated_target = validate_target(target_input)
    except ValidationError as err:
        display_error(str(err))
        return

    session = AssessmentSession(target=validated_target, module_name="IP Intelligence")
    start_time = time.time()

    with console.status(f"[bold {COLOR_BRAND}]Querying IP intelligence for {validated_target}...[/bold {COLOR_BRAND}]"):
        data = query_ip_intelligence(validated_target)

    duration = time.time() - start_time
    session.write_json_artifact("ip_intelligence.json", data)

    console.print()
    if data.get("status") == "private":
        display_warning(f"Private Network Address Detected: {data['query']}")
        console.print(Panel(
            "RFC1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) and loopback addresses "
            "are routed strictly within local or corporate network topologies and cannot be resolved "
            "by global public WHOIS/BGP routing databases.",
            title="Private IP Notice",
            box=None
        ))
        session.finalize(status="Private IP Address", summary_data=data, duration_seconds=duration)
        return

    if data.get("status") != "success":
        display_error(f"Failed to retrieve intelligence: {data.get('message', 'Unknown error')}")
        session.finalize(status="Failed", summary_data=data, duration_seconds=duration)
        return

    display_success(f"IP Intelligence successfully retrieved for {data.get('query')}:")

    # Disclaimer panel
    console.print(Panel(
        "[dim]DISCLAIMER: IP geolocation represents approximate ISP routing points and regional "
        "autonomous network allocations. It does NOT represent exact physical GPS coordinates or user tracking.[/dim]",
        box=None
    ))

    # Display clean table
    tbl = Table(title=f"IP Intelligence: {data.get('query')}", box=None)
    tbl.add_column("Property", style="bold cyan", width=18)
    tbl.add_column("Details", style="bold white")

    tbl.add_row("IP Address", data.get("query", "Unknown"))
    if "resolved_from" in data and data["resolved_from"] != data.get("query"):
        tbl.add_row("Resolved From", data["resolved_from"])
    tbl.add_row("Country", f"{data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})")
    tbl.add_row("Region / State", f"{data.get('regionName', 'N/A')} ({data.get('region', 'N/A')})")
    tbl.add_row("City", data.get("city", "N/A"))
    tbl.add_row("Postal / Zip", data.get("zip", "N/A"))
    tbl.add_row("Approx. Coordinates", f"{data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
    tbl.add_row("Timezone", data.get("timezone", "N/A"))
    tbl.add_row("ISP Provider", data.get("isp", "N/A"))
    tbl.add_row("Organization", data.get("org", "N/A"))
    tbl.add_row("Autonomous System (AS)", data.get("as", "N/A"))

    console.print(tbl)

    reports = session.finalize(
        status="Completed",
        summary_data=data,
        duration_seconds=duration
    )
    console.print()
    display_info(f"Intelligence artifact saved to: {reports['report_txt']}")

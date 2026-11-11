"""
Web Application Reconnaissance Module for Kibuo.

Module [11]: Nmap + Web Recon
Identifies HTTP/HTTPS services, evaluates response headers, performs technology
fingerprinting via WhatWeb/curl, audits essential security headers, and provides
optional confirmed Nikto vulnerability checks.
"""

import json
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

# Suppress unverified TLS warnings during reconnaissance
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
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

logger = get_logger("kibuo.web_recon")
console = Console()

COMMON_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000]

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "Enforces HTTPS connections and guards against SSL stripping"),
    ("Content-Security-Policy", "Restricts resource loading to mitigate XSS and data injection"),
    ("X-Frame-Options", "Prevents clickjacking attacks via framing / iframes"),
    ("X-Content-Type-Options", "Prevents MIME-sniffing attacks (nosniff)"),
    ("Referrer-Policy", "Controls referrer disclosure in outgoing requests"),
    ("Permissions-Policy", "Controls browser features and hardware APIs"),
]


def check_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """Quick socket check to verify if a TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def probe_web_service(url: str, timeout: int = 8) -> Dict[str, Any]:
    """
    Perform deep HTTP inspection of target web endpoint.
    Extracts status code, redirect chains, headers, HTML title, and security headers.
    """
    data = {
        "url": url,
        "is_reachable": False,
        "status_code": None,
        "server_banner": "Unknown",
        "title": None,
        "redirect_history": [],
        "headers": {},
        "security_headers": {},
        "missing_security_headers": []
    }

    try:
        # Disable SSL verification warnings for reconnaissance of self-signed certs
        resp = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Kibuo-Recon/1.0"}
        )
        data["is_reachable"] = True
        data["status_code"] = resp.status_code
        data["server_banner"] = resp.headers.get("Server", "Undisclosed")
        data["headers"] = dict(resp.headers)

        if resp.history:
            data["redirect_history"] = [f"{r.status_code} -> {r.url}" for r in resp.history]

        # Extract title from HTML
        title_match = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
        if title_match:
            data["title"] = title_match.group(1).strip()

        # Audit security headers
        for h_name, h_desc in SECURITY_HEADERS:
            if h_name.lower() in [k.lower() for k in resp.headers.keys()]:
                # Locate exact casing value
                val = next(v for k, v in resp.headers.items() if k.lower() == h_name.lower())
                data["security_headers"][h_name] = val
            else:
                data["missing_security_headers"].append(h_name)

    except requests.exceptions.SSLError:
        data["error"] = "SSL / TLS Handshake Failure"
    except requests.exceptions.ConnectionError:
        data["error"] = "Connection Refused / Host Unreachable"
    except requests.exceptions.Timeout:
        data["error"] = f"Request timed out after {timeout} seconds"
    except Exception as exc:
        data["error"] = str(exc)

    return data


def run_whatweb_inspection(url: str) -> Optional[str]:
    """Execute whatweb if available on the system."""
    if not SubprocessManager.is_binary_available("whatweb"):
        return None
    # Run whatweb with color=never and brief summary mode
    res = SubprocessManager.execute(["whatweb", "--color=never", "-a", "1", url], timeout=30)
    if res.is_ok():
        return res.stdout.strip()
    return None


def run_nikto_scan(target_host: str, port: int) -> Optional[str]:
    """Execute Nikto web scanner on verified authorized target and port."""
    if not SubprocessManager.is_binary_available("nikto"):
        return "Nikto binary is not installed."
    
    cmd = ["nikto", "-h", target_host, "-p", str(port), "-Tuning", "1,2,3,4,8,9,0", "-maxtime", "180s"]
    res = SubprocessManager.execute(cmd, timeout=240)
    return res.stdout or res.stderr


def run_web_recon_module(target_host: Optional[str] = None) -> None:
    """
    Interactive execution handler for Module [11] Web Recon.
    """
    display_section_header("Module [11]: Web Application Reconnaissance", "HTTP/HTTPS service discovery, security headers audit & WhatWeb fingerprinting")

    if not target_host:
        target_input = Prompt.ask(f"[bold {COLOR_BRAND}]Enter Target (IPv4 or Domain Name, e.g. example.com or 192.168.1.10)[/bold {COLOR_BRAND}]")
    else:
        target_input = target_host
    try:
        _, validated_target = validate_target(target_input)
    except ValidationError as err:
        display_error(str(err))
        return

    session = AssessmentSession(target=validated_target, module_name="Web Reconnaissance")
    start_time = time.time()

    # Step 1: Discover active web ports
    open_web_ports = []
    with console.status(f"[bold {COLOR_BRAND}]Probing common web ports on {validated_target}...[/bold {COLOR_BRAND}]"):
        for port in COMMON_WEB_PORTS:
            if check_port_open(validated_target, port, timeout=1.5):
                open_web_ports.append(port)

    if not open_web_ports:
        # Ask user if they have a custom web port
        display_warning(f"No standard web ports ({', '.join(map(str, COMMON_WEB_PORTS))}) were open on {validated_target}.")
        custom_port = Prompt.ask(
            "Enter custom web port to probe, or press Enter to cancel",
            default=""
        )
        if custom_port.isdigit():
            open_web_ports.append(int(custom_port))
        else:
            session.finalize(status="No Web Services Found", duration_seconds=time.time() - start_time)
            return

    display_success(f"Identified open web port(s): {', '.join(map(str, open_web_ports))}")

    inspections: List[Dict[str, Any]] = []
    whatweb_results: Dict[int, str] = {}

    for port in open_web_ports:
        # Determine protocol scheme
        scheme = "https" if port in (443, 8443, 9443) else "http"
        url = f"{scheme}://{validated_target}:{port}" if port not in (80, 443) else f"{scheme}://{validated_target}"
        
        with console.status(f"[bold {COLOR_BRAND}]Inspecting HTTP endpoint: {url}...[/bold {COLOR_BRAND}]"):
            res = probe_web_service(url)
            inspections.append(res)

            # Whatweb fingerprinting if installed
            ww_out = run_whatweb_inspection(url)
            if ww_out:
                whatweb_results[port] = ww_out

    # Render results table
    console.print()
    res_tbl = Table(title="Web Service Inspection Summary", box=None)
    res_tbl.add_column("Endpoint URL", style="bold cyan", width=28)
    res_tbl.add_column("Status", style="bold green", width=10)
    res_tbl.add_column("Server Header", style="yellow", width=18)
    res_tbl.add_column("HTML Page Title", style="white")

    for item in inspections:
        status_str = str(item["status_code"]) if item["status_code"] else f"[red]{item.get('error', 'Error')[:15]}[/red]"
        res_tbl.add_row(item["url"], status_str, item["server_banner"], item["title"] or "[dim]No title[/dim]")
    console.print(res_tbl)

    # Security Headers Table
    for item in inspections:
        if not item.get("is_reachable"):
            continue
        console.print()
        sec_tbl = Table(title=f"Security Headers Evaluation: {item['url']}", box=None)
        sec_tbl.add_column("Security Header", style="bold white", width=26)
        sec_tbl.add_column("Status", width=12)
        sec_tbl.add_column("Observed Value / Impact", style="dim")

        for h_name, h_desc in SECURITY_HEADERS:
            if h_name in item["security_headers"]:
                val = item["security_headers"][h_name]
                sec_tbl.add_row(h_name, "[bold green]PRESENT[/bold green]", val[:50])
            else:
                sec_tbl.add_row(h_name, "[bold red]MISSING[/bold red]", f"Risk: {h_desc}")
        console.print(sec_tbl)

    # WhatWeb findings
    if whatweb_results:
        console.print()
        display_success("WhatWeb Technology Fingerprints:")
        for p, out in whatweb_results.items():
            console.print(Panel(out, title=f"Port {p} Technologies", box=None, border_style="cyan"))

    # Optional Nikto scan
    nikto_report = None
    if SubprocessManager.is_binary_available("nikto"):
        console.print()
        if Confirm.ask("[bold yellow]Would you like to execute an optional Nikto vulnerability scan on target?[/bold yellow]", default=False):
            primary_port = open_web_ports[0]
            with console.status(f"[bold {COLOR_BRAND}]Executing Nikto scan against port {primary_port} (up to 3 min)...[/bold {COLOR_BRAND}]"):
                nikto_report = run_nikto_scan(validated_target, primary_port)
            if nikto_report:
                console.print(Panel(nikto_report[:1200] + "\n...", title="Nikto Findings", border_style="yellow"))
                session.write_artifact("nikto_scan.txt", nikto_report)

    duration = time.time() - start_time
    session.write_json_artifact("web_recon.json", inspections)

    reports = session.finalize(
        status="Completed",
        summary_data={
            "target": validated_target,
            "open_web_ports": open_web_ports,
            "endpoints": [item["url"] for item in inspections],
            "technologies_fingerprinted": list(whatweb_results.keys())
        },
        duration_seconds=duration
    )
    console.print()
    display_info(f"Artifacts saved to: {reports['report_txt']}")

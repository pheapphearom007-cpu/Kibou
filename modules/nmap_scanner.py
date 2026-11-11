"""
Nmap Scanning and Vulnerability Assessment Modules for Kibuo.

Module [03]: Quick Port Scan (Top 100 ports, fast mode)
Module [04]: Full TCP Port Scan (1-65535 ports, duration warning)
Module [05]: OS & Service Detection (-O -sV --traceroute)
Module [06]: SYN Stealth Scan (-sS with raw socket privilege validation)
Module [07]: Vulnerability Assessment (NSE vuln scripts, safe mode, verified vs potential)
"""

import os
import re
import socket
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core.logger import get_logger
from core.permission_manager import PermissionManager
from core.report_generator import AssessmentSession
from core.subprocess_manager import SubprocessManager
from core.ui import (
    COLOR_BRAND, COLOR_BRAND_ALT, COLOR_ERROR, COLOR_INFO,
    COLOR_SUCCESS, COLOR_WARN, display_error, display_info,
    display_section_header, display_summary_card, display_success,
    display_warning
)
from core.validator import ValidationError, validate_target

logger = get_logger("kibuo.nmap_scanner")
console = Console()


@dataclass
class ScannedPort:
    """Represents a discovered network port."""
    port_id: int
    protocol: str
    state: str
    service_name: str = "unknown"
    product: str = ""
    version: str = ""
    extra_info: str = ""
    cpe: List[str] = field(default_factory=list)
    scripts: Dict[str, str] = field(default_factory=dict)

    @property
    def full_service_version(self) -> str:
        parts = [self.product, self.version, self.extra_info]
        res = " ".join(p.strip() for p in parts if p.strip())
        return res if res else self.service_name


@dataclass
class NmapScanResult:
    """Structured container for parsed Nmap scan output."""
    target: str
    status: str
    ipv4_address: Optional[str] = None
    mac_address: Optional[str] = None
    hostnames: List[str] = field(default_factory=list)
    ports: List[ScannedPort] = field(default_factory=list)
    os_matches: List[Dict[str, Any]] = field(default_factory=list)
    traceroute_hops: List[Dict[str, str]] = field(default_factory=list)
    raw_xml: str = ""
    raw_text: str = ""
    command: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0


def parse_nmap_xml(xml_content: str) -> NmapScanResult:
    """
    Parse Nmap XML output safely into structured NmapScanResult object.
    Gracefully handles empty, partial, or malformed XML streams.
    """
    result = NmapScanResult(target="unknown", status="down", raw_xml=xml_content)
    if not xml_content or not xml_content.strip():
        return result

    try:
        root = ET.fromstring(xml_content.strip())
    except ET.ParseError as err:
        logger.warning("Failed to parse Nmap XML: %s", err)
        return result

    host_elem = root.find("host")
    if host_elem is None:
        # Check if runstats or other hosts exist
        for h in root.findall("host"):
            host_elem = h
            break
        if host_elem is None:
            return result

    # Host status
    status_elem = host_elem.find("status")
    if status_elem is not None:
        result.status = status_elem.get("state", "unknown")

    # Addresses
    for addr in host_elem.findall("address"):
        addr_type = addr.get("addrtype", "")
        if addr_type == "ipv4":
            result.ipv4_address = addr.get("addr")
            if result.target == "unknown":
                result.target = result.ipv4_address
        elif addr_type == "mac":
            result.mac_address = addr.get("addr")

    # Hostnames
    hostnames_elem = host_elem.find("hostnames")
    if hostnames_elem is not None:
        for hn in hostnames_elem.findall("hostname"):
            name = hn.get("name")
            if name:
                result.hostnames.append(name)

    # Ports
    ports_elem = host_elem.find("ports")
    if ports_elem is not None:
        for p in ports_elem.findall("port"):
            port_id = int(p.get("portid", 0))
            protocol = p.get("protocol", "tcp")
            state_elem = p.find("state")
            state = state_elem.get("state", "closed") if state_elem is not None else "closed"

            service_elem = p.find("service")
            service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
            product = service_elem.get("product", "") if service_elem is not None else ""
            version = service_elem.get("version", "") if service_elem is not None else ""
            extrainfo = service_elem.get("extrainfo", "") if service_elem is not None else ""

            cpe_list = []
            if service_elem is not None:
                for c in service_elem.findall("cpe"):
                    if c.text:
                        cpe_list.append(c.text.strip())

            # Script outputs
            scripts_dict = {}
            for sc in p.findall("script"):
                sc_id = sc.get("id", "script")
                sc_out = sc.get("output", "")
                scripts_dict[sc_id] = sc_out

            result.ports.append(
                ScannedPort(
                    port_id=port_id,
                    protocol=protocol,
                    state=state,
                    service_name=service_name,
                    product=product,
                    version=version,
                    extra_info=extrainfo,
                    cpe=cpe_list,
                    scripts=scripts_dict
                )
            )

    # OS Matches
    os_elem = host_elem.find("os")
    if os_elem is not None:
        for match in os_elem.findall("osmatch"):
            name = match.get("name", "Unknown OS")
            accuracy = match.get("accuracy", "0")
            cpe_str = ""
            osclass = match.find("osclass")
            if osclass is not None:
                cpe_node = osclass.find("cpe")
                if cpe_node is not None and cpe_node.text:
                    cpe_str = cpe_node.text
            result.os_matches.append({
                "name": name,
                "accuracy": f"{accuracy}%",
                "cpe": cpe_str
            })

    # Traceroute
    trace_elem = host_elem.find("trace")
    if trace_elem is not None:
        for hop in trace_elem.findall("hop"):
            result.traceroute_hops.append({
                "ttl": hop.get("ttl", "?"),
                "ip": hop.get("ipaddr", "*"),
                "rtt": hop.get("rtt", "*"),
                "host": hop.get("host", "")
            })

    return result


def execute_nmap_scan(
    target: str,
    args: List[str],
    timeout: int = 300,
    spinner_text: str = "Scanning target..."
) -> Tuple[NmapScanResult, str, str]:
    """
    Execute Nmap using XML stdout output mode (-oX -) and raw terminal capture.
    Returns (NmapScanResult, raw_stdout, raw_stderr).
    """
    has_nmap = SubprocessManager.is_binary_available("nmap")
    if not has_nmap:
        display_error("Nmap is not installed on this system.")
        display_info("Install Nmap via: sudo apt-get install -y nmap")
        return NmapScanResult(target=target, status="error"), "", "Nmap binary not found."

    # Construct arguments: ensure XML output is enabled
    full_cmd = ["nmap"] + args
    if "-oX" not in full_cmd:
        full_cmd.extend(["-oX", "-"])
    if target not in full_cmd:
        full_cmd.append(target)

    logger.info("Executing Nmap: %s", " ".join(full_cmd))
    
    with console.status(f"[bold {COLOR_BRAND}]{spinner_text}[/bold {COLOR_BRAND}]"):
        res = SubprocessManager.execute(full_cmd, timeout=timeout)

    xml_content = res.stdout if "<nmaprun" in res.stdout else ""
    parsed = parse_nmap_xml(xml_content)
    parsed.target = target
    parsed.raw_text = res.stdout
    parsed.raw_xml = xml_content
    parsed.duration_seconds = res.duration_seconds
    parsed.command = full_cmd

    if not res.is_ok() and not parsed.ports:
        logger.warning("Nmap command exited with code %s: %s", res.returncode, res.stderr)

    return parsed, res.stdout, res.stderr


def render_ports_table(ports: List[ScannedPort], title: str = "Discovered Open Ports & Services") -> None:
    """Render a clean Rich table of discovered open ports and detected services."""
    open_ports = [p for p in ports if p.state.lower() == "open"]
    if not open_ports:
        display_warning("No open ports were discovered.")
        return

    table = Table(title=title, box=None)
    table.add_column("Port", style="bold cyan", width=10)
    table.add_column("State", style="bold green", width=10)
    table.add_column("Service", style="bold white", width=14)
    table.add_column("Version / Software Banner", style="bright_yellow")

    for p in open_ports:
        port_label = f"{p.port_id}/{p.protocol}"
        table.add_row(port_label, p.state.upper(), p.service_name, p.full_service_version)

    console.print(table)


def offer_secondary_reconnaissance(target: str, ports: List[ScannedPort]) -> None:
    """Intelligently suggest and trigger secondary recon workflows based on scan results."""
    from modules.web_recon import run_web_recon_module
    from modules.exploit_lookup import run_exploit_lookup_module
    from modules.smb_recon import run_smb_discovery_module

    open_ports = [p for p in ports if p.state.lower() == "open"]
    if not open_ports:
        return

    web_ports = [p.port_id for p in open_ports if p.port_id in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000) or p.service_name in ("http", "https", "ssl/http")]
    smb_ports = [p.port_id for p in open_ports if p.port_id in (139, 445)]
    services_with_versions = [f"{p.product} {p.version}".strip() for p in open_ports if p.product]

    if not web_ports and not smb_ports and not services_with_versions:
        return

    console.print()
    display_info("Intelligent Workflow: Secondary assessment opportunities detected:")
    if web_ports:
        console.print(f"  • [bold cyan][w][/bold cyan] Web Reconnaissance for active web ports: {web_ports}")
    if services_with_versions:
        console.print(f"  • [bold yellow][e][/bold yellow] Exploit-DB Intelligence for banners: {services_with_versions[:3]}")
    if smb_ports:
        console.print(f"  • [bold green][s][/bold green] SMB Discovery & Security Audit for ports: {smb_ports}")

    choice = Prompt.ask(
        "\nTrigger secondary recon? ([bold cyan]w[/bold cyan]=Web, [bold yellow]e[/bold yellow]=Exploit, [bold green]s[/bold green]=SMB, [dim]Enter=Skip[/dim])",
        default=""
    ).strip().lower()

    if choice == "w" and web_ports:
        console.print()
        run_web_recon_module(target)
    elif choice == "e" and services_with_versions:
        console.print()
        run_exploit_lookup_module(target)
    elif choice == "s" and smb_ports:
        console.print()
        run_smb_discovery_module(target)


# ==================================================
# MODULE [03] QUICK PORT SCAN
# ==================================================

def run_quick_port_scan_module(target_host: Optional[str] = None) -> None:
    """
    Interactive handler for Module [03] Quick Port Scan (Top 100 ports, fast mode).
    """
    display_section_header("Module [03]: Quick Port Scan", "Fast top-100 port scan with service detection")

    if not target_host:
        target_input = Prompt.ask(f"[bold {COLOR_BRAND}]Enter Target (IPv4 or Domain, e.g. 192.168.1.1 or scanme.nmap.org)[/bold {COLOR_BRAND}]")
    else:
        target_input = target_host
    try:
        _, validated_target = validate_target(target_input)
    except ValidationError as err:
        display_error(str(err))
        return

    session = AssessmentSession(target=validated_target, module_name="Quick Port Scan")
    
    # Nmap top 100 ports with service version detection
    args = ["-F", "-sV", "--version-light", "-T4"]
    parsed, raw_out, raw_err = execute_nmap_scan(
        validated_target,
        args,
        timeout=180,
        spinner_text=f"Performing fast top-100 scan on {validated_target}..."
    )

    session.write_artifact("nmap_quick_scan.txt", raw_out)
    session.write_artifact("nmap_quick_scan.xml", parsed.raw_xml)

    console.print()
    open_ports = [p for p in parsed.ports if p.state.lower() == "open"]
    render_ports_table(parsed.ports, title=f"Quick Scan Results: {validated_target}")

    services_found = [p.service_name for p in open_ports]
    reports = session.finalize(
        status="Completed" if parsed.ports else "Finished (No Open Ports)",
        summary_data={
            "target": validated_target,
            "open_ports_count": len(open_ports),
            "ports": [
                {"port": p.port_id, "proto": p.protocol, "service": p.service_name, "version": p.full_service_version}
                for p in open_ports
            ]
        },
        duration_seconds=parsed.duration_seconds
    )

    console.print()
    display_summary_card(
        target=validated_target,
        status="Completed",
        open_ports_count=len(open_ports),
        services_list=services_found[:5],
        duration=parsed.duration_seconds,
        export_paths=reports
    )

    offer_secondary_reconnaissance(validated_target, parsed.ports)


# ==================================================
# MODULE [04] FULL TCP PORT SCAN
# ==================================================

def run_full_port_scan_module(target_host: Optional[str] = None) -> None:
    """
    Interactive handler for Module [04] Full TCP Port Scan (All 65,535 ports).
    Includes duration warning, performance options, and safe execution.
    """
    display_section_header("Module [04]: Full TCP Port Scan", "Comprehensive scan covering all 65,535 TCP ports")

    if not target_host:
        target_input = Prompt.ask(f"[bold {COLOR_BRAND}]Enter Target (IPv4 or Domain)[/bold {COLOR_BRAND}]")
    else:
        target_input = target_host
    try:
        _, validated_target = validate_target(target_input)
    except ValidationError as err:
        display_error(str(err))
        return

    # Warning before lengthy scan
    display_warning("Scanning all 65,535 TCP ports can take several minutes to complete depending on network conditions.")
    if not Confirm.ask("Do you want to proceed with the full port scan?", default=True):
        display_info("Scan aborted by user.")
        return

    timing = Prompt.ask("Select Timing Template (T3=Normal, T4=Aggressive)", choices=["T3", "T4"], default="T4")
    
    session = AssessmentSession(target=validated_target, module_name="Full TCP Port Scan")
    args = ["-p-", "-sV", f"-{timing}"]

    parsed, raw_out, raw_err = execute_nmap_scan(
        validated_target,
        args,
        timeout=1200,
        spinner_text=f"Scanning all 65,535 ports on {validated_target} (Timing: {timing})..."
    )

    session.write_artifact("nmap_full_scan.txt", raw_out)
    session.write_artifact("nmap_full_scan.xml", parsed.raw_xml)

    console.print()
    open_ports = [p for p in parsed.ports if p.state.lower() == "open"]
    render_ports_table(parsed.ports, title=f"Full Port Scan Results: {validated_target}")

    reports = session.finalize(
        status="Completed",
        summary_data={
            "target": validated_target,
            "open_ports_count": len(open_ports),
            "ports": [
                {"port": p.port_id, "proto": p.protocol, "service": p.service_name, "version": p.full_service_version}
                for p in open_ports
            ]
        },
        duration_seconds=parsed.duration_seconds
    )

    console.print()
    display_summary_card(
        target=validated_target,
        status="Completed",
        open_ports_count=len(open_ports),
        services_list=[p.service_name for p in open_ports][:5],
        duration=parsed.duration_seconds,
        export_paths=reports
    )

    offer_secondary_reconnaissance(validated_target, parsed.ports)


# ==================================================
# MODULE [05] OS & SERVICE DETECTION
# ==================================================

def run_os_detection_module(target_host: Optional[str] = None) -> None:
    """
    Interactive handler for Module [05] OS & Service Detection (-O -sV --traceroute).
    Validates root permissions, explains fingerprinting limitations, displays results.
    """
    display_section_header("Module [05]: OS & Service Detection", "Operating system fingerprinting, service versions & traceroute")

    if not target_host:
        target_input = Prompt.ask(f"[bold {COLOR_BRAND}]Enter Target (IPv4 or Domain)[/bold {COLOR_BRAND}]")
    else:
        target_input = target_host
    try:
        _, validated_target = validate_target(target_input)
    except ValidationError as err:
        display_error(str(err))
        return

    # Check root privilege for TCP/IP stack fingerprinting (-O)
    is_root = PermissionManager.is_root()
    args = ["-sV", "--traceroute", "-T4"]
    
    if is_root:
        args.append("-O")
        display_info("Root privileges detected: Full TCP/IP stack OS fingerprinting enabled (-O).")
    else:
        display_warning(
            "Running without root privileges. Raw TCP/IP OS fingerprinting (-O) requires root/CAP_NET_RAW.\n"
            "Kibuo will perform Service Version detection and Traceroute without raw OS probes."
        )

    session = AssessmentSession(target=validated_target, module_name="OS & Service Detection")

    parsed, raw_out, raw_err = execute_nmap_scan(
        validated_target,
        args,
        timeout=300,
        spinner_text=f"Fingerprinting OS and services on {validated_target}..."
    )

    session.write_artifact("nmap_os_scan.txt", raw_out)
    session.write_artifact("nmap_os_scan.xml", parsed.raw_xml)

    console.print()
    # OS Results Table
    if parsed.os_matches:
        display_success("Operating System Fingerprint Matches:")
        os_tbl = Table(title="OS Detection Results", box=None)
        os_tbl.add_column("OS Match Name", style="bold yellow")
        os_tbl.add_column("Accuracy", style="bold green", width=12)
        os_tbl.add_column("CPE Identifier", style="dim cyan")
        for match in parsed.os_matches:
            os_tbl.add_row(match["name"], match["accuracy"], match["cpe"] or "N/A")
        console.print(os_tbl)
    else:
        display_warning("OS Fingerprint was inconclusive or restricted by remote firewall/privileges.")

    console.print()
    render_ports_table(parsed.ports, title=f"Service Versions: {validated_target}")

    # Traceroute hops
    if parsed.traceroute_hops:
        console.print()
        trace_tbl = Table(title="Traceroute Hops", box=None)
        trace_tbl.add_column("TTL", style="dim", width=6)
        trace_tbl.add_column("IP Address", style="bold white", width=18)
        trace_tbl.add_column("RTT", style="yellow", width=12)
        trace_tbl.add_column("Hostname", style="cyan")
        for hop in parsed.traceroute_hops:
            trace_tbl.add_row(hop["ttl"], hop["ip"], hop["rtt"], hop["host"] or "-")
        console.print(trace_tbl)

    open_ports = [p for p in parsed.ports if p.state.lower() == "open"]
    reports = session.finalize(
        status="Completed",
        summary_data={
            "target": validated_target,
            "os_matches": parsed.os_matches,
            "open_ports_count": len(open_ports),
            "hops_count": len(parsed.traceroute_hops)
        },
        duration_seconds=parsed.duration_seconds
    )

    console.print()
    display_summary_card(
        target=validated_target,
        status="Completed",
        open_ports_count=len(open_ports),
        services_list=[p.service_name for p in open_ports][:5],
        duration=parsed.duration_seconds,
        export_paths=reports
    )

    offer_secondary_reconnaissance(validated_target, parsed.ports)


# ==================================================
# MODULE [06] SYN SCAN
# ==================================================

def run_syn_scan_module(target_host: Optional[str] = None) -> None:
    """
    Interactive handler for Module [06] SYN Scan (-sS).
    Requires raw socket permissions, explains stealth mechanics, requires explicit confirmation.
    """
    display_section_header("Module [06]: SYN Stealth Scan", "Half-open TCP SYN scanning with raw socket validation")

    has_priv, priv_msg = PermissionManager.check_module_privilege("syn_scan")
    if not has_priv:
        display_error("TCP SYN scanning requires root/CAP_NET_RAW privileges.")
        display_info(priv_msg)
        return

    console.print(Panel(
        Text(
            "MECHANICS OF TCP SYN SCANNING (-sS):\n\n"
            "A TCP SYN scan (half-open scanning) transmits a raw TCP SYN packet to each target port.\n"
            "  • If the target responds with SYN/ACK, the port is OPEN. Kibuo immediately sends an RST\n"
            "    to tear down the half-open connection without completing the 3-way handshake.\n"
            "  • If the target responds with RST, the port is CLOSED.\n"
            "  • If no response or ICMP unreachable is received, the port is marked FILTERED.\n\n"
            "SYN scanning is fast and avoids full application-layer connection overhead.",
            style="white"
        ),
        box=None,
        title="[bold yellow]Technical Overview[/bold yellow]"
    ))

    if not target_host:
        target_input = Prompt.ask(f"[bold {COLOR_BRAND}]Enter Target (IPv4 or Domain)[/bold {COLOR_BRAND}]")
    else:
        target_input = target_host
    try:
        _, validated_target = validate_target(target_input)
    except ValidationError as err:
        display_error(str(err))
        return

    if not Confirm.ask(f"Confirm authorized SYN scan against {validated_target}?", default=True):
        display_info("Scan aborted by user.")
        return

    session = AssessmentSession(target=validated_target, module_name="SYN Stealth Scan")
    args = ["-sS", "-sV", "-T4"]

    parsed, raw_out, raw_err = execute_nmap_scan(
        validated_target,
        args,
        timeout=300,
        spinner_text=f"Performing half-open TCP SYN scan on {validated_target}..."
    )

    session.write_artifact("nmap_syn_scan.txt", raw_out)
    session.write_artifact("nmap_syn_scan.xml", parsed.raw_xml)

    console.print()
    open_ports = [p for p in parsed.ports if p.state.lower() == "open"]
    render_ports_table(parsed.ports, title=f"SYN Scan Results: {validated_target}")

    reports = session.finalize(
        status="Completed",
        summary_data={
            "target": validated_target,
            "scan_type": "TCP SYN (-sS)",
            "open_ports_count": len(open_ports),
            "ports": [
                {"port": p.port_id, "proto": p.protocol, "service": p.service_name, "version": p.full_service_version}
                for p in open_ports
            ]
        },
        duration_seconds=parsed.duration_seconds
    )

    console.print()
    display_summary_card(
        target=validated_target,
        status="Completed",
        open_ports_count=len(open_ports),
        services_list=[p.service_name for p in open_ports][:5],
        duration=parsed.duration_seconds,
        export_paths=reports
    )

    offer_secondary_reconnaissance(validated_target, parsed.ports)


# ==================================================
# MODULE [07] VULNERABILITY ASSESSMENT
# ==================================================

def run_vulnerability_assessment_module() -> None:
    """
    Interactive handler for Module [07] Vulnerability Assessment.
    Integrates Nmap NSE vuln checks, safe mode toggle, verified vs potential findings.
    """
    display_section_header("Module [07]: Vulnerability Assessment", "NSE script vulnerability auditing with safe mode validation")

    target_input = Prompt.ask(f"[bold {COLOR_BRAND}]Enter Target (IPv4 or Domain)[/bold {COLOR_BRAND}]")
    try:
        _, validated_target = validate_target(target_input)
    except ValidationError as err:
        display_error(str(err))
        return

    safe_mode = Confirm.ask(
        f"[bold {COLOR_BRAND}]Enable Safe Assessment Mode (run only non-intrusive safe vuln scripts)?[/bold {COLOR_BRAND}]",
        default=True
    )

    script_arg = "--script=vuln and safe" if safe_mode else "--script=vuln"
    display_info(f"Selected assessment mode: {'SAFE (vuln and safe)' if safe_mode else 'COMPREHENSIVE (vuln)'}")

    session = AssessmentSession(target=validated_target, module_name="Vulnerability Assessment")
    args = ["-sV", script_arg, "-T4"]

    parsed, raw_out, raw_err = execute_nmap_scan(
        validated_target,
        args,
        timeout=600,
        spinner_text=f"Executing NSE vulnerability assessment on {validated_target}..."
    )

    session.write_artifact("nmap_vuln_assessment.txt", raw_out)
    session.write_artifact("nmap_vuln_assessment.xml", parsed.raw_xml)

    console.print()
    # Parse scripts looking for vulnerability findings
    vuln_findings: List[Dict[str, Any]] = []

    for p in parsed.ports:
        for script_id, script_out in p.scripts.items():
            if not script_out or not script_out.strip():
                continue
            
            # Distinguish confirmed vulnerability vs potential
            is_confirmed = (
                "VULNERABLE:" in script_out.upper() or
                "State: VULNERABLE" in script_out or
                "Exploit results: Successful" in script_out
            )
            is_potential = (
                "LIKELY VULNERABLE" in script_out.upper() or
                "State: LIKELY VULNERABLE" in script_out or
                "CVE-" in script_out.upper()
            )
            
            severity = "CONFIRMED" if is_confirmed else ("POTENTIAL / INFORMATIONAL" if is_potential else "INFO")

            vuln_findings.append({
                "port": f"{p.port_id}/{p.protocol}",
                "service": p.service_name,
                "script_id": script_id,
                "severity": severity,
                "output": script_out
            })

    if vuln_findings:
        display_warning(f"Identified {len(vuln_findings)} security script finding(s):")
        vuln_tbl = Table(title="Vulnerability Assessment Findings", box=None)
        vuln_tbl.add_column("Port", style="bold cyan", width=10)
        vuln_tbl.add_column("Script / Check", style="bold white", width=24)
        vuln_tbl.add_column("Classification", width=22)
        vuln_tbl.add_column("Evidence Summary", style="dim")

        for f in vuln_findings:
            sev = f["severity"]
            sev_style = f"[bold red]{sev}[/bold red]" if "CONFIRMED" in sev else f"[yellow]{sev}[/yellow]"
            first_line = f["output"].splitlines()[0] if f["output"] else ""
            vuln_tbl.add_row(f["port"], f["script_id"], sev_style, first_line[:60])
        console.print(vuln_tbl)
    else:
        display_success("No common vulnerabilities detected by NSE scripts on tested services.")

    open_ports = [p for p in parsed.ports if p.state.lower() == "open"]
    reports = session.finalize(
        status="Completed",
        summary_data={
            "target": validated_target,
            "safe_mode": safe_mode,
            "open_ports_count": len(open_ports),
            "findings_count": len(vuln_findings),
            "findings": vuln_findings
        },
        duration_seconds=parsed.duration_seconds
    )

    console.print()
    display_summary_card(
        target=validated_target,
        status="Completed",
        open_ports_count=len(open_ports),
        services_list=[p.service_name for p in open_ports][:5],
        duration=parsed.duration_seconds,
        export_paths=reports
    )

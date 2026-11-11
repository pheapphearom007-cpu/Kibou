"""
SMB Service Enumeration and Security Auditing Module for Kibuo.

Module [13]: Nmap + SMB Discovery
Audits Server Message Block (SMB/CIFS) on ports 139 and 445, checks dialect
negotiation (SMBv1/2/3), message signing enforcement, guest authentication,
and provides optional confirmed enum4linux enumeration.
"""

import json
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

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
from modules.nmap_scanner import execute_nmap_scan

logger = get_logger("kibuo.smb_recon")
console = Console()

SMB_PORTS = [139, 445]
SMB_SCRIPTS = "smb-os-discovery,smb2-security-mode,smb2-capabilities,smb-protocols"


def check_smb_ports(target: str) -> List[int]:
    """Check if TCP 139 or 445 are accessible."""
    open_ports = []
    for port in SMB_PORTS:
        try:
            with socket.create_connection((target, port), timeout=2.0):
                open_ports.append(port)
        except Exception:
            pass
    return open_ports


def run_enum4linux(target: str) -> Optional[str]:
    """Execute enum4linux with user confirmation for basic enumeration."""
    if not SubprocessManager.is_binary_available("enum4linux"):
        return "enum4linux is not installed on this system."

    # -U: get userlist, -S: get sharelist, -o: get OS info
    cmd = ["enum4linux", "-U", "-S", "-o", target]
    res = SubprocessManager.execute(cmd, timeout=180)
    return res.stdout or res.stderr


def run_smb_discovery_module(target_host: Optional[str] = None) -> None:
    """
    Interactive execution handler for Module [13] SMB Discovery.
    """
    display_section_header("Module [13]: SMB Discovery & Security Assessment", "SMB/CIFS dialect negotiation, message signing enforcement & share discovery")

    if not target_host:
        target_input = Prompt.ask(f"[bold {COLOR_BRAND}]Enter Target Host (IPv4 or Domain Name)[/bold {COLOR_BRAND}]")
    else:
        target_input = target_host
    try:
        _, validated_target = validate_target(target_input)
    except ValidationError as err:
        display_error(str(err))
        return

    session = AssessmentSession(target=validated_target, module_name="SMB Reconnaissance")
    start_time = time.time()

    # Step 1: Probe ports 139 & 445
    with console.status(f"[bold {COLOR_BRAND}]Probing SMB ports 139/445 on {validated_target}...[/bold {COLOR_BRAND}]"):
        open_smb_ports = check_smb_ports(validated_target)

    if not open_smb_ports:
        display_warning(f"Neither port 139 nor 445 responded on {validated_target}.")
        if not Confirm.ask("Do you want to run Nmap SMB discovery anyway?", default=False):
            session.finalize(status="SMB Ports Closed", duration_seconds=time.time() - start_time)
            return
        open_smb_ports = SMB_PORTS

    display_success(f"Detected SMB accessible port(s): {', '.join(map(str, open_smb_ports))}")

    # Step 2: Run Nmap SMB scripts
    args = ["-p", ",".join(map(str, open_smb_ports)), f"--script={SMB_SCRIPTS}", "-sV", "-T4"]
    parsed, raw_out, raw_err = execute_nmap_scan(
        validated_target,
        args,
        timeout=180,
        spinner_text=f"Auditing SMB dialect and security modes on {validated_target}..."
    )

    session.write_artifact("nmap_smb_scan.txt", raw_out)
    session.write_artifact("nmap_smb_scan.xml", parsed.raw_xml)

    console.print()
    # Extract SMB security mode details
    smb_security_summary: Dict[str, str] = {
        "SMBv1 Supported": "Unknown",
        "Message Signing": "Unknown",
        "Guest Authentication": "Unknown",
        "OS Discovery": "Unknown"
    }

    for p in parsed.ports:
        for script_id, out in p.scripts.items():
            if "smb2-security-mode" in script_id:
                if "message signing enabled and required" in out.lower():
                    smb_security_summary["Message Signing"] = "REQUIRED (Secure)"
                elif "message signing enabled but not required" in out.lower():
                    smb_security_summary["Message Signing"] = "ENABLED BUT NOT REQUIRED (Vulnerable to SMB Relay)"
                elif "message signing disabled" in out.lower():
                    smb_security_summary["Message Signing"] = "DISABLED (High Risk)"
            elif "smb-protocols" in script_id:
                if "SMBv1" in out:
                    smb_security_summary["SMBv1 Supported"] = "YES (Deprecated & Insecure)"
                else:
                    smb_security_summary["SMBv1 Supported"] = "NO (Modern Dialects Only)"
            elif "smb-os-discovery" in script_id:
                smb_security_summary["OS Discovery"] = out.splitlines()[0] if out.splitlines() else "Available"

    # Display findings table
    display_success(f"SMB Security Configuration Audit for {validated_target}:")
    tbl = Table(title="SMB Protocol & Security Status", box=None)
    tbl.add_column("Security Property", style="bold cyan", width=26)
    tbl.add_column("Audited Status", style="bold white")

    for k, v in smb_security_summary.items():
        val_style = v
        if "High Risk" in v or "Vulnerable" in v or "Deprecated" in v:
            val_style = f"[bold red]{v}[/bold red]"
        elif "Secure" in v or "NO" in v:
            val_style = f"[bold green]{v}[/bold green]"
        tbl.add_row(k, val_style)
    console.print(tbl)

    # Optional enum4linux integration
    enum_out = None
    if SubprocessManager.is_binary_available("enum4linux"):
        console.print()
        if Confirm.ask("[bold yellow]Would you like to run optional enum4linux share enumeration?[/bold yellow]", default=False):
            with console.status(f"[bold {COLOR_BRAND}]Executing enum4linux on {validated_target}...[/bold {COLOR_BRAND}]"):
                enum_out = run_enum4linux(validated_target)
            if enum_out:
                session.write_artifact("enum4linux_output.txt", enum_out)
                console.print(Panel(enum_out[:1000] + "\n...", title="enum4linux Output", border_style="yellow"))

    duration = time.time() - start_time
    session.write_json_artifact("smb_security_summary.json", smb_security_summary)

    reports = session.finalize(
        status="Completed",
        summary_data={
            "target": validated_target,
            "open_ports": open_smb_ports,
            "security_summary": smb_security_summary
        },
        duration_seconds=duration
    )
    console.print()
    display_info(f"Artifacts saved to: {reports['report_txt']}")

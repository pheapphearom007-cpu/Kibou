"""
DNS Enumeration and Whois Intelligence Module for Kibuo.

Module [09]: Whois & DNS
Queries DNS resource records (A, AAAA, MX, TXT, NS, CNAME, PTR), performs reverse DNS lookups,
and queries WHOIS registrar and domain ownership details with graceful fallback.
"""

import json
import re
import socket
import time
from typing import Any, Dict, List, Optional, Tuple

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
from core.validator import ValidationError, validate_domain, validate_target

logger = get_logger("kibuo.dns_whois")
console = Console()

DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def query_dns_records(domain: str) -> Dict[str, List[str]]:
    """
    Query DNS resource records using 'dig' if available, with python socket fallback.
    """
    records: Dict[str, List[str]] = {}
    has_dig = SubprocessManager.is_binary_available("dig")

    for rec_type in DNS_RECORD_TYPES:
        records[rec_type] = []
        if has_dig:
            # Safe argument array: dig +short <type> <domain>
            res = SubprocessManager.execute(["dig", "+short", rec_type, domain], timeout=8)
            if res.is_ok() and res.stdout:
                for line in res.stdout.splitlines():
                    cleaned = line.strip().strip('"')
                    if cleaned:
                        records[rec_type].append(cleaned)
        else:
            # Fallback for A records using socket
            if rec_type == "A":
                try:
                    _, _, ip_list = socket.gethostbyname_ex(domain)
                    records["A"] = ip_list
                except Exception:
                    pass

    return records


def query_reverse_dns(ip_or_domain: str) -> Optional[str]:
    """
    Perform reverse DNS (PTR) lookup.
    """
    has_dig = SubprocessManager.is_binary_available("dig")
    # If it's a domain, resolve first
    try:
        target_ip = socket.gethostbyname(ip_or_domain)
    except socket.gaierror:
        target_ip = ip_or_domain

    if has_dig:
        res = SubprocessManager.execute(["dig", "+short", "-x", target_ip], timeout=6)
        if res.is_ok() and res.stdout.strip():
            return res.stdout.strip().rstrip(".")

    # Python socket fallback
    try:
        host, _, _ = socket.gethostbyaddr(target_ip)
        return host
    except Exception:
        return None


def query_whois_record(target: str) -> Dict[str, Any]:
    """
    Query WHOIS database using system whois tool.
    Extracts Registrar, Creation Date, Expiry Date, Organization, Name Servers.
    """
    has_whois = SubprocessManager.is_binary_available("whois")
    if not has_whois:
        return {
            "available": False,
            "raw": "WHOIS utility is not installed on this system. (Install via: sudo apt install whois)",
            "details": {}
        }

    res = SubprocessManager.execute(["whois", target], timeout=15)
    raw_text = res.stdout or res.stderr
    
    details: Dict[str, str] = {}
    
    # Common Whois key patterns
    patterns = {
        "Registrar": r"(?:Registrar|registrar):\s*(.+)",
        "Creation Date": r"(?:Creation Date|Created|Registration Time):\s*(.+)",
        "Expiration Date": r"(?:Registry Expiry Date|Expir\w+ Date):\s*(.+)",
        "Updated Date": r"(?:Updated Date|Last Modified):\s*(.+)",
        "Registrant Org": r"(?:Registrant Organization|Registrant Org):\s*(.+)",
        "Registrant Country": r"(?:Registrant Country):\s*(.+)",
        "DNSSEC": r"(?:DNSSEC):\s*(.+)",
    }

    for label, pat in patterns.items():
        match = re.search(pat, raw_text, re.IGNORECASE)
        if match:
            details[label] = match.group(1).strip()

    # Extract Name Servers
    ns_matches = re.findall(r"(?:Name Server|nserver):\s*([a-zA-Z0-9_\-\.]+)", raw_text, re.IGNORECASE)
    if ns_matches:
        details["Name Servers"] = ", ".join(sorted(set(ns.lower().rstrip(".") for ns in ns_matches)))

    return {
        "available": True,
        "raw": raw_text,
        "details": details
    }


def run_dns_whois_module() -> None:
    """
    Interactive execution handler for Module [09] Whois & DNS.
    """
    display_section_header("Module [09]: Whois & DNS Reconnaissance", "DNS resource records (A, MX, TXT, NS), PTR lookups, and WHOIS registration")

    target_input = Prompt.ask(f"[bold {COLOR_BRAND}]Enter Domain Name or IPv4 (e.g. google.com or 8.8.8.8)[/bold {COLOR_BRAND}]")
    try:
        target_type, validated_target = validate_target(target_input)
    except ValidationError as err:
        display_error(str(err))
        return

    session = AssessmentSession(target=validated_target, module_name="Whois & DNS Recon")
    start_time = time.time()

    with console.status(f"[bold {COLOR_BRAND}]Querying DNS and Whois records for {validated_target}...[/bold {COLOR_BRAND}]"):
        dns_records = query_dns_records(validated_target)
        ptr_record = query_reverse_dns(validated_target)
        whois_data = query_whois_record(validated_target)

    duration = time.time() - start_time

    # Save artifacts
    session.write_artifact("whois_raw.txt", whois_data.get("raw", ""))
    session.write_json_artifact("dns_records.json", {
        "dns": dns_records,
        "reverse_dns": ptr_record,
        "whois_details": whois_data.get("details", {})
    })

    console.print()
    # 1. DNS Records Table
    display_success(f"DNS Resource Records for {validated_target}:")
    dns_tbl = Table(title="DNS Resource Records", box=None)
    dns_tbl.add_column("Type", style="bold cyan", width=10)
    dns_tbl.add_column("Count", style="yellow", width=8)
    dns_tbl.add_column("Values / Answers", style="bold white")

    total_records = 0
    for rec_type, values in dns_records.items():
        if values:
            total_records += len(values)
            dns_tbl.add_row(rec_type, str(len(values)), ", ".join(values[:5]) + ("..." if len(values) > 5 else ""))

    if ptr_record:
        dns_tbl.add_row("PTR (rDNS)", "1", ptr_record)
        total_records += 1

    if total_records == 0:
        display_warning("No DNS records resolved or target is an unmapped address.")
    else:
        console.print(dns_tbl)

    # 2. Whois Registration Details Table
    console.print()
    whois_details = whois_data.get("details", {})
    if whois_details:
        display_success("WHOIS Registration Metadata:")
        whois_tbl = Table(title="Domain Registration & Ownership", box=None)
        whois_tbl.add_column("Field", style="bold yellow", width=22)
        whois_tbl.add_column("Value", style="white")

        for k, v in whois_details.items():
            whois_tbl.add_row(k, v)
        console.print(whois_tbl)
    else:
        display_info("Public WHOIS record details were restricted, privacy-shielded, or unavailable.")

    reports = session.finalize(
        status="Completed",
        summary_data={
            "target": validated_target,
            "dns_record_types_found": [k for k, v in dns_records.items() if v],
            "reverse_dns": ptr_record,
            "whois_fields": list(whois_details.keys())
        },
        duration_seconds=duration
    )
    console.print()
    display_info(f"Artifacts saved to: {reports['report_txt']}")

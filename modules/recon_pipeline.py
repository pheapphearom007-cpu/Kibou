"""
Automated Reconnaissance Pipeline Orchestrator for Kibuo.

Module [14]: Full Recon Pipeline
Executes an end-to-end multi-stage reconnaissance workflow:
  1. Target Validation
  2. IP Intelligence & ASN
  3. DNS & WHOIS
  4. Live Host Discovery
  5. Service & Version Detection
  6. Web Reconnaissance (if web ports active)
  7. SMB Security Assessment (if SMB ports active)
  8. Exploit-DB Intelligence Lookup
  9. Consolidated Reporting & Summary Card
"""

import json
import time
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core.logger import get_logger
from core.report_generator import AssessmentSession
from core.subprocess_manager import SubprocessManager
from core.ui import (
    COLOR_BRAND, COLOR_BRAND_ALT, COLOR_ERROR, COLOR_INFO,
    COLOR_SUCCESS, COLOR_WARN, display_error, display_info,
    display_section_header, display_summary_card, display_success,
    display_warning
)
from core.validator import ValidationError, is_private_ip, validate_target
from modules.dns_whois import query_dns_records, query_reverse_dns, query_whois_record
from modules.exploit_lookup import query_searchsploit
from modules.ip_intelligence import query_ip_intelligence
from modules.nmap_scanner import execute_nmap_scan, render_ports_table
from modules.smb_recon import check_smb_ports
from modules.web_recon import check_port_open, probe_web_service, run_whatweb_inspection

logger = get_logger("kibuo.pipeline")
console = Console()


def run_recon_pipeline_module() -> None:
    """
    Interactive execution handler for Module [14] Full Recon Pipeline.
    """
    display_section_header("Module [14]: Full Reconnaissance Pipeline", "Automated multi-stage reconnaissance and vulnerability intelligence pipeline")

    target_input = Prompt.ask(f"[bold {COLOR_BRAND}]Enter Target Host (IPv4 or Domain Name, e.g. scanme.nmap.org)[/bold {COLOR_BRAND}]")
    try:
        target_type, validated_target = validate_target(target_input)
    except ValidationError as err:
        display_error(str(err))
        return

    # Check stage customization
    customize = Confirm.ask("Do you want to customize pipeline stages (or run standard automated pipeline)?", default=False)
    
    stages = {
        "ip_intel": True,
        "dns_whois": True,
        "host_discovery": True,
        "service_scan": True,
        "web_recon": True,
        "smb_audit": True,
        "exploit_lookup": True
    }

    if customize:
        stages["ip_intel"] = Confirm.ask("Enable Stage: IP Intelligence & ASN?", default=True)
        stages["dns_whois"] = Confirm.ask("Enable Stage: DNS & WHOIS Records?", default=True)
        stages["host_discovery"] = Confirm.ask("Enable Stage: Live Host Discovery?", default=True)
        stages["service_scan"] = Confirm.ask("Enable Stage: Nmap Service Detection?", default=True)
        stages["web_recon"] = Confirm.ask("Enable Stage: Web Application Recon?", default=True)
        stages["smb_audit"] = Confirm.ask("Enable Stage: SMB Security Audit?", default=True)
        stages["exploit_lookup"] = Confirm.ask("Enable Stage: Exploit-DB Intelligence?", default=True)

    session = AssessmentSession(target=validated_target, module_name="Full Recon Pipeline")
    pipeline_start = time.time()
    consolidated_findings: Dict[str, Any] = {}

    total_stages = sum(1 for v in stages.values() if v)
    current_stage_idx = 0

    console.print()
    display_info(f"Initiating Kibuo Pipeline against target: {validated_target} ({total_stages} stages active)")

    # ----------------------------------------------------
    # STAGE 1: IP INTELLIGENCE
    # ----------------------------------------------------
    if stages["ip_intel"]:
        current_stage_idx += 1
        with console.status(f"[bold {COLOR_BRAND}][{current_stage_idx}/{total_stages}] Gathering IP Intelligence & ASN...[/bold {COLOR_BRAND}]"):
            try:
                intel_res = query_ip_intelligence(validated_target)
                consolidated_findings["ip_intelligence"] = intel_res
                session.write_json_artifact("ip_intelligence.json", intel_res)
                if intel_res.get("status") == "success":
                    display_success(f"IP Intelligence: {intel_res.get('org', 'N/A')} - {intel_res.get('country', 'N/A')}")
                elif intel_res.get("status") == "private":
                    display_info("IP Intelligence: Target is a private RFC1918 address (geolocation bypassed).")
            except Exception as exc:
                logger.warning("Pipeline IP Intelligence stage error: %s", exc)
                display_warning(f"IP Intelligence failed: {exc}")

    # ----------------------------------------------------
    # STAGE 2: DNS & WHOIS
    # ----------------------------------------------------
    if stages["dns_whois"]:
        current_stage_idx += 1
        with console.status(f"[bold {COLOR_BRAND}][{current_stage_idx}/{total_stages}] Enumerating DNS & WHOIS...[/bold {COLOR_BRAND}]"):
            try:
                dns_res = query_dns_records(validated_target)
                rdns = query_reverse_dns(validated_target)
                whois_res = query_whois_record(validated_target)
                consolidated_findings["dns"] = dns_res
                consolidated_findings["reverse_dns"] = rdns
                consolidated_findings["whois"] = whois_res.get("details", {})
                session.write_json_artifact("dns_whois.json", {
                    "dns": dns_res,
                    "reverse_dns": rdns,
                    "whois": whois_res
                })
                display_success(f"DNS Enumeration: {sum(len(v) for v in dns_res.values())} records identified.")
            except Exception as exc:
                logger.warning("Pipeline DNS/Whois stage error: %s", exc)
                display_warning(f"DNS/Whois lookup encountered an error: {exc}")

    # ----------------------------------------------------
    # STAGE 3: HOST DISCOVERY
    # ----------------------------------------------------
    if stages["host_discovery"]:
        current_stage_idx += 1
        with console.status(f"[bold {COLOR_BRAND}][{current_stage_idx}/{total_stages}] Verifying host responsiveness...[/bold {COLOR_BRAND}]"):
            has_nmap = SubprocessManager.is_binary_available("nmap")
            is_up = True
            if has_nmap:
                res = SubprocessManager.execute(["nmap", "-sn", "-T4", validated_target], timeout=30)
                is_up = "Host is up" in res.stdout or res.is_ok()
            consolidated_findings["host_up"] = is_up
            display_success(f"Host Status: {'ONLINE / UP' if is_up else 'NO DIRECT ICMP RESPONSE (Proceeding with port checks)'}")

    # ----------------------------------------------------
    # STAGE 4: SERVICE DETECTION (NMAP)
    # ----------------------------------------------------
    discovered_ports = []
    discovered_services = []
    if stages["service_scan"]:
        current_stage_idx += 1
        with console.status(f"[bold {COLOR_BRAND}][{current_stage_idx}/{total_stages}] Scanning ports & identifying service versions...[/bold {COLOR_BRAND}]"):
            parsed, raw_out, _ = execute_nmap_scan(
                validated_target,
                ["-F", "-sV", "--version-light", "-T4"],
                timeout=240,
                spinner_text=f"Scanning services on {validated_target}..."
            )
            session.write_artifact("nmap_scan.txt", raw_out)
            session.write_artifact("nmap_scan.xml", parsed.raw_xml)
            
            for p in parsed.ports:
                if p.state.lower() == "open":
                    discovered_ports.append(p)
                    discovered_services.append(p.service_name)
                    
            consolidated_findings["open_ports"] = [
                {"port": p.port_id, "protocol": p.protocol, "service": p.service_name, "version": p.full_service_version}
                for p in discovered_ports
            ]
            display_success(f"Port Scanning: {len(discovered_ports)} open port(s) detected.")

    # ----------------------------------------------------
    # STAGE 5: WEB RECON (CONDITIONAL)
    # ----------------------------------------------------
    web_findings = []
    if stages["web_recon"]:
        current_stage_idx += 1
        web_ports_to_check = [p.port_id for p in discovered_ports if p.service_name in ("http", "https", "ssl/http") or p.port_id in (80, 443, 8080, 8443)]
        if not web_ports_to_check:
            # Check 80 & 443 if no ports discovered earlier
            for default_p in (80, 443):
                if check_port_open(validated_target, default_p, timeout=1.5):
                    web_ports_to_check.append(default_p)

        if web_ports_to_check:
            with console.status(f"[bold {COLOR_BRAND}][{current_stage_idx}/{total_stages}] Inspecting web endpoints ({', '.join(map(str, web_ports_to_check))})...[/bold {COLOR_BRAND}]"):
                for wp in web_ports_to_check:
                    scheme = "https" if wp in (443, 8443) else "http"
                    url = f"{scheme}://{validated_target}:{wp}" if wp not in (80, 443) else f"{scheme}://{validated_target}"
                    p_res = probe_web_service(url)
                    ww = run_whatweb_inspection(url)
                    if ww:
                        p_res["whatweb"] = ww
                    web_findings.append(p_res)
            consolidated_findings["web_recon"] = web_findings
            session.write_json_artifact("web_recon.json", web_findings)
            display_success(f"Web Inspection: Inspected {len(web_findings)} active web service(s).")
        else:
            display_info(f"Stage [{current_stage_idx}/{total_stages}] Web Recon: No active HTTP/HTTPS ports identified.")

    # ----------------------------------------------------
    # STAGE 6: SMB AUDIT (CONDITIONAL)
    # ----------------------------------------------------
    if stages["smb_audit"]:
        current_stage_idx += 1
        smb_ports_active = [p.port_id for p in discovered_ports if p.port_id in (139, 445)]
        if not smb_ports_active:
            smb_ports_active = check_smb_ports(validated_target)

        if smb_ports_active:
            with console.status(f"[bold {COLOR_BRAND}][{current_stage_idx}/{total_stages}] Auditing SMB security configuration...[/bold {COLOR_BRAND}]"):
                parsed_smb, smb_raw, _ = execute_nmap_scan(
                    validated_target,
                    ["-p", ",".join(map(str, smb_ports_active)), "--script=smb2-security-mode,smb-protocols", "-T4"],
                    timeout=120,
                    spinner_text=f"Auditing SMB dialect & signing on {validated_target}..."
                )
                session.write_artifact("smb_audit.txt", smb_raw)
                consolidated_findings["smb_ports"] = smb_ports_active
                display_success(f"SMB Audit: Audited SMB services on ports {smb_ports_active}.")
        else:
            display_info(f"Stage [{current_stage_idx}/{total_stages}] SMB Audit: Ports 139/445 closed (stage skipped).")

    # ----------------------------------------------------
    # STAGE 7: EXPLOIT-DB INTELLIGENCE
    # ----------------------------------------------------
    exploit_matches: Dict[str, List[Any]] = {}
    if stages["exploit_lookup"]:
        current_stage_idx += 1
        with console.status(f"[bold {COLOR_BRAND}][{current_stage_idx}/{total_stages}] Cross-referencing service banners with Exploit-DB...[/bold {COLOR_BRAND}]"):
            for p in discovered_ports:
                term = f"{p.product} {p.version}".strip() if p.product else p.service_name
                if term and term != "unknown" and term not in exploit_matches:
                    matches = query_searchsploit(term)
                    if matches:
                        exploit_matches[term] = matches
            consolidated_findings["exploit_matches"] = exploit_matches
            session.write_json_artifact("exploit_lookup.json", exploit_matches)
            total_exp = sum(len(m) for m in exploit_matches.values())
            display_success(f"Exploit Intelligence: {total_exp} public advisory references matched.")

    duration = time.time() - pipeline_start

    # Render summary table & card
    console.print()
    if discovered_ports:
        render_ports_table(discovered_ports, title=f"Pipeline Discovered Services: {validated_target}")

    reports = session.finalize(
        status="Completed",
        summary_data=consolidated_findings,
        duration_seconds=duration
    )

    console.print()
    display_summary_card(
        target=validated_target,
        status="Completed",
        open_ports_count=len(discovered_ports),
        services_list=list(set(discovered_services))[:6],
        duration=duration,
        export_paths=reports
    )
    display_info(f"Comprehensive executive pipeline report created:\n  • TXT:  {reports['report_txt']}\n  • JSON: {reports['report_json']}")

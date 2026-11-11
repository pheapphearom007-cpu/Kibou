#!/usr/bin/env python3
"""
Kibuo - Professional Cybersecurity Reconnaissance Toolkit
Version 1.0.0

Entry point and interactive terminal loop for Kibuo.
"""

import json
import os
import signal
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core.dependency_manager import DependencyManager
from core.logger import get_logger, setup_logger
from core.permission_manager import PermissionManager
from core.ui import (
    COLOR_BRAND, COLOR_ERROR, COLOR_INFO, COLOR_SUCCESS,
    COLOR_WARN, clear_screen, display_about, display_authorization_warning,
    display_error, display_info, display_warning, pause_prompt,
    print_banner, render_menu
)
from modules.dns_whois import run_dns_whois_module
from modules.exploit_lookup import run_exploit_lookup_module
from modules.ip_intelligence import run_ip_intelligence_module
from modules.network_discovery import run_arp_discovery_module, run_live_host_discovery_module
from modules.nmap_scanner import (
    run_full_port_scan_module, run_os_detection_module,
    run_quick_port_scan_module, run_syn_scan_module,
    run_vulnerability_assessment_module
)
from modules.recon_pipeline import run_recon_pipeline_module
from modules.smb_recon import run_smb_discovery_module
from modules.traceroute import run_traceroute_module
from modules.web_recon import run_web_recon_module

console = Console()
logger = setup_logger("kibuo")

CONFIG_PATH = Path("config/settings.json")

# Standard Menu Definitions
MENU_OPTIONS: List[Tuple[str, str]] = [
    ("[01]", "ARP Network Discovery"),
    ("[02]", "Live Host Discovery"),
    ("[03]", "Quick Port Scan"),
    ("[04]", "Full Port Scan"),
    ("[05]", "OS Detection"),
    ("[06]", "SYN Scan"),
    ("[07]", "Vulnerability Assessment"),
    ("[08]", "IP Intelligence"),
    ("[09]", "Whois & DNS"),
    ("[10]", "Traceroute"),
    ("[11]", "Web Recon"),
    ("[12]", "Exploit Lookup"),
    ("[13]", "SMB Discovery"),
    ("[14]", "Full Recon Pipeline"),
    ("[99]", "About"),
    ("[00]", "Exit"),
]


def load_settings() -> Dict[str, any]:
    """Load configuration settings from config/settings.json."""
    if CONFIG_PATH.exists():
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            logger.warning("Could not read %s: %s", CONFIG_PATH, exc)
    return {"authorization_notice_accepted": False}


def save_settings(settings: Dict[str, any]) -> None:
    """Persist updated settings to config/settings.json."""
    try:
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2)
    except Exception as exc:
        logger.warning("Could not write %s: %s", CONFIG_PATH, exc)


def check_authorization(settings: Dict[str, any]) -> bool:
    """
    Ensure the user has acknowledged the mandatory legal authorization notice.
    """
    if settings.get("authorization_notice_accepted", False):
        return True

    accepted = display_authorization_warning()
    if accepted:
        settings["authorization_notice_accepted"] = True
        save_settings(settings)
        return True
    else:
        clear_screen()
        display_error("Authorization declined. Kibuo cannot execute without confirmed authorization.")
        display_info("Exiting Kibuo.")
        sys.exit(0)


def signal_handler(sig, frame):
    """Graceful Ctrl+C handler preventing Python stack traces."""
    console.print()
    display_warning("Interrupt signal received (Ctrl+C). Returning to menu...")
    raise KeyboardInterrupt()


def view_recent_reports() -> None:
    """List and inspect generated assessment reports in reports/."""
    clear_screen()
    reports_dir = Path("reports")
    if not reports_dir.exists():
        display_warning("Reports directory does not exist yet.")
        return

    txt_files = sorted(list(reports_dir.glob("*_report.txt")), key=os.path.getmtime, reverse=True)
    if not txt_files:
        display_warning("No saved reports found in reports/ directory.")
        return

    table = Table(title="Generated Assessment Reports (reports/)", box=None)
    table.add_column("#", style="dim", width=4)
    table.add_column("Report Filename", style="bold cyan")
    table.add_column("Generated Time", style="yellow", width=20)
    table.add_column("File Size", style="dim", width=12)

    for idx, f in enumerate(txt_files[:15], 1):
        mtime = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        size = f"{f.stat().st_size / 1024:.1f} KB"
        table.add_row(str(idx), f.name, mtime, size)

    console.print(table)
    console.print()
    sel = Prompt.ask("Enter report # to preview in terminal, or press Enter to return", default="")
    if sel.isdigit() and 1 <= int(sel) <= len(txt_files):
        chosen_file = txt_files[int(sel) - 1]
        clear_screen()
        console.print(Panel(chosen_file.read_text(encoding="utf-8", errors="replace"), title=f"Report Preview: {chosen_file.name}", border_style=COLOR_BRAND))


def main():
    """Main interactive execution loop."""
    signal.signal(signal.SIGINT, signal_handler)
    settings = load_settings()

    # Step 1: Legal Authorization Check
    check_authorization(settings)

    # Step 2: Main Menu Loop
    while True:
        try:
            clear_screen()
            print_banner(show_sysinfo=True)
            render_menu(MENU_OPTIONS)
            console.print()

            choice = Prompt.ask(
                f"[bold {COLOR_BRAND}]Kibuo ❯ Select an option [00-14, 99][/bold {COLOR_BRAND}]",
                default="14"
            ).strip().lower()

            # Normalize single digits: '1' -> '01', '2' -> '02', etc.
            if choice.isdigit() and len(choice) == 1 and choice != "0":
                choice = f"0{choice}"
            elif choice == "0":
                choice = "00"

            if choice in ("00", "exit", "q", "quit"):
                clear_screen()
                console.print(f"[bold {COLOR_BRAND}]Thank you for using Kibuo Reconnaissance Toolkit. Stay ethical and secure.[/bold {COLOR_BRAND}]\n")
                break

            elif choice == "01":
                clear_screen()
                run_arp_discovery_module()
                pause_prompt()

            elif choice == "02":
                clear_screen()
                run_live_host_discovery_module()
                pause_prompt()

            elif choice == "03":
                clear_screen()
                run_quick_port_scan_module()
                pause_prompt()

            elif choice == "04":
                clear_screen()
                run_full_port_scan_module()
                pause_prompt()

            elif choice == "05":
                clear_screen()
                run_os_detection_module()
                pause_prompt()

            elif choice == "06":
                clear_screen()
                run_syn_scan_module()
                pause_prompt()

            elif choice == "07":
                clear_screen()
                run_vulnerability_assessment_module()
                pause_prompt()

            elif choice == "08":
                clear_screen()
                run_ip_intelligence_module()
                pause_prompt()

            elif choice == "09":
                clear_screen()
                run_dns_whois_module()
                pause_prompt()

            elif choice == "10":
                clear_screen()
                run_traceroute_module()
                pause_prompt()

            elif choice == "11":
                clear_screen()
                run_web_recon_module()
                pause_prompt()

            elif choice == "12":
                clear_screen()
                run_exploit_lookup_module()
                pause_prompt()

            elif choice == "13":
                clear_screen()
                run_smb_discovery_module()
                pause_prompt()

            elif choice == "14":
                clear_screen()
                run_recon_pipeline_module()
                pause_prompt()

            elif choice in ("deps", "dep", "dependencies", "15"):
                clear_screen()
                DependencyManager.run_interactive_installer()
                pause_prompt()

            elif choice in ("reports", "report", "history", "log", "logs", "r", "16"):
                view_recent_reports()
                pause_prompt()

            elif choice == "99":
                display_about()

            else:
                display_warning(f"Invalid selection: '{choice}'. Enter a valid option between [00] and [14], or [99].")
                time_sleep = Prompt.ask("[dim]Press Enter to continue...[/dim]", default="")

        except KeyboardInterrupt:
            # Caught from signal handler or input
            console.print("\n[dim]Action cancelled by user. Returning to main menu...[/dim]")
            try:
                Prompt.ask("[dim]Press Enter to continue...[/dim]", default="")
            except KeyboardInterrupt:
                pass
        except Exception as exc:
            logger.exception("Unhandled error in main loop: %s", exc)
            display_error(f"An unexpected error occurred: {exc}")
            pause_prompt()


if __name__ == "__main__":
    main()

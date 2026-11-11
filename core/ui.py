"""
Terminal User Interface and Presentation Layer for Kibuo.

Built on Rich to provide responsive terminal layouts, orange/yellow branding,
color-coded status tables, scan summary panels, loading spinners, and graceful transitions.
"""

import os
import platform
import shutil
import sys
from typing import Any, Dict, List, Optional, Tuple

from rich.align import Align
from rich.box import DOUBLE, ROUNDED, SIMPLE, SQUARE
from rich.console import Console, Group
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.status import Status
from rich.style import Style
from rich.table import Table
from rich.text import Text

from core.dependency_manager import DependencyManager
from core.permission_manager import PermissionManager

# Global Rich Console
console = Console()

# Theme color constants
COLOR_BRAND = "bright_yellow"
COLOR_BRAND_ALT = "orange3"
COLOR_INFO = "cyan"
COLOR_SUCCESS = "bright_green"
COLOR_WARN = "bright_yellow"
COLOR_ERROR = "bright_red"
COLOR_MUTED = "bright_black"
COLOR_TEXT = "white"

ASCII_BANNER = r"""
  ██╗  ██╗██╗██████╗ ██╗   ██╗ ██████╗ 
  ██║ ██╔╝██║██╔══██╗██║   ██║██╔═══██╗
  █████═╝ ██║██████╔╝██║   ██║██║   ██║
  ██╔═██╗ ██║██╔══██╗██║   ██║██║   ██║
  ██║ ╚██╗██║██████╔╝╚██████╔╝╚██████╔╝
  ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝  ╚═════╝ 
"""

SUBTITLE = "PROFESSIONAL NETWORK RECONNAISSANCE TOOLKIT"
VERSION_STRING = "Version 1.0.0 | Authorized Auditing & Discovery"


def clear_screen() -> None:
    """Clear terminal screen gracefully without leaving artifacts."""
    os.system("clear" if os.name != "nt" else "cls")


def print_banner(show_sysinfo: bool = True) -> None:
    """Render the Kibuo brand banner and system execution metadata."""
    banner_text = Text(ASCII_BANNER, style=f"bold {COLOR_BRAND}")
    sub_text = Text(f"{SUBTITLE}\n{VERSION_STRING}", style=f"bold {COLOR_BRAND_ALT}", justify="center")
    
    panel_group = [banner_text, sub_text]

    if show_sysinfo:
        os_info = DependencyManager.detect_os()
        priv_info = PermissionManager.get_system_privilege_summary()
        
        status_color = COLOR_SUCCESS if priv_info["is_root"] else COLOR_INFO
        sys_line = Text()
        sys_line.append(" System: ", style="bold white")
        sys_line.append(f"{os_info['distro_name']} ({platform.release()})", style=COLOR_INFO)
        sys_line.append(" | User: ", style="bold white")
        sys_line.append(f"{priv_info['user']}", style=COLOR_INFO)
        sys_line.append(" | Mode: ", style="bold white")
        sys_line.append(f"[{priv_info['status_label']}]", style=f"bold {status_color}")
        panel_group.append(Text("\n"))
        panel_group.append(Align.center(sys_line))

    banner_panel = Panel(
        Group(*panel_group),
        box=DOUBLE,
        border_style=COLOR_BRAND,
        padding=(0, 2)
    )
    console.print(banner_panel)


def display_authorization_warning() -> bool:
    """
    Display mandatory legal authorization warning.
    Returns True if user explicitly accepts, False otherwise.
    """
    clear_screen()
    print_banner(show_sysinfo=False)
    
    warning_text = Text()
    warning_text.append("LEGAL & AUTHORIZATION NOTICE\n\n", style="bold red")
    warning_text.append(
        "Kibuo is an advanced cybersecurity reconnaissance and assessment toolkit\n"
        "strictly engineered for:\n"
        "  • Authorized penetration testing and security assessments\n"
        "  • Authorized internal network administration and asset discovery\n"
        "  • Academic, educational, and laboratory cybersecurity research\n\n",
        style="white"
    )
    warning_text.append(
        "Scanning, assessing, or querying systems and networks without prior explicit,\n"
        "documented permission from the asset owner is illegal and unethical under\n"
        "applicable computer crime statutes (including the CFAA, UK Computer Misuse Act,\n"
        "and international cyber defense laws).\n\n",
        style="bright_yellow"
    )
    warning_text.append(
        "By proceeding, you explicitly warrant and affirm that you possess full legal\n"
        "authorization to assess all specified target hosts, subnets, and domains.\n",
        style="bold white"
    )

    warning_panel = Panel(
        warning_text,
        title="[bold red]⚠️  MANDATORY AUTHORIZATION NOTICE  ⚠️[/bold red]",
        border_style="red",
        box=ROUNDED,
        padding=(1, 2)
    )
    console.print(warning_panel)
    
    console.print()
    return Confirm.ask(
        f"[bold {COLOR_BRAND}]Do you acknowledge this policy and confirm you are authorized to assess target systems?[/bold {COLOR_BRAND}]",
        default=False
    )


def render_menu(options: List[Tuple[str, str]], columns_count: Optional[int] = None) -> None:
    """
    Display a responsive two-column or three-column menu of modules.
    
    Args:
        options: List of tuples (identifier, title), e.g. [("[01]", "ARP Network Discovery")]
        columns_count: Desired number of columns (auto-computed if None).
    """
    term_width = console.width
    if columns_count is None:
        if term_width >= 110:
            columns_count = 2
        else:
            columns_count = 2

    # Split options into categories or balanced columns
    table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
    for _ in range(columns_count):
        table.add_column(justify="left", ratio=1)

    # Format rows
    num_opts = len(options)
    rows_needed = (num_opts + columns_count - 1) // columns_count

    for r in range(rows_needed):
        row_cells = []
        for c in range(columns_count):
            idx = r + c * rows_needed
            if idx < num_opts:
                code, label = options[idx]
                if code in ("[99]", "[00]"):
                    code_style = COLOR_BRAND_ALT
                    label_style = "bold white"
                else:
                    code_style = COLOR_BRAND
                    label_style = "white"

                cell_text = Text()
                cell_text.append(f"{code:<5}", style=f"bold {code_style}")
                cell_text.append(f"{label}", style=label_style)
                row_cells.append(cell_text)
            else:
                row_cells.append("")
        table.add_row(*row_cells)

    menu_panel = Panel(
        table,
        title=f"[bold {COLOR_BRAND_ALT}]RECONNAISSANCE MODULES[/bold {COLOR_BRAND_ALT}]",
        border_style=COLOR_BRAND_ALT,
        box=ROUNDED,
        padding=(1, 2)
    )
    console.print(menu_panel)


def display_section_header(title: str, subtitle: Optional[str] = None) -> None:
    """Render a clean module header."""
    hdr = Text(f"▶ {title.upper()}", style=f"bold {COLOR_BRAND}")
    if subtitle:
        hdr.append(f"\n{subtitle}", style="dim white")
    console.print(Panel(hdr, box=ROUNDED, border_style=COLOR_BRAND, padding=(0, 2)))


def display_success(message: str) -> None:
    """Print success message."""
    console.print(f"[bold {COLOR_SUCCESS}]✔ [SUCCESS][/bold {COLOR_SUCCESS}] {message}")


def display_info(message: str) -> None:
    """Print informational message."""
    console.print(f"[{COLOR_INFO}]ℹ [INFO][/{COLOR_INFO}] {message}")


def display_warning(message: str) -> None:
    """Print warning message."""
    console.print(f"[bold {COLOR_WARN}]⚠ [WARNING][/bold {COLOR_WARN}] {message}")


def display_error(message: str) -> None:
    """Print error message."""
    console.print(f"[bold {COLOR_ERROR}]✖ [ERROR][/bold {COLOR_ERROR}] {message}")


def display_summary_card(
    target: str,
    status: str,
    open_ports_count: int,
    services_list: List[str],
    duration: float,
    export_paths: Optional[Dict[str, str]] = None
) -> None:
    """
    Render professional scan summary card matching project specification:
    ╭──────────── KIBUO SCAN SUMMARY ────────────╮
    │ Target: 192.168.1.10                       │
    │ Status: Completed                          │
    │ Open Ports: 3                              │
    │ Services: SSH, HTTP, HTTPS                 │
    │ Duration: 00:01:24                          │
    ╰────────────────────────────────────────────╯
    """
    mins = int(duration // 60)
    secs = int(duration % 60)
    dur_str = f"{mins:02d}:{secs:02d}"

    content = Table(show_header=False, box=None, padding=(0, 1))
    content.add_column("Key", style="bold cyan", width=14)
    content.add_column("Value", style="white")

    content.add_row("Target", f"[bold white]{target}[/bold white]")
    content.add_row("Status", f"[bold {COLOR_SUCCESS}]{status}[/bold {COLOR_SUCCESS}]")
    content.add_row("Open Ports", f"[bold {COLOR_BRAND}]{open_ports_count}[/bold {COLOR_BRAND}]")
    services_str = ", ".join(services_list) if services_list else "None detected"
    content.add_row("Services", services_str)
    content.add_row("Duration", dur_str)

    if export_paths:
        rep_txt = export_paths.get("report_txt", "N/A")
        rep_json = export_paths.get("report_json", "N/A")
        rep_html = export_paths.get("report_html")
        content.add_row("Text Report", f"[dim]{rep_txt}[/dim]")
        content.add_row("JSON Report", f"[dim]{rep_json}[/dim]")
        if rep_html:
            content.add_row("HTML Report", f"[bold cyan]{rep_html}[/bold cyan]")

    panel = Panel(
        content,
        title="[bold bright_yellow]KIBUO SCAN SUMMARY[/bold bright_yellow]",
        box=ROUNDED,
        border_style=COLOR_BRAND,
        padding=(1, 2)
    )
    console.print(panel)


def display_about() -> None:
    """Render About page with architecture, author, and security ethics."""
    clear_screen()
    print_banner(show_sysinfo=True)

    about_text = Text()
    about_text.append("KIBUO SECURITY RECONNAISSANCE TOOLKIT\n", style=f"bold {COLOR_BRAND}")
    about_text.append("Version: 1.0.0\n", style="bold white")
    about_text.append("Platform: Kali Linux, Debian, Ubuntu\n", style="cyan")
    about_text.append("License: MIT Open Source\n\n", style="white")

    about_text.append("ARCHITECTURE & CAPABILITIES:\n", style="bold bright_yellow")
    about_text.append("  • Modular Python 3 engine with strict subprocess array isolation (shell=False)\n")
    about_text.append("  • Real-time Nmap, ARP, DNS, Whois, Traceroute, and Web recon integration\n")
    about_text.append("  • Structured assessment logs in logs/<target>_<timestamp>/\n")
    about_text.append("  • Executive reports generated in reports/ in JSON and human-readable TXT\n")
    about_text.append("  • Built-in SearchSploit vulnerability and CVE intelligence cross-referencing\n")
    about_text.append("  • Automatic privilege checks and unprivileged fallback recommendations\n\n")

    about_text.append("ETHICAL USE & COMPLIANCE:\n", style="bold red")
    about_text.append("  Kibuo is intended strictly for authorized security assessments, penetration\n")
    about_text.append("  testing with written permission, internal network administration, and safe\n")
    about_text.append("  cybersecurity education. Unauthorized access or network disruption is prohibited.\n")

    panel = Panel(
        about_text,
        title="[bold bright_yellow]ABOUT KIBUO[/bold bright_yellow]",
        box=ROUNDED,
        border_style=COLOR_BRAND,
        padding=(1, 2)
    )
    console.print(panel)
    Prompt.ask("\n[dim]Press Enter to return to main menu...[/dim]", default="")


def pause_prompt() -> None:
    """Pause before clearing or returning to menu."""
    console.print()
    Prompt.ask("[dim]Press Enter to continue...[/dim]", default="")

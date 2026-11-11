"""
MAC Address Analysis and Manufacturer Lookup Module for Kibuo.

Provides offline IEEE OUI vendor resolution, identification of randomized
or locally administered MAC addresses, local device MAC mapping, and clear
educational guidance on Layer 2 (Data Link) vs Layer 3 (Network) boundaries.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table
from rich.text import Text

from core.logger import get_logger
from core.ui import (
    COLOR_BRAND, COLOR_BRAND_ALT, COLOR_INFO, COLOR_SUCCESS,
    COLOR_WARN, display_error, display_info, display_section_header,
    display_success, display_warning
)
from core.validator import ValidationError, validate_mac_address

logger = get_logger("kibuo.mac_lookup")
console = Console()

OUI_DB_PATH = Path("data/mac_vendors/oui_database.json")
_OUI_CACHE: Optional[Dict[str, str]] = None


def load_oui_database() -> Dict[str, str]:
    """Load the offline OUI prefix database into memory."""
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE

    if OUI_DB_PATH.exists():
        try:
            with open(OUI_DB_PATH, "r", encoding="utf-8") as f:
                _OUI_CACHE = json.load(f)
                return _OUI_CACHE
        except Exception as exc:
            logger.warning("Could not load OUI database: %s", exc)

    _OUI_CACHE = {}
    return _OUI_CACHE


def is_locally_administered_mac(mac_str: str) -> bool:
    """
    Check if the IEEE 802 Locally Administered bit is set.
    The second least-significant bit of the first byte indicates
    a locally administered / randomized address (e.g. 02, 06, 0A, 0E, etc.).
    """
    cleaned = mac_str.replace(":", "").replace("-", "")
    if len(cleaned) >= 2:
        try:
            byte0 = int(cleaned[:2], 16)
            return bool(byte0 & 0x02)
        except ValueError:
            pass
    return False


def is_multicast_mac(mac_str: str) -> bool:
    """Check if the MAC is a multicast/broadcast destination."""
    cleaned = mac_str.replace(":", "").replace("-", "")
    if len(cleaned) >= 2:
        try:
            byte0 = int(cleaned[:2], 16)
            return bool(byte0 & 0x01)
        except ValueError:
            pass
    return False


def get_vendor_for_mac(mac_str: str) -> Tuple[str, str]:
    """
    Lookup vendor for a given MAC address.
    
    Returns:
        Tuple of (vendor_name, details_note)
    """
    if not mac_str or mac_str.upper() in ("UNKNOWN", "N/A", "N/A (LOCAL / HOST INTERFACE)"):
        return ("Unknown Vendor", "MAC unavailable")

    try:
        norm_mac = validate_mac_address(mac_str)
    except ValidationError:
        norm_mac = mac_str.upper()

    cleaned = norm_mac.replace(":", "").replace("-", "")
    prefix6 = cleaned[:6]

    db = load_oui_database()
    vendor = db.get(prefix6)

    is_local = is_locally_administered_mac(norm_mac)
    is_mcast = is_multicast_mac(norm_mac)

    if vendor:
        note = "IEEE OUI Match"
        if is_local:
            note += " (Locally Administered)"
        return (vendor, note)

    if is_mcast:
        return ("Multicast / Broadcast Group", "Standard RFC / IEEE Multicast")

    if is_local:
        return (
            "Randomized / Private MAC",
            "Locally administered bit set (iOS / Android / Windows Privacy Address)"
        )

    return ("Unknown Manufacturer", "OUI prefix not in local database")


def display_mac_scope_explanation() -> None:
    """Explain Layer 2 MAC address boundaries vs Layer 3 routed IPs."""
    text = Text()
    text.append("UNDERSTANDING MAC ADDRESS VISIBILITY & BOUNDARIES\n\n", style="bold bright_yellow")
    text.append(
        "1. Local Broadcast Domain (Layer 2):\n", style="bold cyan"
    )
    text.append(
        "   • MAC addresses are hardware identifiers bound to the physical or Wi-Fi data link.\n"
        "   • Devices can only discover each other's MAC addresses on the SAME broadcast subnet\n"
        "     via Link-Layer ARP (Address Resolution Protocol) or NDP (IPv6).\n\n",
        style="white"
    )
    text.append(
        "2. Routed & Remote Internet Traffic (Layer 3):\n", style="bold cyan"
    )
    text.append(
        "   • When communicating across routers or the public internet, each router rewrites\n"
        "     the Layer 2 MAC header with its own next-hop interface address.\n"
        "   • Remote web servers or public IPs NEVER expose their physical MAC address to you;\n"
        "     packets received from the internet will always display your default gateway's MAC.\n\n",
        style="white"
    )
    text.append(
        "3. Privacy Features & MAC Randomization:\n", style="bold cyan"
    )
    text.append(
        "   • Modern mobile devices (iOS, Android, Windows 11) generate randomized MACs per Wi-Fi network.\n"
        "   • These addresses set the IEEE 'Locally Administered' bit (x2:xx:xx, x6:xx:xx, etc.) and\n"
        "     will not match physical vendor factory OUIs by design.\n",
        style="white"
    )

    console.print(Panel(text, title="[bold cyan]Layer 2 vs Layer 3 Networking Guide[/bold cyan]", border_style=COLOR_INFO))


def run_mac_information_module(discovered_devices: Optional[List[Dict[str, Any]]] = None) -> None:
    """
    Interactive execution handler for MAC Address Information module.
    """
    display_section_header("MAC Address Information & Manufacturer Lookup", "IEEE OUI vendor resolution and Layer 2 link analysis")

    # Display discovered devices MACs if available
    if discovered_devices:
        table = Table(title="Discovered Local Devices — MAC Analysis", box=None)
        table.add_column("IP Address", style="bold green", width=18)
        table.add_column("MAC Address", style="bold cyan", width=20)
        table.add_column("Manufacturer / Vendor", style="white", width=28)
        table.add_column("Hardware Scope / Type", style="yellow")

        for dev in discovered_devices:
            ip = dev.get("ip", "Unknown")
            mac = dev.get("mac", "Unknown")
            vendor, details = get_vendor_for_mac(mac)
            table.add_row(ip, mac, vendor, details)

        console.print(table)
        console.print()

    # Menu of options
    while True:
        console.print(f"[bold {COLOR_BRAND}]MAC Analysis Options:[/bold {COLOR_BRAND}]")
        console.print("  [1] Lookup Vendor for an Arbitrary MAC Address")
        console.print("  [2] Read Layer 2 vs Layer 3 MAC Boundary Guide")
        console.print("  [3] Inspect Active Kernel ARP Cache (/proc/net/arp)")
        console.print("  [4] Return to Menu")
        console.print()

        choice = Prompt.ask(f"[bold {COLOR_BRAND}]Select option [1-4][/bold {COLOR_BRAND}]", default="1").strip()

        if choice == "1":
            mac_input = Prompt.ask("[bold white]Enter MAC address (e.g. 00:50:56:C0:00:08 or 4A1374867D81)[/bold white]").strip()
            try:
                norm_mac = validate_mac_address(mac_input)
                vendor, details = get_vendor_for_mac(norm_mac)
                is_local = is_locally_administered_mac(norm_mac)
                
                info_table = Table(show_header=False, box=None)
                info_table.add_column("Property", style="bold cyan", width=22)
                info_table.add_column("Value", style="white")

                info_table.add_row("Normalized MAC", f"[bold white]{norm_mac}[/bold white]")
                info_table.add_row("OUI Prefix (24-bit)", norm_mac[:8])
                info_table.add_row("Manufacturer / Vendor", f"[bold green]{vendor}[/bold green]")
                info_table.add_row("Classification", details)
                info_table.add_row("Locally Administered", "[bold yellow]Yes (Randomized / Virtual)[/bold yellow]" if is_local else "No (Factory Universal OUI)")

                console.print()
                console.print(Panel(info_table, title=f"MAC Query Result: {norm_mac}", border_style=COLOR_SUCCESS))
                console.print()
            except ValidationError as err:
                display_error(str(err))

        elif choice == "2":
            console.print()
            display_mac_scope_explanation()
            console.print()

        elif choice == "3":
            console.print()
            arp_path = Path("/proc/net/arp")
            if arp_path.exists():
                lines = arp_path.read_text(encoding="utf-8").splitlines()
                arp_table = Table(title="Kernel Neighbor Cache (/proc/net/arp)", box=None)
                arp_table.add_column("IP Address", style="bold green", width=18)
                arp_table.add_column("HW Address (MAC)", style="bold cyan", width=20)
                arp_table.add_column("Vendor Resolution", style="white", width=26)
                arp_table.add_column("Device / Interface", style="yellow")

                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 6:
                        ip_val, _, _, mac_val, _, dev_val = parts[:6]
                        if mac_val != "00:00:00:00:00:00":
                            v_name, _ = get_vendor_for_mac(mac_val)
                            arp_table.add_row(ip_val, mac_val.upper(), v_name, dev_val)

                console.print(arp_table)
            else:
                display_warning("/proc/net/arp is not accessible on this system.")
            console.print()

        elif choice in ("4", "back", "q", "quit", "exit"):
            break

"""
Device Identification Engine for Kibuo.

Estimates device categories (Smartphone, Laptop, Desktop Computer, Router,
Network Printer, Smart TV, IoT Device, Server, Unknown Device) based on
multi-factor evidence: MAC vendor, hostnames, default gateway status,
and non-intrusive port signatures.

Displays clear confidence levels (High, Medium, Low) and explicitly avoids
claiming certainty when evidence is incomplete or ambiguous.
"""

import socket
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from core.logger import get_logger
from core.ui import (
    COLOR_BRAND, COLOR_BRAND_ALT, COLOR_INFO, COLOR_SUCCESS,
    COLOR_WARN, display_error, display_info, display_section_header,
    display_success, display_warning
)
from modules.mac_lookup import get_vendor_for_mac, is_locally_administered_mac

logger = get_logger("kibuo.device_identification")
console = Console()

# Standard supported categories per specification
CATEGORIES = [
    "Smartphone",
    "Laptop",
    "Desktop Computer",
    "Router",
    "Network Printer",
    "Smart TV",
    "IoT Device",
    "Server",
    "Unknown Device",
]

# Common service fingerprint ports used for non-intrusive heuristic identification
FINGERPRINT_PORTS = {
    22: "SSH (Server / Linux)",
    53: "DNS (Router / Gateway)",
    80: "HTTP (Web / Admin Interface)",
    139: "NetBIOS (Windows / Samba)",
    443: "HTTPS (Web / Secure Admin)",
    445: "SMB (Windows PC / File Server)",
    515: "LPD (Network Printer)",
    631: "IPP / CUPS (Network Printer)",
    1883: "MQTT (IoT / Smart Home)",
    3389: "RDP (Windows Desktop / Laptop / Server)",
    5000: "UPnP / Media (Smart TV / NAS / IoT)",
    8008: "Google Cast / DIAL (Smart TV / Streaming)",
    8009: "Chromecast (Smart TV / Media Player)",
    8080: "HTTP Alt (Web / Proxy / Server)",
    9100: "JetDirect (Network Printer)",
}


def quick_port_probe(ip: str, ports: Optional[List[int]] = None, timeout: float = 0.5) -> List[int]:
    """
    Non-intrusive TCP connect probe against key fingerprint ports.
    Used solely to gather evidence for device classification on authorized networks.
    """
    if ports is None:
        ports = [22, 53, 80, 445, 631, 1883, 3389, 8008, 9100]

    open_ports = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                res = sock.connect_ex((ip, port))
                if res == 0:
                    open_ports.append(port)
        except Exception:
            pass
    return open_ports


def classify_device(
    ip: str,
    mac: str = "",
    hostname: str = "",
    vendor: str = "",
    is_gateway: bool = False,
    open_ports: Optional[List[int]] = None
) -> Dict[str, Any]:
    """
    Analyze multi-factor evidence to estimate device category and confidence level.
    
    Returns:
        Dict with keys:
            category: str (one of the supported categories)
            confidence: 'High' | 'Medium' | 'Low'
            evidence: List[str]
            details: str
    """
    if open_ports is None:
        open_ports = []

    mac_upper = (mac or "").upper()
    host_lower = (hostname or "").lower()
    vendor_lower = (vendor or "").lower()

    if not vendor or vendor == "Unknown Vendor":
        resolved_vendor, _ = get_vendor_for_mac(mac)
        if resolved_vendor != "Unknown Vendor":
            vendor = resolved_vendor
            vendor_lower = vendor.lower()

    evidence: List[str] = []
    scores: Dict[str, int] = {cat: 0 for cat in CATEGORIES}

    # 1. Gateway Status Check
    if is_gateway:
        scores["Router"] += 40
        evidence.append("Host configured as active network default gateway")

    # 2. Hostname Heuristics
    if host_lower:
        if any(w in host_lower for w in ("iphone", "ipad", "android", "galaxy", "pixel", "oneplus", "redmi", "mobile")):
            scores["Smartphone"] += 35
            evidence.append(f"Hostname suggests mobile device ('{hostname}')")
        elif any(w in host_lower for w in ("macbook", "laptop", "thinkpad", "zenbook", "notebook", "xps")):
            scores["Laptop"] += 35
            evidence.append(f"Hostname suggests portable laptop ('{hostname}')")
        elif any(w in host_lower for w in ("desktop", "workstation", "pc", "optiplex", "rig")):
            scores["Desktop Computer"] += 30
            evidence.append(f"Hostname suggests desktop system ('{hostname}')")
        elif any(w in host_lower for w in ("router", "gateway", "ap", "modem", "openwrt", "asus", "linksys", "unifi")):
            scores["Router"] += 35
            evidence.append(f"Hostname indicates network routing hardware ('{hostname}')")
        elif any(w in host_lower for w in ("printer", "print", "canon", "epson", "brother", "laserjet", "deskjet")):
            scores["Network Printer"] += 45
            evidence.append(f"Hostname matches printing appliance ('{hostname}')")
        elif any(w in host_lower for w in ("tv", "bravia", "roku", "chromecast", "firestick", "webos", "tizen", "shield")):
            scores["Smart TV"] += 45
            evidence.append(f"Hostname indicates smart display or TV ('{hostname}')")
        elif any(w in host_lower for w in ("esp_", "tuya", "sonos", "philips-hue", "shelly", "smart", "cam", "camera", "sensor")):
            scores["IoT Device"] += 40
            evidence.append(f"Hostname indicates embedded/smart home IoT ('{hostname}')")
        elif any(w in host_lower for w in ("server", "srv", "nas", "synology", "qnap", "proxmox", "esxi", "docker", "debian", "ubuntu", "arch")):
            scores["Server"] += 35
            evidence.append(f"Hostname matches server / infrastructure ('{hostname}')")

    # 3. Vendor OUI Heuristics
    if vendor_lower:
        if "cisco" in vendor_lower or "tp-link" in vendor_lower or "netgear" in vendor_lower or "d-link" in vendor_lower or "ubiquiti" in vendor_lower or "mikrotik" in vendor_lower or "huawei" in vendor_lower:
            scores["Router"] += 25
            evidence.append(f"Vendor '{vendor}' specializes in routing & network appliances")
        elif "canon" in vendor_lower or "brother" in vendor_lower or "epson" in vendor_lower or "xerox" in vendor_lower or "ricoh" in vendor_lower:
            scores["Network Printer"] += 45
            evidence.append(f"Vendor '{vendor}' is a dedicated printer manufacturer")
        elif "espressif" in vendor_lower or "raspberry pi" in vendor_lower:
            scores["IoT Device"] += 35
            evidence.append(f"Vendor '{vendor}' manufactures embedded microcontrollers/SBCs")
        elif "roku" in vendor_lower or "sonos" in vendor_lower:
            scores["Smart TV"] += 40
            evidence.append(f"Vendor '{vendor}' manufactures media/audio streaming hardware")
        elif "synology" in vendor_lower or "qnap" in vendor_lower or "vmware" in vendor_lower or "qemu" in vendor_lower:
            scores["Server"] += 40
            evidence.append(f"Vendor '{vendor}' provides servers / virtualization")
        elif "apple" in vendor_lower:
            # Apple could be iPhone, iPad, MacBook, iMac, Apple TV
            if 8008 in open_ports or 5000 in open_ports:
                scores["Smart TV"] += 20
            elif "macbook" in host_lower:
                scores["Laptop"] += 30
            else:
                scores["Smartphone"] += 15
                scores["Laptop"] += 10
            evidence.append(f"Vendor is Apple, Inc. (consumer mobile/PC ecosystem)")
        elif "samsung" in vendor_lower:
            if 8008 in open_ports or "tizen" in host_lower or "tv" in host_lower:
                scores["Smart TV"] += 35
            else:
                scores["Smartphone"] += 20
            evidence.append(f"Vendor is Samsung Electronics (mobile/smart display)")
        elif "intel" in vendor_lower or "realtek" in vendor_lower:
            scores["Laptop"] += 15
            scores["Desktop Computer"] += 15
            evidence.append(f"Vendor '{vendor}' produces general PC NIC hardware")
        elif "dell" in vendor_lower or "lenovo" in vendor_lower or "hewlett packard" in vendor_lower:
            scores["Laptop"] += 20
            scores["Desktop Computer"] += 15
            scores["Server"] += 10
            evidence.append(f"Vendor '{vendor}' builds business PCs, laptops, and servers")

    # 4. Open Port Heuristics
    if 631 in open_ports or 515 in open_ports or 9100 in open_ports:
        scores["Network Printer"] += 50
        evidence.append(f"Printer daemon ports open ({[p for p in open_ports if p in (631, 515, 9100)]})")
    if 8008 in open_ports or 8009 in open_ports:
        scores["Smart TV"] += 45
        evidence.append(f"Google Cast / DIAL media streaming ports open ({[p for p in open_ports if p in (8008, 8009)]})")
    if 53 in open_ports and (is_gateway or 80 in open_ports or 443 in open_ports):
        scores["Router"] += 35
        evidence.append("DNS daemon (53) and web administration interface open")
    if 1883 in open_ports:
        scores["IoT Device"] += 40
        evidence.append("MQTT broker / client port 1883 active")
    if 22 in open_ports and (80 in open_ports or 443 in open_ports or 8080 in open_ports):
        scores["Server"] += 30
        evidence.append("SSH administration (22) and web server services detected")
    if 445 in open_ports or 139 in open_ports or 3389 in open_ports:
        scores["Desktop Computer"] += 15
        scores["Laptop"] += 15
        evidence.append("SMB / RDP file sharing or remote desktop service open")

    # 5. Randomized MAC check
    if is_locally_administered_mac(mac_upper):
        evidence.append("MAC address has locally administered bit set (frequent on mobile OS)")
        scores["Smartphone"] += 15

    # Determine highest scoring category
    sorted_categories = sorted(
        [(cat, score) for cat, score in scores.items() if cat != "Unknown Device"],
        key=lambda x: x[1],
        reverse=True
    )

    top_cat, top_score = sorted_categories[0]

    if top_score >= 50:
        confidence = "High"
    elif top_score >= 25:
        confidence = "Medium"
    elif top_score > 0:
        confidence = "Low"
    else:
        top_cat = "Unknown Device"
        confidence = "Low"
        evidence.append("Insufficient identifiable indicators; general device")

    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname or "N/A",
        "vendor": vendor or "Unknown",
        "category": top_cat,
        "confidence": confidence,
        "score": top_score,
        "evidence": evidence,
        "open_ports": open_ports,
    }


def run_device_identification_module(discovered_devices: Optional[List[Dict[str, Any]]] = None) -> None:
    """
    Interactive execution handler for Device Identification module.
    """
    display_section_header("Device Identification Engine", "Heuristic multi-factor device categorization with confidence scoring")

    devices_to_analyze = list(discovered_devices) if discovered_devices else []

    if not devices_to_analyze:
        display_info("No devices currently held in discovery memory.")
        console.print(f"[bold {COLOR_BRAND}]Options:[/bold {COLOR_BRAND}]")
        console.print("  [1] Enter a single IP or MAC to classify")
        console.print("  [2] Read available device categories and heuristic principles")
        console.print("  [3] Return to Menu")
        console.print()

        choice = Prompt.ask(f"[bold {COLOR_BRAND}]Select option [1-3][/bold {COLOR_BRAND}]", default="1").strip()

        if choice == "1":
            target_ip = Prompt.ask("[bold white]Enter Target IP address (e.g. 192.168.100.1)[/bold white]").strip()
            target_mac = Prompt.ask("[bold white]Enter MAC address (optional, or press Enter)[/bold white]", default="").strip()
            target_host = Prompt.ask("[bold white]Enter Hostname (optional, or press Enter)[/bold white]", default="").strip()
            
            probe_ports = Confirm.ask("Perform quick non-intrusive service fingerprint check?", default=True)
            open_ports = quick_port_probe(target_ip) if probe_ports else []

            devices_to_analyze.append({
                "ip": target_ip,
                "mac": target_mac,
                "hostname": target_host,
                "vendor": "",
                "open_ports": open_ports
            })
        elif choice == "2":
            cat_table = Table(title="Kibuo Supported Device Categories", box=None)
            cat_table.add_column("Category", style="bold cyan", width=20)
            cat_table.add_column("Key Heuristics & Signatures", style="white")

            cat_table.add_row("Smartphone", "Apple/Samsung/Android mobile hostnames, randomized MACs, mobile vendor OUIs")
            cat_table.add_row("Laptop", "Portable PC hostnames (ThinkPad, MacBook), Wi-Fi NICs, sleep-wake cycles")
            cat_table.add_row("Desktop Computer", "Stationary workstations, Ethernet controllers, NetBIOS/SMB names")
            cat_table.add_row("Router", "Default gateway status, DNS port 53, HTTP/HTTPS web management, network vendor OUI")
            cat_table.add_row("Network Printer", "IPP port 631, LPD port 515, JetDirect port 9100, Canon/Epson/HP/Brother OUI")
            cat_table.add_row("Smart TV", "Google Cast 8008, Chromecast 8009, UPnP 5000, Roku/Sony/LG/Samsung smart display")
            cat_table.add_row("IoT Device", "Espressif/Raspberry Pi/Tuya OUI, MQTT port 1883, smart home device names")
            cat_table.add_row("Server", "SSH port 22, Web 80/443/8080, SQL databases, server OS hostnames")
            cat_table.add_row("Unknown Device", "Default when evidence is ambiguous or insufficient to ensure zero false claims")

            console.print()
            console.print(cat_table)
            console.print()
            return
        else:
            return

    # Check for gateway to assist router detection
    from modules.network_discovery import get_local_interfaces
    gateway_ip = None
    try:
        from core.subprocess_manager import SubprocessManager
        res = SubprocessManager.execute(["ip", "route", "show", "default"], timeout=3)
        if res.is_ok() and "via" in res.stdout:
            gateway_ip = res.stdout.split("via")[1].split()[0].strip()
    except Exception:
        pass

    results = []
    with console.status(f"[bold {COLOR_BRAND}]Analyzing device signatures and confidence indicators...[/bold {COLOR_BRAND}]"):
        for dev in devices_to_analyze:
            ip = dev.get("ip", "")
            mac = dev.get("mac", "")
            host = dev.get("hostname", "")
            vendor = dev.get("vendor", "")
            is_gw = (ip == gateway_ip) if gateway_ip else False
            open_p = dev.get("open_ports", [])
            
            # If ports not checked yet, quick probe
            if not open_p and ip:
                open_p = quick_port_probe(ip, timeout=0.3)

            classified = classify_device(
                ip=ip,
                mac=mac,
                hostname=host,
                vendor=vendor,
                is_gateway=is_gw,
                open_ports=open_p
            )
            results.append(classified)

    # Render summary table
    console.print()
    table = Table(title="Device Identification & Confidence Matrix", box=None)
    table.add_column("IP Address", style="bold green", width=16)
    table.add_column("Hostname", style="cyan", width=18)
    table.add_column("Estimated Category", style="bold white", width=18)
    table.add_column("Confidence", style="bold yellow", width=12)
    table.add_column("Primary Supporting Evidence", style="dim white")

    for r in results:
        conf = r["confidence"]
        if conf == "High":
            conf_style = f"bold {COLOR_SUCCESS}"
        elif conf == "Medium":
            conf_style = f"bold {COLOR_WARN}"
        else:
            conf_style = f"dim {COLOR_BRAND_ALT}"

        ev_summary = "; ".join(r["evidence"][:2]) if r["evidence"] else "Generic network host"
        table.add_row(
            r["ip"],
            r["hostname"][:18],
            r["category"],
            f"[{conf_style}]{conf}[/{conf_style}]",
            ev_summary
        )

    console.print(table)
    console.print()
    display_info("Confidence ratings reflect available evidence. Incomplete data defaults to lower confidence.")

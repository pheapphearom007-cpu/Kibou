"""
Unit tests for Fing-Inspired Network Discovery & Monitoring Suite.

Tests MAC OUI vendor resolution, device classification heuristics,
confidence scoring, duplicate IP detection, and report exporter.
"""

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from core.validator import is_private_subnet, validate_mac_address
from modules.device_identification import classify_device, quick_port_probe
from modules.ip_information import get_network_configuration
from modules.mac_lookup import (
    get_vendor_for_mac,
    is_locally_administered_mac,
    is_multicast_mac,
    load_oui_database
)
from modules.report_export import export_network_report, generate_txt_report
from modules.security_check import check_duplicate_ips


class TestFingSuite(unittest.TestCase):
    """Test suite for Network Discovery, Identification, and Telemetry."""

    def test_oui_database_loaded(self):
        """Verify that offline OUI database is loaded and contains key vendors."""
        db = load_oui_database()
        self.assertGreater(len(db), 100)
        # Check standard OUIs
        self.assertEqual(db.get("9CB2E8"), "Samsung Electronics")
        self.assertIn("Apple", db.get("000393", ""))
        self.assertIn("Intel", db.get("0002B3", ""))
        self.assertIn("Raspberry Pi", db.get("B827EB", ""))
        self.assertIn("Espressif", db.get("18FE34", ""))

    def test_mac_lookup_vendor(self):
        """Test MAC lookup resolution and classification."""
        # 1. Known Samsung MAC
        vendor, note = get_vendor_for_mac("9C:B2:E8:A7:9A:31")
        self.assertEqual(vendor, "Samsung Electronics")
        self.assertIn("IEEE OUI Match", note)

        # 2. Locally Administered / Randomized MAC (2nd bit of byte0 is 1: 0x4A has bit 1 set)
        vendor, note = get_vendor_for_mac("4A:13:74:86:7D:81")
        self.assertEqual(vendor, "Randomized / Private MAC")
        self.assertIn("Locally administered", note)

        # 3. Multicast / Broadcast
        vendor, note = get_vendor_for_mac("01:00:5E:00:00:01")
        self.assertIn("Multicast", vendor)

        # 4. Unknown factory MAC
        vendor, note = get_vendor_for_mac("00:99:99:11:22:33")
        self.assertEqual(vendor, "Unknown Manufacturer")

    def test_locally_administered_mac_detection(self):
        """Test bitwise check for IEEE locally administered addresses."""
        self.assertTrue(is_locally_administered_mac("4A:13:74:86:7D:81"))
        self.assertTrue(is_locally_administered_mac("02:00:00:00:00:00"))
        self.assertTrue(is_locally_administered_mac("DA:A1:19:22:33:44"))
        self.assertFalse(is_locally_administered_mac("9C:B2:E8:A7:9A:31"))
        self.assertFalse(is_locally_administered_mac("00:50:56:C0:00:08"))

    def test_device_classification_router(self):
        """Test Router classification for default gateway with DNS port open."""
        res = classify_device(
            ip="192.168.1.1",
            mac="00:1D:0F:11:22:33",
            hostname="_gateway",
            vendor="TP-Link Corporation",
            is_gateway=True,
            open_ports=[53, 80]
        )
        self.assertEqual(res["category"], "Router")
        self.assertEqual(res["confidence"], "High")
        self.assertGreater(res["score"], 50)
        self.assertTrue(any("gateway" in ev.lower() for ev in res["evidence"]))

    def test_device_classification_printer(self):
        """Test Network Printer classification based on IPP port 631 and Canon vendor."""
        res = classify_device(
            ip="192.168.1.50",
            mac="00:00:85:AA:BB:CC",
            hostname="canon-office-print",
            vendor="Canon Inc.",
            is_gateway=False,
            open_ports=[631, 9100]
        )
        self.assertEqual(res["category"], "Network Printer")
        self.assertEqual(res["confidence"], "High")

    def test_device_classification_smart_tv(self):
        """Test Smart TV classification based on Google Cast port 8008 and Roku vendor."""
        res = classify_device(
            ip="192.168.1.75",
            mac="00:0D:4B:11:22:33",
            hostname="living-room-roku",
            vendor="Roku, Inc.",
            is_gateway=False,
            open_ports=[8008, 8009]
        )
        self.assertEqual(res["category"], "Smart TV")
        self.assertEqual(res["confidence"], "High")

    def test_device_classification_iot(self):
        """Test IoT Device classification based on Espressif microcontroller vendor."""
        res = classify_device(
            ip="192.168.1.90",
            mac="24:0A:C4:AA:BB:CC",
            hostname="esp32-sensor",
            vendor="Espressif Inc.",
            is_gateway=False,
            open_ports=[1883]
        )
        self.assertEqual(res["category"], "IoT Device")
        self.assertEqual(res["confidence"], "High")

    def test_device_classification_laptop(self):
        """Test Laptop classification from portable hostname and Dell vendor."""
        res = classify_device(
            ip="192.168.1.105",
            mac="18:03:73:11:22:33",
            hostname="alice-thinkpad-laptop",
            vendor="Dell Inc.",
            is_gateway=False,
            open_ports=[445]
        )
        self.assertEqual(res["category"], "Laptop")
        self.assertIn(res["confidence"], ("High", "Medium"))

    def test_device_classification_unknown_low_confidence(self):
        """Test that device with zero identifiable evidence is classified as Unknown Device with Low confidence."""
        res = classify_device(
            ip="192.168.1.200",
            mac="",
            hostname="",
            vendor="",
            is_gateway=False,
            open_ports=[]
        )
        self.assertEqual(res["category"], "Unknown Device")
        self.assertEqual(res["confidence"], "Low")

    def test_duplicate_ip_detection(self):
        """Test security audit for duplicate IP address collisions."""
        devices = [
            {"ip": "192.168.1.10", "mac": "00:11:22:33:44:55"},
            {"ip": "192.168.1.10", "mac": "AA:BB:CC:DD:EE:FF"},  # Collision!
            {"ip": "192.168.1.20", "mac": "11:22:33:44:55:66"},
        ]
        dups = check_duplicate_ips(devices)
        self.assertEqual(len(dups), 1)
        self.assertEqual(dups[0]["ip"], "192.168.1.10")
        self.assertEqual(len(dups[0]["macs"]), 2)

    def test_network_config_retrieval(self):
        """Verify network configuration retrieval returns structured attributes."""
        cfg = get_network_configuration()
        self.assertIn("interface", cfg)
        self.assertIn("ipv4", cfg)
        self.assertIn("subnet_cidr", cfg)
        self.assertIn("gateway", cfg)
        self.assertIn("dns_servers", cfg)
        self.assertIn("is_dhcp", cfg)
        self.assertIsInstance(cfg["dns_servers"], list)

    def test_private_subnet_check(self):
        """Test RFC 1918 private subnet validation."""
        self.assertTrue(is_private_subnet("192.168.1.0/24"))
        self.assertTrue(is_private_subnet("10.0.0.0/8"))
        self.assertTrue(is_private_subnet("172.16.0.0/16"))
        self.assertTrue(is_private_subnet("127.0.0.0/8"))
        # Public IP subnets must return False
        self.assertFalse(is_private_subnet("8.8.8.0/24"))
        self.assertFalse(is_private_subnet("1.1.1.0/24"))

    def test_export_network_report_generation(self):
        """Test TXT, JSON, and CSV export functionality."""
        sample_devices = [
            {
                "ip": "192.168.100.1",
                "mac": "9C:B2:E8:A7:9A:31",
                "hostname": "_gateway",
                "vendor": "Samsung Electronics",
                "status": "Online",
                "category": "Router",
                "confidence": "High",
                "evidence": ["Host configured as default gateway"]
            },
            {
                "ip": "192.168.100.136",
                "mac": "A8:64:F1:A5:89:0D",
                "hostname": "local-laptop",
                "vendor": "Intel Corporate",
                "status": "Online (This Machine)",
                "category": "Laptop",
                "confidence": "Medium",
                "evidence": ["Hostname suggests laptop"]
            }
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("modules.report_export.REPORTS_DIR", Path(tmpdir)):
                exported = export_network_report(sample_devices, "192.168.100.0/24", "wlp0s20f3")

                self.assertIn("TXT", exported)
                self.assertIn("JSON", exported)
                self.assertIn("CSV", exported)

                # Verify TXT file
                txt_path = Path(exported["TXT"])
                self.assertTrue(txt_path.exists())
                txt_data = txt_path.read_text(encoding="utf-8")
                self.assertIn("192.168.100.1", txt_data)
                self.assertIn("Samsung Electronics", txt_data)
                self.assertIn("Router (High)", txt_data)

                # Verify JSON file
                json_path = Path(exported["JSON"])
                self.assertTrue(json_path.exists())
                with open(json_path, "r", encoding="utf-8") as f:
                    json_data = json.load(f)
                self.assertEqual(json_data["metadata"]["device_count"], 2)
                self.assertEqual(len(json_data["devices"]), 2)

                # Verify CSV file
                csv_path = Path(exported["CSV"])
                self.assertTrue(csv_path.exists())
                with open(csv_path, "r", encoding="utf-8") as f:
                    reader = list(csv.DictReader(f))
                self.assertEqual(len(reader), 2)
                self.assertEqual(reader[0]["ip"], "192.168.100.1")
                self.assertEqual(reader[0]["category"], "Router")


if __name__ == "__main__":
    unittest.main()

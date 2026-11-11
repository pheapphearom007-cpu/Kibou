"""
Unit tests for Nmap XML output parsing in modules/nmap_scanner.py
"""

import unittest
from modules.nmap_scanner import parse_nmap_xml

SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -p 22,80 -oX - 192.168.1.50" version="7.94">
<host starttime="1700000000" endtime="1700000010">
<status state="up" reason="arp-response"/>
<address addr="192.168.1.50" addrtype="ipv4"/>
<address addr="00:11:22:33:44:55" addrtype="mac" vendor="Testing Hardware Inc."/>
<hostnames>
<hostname name="server.local" type="user"/>
</hostnames>
<ports>
<port protocol="tcp" portid="22">
<state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu Linux" method="probed">
<cpe>cpe:/a:openbsd:openssh:8.9p1</cpe>
</service>
</port>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.18.0" extrainfo="" method="probed">
<cpe>cpe:/a:igor_sysoev:nginx:1.18.0</cpe>
</service>
<script id="http-title" output="Welcome to nginx!"/>
</port>
<port protocol="tcp" portid="443">
<state state="closed" reason="reset"/>
</port>
</ports>
<os>
<osmatch name="Linux 5.4 - 5.15" accuracy="96">
<osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="5.X">
<cpe>cpe:/o:linux:linux_kernel:5</cpe>
</osclass>
</osmatch>
</os>
<trace>
<hop ttl="1" ipaddr="192.168.1.1" rtt="0.45" host="gateway.local"/>
<hop ttl="2" ipaddr="192.168.1.50" rtt="1.20" host="server.local"/>
</trace>
</host>
</nmaprun>
"""


class TestXmlParser(unittest.TestCase):
    """Test suite for Nmap XML parsing reliability."""

    def test_parse_valid_xml(self):
        """Test parsing comprehensive Nmap XML with ports, services, OS and trace."""
        result = parse_nmap_xml(SAMPLE_NMAP_XML)
        self.assertEqual(result.status, "up")
        self.assertEqual(result.ipv4_address, "192.168.1.50")
        self.assertEqual(result.mac_address, "00:11:22:33:44:55")
        self.assertIn("server.local", result.hostnames)

        # Verify Ports
        self.assertEqual(len(result.ports), 3)
        open_ports = [p for p in result.ports if p.state == "open"]
        self.assertEqual(len(open_ports), 2)

        # Port 22 SSH
        p22 = next(p for p in result.ports if p.port_id == 22)
        self.assertEqual(p22.service_name, "ssh")
        self.assertEqual(p22.product, "OpenSSH")
        self.assertEqual(p22.version, "8.9p1")
        self.assertIn("cpe:/a:openbsd:openssh:8.9p1", p22.cpe)
        self.assertIn("OpenSSH 8.9p1", p22.full_service_version)

        # Port 80 HTTP & script output
        p80 = next(p for p in result.ports if p.port_id == 80)
        self.assertEqual(p80.product, "nginx")
        self.assertIn("http-title", p80.scripts)
        self.assertEqual(p80.scripts["http-title"], "Welcome to nginx!")

        # OS matches
        self.assertEqual(len(result.os_matches), 1)
        self.assertEqual(result.os_matches[0]["name"], "Linux 5.4 - 5.15")
        self.assertEqual(result.os_matches[0]["accuracy"], "96%")

        # Traceroute hops
        self.assertEqual(len(result.traceroute_hops), 2)
        self.assertEqual(result.traceroute_hops[0]["ip"], "192.168.1.1")
        self.assertEqual(result.traceroute_hops[1]["ip"], "192.168.1.50")

    def test_parse_empty_xml(self):
        """Test parsing empty or whitespace XML."""
        result = parse_nmap_xml("")
        self.assertEqual(result.status, "down")
        self.assertEqual(len(result.ports), 0)

    def test_parse_malformed_xml(self):
        """Test parsing corrupt XML string without raising unhandled exceptions."""
        result = parse_nmap_xml("<nmaprun><host><truncated>")
        self.assertEqual(result.status, "down")
        self.assertEqual(len(result.ports), 0)


if __name__ == "__main__":
    unittest.main()

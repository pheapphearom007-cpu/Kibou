# KIBUO — Professional Cybersecurity Reconnaissance Toolkit

```text
  ██╗  ██╗██╗██████╗ ██╗   ██╗ ██████╗ 
  ██║ ██╔╝██║██╔══██╗██║   ██║██╔═══██╗
  █████═╝ ██║██████╔╝██║   ██║██║   ██║
  ██╔═██╗ ██║██╔══██╗██║   ██║██║   ██║
  ██║ ╚██╗██║██████╔╝╚██████╔╝╚██████╔╝
  ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝  ╚═════╝ 
     NETWORK RECONNAISSANCE TOOLKIT
              Version 1.0.0
```

[![Platform](https://img.shields.io/badge/Platform-Kali%20%7C%20Debian%20%7C%20Ubuntu-orange.svg)]()
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)]()
[![UI](https://img.shields.io/badge/UI-Rich%20Terminal-yellow.svg)]()
[![License](https://img.shields.io/badge/License-MIT%20with%20Ethical%20Clause-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-33%20Passing-brightgreen.svg)]()

**Kibuo** is an advanced, modular cybersecurity reconnaissance and auditing toolkit built for authorized penetration testing, security auditing, asset discovery, and educational cybersecurity laboratories.

Engineered with strict defensive coding standards, Kibuo combines real-time Linux security tool integration, robust argument-array execution (`shell=False`), end-to-end input validation, rich terminal presentations, and structured multi-format reporting.

---

## Table of Contents

- [Architectural Overview](#architectural-overview)
- [Core Modules & Capabilities](#core-modules--capabilities)
- [Security & Defensive Engineering](#security--defensive-engineering)
- [Privilege & Permission Management](#privilege--permission-management)
- [Dependency Management](#dependency-management)
- [Structured Logging & Reporting](#structured-logging--reporting)
- [Installation & Quick Start](#installation--quick-start)
- [Running Unit Tests](#running-unit-tests)
- [Ethical Compliance & Legal Notice](#ethical-compliance--legal-notice)

---

## Architectural Overview

Kibuo adopts a decoupled, modular architecture cleanly separating terminal UI presentation, security sanitization, subprocess management, scanning logic, and report generation:

```text
kibuo/
├── main.py                     # Interactive CLI entrypoint & menu dispatcher
├── requirements.txt            # Python dependencies (Rich, Requests)
├── install.sh                  # Automated environment setup script
├── run.sh                      # Environment launcher
├── README.md                   # System documentation
├── LICENSE                     # MIT License + Ethical Use Clause
├── config/
│   └── settings.json           # Application settings & color palette
├── core/
│   ├── __init__.py
│   ├── ui.py                   # Rich terminal branding, menus, cards & spinners
│   ├── validator.py            # Strict IP, CIDR, domain, and injection sanitization
│   ├── subprocess_manager.py   # Safe command execution (shell=False, timeouts)
│   ├── permission_manager.py   # Root detection & least-privilege guidance
│   ├── dependency_manager.py   # Distribution detection & apt package installer
│   ├── logger.py               # Sanitized logging with secret masking
│   └── report_generator.py     # Session manager, JSON & TXT report exporter
├── modules/
│   ├── __init__.py
│   ├── network_discovery.py    # Modules [01] & [02]: ARP & Live Host discovery
│   ├── nmap_scanner.py         # Modules [03]-[07]: Port scans, OS & Vuln assessment
│   ├── ip_intelligence.py      # Module [08]: Public IP & ASN intelligence
│   ├── dns_whois.py            # Module [09]: DNS records & WHOIS registration
│   ├── traceroute.py           # Module [10]: Route hop latency & path analysis
│   ├── web_recon.py            # Module [11]: HTTP/HTTPS inspection & headers audit
│   ├── exploit_lookup.py       # Module [12]: SearchSploit advisory cross-referencing
│   ├── smb_recon.py            # Module [13]: SMB dialect & security audit
│   └── recon_pipeline.py       # Module [14]: Automated end-to-end recon pipeline
├── logs/                       # Timestamped raw tool outputs and metadata
├── reports/                    # Consolidated JSON and TXT executive reports
└── tests/                      # Comprehensive unit test suite (26 passing tests)
    ├── __init__.py
    ├── test_validator.py
    ├── test_subprocess_manager.py
    ├── test_xml_parser.py
    ├── test_report_generator.py
    ├── test_dependencies.py
    └── test_logger.py
```

---

## Core Modules & Capabilities

Kibuo implements **14 functional reconnaissance modules** accessible from an interactive, responsive two-column terminal dashboard:

```text
╔══════════════════════════════════════════════════════════════════╗
║     ██╗  ██╗██╗██████╗ ██╗   ██╗ ██████╗                         ║
║     ██║ ██╔╝██║██╔══██╗██║   ██║██╔═══██╗                        ║
║     █████═╝ ██║██████╔╝██║   ██║██║   ██║                        ║
║     ██╔═██╗ ██║██╔══██╗██║   ██║██║   ██║                        ║
║     ██║ ╚██╗██║██████╔╝╚██████╔╝╚██████╔╝                        ║
║     ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝  ╚═════╝                         ║
║              NETWORK RECONNAISSANCE TOOLKIT                      ║
║                       Version 1.0.0                              ║
╚══════════════════════════════════════════════════════════════════╝

[01] ARP Network Discovery       [08] IP Intelligence
[02] Live Host Discovery        [09] Whois & DNS
[03] Quick Port Scan            [10] Traceroute
[04] Full Port Scan             [11] Web Recon
[05] OS Detection               [12] Exploit Lookup
[06] SYN Scan                   [13] SMB Discovery
[07] Vulnerability Assessment   [14] Full Recon Pipeline

[99] About                     [00] Exit
```

### Module Breakdown

| Identifier | Module Name | Primary Utilities | Description |
|---|---|---|---|
| **[01]** | **ARP Network Discovery** | `arp-scan`, `nmap -PR` | Discovers active devices on local subnets; detects interfaces and parses IP, MAC address, and vendor hardware details. |
| **[02]** | **Live Host Discovery** | `nmap -sn`, `ping` | Ping sweep host discovery for IPv4 single targets or CIDR ranges without port scanning. |
| **[03]** | **Quick Port Scan** | `nmap -F -sV` | High-speed scan of the top 100 commonly utilized TCP ports with service version detection. |
| **[04]** | **Full TCP Port Scan** | `nmap -p- -sV` | Exhaustive scan covering all 65,535 TCP ports with timing controls (`-T3`/`-T4`) and pre-scan duration warnings. |
| **[05]** | **OS & Service Detection** | `nmap -O -sV --traceroute` | TCP/IP stack operating system fingerprinting, service identification, and traceroute hops. |
| **[06]** | **SYN Stealth Scan** | `nmap -sS -sV` | Half-open raw TCP SYN scanning; validates raw socket capabilities and explains connection mechanics. |
| **[07]** | **Vulnerability Assessment**| `nmap --script vuln` | NSE vulnerability engine auditing; includes a **Safe Assessment Mode** toggle and verifies findings vs. banners. |
| **[08]** | **IP Intelligence** | `ip-api.com`, `requests` | Public IPv4 OSINT: Country, region, city, ISP, ASN, organization, and coordinates with private IP filtering. |
| **[09]** | **Whois & DNS** | `dig`, `whois`, `socket` | Queries A, AAAA, MX, TXT, NS, CNAME, SOA records, reverse DNS (PTR), and registrar ownership data. |
| **[10]** | **Traceroute & Path Analysis**| `traceroute`, `mtr` | Network transit path analysis, hop latency (RTT), and graceful handling of blocked ICMP nodes (`* * *`). |
| **[11]** | **Web Application Recon** | `requests`, `whatweb`, `curl` | Probes HTTP/HTTPS endpoints, extracts titles and server banners, audits essential security headers, and offers optional Nikto checks. |
| **[12]** | **Public Exploit Intelligence**| `searchsploit` | Queries the Exploit-DB archive for service version references. **Strictly informational; does not execute exploits.** |
| **[13]** | **SMB Discovery & Audit** | `nmap`, `enum4linux` | Audits ports 139/445, checks SMBv1/v2/v3 support, evaluates message signing enforcement, and tests guest access. |
| **[14]** | **Full Recon Pipeline** | Consolidated Workflow | Automated, sequential execution of target validation, IP intelligence, DNS, host discovery, service scan, web recon, SMB audit, and exploit lookup. |

---

## Security & Defensive Engineering

Kibuo implements strict defense-in-depth principles:

1. **Subprocess Safety**:
   - Zero use of `shell=True`. All commands are constructed strictly as argument arrays (`List[str]`).
   - Timeouts enforced on every subprocess to prevent process hangs.
   - Separation of `stdout` and `stderr` streams.
   - Handles `FileNotFoundError` when a tool is missing and `PermissionError` when root is required.
2. **Input Validation & Sanitization**:
   - IPv4 and CIDR subnets are parsed and verified using Python's `ipaddress` library.
   - Domain names are validated against RFC 1123 regex standards.
   - Shell metacharacters (`;`, `&`, `|`, `$`, `` ` ``, `<`, `>`, `\`, `\n`, `!`) are rejected.
   - Target strings beginning with `-` are blocked to prevent command-line option injection (e.g. `-oX`).
3. **Secret Masking**:
   - Standard logging streams automatically mask API tokens, passwords, and bearer authorization credentials before writing to disk.

---

## Privilege & Permission Management

Kibuo respects the principle of least privilege:
- **Standard User Execution**: Most modules (Port Scanning, DNS, Whois, IP Intelligence, Web Recon, Exploit Lookup, Traceroute) execute without elevated privileges.
- **Root Operations Detected**: Modules requiring raw socket access (Link-layer ARP scans, TCP SYN scans `-sS`, and OS stack fingerprinting `-O`) are proactively evaluated by `core/permission_manager.py`.
- **Informative Guidance**: When privileges are insufficient, Kibuo explains why elevated access is needed and recommends safe unprivileged alternatives (e.g., standard TCP connect scanning `-sT` instead of `-sS`).

---

## Dependency Management

Kibuo detects the underlying distribution (Kali Linux, Debian, Ubuntu) and checks for installed security tools:

| Tool | Debian / Ubuntu Package | Kali Linux Package | Purpose |
|---|---|---|---|
| `nmap` | `nmap` | `nmap` | Port scanning, OS detection, NSE scripting |
| `curl` | `curl` | `curl` | Web endpoint verification |
| `whois` | `whois` | `whois` | Domain registrar lookup |
| `dig` | `dnsutils` / `bind9-dnsutils` | `dnsutils` | DNS resource record querying |
| `traceroute` | `traceroute` | `traceroute` | Routing path inspection |
| `arp-scan` | `arp-scan` | `arp-scan` | Link-layer ARP discovery |
| `whatweb` | `whatweb` | `whatweb` | Web technology fingerprinting |
| `searchsploit` | `exploitdb` | `exploitdb` | Public exploit intelligence |
| `nikto` | `nikto` | `nikto` | Web server vulnerability scanning |
| `enum4linux` | `enum4linux` | `enum4linux` | SMB user and share enumeration |
| `jq` | `jq` | `jq` | JSON processing |

Kibuo includes an interactive installer (`[15]` or `deps` in the CLI) that presents the status of all tools and can safely invoke `apt-get install` after explicit user confirmation.

---

## Structured Logging & Reporting

Every scan session creates structured artifacts in `logs/` and exports consolidated reports into `reports/`:

```text
logs/
└── 192.168.1.10_20261111_023000/
    ├── metadata.json           # Session configuration, timings, and status
    ├── nmap_scan.txt           # Raw Nmap stdout
    ├── nmap_scan.xml           # Structured machine-readable XML
    ├── ip_intelligence.json    # Geolocation and ASN response data
    ├── dns_whois.json          # Parsed DNS resource records and WHOIS
    ├── web_recon.json          # HTTP headers, status, and title data
    ├── exploit_lookup.json     # Matched Exploit-DB advisory titles
    ├── summary.json            # Consolidated JSON findings
    ├── summary.txt             # Human-readable executive briefing
    └── summary.html            # Dark-mode cybersecurity HTML report

reports/
├── 192.168.1.10_20261111_023000_report.txt   # Consolidated plain text report
├── 192.168.1.10_20261111_023000_report.json  # Consolidated structured JSON report
└── 192.168.1.10_20261111_023000_report.html  # Standalone responsive HTML dashboard
```

### Scan Summary Card

Upon scan completion, Kibuo renders a terminal summary card:

```text
╭──────────── KIBUO SCAN SUMMARY ────────────╮
│ Target: 192.168.1.10                       │
│ Status: Completed                          │
│ Open Ports: 3                              │
│ Services: SSH, HTTP, HTTPS                 │
│ Duration: 00:01:24                         │
│ Text Report: reports/..._report.txt        │
│ JSON Report: reports/..._report.json       │
│ HTML Report: reports/..._report.html       │
╰────────────────────────────────────────────╯
```

---

## Intelligent Workflow Automation

Kibuo features an intelligent reconnaissance bridge connecting scanning phases:
- **Discovery to Port Scan**: When live hosts are discovered via ARP or ICMP sweeps, users can directly select any active host to launch an immediate port scan.
- **Port Scan to Web Recon**: When web ports (80, 443, 8080, 8443, etc.) are detected open, Kibuo prompts to automatically transition into deep HTTP inspection and security header auditing.
- **Port Scan to Exploit-DB Intelligence**: When service products and versions (e.g., Apache 2.4, OpenSSH 8.9) are detected, Kibuo allows one-key lookup of public Exploit-DB references via `searchsploit`.
- **Port Scan to SMB Security Audit**: When SMB ports (139, 445) are open, Kibuo prompts to audit SMB dialect negotiation and signing enforcement.

---

## Installation & Quick Start

### 1. Clone & Enter Directory
```bash
git clone <repository-url>
cd "Kibuo Tool"
```

### 2. Run Automated Setup
```bash
chmod +x install.sh run.sh
./install.sh
```

### 3. Launch Kibuo
```bash
./run.sh
# Or launch directly with Python 3:
python3 main.py
```

### Running with Privileges (Optional)
To enable raw socket SYN scans and link-layer ARP discovery:
```bash
sudo ./run.sh
```

---

## Running Unit Tests

The test suite covers input validation, metacharacter sanitization, subprocess execution, Nmap XML parsing, report generation, dependency checking, and secret masking:

```bash
python3 -m unittest discover tests -v
```

All 33 unit tests execute cleanly using the Python standard library.

---

## Ethical Compliance & Legal Notice

> [!WARNING]
> **MANDATORY LEGAL POLICY:**
> Kibuo is designed strictly for authorized penetration testing, internal security auditing, and safe academic cybersecurity education.
> 
> Scanning, assessing, or querying networks and computer systems without prior, explicit, written authorization from the system owner is illegal under computer misuse legislation (including the US Computer Fraud and Abuse Act, UK Computer Misuse Act, and international legal equivalents).
> 
> The developers and contributors of Kibuo assume zero liability for unauthorized, malicious, or damaging actions performed with this toolkit.

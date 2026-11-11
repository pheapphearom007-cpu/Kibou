"""
Structured Report and Log Generation for Kibuo.

Manages assessment sessions, writes sanitized artifact directories under logs/,
and generates consolidated JSON and plain text executive reports under reports/.
"""

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


def sanitize_filename(name: str) -> str:
    """Sanitize strings for safe filesystem directory and file names."""
    # Replace slashes, backslashes, colons, spaces, and strange characters with underscores
    sanitized = re.sub(r"[^\w\.\-]", "_", name.strip())
    # Prevent leading dots or dashes
    sanitized = re.sub(r"^[.\-_]+", "", sanitized)
    return sanitized or "assessment"


class AssessmentSession:
    """Tracks and records findings for a specific target assessment session."""

    def __init__(
        self,
        target: str,
        module_name: str,
        logs_base_dir: str = "logs",
        reports_base_dir: str = "reports",
        app_version: str = "1.0.0"
    ):
        self.target = target
        self.module_name = module_name
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.iso_timestamp = datetime.now().isoformat()
        self.app_version = app_version
        
        # Directory names
        safe_target = sanitize_filename(target)
        self.session_id = f"{safe_target}_{self.timestamp}"
        self.session_dir = Path(logs_base_dir) / self.session_id
        self.reports_dir = Path(reports_base_dir)
        
        # Ensure directories exist
        self.session_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        self.metadata: Dict[str, Any] = {
            "session_id": self.session_id,
            "target": target,
            "module": module_name,
            "start_time": self.iso_timestamp,
            "app_version": app_version,
            "status": "In Progress",
            "findings_summary": {},
            "raw_files": []
        }
        self.save_metadata()

    def save_metadata(self) -> None:
        """Persist metadata.json to session directory."""
        meta_file = self.session_dir / "metadata.json"
        with open(meta_file, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

    def write_artifact(self, filename: str, content: str) -> Path:
        """Write raw tool output (e.g., nmap_scan.txt, web_recon.txt)."""
        safe_name = sanitize_filename(filename)
        # Ensure standard extension is preserved
        if "." in filename:
            ext = filename.rsplit(".", 1)[1]
            if not safe_name.endswith(f".{ext}"):
                safe_name = f"{safe_name}.{ext}"
                
        file_path = self.session_dir / safe_name
        with open(file_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(content)
            
        if safe_name not in self.metadata["raw_files"]:
            self.metadata["raw_files"].append(safe_name)
        self.save_metadata()
        return file_path

    def write_json_artifact(self, filename: str, data: Any) -> Path:
        """Write structured JSON artifact (e.g., ip_intelligence.json)."""
        safe_name = sanitize_filename(filename)
        if not safe_name.endswith(".json"):
            safe_name = f"{safe_name}.json"
            
        file_path = self.session_dir / safe_name
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            
        if safe_name not in self.metadata["raw_files"]:
            self.metadata["raw_files"].append(safe_name)
        self.save_metadata()
        return file_path

    def finalize(
        self,
        status: str = "Completed",
        summary_data: Optional[Dict[str, Any]] = None,
        duration_seconds: float = 0.0
    ) -> Dict[str, str]:
        """
        Finalize assessment session and generate summary.json and summary.txt,
        as well as consolidated report in reports/.
        
        Returns:
            Dictionary containing paths to generated report files.
        """
        self.metadata["status"] = status
        self.metadata["end_time"] = datetime.now().isoformat()
        self.metadata["duration_seconds"] = round(duration_seconds, 2)
        if summary_data:
            self.metadata["findings_summary"] = summary_data
        self.save_metadata()

        # 1. Write summary.json in logs/<session_id>/
        summary_file = self.session_dir / "summary.json"
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

        # 2. Write summary.txt in logs/<session_id>/
        txt_content = self._generate_text_summary()
        summary_txt_file = self.session_dir / "summary.txt"
        with open(summary_txt_file, "w", encoding="utf-8") as f:
            f.write(txt_content)

        # 3. Export to reports/
        report_json = self.reports_dir / f"{self.session_id}_report.json"
        with open(report_json, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

        report_txt = self.reports_dir / f"{self.session_id}_report.txt"
        with open(report_txt, "w", encoding="utf-8") as f:
            f.write(txt_content)

        # 4. Generate and export HTML report
        html_content = self._generate_html_report()
        summary_html_file = self.session_dir / "summary.html"
        with open(summary_html_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        report_html = self.reports_dir / f"{self.session_id}_report.html"
        with open(report_html, "w", encoding="utf-8") as f:
            f.write(html_content)

        return {
            "session_dir": str(self.session_dir),
            "summary_json": str(summary_file),
            "summary_txt": str(summary_txt_file),
            "summary_html": str(summary_html_file),
            "report_json": str(report_json),
            "report_txt": str(report_txt),
            "report_html": str(report_html)
        }

    def _generate_html_report(self) -> str:
        """Create a self-contained, responsive cybersecurity HTML report."""
        findings = self.metadata.get("findings_summary", {})
        status = self.metadata.get("status", "Completed")
        duration = self.metadata.get("duration_seconds", 0.0)
        start_time = self.metadata.get("start_time", "N/A")
        end_time = self.metadata.get("end_time", "N/A")
        
        # Determine ports count
        open_ports_count = findings.get("open_ports_count", 0)
        if not open_ports_count and "ports" in findings and isinstance(findings["ports"], list):
            open_ports_count = len([p for p in findings["ports"] if isinstance(p, dict) and p.get("state", "open") == "open"])
        elif not open_ports_count and "open_ports" in findings and isinstance(findings["open_ports"], list):
            open_ports_count = len(findings["open_ports"])

        # Build port rows
        port_rows = []
        ports_data = findings.get("ports") or findings.get("open_ports")
        if ports_data and isinstance(ports_data, list):
            for p in ports_data:
                if isinstance(p, dict):
                    p_num = p.get("port") or p.get("port_id", "N/A")
                    proto = p.get("proto") or p.get("protocol", "tcp")
                    svc = p.get("service") or p.get("service_name", "unknown")
                    ver = p.get("version") or p.get("full_service_version", "-")
                    port_rows.append(f"""
                        <tr>
                            <td><span class="badge badge-port">{p_num}/{proto}</span></td>
                            <td><span class="badge badge-success">OPEN</span></td>
                            <td><strong>{svc}</strong></td>
                            <td class="text-dim">{ver}</td>
                        </tr>
                    """)

        # Build hosts rows (for ARP/Host discovery)
        host_rows = []
        hosts_data = findings.get("hosts")
        if hosts_data and isinstance(hosts_data, list):
            for h in hosts_data:
                if isinstance(h, dict):
                    host_rows.append(f"""
                        <tr>
                            <td><strong>{h.get('ip', 'N/A')}</strong></td>
                            <td><code>{h.get('mac', 'N/A')}</code></td>
                            <td>{h.get('vendor', 'Unknown')}</td>
                            <td><span class="badge badge-success">{h.get('status', 'Active')}</span></td>
                        </tr>
                    """)

        # Build IP intelligence table
        intel_html = ""
        ip_intel = findings.get("ip_intelligence") or (findings if self.module_name == "IP Intelligence" else None)
        if ip_intel and isinstance(ip_intel, dict) and ip_intel.get("status") == "success":
            intel_html = f"""
            <div class="card">
                <h3>🌐 IP Intelligence & Geolocation</h3>
                <div class="grid-2">
                    <div>
                        <p><strong>Query IP:</strong> <code>{ip_intel.get('query', 'N/A')}</code></p>
                        <p><strong>Country:</strong> {ip_intel.get('country', 'N/A')} ({ip_intel.get('countryCode', '')})</p>
                        <p><strong>Region / City:</strong> {ip_intel.get('regionName', 'N/A')} / {ip_intel.get('city', 'N/A')}</p>
                        <p><strong>Timezone:</strong> {ip_intel.get('timezone', 'N/A')}</p>
                    </div>
                    <div>
                        <p><strong>Autonomous System:</strong> {ip_intel.get('as', 'N/A')}</p>
                        <p><strong>ISP Provider:</strong> {ip_intel.get('isp', 'N/A')}</p>
                        <p><strong>Organization:</strong> {ip_intel.get('org', 'N/A')}</p>
                        <p><strong>Coordinates:</strong> {ip_intel.get('lat', 'N/A')}, {ip_intel.get('lon', 'N/A')}</p>
                    </div>
                </div>
            </div>
            """

        # Build artifacts list
        raw_files = self.metadata.get("raw_files", [])
        artifact_items = "".join(f"<li>📄 <code>{f}</code></li>" for f in raw_files)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kibuo Recon Report - {self.target}</title>
    <style>
        :root {{
            --bg-body: #0b0f19;
            --bg-card: #151d2e;
            --bg-hover: #1e293b;
            --border-color: #243247;
            --primary: #f59e0b;
            --primary-light: #fbbf24;
            --cyan: #06b6d4;
            --green: #10b981;
            --red: #ef4444;
            --text-main: #f8fafc;
            --text-dim: #94a3b8;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background-color: var(--bg-body);
            color: var(--text-main);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            padding: 30px 20px;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        header {{
            background: linear-gradient(135deg, #1e293b, #0f172a);
            border: 1px solid var(--border-color);
            border-top: 4px solid var(--primary);
            padding: 24px 30px;
            border-radius: 8px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}
        .brand h1 {{ color: var(--primary-light); font-size: 26px; letter-spacing: 2px; font-weight: 800; }}
        .brand p {{ color: var(--text-dim); font-size: 13px; text-transform: uppercase; letter-spacing: 1px; }}
        .meta-badges {{ display: flex; gap: 10px; flex-wrap: wrap; }}
        .badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .badge-success {{ background: rgba(16, 185, 129, 0.2); color: var(--green); border: 1px solid var(--green); }}
        .badge-port {{ background: rgba(6, 182, 212, 0.2); color: var(--cyan); border: 1px solid var(--cyan); }}
        .badge-primary {{ background: rgba(245, 158, 11, 0.2); color: var(--primary-light); border: 1px solid var(--primary); }}
        
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            padding: 18px 20px;
            border-radius: 8px;
        }}
        .kpi-card span {{ color: var(--text-dim); font-size: 13px; font-weight: 500; text-transform: uppercase; }}
        .kpi-card h2 {{ color: var(--text-main); font-size: 24px; margin-top: 6px; font-weight: 700; }}
        
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
        }}
        .card h3 {{
            color: var(--primary-light);
            font-size: 18px;
            margin-bottom: 16px;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        @media(max-width: 768px) {{ .grid-2 {{ grid-template-columns: 1fr; }} }}
        
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }}
        th, td {{ padding: 12px 14px; text-align: left; border-bottom: 1px solid var(--border-color); }}
        th {{ background: #121927; color: var(--text-dim); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
        tr:hover td {{ background: var(--bg-hover); }}
        code {{ background: #0c121e; padding: 2px 6px; border-radius: 4px; color: var(--cyan); font-family: monospace; font-size: 13px; }}
        .text-dim {{ color: var(--text-dim); }}
        
        ul.artifacts-list {{ list-style: none; display: flex; flex-direction: column; gap: 8px; }}
        ul.artifacts-list li {{ background: #0c121e; padding: 8px 12px; border-radius: 4px; border: 1px solid var(--border-color); font-size: 13px; }}
        
        footer {{
            text-align: center;
            color: var(--text-dim);
            font-size: 12px;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>K I B U O</h1>
                <p>Cybersecurity Reconnaissance Report</p>
            </div>
            <div class="meta-badges">
                <span class="badge badge-primary">v{self.app_version}</span>
                <span class="badge badge-success">{status}</span>
                <span class="badge badge-port">{self.module_name}</span>
            </div>
        </header>

        <div class="kpi-grid">
            <div class="kpi-card">
                <span>Assessment Target</span>
                <h2><code>{self.target}</code></h2>
            </div>
            <div class="kpi-card">
                <span>Scan Duration</span>
                <h2>{duration}s</h2>
            </div>
            <div class="kpi-card">
                <span>Identified Open Ports</span>
                <h2 style="color: var(--primary);">{open_ports_count}</h2>
            </div>
            <div class="kpi-card">
                <span>Session ID</span>
                <h2 style="font-size: 16px; margin-top: 10px;"><code>{self.session_id}</code></h2>
            </div>
        </div>

        {intel_html}

        {"<div class='card'><h3>🔌 Discovered Ports & Services</h3><table><thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version & Banner</th></tr></thead><tbody>" + "".join(port_rows) + "</tbody></table></div>" if port_rows else ""}

        {"<div class='card'><h3>💻 Discovered Active Hosts</h3><table><thead><tr><th>IP Address</th><th>MAC Address</th><th>Vendor</th><th>Status</th></tr></thead><tbody>" + "".join(host_rows) + "</tbody></table></div>" if host_rows else ""}

        <div class="card">
            <h3>📁 Generated Session Artifacts</h3>
            <ul class="artifacts-list">
                {artifact_items if artifact_items else "<li>No secondary raw artifacts recorded.</li>"}
            </ul>
        </div>

        <footer>
            <p><strong>CONFIDENTIAL & PROPRIETARY RECONNAISSANCE DATA</strong></p>
            <p>Generated by Kibuo v{self.app_version} on {start_time} (Completed: {end_time}).</p>
            <p>Authorized security assessment and system administration only.</p>
        </footer>
    </div>
</body>
</html>
"""
        return html


    def _generate_text_summary(self) -> str:
        """Create clean plain text summary report."""
        lines = [
            "=" * 64,
            "                   KIBUO RECONNAISSANCE REPORT",
            "=" * 64,
            f"Session ID     : {self.session_id}",
            f"Target         : {self.target}",
            f"Module         : {self.module_name}",
            f"Status         : {self.metadata.get('status', 'Completed')}",
            f"Start Time     : {self.metadata.get('start_time')}",
            f"End Time       : {self.metadata.get('end_time', 'N/A')}",
            f"Duration       : {self.metadata.get('duration_seconds', 0.0)} seconds",
            f"Tool Version   : Kibuo v{self.app_version}",
            "-" * 64,
            "FINDINGS SUMMARY:",
        ]
        
        findings = self.metadata.get("findings_summary", {})
        if not findings:
            lines.append("  No structured findings recorded.")
        else:
            for key, val in findings.items():
                if isinstance(val, (list, dict)):
                    lines.append(f"  * {key.replace('_', ' ').capitalize()}:")
                    if isinstance(val, list):
                        for item in val[:20]:  # limit 20 items in txt
                            lines.append(f"      - {item}")
                        if len(val) > 20:
                            lines.append(f"      ... and {len(val) - 20} more items.")
                    elif isinstance(val, dict):
                        for sub_k, sub_v in val.items():
                            lines.append(f"      - {sub_k}: {sub_v}")
                else:
                    lines.append(f"  * {key.replace('_', ' ').capitalize()}: {val}")

        lines.extend([
            "-" * 64,
            "GENERATED ARTIFACTS:",
        ])
        for f in self.metadata.get("raw_files", []):
            lines.append(f"  - {f}")

        lines.extend([
            "=" * 64,
            "DISCLAIMER: This reconnaissance report was produced for authorized",
            "security auditing and network administration purposes only.",
            "=" * 64,
        ])
        return "\n".join(lines) + "\n"

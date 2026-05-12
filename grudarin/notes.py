"""
Grudarin - Notes Writer
Generates structured reports in Markdown (.md) and JSON formats.
Security findings are highlighted with bold red headers and large fonts.
"""

import json
import os
import time
from datetime import datetime
from grudarin import __version__


class NotesWriter:
    """
    Writes session notes, reports, and packet logs to disk.
    Output format is Markdown (.md) for human-readable reports.
    """

    def __init__(self, session_dir):
        self.session_dir = session_dir
        self.report_path = os.path.join(session_dir, "session_report.md")
        self.json_path = os.path.join(session_dir, "session_data.json")
        self.packet_log_path = os.path.join(session_dir, "packets.log")
        self._packet_log_handle = None

    def _open_packet_log(self):
        """Open the packet log file for appending."""
        if self._packet_log_handle is None:
            self._packet_log_handle = open(
                self.packet_log_path, "a", encoding="utf-8"
            )
            self._packet_log_handle.write(
                "TIMESTAMP | PROTOCOL | SRC_MAC | SRC_IP:PORT | "
                "DST_MAC | DST_IP:PORT | LENGTH | FLAGS | INFO\n"
            )
            self._packet_log_handle.write("-" * 140 + "\n")
        return self._packet_log_handle

    def log_packet(self, record):
        """Write a single packet record to the log."""
        try:
            fh = self._open_packet_log()
            ts = datetime.fromtimestamp(record.timestamp).strftime(
                "%H:%M:%S.%f"
            )[:-3]
            src = f"{record.src_ip}:{record.src_port}" if record.src_port else record.src_ip
            dst = f"{record.dst_ip}:{record.dst_port}" if record.dst_port else record.dst_ip
            line = (
                f"{ts} | {record.protocol:<8} | {record.src_mac} | "
                f"{src:<22} | {record.dst_mac} | {dst:<22} | "
                f"{record.length:<7} | {record.flags:<12} | {record.info}\n"
            )
            fh.write(line)
            fh.flush()
        except Exception:
            pass

    def write_final_report(self, network_model, findings=None, privacy_mode=False, export_graph="none"):
        """Write the complete session report in Markdown and JSON."""
        data = network_model.get_full_data()
        findings_list = findings or []
        if privacy_mode:
            data = self._apply_privacy_mask(data)
        self._write_json_report(data, findings_list)
        self._write_markdown_report(data, findings_list)
        self._write_graph_exports(data, export_graph or "none")
        if self._packet_log_handle:
            self._packet_log_handle.close()
            self._packet_log_handle = None

    def _mask_ip(self, ip):
        if not ip or ip == "unknown":
            return ip
        if ":" in ip:
            parts = ip.split(":")
            if len(parts) > 2:
                return ":".join(parts[:2] + ["xxxx"] * max(0, len(parts) - 2))
            return "xxxx::xxxx"
        bits = ip.split(".")
        if len(bits) == 4:
            return ".".join(bits[:2] + ["x", "x"])
        return ip

    def _apply_privacy_mask(self, data):
        masked = dict(data)
        devices = {}
        for k, dev in data.get("devices", {}).items():
            d = dict(dev)
            d["ip"] = self._mask_ip(d.get("ip"))
            if "all_ips" in d:
                d["all_ips"] = [self._mask_ip(x) for x in d.get("all_ips", [])]
            devices[k] = d
        masked["devices"] = devices

        dns_cache = {}
        for ip, host in data.get("dns_cache", {}).items():
            dns_cache[self._mask_ip(ip)] = host
        masked["dns_cache"] = dns_cache

        activity = []
        for ev in data.get("activity_log", []):
            e = dict(ev)
            e["source_ip"] = self._mask_ip(e.get("source_ip"))
            activity.append(e)
        masked["activity_log"] = activity
        return masked

    def _write_graph_exports(self, data, export_graph):
        mode = (export_graph or "none").lower()
        if mode not in {"json", "csv", "both"}:
            return

        nodes = []
        for key, dev in data.get("devices", {}).items():
            nodes.append({
                "id": key,
                "label": dev.get("hostname") or dev.get("ip") or key,
                "ip": dev.get("ip", "unknown"),
                "mac": dev.get("mac", "unknown"),
                "node_type": dev.get("node_type", "DEVICE"),
                "packets_sent": int(dev.get("packets_sent", 0)),
                "packets_received": int(dev.get("packets_received", 0)),
                "bytes_sent": int(dev.get("bytes_sent", 0)),
                "bytes_received": int(dev.get("bytes_received", 0)),
            })

        edges = []
        for c in data.get("connections", []):
            edges.append({
                "source": c.get("source", ""),
                "destination": c.get("destination", ""),
                "packet_count": int(c.get("packet_count", 0)),
                "byte_count": int(c.get("byte_count", 0)),
                "protocols": ",".join(c.get("protocols", [])),
            })

        if mode in {"json", "both"}:
            out = {
                "generated_at": datetime.now().isoformat(),
                "nodes": nodes,
                "edges": edges,
            }
            with open(os.path.join(self.session_dir, "graph_export.json"), "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2)

        if mode in {"csv", "both"}:
            nodes_path = os.path.join(self.session_dir, "graph_nodes.csv")
            edges_path = os.path.join(self.session_dir, "graph_edges.csv")
            with open(nodes_path, "w", encoding="utf-8") as f:
                f.write("id,label,ip,mac,node_type,packets_sent,packets_received,bytes_sent,bytes_received\n")
                for n in nodes:
                    f.write(
                        f"\"{n['id']}\",\"{n['label']}\",\"{n['ip']}\",\"{n['mac']}\",\"{n['node_type']}\","
                        f"{n['packets_sent']},{n['packets_received']},{n['bytes_sent']},{n['bytes_received']}\n"
                    )
            with open(edges_path, "w", encoding="utf-8") as f:
                f.write("source,destination,packet_count,byte_count,protocols\n")
                for e in edges:
                    f.write(
                        f"\"{e['source']}\",\"{e['destination']}\",{e['packet_count']},{e['byte_count']},\"{e['protocols']}\"\n"
                    )

    def _write_json_report(self, data, findings):
        """Write full session data as JSON."""
        try:
            data["security_findings"] = findings
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            print(f"  Error writing JSON report: {e}")

    def _write_markdown_report(self, data, findings):
        """Write the full Markdown report."""
        try:
            with open(self.report_path, "w", encoding="utf-8") as f:
                f.write(self._format_markdown(data, findings))
        except Exception as e:
            print(f"  Error writing Markdown report: {e}")

    def _format_markdown(self, data, findings):
        """Format the complete Markdown report."""
        md = []

        # ============================================================
        # HEADER
        # ============================================================
        md.append("# GRUDARIN - Network Monitoring Session Report")
        md.append("")
        md.append(f"> Generated by Grudarin v{__version__}")
        md.append(f"> Report time: `{datetime.now().isoformat()}`")
        md.append("")
        md.append("---")
        md.append("")

        # ============================================================
        # SESSION SUMMARY
        # ============================================================
        session = data["session"]
        md.append("## Session Summary")
        md.append("")
        md.append("| Property | Value |")
        md.append("|----------|-------|")
        md.append(f"| **Start Time** | `{session['start_time']}` |")
        md.append(f"| **End Time** | `{session['end_time']}` |")
        md.append(f"| **Duration** | `{session['duration_seconds']}` seconds |")
        md.append(f"| **Total Packets** | `{session['total_packets']}` |")
        md.append(f"| **Total Data** | `{self._format_bytes(session['total_bytes'])}` |")
        md.append(f"| **Devices Found** | `{len(data['devices'])}` |")
        md.append(f"| **Connections** | `{len(data['connections'])}` |")

        # Count findings by severity
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info") if isinstance(f, dict) else f.severity
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        total_vulns = sum(sev_counts.get(s, 0) for s in ["critical", "high", "medium"])
        md.append(f"| **Security Findings** | `{len(findings)}` total, `{total_vulns}` actionable |")
        md.append("")

        # ============================================================
        # PROTOCOL DISTRIBUTION
        # ============================================================
        md.append("## Protocol Distribution")
        md.append("")

        proto_dist = session.get("protocol_distribution", {})
        if proto_dist:
            total = sum(proto_dist.values()) or 1
            sorted_protos = sorted(proto_dist.items(), key=lambda x: x[1], reverse=True)
            md.append("| Protocol | Packets | Percentage |")
            md.append("|----------|---------|------------|")
            for proto, count in sorted_protos:
                pct = count / total * 100
                md.append(f"| {proto} | {count:,} | {pct:.1f}% |")
            md.append("")

        # ============================================================
        # DISCOVERED DEVICES
        # ============================================================
        md.append("## Discovered Devices")
        md.append("")

        devices = data.get("devices", {})
        for idx, (key, dev) in enumerate(devices.items(), 1):
            md.append(f"### Device #{idx}: {dev.get('ip', key)}")
            md.append("")
            md.append("| Property | Value |")
            md.append("|----------|-------|")
            md.append(f"| **MAC Address** | `{dev['mac']}` |")
            md.append(f"| **IP Address** | `{dev['ip']}` |")

            if dev.get("node_type"):
                md.append(f"| **Node Type** | `{dev['node_type']}` |")
            if dev.get("label") and dev.get("label") not in (dev.get("ip"), dev.get("hostname")):
                md.append(f"| **Label** | `{dev['label']}` |")

            if len(dev.get("all_ips", [])) > 1:
                ips = ", ".join(f"`{ip}`" for ip in dev["all_ips"])
                md.append(f"| **All IPs** | {ips} |")
            if dev.get("hostname"):
                md.append(f"| **Hostname** | `{dev['hostname']}` |")
            if dev.get("vendor"):
                md.append(f"| **Vendor** | {dev['vendor']} |")
            if dev.get("os_hint"):
                md.append(f"| **OS Hint** | {dev['os_hint']} |")
            if dev.get("is_gateway"):
                md.append(f"| **Role** | **Gateway/Router** |")

            md.append(f"| **First Seen** | `{dev['first_seen']}` |")
            md.append(f"| **Last Seen** | `{dev['last_seen']}` |")
            md.append(f"| **Packets Sent** | {dev['packets_sent']:,} |")
            md.append(f"| **Packets Received** | {dev['packets_received']:,} |")
            md.append(
                f"| **Data Sent** | {self._format_bytes(dev['bytes_sent'])} |"
            )
            md.append(
                f"| **Data Received** | {self._format_bytes(dev['bytes_received'])} |"
            )

            if dev.get("protocols"):
                md.append(f"| **Protocols** | {', '.join(dev['protocols'])} |")
            if dev.get("services"):
                md.append(f"| **Services** | {', '.join(dev['services'])} |")
            if dev.get("open_ports"):
                ports_str = ", ".join(str(p) for p in dev["open_ports"][:30])
                md.append(f"| **Open Ports** | `{ports_str}` |")
            if dev.get("ttl_values"):
                md.append(
                    f"| **TTL Values** | {', '.join(str(t) for t in dev['ttl_values'])} |"
                )
            md.append("")

        # ============================================================
        # NETWORK CONNECTIONS
        # ============================================================
        md.append("## Network Connections")
        md.append("")

        connections = data.get("connections", [])
        if connections:
            md.append("| # | Source | Destination | Packets | Data | Protocols |")
            md.append("|---|--------|-------------|---------|------|-----------|")
            for idx, conn in enumerate(connections, 1):
                protos = ", ".join(conn.get("protocols", []))
                md.append(
                    f"| {idx} | `{conn['source']}` | `{conn['destination']}` | "
                    f"{conn['packet_count']:,} | "
                    f"{self._format_bytes(conn['byte_count'])} | {protos} |"
                )
            md.append("")

        # ============================================================
        # DNS HOSTNAME MAPPINGS
        # ============================================================
        dns_cache = data.get("dns_cache", {})
        if dns_cache:
            md.append("## DNS Hostname Mappings")
            md.append("")
            md.append("| IP Address | Hostname |")
            md.append("|------------|----------|")
            for ip, hostname in sorted(dns_cache.items()):
                md.append(f"| `{ip}` | `{hostname}` |")
            md.append("")

        # ============================================================
        # RECENT NETWORK ACTIVITY
        # ============================================================
        activity = data.get("activity_log", [])
        if activity:
            md.append("## Realtime Activity Timeline")
            md.append("")
            md.append("| Time | Source IP | Activity Type | Target | Details |")
            md.append("|------|-----------|---------------|--------|---------|")
            for item in activity[-200:]:
                md.append(
                    f"| `{item.get('time','')}` | "
                    f"`{item.get('source_ip','unknown')}` | "
                    f"{item.get('event_type','activity')} | "
                    f"`{item.get('target','')[:80]}` | "
                    f"{(item.get('details','') or '').replace('|', '/')} |"
                )
            md.append("")

        # ============================================================
        # NETWORK CHANGES LOG
        # ============================================================
        changes = data.get("changes_log", [])
        if changes:
            md.append("## Network Changes Log")
            md.append("")
            md.append("| Time | Event | Details |")
            md.append("|------|-------|---------|")
            for change in changes[-100:]:
                event = change.get("event", "unknown")
                ts = change.get("time", "")
                if event == "device_discovered":
                    details = (
                        f"IP=`{change.get('ip', '?')}` "
                        f"MAC=`{change.get('mac', '?')}`"
                    )
                    md.append(f"| `{ts}` | New Device | {details} |")
                elif event == "connection_established":
                    details = (
                        f"`{change.get('source', '?')}` to "
                        f"`{change.get('destination', '?')}` "
                        f"({change.get('protocol', '?')})"
                    )
                    md.append(f"| `{ts}` | New Connection | {details} |")
            md.append("")

        # ============================================================
        # SECURITY FINDINGS - THE BIG RED SECTION
        # ============================================================
        md.append("")
        md.append("---")
        md.append("")
        md.append("---")
        md.append("")

        if findings:
            # Giant red header using HTML in Markdown
            md.append(
                '<h1 style="color: red; font-size: 2.5em; '
                'border: 3px solid red; padding: 15px; text-align: center;">'
                'SECURITY FINDINGS & VULNERABILITIES'
                '</h1>'
            )
            md.append("")
            md.append(
                '<p style="color: red; font-size: 1.3em; font-weight: bold; text-align: center;">'
                f'Total: {len(findings)} findings | '
                f'Critical: {sev_counts.get("critical", 0)} | '
                f'High: {sev_counts.get("high", 0)} | '
                f'Medium: {sev_counts.get("medium", 0)} | '
                f'Low: {sev_counts.get("low", 0)} | '
                f'Info: {sev_counts.get("info", 0)}'
                '</p>'
            )
            md.append("")

            # Severity color mapping for HTML
            severity_styles = {
                "critical": (
                    "color: #ff0000; background-color: #2d0000; "
                    "border-left: 6px solid #ff0000; padding: 12px; "
                    "font-size: 1.2em; font-weight: bold; margin: 10px 0;"
                ),
                "high": (
                    "color: #ff4444; background-color: #1a0000; "
                    "border-left: 6px solid #ff4444; padding: 12px; "
                    "font-size: 1.1em; font-weight: bold; margin: 10px 0;"
                ),
                "medium": (
                    "color: #ff8800; background-color: #1a1100; "
                    "border-left: 5px solid #ff8800; padding: 10px; "
                    "font-size: 1.05em; margin: 8px 0;"
                ),
                "low": (
                    "color: #ddaa00; background-color: #1a1500; "
                    "border-left: 4px solid #ddaa00; padding: 8px; "
                    "margin: 6px 0;"
                ),
                "info": (
                    "color: #88aacc; background-color: #0a1118; "
                    "border-left: 3px solid #88aacc; padding: 8px; "
                    "margin: 6px 0;"
                ),
            }

            severity_labels = {
                "critical": "CRITICAL",
                "high": "HIGH",
                "medium": "MEDIUM",
                "low": "LOW",
                "info": "INFO",
            }

            severity_md_icons = {
                "critical": "**[!!! CRITICAL !!!]**",
                "high": "**[!! HIGH !!]**",
                "medium": "**[! MEDIUM !]**",
                "low": "**[LOW]**",
                "info": "[INFO]",
            }

            # Group by severity
            for sev_level in ["critical", "high", "medium", "low", "info"]:
                sev_findings = [
                    f for f in findings
                    if (f.get("severity") if isinstance(f, dict) else f.severity) == sev_level
                ]
                if not sev_findings:
                    continue

                sev_label = severity_labels[sev_level]
                style = severity_styles[sev_level]

                # Section header
                if sev_level in ("critical", "high"):
                    md.append(
                        f'<h2 style="color: red; font-size: 1.8em; '
                        f'margin-top: 30px;">'
                        f'{sev_label} SEVERITY ({len(sev_findings)} findings)'
                        f'</h2>'
                    )
                elif sev_level == "medium":
                    md.append(
                        f'<h2 style="color: #ff8800; font-size: 1.5em; '
                        f'margin-top: 25px;">'
                        f'{sev_label} SEVERITY ({len(sev_findings)} findings)'
                        f'</h2>'
                    )
                else:
                    md.append(f"### {sev_label} SEVERITY ({len(sev_findings)} findings)")

                md.append("")

                for i, finding in enumerate(sev_findings, 1):
                    if isinstance(finding, dict):
                        title = finding.get("title", "Unknown")
                        desc = finding.get("description", "")
                        affected = finding.get("affected", "")
                        rec = finding.get("recommendation", "")
                        sev = finding.get("severity", "info")
                    else:
                        title = finding.title
                        desc = finding.description
                        affected = finding.affected
                        rec = finding.recommendation
                        sev = finding.severity

                    icon = severity_md_icons.get(sev, "")

                    # HTML block for critical/high with red styling
                    md.append(f'<div style="{style}">')
                    md.append("")
                    md.append(f"{icon} **{title}**")
                    md.append("")
                    md.append(f"{desc}")
                    md.append("")
                    if affected:
                        md.append(f"**Affected:** `{affected}`")
                        md.append("")
                    if rec:
                        if sev in ("critical", "high"):
                            md.append(
                                f'<strong style="color: #ff6666;">'
                                f'Recommendation: {rec}</strong>'
                            )
                        else:
                            md.append(f"**Recommendation:** {rec}")
                        md.append("")
                    md.append("</div>")
                    md.append("")

        else:
            md.append(
                '<h2 style="color: #00cc88; font-size: 1.8em; text-align: center;">'
                'No Security Findings Detected'
                '</h2>'
            )
            md.append("")
            md.append("> No vulnerabilities or misconfigurations were detected during this session.")
            md.append("> This does not guarantee the network is secure - extend scan duration and scope.")
            md.append("")

        # ============================================================
        # FOOTER
        # ============================================================
        md.append("---")
        md.append("")
        md.append(f"*Report generated by Grudarin v{__version__} at `{datetime.now().isoformat()}`*")
        md.append("")
        md.append("*This tool is for authorized security assessment only.*")
        md.append("")

        return "\n".join(md) + "\n"

    @staticmethod
    def _format_bytes(num_bytes):
        """Format byte count to human-readable string."""
        if num_bytes < 1024:
            return f"{num_bytes} B"
        elif num_bytes < 1024 * 1024:
            return f"{num_bytes / 1024:.1f} KB"
        elif num_bytes < 1024 * 1024 * 1024:
            return f"{num_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"

    def save_graph_snapshot(self, surface_data, filename):
        """Save a graph snapshot image."""
        try:
            path = os.path.join(self.session_dir, filename)
            # Tkinter Canvas supports PostScript export; keep method generic.
            if hasattr(surface_data, "postscript"):
                surface_data.postscript(file=path)
            else:
                raise RuntimeError("snapshot surface does not support export")
        except Exception as e:
            print(f"  Error saving snapshot: {e}")

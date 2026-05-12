"""
Grudarin - Entry point
Run with: sudo grudarin [command] [options]

Workflow:
  1. grudarin                    -- Interactive mode, lists networks
  2. grudarin --scan <interface> -- Start scan on interface
  3. grudarin --help             -- Show all commands
  4. grudarin --list             -- List available interfaces/networks
"""

import argparse
import os
import sys
import signal
import subprocess
import threading
import time
import ipaddress
import tempfile
from datetime import datetime

from grudarin import __version__
from grudarin.capture import PacketCapture
from grudarin.network_model import NetworkModel
from grudarin.notes import NotesWriter
from grudarin.graph_window import GraphWindow
from grudarin.vuln_analyzer import VulnAnalyzer
from grudarin.site_scan import SiteGraphModel, SiteScanner


# ----------------------------------------------------------------
# Network / WiFi discovery
# ----------------------------------------------------------------

def discover_wifi_networks():
    """Scan for available WiFi networks using system tools."""
    networks = []
    try:
        if sys.platform == "linux":
            # Try iwlist first
            try:
                out = subprocess.check_output(
                    ["iwlist", "scan"], stderr=subprocess.DEVNULL, timeout=15
                ).decode("utf-8", errors="ignore")
                ssid = None
                for line in out.splitlines():
                    line = line.strip()
                    if "ESSID:" in line:
                        ssid = line.split("ESSID:")[1].strip().strip('"')
                    if "Address:" in line:
                        bssid = line.split("Address:")[1].strip()
                        if ssid:
                            networks.append({"ssid": ssid, "bssid": bssid})
                            ssid = None
            except Exception:
                pass

            # Try nmcli as fallback
            if not networks:
                try:
                    out = subprocess.check_output(
                        ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi", "list"],
                        stderr=subprocess.DEVNULL, timeout=15
                    ).decode("utf-8", errors="ignore")
                    for line in out.strip().splitlines():
                        parts = line.split(":")
                        if len(parts) >= 4 and parts[0].strip():
                            networks.append({
                                "ssid": parts[0].strip(),
                                "bssid": parts[1].strip(),
                                "signal": parts[2].strip(),
                                "security": parts[3].strip(),
                            })
                except Exception:
                    pass

        elif sys.platform == "darwin":
            try:
                out = subprocess.check_output(
                    ["/System/Library/PrivateFrameworks/Apple80211.framework/"
                     "Versions/Current/Resources/airport", "-s"],
                    stderr=subprocess.DEVNULL, timeout=15
                ).decode("utf-8", errors="ignore")
                for line in out.strip().splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 2:
                        networks.append({"ssid": parts[0], "bssid": parts[1]})
            except Exception:
                pass

        elif sys.platform == "win32":
            try:
                out = subprocess.check_output(
                    ["netsh", "wlan", "show", "networks", "mode=bssid"],
                    stderr=subprocess.DEVNULL, timeout=15
                ).decode("utf-8", errors="ignore")
                ssid = None
                for line in out.splitlines():
                    line = line.strip()
                    if line.startswith("SSID") and "BSSID" not in line:
                        ssid = line.split(":")[1].strip() if ":" in line else None
                    if line.startswith("BSSID"):
                        bssid = line.split(":")[1].strip() if ":" in line else ""
                        if ssid:
                            networks.append({"ssid": ssid, "bssid": bssid})
            except Exception:
                pass
    except Exception:
        pass

    return networks


def list_interfaces():
    """List available network interfaces."""
    try:
        from scapy.all import get_if_list, get_if_addr, get_if_hwaddr, conf
    except ImportError:
        print("  [error] scapy is required. Install with: pip install scapy")
        sys.exit(1)

    interfaces = get_if_list()
    print("\n  AVAILABLE NETWORK INTERFACES")
    print("  " + "-" * 60)
    print(f"  {'Interface':<18} {'IP Address':<18} {'MAC Address':<20} {'Status'}")
    print("  " + "-" * 60)

    for iface in interfaces:
        try:
            addr = get_if_addr(iface)
        except Exception:
            addr = "N/A"
        try:
            mac = get_if_hwaddr(iface)
        except Exception:
            mac = "N/A"
        status = "UP" if addr and addr != "0.0.0.0" else "DOWN"
        print(f"  {iface:<18} {addr:<18} {mac:<20} {status}")

    # Discover WiFi
    print("\n  DETECTED WIFI NETWORKS")
    print("  " + "-" * 60)
    wifi_nets = discover_wifi_networks()
    if wifi_nets:
        print(f"  {'SSID':<25} {'BSSID':<20} {'Signal':<8} {'Security'}")
        print("  " + "-" * 60)
        for net in wifi_nets:
            print(
                f"  {net.get('ssid','?'):<25} "
                f"{net.get('bssid','?'):<20} "
                f"{net.get('signal','?'):<8} "
                f"{net.get('security','?')}"
            )
    else:
        print("  No WiFi networks found (may need root or wireless tools)")

    # Connected LANs
    print("\n  CONNECTED LAN / GATEWAY INFO")
    print("  " + "-" * 60)
    try:
        gw = conf.route.route("0.0.0.0")
        if gw:
            print(f"  Default Gateway  : {gw[2]}")
            print(f"  Output Interface : {gw[0]}")
    except Exception:
        print("  Could not detect gateway")

    print()


def parse_args():
    """Parse command line arguments."""
    argv = list(sys.argv[1:])
    # Support user shorthand: grudarin --scan -site example.invalid
    for idx, tok in enumerate(argv):
        if tok == "--scan" and idx + 2 < len(argv) and argv[idx + 1] == "-site":
            domain = argv[idx + 2]
            argv = argv[:idx] + ["--scan-site", domain] + argv[idx + 3:]
            break

    parser = argparse.ArgumentParser(
        prog="grudarin",
        description=(
            "Grudarin - Network Monitor + Vulnerability Scanner + "
            "Force-Directed Graph Visualization"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WORKFLOW:
  1. sudo grudarin --list                 List interfaces and WiFi networks
  2. sudo grudarin --scan wlan0           Start monitoring on wlan0
  3. sudo grudarin --scan eth0 -o ~/notes Start monitoring, save to ~/notes

EXAMPLES:
  sudo grudarin --scan wlan0 --name my_home_scan
    grudarin --scan-site example.invalid
  sudo grudarin --scan eth0 -o /tmp/reports --ports 1-65535
  sudo grudarin --scan wlan0 --no-graph --duration 120
  sudo grudarin --scan eth0 --targets 192.168.1.1,192.168.1.100
  sudo grudarin --list

GRAPH CONTROLS:
    Left Click      Select node and inspect all details
    Left Drag       Move node in graph
    Left Drag BG    Pan graph canvas
    Mouse Wheel     Smooth zoom in/out
    Scan Button     Scan selected node from GUI panel
    Live Charts     Built-in protocol and top-talker charts
    Ctrl+C / Close  Stop capture and print report output path
"""
    )
    parser.add_argument(
        "--scan", metavar="INTERFACE",
        type=str, default=None,
        help="Start scan on this interface (e.g., wlan0, eth0, en0)"
    )
    parser.add_argument(
        "--scan-site", "--site", "-site", metavar="DOMAIN",
        type=str, default=None,
        help="Scan a website/domain (e.g., example.invalid) and build live recon graph"
    )
    parser.add_argument(
        "--list", "-l", action="store_true",
        help="List available interfaces, WiFi networks, and connected LANs"
    )
    parser.add_argument(
        "-o", "--output", type=str, default=None,
        help="Directory to save notes and reports"
    )
    parser.add_argument(
        "--name", "-n", type=str, default=None,
        help="Name for this scan session (used in filenames)"
    )
    parser.add_argument(
        "--duration", "-d", type=int, default=0,
        help="Stop after N seconds (0 = unlimited, stop with Ctrl+C)"
    )
    parser.add_argument(
        "--no-graph", action="store_true",
        help="Run headless without the graph window"
    )
    parser.add_argument(
        "--ports", type=str, default="1-1024",
        help="Port range for vulnerability scan (default: 1-1024)"
    )
    parser.add_argument(
        "--targets", type=str, default=None,
        help="Comma-separated IPs to port-scan (default: auto-discover)"
    )
    parser.add_argument(
        "--no-scan", action="store_true",
        help="Skip vulnerability scanning (capture only)"
    )
    parser.add_argument(
        "--promisc", action="store_true", default=True,
        help="Enable promiscuous mode (default: on)"
    )
    parser.add_argument(
        "--filter", "-f", type=str, default=None,
        help="BPF filter (e.g., 'tcp port 80')"
    )
    parser.add_argument(
        "--export-graph", type=str, default="none",
        choices=["none", "json", "csv", "both"],
        help="Export graph data as JSON/CSV files (default: none)"
    )
    parser.add_argument(
        "--privacy-mode", action="store_true",
        help="Mask sensitive IP details in output reports/exports"
    )
    return parser.parse_args(argv)


def print_banner():
    """Print the Grudarin banner."""
    print("""
    ================================================================
                          G R U D A R I N
              Network Monitor + Vulnerability Scanner
               + Built-in Graph Viewer  v%s
    ================================================================
    """ % __version__)


def _resolve_output_base_dir(requested_dir=None):
    """
    Return a writable base output directory.
    Falls back to user-home local data path, then temp directory.
    """
    candidates = []
    if requested_dir:
        candidates.append(os.path.abspath(os.path.expanduser(requested_dir)))
    else:
        candidates.append(os.path.join(os.getcwd(), "grudarin_output"))

    home = os.path.expanduser("~")
    candidates.append(os.path.join(home, ".local", "share", "grudarin_output"))
    candidates.append(os.path.join(tempfile.gettempdir(), "grudarin_output"))

    last_err = None
    for base in candidates:
        try:
            os.makedirs(base, exist_ok=True)
            test_file = os.path.join(base, ".grudarin_write_test")
            with open(test_file, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(test_file)
            return base
        except Exception as e:
            last_err = e
            continue

    print(f"  [error] No writable output directory found: {last_err}")
    sys.exit(1)


def check_privileges():
    """Check root/admin privileges."""
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def check_tools():
    """Check which compiled tools are available."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tools = {}

    scanner_path = os.path.join(base, "bin", "grudarin_scanner")
    tools["cpp_scanner"] = os.path.isfile(scanner_path) and os.access(scanner_path, os.X_OK)

    netprobe_path = os.path.join(base, "bin", "grudarin_netprobe")
    tools["go_netprobe"] = os.path.isfile(netprobe_path) and os.access(netprobe_path, os.X_OK)

    for lua_cmd in ["lua5.4", "lua5.3", "lua"]:
        try:
            subprocess.run([lua_cmd, "-v"], capture_output=True, timeout=3)
            tools["lua"] = True
            tools["lua_cmd"] = lua_cmd
            break
        except Exception:
            continue
    else:
        tools["lua"] = False

    return tools


def interactive_mode():
    """Interactive mode when no arguments given."""
    print_banner()
    if not check_privileges():
        print("  [warn] Not running as root. Run with sudo for full capture.")
        print()

    list_interfaces()

    print("  To start scanning, use:")
    print("    sudo grudarin --scan <interface_name>")
    print()
    print("  For full help:")
    print("    grudarin --help")
    print()

    iface = input("  Enter interface to scan (or press Enter to exit): ").strip()
    if not iface:
        print("  Exiting.")
        sys.exit(0)

    output_dir = input("  Enter path to save notes [./grudarin_output]: ").strip()
    if not output_dir:
        output_dir = _resolve_output_base_dir(None)
    else:
        output_dir = _resolve_output_base_dir(output_dir)

    scan_name = input("  Enter a name for this scan [session]: ").strip()
    if not scan_name:
        scan_name = "session"

    return iface, output_dir, scan_name


def run_scan(iface, output_dir, scan_name, args):
    """Run the main scan pipeline."""
    output_dir = _resolve_output_base_dir(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in scan_name)
    session_dir = os.path.join(output_dir, f"grudarin_{safe_name}_{timestamp}")
    os.makedirs(session_dir, exist_ok=True)

    tools = check_tools()

    print(f"\n  Interface   : {iface}")
    print(f"  Output      : {session_dir}")
    print(f"  Scan Name   : {scan_name}")
    print(f"  Duration    : {'Unlimited' if args.duration == 0 else str(args.duration) + 's'}")
    print(f"  Port Range  : {args.ports}")
    print(f"  Graph       : {'Disabled' if args.no_graph else 'Enabled'}")
    print(f"  Vuln Scan   : {'Disabled' if args.no_scan else 'Enabled'}")
    print(f"  C++ Scanner : {'Ready' if tools.get('cpp_scanner') else 'Python fallback'}")
    print(f"  Go Netprobe : {'Ready' if tools.get('go_netprobe') else 'Python fallback'}")
    print(f"  Lua Rules   : {'Ready' if tools.get('lua') else 'Python fallback'}")
    print()

    # Shared state
    network_model = NetworkModel()
    notes_writer = NotesWriter(session_dir)
    stop_event = threading.Event()

    # Capture engine
    capture = PacketCapture(
        interface=iface,
        network_model=network_model,
        notes_writer=notes_writer,
        stop_event=stop_event,
        promisc=args.promisc,
        bpf_filter=args.filter
    )

    # Vuln analyzer
    vuln_analyzer = VulnAnalyzer(
        network_model=network_model,
        session_dir=session_dir
    )

    # Signal handler
    def on_signal(sig, frame):
        print("\n\n  Stopping Grudarin...")
        stop_event.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    # Start capture thread
    capture_thread = threading.Thread(target=capture.start, daemon=True)
    capture_thread.start()
    print("  [live] Capture started on", iface)
    print("  [live] Packets are being captured and analyzed in real time")
    print()

    # Console printer thread (prints live stats in terminal)
    def console_printer():
        while not stop_event.is_set():
            stats = network_model.get_stats()
            line = (
                f"\r  [scanning] "
                f"Packets: {stats['total_packets']}  "
                f"Devices: {stats['total_devices']}  "
                f"Links: {stats['total_connections']}  "
                f"Data: {_fmt_bytes(stats['total_bytes'])}  "
                f"Uptime: {int(stats['uptime'])}s    "
            )
            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.8)

    printer_thread = threading.Thread(target=console_printer, daemon=True)
    printer_thread.start()

    # Graph or headless
    if not args.no_graph:
        def scan_node_callback(target_ip):
            """Scan a selected graph node and return structured details."""
            issues = []
            open_ports = []

            # Prefer C++ scanner when available.
            if vuln_analyzer.has_cpp_scanner:
                cpp_res = vuln_analyzer.run_cpp_scanner(
                    target_ip,
                    port_range=args.ports,
                    threads=40,
                    timeout=400,
                )
                if cpp_res:
                    # Handle both host-list and single-host style payloads.
                    hosts = cpp_res if isinstance(cpp_res, list) else [cpp_res]
                    for host in hosts:
                        if host.get("ip") == target_ip or host.get("target") == target_ip:
                            for p in host.get("open_ports", []):
                                pnum = p.get("port") if isinstance(p, dict) else p
                                if pnum:
                                    open_ports.append(int(pnum))
                                if isinstance(p, dict) and p.get("vulnerability"):
                                    issues.append({
                                        "severity": p.get("severity", "medium"),
                                        "text": p.get("vulnerability", ""),
                                    })

            # Python fallback or supplement.
            if not open_ports:
                try:
                    parts = str(args.ports).split("-")
                    p_start = int(parts[0]) if len(parts) >= 1 else 1
                    p_end = int(parts[1]) if len(parts) >= 2 else 1024
                except Exception:
                    p_start, p_end = 1, 1024

                py_ports = vuln_analyzer.run_python_scanner(
                    target_ip,
                    port_start=p_start,
                    port_end=p_end,
                    threads=40,
                    timeout=0.35,
                )
                for p in py_ports:
                    pnum = int(p.get("port", 0))
                    if pnum > 0:
                        open_ports.append(pnum)
                    if pnum in vuln_analyzer.DANGEROUS_PORTS:
                        svc, sev, risk = vuln_analyzer.DANGEROUS_PORTS[pnum]
                        issues.append({
                            "severity": sev,
                            "text": f"{svc} on {pnum}: {risk}",
                        })
                    banner = p.get("banner", "") or ""
                    if banner:
                        for pat, _name, sev, desc in vuln_analyzer.VULN_SIGNATURES:
                            if pat in banner:
                                issues.append({"severity": sev, "text": desc})
                                break

            # Deduplicate while preserving order.
            dedup_ports = []
            seen = set()
            for p in sorted(open_ports):
                if p not in seen:
                    seen.add(p)
                    dedup_ports.append(p)

            return {
                "ip": target_ip,
                "port_range": args.ports,
                "open_ports": dedup_ports,
                "issues": issues,
            }

        graph_window = GraphWindow(
            network_model=network_model,
            stop_event=stop_event,
            notes_writer=notes_writer,
            session_dir=session_dir,
            scan_callback=scan_node_callback,
        )
        graph_window.run()
    else:
        try:
            if args.duration > 0:
                deadline = time.time() + args.duration
                while not stop_event.is_set() and time.time() < deadline:
                    time.sleep(0.5)
                stop_event.set()
            else:
                while not stop_event.is_set():
                    time.sleep(0.5)
        except KeyboardInterrupt:
            stop_event.set()

    stop_event.set()
    capture_thread.join(timeout=5)
    print("\n")

    # Vulnerability analysis
    findings_data = []
    if not args.no_scan:
        print("  [analysis] Running vulnerability and misconfiguration scan...")
        scan_targets = None
        if args.targets:
            scan_targets = [t.strip() for t in args.targets.split(",")]
        findings = vuln_analyzer.analyze(
            scan_targets=scan_targets,
            port_range=args.ports
        )
        findings_data = vuln_analyzer.get_findings_dicts()

        # Print findings to console
        if findings:
            print()
            print("  " + "=" * 60)
            print("  SECURITY FINDINGS")
            print("  " + "=" * 60)
            for f in findings:
                sev = f.severity.upper()
                tag = f"[{sev}]"
                print(f"  {tag:<12} {f.title}")
                print(f"               {f.description[:80]}")
                if f.affected:
                    print(f"               Affected: {f.affected}")
                print()
    else:
        print("  [skip] Vulnerability scan disabled")

    # Write reports
    print("  [report] Writing final reports...")
    notes_writer.write_final_report(
        network_model,
        findings_data,
        privacy_mode=args.privacy_mode,
        export_graph=args.export_graph,
    )

    print()
    print(f"  Reports saved to: {session_dir}")
    print(f"    session_report.md    Markdown report (security findings in red)")
    print(f"    session_data.json    Machine-readable full data")
    print(f"    packets.log          Raw packet log")
    if args.export_graph in ("json", "both"):
        print(f"    graph_export.json    Graph export (nodes/edges)")
    if args.export_graph in ("csv", "both"):
        print(f"    graph_nodes.csv      Graph nodes table")
        print(f"    graph_edges.csv      Graph edges table")
    print()

    stats = network_model.get_stats()
    print(f"  Session Summary:")
    print(f"    Total Packets  : {stats['total_packets']}")
    print(f"    Devices Found  : {stats['total_devices']}")
    print(f"    Connections    : {stats['total_connections']}")
    print(f"    Data Captured  : {_fmt_bytes(stats['total_bytes'])}")
    print(f"    Findings       : {len(findings_data)}")
    print()
    print("  Grudarin session complete.")
    print()


def run_site_scan(domain, output_dir, scan_name, args):
    """Run website/domain reconnaissance and show live graph."""
    output_dir = _resolve_output_base_dir(output_dir)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in scan_name)
    session_dir = os.path.join(output_dir, f"grudarin_site_{safe_name}_{timestamp}")
    os.makedirs(session_dir, exist_ok=True)

    print(f"\n  Site Target  : {domain}")
    print(f"  Output       : {session_dir}")
    print(f"  Scan Name    : {scan_name}")
    print(f"  Graph        : {'Disabled' if args.no_graph else 'Enabled'}")
    print(f"  Duration     : {'Unlimited' if args.duration == 0 else str(args.duration) + 's'}")
    print("  Recon Types  : DNS_NAME, IP_ADDRESS, IP_RANGE, OPEN_TCP_PORT, URL,")
    print("                 EMAIL_ADDRESS, STORAGE_BUCKET, ORG_STUB, USER_STUB,")
    print("                 TECHNOLOGY, VULNERABILITY")
    print()

    model = SiteGraphModel()
    notes_writer = NotesWriter(session_dir)
    stop_event = threading.Event()
    scanner = SiteScanner(model=model, domain=domain, stop_event=stop_event)

    def on_signal(_sig, _frame):
        print("\n\n  Stopping site scan...")
        stop_event.set()

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    scan_thread = threading.Thread(target=scanner.run, daemon=True)
    scan_thread.start()

    # Node-level scan callback for site entities.
    def scan_site_node(target_ip):
        issues = []
        open_ports = []

        vuln = VulnAnalyzer(network_model=model, session_dir=session_dir)
        try:
            ip_obj = ipaddress.ip_address(target_ip)
            if ip_obj.version == 4:
                ports = vuln.run_python_scanner(
                    target_ip,
                    port_start=1,
                    port_end=1024,
                    threads=40,
                    timeout=0.35,
                )
                for p in ports:
                    pn = int(p.get("port", 0))
                    if pn > 0:
                        open_ports.append(pn)
                    if pn in vuln.DANGEROUS_PORTS:
                        svc, sev, risk = vuln.DANGEROUS_PORTS[pn]
                        issues.append({"severity": sev, "text": f"{svc} on {pn}: {risk}"})
        except Exception as e:
            issues.append({"severity": "medium", "text": str(e)})

        return {
            "ip": target_ip,
            "port_range": "1-1024",
            "open_ports": sorted(set(open_ports)),
            "issues": issues,
        }

    if not args.no_graph:
        graph_window = GraphWindow(
            network_model=model,
            stop_event=stop_event,
            notes_writer=notes_writer,
            session_dir=session_dir,
            scan_callback=scan_site_node,
        )

        if args.duration and args.duration > 0:
            def timer_stop():
                deadline = time.time() + args.duration
                while not stop_event.is_set() and time.time() < deadline:
                    time.sleep(0.5)
                stop_event.set()
            threading.Thread(target=timer_stop, daemon=True).start()

        graph_window.run()
    else:
        try:
            if args.duration > 0:
                deadline = time.time() + args.duration
                while not stop_event.is_set() and time.time() < deadline:
                    time.sleep(0.5)
                stop_event.set()
            else:
                while not stop_event.is_set():
                    if not scan_thread.is_alive():
                        break
                    time.sleep(0.5)
        except KeyboardInterrupt:
            stop_event.set()

    stop_event.set()
    scan_thread.join(timeout=5)

    findings_data = []
    if not args.no_scan:
        print("  [analysis] Running site vulnerability analysis...")
        vuln_analyzer = VulnAnalyzer(network_model=model, session_dir=session_dir)
        findings = vuln_analyzer.analyze(scan_targets=None, port_range=args.ports)
        findings_data = vuln_analyzer.get_findings_dicts()
        if findings:
            print()
            print("  " + "=" * 60)
            print("  SITE SECURITY FINDINGS")
            print("  " + "=" * 60)
            for finding in findings:
                sev = finding.severity.upper()
                print(f"  [{sev:<8}] {finding.title}")
                print(f"               {finding.description[:80]}")
                if finding.affected:
                    print(f"               Affected: {finding.affected}")
                print()
    else:
        print("  [skip] Vulnerability scan disabled")

    site_data = model.get_full_data()
    for key, dev in site_data.get("devices", {}).items():
        if dev.get("node_type") != "VULNERABILITY":
            continue
        findings_data.append({
            "severity": (dev.get("severity") or "info").lower(),
            "title": dev.get("label", dev.get("hostname", key)),
            "description": dev.get("description", dev.get("label", key)),
            "affected": dev.get("ip", ""),
            "recommendation": dev.get("recommendation", "Review the exposed endpoint and restrict access."),
        })

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings_data.sort(key=lambda item: severity_order.get(str(item.get("severity", "info")).lower(), 99))

    print("\n  [report] Writing final reports...")
    notes_writer.write_final_report(
        model,
        findings_data,
        privacy_mode=args.privacy_mode,
        export_graph=args.export_graph,
    )

    stats = model.get_stats()
    print(f"\n  Reports saved to: {session_dir}")
    print("    session_report.md")
    print("    session_data.json")
    print("    packets.log")
    if args.export_graph in ("json", "both"):
        print("    graph_export.json")
    if args.export_graph in ("csv", "both"):
        print("    graph_nodes.csv")
        print("    graph_edges.csv")
    print("\n  Site Scan Summary:")
    print(f"    Entities Found : {stats['total_devices']}")
    print(f"    Relationships  : {stats['total_connections']}")
    print(f"    Events         : {stats['total_packets']}")
    print(f"    Data Processed : {_fmt_bytes(stats['total_bytes'])}")
    print("\n  Grudarin site scan complete.\n")


def _fmt_bytes(n):
    if n < 1024:
        return f"{n} B"
    elif n < 1048576:
        return f"{n/1024:.1f} KB"
    elif n < 1073741824:
        return f"{n/1048576:.1f} MB"
    return f"{n/1073741824:.2f} GB"


def main():
    """Main entry point."""
    args = parse_args()

    if args.list:
        print_banner()
        if not check_privileges():
            print("  [warn] Run with sudo for full interface/WiFi info")
        list_interfaces()
        sys.exit(0)

    if args.scan:
        print_banner()
        if not check_privileges():
            print("  [warn] Not root. Packet capture may fail.")
            print("  [warn] Re-run with: sudo grudarin --scan", args.scan)
            print()

        output_dir = _resolve_output_base_dir(args.output)
        scan_name = args.name or "session"
        run_scan(args.scan, output_dir, scan_name, args)
    elif args.scan_site:
        print_banner()
        output_dir = _resolve_output_base_dir(args.output)
        scan_name = args.name or args.scan_site
        run_site_scan(args.scan_site, output_dir, scan_name, args)
    else:
        # Interactive mode
        iface, output_dir, scan_name = interactive_mode()
        args.duration = 0
        args.ports = "1-1024"
        args.targets = None
        args.no_scan = False
        args.no_graph = False
        args.promisc = True
        args.filter = None
        run_scan(iface, output_dir, scan_name, args)
if __name__ == "__main__":
    main()

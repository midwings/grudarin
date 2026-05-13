"""
Grudarin - Entry point
Run with: sudo grudarin [command] [options]

Workflow:
  1. grudarin                    -- Interactive mode, lists networks
  2. grudarin --scan <interface> -- Start live activity monitoring
  3. grudarin --help             -- Show all commands
  4. grudarin --list             -- List available interfaces/networks
"""

import argparse
import difflib
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
from grudarin.dashboard_window import DashboardWindow
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


def _get_interfaces():
    """Return available system interfaces (best effort)."""
    try:
        from scapy.all import get_if_list
        return list(get_if_list())
    except Exception:
        return []


def _normalize_interface_guess(value):
    """Normalize common interface typos such as wlano -> wlan0."""
    raw = (value or "").strip()
    if not raw:
        return raw
    if raw.lower().endswith("o"):
        return raw[:-1] + "0"
    return raw


def _suggest_interface(user_value, interfaces=None):
    """Suggest the closest known interface for a mistyped name."""
    raw = (user_value or "").strip()
    if not raw:
        return None
    interfaces = interfaces or _get_interfaces()
    if not interfaces:
        return None

    lowered = {iface.lower(): iface for iface in interfaces}
    normalized = _normalize_interface_guess(raw).lower()
    if normalized in lowered:
        return lowered[normalized]

    matches = difflib.get_close_matches(
        raw.lower(),
        list(lowered.keys()),
        n=1,
        cutoff=0.55,
    )
    if matches:
        return lowered[matches[0]]
    return None


def _resolve_scan_interface(user_value):
    """
    Resolve user-provided scan target to an interface.
    Accepts direct interface names and, on Linux, connected SSID names.
    """
    raw = (user_value or "").strip()
    if not raw:
        return None

    interfaces = _get_interfaces()
    iface_map = {i.lower(): i for i in interfaces}
    if raw.lower() in iface_map:
        return iface_map[raw.lower()]

    normalized_guess = _normalize_interface_guess(raw)
    if normalized_guess.lower() in iface_map:
        return iface_map[normalized_guess.lower()]

    # Linux convenience: allow passing SSID (e.g., hotspot name) instead of iface.
    if sys.platform == "linux":
        # Try active WiFi map first.
        try:
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "DEVICE,ACTIVE,SSID", "dev", "wifi"],
                stderr=subprocess.DEVNULL,
                timeout=8,
            ).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                parts = line.split(":")
                if len(parts) < 3:
                    continue
                dev = parts[0].strip()
                active = parts[1].strip().lower()
                ssid = ":".join(parts[2:]).strip()
                if active == "yes" and ssid.lower() == raw.lower():
                    if dev in interfaces:
                        return dev
                    if dev.lower() in iface_map:
                        return iface_map[dev.lower()]
        except Exception:
            pass

        # Try iw dev as second option for connected SSID
        try:
            out = subprocess.check_output(["iw", "dev"], stderr=subprocess.DEVNULL, timeout=5).decode("utf-8", errors="ignore")
            curr_iface = None
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Interface"):
                    curr_iface = line.split()[1]
                if line.startswith("ssid") and curr_iface:
                    found_ssid = line.split(" ", 1)[1].strip()
                    if found_ssid.lower() == raw.lower():
                        if curr_iface in interfaces: return curr_iface
                        if curr_iface.lower() in iface_map: return iface_map[curr_iface.lower()]
        except Exception:
            pass

        # Fallback: if SSID exists in scan list, pick connected wifi device or first wifi device.
        try:
            nets = discover_wifi_networks()
            if any(str(n.get("ssid", "")).lower() == raw.lower() for n in nets):
                # Prefer connected wifi interface if nmcli is available.
                wifi_devices = []
                try:
                    out = subprocess.check_output(
                        ["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "dev", "status"],
                        stderr=subprocess.DEVNULL,
                        timeout=8,
                    ).decode("utf-8", errors="ignore")
                    for line in out.splitlines():
                        parts = line.split(":" )
                        if len(parts) < 3:
                            continue
                        dev = parts[0].strip()
                        typ = parts[1].strip().lower()
                        state = parts[2].strip().lower()
                        if typ == "wifi" and dev:
                            if dev in interfaces or dev.lower() in iface_map:
                                mapped = dev if dev in interfaces else iface_map[dev.lower()]
                                if state == "connected":
                                    return mapped
                                wifi_devices.append(mapped)
                except Exception:
                    # nmcli may not be available in the sudo environment; continue to other fallbacks.
                    wifi_devices = []

                if wifi_devices:
                    return wifi_devices[0]

                # As a last resort, pick the first interface that looks like a wireless adapter
                # (common prefixes used by Linux: wlan, wl, wlp, wifi). This helps when nmcli
                # or iwlist are unavailable under sudo but a wireless device exists.
                for candidate in interfaces:
                    low = candidate.lower()
                    if low.startswith(("wlan", "wl", "wlp", "wifi")):
                        return candidate
        except Exception:
            pass

    return None


def _validate_interface_exists(iface):
    """True if interface currently exists from Scapy's perspective."""
    return iface in _get_interfaces()


def _print_subprocess_output(prefix, result):
    """Print captured subprocess output with a consistent prefix."""
    for stream in (getattr(result, "stdout", "") or "", getattr(result, "stderr", "") or ""):
        for line in str(stream).splitlines():
            line = line.rstrip()
            if line:
                print(f"  {prefix} {line}")


def parse_args():
    """Parse command line arguments."""
    argv = list(sys.argv[1:])
    # Support user shorthand: grudarin --scan -site example.invalid
    for idx, tok in enumerate(argv):
        if tok == "--scan" and idx + 2 < len(argv) and argv[idx + 1] == "-site":
            domain = argv[idx + 2]
            argv = argv[:idx] + ["--scan-site", domain] + argv[idx + 3:]
            break
    # Support shorthand: grudarin --scan wlan0 Pixel
    for idx, tok in enumerate(argv):
        if tok == "--scan" and idx + 2 < len(argv):
            iface = argv[idx + 1]
            maybe_ssid = argv[idx + 2]
            if iface and not iface.startswith("-") and maybe_ssid and not maybe_ssid.startswith("-"):
                argv = argv[:idx] + ["--scan", iface, "--ssid", maybe_ssid] + argv[idx + 3:]
            break

    parser = argparse.ArgumentParser(
        prog="grudarin",
        description=(
            "Grudarin - Network Monitor (Spy of your own network) + Vulnerability Scanner"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
WORKFLOW:
  1. sudo grudarin --list                 List interfaces and WiFi networks
  2. sudo grudarin --scan wlan0           Start live monitoring on wlan0 (Spy mode)
  3. sudo grudarin -s example.com         Scan a site and track visitors
  4. sudo grudarin --scan eth0 -o ~/notes Start monitoring, save detailed notes

EXAMPLES:
  sudo grudarin --scan wlan0 --name my_home_scan
  sudo grudarin --scan wlan0 Pixel
  sudo grudarin --scan wlan0 --ssid Pixel --view dashboard
  sudo grudarin --scan wlan0 --view graph
  grudarin -s example.com
  sudo grudarin --scan eth0 -o /tmp/reports --ports 1-65535
  sudo grudarin --scan wlan0 --no-graph --duration 120
  sudo grudarin --scan eth0 --targets 192.168.1.1,192.168.1.100
  sudo grudarin --list

UI MODES:
    dashboard       Default live activity and packet dashboard
    graph           Network Activity Map for structure visualization
    Ctrl+C / Close  Stop capture and print report output path
"""
    )
    parser.add_argument(
        "--scan", metavar="INTERFACE",
        type=str, default=None,
        help="Start scan on this interface (e.g., wlan0, eth0, en0)"
    )
    parser.add_argument(
        "--ssid", type=str, default=None,
        help="Optional WiFi/hotspot SSID label for capture context"
    )
    parser.add_argument(
        "--scan-site", "--site", "-site", "-s", metavar="DOMAIN",
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
        help="Run headless without the live UI window"
    )
    parser.add_argument(
        "--view", type=str, default="dashboard",
        choices=["dashboard", "graph"],
        help="Live UI mode (default: dashboard)"
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
        "--monitor", action="store_true",
        help="Attempt to put interface in monitor mode (Linux only)"
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
    parser.add_argument(
        "--update", action="store_true",
        help="Update Grudarin to latest version (git repo or pipx install)"
    )
    parser.add_argument(
        "--update-repo", type=str, default="https://github.com/Chintanpatel24/grudarin.git",
        help="GitHub repo URL used for pipx update/install"
    )
    return parser.parse_args(argv)


def print_banner():
    """Print the Grudarin banner."""
    print("""
    ================================================================
                          G R U D A R I N
           Network Monitor (Spy) + Vulnerability Scanner
                           v%s
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


def _set_monitor_mode(iface, enabled=True):
    """Enable or disable monitor mode on Linux."""
    if sys.platform != "linux":
        return False
    try:
        # Check if interface exists
        subprocess.check_call(["ip", "link", "show", iface], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        mode = "monitor" if enabled else "managed"
        print(f"  [monitor] Setting {iface} to {mode} mode...")

        subprocess.check_call(["ip", "link", "set", iface, "down"])
        subprocess.check_call(["iw", "dev", iface, "set", "type", mode])
        subprocess.check_call(["ip", "link", "set", iface, "up"])
        return True
    except Exception as e:
        print(f"  [error] Failed to set monitor mode: {e}")
        return False


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
    if args.ssid:
        print(f"  Target SSID : {args.ssid}")
    print(f"  Output      : {session_dir}")
    print(f"  Scan Name   : {scan_name}")
    print(f"  Duration    : {'Unlimited' if args.duration == 0 else str(args.duration) + 's'}")
    print(f"  Port Range  : {args.ports}")
    print(f"  Live UI     : {'Disabled' if args.no_graph else args.view}")
    if not args.no_graph:
        print(f"  Map Mode    : {'Network Activity Map' if args.view == 'graph' else 'Available via --view graph'}")
    print(f"  Vuln Scan   : {'Disabled' if args.no_scan else 'Enabled'}")
    print(f"  C++ Scanner : {'Ready' if tools.get('cpp_scanner') else 'Python fallback'}")
    print(f"  Go Netprobe : {'Ready' if tools.get('go_netprobe') else 'Python fallback'}")
    print(f"  Lua Rules   : {'Ready' if tools.get('lua') else 'Python fallback'}")
    print("  Notice      : Ethical and educational use only on authorized networks")
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
    print("  [live] Packets and network activity are being observed in real time")
    print("  [live] Authorized monitoring only. HTTPS content stays encrypted; hostnames may appear via DNS/TLS SNI.")
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

    def activity_printer():
        last_index = 0
        while not stop_event.is_set():
            events, last_index = network_model.get_activity_since(last_index)
            for ev in events:
                target = ev.get("target", "-")
                source_ip = ev.get("source_ip", "-")
                event_type = ev.get("event_type", "activity")
                details = ev.get("details", "")
                message = f"\n  [activity] {source_ip} -> {target} [{event_type}]"
                if details:
                    message += f" {details}"
                print(message[:220])
            time.sleep(0.4)

    activity_thread = threading.Thread(target=activity_printer, daemon=True)
    activity_thread.start()

    # Dashboard, graph, or headless
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

        if args.view == "graph":
            graph_window = GraphWindow(
                network_model=network_model,
                stop_event=stop_event,
                notes_writer=notes_writer,
                session_dir=session_dir,
                scan_callback=scan_node_callback,
            )
            graph_window.run()
        else:
            dashboard = DashboardWindow(
                network_model=network_model,
                stop_event=stop_event,
                interface_name=iface,
                target_ssid=args.ssid or "",
            )
            dashboard.run()
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

    # Also start a packet capture to track local visitors to this site
    local_net_model = NetworkModel()
    stop_event = threading.Event()

    # Try to find a default interface for capture
    from scapy.all import conf
    default_iface = conf.iface
    capture = None
    if default_iface:
        from grudarin.notes import NotesWriter as DummyNotesWriter
        capture = PacketCapture(
            interface=str(default_iface),
            network_model=local_net_model,
            notes_writer=DummyNotesWriter(tempfile.gettempdir()),
            stop_event=stop_event
        )
        threading.Thread(target=capture.start, daemon=True).start()

    notes_writer = NotesWriter(session_dir)
    scanner = SiteScanner(model=model, domain=domain, stop_event=stop_event, network_model=local_net_model)

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


def _run_update(args):
    """Update Grudarin using best available method."""
    print_banner()
    print("  [update] Preparing upgrade plan...")
    print(f"  [update] Current version: {__version__}")

    # Method 1: local repo updater script
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    update_script = os.path.join(base, "update.sh")
    if os.path.isfile(update_script):
        print("  [update] Found local repository update script.")
        print(f"  [update] Running: {update_script}")
        try:
            result = subprocess.run(
                ["bash", update_script],
                check=False,
                text=True,
                capture_output=True,
            )
            _print_subprocess_output("[update]", result)
            if result.returncode == 0:
                print("  [ok] Update completed using local update.sh")
                return
            print("  [warn] Local update.sh failed, trying pipx fallback...")
        except Exception as e:
            print(f"  [warn] Local update script error: {e}")

    # Method 2: pipx upgrade if available
    try:
        chk = subprocess.run(["pipx", "--version"], capture_output=True, text=True, timeout=8)
        if chk.returncode == 0:
            print("  [update] Using pipx to upgrade Grudarin...")
            cmd = ["pipx", "upgrade", "--include-injected", "grudarin"]
            res = subprocess.run(cmd, check=False, text=True, capture_output=True)
            _print_subprocess_output("[pipx]", res)
            if res.returncode == 0:
                print("  [ok] pipx upgrade complete.")
                return

            print("  [update] pipx upgrade did not complete. Reinstalling from repo...")
            reinstall = [
                "pipx", "install", "--force", f"git+{args.update_repo}"
            ]
            res2 = subprocess.run(reinstall, check=False, text=True, capture_output=True)
            _print_subprocess_output("[pipx]", res2)
            if res2.returncode == 0:
                print("  [ok] pipx reinstall from GitHub complete.")
                return
    except Exception:
        pass

    # Method 3: pip user install fallback
    print("  [update] Falling back to pip user install from GitHub...")
    pip_cmds = [
        [sys.executable, "-m", "pip", "install", "--upgrade", f"git+{args.update_repo}"],
        [sys.executable, "-m", "pip", "install", "--user", "--upgrade", f"git+{args.update_repo}"],
    ]
    for cmd in pip_cmds:
        try:
            res = subprocess.run(cmd, check=False, text=True, capture_output=True)
            _print_subprocess_output("[pip]", res)
            if res.returncode == 0:
                print("  [ok] pip update complete.")
                return
        except Exception:
            continue

    print("  [error] Update failed with all available methods.")
    print("  Try manually:")
    print(f"    pipx install --force \"git+{args.update_repo}\"")
    sys.exit(1)


def main():
    """Main entry point."""
    # Wayland support: Tkinter (via Tcl/Tk) often fails on Wayland unless forced to X11.
    if os.environ.get("XDG_SESSION_TYPE") == "wayland":
        if "GDK_BACKEND" not in os.environ:
            os.environ["GDK_BACKEND"] = "x11"
        if "QT_QPA_PLATFORM" not in os.environ:
            os.environ["QT_QPA_PLATFORM"] = "xcb"

    args = parse_args()

    if args.list:
        print_banner()
        if not check_privileges():
            print("  [warn] Run with sudo for full interface/WiFi info")
        list_interfaces()
        sys.exit(0)

    if args.update:
        _run_update(args)
        sys.exit(0)

    if args.scan:
        print_banner()
        requested_scan = args.scan

        if args.monitor:
            if sys.platform == "linux":
                if not check_privileges():
                    print("  [!] Root privileges required for monitor mode.")
                    sys.exit(1)
                _set_monitor_mode(requested_scan, True)
            else:
                print("  [warn] Monitor mode only supported on Linux via 'iw'.")

        resolved_iface = _resolve_scan_interface(requested_scan)
        if not resolved_iface:
            suggested_iface = _suggest_interface(requested_scan)
            print(f"  [error] Interface not found: {requested_scan}")
            if suggested_iface:
                print(f"  [hint] Did you mean: {suggested_iface}")
            print("  [hint] Use a real interface name (e.g., wlan0/eth0/en0), not SSID.")
            if args.name and not args.ssid:
                print(f"  [hint] '--name {args.name}' sets the session name only.")
                print(f"  [hint] For WiFi label use: --ssid {args.name}")
            print("  [hint] Run: sudo grudarin --list")
            sys.exit(1)
        if not _validate_interface_exists(resolved_iface):
            print(f"  [error] Interface is not available right now: {resolved_iface}")
            print("  [hint] Check adapter state and run: sudo grudarin --list")
            sys.exit(1)
        if resolved_iface != requested_scan:
            print(f"  [info] Resolved '{requested_scan}' to interface '{resolved_iface}'")
        if args.ssid:
            print("  [legal] For authorized monitoring and security testing only.")
        elif args.name:
            known_ssids = {str(net.get('ssid', '')) for net in discover_wifi_networks()}
            if args.name in known_ssids:
                print(f"  [hint] '{args.name}' looks like a WiFi name.")
                print(f"  [hint] If intended, use: --ssid {args.name}")

        if not check_privileges():
            print("  [!] ERROR: Root privileges required for network monitoring.")
            print("  [!] Grudarin needs raw socket access to capture packets.")
            print(f"  [!] Please run: sudo grudarin --scan {resolved_iface}")
            print()
            sys.exit(1)

        output_dir = _resolve_output_base_dir(args.output)
        scan_name = args.name or "session"
        run_scan(resolved_iface, output_dir, scan_name, args)
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

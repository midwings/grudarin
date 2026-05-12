"""
Grudarin - Vulnerability Analyzer
Integrates the C++ port scanner and Lua security rules engine.
Falls back to pure Python implementations if external tools are unavailable.
"""

import json
import os
import socket
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


class Finding:
    """A single security finding."""

    SEVERITY_ORDER = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    def __init__(self, severity, title, description, affected="", recommendation=""):
        self.severity = severity
        self.title = title
        self.description = description
        self.affected = affected
        self.recommendation = recommendation
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "affected": self.affected,
            "recommendation": self.recommendation,
            "timestamp": self.timestamp,
        }

    def __repr__(self):
        return f"[{self.severity.upper()}] {self.title}"


class VulnAnalyzer:
    """
    Runs vulnerability analysis against the discovered network.
    Uses C++ scanner for fast port scanning and Lua for rule evaluation.
    Falls back to Python if those are unavailable.
    """

    # Dangerous ports with risk info (Python fallback)
    DANGEROUS_PORTS = {
        21: ("FTP", "critical", "Cleartext protocol. Credentials exposed."),
        23: ("Telnet", "critical", "Cleartext remote shell. Extremely dangerous."),
        25: ("SMTP", "medium", "Open mail relay possible."),
        69: ("TFTP", "high", "No authentication at all."),
        111: ("RPCbind", "medium", "RPC portmapper. Information disclosure."),
        135: ("MSRPC", "high", "Microsoft RPC. Frequently exploited."),
        137: ("NetBIOS-NS", "medium", "NetBIOS. Information leakage."),
        139: ("NetBIOS-SSN", "high", "SMB over NetBIOS. Attack surface."),
        161: ("SNMP", "high", "Default community strings often unchanged."),
        445: ("SMB", "critical", "EternalBlue, WannaCry attack vector."),
        512: ("rexec", "critical", "No encryption. Remote execution."),
        513: ("rlogin", "critical", "No encryption. Remote login."),
        514: ("rsh", "critical", "No encryption. No authentication."),
        1433: ("MSSQL", "high", "Database exposed to network."),
        1521: ("Oracle", "high", "Database listener exposed."),
        2049: ("NFS", "high", "Network filesystem. Check exports."),
        3306: ("MySQL", "high", "Database exposed to network."),
        3389: ("RDP", "high", "Brute force target. BlueKeep risk."),
        4444: ("Metasploit", "critical", "Default Metasploit port. Possible backdoor."),
        5432: ("PostgreSQL", "medium", "Database exposed."),
        5555: ("ADB", "critical", "Android Debug Bridge. Full device access."),
        5900: ("VNC", "high", "Often weak or no authentication."),
        6379: ("Redis", "critical", "Usually no auth. RCE risk."),
        6667: ("IRC", "medium", "Sometimes used as C2 channel."),
        9200: ("Elasticsearch", "critical", "Often unauthenticated API."),
        11211: ("Memcached", "critical", "No auth. DDoS amplification."),
        27017: ("MongoDB", "critical", "Often no authentication."),
    }

    # Banner vulnerability signatures (Python fallback)
    VULN_SIGNATURES = [
        ("SSH-1.", "SSHv1 Protocol", "critical",
         "SSHv1 is broken. Upgrade to SSHv2 immediately."),
        ("OpenSSH_4", "Outdated OpenSSH 4.x", "high",
         "OpenSSH 4.x has multiple known CVEs."),
        ("OpenSSH_5", "Outdated OpenSSH 5.x", "high",
         "OpenSSH 5.x has known vulnerabilities."),
        ("vsFTPd 2.3.4", "vsFTPd 2.3.4 Backdoor", "critical",
         "vsFTPd 2.3.4 contains a known backdoor."),
        ("ProFTPD 1.3.3", "ProFTPD 1.3.3 Backdoor", "critical",
         "ProFTPD 1.3.3 backdoor vulnerability."),
        ("Apache/2.2", "Outdated Apache 2.2", "high",
         "Apache 2.2 is EOL. Multiple known CVEs."),
        ("Apache/2.0", "Outdated Apache 2.0", "critical",
         "Apache 2.0 is ancient. Dozens of known CVEs."),
        ("nginx/0.", "Ancient nginx", "critical",
         "Extremely outdated nginx version."),
        ("nginx/1.0", "Outdated nginx 1.0", "high",
         "nginx 1.0 has known vulnerabilities."),
        ("Microsoft-IIS/5", "IIS 5.x", "critical",
         "IIS 5.x has critical remote code execution vulns."),
        ("Microsoft-IIS/6", "IIS 6.x", "critical",
         "IIS 6.x has known RCE (CVE-2017-7269)."),
        ("PHP/5.2", "Outdated PHP 5.2", "critical",
         "PHP 5.2 is dangerously outdated."),
        ("PHP/5.3", "Outdated PHP 5.3", "critical",
         "PHP 5.3 is EOL with known RCEs."),
        ("PHP/5.6", "Outdated PHP 5.6", "medium",
         "PHP 5.6 is EOL. Upgrade to PHP 8.x."),
    ]

    def __init__(self, network_model, session_dir):
        self.model = network_model
        self.session_dir = session_dir
        self.findings = []
        self._lock = threading.Lock()

        # Find tool paths
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.scanner_path = os.path.join(base_dir, "bin", "grudarin_scanner")
        self.lua_rules_path = os.path.join(base_dir, "lua_rules", "security_rules.lua")

        # Check what tools are available
        self.has_cpp_scanner = os.path.isfile(self.scanner_path) and os.access(
            self.scanner_path, os.X_OK
        )
        self.has_lua = self._check_lua()

    def _check_lua(self):
        """Check if Lua is available."""
        for lua_cmd in ["lua5.4", "lua5.3", "lua"]:
            try:
                result = subprocess.run(
                    [lua_cmd, "-v"],
                    capture_output=True, timeout=5
                )
                if result.returncode == 0:
                    self._lua_cmd = lua_cmd
                    return True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
        return False

    def _add_finding(self, severity, title, description, affected="", recommendation=""):
        """Thread-safe finding addition."""
        with self._lock:
            self.findings.append(
                Finding(severity, title, description, affected, recommendation)
            )

    # ----------------------------------------------------------------
    # C++ Scanner Integration
    # ----------------------------------------------------------------

    def run_cpp_scanner(self, target_ip, port_range="1-1024", threads=50, timeout=500):
        """Run the C++ port scanner on a target."""
        if not self.has_cpp_scanner:
            return None

        try:
            result = subprocess.run(
                [self.scanner_path, target_ip, port_range, str(threads), str(timeout)],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            print(f"  Scanner error: {e}")
        return None

    # ----------------------------------------------------------------
    # Python Port Scanner Fallback
    # ----------------------------------------------------------------

    def _scan_port_python(self, ip, port, timeout=0.5):
        """Scan a single port using Python socket."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                # Try banner grab
                banner = ""
                try:
                    sock.settimeout(1.0)
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode("utf-8", errors="ignore").strip()
                        banner = banner[:256]
                except Exception:
                    pass
                sock.close()
                return {"port": port, "open": True, "banner": banner}
            sock.close()
        except Exception:
            pass
        return {"port": port, "open": False, "banner": ""}

    def run_python_scanner(self, ip, port_start=1, port_end=1024, threads=50, timeout=0.5):
        """Port scan using Python (fallback)."""
        open_ports = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for port in range(port_start, port_end + 1):
                f = executor.submit(self._scan_port_python, ip, port, timeout)
                futures[f] = port

            for future in as_completed(futures):
                try:
                    result = future.result(timeout=timeout + 1)
                    if result and result["open"]:
                        open_ports.append(result)
                except Exception:
                    pass

        return sorted(open_ports, key=lambda x: x["port"])

    # ----------------------------------------------------------------
    # Lua Rules Integration
    # ----------------------------------------------------------------

    def run_lua_rules(self, data):
        """Execute Lua security rules against the network data."""
        if not self.has_lua or not os.path.isfile(self.lua_rules_path):
            return None

        # Write data as Lua-compatible JSON for the rules engine
        data_json = json.dumps(data, default=str)
        lua_wrapper = self._generate_lua_wrapper(data_json)

        wrapper_path = os.path.join(self.session_dir, "_temp_rules_input.lua")
        try:
            with open(wrapper_path, "w", encoding="utf-8") as f:
                f.write(lua_wrapper)

            result = subprocess.run(
                [self._lua_cmd, wrapper_path],
                capture_output=True,
                text=True,
                timeout=60,
            )

            # Clean up temp file
            os.remove(wrapper_path)

            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
            if result.returncode != 0:
                err_out = (result.stderr or "").strip()
                if err_out and os.environ.get("GRUDARIN_DEBUG") == "1":
                    print(f"  Lua rules stderr: {err_out[:400]}")
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            if os.environ.get("GRUDARIN_DEBUG") == "1":
                print(f"  Lua rules error: {e}")
            try:
                os.remove(wrapper_path)
            except Exception:
                pass

        return None

    def _generate_lua_wrapper(self, data_json):
        """Generate a Lua script that loads rules and processes data."""
        rules_path = self.lua_rules_path.replace("\\", "/")

        # Escape JSON for safe embedding in a Lua quoted string.
        escaped = data_json.replace("\\", "\\\\").replace('"', '\\"')
        escaped = escaped.replace("\n", "\\n").replace("\r", "\\r")

        wrapper = """
-- Auto-generated wrapper for Grudarin rules execution
-- Minimal JSON parser for Lua (handles the data we need)

local function parse_json(s)
    -- Use Lua's load() with safe environment for simple JSON
    -- Replace JSON true/false/null with Lua equivalents
    s = s:gsub('"([^"]-)"%s*:', '["%1"]=')
    s = s:gsub('%[%s*%{', '{{')
    s = s:gsub('%}%s*%]', '}}')
    s = s:gsub('%[%s*%]', '{{}}')
    s = s:gsub(': *true', '=true')
    s = s:gsub(': *false', '=false')
    s = s:gsub(': *null', '=nil')
    -- Wrap in return statement
    local fn, err = load("return " .. s, "json", "t", {})
    if fn then
        local ok, result = pcall(fn)
        if ok then return result end
    end
    return nil
end

-- Alternative: build data table directly from known structure
local function build_data()
    local json_str = "__GRUDARIN_JSON__"
    local data = parse_json(json_str)
    if not data then
        -- Fallback: return empty structure
        data = {
            protocol_counts = {},
            total_packets = 0,
            devices = {},
            scan_results = {},
        }
    end
    return data
end

-- Load the rules
dofile("__GRUDARIN_RULES_PATH__")

-- Execute
local data = build_data()
local results = run_all_rules(data)

-- Output as JSON
local function to_json_string(s)
    return '"' .. s:gsub('\\', '\\\\'):gsub('"', '\\"'):gsub('\\n', '\\n'):gsub('\\r', '\\r') .. '"'
end

io.write("[\\n")
for i, f in ipairs(results) do
    io.write("  {\\n")
    io.write('    "severity": ' .. to_json_string(f.severity or "info") .. ',\\n')
    io.write('    "title": ' .. to_json_string(f.title or "") .. ',\\n')
    io.write('    "description": ' .. to_json_string(f.description or "") .. ',\\n')
    io.write('    "affected": ' .. to_json_string(f.affected or "") .. ',\\n')
    io.write('    "recommendation": ' .. to_json_string(f.recommendation or "") .. '\\n')
    if i < #results then
        io.write("  },\\n")
    else
        io.write("  }\\n")
    end
end
io.write("]\\n")
"""

        wrapper = wrapper.replace("__GRUDARIN_JSON__", escaped)
        wrapper = wrapper.replace("__GRUDARIN_RULES_PATH__", rules_path)
        return wrapper

    # ----------------------------------------------------------------
    # Python Rules Fallback
    # ----------------------------------------------------------------

    def run_python_rules(self, data):
        """Pure Python security rules (fallback when Lua unavailable)."""
        findings = []

        # Insecure protocols
        insecure_protos = {
            "Telnet": ("critical", "Telnet transmits everything in cleartext.",
                       "Replace Telnet with SSH."),
            "FTP": ("high", "FTP transmits credentials in cleartext.",
                    "Replace FTP with SFTP or FTPS."),
            "HTTP": ("medium", "HTTP traffic is unencrypted.",
                     "Migrate to HTTPS with valid TLS certificates."),
            "SNMP": ("high", "SNMP often uses default community strings.",
                     "Use SNMPv3 with authentication and encryption."),
            "RDP": ("high", "RDP exposed. Brute-force and BlueKeep risk.",
                    "Enable NLA. Use VPN. Restrict by IP."),
            "SMB": ("high", "SMB exposed. EternalBlue/WannaCry surface.",
                    "Disable SMBv1. Restrict to trusted subnets."),
        }

        proto_counts = data.get("protocol_counts", {})
        for proto, (sev, desc, rec) in insecure_protos.items():
            count = proto_counts.get(proto, 0)
            if count > 0:
                findings.append({
                    "severity": sev,
                    "title": f"Insecure Protocol: {proto}",
                    "description": f"{desc} (Detected {count} packets)",
                    "affected": "Network-wide",
                    "recommendation": rec,
                })

        # Dangerous ports on devices
        devices = data.get("devices", {})
        for key, dev in devices.items():
            ports = dev.get("open_ports", [])
            for port in ports:
                if port in self.DANGEROUS_PORTS:
                    name, sev, risk = self.DANGEROUS_PORTS[port]
                    findings.append({
                        "severity": sev,
                        "title": f"Dangerous Port Open: {port} ({name})",
                        "description": f"{name} on port {port} on {dev.get('ip', key)}. {risk}",
                        "affected": dev.get("ip", key),
                        "recommendation": f"Close port {port} or restrict access.",
                    })

            # Excessive ports
            if len(ports) > 20:
                findings.append({
                    "severity": "high",
                    "title": f"Excessive Open Ports: {len(ports)} ports",
                    "description": f"Device {dev.get('ip', key)} has {len(ports)} open ports.",
                    "affected": dev.get("ip", key),
                    "recommendation": "Close unnecessary ports.",
                })

        # ARP spoofing detection
        ip_to_macs = {}
        for key, dev in devices.items():
            for ip in dev.get("all_ips", []):
                mac = dev.get("mac", "")
                if mac and mac != "unknown" and mac != "ff:ff:ff:ff:ff:ff":
                    ip_to_macs.setdefault(ip, set()).add(mac)

        for ip, macs in ip_to_macs.items():
            if len(macs) > 1:
                findings.append({
                    "severity": "critical",
                    "title": "Possible ARP Spoofing Detected",
                    "description": f"IP {ip} mapped to {len(macs)} MACs: {', '.join(macs)}",
                    "affected": ip,
                    "recommendation": "Investigate. Use static ARP for critical devices.",
                })

        # Multiple gateways
        gateways = [k for k, v in devices.items() if v.get("is_gateway")]
        if len(gateways) > 1:
            findings.append({
                "severity": "high",
                "title": f"Multiple Gateways Detected ({len(gateways)})",
                "description": "Multiple gateway devices may cause routing conflicts.",
                "affected": "Network-wide",
                "recommendation": "Verify only one default gateway per subnet.",
            })

        # Broadcast storm
        total = data.get("total_packets", 0)
        if total > 100:
            broadcast_pkts = sum(
                v.get("packets_received", 0)
                for v in devices.values()
                if v.get("is_broadcast")
            )
            ratio = broadcast_pkts / total if total > 0 else 0
            if ratio > 0.5:
                findings.append({
                    "severity": "high",
                    "title": "Excessive Broadcast Traffic",
                    "description": f"Broadcast is {int(ratio * 100)}% of traffic.",
                    "affected": "Network-wide",
                    "recommendation": "Check for switching loops. Verify STP.",
                })

        # DNS anomalies
        dns_count = proto_counts.get("DNS", 0)
        if total > 100 and dns_count > total * 0.4:
            findings.append({
                "severity": "high",
                "title": "Excessive DNS Traffic",
                "description": f"DNS is {int(dns_count / total * 100)}% of traffic. Possible tunneling.",
                "affected": "Network-wide",
                "recommendation": "Analyze DNS queries for suspicious domains.",
            })

        # DHCP issues
        dhcp_count = proto_counts.get("DHCP", 0)
        if dhcp_count > 100:
            findings.append({
                "severity": "high",
                "title": "Excessive DHCP Traffic",
                "description": f"{dhcp_count} DHCP packets. Possible rogue DHCP or exhaustion.",
                "affected": "Network-wide",
                "recommendation": "Enable DHCP snooping on switches.",
            })

        # HTTP vs HTTPS ratio
        http = proto_counts.get("HTTP", 0)
        https = proto_counts.get("HTTPS", 0)
        if http > 0 and https == 0:
            findings.append({
                "severity": "high",
                "title": "No HTTPS Traffic Detected",
                "description": f"All {http} web packets are unencrypted HTTP.",
                "affected": "Network-wide",
                "recommendation": "Deploy HTTPS on all web services.",
            })

        # Unknown devices
        unknown = sum(
            1 for v in devices.values()
            if not v.get("vendor") and not v.get("hostname") and not v.get("is_broadcast")
        )
        if unknown > 3:
            findings.append({
                "severity": "medium",
                "title": f"Multiple Unknown Devices ({unknown})",
                "description": f"{unknown} unidentified devices on the network.",
                "affected": "Network-wide",
                "recommendation": "Implement 802.1X. Use MAC filtering.",
            })

        # Scan results vulnerabilities
        for host in data.get("scan_results", []):
            if host.get("alive"):
                for p in host.get("open_ports", []):
                    if p.get("vulnerability"):
                        findings.append({
                            "severity": p.get("severity", "medium"),
                            "title": f"Vulnerability: {p.get('service', '?')} (port {p.get('port', '?')})",
                            "description": p.get("vulnerability", ""),
                            "affected": host.get("ip", "unknown"),
                            "recommendation": "Patch or upgrade. Restrict access.",
                        })

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: sev_order.get(f["severity"], 99))

        return findings

    # ----------------------------------------------------------------
    # Main Analysis Pipeline
    # ----------------------------------------------------------------

    def analyze(self, scan_targets=None, port_range="1-1024"):
        """
        Run the full vulnerability analysis.
        1. Port scan discovered devices (C++ or Python)
        2. Run security rules (Lua or Python)
        3. Collect all findings
        """
        self.findings = []
        data = self.model.get_full_data()

        # Flatten data for rules
        rules_data = {
            "protocol_counts": data["session"].get("protocol_distribution", {}),
            "total_packets": data["session"].get("total_packets", 0),
            "devices": data.get("devices", {}),
            "scan_results": [],
        }

        # Step 1: Port scan if targets provided
        if scan_targets:
            print("  Running port scanner...")
            for target in scan_targets:
                scan_result = None
                if self.has_cpp_scanner:
                    print(f"    C++ scanner -> {target}")
                    results = self.run_cpp_scanner(target, port_range)
                    if results:
                        rules_data["scan_results"].extend(results)
                        scan_result = results
                else:
                    print(f"    Python scanner -> {target}")
                    parts = port_range.split("-")
                    p_start = int(parts[0]) if len(parts) >= 1 else 1
                    p_end = int(parts[1]) if len(parts) >= 2 else 1024
                    open_ports = self.run_python_scanner(target, p_start, p_end)
                    if open_ports:
                        host_result = {
                            "ip": target,
                            "alive": True,
                            "open_ports": open_ports,
                        }
                        # Check for vulnerabilities on open ports
                        for p in open_ports:
                            port_num = p["port"]
                            p["service"] = self._get_service(port_num)
                            p["vulnerability"] = ""
                            p["severity"] = ""
                            # Check dangerous
                            if port_num in self.DANGEROUS_PORTS:
                                name, sev, risk = self.DANGEROUS_PORTS[port_num]
                                p["vulnerability"] = risk
                                p["severity"] = sev
                            # Check banner
                            if p.get("banner"):
                                for pattern, name, sev, desc in self.VULN_SIGNATURES:
                                    if pattern in p["banner"]:
                                        p["vulnerability"] = desc
                                        p["severity"] = sev
                                        break
                        rules_data["scan_results"].append(host_result)
        else:
            # Auto-scan discovered devices
            devices = data.get("devices", {})
            targets_to_scan = []
            for key, dev in devices.items():
                ip = dev.get("ip", "")
                if ip and ip != "unknown" and not ip.endswith(".255") and not ip.startswith("224."):
                    targets_to_scan.append(ip)

            if targets_to_scan:
                # Limit to first 20 devices to avoid excessive scanning
                targets_to_scan = targets_to_scan[:20]
                print(f"  Auto-scanning {len(targets_to_scan)} discovered devices...")
                for target in targets_to_scan:
                    if self.has_cpp_scanner:
                        results = self.run_cpp_scanner(target, port_range, threads=30, timeout=300)
                        if results:
                            rules_data["scan_results"].extend(results)
                    else:
                        parts = port_range.split("-")
                        p_start = int(parts[0]) if len(parts) >= 1 else 1
                        p_end = int(parts[1]) if len(parts) >= 2 else 1024
                        open_ports = self.run_python_scanner(target, p_start, p_end, threads=30, timeout=0.3)
                        if open_ports:
                            for p in open_ports:
                                pn = p["port"]
                                p["service"] = self._get_service(pn)
                                p["vulnerability"] = ""
                                p["severity"] = ""
                                if pn in self.DANGEROUS_PORTS:
                                    nm, sv, rk = self.DANGEROUS_PORTS[pn]
                                    p["vulnerability"] = rk
                                    p["severity"] = sv
                                if p.get("banner"):
                                    for pat, nm, sv, dsc in self.VULN_SIGNATURES:
                                        if pat in p["banner"]:
                                            p["vulnerability"] = dsc
                                            p["severity"] = sv
                                            break
                            rules_data["scan_results"].append({
                                "ip": target,
                                "alive": True,
                                "open_ports": open_ports,
                            })

        # Step 2: Run security rules
        print("  Running security rules...")
        lua_findings = None
        if self.has_lua and os.path.isfile(self.lua_rules_path):
            print("    Using Lua rules engine")
            lua_findings = self.run_lua_rules(rules_data)

        if lua_findings:
            for f in lua_findings:
                self._add_finding(
                    f.get("severity", "info"),
                    f.get("title", "Unknown"),
                    f.get("description", ""),
                    f.get("affected", ""),
                    f.get("recommendation", ""),
                )
        else:
            print("    Using Python rules (Lua unavailable)")
            py_findings = self.run_python_rules(rules_data)
            for f in py_findings:
                self._add_finding(
                    f.get("severity", "info"),
                    f.get("title", "Unknown"),
                    f.get("description", ""),
                    f.get("affected", ""),
                    f.get("recommendation", ""),
                )

        # Sort all findings
        with self._lock:
            self.findings.sort(
                key=lambda f: Finding.SEVERITY_ORDER.get(f.severity, 99)
            )

        print(f"  Analysis complete: {len(self.findings)} findings")
        return self.findings

    def get_findings(self):
        """Get all findings sorted by severity."""
        with self._lock:
            return list(self.findings)

    def get_findings_dicts(self):
        """Get findings as list of dicts."""
        with self._lock:
            return [f.to_dict() for f in self.findings]

    @staticmethod
    def _get_service(port):
        """Get service name for a port."""
        services = {
            20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet",
            25: "smtp", 53: "dns", 80: "http", 110: "pop3",
            143: "imap", 443: "https", 445: "smb", 993: "imaps",
            995: "pop3s", 1433: "mssql", 3306: "mysql",
            3389: "rdp", 5432: "postgresql", 5900: "vnc",
            6379: "redis", 8080: "http-alt", 8443: "https-alt",
            27017: "mongodb",
        }
        return services.get(port, "unknown")

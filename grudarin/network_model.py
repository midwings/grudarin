"""
Grudarin - Network Model
Thread-safe data model representing the discovered network topology.
"""

import threading
import time
from collections import defaultdict
from datetime import datetime


class Device:
    """Represents a discovered network device."""

    def __init__(self, mac=None, ip=None):
        self.mac = mac or "unknown"
        self.ip = ip or "unknown"
        self.ips = set()
        if ip and ip != "unknown":
            self.ips.add(ip)
        self.hostname = ""
        self.vendor = ""
        self.os_hint = ""
        self.open_ports = set()
        self.protocols_seen = set()
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.packets_sent = 0
        self.packets_received = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.is_gateway = False
        self.is_broadcast = False
        self.ttl_values = set()
        self.services = set()

    def to_dict(self):
        """Serialize device to dictionary."""
        return {
            "mac": self.mac,
            "ip": self.ip,
            "all_ips": list(self.ips),
            "hostname": self.hostname,
            "vendor": self.vendor,
            "os_hint": self.os_hint,
            "open_ports": sorted(list(self.open_ports)),
            "protocols": sorted(list(self.protocols_seen)),
            "first_seen": datetime.fromtimestamp(self.first_seen).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "is_gateway": self.is_gateway,
            "ttl_values": sorted(list(self.ttl_values)),
            "services": sorted(list(self.services)),
        }

    def get_label(self):
        """Get the best label for this device."""
        if self.hostname:
            return self.hostname
        if self.ip and self.ip != "unknown":
            return self.ip
        return self.mac[:11] if self.mac else "?"


class Connection:
    """Represents a connection between two devices."""

    def __init__(self, src_key, dst_key):
        self.src_key = src_key
        self.dst_key = dst_key
        self.packet_count = 0
        self.byte_count = 0
        self.protocols = set()
        self.ports = set()
        self.first_seen = time.time()
        self.last_seen = time.time()

    def to_dict(self):
        """Serialize connection to dictionary."""
        return {
            "source": self.src_key,
            "destination": self.dst_key,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "protocols": sorted(list(self.protocols)),
            "ports": sorted(list(self.ports)),
            "first_seen": datetime.fromtimestamp(self.first_seen).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
        }


class PacketRecord:
    """Stores metadata about a captured packet."""

    def __init__(self):
        self.timestamp = 0.0
        self.src_mac = ""
        self.dst_mac = ""
        self.src_ip = ""
        self.dst_ip = ""
        self.protocol = ""
        self.src_port = 0
        self.dst_port = 0
        self.length = 0
        self.info = ""
        self.ttl = 0
        self.flags = ""
        self.activity = ""

    def to_dict(self):
        """Serialize packet record to dictionary."""
        return {
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "src_mac": self.src_mac,
            "dst_mac": self.dst_mac,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "length": self.length,
            "info": self.info,
            "ttl": self.ttl,
            "flags": self.flags,
            "activity": self.activity,
        }


class NetworkModel:
    """
    Thread-safe model of the network topology.
    All methods that mutate state acquire the lock.
    """

    # Common port-to-service mapping
    PORT_SERVICES = {
        20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client",
        80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
        161: "SNMP", 162: "SNMP-Trap", 443: "HTTPS", 445: "SMB",
        465: "SMTPS", 514: "Syslog", 587: "SMTP-Submission",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        8888: "HTTP-Alt2", 9090: "HTTP-Alt3", 27017: "MongoDB",
    }

    # MAC OUI prefix to vendor (small built-in list)
    OUI_VENDORS = {
        "00:50:56": "VMware",
        "00:0c:29": "VMware",
        "00:1a:11": "Google",
        "00:1e:65": "Intel",
        "3c:22:fb": "Apple",
        "ac:de:48": "Apple",
        "f8:ff:c2": "Apple",
        "a4:83:e7": "Apple",
        "00:25:00": "Apple",
        "d8:bb:c1": "Apple",
        "b8:27:eb": "Raspberry Pi",
        "dc:a6:32": "Raspberry Pi",
        "e4:5f:01": "Raspberry Pi",
        "00:15:5d": "Microsoft Hyper-V",
        "08:00:27": "VirtualBox",
        "52:54:00": "QEMU/KVM",
        "00:1a:2b": "Cisco",
        "00:1b:44": "Cisco",
        "00:24:d7": "Intel",
        "00:26:c6": "Intel",
        "3c:97:0e": "Intel",
        "4c:eb:42": "Intel",
        "d0:50:99": "ASRock",
        "00:e0:4c": "Realtek",
        "00:0a:cd": "Realtek",
        "48:5b:39": "ASUSTek",
        "1c:87:2c": "ASUSTek",
        "00:23:cd": "TP-Link",
        "30:b5:c2": "TP-Link",
        "50:c7:bf": "TP-Link",
        "c0:25:e9": "TP-Link",
        "00:1f:1f": "D-Link",
        "28:10:7b": "D-Link",
        "f0:9f:c2": "Ubiquiti",
        "24:a4:3c": "Ubiquiti",
        "68:d7:9a": "Ubiquiti",
        "44:d9:e7": "Ubiquiti",
        "00:18:0a": "Hewlett-Packard",
        "3c:d9:2b": "Hewlett-Packard",
        "9c:b6:d0": "Hewlett-Packard",
        "fc:15:b4": "Hewlett-Packard",
        "00:17:a4": "Samsung",
        "00:21:19": "Samsung",
        "a8:f2:74": "Samsung",
        "c0:97:27": "Samsung",
        "00:26:e8": "Dell",
        "18:a9:9b": "Dell",
        "b0:83:fe": "Dell",
        "f8:b1:56": "Dell",
        "00:21:5a": "Hewlett-Packard",
        "00:19:bb": "Hewlett-Packard",
    }

    # TTL-based OS hinting
    TTL_OS_HINTS = {
        64: "Linux/macOS/Unix",
        128: "Windows",
        255: "Cisco/Network Device",
        254: "Solaris/AIX",
    }

    def __init__(self):
        self.lock = threading.Lock()
        self.devices = {}           # key -> Device
        self.connections = {}       # (src_key, dst_key) -> Connection
        self.packet_log = []        # list of PacketRecord
        self.total_packets = 0
        self.total_bytes = 0
        self.start_time = time.time()
        self.protocol_counts = defaultdict(int)
        self.dns_cache = {}         # ip -> hostname
        self.changes_log = []       # list of change events
        self.activity_log = []      # list of high-level activity events
        self._max_packet_log = 50000  # cap to prevent memory issues
        self._max_activity_log = 2000

    def _device_key(self, mac, ip):
        """
        Generate a unique key for a device.
        Prefer MAC address; fall back to IP.
        """
        if mac and mac != "unknown" and mac != "ff:ff:ff:ff:ff:ff":
            return mac.lower()
        if ip and ip != "unknown":
            return ip
        return mac.lower() if mac else "unknown"

    def _lookup_vendor(self, mac):
        """Look up vendor from MAC OUI prefix."""
        if not mac or mac == "unknown":
            return ""
        prefix = mac[:8].lower()
        return self.OUI_VENDORS.get(prefix, "")

    def _lookup_service(self, port):
        """Look up service name from port number."""
        return self.PORT_SERVICES.get(port, "")

    def _guess_os(self, ttl):
        """Guess OS from TTL value."""
        if ttl <= 0:
            return ""
        # Find nearest standard TTL
        nearest = min(self.TTL_OS_HINTS.keys(), key=lambda x: abs(x - ttl))
        if abs(nearest - ttl) <= 10:
            return self.TTL_OS_HINTS[nearest]
        return ""

    def _is_broadcast(self, mac, ip):
        """Check if address is broadcast/multicast."""
        if mac == "ff:ff:ff:ff:ff:ff":
            return True
        if ip and (ip.endswith(".255") or ip.startswith("224.")
                   or ip.startswith("239.") or ip == "255.255.255.255"):
            return True
        return False

    def _is_likely_gateway(self, ip):
        """Heuristic: x.x.x.1 is often the gateway."""
        if ip and ip != "unknown":
            parts = ip.split(".")
            if len(parts) == 4 and parts[3] == "1":
                return True
        return False

    def add_packet(self, record):
        """
        Process a captured packet record and update the network model.
        Thread-safe.
        """
        with self.lock:
            self.total_packets += 1
            self.total_bytes += record.length
            self.protocol_counts[record.protocol] += 1

            # Log packet (with cap)
            if len(self.packet_log) < self._max_packet_log:
                self.packet_log.append(record)

            # Resolve source device
            src_key = self._device_key(record.src_mac, record.src_ip)
            if src_key not in self.devices:
                dev = Device(mac=record.src_mac, ip=record.src_ip)
                dev.vendor = self._lookup_vendor(record.src_mac)
                dev.is_broadcast = self._is_broadcast(
                    record.src_mac, record.src_ip
                )
                dev.is_gateway = self._is_likely_gateway(record.src_ip)
                self.devices[src_key] = dev
                self.changes_log.append({
                    "time": datetime.now().isoformat(),
                    "event": "device_discovered",
                    "device": src_key,
                    "ip": record.src_ip,
                    "mac": record.src_mac,
                })

            src_dev = self.devices[src_key]
            src_dev.last_seen = time.time()
            src_dev.packets_sent += 1
            src_dev.bytes_sent += record.length
            if record.src_ip and record.src_ip != "unknown":
                src_dev.ips.add(record.src_ip)
                if src_dev.ip == "unknown":
                    src_dev.ip = record.src_ip
            if record.protocol:
                src_dev.protocols_seen.add(record.protocol)
            if record.src_port:
                service = self._lookup_service(record.src_port)
                if service:
                    src_dev.services.add(service)
            if record.ttl > 0:
                src_dev.ttl_values.add(record.ttl)
                if not src_dev.os_hint:
                    src_dev.os_hint = self._guess_os(record.ttl)

            # Resolve destination device
            dst_key = self._device_key(record.dst_mac, record.dst_ip)
            if dst_key not in self.devices:
                dev = Device(mac=record.dst_mac, ip=record.dst_ip)
                dev.vendor = self._lookup_vendor(record.dst_mac)
                dev.is_broadcast = self._is_broadcast(
                    record.dst_mac, record.dst_ip
                )
                dev.is_gateway = self._is_likely_gateway(record.dst_ip)
                self.devices[dst_key] = dev
                self.changes_log.append({
                    "time": datetime.now().isoformat(),
                    "event": "device_discovered",
                    "device": dst_key,
                    "ip": record.dst_ip,
                    "mac": record.dst_mac,
                })

            dst_dev = self.devices[dst_key]
            dst_dev.last_seen = time.time()
            dst_dev.packets_received += 1
            dst_dev.bytes_received += record.length
            if record.dst_ip and record.dst_ip != "unknown":
                dst_dev.ips.add(record.dst_ip)
                if dst_dev.ip == "unknown":
                    dst_dev.ip = record.dst_ip
            if record.dst_port:
                dst_dev.open_ports.add(record.dst_port)
                service = self._lookup_service(record.dst_port)
                if service:
                    dst_dev.services.add(service)

            # DNS hostname resolution cache
            if record.src_ip in self.dns_cache and not src_dev.hostname:
                src_dev.hostname = self.dns_cache[record.src_ip]
            if record.dst_ip in self.dns_cache and not dst_dev.hostname:
                dst_dev.hostname = self.dns_cache[record.dst_ip]

            # Connection tracking
            if src_key != dst_key:
                # Normalize connection key (smaller key first for bidirectional)
                conn_key = (src_key, dst_key)
                if conn_key not in self.connections:
                    reverse_key = (dst_key, src_key)
                    if reverse_key in self.connections:
                        conn_key = reverse_key

                if conn_key not in self.connections:
                    conn = Connection(src_key, dst_key)
                    self.connections[conn_key] = conn
                    self.changes_log.append({
                        "time": datetime.now().isoformat(),
                        "event": "connection_established",
                        "source": src_key,
                        "destination": dst_key,
                        "protocol": record.protocol,
                    })

                conn = self.connections[conn_key]
                conn.packet_count += 1
                conn.byte_count += record.length
                conn.last_seen = time.time()
                if record.protocol:
                    conn.protocols.add(record.protocol)
                if record.src_port:
                    conn.ports.add(record.src_port)
                if record.dst_port:
                    conn.ports.add(record.dst_port)

    def add_dns_mapping(self, ip, hostname):
        """Add a DNS hostname mapping."""
        with self.lock:
            self.dns_cache[ip] = hostname
            # Update any existing device
            for dev in self.devices.values():
                if ip in dev.ips and not dev.hostname:
                    dev.hostname = hostname

    def add_activity(self, source_ip, target, event_type, details=""):
        """Record a high-level realtime activity (DNS/HTTP/etc)."""
        if not target:
            return
        with self.lock:
            self.activity_log.append({
                "time": datetime.now().isoformat(),
                "source_ip": source_ip or "unknown",
                "target": target,
                "event_type": event_type or "activity",
                "details": details or "",
            })
            if len(self.activity_log) > self._max_activity_log:
                self.activity_log = self.activity_log[-self._max_activity_log:]

    def get_activity_since(self, start_index=0):
        """Return activity entries added since a given index."""
        with self.lock:
            total = len(self.activity_log)
            if start_index < 0:
                start_index = 0
            if start_index > total:
                start_index = total
            return list(self.activity_log[start_index:]), total

    def get_recent_packets(self, limit=30):
        """Return the most recent packet records as serializable dicts."""
        with self.lock:
            tail = self.packet_log[-max(1, int(limit)):]
            return [pkt.to_dict() for pkt in tail]

    def get_snapshot(self):
        """
        Get a thread-safe snapshot of the current network state.
        Returns copies of devices and connections for rendering.
        """
        with self.lock:
            devices_snapshot = {}
            for key, dev in self.devices.items():
                devices_snapshot[key] = {
                    "key": key,
                    "label": dev.get_label(),
                    "ip": dev.ip,
                    "mac": dev.mac,
                    "vendor": dev.vendor,
                    "hostname": dev.hostname,
                    "os_hint": dev.os_hint,
                    "is_gateway": dev.is_gateway,
                    "is_broadcast": dev.is_broadcast,
                    "packets_sent": dev.packets_sent,
                    "packets_received": dev.packets_received,
                    "bytes_sent": dev.bytes_sent,
                    "bytes_received": dev.bytes_received,
                    "protocols": list(dev.protocols_seen),
                    "services": list(dev.services),
                    "open_ports": list(dev.open_ports)[:20],
                }

            connections_snapshot = []
            for (src, dst), conn in self.connections.items():
                connections_snapshot.append({
                    "src": src,
                    "dst": dst,
                    "packet_count": conn.packet_count,
                    "byte_count": conn.byte_count,
                    "protocols": list(conn.protocols),
                })

            return devices_snapshot, connections_snapshot

    def get_stats(self):
        """Get basic statistics."""
        with self.lock:
            return {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "total_devices": len(self.devices),
                "total_connections": len(self.connections),
                "uptime": time.time() - self.start_time,
                "protocol_counts": dict(self.protocol_counts),
                "recent_activity": list(self.activity_log[-20:]),
            }

    def get_full_data(self):
        """Get full serializable data for report generation."""
        with self.lock:
            return {
                "session": {
                    "start_time": datetime.fromtimestamp(
                        self.start_time
                    ).isoformat(),
                    "end_time": datetime.now().isoformat(),
                    "duration_seconds": round(
                        time.time() - self.start_time, 2
                    ),
                    "total_packets": self.total_packets,
                    "total_bytes": self.total_bytes,
                    "protocol_distribution": dict(self.protocol_counts),
                },
                "devices": {
                    k: v.to_dict() for k, v in self.devices.items()
                },
                "connections": [
                    c.to_dict() for c in self.connections.values()
                ],
                "dns_cache": dict(self.dns_cache),
                "changes_log": list(self.changes_log),
                "activity_log": list(self.activity_log),
            }

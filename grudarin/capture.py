"""
Grudarin - Packet Capture Engine
Uses Scapy for passive network traffic sniffing.
"""
"""
Grudarin - Packet Capture Engine
Uses Scapy for passive network traffic sniffing.
"""

import time

from grudarin.network_model import PacketRecord


class PacketCapture:
    """
    Captures packets on a network interface using Scapy.
    Parses each packet and feeds data into the NetworkModel.
    """

    def __init__(self, interface, network_model, notes_writer,
                 stop_event, promisc=True, bpf_filter=None):
        self.interface = interface
        self.model = network_model
        self.notes = notes_writer
        self.stop_event = stop_event
        self.promisc = promisc
        self.bpf_filter = bpf_filter
        self._packet_count = 0
        self._activity_cache = {}

    def _remember_activity(self, source_ip, target, event_type, details=""):
        """Deduplicate bursty activity so the live feed stays readable."""
        if not target:
            return
        now = time.time()
        key = (source_ip or "unknown", target, event_type)
        last_seen = self._activity_cache.get(key, 0.0)
        if now - last_seen < 2.5:
            return
        self._activity_cache[key] = now
        self.model.add_activity(source_ip, target, event_type, details)

    def _extract_http_activity(self, payload):
        """Extract HTTP host/path from plaintext requests."""
        try:
            text = payload[:2048].decode("utf-8", errors="ignore")
        except Exception:
            return "", "", ""

        first_line = text.splitlines()[0] if text else ""
        if not first_line.startswith(
            ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")
        ):
            return "", "", ""

        host = ""
        for line in text.splitlines()[:40]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        if not host:
            return "", "", ""

        path = first_line.split(" ")[1] if " " in first_line else "/"
        return host, path, first_line[:120]

    def _extract_tls_sni(self, payload):
        """Best-effort extraction of TLS SNI hostname from a ClientHello."""
        try:
            if len(payload) < 11 or payload[0] != 0x16:
                return ""
            if payload[5] != 0x01:
                return ""

            pos = 9
            if len(payload) < pos + 34:
                return ""

            pos += 2  # legacy_version
            pos += 32  # random

            session_id_len = payload[pos]
            pos += 1 + session_id_len
            if len(payload) < pos + 2:
                return ""

            cipher_len = int.from_bytes(payload[pos:pos + 2], "big")
            pos += 2 + cipher_len
            if len(payload) < pos + 1:
                return ""

            comp_len = payload[pos]
            pos += 1 + comp_len
            if len(payload) < pos + 2:
                return ""

            ext_len = int.from_bytes(payload[pos:pos + 2], "big")
            pos += 2
            end = min(len(payload), pos + ext_len)

            while pos + 4 <= end:
                ext_type = int.from_bytes(payload[pos:pos + 2], "big")
                ext_size = int.from_bytes(payload[pos + 2:pos + 4], "big")
                pos += 4
                ext_end = min(end, pos + ext_size)

                if ext_type == 0 and pos + 2 <= ext_end:
                    server_name_list_len = int.from_bytes(payload[pos:pos + 2], "big")
                    pos += 2
                    list_end = min(ext_end, pos + server_name_list_len)

                    while pos + 3 <= list_end:
                        name_type = payload[pos]
                        name_len = int.from_bytes(payload[pos + 1:pos + 3], "big")
                        pos += 3
                        if name_type == 0 and pos + name_len <= list_end:
                            host = payload[pos:pos + name_len].decode(
                                "utf-8", errors="ignore"
                            ).strip().rstrip(".")
                            if host:
                                return host
                            return ""
                        pos += name_len
                    return ""

                pos = ext_end
        except Exception:
            return ""
        return ""

    def _process_packet(self, pkt):
        """Process a single captured packet."""
        try:
            from scapy.all import (
                Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSRR,
                Raw, Dot11
            )
        except ImportError:
            return

        if self.stop_event.is_set():
            return

        record = PacketRecord()
        record.timestamp = time.time()

        # Layer 2 - Ethernet
        if pkt.haslayer(Ether):
            record.src_mac = pkt[Ether].src
            record.dst_mac = pkt[Ether].dst

        # 802.11 Wireless
        if pkt.haslayer(Dot11):
            try:
                record.src_mac = pkt[Dot11].addr2 or ""
                record.dst_mac = pkt[Dot11].addr1 or ""
            except Exception:
                pass

        # ARP
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            record.protocol = "ARP"
            record.src_ip = arp.psrc or ""
            record.dst_ip = arp.pdst or ""
            if not record.src_mac:
                record.src_mac = arp.hwsrc or ""
            if not record.dst_mac:
                record.dst_mac = arp.hwdst or ""
            if arp.op == 1:
                record.info = f"Who has {arp.pdst}? Tell {arp.psrc}"
            elif arp.op == 2:
                record.info = f"{arp.psrc} is at {arp.hwsrc}"
            record.length = len(pkt)
            self.model.add_packet(record)
            self._packet_count += 1
            return

        # Layer 3 - IP
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            record.src_ip = ip_layer.src
            record.dst_ip = ip_layer.dst
            record.ttl = ip_layer.ttl
            record.length = ip_layer.len or len(pkt)

            # Layer 4 - TCP
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                record.protocol = "TCP"
                record.src_port = tcp.sport
                record.dst_port = tcp.dport
                flags = []
                if tcp.flags.S:
                    flags.append("SYN")
                if tcp.flags.A:
                    flags.append("ACK")
                if tcp.flags.F:
                    flags.append("FIN")
                if tcp.flags.R:
                    flags.append("RST")
                if tcp.flags.P:
                    flags.append("PSH")
                record.flags = ",".join(flags)

                # Detect common protocols by port
                ports = {tcp.sport, tcp.dport}
                if 80 in ports or 8080 in ports:
                    record.protocol = "HTTP"
                elif 443 in ports or 8443 in ports:
                    record.protocol = "HTTPS"
                elif 22 in ports:
                    record.protocol = "SSH"
                elif 21 in ports:
                    record.protocol = "FTP"
                elif 25 in ports or 587 in ports:
                    record.protocol = "SMTP"
                elif 3389 in ports:
                    record.protocol = "RDP"
                elif 445 in ports:
                    record.protocol = "SMB"
                elif 23 in ports:
                    record.protocol = "Telnet"

                record.info = (
                    f"{record.src_ip}:{tcp.sport} -> "
                    f"{record.dst_ip}:{tcp.dport} [{record.flags}]"
                )
                if pkt.haslayer(Raw):
                    try:
                        raw_payload = bytes(pkt[Raw].load[:4096])
                        host, path, summary = self._extract_http_activity(raw_payload)
                        if host:
                            activity = f"http://{host}{path}"
                            record.activity = activity
                            self._remember_activity(
                                record.src_ip,
                                activity,
                                "http_request",
                                summary,
                            )
                        elif tcp.dport in (443, 8443):
                            tls_host = self._extract_tls_sni(raw_payload)
                            if tls_host:
                                record.activity = f"tls://{tls_host}"
                                self._remember_activity(
                                    record.src_ip,
                                    tls_host,
                                    "tls_sni",
                                    f"dst={record.dst_ip}:{tcp.dport}",
                                )
                    except Exception:
                        pass

            # Layer 4 - UDP
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                record.protocol = "UDP"
                record.src_port = udp.sport
                record.dst_port = udp.dport

                ports = {udp.sport, udp.dport}
                if 53 in ports:
                    record.protocol = "DNS"
                elif 67 in ports or 68 in ports:
                    record.protocol = "DHCP"
                elif 123 in ports:
                    record.protocol = "NTP"
                elif 161 in ports or 162 in ports:
                    record.protocol = "SNMP"
                elif 514 in ports:
                    record.protocol = "Syslog"
                elif 5353 in ports:
                    record.protocol = "mDNS"
                elif 1900 in ports:
                    record.protocol = "SSDP"

                record.info = (
                    f"{record.src_ip}:{udp.sport} -> "
                    f"{record.dst_ip}:{udp.dport}"
                )

            # ICMP
            elif pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                record.protocol = "ICMP"
                type_names = {
                    0: "Echo Reply", 3: "Dest Unreachable",
                    8: "Echo Request", 11: "Time Exceeded",
                }
                type_name = type_names.get(icmp.type, f"Type {icmp.type}")
                record.info = (
                    f"{record.src_ip} -> {record.dst_ip} {type_name}"
                )

            else:
                record.protocol = f"IP-Proto-{ip_layer.proto}"
                record.info = (
                    f"{record.src_ip} -> {record.dst_ip}"
                )

            # DNS resolution extraction
            if pkt.haslayer(DNS):
                try:
                    dns = pkt[DNS]
                    if getattr(dns, "qd", None):
                        qname = dns.qd.qname
                        if isinstance(qname, bytes):
                            qname = qname.decode("utf-8", errors="ignore")
                        qname = str(qname).rstrip(".")
                        if qname:
                            record.activity = f"dns://{qname}"
                            if int(getattr(dns, "qr", 0)) == 0:
                                self._remember_activity(
                                    record.src_ip,
                                    qname,
                                    "dns_query",
                                    f"dst={record.dst_ip}",
                                )
                except Exception:
                    pass
            if pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
                try:
                    dns = pkt[DNS]
                    for i in range(dns.ancount):
                        rr = dns.an[i]
                        if hasattr(rr, "rdata") and hasattr(rr, "rrname"):
                            rdata = rr.rdata
                            rrname = rr.rrname
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode("utf-8", errors="ignore")
                            if isinstance(rrname, bytes):
                                rrname = rrname.decode(
                                    "utf-8", errors="ignore"
                                )
                            if rrname.endswith("."):
                                rrname = rrname[:-1]
                            # Only map if rdata looks like an IP
                            parts = str(rdata).split(".")
                            if len(parts) == 4:
                                try:
                                    if all(0 <= int(p) <= 255 for p in parts):
                                        self.model.add_dns_mapping(
                                            str(rdata), rrname
                                        )
                                except ValueError:
                                    pass
                except Exception:
                    pass

        elif pkt.haslayer(IPv6):
            ipv6 = pkt[IPv6]
            record.src_ip = ipv6.src
            record.dst_ip = ipv6.dst
            record.protocol = "IPv6"
            record.length = len(pkt)
            record.info = f"{ipv6.src} -> {ipv6.dst}"

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                record.protocol = "TCPv6"
                record.src_port = tcp.sport
                record.dst_port = tcp.dport
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                record.protocol = "UDPv6"
                record.src_port = udp.sport
                record.dst_port = udp.dport

        else:
            # Unknown or non-IP packet
            record.protocol = "Other"
            record.length = len(pkt)
            record.info = pkt.summary()

        self.model.add_packet(record)
        self._packet_count += 1

    def _stop_filter(self, pkt):
        """Scapy stop filter - returns True to stop sniffing."""
        return self.stop_event.is_set()

    def start(self):
        """Start capturing packets. Blocks until stop_event is set."""
        try:
            from scapy.all import sniff
        except ImportError:
            print("  Error: scapy is required. Install: pip install scapy")
            self.stop_event.set()
            return

        # Suppress Scapy warnings
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

        while not self.stop_event.is_set():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    stop_filter=self._stop_filter,
                    store=False,
                    promisc=self.promisc,
                    filter=self.bpf_filter,
                )
                # If sniff returned naturally without stop signal, retry to keep capture alive.
                if not self.stop_event.is_set():
                    time.sleep(0.4)
            except PermissionError:
                print(
                    "\n  Error: Permission denied. "
                    "Run with sudo or as Administrator."
                )
                self.stop_event.set()
                return
            except OSError as e:
                print(f"\n  Error: Could not open interface: {e}")
                if self.stop_event.is_set():
                    return
                print("  [live] Capture retrying in 2s... Press Ctrl+C to stop.")
                time.sleep(2)
            except Exception as e:
                print(f"\n  Error during capture: {e}")
                if self.stop_event.is_set():
                    return
                print("  [live] Capture retrying in 2s... Press Ctrl+C to stop.")
                time.sleep(2)

import time
import threading

from grudarin.network_model import PacketRecord


class PacketCapture:
    """
    Captures packets on a network interface using Scapy.
    Parses each packet and feeds data into the NetworkModel.
    """

    def __init__(self, interface, network_model, notes_writer,
                 stop_event, promisc=True, bpf_filter=None):
        self.interface = interface
        self.model = network_model
        self.notes = notes_writer
        self.stop_event = stop_event
        self.promisc = promisc
        self.bpf_filter = bpf_filter
        self._packet_count = 0

    def _process_packet(self, pkt):
        """Process a single captured packet."""
        try:
            from scapy.all import (
                Ether, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, DNSRR,
                Raw, Dot11
            )
        except ImportError:
            return

        if self.stop_event.is_set():
            return

        record = PacketRecord()
        record.timestamp = time.time()

        # Layer 2 - Ethernet
        if pkt.haslayer(Ether):
            record.src_mac = pkt[Ether].src
            record.dst_mac = pkt[Ether].dst

        # 802.11 Wireless
        if pkt.haslayer(Dot11):
            try:
                record.src_mac = pkt[Dot11].addr2 or ""
                record.dst_mac = pkt[Dot11].addr1 or ""
            except Exception:
                pass

        # ARP
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            record.protocol = "ARP"
            record.src_ip = arp.psrc or ""
            record.dst_ip = arp.pdst or ""
            if not record.src_mac:
                record.src_mac = arp.hwsrc or ""
            if not record.dst_mac:
                record.dst_mac = arp.hwdst or ""
            if arp.op == 1:
                record.info = f"Who has {arp.pdst}? Tell {arp.psrc}"
            elif arp.op == 2:
                record.info = f"{arp.psrc} is at {arp.hwsrc}"
            record.length = len(pkt)
            self.model.add_packet(record)
            self._packet_count += 1
            return

        # Layer 3 - IP
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            record.src_ip = ip_layer.src
            record.dst_ip = ip_layer.dst
            record.ttl = ip_layer.ttl
            record.length = ip_layer.len or len(pkt)

            # Layer 4 - TCP
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                record.protocol = "TCP"
                record.src_port = tcp.sport
                record.dst_port = tcp.dport
                flags = []
                if tcp.flags.S:
                    flags.append("SYN")
                if tcp.flags.A:
                    flags.append("ACK")
                if tcp.flags.F:
                    flags.append("FIN")
                if tcp.flags.R:
                    flags.append("RST")
                if tcp.flags.P:
                    flags.append("PSH")
                record.flags = ",".join(flags)

                # Detect common protocols by port
                ports = {tcp.sport, tcp.dport}
                if 80 in ports or 8080 in ports:
                    record.protocol = "HTTP"
                elif 443 in ports or 8443 in ports:
                    record.protocol = "HTTPS"
                elif 22 in ports:
                    record.protocol = "SSH"
                elif 21 in ports:
                    record.protocol = "FTP"
                elif 25 in ports or 587 in ports:
                    record.protocol = "SMTP"
                elif 3389 in ports:
                    record.protocol = "RDP"
                elif 445 in ports:
                    record.protocol = "SMB"
                elif 23 in ports:
                    record.protocol = "Telnet"

                record.info = (
                    f"{record.src_ip}:{tcp.sport} -> "
                    f"{record.dst_ip}:{tcp.dport} [{record.flags}]"
                )
                if pkt.haslayer(Raw):
                    try:
                        payload = bytes(pkt[Raw].load[:2048]).decode("utf-8", errors="ignore")
                        first_line = payload.splitlines()[0] if payload else ""
                        if first_line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")):
                            host = ""
                            for ln in payload.splitlines()[:40]:
                                if ln.lower().startswith("host:"):
                                    host = ln.split(":", 1)[1].strip()
                                    break
                            if host:
                                path = first_line.split(" ")[1] if " " in first_line else "/"
                                activity = f"http://{host}{path}"
                                record.activity = activity
                                self.model.add_activity(
                                    record.src_ip,
                                    activity,
                                    "http_request",
                                    first_line[:120],
                                )
                    except Exception:
                        pass

            # Layer 4 - UDP
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                record.protocol = "UDP"
                record.src_port = udp.sport
                record.dst_port = udp.dport

                ports = {udp.sport, udp.dport}
                if 53 in ports:
                    record.protocol = "DNS"
                elif 67 in ports or 68 in ports:
                    record.protocol = "DHCP"
                elif 123 in ports:
                    record.protocol = "NTP"
                elif 161 in ports or 162 in ports:
                    record.protocol = "SNMP"
                elif 514 in ports:
                    record.protocol = "Syslog"
                elif 5353 in ports:
                    record.protocol = "mDNS"
                elif 1900 in ports:
                    record.protocol = "SSDP"

                record.info = (
                    f"{record.src_ip}:{udp.sport} -> "
                    f"{record.dst_ip}:{udp.dport}"
                )

            # ICMP
            elif pkt.haslayer(ICMP):
                icmp = pkt[ICMP]
                record.protocol = "ICMP"
                type_names = {
                    0: "Echo Reply", 3: "Dest Unreachable",
                    8: "Echo Request", 11: "Time Exceeded",
                }
                type_name = type_names.get(icmp.type, f"Type {icmp.type}")
                record.info = (
                    f"{record.src_ip} -> {record.dst_ip} {type_name}"
                )

            else:
                record.protocol = f"IP-Proto-{ip_layer.proto}"
                record.info = (
                    f"{record.src_ip} -> {record.dst_ip}"
                )

            # DNS resolution extraction
            if pkt.haslayer(DNS):
                try:
                    dns = pkt[DNS]
                    if getattr(dns, "qd", None):
                        qname = dns.qd.qname
                        if isinstance(qname, bytes):
                            qname = qname.decode("utf-8", errors="ignore")
                        qname = str(qname).rstrip(".")
                        if qname:
                            record.activity = f"dns://{qname}"
                            if int(getattr(dns, "qr", 0)) == 0:
                                self.model.add_activity(
                                    record.src_ip,
                                    qname,
                                    "dns_query",
                                    f"dst={record.dst_ip}",
                                )
                except Exception:
                    pass
            if pkt.haslayer(DNS) and pkt.haslayer(DNSRR):
                try:
                    dns = pkt[DNS]
                    for i in range(dns.ancount):
                        rr = dns.an[i]
                        if hasattr(rr, "rdata") and hasattr(rr, "rrname"):
                            rdata = rr.rdata
                            rrname = rr.rrname
                            if isinstance(rdata, bytes):
                                rdata = rdata.decode("utf-8", errors="ignore")
                            if isinstance(rrname, bytes):
                                rrname = rrname.decode(
                                    "utf-8", errors="ignore"
                                )
                            if rrname.endswith("."):
                                rrname = rrname[:-1]
                            # Only map if rdata looks like an IP
                            parts = str(rdata).split(".")
                            if len(parts) == 4:
                                try:
                                    if all(0 <= int(p) <= 255 for p in parts):
                                        self.model.add_dns_mapping(
                                            str(rdata), rrname
                                        )
                                except ValueError:
                                    pass
                except Exception:
                    pass

        elif pkt.haslayer(IPv6):
            ipv6 = pkt[IPv6]
            record.src_ip = ipv6.src
            record.dst_ip = ipv6.dst
            record.protocol = "IPv6"
            record.length = len(pkt)
            record.info = f"{ipv6.src} -> {ipv6.dst}"

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                record.protocol = "TCPv6"
                record.src_port = tcp.sport
                record.dst_port = tcp.dport
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                record.protocol = "UDPv6"
                record.src_port = udp.sport
                record.dst_port = udp.dport

        else:
            # Unknown or non-IP packet
            record.protocol = "Other"
            record.length = len(pkt)
            record.info = pkt.summary()

        self.model.add_packet(record)
        self._packet_count += 1

    def _stop_filter(self, pkt):
        """Scapy stop filter - returns True to stop sniffing."""
        return self.stop_event.is_set()

    def start(self):
        """Start capturing packets. Blocks until stop_event is set."""
        try:
            from scapy.all import sniff
        except ImportError:
            print("  Error: scapy is required. Install: pip install scapy")
            self.stop_event.set()
            return

        # Suppress Scapy warnings
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

        while not self.stop_event.is_set():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._process_packet,
                    stop_filter=self._stop_filter,
                    store=False,
                    promisc=self.promisc,
                    filter=self.bpf_filter,
                )
                # If sniff returned naturally without stop signal, retry to keep capture alive.
                if not self.stop_event.is_set():
                    time.sleep(0.4)
            except PermissionError:
                print(
                    "\n  Error: Permission denied. "
                    "Run with sudo or as Administrator."
                )
                self.stop_event.set()
                return
            except OSError as e:
                print(f"\n  Error: Could not open interface: {e}")
                if self.stop_event.is_set():
                    return
                print("  [live] Capture retrying in 2s... Press Ctrl+C to stop.")
                time.sleep(2)
            except Exception as e:
                print(f"\n  Error during capture: {e}")
                if self.stop_event.is_set():
                    return
                print("  [live] Capture retrying in 2s... Press Ctrl+C to stop.")
                time.sleep(2)

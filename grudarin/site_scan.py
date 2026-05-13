"""
Grudarin - Site Recon Scanner
Builds a graph model of website assets and findings in real time.
"""

import ipaddress
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime


class SiteGraphModel:
    """Thread-safe graph model for site/domain reconnaissance."""

    def __init__(self):
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.entities = {}
        self.connections = {}
        self.total_events = 0
        self.total_bytes = 0
        self.type_counts = {}

    def _entity_key(self, entity_type, value):
        return f"{entity_type}:{value}".lower()

    def add_entity(self, entity_type, value, attrs=None):
        attrs = attrs or {}
        key = self._entity_key(entity_type, value)
        now = time.time()

        with self.lock:
            self.total_events += 1
            if key not in self.entities:
                self.entities[key] = {
                    "key": key,
                    "type": entity_type,
                    "value": value,
                    "attrs": {},
                    "first_seen": now,
                    "last_seen": now,
                    "hits": 1,
                }
                self.type_counts[entity_type] = self.type_counts.get(entity_type, 0) + 1
            else:
                self.entities[key]["hits"] += 1
                self.entities[key]["last_seen"] = now

            self.entities[key]["attrs"].update(attrs)

        return key

    def add_connection(self, src_key, dst_key, relation, byte_count=0):
        if not src_key or not dst_key:
            return
        ck = (src_key, dst_key, relation)

        with self.lock:
            self.total_events += 1
            if byte_count > 0:
                self.total_bytes += int(byte_count)
            if ck not in self.connections:
                self.connections[ck] = {
                    "src": src_key,
                    "dst": dst_key,
                    "relation": relation,
                    "count": 1,
                    "bytes": int(byte_count),
                    "first_seen": time.time(),
                    "last_seen": time.time(),
                }
            else:
                c = self.connections[ck]
                c["count"] += 1
                c["bytes"] += int(byte_count)
                c["last_seen"] = time.time()

    def get_snapshot(self):
        with self.lock:
            devices_snapshot = {}
            for key, ent in self.entities.items():
                attrs = ent.get("attrs", {})
                et = ent.get("type", "UNKNOWN")
                value = ent.get("value", key)
                ip = attrs.get("ip", "unknown")
                if et == "IP_ADDRESS":
                    ip = value

                open_ports = attrs.get("open_ports", [])
                services = attrs.get("services", [])
                protocols = attrs.get("protocols", [et])

                devices_snapshot[key] = {
                    "key": key,
                    "label": value,
                    "ip": ip,
                    "mac": attrs.get("mac", "unknown"),
                    "vendor": attrs.get("vendor", ""),
                    "hostname": attrs.get("hostname", value if et == "DNS_NAME" else ""),
                    "os_hint": attrs.get("os_hint", ""),
                    "severity": attrs.get("severity", ""),
                    "description": attrs.get("description", ""),
                    "recommendation": attrs.get("recommendation", ""),
                    "is_gateway": False,
                    "is_broadcast": et == "VULNERABILITY",
                    "packets_sent": int(ent.get("hits", 0)),
                    "packets_received": int(ent.get("hits", 0)),
                    "bytes_sent": int(attrs.get("bytes", 0)),
                    "bytes_received": int(attrs.get("bytes", 0)),
                    "protocols": list(protocols),
                    "services": list(services),
                    "open_ports": list(open_ports),
                    "node_type": et,
                }

            connections_snapshot = []
            for (_src, _dst, _rel), c in self.connections.items():
                connections_snapshot.append({
                    "src": c["src"],
                    "dst": c["dst"],
                    "packet_count": int(c["count"]),
                    "byte_count": int(c["bytes"]),
                    "protocols": [c["relation"]],
                })

            return devices_snapshot, connections_snapshot

    def get_stats(self):
        with self.lock:
            return {
                "total_packets": int(self.total_events),
                "total_bytes": int(self.total_bytes),
                "total_devices": len(self.entities),
                "total_connections": len(self.connections),
                "uptime": time.time() - self.start_time,
                "protocol_counts": dict(self.type_counts),
            }

    def get_full_data(self):
        with self.lock:
            devices = {}
            for key, ent in self.entities.items():
                attrs = dict(ent.get("attrs", {}))
                et = ent.get("type", "UNKNOWN")
                val = ent.get("value", "")
                devices[key] = {
                    "mac": attrs.get("mac", "unknown"),
                    "ip": val if et == "IP_ADDRESS" else attrs.get("ip", "unknown"),
                    "all_ips": [val] if et == "IP_ADDRESS" else ([] if attrs.get("ip") in (None, "unknown") else [attrs.get("ip")]),
                    "hostname": attrs.get("hostname", val if et == "DNS_NAME" else ""),
                    "vendor": attrs.get("vendor", ""),
                    "os_hint": attrs.get("os_hint", ""),
                    "severity": attrs.get("severity", ""),
                    "description": attrs.get("description", ""),
                    "recommendation": attrs.get("recommendation", ""),
                    "open_ports": list(attrs.get("open_ports", [])),
                    "protocols": [et],
                    "first_seen": datetime.fromtimestamp(ent["first_seen"]).isoformat(),
                    "last_seen": datetime.fromtimestamp(ent["last_seen"]).isoformat(),
                    "packets_sent": int(ent.get("hits", 0)),
                    "packets_received": int(ent.get("hits", 0)),
                    "bytes_sent": int(attrs.get("bytes", 0)),
                    "bytes_received": int(attrs.get("bytes", 0)),
                    "is_gateway": False,
                    "ttl_values": [],
                    "services": list(attrs.get("services", [])),
                    "node_type": et,
                }

            conns = []
            for (_src, _dst, _rel), c in self.connections.items():
                conns.append({
                    "source": c["src"],
                    "destination": c["dst"],
                    "packet_count": int(c["count"]),
                    "byte_count": int(c["bytes"]),
                    "protocols": [c["relation"]],
                    "ports": [],
                    "first_seen": datetime.fromtimestamp(c["first_seen"]).isoformat(),
                    "last_seen": datetime.fromtimestamp(c["last_seen"]).isoformat(),
                })

            return {
                "session": {
                    "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
                    "end_time": datetime.now().isoformat(),
                    "duration_seconds": round(time.time() - self.start_time, 2),
                    "total_packets": int(self.total_events),
                    "total_bytes": int(self.total_bytes),
                    "protocol_distribution": dict(self.type_counts),
                },
                "devices": devices,
                "connections": conns,
                "dns_cache": {},
                "changes_log": [],
            }


class SiteScanner:
    """Domain/site scanner producing typed graph entities in real time."""

    COMMON_SUBS = [
        "www", "api", "app", "dev", "test", "stage", "staging", "beta", "mail", "mx",
        "cdn", "static", "assets", "portal", "admin", "blog", "shop", "docs", "m", "auth",
    ]

    COMMON_PORTS = [
        21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 6379, 8080, 8443,
    ]

    TECH_PATTERNS = [
        (re.compile(r"wordpress", re.I), "WordPress"),
        (re.compile(r"wp-content", re.I), "WordPress"),
        (re.compile(r"react", re.I), "React"),
        (re.compile(r"next\.js|_next", re.I), "Next.js"),
        (re.compile(r"vue", re.I), "Vue"),
        (re.compile(r"angular", re.I), "Angular"),
        (re.compile(r"cloudflare", re.I), "Cloudflare"),
        (re.compile(r"nginx", re.I), "nginx"),
        (re.compile(r"apache", re.I), "Apache"),
        (re.compile(r"iis", re.I), "IIS"),
    ]
    PACKAGE_PATTERNS = [
        re.compile(r"/npm/(@?[\w\.-]+(?:/[\w\.-]+)?)@([\w\.-]+)/", re.I),
        re.compile(r"unpkg\.com/(@?[\w\.-]+(?:/[\w\.-]+)?)(?:@([\w\.-]+))?", re.I),
        re.compile(r"jsdelivr\.net/npm/(@?[\w\.-]+(?:/[\w\.-]+)?)(?:@([\w\.-]+))?", re.I),
    ]

    def __init__(self, model, domain, stop_event, network_model=None):
        self.model = model
        self.domain = domain.strip().lower()
        self.stop_event = stop_event
        self.network_model = network_model
        self.seen_hosts = set()
        self.seen_ips = set()
        self.seen_urls = set()
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.rust_probe_path = os.path.join(base_dir, "bin", "grudarin_probe")
        self.sensitive_paths = [
            "/.git/HEAD",
            "/.env",
            "/.well-known/security.txt",
            "/robots.txt",
            "/sitemap.xml",
            "/phpinfo.php",
            "/server-status",
            "/wp-login.php",
            "/admin/",
            "/backup.zip",
        ]

    def _record_vulnerability(self, source_key, title, description, severity="medium", recommendation=""):
        vuln_key = self.model.add_entity(
            "VULNERABILITY",
            title,
            {
                "severity": severity,
                "description": description,
                "recommendation": recommendation,
            },
        )
        self.model.add_connection(source_key, vuln_key, f"vuln_{severity}")
        return vuln_key

    def _probe_severity_for_path(self, path):
        path = path.lower()
        if path in {"/.git/HEAD", "/.env", "/phpinfo.php", "/server-status", "/backup.zip"}:
            return "high"
        if path in {"/wp-login.php", "/admin/", "/admin"}:
            return "low"
        return "medium"

    def _probe_recommendation_for_path(self, path):
        if path in {"/.git/HEAD", "/.env", "/phpinfo.php", "/server-status", "/backup.zip"}:
            return "Remove the exposed asset or restrict it behind authentication."
        if path in {"/wp-login.php", "/admin/", "/admin"}:
            return "Restrict administrative paths to trusted networks."
        return "Review the endpoint and restrict access if it should not be public."

    def _run_rust_probe(self, base_url):
        if not (os.path.isfile(self.rust_probe_path) and os.access(self.rust_probe_path, os.X_OK)):
            return None

        cmd = [
            self.rust_probe_path,
            "--base",
            base_url,
            "--paths",
            ",".join(self.sensitive_paths),
            "--timeout-ms",
            "6500",
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except Exception:
            return None

        if result.returncode != 0 or not result.stdout.strip():
            return None

        try:
            return json.loads(result.stdout)
        except Exception:
            return None

    def run(self):
        base = self.domain
        seed_key = self.model.add_entity("DNS_NAME", base, {"hostname": base})

        org_stub = base.split(".")[0]
        org_key = self.model.add_entity("ORG_STUB", org_stub)
        self.model.add_connection(org_key, seed_key, "seed")

        queue = [base]

        # Seed common subdomains quickly.
        for sub in self.COMMON_SUBS:
            if self.stop_event.is_set():
                return
            host = f"{sub}.{base}"
            queue.append(host)

        # Best-effort crt.sh expansion.
        for host in self._crtsh_subdomains(base):
            queue.append(host)

        while queue and not self.stop_event.is_set():
            # Track local visitors if network_model is provided
            if self.network_model:
                self._track_local_visitors()

            host = queue.pop(0).strip().lower().rstrip(".")
            if not host or host in self.seen_hosts:
                continue
            self.seen_hosts.add(host)

            dns_key = self.model.add_entity("DNS_NAME", host, {"hostname": host})
            self.model.add_connection(seed_key, dns_key, "subdomain")

            ips = self._resolve_host(host)
            for ip in ips:
                if self.stop_event.is_set():
                    return
                ip_key = self.model.add_entity("IP_ADDRESS", ip, {"ip": ip})
                self.model.add_connection(dns_key, ip_key, "resolves_to")

                if ip not in self.seen_ips:
                    self.seen_ips.add(ip)
                    cidr = self._to_cidr(ip)
                    if cidr:
                        rng_key = self.model.add_entity("IP_RANGE", cidr)
                        self.model.add_connection(ip_key, rng_key, "in_range")
                    self._scan_ports(ip, ip_key)

            # URL probes
            for scheme in ("https", "http"):
                if self.stop_event.is_set():
                    return
                url = f"{scheme}://{host}/"
                if url in self.seen_urls:
                    continue
                self.seen_urls.add(url)
                self._analyze_url(url, dns_key)

            time.sleep(0.02)

    def _resolve_host(self, host):
        ips = []
        try:
            infos = socket.getaddrinfo(host, None)
            seen = set()
            for it in infos:
                addr = it[4][0]
                if addr not in seen:
                    seen.add(addr)
                    ips.append(addr)
        except Exception:
            pass
        return ips

    def _to_cidr(self, ip):
        try:
            obj = ipaddress.ip_address(ip)
            if obj.version == 4:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
                return str(net)
        except Exception:
            pass
        return ""

    def _scan_ports(self, ip, ip_key):
        open_ports = []
        for p in self.COMMON_PORTS:
            if self.stop_event.is_set():
                return
            s = socket.socket(socket.AF_INET6 if ":" in ip else socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.35)
            try:
                code = s.connect_ex((ip, p))
                if code == 0:
                    open_ports.append(p)
                    port_node = self.model.add_entity("OPEN_TCP_PORT", f"{ip}:{p}", {"open_ports": [p]})
                    self.model.add_connection(ip_key, port_node, "open_port")
            except Exception:
                pass
            finally:
                s.close()

        # Update IP node with collected ports.
        if open_ports:
            self.model.add_entity("IP_ADDRESS", ip, {"ip": ip, "open_ports": sorted(open_ports)})

    def _analyze_url(self, url, dns_key):
        parsed = urllib.parse.urlparse(url)
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "grudarin-site-scan/1.0",
                "Accept": "text/html,application/json,*/*;q=0.8",
            },
        )

        body = b""
        headers = {}
        status = 0
        final_url = url

        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                status = getattr(resp, "status", 200)
                headers = dict(resp.headers.items())
                body = resp.read(250000)
                final_url = getattr(resp, "url", url)
        except urllib.error.HTTPError as e:
            status = e.code
            headers = dict(getattr(e, "headers", {}).items()) if getattr(e, "headers", None) else {}
            try:
                body = e.read(120000)
            except Exception:
                body = b""
        except Exception:
            return

        text = body.decode("utf-8", errors="ignore")
        url_key = self.model.add_entity("URL", url, {"bytes": len(body), "status": status})
        self.model.add_connection(dns_key, url_key, "url", byte_count=len(body))
        if final_url and final_url != url:
            final_key = self.model.add_entity("URL", final_url, {"bytes": len(body), "status": status})
            self.model.add_connection(url_key, final_key, "redirects_to")

        # TECHNOLOGY from headers/body
        techs = set()
        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        content_for_tech = "\n".join([server, powered, text[:60000]])
        for pat, name in self.TECH_PATTERNS:
            if pat.search(content_for_tech):
                techs.add(name)

        for t in sorted(techs):
            t_key = self.model.add_entity("TECHNOLOGY", t)
            self.model.add_connection(url_key, t_key, "technology")

        # PACKAGE fingerprinting from script/link URLs and CDN imports.
        self._extract_web_packages(text, url_key)

        # Security header and cookie hygiene checks.
        headers_lower = {k.lower(): v for k, v in headers.items()}
        missing_headers = []
        for header_name, label in (
            ("content-security-policy", "CSP missing"),
            ("x-frame-options", "X-Frame-Options missing"),
            ("x-content-type-options", "X-Content-Type-Options missing"),
            ("referrer-policy", "Referrer-Policy missing"),
            ("permissions-policy", "Permissions-Policy missing"),
        ):
            if header_name not in headers_lower:
                missing_headers.append(label)

        if parsed.scheme == "https" and "strict-transport-security" not in headers_lower:
            missing_headers.append("HSTS missing")

        if missing_headers:
            severity = "medium" if len(missing_headers) >= 3 else "low"
            self._record_vulnerability(
                url_key,
                "Weak HTTP Security Headers",
                f"Missing headers: {', '.join(missing_headers)}",
                severity,
                "Set security headers at the application or reverse proxy layer.",
            )

        cors_origin = headers_lower.get("access-control-allow-origin", "")
        cors_creds = headers_lower.get("access-control-allow-credentials", "").lower()
        if cors_origin == "*" and cors_creds == "true":
            self._record_vulnerability(
                url_key,
                "Unsafe CORS Configuration",
                "Access-Control-Allow-Origin is '*' while credentials are enabled.",
                "high",
                "Restrict allowed origins and avoid credentialed wildcard CORS.",
            )

        for cookie in headers.get("Set-Cookie", "").split("\n"):
            cookie_lower = cookie.lower()
            if not cookie.strip():
                continue
            if ("session" in cookie_lower or "auth" in cookie_lower) and "httponly" not in cookie_lower:
                self._record_vulnerability(
                    url_key,
                    "Session Cookie Missing HttpOnly",
                    cookie.strip()[:240],
                    "medium",
                    "Mark session cookies as HttpOnly.",
                )
            if parsed.scheme == "https" and ("session" in cookie_lower or "auth" in cookie_lower) and "secure" not in cookie_lower:
                self._record_vulnerability(
                    url_key,
                    "Session Cookie Missing Secure Flag",
                    cookie.strip()[:240],
                    "medium",
                    "Mark authentication cookies as Secure over HTTPS.",
                )

        # EMAIL_ADDRESS
        for em in set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text)):
            em = em.lower()
            if len(em) > 120:
                continue
            e_key = self.model.add_entity("EMAIL_ADDRESS", em)
            self.model.add_connection(url_key, e_key, "email")
            user = em.split("@", 1)[0]
            if user:
                u_key = self.model.add_entity("USER_STUB", user)
                self.model.add_connection(e_key, u_key, "user_stub")

        # STORAGE_BUCKET patterns
        bucket_patterns = [
            r"[A-Za-z0-9.-]+\.s3\.amazonaws\.com",
            r"storage\.googleapis\.com/[A-Za-z0-9._/-]+",
            r"[A-Za-z0-9.-]+\.blob\.core\.windows\.net",
        ]
        for bp in bucket_patterns:
            for b in set(re.findall(bp, text, flags=re.I)):
                b_key = self.model.add_entity("STORAGE_BUCKET", b)
                self.model.add_connection(url_key, b_key, "storage_bucket")

        # Discover more subdomains belonging to the seed domain.
        escaped = re.escape(self.domain)
        sub_re = re.compile(rf"(?:[a-zA-Z0-9-]+\.)+{escaped}")
        for sub in set(sub_re.findall(text)):
            sub = sub.lower().strip(".")
            sub_key = self.model.add_entity("DNS_NAME", sub, {"hostname": sub})
            self.model.add_connection(url_key, sub_key, "mentions_subdomain")

        # Basic vulnerability heuristics.
        vuln_hits = []
        if status >= 500:
            vuln_hits.append(("medium", f"Server error status {status} at {url}"))
        if "index of /" in text.lower():
            vuln_hits.append(("high", f"Possible directory listing at {url}"))
        if "server: apache/2.2" in content_for_tech.lower() or "server: nginx/1.0" in content_for_tech.lower():
            vuln_hits.append(("high", f"Outdated web server version exposed at {url}"))

        if re.search(r"<input[^>]+type=['\"]?password", text, flags=re.I) and parsed.scheme != "https":
            vuln_hits.append(("critical", f"Password form submitted over HTTP at {url}"))

        if any(token in text.lower() for token in ["phpinfo()", "php version", "xdebug profiler", "debug toolbar"]):
            vuln_hits.append(("medium", f"Debug content exposed at {url}"))

        if parsed.scheme == "https" and parsed.hostname:
            self._inspect_tls(parsed.hostname, url_key)

        self._probe_common_paths(parsed, url_key)

        for sev, desc in vuln_hits:
            self._record_vulnerability(url_key, desc, desc, sev)

    def _extract_web_packages(self, html_text, url_key):
        if not html_text:
            return

        package_hits = {}
        refs = re.findall(r"""(?:src|href)=["']([^"']+)["']""", html_text, flags=re.I)
        blob = "\n".join(refs + [html_text[:100000]])

        for pat in self.PACKAGE_PATTERNS:
            for m in pat.finditer(blob):
                name = (m.group(1) or "").strip()
                version = (m.group(2) or "").strip() if len(m.groups()) >= 2 else ""
                if not name:
                    continue
                package_hits[name.lower()] = {"name": name, "version": version}

        # Framework-specific fallback hints from static bundle names.
        if re.search(r"(?:^|/)(react|react-dom)(?:\.min)?\.js", blob, flags=re.I):
            package_hits.setdefault("react", {"name": "react", "version": ""})
        if re.search(r"(?:^|/)(vue)(?:\.runtime)?(?:\.min)?\.js", blob, flags=re.I):
            package_hits.setdefault("vue", {"name": "vue", "version": ""})
        if re.search(r"(?:^|/)(angular)(?:\.min)?\.js", blob, flags=re.I):
            package_hits.setdefault("angular", {"name": "angular", "version": ""})

        for item in sorted(package_hits.values(), key=lambda v: v["name"]):
            node_value = item["name"] + (f"@{item['version']}" if item["version"] else "")
            attrs = {"package": item["name"]}
            if item["version"]:
                attrs["version"] = item["version"]
            pkg_key = self.model.add_entity("PACKAGE", node_value, attrs)
            self.model.add_connection(url_key, pkg_key, "uses_package")

    def _inspect_tls(self, host, url_key):
        if not host:
            return
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=4) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
        except ssl.SSLCertVerificationError as exc:
            self._record_vulnerability(
                url_key,
                "TLS Certificate Validation Failed",
                str(exc),
                "high",
                "Install a valid certificate chain trusted by clients.",
            )
            return
        except Exception:
            return

        not_after = cert.get("notAfter") if isinstance(cert, dict) else None
        if not_after:
            try:
                expires = time.mktime(time.strptime(not_after, "%b %d %H:%M:%S %Y %Z"))
                days_left = (expires - time.time()) / 86400.0
                if days_left < 0:
                    self._record_vulnerability(
                        url_key,
                        "TLS Certificate Expired",
                        f"Certificate expired {abs(days_left):.1f} days ago.",
                        "high",
                        "Renew the certificate immediately.",
                    )
                elif days_left < 30:
                    self._record_vulnerability(
                        url_key,
                        "TLS Certificate Expiring Soon",
                        f"Certificate expires in {days_left:.1f} days.",
                        "medium",
                        "Renew the certificate before expiry.",
                    )
            except Exception:
                pass

    def _probe_common_paths(self, parsed, url_key):
        if not parsed.scheme or not parsed.netloc:
            return

        base = f"{parsed.scheme}://{parsed.netloc}"
        rust_data = self._run_rust_probe(base)
        if rust_data:
            for probe in rust_data.get("probes", []):
                path = probe.get("path", "")
                status = int(probe.get("status", 0) or 0)
                probe_url = probe.get("url") or urllib.parse.urljoin(base, path)
                if status in (200, 206):
                    path_key = self.model.add_entity("URL", probe_url, {"status": status, "bytes": 0})
                    self.model.add_connection(url_key, path_key, "exposes_path")
                    self._record_vulnerability(
                        url_key,
                        f"Sensitive Path Exposed: {path}",
                        f"Rust probe confirmed HTTP {status} response from {probe_url}",
                        self._probe_severity_for_path(path),
                        self._probe_recommendation_for_path(path),
                    )
            return

        sensitive_set = {"/.git/HEAD", "/.env", "/phpinfo.php", "/server-status", "/backup.zip"}
        for path in self.sensitive_paths:
            if self.stop_event.is_set():
                return
            probe_url = urllib.parse.urljoin(base, path)
            req = urllib.request.Request(
                probe_url,
                headers={"User-Agent": "grudarin-site-scan/1.0"},
                method="HEAD",
            )
            status = 0
            try:
                with urllib.request.urlopen(req, timeout=4) as resp:
                    status = getattr(resp, "status", 200)
            except urllib.error.HTTPError as e:
                status = e.code
            except Exception:
                continue

            if status in (200, 206):
                path_key = self.model.add_entity("URL", probe_url, {"status": status, "bytes": 0})
                self.model.add_connection(url_key, path_key, "exposes_path")
                if path in sensitive_set:
                    self._record_vulnerability(
                        url_key,
                        f"Sensitive Path Exposed: {path}",
                        f"Confirmed HTTP {status} response from {probe_url}",
                        "high",
                        "Remove the file or restrict access behind authentication.",
                    )
                elif path in {"/wp-login.php", "/admin/"}:
                    self._record_vulnerability(
                        url_key,
                        f"Administrative Endpoint Discovered: {path}",
                        f"Endpoint responds with HTTP {status} at {probe_url}",
                        "low",
                        "Restrict administrative paths to trusted networks.",
                    )

    def _track_local_visitors(self):
        """Identify local devices that have communicated with resolved target IPs."""
        if not self.network_model: return

        # Use the activity_log from network_model to find local devices visiting our targets
        stats = self.network_model.get_stats()
        recent = stats.get("recent_activity", [])
        for ev in recent:
            target = ev.get("target", "")
            # If target is one of our hosts or IPs
            if target in self.seen_hosts or target in self.seen_ips or any(h in target for h in self.seen_hosts):
                src = ev.get("source_ip", "unknown")
                visitor_key = self.model.add_entity("VISITOR", src, {"ip": src, "node_type": "VISITOR"})
                # Link visitor to the domain
                seed_key = self.model._entity_key("DNS_NAME", self.domain)
                if seed_key in self.model.entities:
                    self.model.add_connection(visitor_key, seed_key, "visited", byte_count=0)

    def _crtsh_subdomains(self, domain):
        """Best-effort crt.sh lookup for subdomains."""
        found = set()
        q = urllib.parse.quote(domain)
        url = f"https://crt.sh/?q=%25.{q}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "grudarin-site-scan/1.0"})

        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = resp.read(1200000)
                entries = json.loads(data.decode("utf-8", errors="ignore"))
                for e in entries[:4000]:
                    name_val = e.get("name_value", "")
                    for part in str(name_val).split("\n"):
                        part = part.strip().lower().strip(".")
                        if part.endswith(domain) and "*" not in part:
                            found.add(part)
        except Exception:
            return []

        return sorted(found)

"""
Grudarin - Built-in Graph GUI (Tkinter)
Classic black-themed, live force-directed graph with node detail and charts.
"""

import math
import random
import threading
import time
from grudarin import __version__

try:
    import tkinter as tk
except Exception:
    tk = None


class GraphWindow:
    """
    Native built-in graph view using Tkinter (no external graph frameworks).
    """

    BG = "#0a0a0a"
    PANEL = "#121212"
    GRID = "#1c1c1c"
    EDGE = "#404040"
    EDGE_HOT = "#7a7a7a"
    TEXT = "#f0f0f0"
    DIM = "#a0a0a0"
    NODE_ORANGE = "#ff7a1a"
    NODE_ORANGE_DARK = "#cc5f12"
    NODE_RED = "#d63031"
    NODE_BORDER = "#f1f1f1"
    ACCENT = "#ff8f1f"

    def __init__(
        self,
        network_model,
        stop_event,
        notes_writer,
        session_dir,
        scan_callback=None,
    ):
        self.model = network_model
        self.stop_event = stop_event
        self.notes = notes_writer
        self.session_dir = session_dir
        self.scan_callback = scan_callback

        self.w = 1320
        self.h = 840
        self.graph_w = 920

        # Camera/interaction state for smooth pan+zoom navigation.
        self.cam_x = 0.0
        self.cam_y = 0.0
        self.zoom = 1.0
        self.panning = False
        self.pan_start = (0, 0)
        self.cam_start = (0.0, 0.0)

        self.nodes = {}
        self.edges = []
        self.selected = None
        self.dragging = None
        self.last_sync = 0.0
        self.last_tick = time.time()
        self.last_mouse = (0, 0)
        self.protocol_counts = {}
        self.top_talkers = []
        self.scan_results = {}
        self.scan_status = ""
        self.history = []
        self.relation_counts = {}
        self.node_type_counts = {}
        self.recent_activity = []

        self.root = None
        self.canvas = None
        self.detail_text = None
        self.status_var = None
        self.scan_btn = None
        self.scan_all_btn = None

    def _w2s(self, wx, wy):
        sx = (wx - self.cam_x) * self.zoom + self.graph_w / 2
        sy = (wy - self.cam_y) * self.zoom + self.h / 2
        return sx, sy

    def _s2w(self, sx, sy):
        wx = (sx - self.graph_w / 2) / self.zoom + self.cam_x
        wy = (sy - self.h / 2) / self.zoom + self.cam_y
        return wx, wy

    # ------------------------------------------------------------
    # Model Sync
    # ------------------------------------------------------------

    def _sync(self):
        now = time.time()
        if now - self.last_sync < 0.5:
            return
        self.last_sync = now

        devices, connections = self.model.get_snapshot()
        stats = self.model.get_stats()
        self.protocol_counts = stats.get("protocol_counts", {})
        self.recent_activity = stats.get("recent_activity", [])

        cx = self.graph_w / 2.0
        cy = self.h / 2.0

        for key, info in devices.items():
            if key not in self.nodes:
                ang = random.uniform(0, 2 * math.pi)
                rad = random.uniform(80, 260)
                self.nodes[key] = {
                    "key": key,
                    "x": cx + math.cos(ang) * rad,
                    "y": cy + math.sin(ang) * rad,
                    "vx": 0.0,
                    "vy": 0.0,
                    "r": 13,
                    "spawn": 0.0,
                    "info": info,
                    "neighbors": set(),
                }
            nd = self.nodes[key]
            nd["info"] = info
            total_pkts = int(info.get("packets_sent", 0)) + int(info.get("packets_received", 0))
            nd["r"] = max(8, min(24, 9 + int(math.log2(total_pkts + 1)) * 2))
            nd["spawn"] = min(1.0, nd.get("spawn", 0.0) + 0.12)

        # Remove stale nodes after long inactivity only if not selected/dragging.
        stale = []
        for key, nd in self.nodes.items():
            if key not in devices and key != self.selected and key != self.dragging:
                stale.append(key)
        for key in stale:
            self.nodes.pop(key, None)

        self.edges = []
        self.relation_counts = {}
        self.node_type_counts = {}
        for nd in self.nodes.values():
            nd["neighbors"] = set()
            t = str(nd["info"].get("node_type", "NODE"))
            self.node_type_counts[t] = self.node_type_counts.get(t, 0) + 1

        for c in connections:
            s = c.get("src")
            d = c.get("dst")
            if s in self.nodes and d in self.nodes:
                self.edges.append({
                    "src": s,
                    "dst": d,
                    "packets": int(c.get("packet_count", 0)),
                    "bytes": int(c.get("byte_count", 0)),
                    "protocols": list(c.get("protocols", [])),
                })
                self.nodes[s]["neighbors"].add(d)
                self.nodes[d]["neighbors"].add(s)
                for rel in list(c.get("protocols", [])) or ["link"]:
                    self.relation_counts[rel] = self.relation_counts.get(rel, 0) + 1

        talkers = []
        for key, nd in self.nodes.items():
            info = nd["info"]
            packets = int(info.get("packets_sent", 0)) + int(info.get("packets_received", 0))
            talkers.append((key, packets, info.get("label", key)))
        talkers.sort(key=lambda x: x[1], reverse=True)
        self.top_talkers = talkers[:8]

    # ------------------------------------------------------------
    # Physics
    # ------------------------------------------------------------

    def _step_physics(self, dt):
        if not self.nodes:
            return

        repulsion = 6400.0
        spring_k = 0.011
        spring_len = 155.0
        damping = 0.86
        gravity = 0.022
        max_speed = 9.0

        keys = list(self.nodes.keys())
        n = len(keys)

        forces = {k: [0.0, 0.0] for k in keys}

        # Repulsion
        for i in range(n):
            a = self.nodes[keys[i]]
            for j in range(i + 1, n):
                b = self.nodes[keys[j]]
                dx = a["x"] - b["x"]
                dy = a["y"] - b["y"]
                dsq = dx * dx + dy * dy
                if dsq < 1.0:
                    dx = random.uniform(-1, 1)
                    dy = random.uniform(-1, 1)
                    dsq = max(0.1, dx * dx + dy * dy)
                d = math.sqrt(dsq)
                f = repulsion / dsq
                fx = (dx / d) * f
                fy = (dy / d) * f
                forces[a["key"]][0] += fx
                forces[a["key"]][1] += fy
                forces[b["key"]][0] -= fx
                forces[b["key"]][1] -= fy

        # Springs
        for e in self.edges:
            a = self.nodes[e["src"]]
            b = self.nodes[e["dst"]]
            dx = b["x"] - a["x"]
            dy = b["y"] - a["y"]
            d = math.sqrt(dx * dx + dy * dy)
            if d < 0.01:
                continue
            disp = d - spring_len
            wf = min(e["packets"] / 10.0, 3.0)
            k = spring_k * (1.0 + wf * 0.22)
            f = k * disp
            fx = (dx / d) * f
            fy = (dy / d) * f
            forces[a["key"]][0] += fx
            forces[a["key"]][1] += fy
            forces[b["key"]][0] -= fx
            forces[b["key"]][1] -= fy

        # Gravity to center
        cx = self.graph_w / 2.0
        cy = self.h / 2.0
        for key, nd in self.nodes.items():
            forces[key][0] += (cx - nd["x"]) * gravity
            forces[key][1] += (cy - nd["y"]) * gravity

        # Integrate
        for key, nd in self.nodes.items():
            if key == self.dragging:
                nd["vx"] = 0.0
                nd["vy"] = 0.0
                continue
            nd["vx"] = (nd["vx"] + forces[key][0] * dt) * damping
            nd["vy"] = (nd["vy"] + forces[key][1] * dt) * damping
            spd = math.sqrt(nd["vx"] * nd["vx"] + nd["vy"] * nd["vy"])
            if spd > max_speed:
                nd["vx"] = nd["vx"] / spd * max_speed
                nd["vy"] = nd["vy"] / spd * max_speed
            nd["x"] += nd["vx"]
            nd["y"] += nd["vy"]
            nd["x"] = max(40, min(self.graph_w - 40, nd["x"]))
            nd["y"] = max(46, min(self.h - 46, nd["y"]))

    # ------------------------------------------------------------
    # Drawing
    # ------------------------------------------------------------

    def _node_color(self, nd):
        info = nd["info"]
        if info.get("is_broadcast"):
            return self.NODE_RED
        if info.get("is_gateway"):
            return self.NODE_ORANGE
        packets = int(info.get("packets_sent", 0)) + int(info.get("packets_received", 0))
        if packets > 1500:
            return self.NODE_RED
        return self.NODE_ORANGE_DARK

    def _draw(self):
        c = self.canvas
        c.delete("all")

        # background + grid
        c.create_rectangle(0, 0, self.graph_w, self.h, fill=self.BG, outline="")
        gs = max(20, int(48 * self.zoom))
        ox = int((-self.cam_x * self.zoom + self.graph_w / 2) % gs)
        oy = int((-self.cam_y * self.zoom + self.h / 2) % gs)
        for x in range(ox, self.graph_w, gs):
            c.create_line(x, 0, x, self.h, fill=self.GRID)
        for y in range(oy, self.h, gs):
            c.create_line(0, y, self.graph_w, y, fill=self.GRID)

        # edges
        for e in self.edges:
            a = self.nodes.get(e["src"])
            b = self.nodes.get(e["dst"])
            if not a or not b:
                continue
            ax, ay = self._w2s(a["x"], a["y"])
            bx, by = self._w2s(b["x"], b["y"])
            thick = max(1, min(4, int(math.log2(e["packets"] + 1))))
            clr = self.EDGE_HOT if e["packets"] > 20 else self.EDGE
            c.create_line(ax, ay, bx, by, fill=clr, width=thick)

            protos = e.get("protocols") or []
            if protos:
                mx = (ax + bx) / 2.0
                my = (ay + by) / 2.0
                ptxt = ",".join(protos[:3])
                c.create_text(mx, my - 6, text=ptxt, fill=self.DIM, font=("Courier", 8))

        # nodes and labels
        for key, nd in self.nodes.items():
            x, y = self._w2s(nd["x"], nd["y"])
            if x < -120 or x > self.graph_w + 120 or y < -120 or y > self.h + 120:
                continue

            spawn = nd.get("spawn", 1.0)
            r = max(4, int(nd["r"] * self.zoom * (0.35 + 0.65 * spawn)))
            fill = self._node_color(nd)
            outline = self.NODE_BORDER if key == self.selected else "#cfcfcf"
            width = 2 if key == self.selected else 1

            c.create_oval(x - r, y - r, x + r, y + r, fill=fill, outline=outline, width=width)

            info = nd["info"]
            node_type = str(info.get("node_type", "NODE"))
            label = info.get("label") or info.get("hostname") or info.get("ip") or key
            ip = info.get("ip") or "unknown"
            if self.zoom > 0.55:
                c.create_text(x, y + r + 12, text=f"[{node_type}] {label}"[:36], fill=self.TEXT, font=("Courier", 9))
                c.create_text(x, y + r + 24, text=ip[:26], fill=self.DIM, font=("Courier", 8))

            peers = []
            for pk in sorted(nd["neighbors"]):
                pi = self.nodes.get(pk, {}).get("info", {})
                peers.append((pi.get("label") or pi.get("hostname") or pi.get("ip") or pk)[:14])
            peers_txt = ", ".join(peers[:2])
            if len(peers) > 2:
                peers_txt += "..."
            if peers_txt and self.zoom > 0.75:
                c.create_text(x, y + r + 36, text=f"to: {peers_txt}", fill=self.DIM, font=("Courier", 8))

        # top status bar
        stats = self.model.get_stats()
        c.create_rectangle(0, 0, self.graph_w, 30, fill="#0f0f0f", outline="#1f1f1f")
        status = (
            f"Packets:{stats.get('total_packets',0)}  "
            f"Devices:{stats.get('total_devices',0)}  "
            f"Links:{stats.get('total_connections',0)}  "
            f"Data:{self._fmt_bytes(stats.get('total_bytes',0))}  "
            f"Uptime:{int(stats.get('uptime',0))}s  "
            f"Zoom:{self.zoom:.2f}"
        )
        c.create_text(10, 16, text=status, fill=self.TEXT, font=("Courier", 10), anchor="w")

    def _draw_protocol_chart(self, cv):
        cv.delete("all")
        cv.create_rectangle(0, 0, 360, 180, fill=self.PANEL, outline="#262626")
        cv.create_text(8, 8, anchor="nw", text="Protocol Distribution", fill=self.ACCENT, font=("Courier", 10, "bold"))

        items = sorted(self.protocol_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        if not items:
            cv.create_text(10, 42, anchor="nw", text="No protocol data yet", fill=self.DIM, font=("Courier", 9))
            return

        total = sum(v for _, v in items) or 1
        y = 30
        for name, count in items:
            width = int((count / total) * 220)
            cv.create_rectangle(12, y, 12 + width, y + 12, fill=self.NODE_ORANGE, outline="")
            cv.create_text(238, y + 6, text=f"{name}: {count}", fill=self.TEXT, font=("Courier", 9), anchor="w")
            y += 18

    def _draw_talker_chart(self, cv):
        cv.delete("all")
        cv.create_rectangle(0, 0, 360, 200, fill=self.PANEL, outline="#262626")
        cv.create_text(8, 8, anchor="nw", text="Top Talkers (packets)", fill=self.ACCENT, font=("Courier", 10, "bold"))

        if not self.top_talkers:
            cv.create_text(10, 42, anchor="nw", text="No talker data yet", fill=self.DIM, font=("Courier", 9))
            return

        maxv = max(v for _, v, _ in self.top_talkers) or 1
        y = 32
        for _, value, label in self.top_talkers:
            bw = int((value / maxv) * 220)
            cv.create_rectangle(12, y, 12 + bw, y + 12, fill=self.NODE_RED, outline="")
            cv.create_text(238, y + 6, text=f"{label[:16]}: {value}", fill=self.TEXT, font=("Courier", 9), anchor="w")
            y += 18

    def _draw_timeline_chart(self, cv):
        cv.delete("all")
        w = 360
        h = 190
        cv.create_rectangle(0, 0, w, h, fill=self.PANEL, outline="#262626")
        cv.create_text(8, 8, anchor="nw", text="Realtime Timeline (nodes / events / bytes)", fill=self.ACCENT, font=("Courier", 10, "bold"))

        if len(self.history) < 2:
            cv.create_text(10, 42, anchor="nw", text="Collecting timeline data...", fill=self.DIM, font=("Courier", 9))
            return

        x0, y0 = 14, 28
        x1, y1 = w - 10, h - 18
        cv.create_rectangle(x0, y0, x1, y1, outline="#333333")

        recent = self.history[-90:]
        nodes = [v[0] for v in recent]
        events = [v[1] for v in recent]
        bytes_vals = [v[2] for v in recent]

        max_nodes = max(nodes) or 1
        max_events = max(events) or 1
        max_bytes = max(bytes_vals) or 1

        def plot(vals, vmax, color):
            pts = []
            n = len(vals)
            for i, v in enumerate(vals):
                xx = x0 + (i / max(1, n - 1)) * (x1 - x0)
                yy = y1 - (v / vmax) * (y1 - y0)
                pts.extend([xx, yy])
            if len(pts) >= 4:
                cv.create_line(*pts, fill=color, width=2)

        plot(nodes, max_nodes, self.NODE_ORANGE)
        plot(events, max_events, self.NODE_RED)
        plot(bytes_vals, max_bytes, "#f0f0f0")

        cv.create_text(14, h - 8, anchor="sw", text="orange=nodes", fill=self.NODE_ORANGE, font=("Courier", 8))
        cv.create_text(128, h - 8, anchor="sw", text="red=events", fill=self.NODE_RED, font=("Courier", 8))
        cv.create_text(232, h - 8, anchor="sw", text="white=bytes", fill="#f0f0f0", font=("Courier", 8))

    def _draw_node_type_chart(self, cv):
        cv.delete("all")
        cv.create_rectangle(0, 0, 360, 170, fill=self.PANEL, outline="#262626")
        cv.create_text(8, 8, anchor="nw", text="Node Type Distribution", fill=self.ACCENT, font=("Courier", 10, "bold"))

        items = sorted(self.node_type_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        if not items:
            cv.create_text(10, 42, anchor="nw", text="No type data yet", fill=self.DIM, font=("Courier", 9))
            return

        total = sum(v for _, v in items) or 1
        y = 30
        for name, count in items:
            width = int((count / total) * 210)
            cv.create_rectangle(12, y, 12 + width, y + 12, fill="#ff9f43", outline="")
            cv.create_text(228, y + 6, text=f"{name[:14]}: {count}", fill=self.TEXT, font=("Courier", 9), anchor="w")
            y += 17

    def _draw_relation_chart(self, cv):
        cv.delete("all")
        cv.create_rectangle(0, 0, 360, 170, fill=self.PANEL, outline="#262626")
        cv.create_text(8, 8, anchor="nw", text="Relation/Link Type Counts", fill=self.ACCENT, font=("Courier", 10, "bold"))

        items = sorted(self.relation_counts.items(), key=lambda x: x[1], reverse=True)[:8]
        if not items:
            cv.create_text(10, 42, anchor="nw", text="No relation data yet", fill=self.DIM, font=("Courier", 9))
            return

        maxv = max(v for _, v in items) or 1
        y = 30
        for rel, count in items:
            width = int((count / maxv) * 210)
            cv.create_rectangle(12, y, 12 + width, y + 12, fill="#d63031", outline="")
            cv.create_text(228, y + 6, text=f"{rel[:14]}: {count}", fill=self.TEXT, font=("Courier", 9), anchor="w")
            y += 17

    def _draw_activity_feed(self, cv):
        cv.delete("all")
        w = 360
        h = 200
        cv.create_rectangle(0, 0, w, h, fill=self.PANEL, outline="#262626")
        cv.create_text(8, 8, anchor="nw", text="Realtime Activity Feed", fill=self.ACCENT, font=("Courier", 10, "bold"))

        items = list(self.recent_activity)[-8:]
        if not items:
            cv.create_text(10, 42, anchor="nw", text="No DNS/HTTP activity yet", fill=self.DIM, font=("Courier", 9))
            return

        y = 28
        for it in items:
            src = str(it.get("source_ip", "unknown"))[:15]
            et = str(it.get("event_type", "activity"))[:10]
            tgt = str(it.get("target", ""))[:35]
            line = f"{src} [{et}] {tgt}"
            cv.create_text(10, y, anchor="nw", text=line, fill=self.TEXT, font=("Courier", 8))
            y += 20

    @staticmethod
    def _fmt_bytes(n):
        if n < 1024:
            return f"{n}B"
        if n < 1048576:
            return f"{n/1024:.1f}KB"
        if n < 1073741824:
            return f"{n/1048576:.1f}MB"
        return f"{n/1073741824:.2f}GB"

    # ------------------------------------------------------------
    # Selection + Scan
    # ------------------------------------------------------------

    def _pick_node(self, x, y):
        wx, wy = self._s2w(x, y)
        best = None
        best_d = 1e9
        for key, nd in self.nodes.items():
            dx = nd["x"] - wx
            dy = nd["y"] - wy
            d = math.sqrt(dx * dx + dy * dy)
            if d <= (nd["r"] / max(0.25, self.zoom)) + 6 and d < best_d:
                best = key
                best_d = d
        return best

    def _refresh_detail_panel(self):
        if self.detail_text is None:
            return

        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")

        if not self.selected or self.selected not in self.nodes:
            self.detail_text.insert("end", "Select a node to inspect full details.\n")
            self.detail_text.configure(state="disabled")
            return

        nd = self.nodes[self.selected]
        info = nd["info"]
        ip = info.get("ip") or "unknown"

        lines = []
        lines.append("NODE DETAILS")
        lines.append("-" * 48)
        lines.append(f"Label        : {info.get('label', self.selected)}")
        lines.append(f"IP           : {ip}")
        lines.append(f"MAC          : {info.get('mac', 'unknown')}")
        lines.append(f"Hostname     : {info.get('hostname', '-')}")
        lines.append(f"Vendor       : {info.get('vendor', '-')}")
        lines.append(f"OS Hint      : {info.get('os_hint', '-')}")
        lines.append(f"Gateway      : {bool(info.get('is_gateway', False))}")
        lines.append(f"Broadcast    : {bool(info.get('is_broadcast', False))}")
        lines.append(f"Packets Sent : {int(info.get('packets_sent', 0))}")
        lines.append(f"Packets Recv : {int(info.get('packets_received', 0))}")
        lines.append(f"Bytes Sent   : {self._fmt_bytes(int(info.get('bytes_sent', 0)))}")
        lines.append(f"Bytes Recv   : {self._fmt_bytes(int(info.get('bytes_received', 0)))}")

        protocols = sorted(info.get("protocols") or [])
        services = sorted(info.get("services") or [])
        ports = sorted(info.get("open_ports") or [])
        lines.append(f"Protocols    : {', '.join(protocols) if protocols else '-'}")
        lines.append(f"Services     : {', '.join(services) if services else '-'}")
        lines.append(f"Open Ports   : {', '.join(str(p) for p in ports) if ports else '-'}")

        peers = []
        for pk in sorted(nd["neighbors"]):
            pi = self.nodes.get(pk, {}).get("info", {})
            peers.append(pi.get("label") or pi.get("hostname") or pi.get("ip") or pk)
        lines.append(f"Connected To : {', '.join(peers) if peers else '-'}")

        if ip in self.scan_results:
            lines.append("")
            lines.append("NODE SCAN RESULTS")
            lines.append("-" * 48)
            scan = self.scan_results[ip]
            lines.append(f"Status       : {scan.get('status', 'done')}")
            lines.append(f"Scanned Ports: {scan.get('port_range', '-')}")
            op = scan.get("open_ports", [])
            lines.append(f"Open Ports   : {', '.join(str(p) for p in op) if op else '-'}")
            issues = scan.get("issues", [])
            lines.append(f"Issues Found : {len(issues)}")
            for it in issues[:15]:
                lines.append(f"- [{it.get('severity', 'info')}] {it.get('text', '')}")

        if self.scan_status:
            lines.append("")
            lines.append(f"Scan Status  : {self.scan_status}")

        self.detail_text.insert("end", "\n".join(lines) + "\n")
        self.detail_text.configure(state="disabled")

    def _run_selected_scan(self):
        if not self.selected or self.selected not in self.nodes:
            self.scan_status = "Select a node first."
            self._refresh_detail_panel()
            return

        if not self.scan_callback:
            self.scan_status = "Node scan callback not configured."
            self._refresh_detail_panel()
            return

        ip = self.nodes[self.selected]["info"].get("ip") or ""
        if not ip or ip == "unknown":
            self.scan_status = "Selected node has no valid IP to scan."
            self._refresh_detail_panel()
            return

        self.scan_status = f"Scanning {ip}..."
        self._refresh_detail_panel()

        def worker():
            try:
                result = self.scan_callback(ip) or {}
                result["status"] = "done"
                self.scan_results[ip] = result
                self.scan_status = f"Scan complete for {ip}."
            except Exception as e:
                self.scan_status = f"Scan failed: {e}"
            finally:
                if self.root:
                    self.root.after(0, self._refresh_detail_panel)

        threading.Thread(target=worker, daemon=True).start()

    def _run_scan_all_nodes(self):
        """Scan every visible node with a valid IP."""
        if not self.scan_callback:
            self.scan_status = "Node scan callback not configured."
            self._refresh_detail_panel()
            return

        targets = []
        for nd in self.nodes.values():
            ip = nd["info"].get("ip") or ""
            if ip and ip != "unknown" and not ip.endswith(".255") and not ip.startswith("224."):
                targets.append(ip)

        # Deduplicate while keeping order.
        seen = set()
        targets = [ip for ip in targets if not (ip in seen or seen.add(ip))]

        if not targets:
            self.scan_status = "No scannable node IPs found."
            self._refresh_detail_panel()
            return

        self.scan_status = f"Scanning {len(targets)} nodes..."
        self._refresh_detail_panel()

        def worker():
            done = 0
            total = len(targets)
            for ip in targets:
                if self.stop_event.is_set():
                    break
                try:
                    result = self.scan_callback(ip) or {}
                    result["status"] = "done"
                    self.scan_results[ip] = result
                except Exception as e:
                    self.scan_results[ip] = {
                        "status": "failed",
                        "port_range": "-",
                        "open_ports": [],
                        "issues": [{"severity": "high", "text": str(e)}],
                    }
                done += 1
                self.scan_status = f"Scanned {done}/{total} nodes..."
                if self.root:
                    self.root.after(0, self._refresh_detail_panel)

            self.scan_status = f"Scan-all complete: {done}/{total} nodes."
            if self.root:
                self.root.after(0, self._refresh_detail_panel)

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------
    # Events + Main Loop
    # ------------------------------------------------------------

    def _on_click(self, event):
        self.last_mouse = (event.x, event.y)
        picked = self._pick_node(event.x, event.y)
        self.selected = picked
        if picked:
            self.dragging = picked
        else:
            self.panning = True
            self.pan_start = (event.x, event.y)
            self.cam_start = (self.cam_x, self.cam_y)
        self._refresh_detail_panel()

    def _on_release(self, _event):
        self.dragging = None
        self.panning = False

    def _on_motion(self, event):
        self.last_mouse = (event.x, event.y)
        if self.dragging and self.dragging in self.nodes:
            nd = self.nodes[self.dragging]
            wx, wy = self._s2w(event.x, event.y)
            nd["x"] = wx
            nd["y"] = wy
        elif self.panning:
            dx = (event.x - self.pan_start[0]) / max(0.1, self.zoom)
            dy = (event.y - self.pan_start[1]) / max(0.1, self.zoom)
            self.cam_x = self.cam_start[0] - dx
            self.cam_y = self.cam_start[1] - dy

    def _on_mousewheel(self, event):
        # Linux/Windows wheel compatibility.
        delta = 0
        if hasattr(event, "delta") and event.delta:
            delta = 1 if event.delta > 0 else -1
        elif getattr(event, "num", None) == 4:
            delta = 1
        elif getattr(event, "num", None) == 5:
            delta = -1
        if delta == 0:
            return

        wx_before, wy_before = self._s2w(event.x, event.y)
        if delta > 0:
            self.zoom = min(3.5, self.zoom * 1.12)
        else:
            self.zoom = max(0.35, self.zoom / 1.12)

        # Keep cursor-focused zoom.
        wx_after, wy_after = self._s2w(event.x, event.y)
        self.cam_x += (wx_before - wx_after)
        self.cam_y += (wy_before - wy_after)

    def _loop_tick(self):
        if self.stop_event.is_set():
            if self.root:
                self.root.destroy()
            return

        now = time.time()
        dt = max(0.01, min(0.06, now - self.last_tick))
        self.last_tick = now

        self._sync()
        stats = self.model.get_stats()
        self.history.append((
            int(stats.get("total_devices", 0)),
            int(stats.get("total_packets", 0)),
            int(stats.get("total_bytes", 0)),
        ))
        if len(self.history) > 360:
            self.history = self.history[-360:]
        self._step_physics(dt)
        self._draw()
        self._draw_protocol_chart(self.proto_canvas)
        self._draw_node_type_chart(self.type_canvas)
        self._draw_relation_chart(self.relation_canvas)
        self._draw_talker_chart(self.talker_canvas)
        self._draw_timeline_chart(self.timeline_canvas)
        self._draw_activity_feed(self.activity_canvas)

        self.root.after(33, self._loop_tick)

    def run(self):
        """Run native graph GUI until closed/stop event is set."""
        if tk is None:
            print("  [warn] Tkinter not available. Falling back to headless mode.")
            while not self.stop_event.is_set():
                time.sleep(0.5)
            return

        try:
            self.root = tk.Tk()
        except Exception as e:
            print(f"  [warn] Cannot start GUI: {e}")
            print("  [warn] Falling back to headless mode.")
            while not self.stop_event.is_set():
                time.sleep(0.5)
            return

        self.root.title(f"Grudarin v{__version__} - Built-in Graph View")
        self.root.geometry(f"{self.w}x{self.h}")
        self.root.configure(bg=self.BG)

        # Left graph canvas
        self.canvas = tk.Canvas(
            self.root,
            width=self.graph_w,
            height=self.h,
            bg=self.BG,
            highlightthickness=0,
        )
        self.canvas.pack(side="left", fill="both", expand=False)
        self.canvas.bind("<Button-1>", self._on_click)
        self.canvas.bind("<ButtonRelease-1>", self._on_release)
        self.canvas.bind("<B1-Motion>", self._on_motion)
        self.canvas.bind("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind("<Button-4>", self._on_mousewheel)
        self.canvas.bind("<Button-5>", self._on_mousewheel)

        # Right panel
        side = tk.Frame(self.root, width=self.w - self.graph_w, bg=self.PANEL)
        side.pack(side="right", fill="both", expand=True)

        title = tk.Label(
            side,
            text="GRUDARIN NODE INSPECTOR",
            bg=self.PANEL,
            fg=self.ACCENT,
            font=("Courier", 12, "bold"),
            anchor="w",
            padx=8,
            pady=6,
        )
        title.pack(fill="x")

        self.scan_btn = tk.Button(
            side,
            text="Scan Selected Node",
            command=self._run_selected_scan,
            bg="#202020",
            fg=self.TEXT,
            activebackground="#303030",
            activeforeground=self.TEXT,
            relief="flat",
            padx=8,
            pady=6,
        )
        self.scan_btn.pack(fill="x", padx=8, pady=(0, 8))

        self.scan_all_btn = tk.Button(
            side,
            text="Scan All Visible Nodes",
            command=self._run_scan_all_nodes,
            bg="#202020",
            fg=self.TEXT,
            activebackground="#303030",
            activeforeground=self.TEXT,
            relief="flat",
            padx=8,
            pady=6,
        )
        self.scan_all_btn.pack(fill="x", padx=8, pady=(0, 8))

        self.detail_text = tk.Text(
            side,
            height=20,
            bg="#0f0f0f",
            fg=self.TEXT,
            insertbackground=self.TEXT,
            relief="flat",
            wrap="word",
            font=("Courier", 9),
        )
        self.detail_text.pack(fill="x", padx=8)
        self.detail_text.configure(state="disabled")

        self.proto_canvas = tk.Canvas(
            side,
            width=360,
            height=170,
            bg=self.PANEL,
            highlightthickness=0,
        )
        self.proto_canvas.pack(fill="x", padx=8, pady=(8, 4))

        self.type_canvas = tk.Canvas(
            side,
            width=360,
            height=170,
            bg=self.PANEL,
            highlightthickness=0,
        )
        self.type_canvas.pack(fill="x", padx=8, pady=(0, 4))

        self.relation_canvas = tk.Canvas(
            side,
            width=360,
            height=170,
            bg=self.PANEL,
            highlightthickness=0,
        )
        self.relation_canvas.pack(fill="x", padx=8, pady=(0, 4))

        self.talker_canvas = tk.Canvas(
            side,
            width=360,
            height=170,
            bg=self.PANEL,
            highlightthickness=0,
        )
        self.talker_canvas.pack(fill="x", padx=8, pady=(4, 8))

        self.timeline_canvas = tk.Canvas(
            side,
            width=360,
            height=190,
            bg=self.PANEL,
            highlightthickness=0,
        )
        self.timeline_canvas.pack(fill="x", padx=8, pady=(0, 8))

        self.activity_canvas = tk.Canvas(
            side,
            width=360,
            height=200,
            bg=self.PANEL,
            highlightthickness=0,
        )
        self.activity_canvas.pack(fill="x", padx=8, pady=(0, 8))

        def on_close():
            print(f"\n  [info] Graph closed. Reports are stored in: {self.session_dir}")
            self.stop_event.set()
            self.root.destroy()

        self.root.protocol("WM_DELETE_WINDOW", on_close)

        self._refresh_detail_panel()
        self.root.after(50, self._loop_tick)

        try:
            self.root.mainloop()
        finally:
            self.stop_event.set()

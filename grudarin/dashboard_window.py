"""
Grudarin - Live Dashboard GUI (Tkinter)
High-information operational view focused on continuous monitoring.
"""

import time

from grudarin import __version__

try:
    import tkinter as tk
except Exception:
    tk = None


def _fmt_bytes(n):
    n = float(n or 0)
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.2f} {units[i]}"


class DashboardWindow:
    """Live network monitoring dashboard."""

    BG = "#0b1020"
    PANEL = "#141b32"
    CARD = "#1b2444"
    TEXT = "#e8ecff"
    DIM = "#9ea7cb"
    ACCENT = "#2dd4bf"
    WARN = "#f59e0b"

    def __init__(self, network_model, stop_event, interface_name="", target_ssid=""):
        self.model = network_model
        self.stop_event = stop_event
        self.interface_name = interface_name or "-"
        self.target_ssid = target_ssid or "N/A"
        self.root = None
        self.last_tick = time.time()

        self.total_var = None
        self.devices_var = None
        self.links_var = None
        self.data_var = None
        self.uptime_var = None
        self.proto_list = None
        self.device_list = None
        self.activity_text = None
        self.packet_list = None

    def _build(self):
        self.root = tk.Tk()
        self.root.title(f"Grudarin v{__version__} - Live Dashboard")
        self.root.geometry("1380x860")
        self.root.configure(bg=self.BG)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        header = tk.Frame(self.root, bg=self.PANEL, height=76)
        header.pack(fill="x")
        header.pack_propagate(False)

        title = tk.Label(
            header,
            text=(
                f"GRUDARIN LIVE ACTIVITY MONITOR  |  IFACE: {self.interface_name}"
                f"  |  SSID: {self.target_ssid}"
            ),
            bg=self.PANEL,
            fg=self.ACCENT,
            font=("Courier", 14, "bold"),
            anchor="w",
            padx=14,
        )
        title.pack(fill="both")

        stats = tk.Frame(self.root, bg=self.BG)
        stats.pack(fill="x", padx=12, pady=(12, 8))

        self.total_var = tk.StringVar(value="Packets: 0")
        self.devices_var = tk.StringVar(value="Devices: 0")
        self.links_var = tk.StringVar(value="Links: 0")
        self.data_var = tk.StringVar(value="Data: 0 B")
        self.uptime_var = tk.StringVar(value="Uptime: 0s")

        for var in [
            self.total_var,
            self.devices_var,
            self.links_var,
            self.data_var,
            self.uptime_var,
        ]:
            card = tk.Label(
                stats,
                textvariable=var,
                bg=self.CARD,
                fg=self.TEXT,
                font=("Courier", 12, "bold"),
                padx=14,
                pady=12,
                width=22,
                anchor="w",
            )
            card.pack(side="left", padx=(0, 8))

        body = tk.Frame(self.root, bg=self.BG)
        body.pack(fill="both", expand=True, padx=12, pady=(4, 12))

        left = tk.Frame(body, bg=self.PANEL)
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))

        right = tk.Frame(body, bg=self.PANEL, width=430)
        right.pack(side="right", fill="y", padx=(6, 0))
        right.pack_propagate(False)

        tk.Label(
            left,
            text="Top Devices",
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Courier", 11, "bold"),
        ).pack(anchor="w", padx=10, pady=(10, 4))
        self.device_list = tk.Listbox(left, bg="#0f1630", fg=self.TEXT, relief="flat", font=("Courier", 10))
        self.device_list.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        tk.Label(
            left,
            text="Recent Packets",
            bg=self.PANEL,
            fg=self.TEXT,
            font=("Courier", 11, "bold"),
        ).pack(anchor="w", padx=10, pady=(0, 4))
        self.packet_list = tk.Listbox(
            left,
            bg="#0f1630",
            fg=self.DIM,
            relief="flat",
            font=("Courier", 9),
            height=14,
        )
        self.packet_list.pack(fill="x", padx=10, pady=(0, 10))

        tk.Label(right, text="Protocol Distribution", bg=self.PANEL, fg=self.TEXT, font=("Courier", 11, "bold")).pack(anchor="w", padx=10, pady=(10, 4))
        self.proto_list = tk.Listbox(right, bg="#0f1630", fg=self.TEXT, relief="flat", font=("Courier", 10), height=14)
        self.proto_list.pack(fill="x", padx=10, pady=(0, 10))

        tk.Label(right, text="Recent Activity", bg=self.PANEL, fg=self.TEXT, font=("Courier", 11, "bold")).pack(anchor="w", padx=10, pady=(0, 4))
        self.activity_text = tk.Text(right, bg="#0f1630", fg=self.DIM, relief="flat", font=("Courier", 9), wrap="word")
        self.activity_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.activity_text.configure(state="disabled")

    def _on_close(self):
        self.stop_event.set()
        if self.root:
            self.root.destroy()

    def _tick(self):
        if self.stop_event.is_set():
            if self.root:
                self.root.destroy()
            return

        stats = self.model.get_stats()
        devices, connections = self.model.get_snapshot()

        self.total_var.set(f"Packets: {stats.get('total_packets', 0)}")
        self.devices_var.set(f"Devices: {stats.get('total_devices', 0)}")
        self.links_var.set(f"Links: {stats.get('total_connections', 0)}")
        self.data_var.set(f"Data: {_fmt_bytes(stats.get('total_bytes', 0))}")
        self.uptime_var.set(f"Uptime: {int(stats.get('uptime', 0))}s")

        self.proto_list.delete(0, tk.END)
        proto_counts = stats.get("protocol_counts", {})
        for proto, count in sorted(proto_counts.items(), key=lambda kv: kv[1], reverse=True)[:20]:
            self.proto_list.insert(tk.END, f"{proto:<12}  {count:>8}")

        self.device_list.delete(0, tk.END)
        rows = []
        for _, info in devices.items():
            pkt = int(info.get("packets_sent", 0)) + int(info.get("packets_received", 0))
            rows.append((pkt, info))
        rows.sort(key=lambda x: x[0], reverse=True)
        for pkt, info in rows[:60]:
            label = info.get("label") or info.get("ip") or info.get("mac") or "?"
            ip = info.get("ip", "-")
            vendor = info.get("vendor", "") or "-"
            self.device_list.insert(tk.END, f"{label[:24]:<24}  {ip:<16}  {pkt:>6} pkts  {vendor[:12]}")

        self.packet_list.delete(0, tk.END)
        for pkt in self.model.get_recent_packets(limit=24):
            ts = pkt.get("timestamp", "")[-8:]
            proto = pkt.get("protocol", "-")
            src = pkt.get("src_ip", "-")
            dst = pkt.get("dst_ip", "-")
            activity = pkt.get("activity", "")
            if activity:
                text = f"[{ts}] {proto:<7} {src} -> {activity}"
            else:
                text = f"[{ts}] {proto:<7} {src} -> {dst}"
            self.packet_list.insert(tk.END, text[:140])

        self.activity_text.configure(state="normal")
        self.activity_text.delete("1.0", tk.END)
        for ev in stats.get("recent_activity", [])[-30:]:
            t = ev.get("time", "")[-8:]
            src = ev.get("source_ip", "-")
            target = ev.get("target", "-")
            et = ev.get("event_type", "-")
            details = ev.get("details", "")
            line = f"[{t}] {src} -> {target} ({et})"
            if details:
                line += f" | {details}"
            self.activity_text.insert(tk.END, line[:220] + "\n")
        self.activity_text.configure(state="disabled")

        self.root.after(500, self._tick)

    def run(self):
        if tk is None:
            print("  [warn] Tkinter not available. Falling back to headless mode.")
            while not self.stop_event.is_set():
                time.sleep(0.5)
            return

        try:
            self._build()
        except Exception as e:
            print(f"  [warn] Cannot start dashboard GUI: {e}")
            print("  [warn] Falling back to headless mode.")
            while not self.stop_event.is_set():
                time.sleep(0.5)
            return

        self._tick()
        self.root.mainloop()

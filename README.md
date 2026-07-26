<div align=center>
<img width="300" alt="grudarin-logo" src="public/images/grudarin-logo.png" />

</div>

---

# Grudarin
>- Grudarin is an open-source network activity monitor and LAN mapper for authorized security analysis and education. It captures real-time traffic metadata, highlights destinations such as DNS, HTTP hostnames, and TLS SNI names when available, and helps operators understand how devices communicate on a network without breaking HTTPS encryption.
- real-time packet monitoring
- live activity and destination feed
- node-level vulnerability scanning
- dashboard-first native GUI
- markdown + JSON reporting

## Example output
> [!important]
> This tool is under active development.
  
<table>
  <tr>
    <td><img width="1322" height="767" alt="gru2" src="https://github.com/user-attachments/assets/575d7720-6c31-4b84-bce4-ff4a6fb94adb" /> </td>
    <td><img width="1323" height="767" alt="gru1" src="https://github.com/user-attachments/assets/e150b919-bc5e-4e40-9d57-5504ca559eab" /> </td>

  </tr>
</table>

## Key Capabilities

- Real-time activity dashboard for packets, destinations, devices, and protocols
- Optional LAN topology graph for structural mapping
- Flat orange/red nodes on a black dashboard
- Live edge relation labels and per-node connection labels
- Node inspector with:
  - IP, MAC, hostname, vendor, OS hint
  - protocols, services, open ports
  - packets/bytes and connected peers
- One-click node scan and scan-all-visible-nodes
- Live dashboard charts:
  - protocol distribution
  - node type distribution
  - relation/link type counts
  - top talkers
  - realtime timeline (nodes/events/bytes)
- Site scan mode with graph entities:
  - DNS_NAME, IP_ADDRESS, IP_RANGE, OPEN_TCP_PORT
  - URL, EMAIL_ADDRESS, STORAGE_BUCKET
  - ORG_STUB, USER_STUB
  - TECHNOLOGY, VULNERABILITY

## Tech Stack

| Language | Component | Purpose |
|----------|-----------|---------|
| **Python** | Core engine (`grudarin/`) | Packet capture (Scapy), data model, CLI, orchestration |
| **C++** | Port scanner (`scanner/scanner.cpp`) | Multi-threaded TCP port scanning, banner grabbing, CVE detection |
| **Go** | Network probe (`netprobe/netprobe.go`) | Concurrent host discovery, ARP table lookup, TCP fingerprinting |
| **Lua** | Rules engine (`lua_rules/security_rules.lua`) | Extensible security rules, misconfig detection, anomaly analysis |
| **Bash** | Install/Update/Uninstall (`*.sh`) | Cross-distro system setup, compilation, dependency management |
| **Batch** | Windows installer (`install.bat`) | Windows setup with MSVC/MinGW support |

>## visit the usage.md for more details : [Tap for more details.](usage.md)

## Installation

### Linux/macOS/WSL

```bash
git clone https://github.com/Chintanpatel24/grudarin.git
cd grudarin
chmod +x install.sh
sudo ./install.sh
```

### pip install (after PyPI publish)

```bash
pip install grudarin
```

If package is not published yet, install directly from GitHub:

```bash
pip install "git+https://github.com/Chintanpatel24/grudarin.git"
```

Or with pipx (recommended for CLI tools):

```bash
pipx install "git+https://github.com/Chintanpatel24/grudarin.git"
```

After publish to PyPI:

```bash
pipx install grudarin
```

Then run:

```bash
sudo grudarin --list
sudo grudarin --scan wlan0
grudarin --scan-site example.com
```

Update to latest version:

```bash
grudarin --update
```

### Windows

```text
1. Install Python 3.8+
2. Install Npcap (WinPcap compatibility mode)
3. Open CMD as Administrator
4. cd grudarin
5. install.bat
```

### Manual (any OS)

```bash
pip install scapy pygame
g++ -std=c++17 -O2 -Wall -pthread -o bin/grudarin_scanner scanner/scanner.cpp -lpthread
cd netprobe && go build -o ../bin/grudarin_netprobe netprobe.go && cd ..
```

## Features

- **Real-time packet capture** with protocol analysis (TCP, UDP, ICMP, ARP, DNS, DHCP, HTTP, HTTPS, SSH, FTP, SMB, RDP, SNMP, and more)
- **Live activity dashboard** with device, protocol, packet, and destination feeds
- **Node labels** showing IP, MAC address, vendor, hostname, and open ports under each device
- **Protocol labels** on graph edges showing what protocols flow between devices
- **C++ port scanner** with 38 vulnerability signatures and 34 dangerous port definitions
- **Go network probe** for fast concurrent host discovery across entire subnets
- **Lua security rules** with 12 rule categories (extensible with custom rules)
- **WiFi network discovery** showing available SSIDs, BSSIDs, signal strength
- **LAN detection** showing connected interfaces, gateways, and routes
- **ARP spoofing detection** (multiple MACs claiming same IP)
- **Broadcast storm detection** (excessive broadcast traffic ratios)
- **DNS anomaly detection** (potential tunneling or exfiltration)
- **Outdated software detection** (old SSH, Apache, nginx, PHP, IIS versions)
- **Known backdoor detection** (vsFTPd 2.3.4, ProFTPD 1.3.3)
- **Markdown reports** with security findings in red bold HTML at the end
- **JSON data export** for machine processing
- **Zero tracking, zero telemetry** - completely offline and private

> [!NOTE]
>- **Live Activity Monitor + Vulnerability Scanner + LAN Mapper**
>- **Grudarin** is an open-source cybersecurity tool for authorized monitoring that
>captures live network activity, discovers devices, scans for vulnerabilities and
>misconfigurations, maps LAN structure when needed, and saves detailed reports in
>Markdown with security findings highlighted in red bold text.

## Quick launcher (local)

A small launcher is provided in `bin/grudarin` to run the project without installing globally. To make `grudarin` available system-wide, one of these options is recommended:

- Use the installer (recommended):

```bash
cd /path/to/grudarin
sudo ./install.sh
```

- Symlink the provided launcher (manual):

```bash
cd /path/to/grudarin
sudo ln -sf "$(pwd)/grudarin.sh" /usr/local/bin/grudarin
# or use the lightweight launcher
sudo ln -sf "$(pwd)/bin/grudarin" /usr/local/bin/grudarin
sudo chmod +x /usr/local/bin/grudarin
```

- Editable/developer install (no system-wide changes):

```bash
cd /path/to/grudarin
python3 -m pip install --user -e .
```

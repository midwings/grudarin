<div align=center>
<pre>                                                                                                
                                         +++ ++++                                                                 
                                       +++++++++       +++++++++                                                  
                                      +++++++++     ++++++++++++++++++                                            
                                    ++++++ +++++++    ++++   +=+++++++++++                                        
                                  ++++++  +=+=++++++   ++++ +++=+++=++++++++                                      
                                ++++++++  +++=+=++++++  ++++  ++++++++++++++++                                    
                                +++++++   +++++++==+++   +++  ++++++++++++++++++                                  
                               ++++     ++++++++++=++++  +++    +=  +++++++++++++                                 
                             ++++  ++++++++ +++++++++++  +++ ++ +++=++++++++++++++                                
                             ++++++++       +++++++++++  +++ ++=+++++=+++++++++++++                               
                              +++++        +++ ++++++++  +++ +++++++++ =+ ++++++++++                              
                                         ++++++++++++++ +++ ++=+===+++++ ++++++++++++                             
                                       +++++ +++++++++ +++++++===+==+++++++++   +++++                             
                                      ++++  +++ +++++ ++++++++++==+++++++++   ++  +++                             
                                     +++++++++ +++++++++ ++++++=+++++++++++   +++ +++                             
                                    +++   +++++++++++++++++++++++++++       += ++ +++                             
                                   +++   +++++++++++ +++++++++++++++++++   +++ ++ +++                             
                                  ++++++++++ +++++=+ ++++++++ =    ++++++++++ +++++++                             
                                  +++++++++++++    +        +++++   +  ++++++ +++++++                             
                                  ++++   +++++ +         +++++ +++++ ++ ++++ +++++++                              
                                  +++++++++++ += +++  +++++      ++++ +++++++++++++                               
                                  +++++++ +++ + ++++++++         ++++++++++++++++++                               
                                   +++++++++++++ +++++          ++++++++++++++++++                                
                                   +++++++++++++=++++          +++++++++++++++++                                  
                                    +++++++++++  ++++       +++++++++++++++++++                                   
                                      +++++++++++++++++++++++++++++++++++++++                                     
                               +++++++ ++++++++++++++++++++++++++++++++++++                                       
                             ++++++++++++++++++++++++++++++++++++++++++++                                         
                              ++++++++       ++++++++++++++++++++++++                                             
                              ++++++++++++++++++++++++++++++++++
         ++++++++++      +++++    +++++    +++  +++++++++++      +++++     ++++++++++  ++++ +++++    +++++         
       +++++++++++++   +++++++   +++++    +++  ++++++++++++    +++++++    +++++++++++ ++++ +++++++  +++++         
      +++++     +++    ++++++++  +++++    +++  ++++    +++++  +++++++++   ++++   ++++ ++++ ++++++++ +++++         
      ++++  +++++++++ ++++ +++++ +++++    +++  ++++     ++++  ++++ ++++   +++++++++++ ++++ ++++++++++++++         
      +++++  +++++++++++++++++++ +++++    +++  ++++    +++++ +++++++++++  +++++++++   ++++ +++++ ++++++++         
       ++++++++++++++++++++++++++ +++++++++++  ++++++++++++ +++++++++++++ ++++ +++++  ++++ +++++  +++++++         
         +++++++++  ++++     +++++  ++++++++   ++++++++++   ++++     +++++++++  +++++ ++++ +++++   ++++++         
                                                                                                                  
</pre></div>

## Usage

```bash
# interactive mode
sudo grudarin

# list interfaces and wifi
sudo grudarin --list

# live network scan (graph GUI)
sudo grudarin --scan wlan0

# headless network scan
sudo grudarin --scan eth0 --no-graph -d 120

# site/domain scan (live graph entities)
grudarin --scan-site example.invalid
```

## Built-in Graph Controls

- Left click node: select and inspect full details
- Left drag node: move node
- Left drag background: pan graph
- Mouse wheel: zoom in/out
- Scan Selected Node: targeted node scan
- Scan All Visible Nodes: bulk node scan
- Ctrl+C or close window: stop scan

## Reports and Output

Each scan session writes output to a timestamped folder under `grudarin_output/`:

- `session_report.md` (human-readable report)
- `session_data.json` (machine-readable report)
- `packets.log` (capture/recon event stream)

When scan is closed, Grudarin prints the session output path in terminal.

## Security Rules

Custom rules can be added in:
- `lua_rules/security_rules.lua`


## Workflow

```
Step 1: List available networks
  $ sudo grudarin --list

Step 2: Start scanning
  $ sudo grudarin --scan wlan0

Step 3: Tool asks for save path and note name
  Enter path to save notes: ~/my_reports
  Enter a name for this scan: home_network

Step 4: Live monitoring begins
  - Terminal shows real-time packet counts, device counts, data volume
  - Graph window opens showing network topology
  - Devices appear as nodes, connections as edges
  - Labels show IP, MAC, vendor, ports under each node

Step 5: Stop with Ctrl+C or Q in graph window
  - Vulnerability scan runs on discovered devices
  - Security rules analyze traffic patterns
  - Markdown report saved with findings in RED
```

## Usage

```bash
# Interactive mode (guides you through everything)
sudo grudarin

# List interfaces, WiFi networks, connected LANs
sudo grudarin --list

# Scan a specific interface
sudo grudarin --scan wlan0

# Scan with output path and session name
sudo grudarin --scan eth0 -o ~/reports --name office_scan

# Scan all 65535 ports on specific targets
sudo grudarin --scan wlan0 --ports 1-65535 --targets 192.168.1.1,192.168.1.100

# Headless mode (no graph, terminal only)
sudo grudarin --scan eth0 --no-graph -d 120

# Capture only, no vuln scanning
sudo grudarin --scan wlan0 --no-scan

# With BPF filter
sudo grudarin --scan wlan0 -f "tcp port 80 or tcp port 443"

# Full help
grudarin --help

# Update tool to latest version
grudarin --update
```

## Graph Controls

| Action | Function |
|--------|----------|
| Mouse Wheel | Zoom in/out |
| Left Click + Drag Node | Move device node |
| Left Click + Drag Background | Pan camera |
| Right Click Node | Show device details panel |
| `P` | Pause/resume physics simulation |
| `S` | Save graph as PNG snapshot |
| `R` | Reset graph layout |
| `L` | Toggle label visibility |
| `M` | Toggle MAC address display |
| `Tab` | Toggle protocol stats panel |
| `Q` / `Esc` | Quit and save report |



## Security Rules

The tool checks for these categories of issues:

| Category | Severity | What it Detects |
|----------|----------|-----------------|
| Insecure Protocols | CRITICAL-MEDIUM | Telnet, FTP, unencrypted HTTP, SNMP, SMB |
| Dangerous Ports | CRITICAL-HIGH | Redis, MongoDB, Metasploit, ADB, VNC exposed |
| ARP Spoofing | CRITICAL | Multiple MACs on same IP (MITM attack) |
| Broadcast Storm | HIGH | Excessive broadcast traffic ratios |
| DNS Anomalies | HIGH | Possible DNS tunneling or exfiltration |
| Rogue DHCP | HIGH | Excessive DHCP traffic (rogue server) |
| Outdated Software | CRITICAL-MEDIUM | Old SSH, Apache, nginx, PHP, IIS versions |
| Known Backdoors | CRITICAL | vsFTPd 2.3.4, ProFTPD 1.3.3 |
| Exposed Databases | CRITICAL-HIGH | MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch |
| Gateway Issues | HIGH-MEDIUM | Multiple gateways, missing gateway |
| Unknown Devices | MEDIUM | Unidentified devices on network |
| Excessive Ports | HIGH | Devices with too many open ports |

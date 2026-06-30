# Persistent Passive Monitoring

## Overview

Persistent mode provides continuous passive traffic analysis, monitoring real network connections as they happen.

## Architecture

- **Daemon**: `persistent-monitor.py` runs as a systemd service
- **Capture**: Uses `quantum-sniffer -i INTERFACE` to capture live packets
- **Output**: Streams JSONL events to rolling log files
- **Logs**: `/var/log/quantum-sniffer/pqc-monitor-{hostname}-{timestamp}.jsonl`
- **Rotation**: Automatically rotates old logs (keeps last 30 files)

## Deployment

```bash
cd quantum-sniffer
sudo ./deploy-monitor.sh --persistent
```

This installs:
- `/opt/quantum-sniffer/persistent-monitor.py` - Daemon script
- `/etc/systemd/system/quantum-sniffer-monitor@.service` - Service template  
- Service enabled for `eth0` interface by default

## Management

```bash
# Check status
sudo systemctl status quantum-sniffer-monitor@eth0.service

# View logs
sudo journalctl -u quantum-sniffer-monitor@eth0.service -f

# Stop monitoring
sudo systemctl stop quantum-sniffer-monitor@eth0.service

# Start monitoring
sudo systemctl start quantum-sniffer-monitor@eth0.service

# Change interface
sudo systemctl disable quantum-sniffer-monitor@eth0.service
sudo systemctl enable quantum-sniffer-monitor@ens3.service
sudo systemctl start quantum-sniffer-monitor@ens3.service
```

## Log Format

### JSONL Event Stream

Each line in the `.jsonl` files is a complete JSON object representing one connection event:

```json
{
  "protocol": "SSH",
  "type": "SSH KEX Init",
  "timestamp": "2026-06-30T09:33:15.014050",
  "post_quantum_secure": "Hybrid",
  "src_ip": "10.22.22.10",
  "src_port": 22,
  "dst_ip": "10.22.22.4",
  "dst_port": 33530,
  "connection": "10.22.22.10:22 -> 10.22.22.4:33530",
  "direction": "inbound",
  "encrypted": true,
  "ssh_kex_algorithms": ["sntrup761x25519-sha512@openssh.com", ...]
}
```

### Key Fields

- `protocol`: Protocol detected (SSH, TLS, QUIC, etc.)
- `type`: Event type (SSH Banner, SSH KEX Init, TLS ClientHello, etc.)
- `timestamp`: ISO 8601 timestamp
- `post_quantum_secure`: PQ status (Hybrid, Yes, No, Unknown)
- `src_ip`, `src_port`: Source address
- `dst_ip`, `dst_port`: Destination address  
- `direction`: `inbound` or `outbound`
- `encrypted`: Boolean - is connection encrypted
- Protocol-specific fields (ssh_kex_algorithms, tls_version, etc.)

### Differences from Self-Scan Format

**Self-Scan (Active Scanning):**
- Single JSON file with aggregated results
- Structure: `{"scan_results": {"results": [...]}}`
- Fields: `target_ip`, `target_port`, `status` (open/closed/error)
- Summary statistics included

**Persistent Monitoring (Passive Capture):**
- JSONL stream (one JSON per line)
- Each event is independent
- Fields: `src_ip`, `src_port`, `dst_ip`, `dst_port`, `direction`
- No aggregation - raw event stream

## Integration with UPCE

### Current Status

- ✅ Persistent monitoring deployed to web-server, app-server, db-server
- ✅ Capturing and logging SSH connections with PQ status
- ❌ NOT YET integrated with UPCE database/UI

### TODO: Database Integration

The UPCE database (`upce_pqc.ports` table) currently expects self-scan format data:
- Single scan with multiple ports
- Aggregated per workload
- Status: open/closed/error/timeout

Persistent monitoring produces:
- Streaming events
- Per-connection granularity  
- Direction: inbound/outbound

**Options:**

1. **Separate table for passive events**
   - Create `pqc_connections` table for streaming events
   - Keep `ports` table for self-scan results
   - UI shows both active scan results and passive monitoring

2. **Aggregate JSONL to scan format**
   - Process JSONL files periodically
   - Aggregate by workload and port
   - Insert as "passive scan" results into existing `ports` table

3. **Real-time streaming to database**
   - Modify persistent-monitor.py to write directly to database
   - Each connection event inserted as it's captured
   - Most complex but most powerful

### TODO: Log Collector Updates

Current log collector (`/opt/upce/back-end/quantum_sniffer/log_collector.py`):
- Fetches `/var/log/quantum-sniffer/self-scan.json`
- Parses self-scan format
- Stores in `upce_pqc.scans` and `ports` tables

Needs to handle persistent monitoring:
- Fetch latest `.jsonl` files
- Parse JSONL format (one JSON per line)
- Aggregate or store events appropriately

## Requirements

- **Root/sudo**: Required for packet capture (CAP_NET_RAW capability)
- **Scapy**: Python packet capture library
- **quantum-sniffer**: PQC analysis engine

## Known Issues

- **Interface name**: Service uses interface name from systemd instance (e.g., `@eth0`)
  - Must match actual interface name on host
  - Check with: `ip link show`
  
- **Scapy in venv**: If using venv, scapy must be available
  - System-wide: `sudo pip install --break-system-packages scapy`
  - In venv: `sudo cp -r /usr/local/lib/python3.12/dist-packages/scapy* /opt/quantum-sniffer/venv/lib/python3.12/site-packages/`

- **Log volume**: Can generate large amounts of data on busy hosts
  - Automatic rotation helps (keeps last 30 sessions)
  - Each session lasts until quantum-sniffer restarts
  - Consider disk space on busy production hosts

## Example: Viewing Live Captures

```bash
# Watch events in real-time
sudo tail -f /var/log/quantum-sniffer/pqc-monitor-*.jsonl | jq .

# Count connections by PQ status
cat /var/log/quantum-sniffer/pqc-monitor-*.jsonl | \
  jq -r '.post_quantum_secure' | sort | uniq -c

# Find non-PQ connections
cat /var/log/quantum-sniffer/pqc-monitor-*.jsonl | \
  jq 'select(.post_quantum_secure == "No")'

# SSH connections with PQ status
cat /var/log/quantum-sniffer/pqc-monitor-*.jsonl | \
  jq 'select(.protocol == "SSH" and .type == "SSH KEX Init") | {src: .src_ip, dst: .dst_ip, port: .dst_port, pq: .post_quantum_secure}'
```

## Security Considerations

- Service runs as root (required for packet capture)
- Security hardening in systemd unit:
  - `NoNewPrivileges=true`
  - `PrivateTmp=true`
  - `ProtectSystem=strict`
  - `ProtectHome=true`
  - Minimal capabilities: `CAP_NET_RAW`, `CAP_NET_ADMIN`

- Logs may contain sensitive information:
  - IP addresses
  - Port numbers
  - Connection patterns
  - Protect `/var/log/quantum-sniffer/` accordingly

## Performance

- **CPU**: Minimal (<5% on typical workload)
- **Memory**: ~10-20MB per instance
- **Disk I/O**: Depends on connection rate
  - Low traffic: ~100KB/hour
  - High traffic: Several MB/hour
- **Network**: Passive capture, no additional traffic generated

# Self-Scan Mode - Automated Daily PQ Crypto Testing

Automatically scan this machine's external services daily for post-quantum crypto support.

## Overview

The self-scan feature:
1. ✅ Discovers services listening on external interfaces (not localhost)
2. ✅ Runs quantum-sniffer active probes against discovered services
3. ✅ Outputs complete results in JSON format
4. ✅ Runs daily via cron (2 AM by default)
5. ✅ Suitable for deployment on hundreds of machines

**Use cases:**
- Monitor your infrastructure for PQ crypto adoption
- Automated compliance checking
- Track services as they're upgraded
- Generate inventory of externally-accessible services

## Quick Start

### One-Command Deployment

```bash
cd ~/quantum-sniffer

# System-wide installation (requires sudo)
sudo ./deploy-self-scan.sh

# Or user-only installation (no sudo)
./deploy-self-scan.sh --user-cron
```

This will:
- Install quantum-sniffer (if needed)
- Test the self-scan
- Set up daily cron job (2 AM)
- Configure log rotation
- Create `/var/log/quantum-sniffer/self-scan.json`

### Manual Execution

```bash
# Run once manually
./self-scan.py

# Run and save to file
./self-scan.py > today-scan.json

# View summary from saved file
jq '.summary' today-scan.json
```

## How It Works

### Service Discovery

**Discovers services listening on:**
- `0.0.0.0` (all interfaces)
- Specific external IP addresses (e.g., `10.1.1.50`)
- IPv6 equivalents (`::`)

**Excludes services listening ONLY on:**
- `127.0.0.1` (localhost IPv4)
- `::1` (localhost IPv6)

**Discovery method:**
1. Uses `ss -tuln` (preferred) or `netstat -tuln` (fallback)
2. Parses listening TCP/UDP ports
3. Filters to only external-facing services
4. Returns list of ports to scan

**Example discovery output:**
```json
{
  "primary_ip": "10.1.1.50",
  "ports": [22, 80, 443, 3389],
  "details": {
    "22": ["0.0.0.0", "::"],
    "80": ["0.0.0.0"],
    "443": ["0.0.0.0", "::"],
    "3389": ["10.1.1.50"]
  },
  "tool_used": "ss"
}
```

### Active Scanning

**For each discovered port:**
1. Runs quantum-sniffer active probe
2. Tests primary external IP address
3. Determines PQ crypto support
4. Records detailed results

**Scan configuration:**
- Mode: Active probe (not passive capture)
- Target: Primary external IP
- Ports: All discovered external ports
- Timeout: 5 seconds per connection
- Workers: 10 parallel probes

### JSON Output

**Complete output structure:**
```json
{
  "scan_info": {
    "hostname": "web-prod-1",
    "timestamp": "2026-06-29T02:00:15.123456",
    "scan_type": "self-scan",
    "tool": "quantum-sniffer self-scan",
    "version": "0.4.1",
    "end_time": "2026-06-29T02:00:47.234567",
    "duration_seconds": 32.11
  },
  "discovery": {
    "primary_ip": "10.1.1.50",
    "ports": [22, 443, 3389],
    "details": {...},
    "tool_used": "ss"
  },
  "scan_results": {
    "metadata": {...},
    "summary": {
      "total_ports_scanned": 3,
      "open_ports": 3,
      "closed_ports": 0,
      "pq_capable_ports": 2
    },
    "results": [
      {
        "target_ip": "10.1.1.50",
        "target_port": 22,
        "status": "open",
        "protocol": "ssh",
        "post_quantum_secure": "Hybrid",
        "extras": {
          "ssh_banner": "SSH-2.0-OpenSSH_8.9p1",
          "ssh_kex_algorithms": ["sntrup761x25519-sha512@openssh.com", ...]
        }
      },
      {
        "target_ip": "10.1.1.50",
        "target_port": 443,
        "status": "open",
        "protocol": "tls",
        "post_quantum_secure": "No",
        "tls_version": "TLSv1.3",
        "cipher_suite": "TLS_AES_256_GCM_SHA384"
      },
      {
        "target_ip": "10.1.1.50",
        "target_port": 3389,
        "status": "open",
        "protocol": "rdp",
        "post_quantum_secure": "Unknown"
      }
    ]
  },
  "summary": {
    "total_ports_scanned": 3,
    "open_ports": 3,
    "closed_ports": 0,
    "pq_capable_ports": 2,
    "pq_percentage": 66.7
  },
  "errors": []
}
```

## Deployment

### System-Wide Installation (Recommended)

```bash
cd ~/quantum-sniffer
sudo ./deploy-self-scan.sh
```

**Creates:**
- `/opt/quantum-sniffer/` - Quantum-sniffer installation
- `/var/log/quantum-sniffer/self-scan.json` - Daily results
- `/etc/cron.d/quantum-sniffer-self-scan` - Cron job
- `/etc/logrotate.d/quantum-sniffer` - Log rotation (30 days)

**Runs:**
- Daily at 2:00 AM as root

**Requires:**
- sudo access
- Python 3.9+

### User Installation (No Sudo)

```bash
cd ~/quantum-sniffer
./deploy-self-scan.sh --user-cron
```

**Creates:**
- `~/.local/share/quantum-sniffer/` - Installation
- `~/.local/log/quantum-sniffer/self-scan.json` - Daily results
- User crontab entry

**Runs:**
- Daily at 2:00 AM as current user

**Note:** Cannot scan privileged ports (<1024) as non-root user.

### Manual Installation

```bash
# 1. Copy scripts to target location
sudo mkdir -p /opt/quantum-sniffer
sudo cp -r ~/quantum-sniffer/* /opt/quantum-sniffer/

# 2. Install dependencies
cd /opt/quantum-sniffer
python3 -m venv venv
venv/bin/pip install scapy cryptography python-dotenv

# 3. Create log directory
sudo mkdir -p /var/log/quantum-sniffer

# 4. Test
/opt/quantum-sniffer/self-scan.py

# 5. Add to cron
sudo crontab -e
# Add line:
0 2 * * * /opt/quantum-sniffer/self-scan.py > /var/log/quantum-sniffer/self-scan.json 2>&1
```

## Usage Examples

### View Latest Results

```bash
# View entire output
cat /var/log/quantum-sniffer/self-scan.json

# Pretty print with jq
jq . /var/log/quantum-sniffer/self-scan.json

# View summary only
jq '.summary' /var/log/quantum-sniffer/self-scan.json
```

### Extract Specific Information

```bash
# Get PQ status of each port
jq '.scan_results.results[] | {port: .target_port, status: .status, pq: .post_quantum_secure}' /var/log/quantum-sniffer/self-scan.json

# List PQ-capable services
jq '.scan_results.results[] | select(.post_quantum_secure == "Yes" or .post_quantum_secure == "Hybrid") | {port: .target_port, protocol: .protocol}' /var/log/quantum-sniffer/self-scan.json

# List quantum-vulnerable services
jq '.scan_results.results[] | select(.post_quantum_secure == "No") | {port: .target_port, protocol: .protocol, tls_version: .tls_version}' /var/log/quantum-sniffer/self-scan.json

# Get timestamp of last scan
jq -r '.scan_info.timestamp' /var/log/quantum-sniffer/self-scan.json

# Get compliance percentage
jq -r '.summary.pq_percentage' /var/log/quantum-sniffer/self-scan.json
```

### Run Manual Scan

```bash
# Run immediately
/opt/quantum-sniffer/self-scan.py

# Run and save to custom file
/opt/quantum-sniffer/self-scan.py > /tmp/test-scan.json

# Run with different python
python3 /opt/quantum-sniffer/self-scan.py
```

### Check Cron Status

```bash
# System-wide cron
cat /etc/cron.d/quantum-sniffer-self-scan

# User cron
crontab -l | grep quantum-sniffer

# View cron execution logs
grep quantum-sniffer /var/log/syslog
# or
journalctl -t CRON | grep quantum-sniffer
```

## Collecting Results from Multiple Machines

### Option 1: Centralized Logging (rsyslog)

Configure remote logging on each machine:

```bash
# On each machine: /etc/rsyslog.d/quantum-sniffer.conf
$ModLoad imfile
$InputFileName /var/log/quantum-sniffer/self-scan.json
$InputFileTag quantum-sniffer:
$InputFileStateFile stat-quantum-sniffer
$InputFileSeverity info
$InputFileFacility local7
$InputRunFileMonitor

local7.* @@central-log-server:514
```

### Option 2: Pull from Central Server

```bash
#!/bin/bash
# collect-all-scans.sh - Run on central server

HOSTS_FILE="hosts.txt"  # One hostname per line
RESULTS_DIR="/var/log/quantum-sniffer/collected"

mkdir -p "$RESULTS_DIR"

while read -r host; do
  echo "Collecting from $host..."
  scp "$host:/var/log/quantum-sniffer/self-scan.json" \
    "$RESULTS_DIR/${host}-$(date +%Y%m%d).json" 2>/dev/null || echo "  Failed"
done < "$HOSTS_FILE"

echo "Results collected to $RESULTS_DIR/"
```

### Option 3: Ansible Collection

```yaml
# collect-self-scans.yml
- name: Collect self-scan results
  hosts: all
  tasks:
    - name: Fetch self-scan results
      fetch:
        src: /var/log/quantum-sniffer/self-scan.json
        dest: collected/{{ inventory_hostname }}-{{ ansible_date_time.date }}.json
        flat: yes
```

Run:
```bash
ansible-playbook -i inventory.ini collect-self-scans.yml
```

### Option 4: API Push (Future Enhancement)

Each machine posts results to central API:

```bash
# In cron job
/opt/quantum-sniffer/self-scan.py | curl -X POST \
  -H "Content-Type: application/json" \
  -d @- \
  https://central-server/api/pq-scan-results
```

## Integration Examples

### Compliance Dashboard

```python
#!/usr/bin/env python3
# Generate compliance dashboard from collected results

import json
import glob
from datetime import datetime

results_dir = "/var/log/quantum-sniffer/collected"
results = []

for file_path in glob.glob(f"{results_dir}/*.json"):
    with open(file_path) as f:
        data = json.load(f)
        hostname = data['scan_info']['hostname']
        pq_pct = data['summary']['pq_percentage']
        timestamp = data['scan_info']['timestamp']

        results.append({
            'hostname': hostname,
            'pq_percentage': pq_pct,
            'timestamp': timestamp
        })

# Sort by PQ percentage
results.sort(key=lambda x: x['pq_percentage'])

print("PQ Crypto Compliance Dashboard")
print("=" * 60)
for r in results:
    bar_length = int(r['pq_percentage'] / 5)
    bar = '█' * bar_length + '░' * (20 - bar_length)
    print(f"{r['hostname']:20s} {bar} {r['pq_percentage']:5.1f}%")

total_pct = sum(r['pq_percentage'] for r in results) / len(results)
print("=" * 60)
print(f"Average: {total_pct:.1f}%")
```

### Alert on Regression

```bash
#!/bin/bash
# alert-on-regression.sh - Detect PQ downgrades

CURRENT="/var/log/quantum-sniffer/self-scan.json"
PREVIOUS="/var/log/quantum-sniffer/self-scan.json.1"

if [ ! -f "$PREVIOUS" ]; then
  exit 0
fi

CURRENT_PCT=$(jq -r '.summary.pq_percentage' "$CURRENT")
PREVIOUS_PCT=$(jq -r '.summary.pq_percentage' "$PREVIOUS")

DIFF=$(echo "$CURRENT_PCT - $PREVIOUS_PCT" | bc)

if (( $(echo "$DIFF < -5" | bc -l) )); then
  HOSTNAME=$(hostname)
  echo "ALERT: PQ compliance dropped on $HOSTNAME: $PREVIOUS_PCT% -> $CURRENT_PCT%"
  # Send alert (email, Slack, etc.)
fi
```

Add to cron after self-scan:
```
0 2 * * * /opt/quantum-sniffer/self-scan.py > /var/log/quantum-sniffer/self-scan.json 2>&1
5 2 * * * /opt/quantum-sniffer/alert-on-regression.sh
```

### Export to Prometheus

```python
#!/usr/bin/env python3
# prometheus-exporter.py - Export metrics for Prometheus

import json
from prometheus_client import start_http_server, Gauge
import time

pq_percentage = Gauge('quantum_sniffer_pq_percentage', 'PQ crypto percentage', ['hostname'])
open_ports = Gauge('quantum_sniffer_open_ports', 'Number of open ports', ['hostname'])
pq_capable_ports = Gauge('quantum_sniffer_pq_capable_ports', 'Number of PQ-capable ports', ['hostname'])

def update_metrics():
    with open('/var/log/quantum-sniffer/self-scan.json') as f:
        data = json.load(f)

    hostname = data['scan_info']['hostname']
    pq_percentage.labels(hostname=hostname).set(data['summary']['pq_percentage'])
    open_ports.labels(hostname=hostname).set(data['summary']['open_ports'])
    pq_capable_ports.labels(hostname=hostname).set(data['summary']['pq_capable_ports'])

if __name__ == '__main__':
    start_http_server(9100)
    while True:
        update_metrics()
        time.sleep(60)
```

## Troubleshooting

### No External Ports Found

**Symptom:**
```json
{
  "errors": ["No externally-accessible ports found"]
}
```

**Causes:**
1. No services listening on external interfaces
2. All services listen only on 127.0.0.1
3. Firewall blocking access to `ss`/`netstat`

**Solutions:**
```bash
# Check listening ports manually
ss -tuln | grep LISTEN

# Check if services bound to localhost only
ss -tuln | grep 127.0.0.1

# Verify firewall allows external access
sudo iptables -L -n | grep INPUT
```

### Cannot Determine Primary IP

**Symptom:**
```json
{
  "errors": ["Could not determine primary IP address"]
}
```

**Solutions:**
```bash
# Check network interfaces
ip addr show

# Check default route
ip route show default

# Manual override in script (edit self-scan.py)
# Set primary_ip explicitly
```

### Quantum-Sniffer Not Found

**Symptom:**
```json
{
  "errors": ["quantum-sniffer not found"]
}
```

**Solutions:**
```bash
# Install quantum-sniffer
pip install quantum-sniffer

# Or use venv
cd /opt/quantum-sniffer
python3 -m venv venv
venv/bin/pip install scapy cryptography python-dotenv

# Verify installation
quantum-sniffer --help
# or
python3 -m quantum_sniffer --help
```

### Cron Job Not Running

**Check cron service:**
```bash
# System cron
systemctl status cron

# View cron logs
grep CRON /var/log/syslog | grep quantum-sniffer

# Test cron entry manually
/opt/quantum-sniffer/self-scan.py
```

**Common issues:**
- Script not executable: `chmod +x /opt/quantum-sniffer/self-scan.py`
- Wrong path in cron: Use absolute paths
- Permissions: System cron should run as root

### JSON Parse Errors

**Symptom:** `jq` fails to parse results

**Solutions:**
```bash
# Check if file is valid JSON
jq empty /var/log/quantum-sniffer/self-scan.json

# View raw file
cat /var/log/quantum-sniffer/self-scan.json

# Check for partial writes (file truncated)
ls -lh /var/log/quantum-sniffer/self-scan.json

# Rerun scan
/opt/quantum-sniffer/self-scan.py > /tmp/test.json
jq . /tmp/test.json
```

## Performance

**Typical execution time:**
- Discovery: ~1 second
- Scan (5 ports): ~10-30 seconds
- JSON output: <1 second
- **Total: ~30-60 seconds**

**Resource usage:**
- CPU: Low (1-5% during scan)
- Memory: ~50-100 MB
- Network: Minimal (only outbound probes)
- Disk: <1 KB per day (JSON results)

**Scaling:**
- Can run on hundreds of machines simultaneously
- No central coordination needed
- Each machine operates independently

## Security Considerations

### Privileges

**Running as root (system-wide):**
- ✅ Can scan all ports including <1024
- ✅ Can write to /var/log/
- ⚠️ Runs with full system privileges

**Running as user:**
- ✅ Lower privilege level
- ❌ Cannot scan privileged ports
- ⚠️ May not detect all services

**Recommendation:** Run as root for complete coverage.

### Network Impact

**Scan characteristics:**
- Outbound connections only (to 127.0.0.1)
- No external network traffic
- Short-lived connections (5s timeout)
- Low bandwidth usage

**Safe for production:** Yes, minimal impact.

### Data Sensitivity

**Results contain:**
- Hostnames
- IP addresses
- Open ports
- Service versions (SSH banner, TLS version)
- PQ crypto status

**Protection:**
- Restrict access to log files: `chmod 600 /var/log/quantum-sniffer/self-scan.json`
- Encrypt during transmission if collecting remotely
- Consider anonymizing before sharing

## Files

```
quantum-sniffer/
├── discover-external-services.py   # Service discovery (220 lines)
├── self-scan.py                    # Main self-scan script (250 lines)
├── deploy-self-scan.sh             # Deployment automation (200 lines)
└── SELF_SCAN.md                    # This documentation

After deployment (system-wide):
/opt/quantum-sniffer/              # Installation directory
/var/log/quantum-sniffer/          # Log directory
  └── self-scan.json               # Daily results
/etc/cron.d/quantum-sniffer-self-scan   # Cron job
/etc/logrotate.d/quantum-sniffer        # Log rotation

After deployment (user):
~/.local/share/quantum-sniffer/    # Installation
~/.local/log/quantum-sniffer/      # Logs
  └── self-scan.json
~/.crontab                         # User cron (contains entry)
```

## Future Enhancements

1. **History tracking** - Store trend data, detect changes over time
2. **Central API** - Push results to central server automatically
3. **Alerting** - Email/Slack notifications on downgrades
4. **Web dashboard** - Real-time visualization of fleet status
5. **Filtering** - Skip certain ports/services
6. **Custom schedule** - Configurable scan frequency
7. **IPv6 support** - Better IPv6 handling and scanning
8. **Service correlation** - Match ports to systemd units/processes

## License

GNU General Public License v3.0 (same as quantum-sniffer)

---

**Summary:** Self-scan provides automated, zero-configuration daily testing of external services for post-quantum crypto support. Deploy once, monitor continuously.
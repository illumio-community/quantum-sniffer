# quantum-sniffer

A network traffic analyzer and active prober that captures and classifies cryptographic
handshakes from encrypted protocols (TLS, SSH, IPsec, QUIC, WireGuard, and more) and tags 
each one as **post-quantum secure**, **hybrid**, **classical**, or **unknown**.

> **Status: alpha.** Public protocols and CLI flags may change.

## Features

### Passive Analysis (Packet Capture)
- **Live capture** or **pcap replay** with full protocol analysis
- **Supported protocols**: TLS, DTLS, QUIC, SSH, IPsec/IKEv2, WireGuard, DNS-over-TLS, DNSSEC, 
  STARTTLS variants, SMB, RDP, Kerberos, SNMPv3, OpenVPN, RADIUS, AMQP, SIP/SIPS, ZRTP, BGP, OPC-UA
- **Dual output**: CSV (spreadsheet-friendly) + JSONL (complete event data)
- **Skynet report**: Harvest-now-decrypt-later exposure analysis

### Active Probing (NEW in v0.4.0)
- **Test targets** for post-quantum crypto support without waiting for traffic
- **Auto-detection**: Probes TLS, SSH, STARTTLS (SMTP/IMAP/POP3/FTP), IKEv2 based on port
- **Bulk scanning**: CIDR subnets, IP ranges, comma-separated lists
- **Parallel probing**: Configurable workers for fast scanning
- **Rich output**: JSON with metadata, Markdown reports, stdout display
- **SNI support**: Works with virtual hosting and name-based servers

### Illumio PCE Integration (NEW in v0.4.1)
- **Auto-labeling**: Scan workloads and automatically update Illumio PCE labels with PQC status
- **Compliance tracking**: Use `pqc` labels to track quantum-readiness across infrastructure
- **Policy integration**: Build Illumio policies based on PQ crypto support
- **Bulk operations**: Initialize all workloads, generate compliance reports
- **Python API**: Integrate into custom automation workflows

### Self-Scan Mode (NEW in v0.4.2)
- **Automated daily scans**: Discover and test external services automatically
- **Zero configuration**: Automatically finds services bound to external interfaces
- **JSON output**: Complete structured results for integration
- **Cron deployment**: One-command setup for daily execution
- **Fleet-ready**: Deploy across hundreds of machines independently

## Install

**From PyPI** (recommended):

```bash
pip install quantum-sniffer

# To upgrade an existing installation:
pip install --upgrade quantum-sniffer
```

**From source** (for development):

```bash
git clone https://github.com/illumio-community/quantum-sniffer.git
cd quantum-sniffer
pip install -e '.[dev]'
```

**Requirements:**
- Python 3.9+
- `scapy` (required for packet capture)
- `cryptography` (optional, unlocks QUIC Initial-packet decryption)
- `illumio` (optional, for Illumio PCE integration)

**Install optional dependencies:**

```bash
# For QUIC support
pip install cryptography

# For Illumio PCE integration
pip install illumio

# Install everything
pip install quantum-sniffer cryptography illumio
```

After install, the `quantum-sniffer` console script is on `$PATH`. If
you'd rather not install, every example below works with
`python3 -m quantum_sniffer …` from the repo root.

## Quick Start

### Passive Capture

```bash
# Live capture (creates .csv + .jsonl)
sudo quantum-sniffer -o capture -i eth0

# Replay a saved pcap
quantum-sniffer -o capture -r some.pcap

# Skynet readiness report
quantum-sniffer --find-sarah-connor capture.jsonl
```

### Active Probing

```bash
# Probe single target
quantum-sniffer --probe example.com

# Probe specific ports
quantum-sniffer --probe 10.1.1.100 --ports 22,443

# Probe subnet with JSON output
quantum-sniffer --probe 10.1.1.0/24 --ports 22,443 \
  --output-json scan-results.json \
  --output-markdown scan-report.md

# Probe IP range
quantum-sniffer --probe 192.168.1.1-50 --ports 443 --workers 20

# Probe multiple specific IPs
quantum-sniffer --probe 10.1.1.10,10.1.1.20,10.1.1.30 --ports 22,443
```

### Automated Monitoring: Two Modes

Quantum-sniffer supports two distinct monitoring approaches:

#### Mode 1: Daily Active Scanning (`--daily`)

Active scanning with `self-scan.py` - probes services once per day:

```bash
# Deploy daily active scanning
cd quantum-sniffer
sudo ./deploy-monitor.sh --daily

# Or user-only (no sudo)
./deploy-monitor.sh --daily --user-cron

# Manual execution
./self-scan.py > today-scan.json

# View results
jq '.summary' /var/log/quantum-sniffer/self-scan.json
```

**What it does:**
- Discovers externally-accessible services (excludes localhost)
- **Actively probes** each service with `quantum-sniffer --probe`
- Runs once daily at 2 AM via cron
- Outputs JSON report to `/var/log/quantum-sniffer/self-scan.json`
- Suitable for compliance audits and periodic checks

#### Mode 2: Persistent Passive Monitoring (`--persistent`)

Continuous traffic analysis with `persistent-monitor.py` - monitors actual connections:

```bash
# Deploy persistent passive monitoring
cd quantum-sniffer
sudo ./deploy-monitor.sh --persistent

# Check status
sudo systemctl status quantum-sniffer-monitor@eth0

# View logs
sudo journalctl -u quantum-sniffer-monitor@eth0 -f
tail -f /var/log/quantum-sniffer/pqc-monitor-*.jsonl
```

**What it does:**
- **Passively captures** live network traffic (no active probing)
- Analyzes PQC status of real incoming/outgoing connections
- Runs continuously as a systemd daemon
- Logs to rolling JSONL files
- Suitable for real-time monitoring and traffic analysis
- Integrates with UPCE for centralized collection

**Key Difference:**
- **Daily mode** = Active probing (like nmap for PQC)
- **Persistent mode** = Passive monitoring (like tcpdump + analysis)

### Illumio Integration

**Prerequisites:** `pip install illumio` and configure environment variables:

```bash
export ILLUMIO_PCE_HOST=pce.example.com
export ILLUMIO_API_KEY=api_1234567890abcdef
export ILLUMIO_API_SECRET=1234567890abcdef1234567890abcdef
```

**Commands:**

```bash
# Initialize all workloads with pqc=unknown label
quantum-sniffer --illumio-init

# Scan a workload and update its PQC label
quantum-sniffer --probe 10.1.1.50 --ports 22,443 --illumio-label 10.1.1.50

# View PQC compliance summary
quantum-sniffer --illumio-summary

# Bulk scan and label (example script)
for ip in 10.1.1.{50..60}; do
  quantum-sniffer --probe "$ip" --ports 22,443 --illumio-label "$ip"
done
```

## Usage

### Passive Capture Mode

**Live capture:**

```bash
sudo quantum-sniffer -o capture -i eth0
```

This creates **two files**:
- `capture.csv` — flattened data (17 columns) for spreadsheet analysis
- `capture.jsonl` — complete event data with nested structures

Live mode requires root (or `cap_net_raw` on Linux: `sudo setcap
cap_net_raw+ep $(readlink -f $(which python3))`).

**Replay a saved pcap:**

No root needed — useful for regression testing and analyzing captures
collected elsewhere.

```bash
quantum-sniffer -o capture -r some.pcap
```

**Common flags:**

- `-o, --output PATH` — base filename for output logs (extensions `.csv` 
  and `.jsonl` added automatically). Defaults to `quantum-log` if not specified.
  Not used by `--find-sarah-connor`.
- `-i, --interface IFACE` — capture interface (default: scapy's default)
- `-r, --read FILE.pcap` — analyze a saved capture instead of going live
- `-a, --all` — include unencrypted protocols (HTTP, plain DNS, etc.)
- `--bpf "tcp port 443"` — override the built-in BPF filter
- `--host 10.0.0.5` — narrow whichever filter is in effect to one host
- `-q, --quiet` — write JSONL without printing each event to the console
- `--debug` — re-raise analyzer exceptions instead of logging them
- `--find-sarah-connor CAPTURE.jsonl` — see "Skynet readiness report" below
- `--with-skull` — adds an ASCII skull to the readiness report

`--interface` and `--read` are mutually exclusive.

### Active Probing Mode

**Basic probing:**

```bash
# Probe single target (auto-detects protocols on default ports)
quantum-sniffer --probe example.com

# Probe specific port
quantum-sniffer --probe example.com:443

# Probe custom ports
quantum-sniffer --probe 10.1.1.100 --ports 22,443,25,587
```

**Bulk scanning:**

```bash
# CIDR subnet
quantum-sniffer --probe 10.1.1.0/24 --ports 443

# IP range (full)
quantum-sniffer --probe 10.1.1.1-10.1.1.50 --ports 22,443

# IP range (shorthand - same first 3 octets)
quantum-sniffer --probe 10.1.1.1-50 --ports 443

# Comma-separated list
quantum-sniffer --probe 10.1.1.10,10.1.1.20,10.1.1.30 --ports 22,443
```

**Output options:**

```bash
# JSON output with full metadata
quantum-sniffer --probe 10.1.1.0/24 --ports 443 \
  --output-json results.json

# Markdown report
quantum-sniffer --probe example.com --ports 22,443,25 \
  --output-markdown report.md

# Both formats
quantum-sniffer --probe 10.1.1.0/24 --ports 22,443 \
  --output-json results.json \
  --output-markdown report.md \
  --workers 20 \
  --timeout 3
```

**Probing flags:**

- `--probe TARGET` — active probe mode (supports: single IP, hostname, CIDR, range, list)
- `--ports PORT,PORT,...` — ports to probe (default: auto-detect common encrypted ports)
- `--timeout SECONDS` — connection timeout (default: 5.0)
- `--workers N` — parallel probe workers for bulk scans (default: 10)
- `--output-json FILE` — save results as JSON with metadata
- `--output-markdown FILE` — save results as Markdown report

**Supported probe protocols:**

- **TLS/HTTPS** (ports 443, 8443, 636, 853, 989, 990, 992, 993, 995, 5061, etc.)
- **SSH** (port 22) - Excellent PQ detection (KEX algorithms visible)
- **STARTTLS-SMTP** (ports 25, 587) - Upgrades connection then analyzes TLS
- **STARTTLS-IMAP** (port 143)
- **STARTTLS-POP3** (port 110)
- **STARTTLS-FTP** (port 21)
- **IKEv2/IPsec** (ports 500, 4500) - Basic probe (simplified)

Protocol is auto-detected based on port number.

### Illumio PCE Integration Mode

> **⚠️ WARNING: This feature is UNTESTED in this version. Use with caution in production environments.**

Quantum-sniffer can integrate with Illumio Policy Compute Engine to automatically label workloads with their post-quantum crypto status.

**Prerequisites:**

1. Install Illumio SDK:
   ```bash
   pip install illumio
   ```

2. Configure PCE credentials (create `.env` file or export variables):
   ```bash
   export ILLUMIO_PCE_HOST=pce.example.com
   export ILLUMIO_API_KEY=api_1234567890abcdef
   export ILLUMIO_API_SECRET=1234567890abcdef1234567890abcdef
   # Optional:
   export ILLUMIO_PCE_PORT=443
   export ILLUMIO_ORG_ID=1
   ```

3. Create API key in PCE with permissions:
   - `workloads:read`, `workloads:write`
   - `labels:read`, `labels:write`

**Initialize all workloads:**

Adds `pqc=unknown` label to all workloads that don't have a PQC label:

```bash
quantum-sniffer --illumio-init
```

This will:
- Connect to Illumio PCE
- Count workloads without a `pqc` label
- Show a warning and require confirmation (type "yes")
- Bulk update all unlabeled workloads

Skip confirmation (for automation):
```bash
quantum-sniffer --illumio-init --yes
```

**Scan and label a workload:**

Probe a workload and automatically update its Illumio label:

```bash
# Scan and label in one command
quantum-sniffer --probe 10.1.1.50 --ports 22,443 --illumio-label 10.1.1.50
```

This will:
1. Probe the IP address on specified ports
2. Determine PQC status from probe results
3. Find workload in Illumio PCE by IP address
4. Create or update the `pqc` label with detected status

**View compliance summary:**

```bash
quantum-sniffer --illumio-summary
```

Output shows:
- Total workloads
- Count by PQC status (yes/hybrid/no/unknown/not_labeled)
- Labeling progress percentage
- PQ-capable percentage

**Label values:**

- `yes` - Pure post-quantum secure
- `hybrid` - PQ + classical (transition mode)
- `no` - Classical only (quantum-vulnerable)
- `unknown` - Not yet scanned

**Bulk workflow example:**

```bash
#!/bin/bash
# 1. Initialize all workloads
quantum-sniffer --illumio-init --yes

# 2. Scan network
quantum-sniffer --probe 10.1.0.0/23 --ports 22,443 \
  --output-json scan.json --workers 50

# 3. Label workloads from scan
jq -r '.results[] | select(.status == "open") | .target_ip' scan.json | \
  sort -u | while read ip; do
    quantum-sniffer --probe "$ip" --ports 22,443 --illumio-label "$ip"
  done

# 4. View summary
quantum-sniffer --illumio-summary
```

**Python API:**

```python
from quantum_sniffer.integrations.illumio import IllumioIntegration
from quantum_sniffer.lib import probe_target

# Connect to PCE
illumio = IllumioIntegration()

# Probe workload
results = probe_target('10.1.1.50', ports=[443])
pqc_value = results[0].post_quantum_secure.lower()

# Update label
illumio.update_workload_pqc_label('10.1.1.50', pqc_value)

# Get summary
summary = illumio.get_workload_summary()
print(f"Total: {summary['total']}")
print(f"PQ-capable: {summary['by_pqc_status']['yes'] + summary['by_pqc_status']['hybrid']}")
```

**See full documentation:** [ILLUMIO_INTEGRATION.md](ILLUMIO_INTEGRATION.md)

## Post-Quantum Classification

Each event carries a `post_quantum_secure` field:

| Status    | Meaning                                                              |
|-----------|----------------------------------------------------------------------|
| `Yes`     | Pure post-quantum KEX/signature confirmed                            |
| `Hybrid`  | Mix of PQ and classical (transition deployment)                      |
| `No`      | Classical only — vulnerable to harvest-now-decrypt-later             |
| `Unknown` | Couldn't determine from observable handshake bytes                   |

Classification is driven from explicit `(group_id -> classification)` tables
(`quantum_sniffer/pq.py`), not substring matching, so novel hybrid names
can't be silently misclassified.

PQ algorithms tracked include CRYSTALS-Kyber (and the standardized name
ML-KEM), x25519/x448 hybrids, sntrup761x25519 (OpenSSH), and IKEv2 ML-KEM
DH groups (transform IDs 35–37).

## Output Formats

### Passive Capture Outputs

**CSV Format** — Spreadsheet-friendly with 17 core columns:
- `timestamp`, `protocol`, `type`, `post_quantum_secure`
- `src_ip`, `src_port`, `dst_ip`, `dst_port`, `connection`, `direction`
- `encrypted`, `tls_version`, `server_name`, `selected_cipher_name`
- `ssh_banner`, `application`, `note`

Perfect for filtering/sorting in Excel, LibreOffice Calc, or `csvkit`.

```bash
# Quick analysis in spreadsheet
libreoffice capture.csv

# Command-line filtering
csvgrep -c post_quantum_secure -m "No" capture.csv | csvlook
```

**JSONL Format** — Complete event data with nested structures. One JSON object per line, 
append-only — safe for long-running captures.

```jsonl
{"protocol":"TLS","type":"TLS ClientHello","timestamp":"2026-06-24T12:34:56.789",...,"supported_groups":["x25519kyber768","x25519"],...}
{"protocol":"SSH","type":"SSH KEXINIT","timestamp":"2026-06-24T12:34:57.123",...,"ssh_kex_algorithms":["sntrup761x25519-sha512@openssh.com",...],...}
```

To consume:

```bash
# As a single JSON array
jq -s . capture.jsonl

# Filter line-by-line
jq -c 'select(.post_quantum_secure == "Hybrid")' capture.jsonl

# Quantum readiness summary
jq -s 'group_by(.post_quantum_secure) | map({status: .[0].post_quantum_secure, count: length})' capture.jsonl

# Extract specific fields
jq -r '[.timestamp, .protocol, .supported_groups[]] | @csv' capture.jsonl
```

### Active Probing Outputs

**Console Output** — Human-readable summary:

```
================================================================================
PROBE RESULTS
================================================================================

✓ 10.1.1.100:22    open       🔒 Hybrid     
✓ 10.1.1.100:443   open       ⚠️  No         TLSv1.3, TLS_AES_256_GCM_SHA384
✗ 10.1.1.100:8443  closed
⏱ 10.1.1.100:9443  timeout    (Connection timeout (5.0s))

================================================================================
Summary: 2/4 ports open
         1/2 with PQ crypto support
================================================================================
```

**JSON Output** — Complete scan data with metadata:

```json
{
  "metadata": {
    "scan_info": {
      "source_hostname": "scanner.local",
      "source_ip": "10.0.0.5",
      "target": "10.1.1.0/24",
      "ports_scanned": [22, 443],
      "timeout_seconds": 5.0,
      "command_line": "quantum-sniffer --probe 10.1.1.0/24 --ports 22,443"
    },
    "timing": {
      "start_time": "2026-06-24T12:00:00.000000",
      "end_time": "2026-06-24T12:05:23.456789",
      "duration_seconds": 323.457
    }
  },
  "summary": {
    "total_ports_scanned": 512,
    "open_ports": 48,
    "pq_capable_ports": 12
  },
  "results": [...]
}
```

**Markdown Output** — Formatted report with tables and sections:

```markdown
# Quantum-Sniffer Probe Report

## Scan Information
**Source Hostname**: scanner.local
**Target**: 10.1.1.0/24
...

## Summary
- **Total Ports Scanned**: 512
- **Open**: 48
- **PQ-Capable**: 12/48

## Results
### Open Ports
| Port | Status | TLS Version | Cipher Suite | PQ Status |
|------|--------|-------------|--------------|-----------|
| 22   | open   | N/A         | N/A          | ✓ Hybrid  |
| 443  | open   | TLSv1.3     | TLS_AES_...  | ✗ No      |
...
```

## Library Usage

All functionality is available as a Python library:

### Passive Analysis

```python
from quantum_sniffer.lib import ProtocolAnalyzer
from scapy.all import rdpcap

# Analyze packets
analyzer = ProtocolAnalyzer(encrypted_only=True)
packets = rdpcap("capture.pcap")

for pkt in packets:
    result = analyzer.process(pkt)
    if result:
        print(f"{result.protocol}: {result.post_quantum_secure}")

# Get summary
summary = analyzer.summary()
print(f"Total events: {summary['events']}")
print(f"PQ status: {summary['post_quantum']}")
```

### Active Probing

```python
from quantum_sniffer.lib import probe_target
from quantum_sniffer.lib.prober import generate_json_report, save_report

# Probe a target
results = probe_target("10.1.1.100", ports=[22, 443], timeout=5.0)

for r in results:
    if r.status.value == "open":
        print(f"Port {r.target_port}: {r.post_quantum_secure}")
        if r.protocol == "ssh":
            print(f"  SSH KEX: {r.extras.get('ssh_kex_algorithms', [])[:3]}")
        elif r.protocol == "tls":
            print(f"  TLS: {r.tls_version}, {r.cipher_suite}")

# Probe subnet with progress
def show_progress(done, total):
    print(f"\rProgress: {done}/{total}", end="", flush=True)

results = probe_target(
    "10.1.1.0/24",
    ports=[443],
    max_workers=20,
    timeout=3.0,
    progress_callback=show_progress
)

# Generate and save report
json_report = generate_json_report(
    results=results,
    target="10.1.1.0/24",
    ports=[443],
    timeout=3.0,
    start_time="2026-06-24T12:00:00",
    end_time="2026-06-24T12:05:00",
    duration_seconds=300.0
)
save_report(json_report, "scan-results.json")
```

### PQ Classification

```python
from quantum_sniffer.lib.pq import classify_tls_group, classify_ssh_kex

# Classify TLS groups
status = classify_tls_group(0x11ec)  # x25519kyber768 -> 'hybrid'

# Classify SSH KEX
status = classify_ssh_kex("sntrup761x25519-sha512@openssh.com")  # -> 'pq'
```

## What Gets Captured/Probed

### Passive Capture

**TLS / DTLS / QUIC**: protocol versions, cipher suites, key exchange
groups (including PQ groups like `x25519kyber768`), SNI, ALPN, ECH presence,
session resumption flags. QUIC Initial packets are decrypted when
`cryptography` is installed, exposing the inner TLS 1.3 ClientHello.

**SSH**: banner version, then KEXINIT — full algorithm negotiation lists
(KEX, host-key, encryption, MAC).

**IPsec/IKEv2**: SA proposals walked end-to-end, including PQ DH transform
IDs (ML-KEM-512/768/1024).

**WireGuard**: handshake message types and sizes; oversized handshakes
flag possible experimental PQ variants.

**Other**: STARTTLS upgrades, SMB dialect, RDP/CredSSP negotiation,
Kerberos etypes, SNMPv3 security level, OpenVPN control packets, RADIUS
codes + EAP method, AMQP banner, SIP/SIPS, ZRTP key agreement, BGP/BGP-
over-TLS, OPC-UA security policies, and a heuristic TLS detector.

### Active Probing

**TLS/HTTPS**: Full TLS handshake, extracts version/cipher/certificate. 
SNI support for virtual hosting. *Limitation*: Python ssl module doesn't 
expose negotiated groups (TLS 1.3 classified as "Unknown").

**SSH**: Banner exchange + KEXINIT negotiation. Extracts full KEX algorithm 
list from server. *Excellent PQ detection* - algorithms visible in plaintext.
Example: GitHub correctly detected as Hybrid (sntrup761x25519).

**STARTTLS**: Upgrades SMTP/IMAP/POP3/FTP connections to TLS, then analyzes 
like TLS/HTTPS.

**IKEv2**: Sends IKE_SA_INIT request, parses response. *Simplified* - detects 
IKE but doesn't fully parse proposals yet.

## Skynet Readiness Report

`--find-sarah-connor` reads a JSONL capture and reports how much of the
traffic would be readable by a sufficiently large quantum computer — i.e.,
the harvest-now-decrypt-later exposure surface, in Terminator drag.

```bash
quantum-sniffer --find-sarah-connor capture.jsonl
quantum-sniffer --find-sarah-connor capture.jsonl --with-skull
```

You get:

- Counts and percentages by classification (classical / hybrid / PQ / unknown)
- A ranked list of "high-value targets" — SNIs/IPs whose sessions were classical-only
- Per-protocol breakdown (TLS / WireGuard / SSH / …)
- A verdict that scales with the data ("JUDGMENT DAY IS INEVITABLE" all
  the way up to "HASTA LA VISTA, BABY")

This mode does not require `--output` and does no packet capture.

## Examples

### Security Audit

```bash
# Scan your infrastructure for PQ support
quantum-sniffer --probe 10.0.0.0/16 --ports 22,443 \
  --output-json pq-audit-2026-06-24.json \
  --output-markdown pq-audit-2026-06-24.md \
  --workers 50 \
  --timeout 3

# Find quantum-vulnerable services
jq -r '.results[] | select(.status == "open" and .post_quantum_secure == "No") | "\(.target_ip):\(.target_port) - \(.protocol)"' pq-audit-2026-06-24.json
```

### Protocol-Specific Scanning

```bash
# SSH servers only
quantum-sniffer --probe 10.1.1.0/24 --ports 22

# Web servers
quantum-sniffer --probe servers.txt --ports 443,8443

# Mail servers (STARTTLS)
quantum-sniffer --probe mail.example.com --ports 25,587,143,110
```

### Monitoring

```bash
# Passive monitoring
sudo quantum-sniffer -o daily-$(date +%Y%m%d) -i eth0

# Generate report
quantum-sniffer --find-sarah-connor daily-*.jsonl > daily-report.txt

# Active verification
quantum-sniffer --probe critical-servers.txt --ports 22,443 \
  --output-json daily-probe-$(date +%Y%m%d).json
```

## Testing

```bash
python3 -m pytest tests/
```

45 tests cover the bounds-check fixes in the raw TLS parser (truncated
session-id / cipher-list / extensions don't crash), PQ classification,
SSH KEX parsing, IKEv2 SA parsing (including ML-KEM transform IDs), the
dual CSV/JSONL writer, CLI argument handling, and the Skynet report.

## Building for PyPI

The repo ships `pyproject.toml` and `MANIFEST.in`, so:

```bash
pip install --user build twine
python3 -m build              # produces dist/*.whl + dist/*.tar.gz
python3 -m twine check dist/* # validates README + metadata
# python3 -m twine upload dist/*    # uncomment to actually publish
```

## Limitations

### Passive Capture

- Cannot decrypt application traffic — handshake metadata only
- ClientHello fragmentation across TCP segments is detected and flagged
  but not yet reassembled. PQ key shares often push ClientHello past one
  segment, so flagged events deserve attention
- PQ detection only catches algorithms whose IDs/names this tool knows
  about. New IANA assignments need updates to `quantum_sniffer/constants.py`
  and `quantum_sniffer/pq.py`

### Active Probing

- **TLS/HTTPS**: Python's `ssl` module doesn't expose negotiated key exchange 
  groups. Result: TLS 1.3 connections classified as "Unknown" (can't see which 
  group was used). Future: Use `cryptography` library to craft custom ClientHello.
- **IKEv2**: Simplified implementation - detects IKE response but doesn't fully 
  parse proposals/transforms yet. Future: Complete DH group extraction.
- **No support for**: QUIC (complex UDP), RDP/Kerberos (need auth), WireGuard 
  (no negotiation), LDAP STARTTLS (needs ASN.1 encoding)

## Legal

Authorized use only. 

- **Passive monitoring**: Monitor networks you own or have permission to monitor
- **Active probing**: Probe only systems you own or have written permission to test

Port scanning without authorization likely violates the Computer Fraud and Abuse Act
(US), GDPR (EU), Computer Misuse Act (UK), or similar laws elsewhere. Always:
- Use reasonable timeouts and rate limiting
- Respect robots.txt and security.txt
- Document authorization in writing
- Comply with local laws

## Illumio Integration

Quantum-sniffer can automatically label Illumio PCE workloads with their PQ crypto status:

```bash
# Initialize all workloads with pqc=unknown
quantum-sniffer --illumio-init

# Scan and label a workload
quantum-sniffer --probe 10.1.1.50 --ports 22,443 --illumio-label 10.1.1.50

# View compliance summary
quantum-sniffer --illumio-summary
```

See **[ILLUMIO_INTEGRATION.md](ILLUMIO_INTEGRATION.md)** for complete documentation.

## Self-Scan Mode

Deploy automated daily scanning on each machine:

```bash
cd quantum-sniffer

# Deploy (one command)
sudo ./deploy-self-scan.sh

# View results
cat /var/log/quantum-sniffer/self-scan.json
jq '.summary' /var/log/quantum-sniffer/self-scan.json
```

**Features:**
- Automatically discovers external services (excludes localhost)
- Runs daily at 2 AM via cron
- JSON output for easy integration
- Deploy across entire fleet independently

See **[SELF_SCAN.md](SELF_SCAN.md)** for complete documentation.

## Ansible Deployment

Run quantum-sniffer on remote hosts **without installing anything permanently**:

```bash
cd ansible

# Generate inventory from UPCE
./generate-inventory-from-upce.py > inventory.ini

# Run scan on all hosts
ansible-playbook -i inventory.ini run-quantum-sniffer.yml

# View results
ls results/
```

The Ansible playbook:
- Creates temporary environment on remote host
- Installs dependencies in isolated venv
- Runs scan and fetches results
- **Deletes everything** (guaranteed cleanup)

See **[ANSIBLE_DEPLOYMENT.md](ANSIBLE_DEPLOYMENT.md)** for complete documentation.

## Documentation

- **README.md** (this file) - Getting started and usage
- **PROBING.md** - Complete active probing documentation
- **SELF_SCAN.md** - Automated daily self-scanning
- **ILLUMIO_INTEGRATION.md** - Illumio PCE integration guide (⚠️ UNTESTED)
- **ANSIBLE_DEPLOYMENT.md** - Zero-install remote execution via Ansible
- **REFACTORING_SUMMARY.md** - Library architecture details
- **example_library_usage.py** - Passive analysis examples
- **example_probing.py** - Active probing examples
- **example_illumio_integration.py** - Illumio integration examples (⚠️ UNTESTED)
- **ansible/** - Ansible playbooks and examples
- **discover-external-services.py** - Service discovery tool
- **self-scan.py** - Self-scan script
- **deploy-self-scan.sh** - Self-scan deployment automation

## License

GNU General Public License v3.0

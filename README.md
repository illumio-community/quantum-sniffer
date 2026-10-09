# quantum-sniffer

A network traffic analyzer and active prober that captures and classifies cryptographic
handshakes from encrypted protocols (TLS, SSH, IPsec, QUIC, WireGuard, and more) and tags 
each one as **post-quantum secure**, **hybrid**, **classical**, or **unknown**.

> **Status: alpha.** Public protocols and CLI flags may change.

## Features

### Passive Analysis (Packet Capture)
- **Live capture** or **pcap replay** with full protocol analysis
- **Supported protocols**: TLS (any port), DTLS, QUIC (v1 and v2), SSH, IPsec/IKEv2, WireGuard,
  DNS-over-TLS, DNSSEC, STARTTLS variants, SMB, RDP, Kerberos, SNMPv3, OpenVPN, RADIUS, AMQP,
  SIP/SIPS, ZRTP, BGP, OPC-UA; with `--l7` also HTTP, DNS and NetBIOS
- **Reassembly**: TCP handshakes, multi-packet QUIC hellos and IP fragments are rebuilt
  before analysis, so a post-quantum ClientHello that spans packets still yields its SNI,
  key shares and negotiated group
- **Layer-7 detections**: weak/deprecated TLS, SSH protocol version, SMB dialect/encryption/
  transport, SMB over QUIC; with `--l7`, cleartext HTTP requests, DNS with an "is port 53
  really DNS?" verdict, and NetBIOS names. Detection and reporting only
- **Dual output**: CSV (spreadsheet-friendly) + JSONL (complete event data)
- **Skynet report**: Harvest-now-decrypt-later exposure analysis

### Active Probing
- **Test targets** for post-quantum crypto support without waiting for traffic
- **Auto-detection**: Probes TLS, SSH, STARTTLS (SMTP/IMAP/POP3/FTP), IKEv2 based on port
- **Bulk scanning**: CIDR subnets, IP ranges, comma-separated lists
- **Parallel probing**: Configurable workers for fast scanning
- **Rich output**: JSON with metadata, Markdown reports, stdout display
- **SNI support**: Works with virtual hosting and name-based servers

## Install

**From PyPI** (recommended):

```bash
pip install quantum-sniffer
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
- `cryptography` (optional, unlocks QUIC Initial-packet decryption; without it a QUIC
  connection is reported once with no handshake detail)

**Install optional dependencies:**

```bash
# For QUIC support
pip install cryptography

# Install everything
pip install quantum-sniffer cryptography
```

After install, the `quantum-sniffer` console script is on `$PATH`. If you'd rather not install, 
every example below works with `python3 -m quantum_sniffer …` from the repo root.

## Quick Start

### Passive Capture

```bash
# Live capture (creates .csv + .jsonl)
sudo quantum-sniffer -o capture -i eth0

# Replay a saved pcap
quantum-sniffer -o capture -r some.pcap

# Add layer-7 detection (HTTP, DNS conformance, NetBIOS)
sudo quantum-sniffer -o capture -i eth0 --l7

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

## Usage

### Passive Capture Mode

**Live capture:**

```bash
sudo quantum-sniffer -o capture -i eth0
```

This creates **two files**:
- `capture.csv` — flattened data (32 columns) for spreadsheet analysis
- `capture.jsonl` — complete event data with nested structures

Live mode requires root (or `cap_net_raw` on Linux: `sudo setcap cap_net_raw+ep $(readlink -f $(which python3))`).

**Replay a saved pcap:**

No root needed — useful for regression testing and analyzing captures collected elsewhere.

```bash
quantum-sniffer -o capture -r some.pcap
```

**Common flags:**

- `-o, --output PATH` — base filename for output logs (extensions `.csv` and `.jsonl` added automatically). Defaults to `quantum-log` if not specified.
- `-i, --interface IFACE` — capture interface (default: scapy's default)
- `-r, --read FILE.pcap` — analyze a saved capture instead of going live
- `-a, --all` — include unencrypted events and the plaintext STARTTLS-capable ports
- `--l7` — layer-7 detection: also report cleartext HTTP, DNS and NetBIOS (see below)
- `--bpf "tcp port 443"` — override the built-in BPF filter
- `--host 10.0.0.5` — narrow whichever filter is in effect to one host
- `-q, --quiet` — write JSONL without printing each event to the console
- `--debug` — re-raise analyzer exceptions instead of logging them
- `--find-sarah-connor CAPTURE.jsonl` — see "Skynet readiness report" below
- `--with-skull` — adds an ASCII skull to the readiness report

`--interface` and `--read` are mutually exclusive.

When the capture ends (Ctrl+C, or the end of the pcap) it prints event counts
by protocol and by PQ classification, then a count of each layer-7 finding:
weak or deprecated TLS offered or negotiated, SSH-1, SMB1, encrypted SMB3,
SMB over QUIC, non-DNS traffic on port 53, and cleartext HTTP.

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

## Post-Quantum Classification

Each event carries a `post_quantum_secure` field:

| Status    | Meaning                                                              |
|-----------|----------------------------------------------------------------------|
| `Yes`     | Pure post-quantum KEX/signature confirmed                            |
| `Hybrid`  | Mix of PQ and classical (transition deployment)                      |
| `No`      | Classical only — vulnerable to harvest-now-decrypt-later             |
| `Unknown` | Couldn't determine from observable handshake bytes                   |
| `N/A`     | Cleartext layer-7 event (`--l7`): no key exchange to classify        |

A ClientHello is classified by what the client **offers**; a ServerHello by the
group the server **chose**. Read both: a client offering X25519MLKEM768 to a
server that negotiates plain x25519 is a `Hybrid` ClientHello followed by a
`No` ServerHello, and only the second describes the session.

Classification is driven from explicit `(group_id -> classification)` tables
(`quantum_sniffer/pq.py`), not substring matching, so novel hybrid names
can't be silently misclassified.

PQ algorithms tracked, with names as in the IANA "TLS Supported Groups"
registry: the ML-KEM hybrids X25519MLKEM768, SecP256r1MLKEM768,
SecP384r1MLKEM1024, SecP256r1MLKEM512, MLKEM512X25519 and curveSM2MLKEM768;
pure MLKEM512/768/1024; the obsolete pre-standard X25519Kyber768Draft00 and
SecP256r1Kyber768Draft00; OpenSSH's mlkem768x25519 and sntrup761x25519; and
IKEv2 ML-KEM DH groups (transform IDs 35–37). GREASE values appear as
`GREASE(0x....)`.

## Output Formats

### Passive Capture Outputs

**CSV Format** — Spreadsheet-friendly with 32 columns:
- `timestamp`, `protocol`, `type`, `post_quantum_secure`
- `src_ip`, `src_port`, `dst_ip`, `dst_port`, `connection`, `direction`
- `encrypted`, `tls_version`, `server_name`, `selected_cipher_name`
- `ssh_banner`, `application`, `note`
- Layer-7: `tls_deprecated_version`, `tls_weak_cipher`, `tls_weak_offered`, `ssh_version`,
  `smb_version`, `smb_encrypted`, `smb_transport`, `netbios_name`, `dns_query`,
  `dns_conforming`, `dns_nonconformance`, `http_method`, `http_host`, `http_path`,
  `http_user_agent`

Appending to an existing CSV keeps that file's header, so rows stay aligned
with a file written by an older version (the newer columns are left out of it).

`timestamp` is the packet's capture time, so pcap replays keep their original
times.

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
{"protocol":"TLS","type":"TLS ClientHello","timestamp":"2026-06-24T12:34:56.789",...,"supported_groups":["X25519MLKEM768","x25519"],...}
{"protocol":"SSH","type":"SSH KEX Init","timestamp":"2026-06-24T12:34:57.123",...,"ssh_kex_algorithms":["sntrup761x25519-sha512@openssh.com",...],...}
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
jq -r '[.timestamp, .protocol, .server_name, (.supported_groups // [] | join(" "))] | @csv' capture.jsonl
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

All functionality is available as a Python library. See `example_library_usage.py` for complete examples.

### Passive Analysis

```python
from quantum_sniffer.lib import ProtocolAnalyzer
from scapy.all import rdpcap

# Analyze packets
analyzer = ProtocolAnalyzer(encrypted_only=True)
packets = rdpcap("capture.pcap")

# Feed packets in capture order to ONE analyzer: it reassembles TCP
# handshakes, IP fragments and multi-packet QUIC hellos across packets.
for pkt in packets:
    for result in analyzer.process_all(pkt):   # a packet can complete 0..n events
        print(f"{result.protocol}: {result.post_quantum_secure}")

# Get summary
summary = analyzer.summary()
print(f"Total events: {summary['events']}")
print(f"PQ status: {summary['post_quantum']}")
print(f"Layer-7 findings: {summary['findings']}")
```

`ProtocolAnalyzer(l7=True)` adds the layer-7 analyzers. `process(pkt)` still
exists but returns only the first event a packet completes. The one-shot
`analyze_packet(pkt)` builds a fresh analyzer per call, so it can't reassemble
anything; use it only on packets you know hold a complete message.

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
status = classify_tls_group(0x11ec)  # X25519MLKEM768 -> 'hybrid'

# Classify SSH KEX
status = classify_ssh_kex("sntrup761x25519-sha512@openssh.com")  # -> 'pq'
```

## What Gets Captured/Probed

### Passive Capture

**TLS / DTLS / QUIC**: protocol versions, cipher suites, offered groups and
key shares (including PQ groups like `X25519MLKEM768`, named as in the IANA
registry), the group the server actually negotiated, HelloRetryRequests, SNI,
ALPN, ECH presence, session resumption flags. TLS is recognised on any TCP
port, including DoT (853), IMAPS/POP3S/LDAPS and STARTTLS upgrades. QUIC
Initial packets (v1 and v2) are decrypted when `cryptography` is installed,
exposing both the ClientHello and the ServerHello.

**SSH**: client and server banners (with the protocol version), then each
side's KEXINIT: full algorithm negotiation lists (KEX, host-key, encryption,
MAC).

**IPsec/IKEv2**: SA proposals walked end-to-end, including PQ DH transform
IDs (ML-KEM-512/768/1024).

**WireGuard**: handshake message types and sizes; oversized handshakes
flag possible experimental PQ variants. A packet must carry WireGuard's
3-byte zero reserved field to count, so DHCP and RADIUS aren't mistaken for
it.

**Other**: STARTTLS upgrades, RDP/CredSSP negotiation,
Kerberos etypes, SNMPv3 security level, OpenVPN control packets, RADIUS
codes + EAP method, AMQP banner, SIP/SIPS, ZRTP key agreement, BGP/BGP-
over-TLS and OPC-UA security policies. TLS on the non-standard ports in
`TLS_HEURISTIC_PORTS` and the Tor ports is labelled as such.

**Layer 7**: see [Layer-7 Detections](#layer-7-detections) below.

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

## Layer-7 Detections

These detect and report; nothing here blocks or alters traffic.

A boolean finding appears only when it is **true**. A missing key means "not
seen", not "clean". The one exception is `dns_conforming`, which really has
three states.

**Always on** (fields on the TLS, QUIC and SSH events, plus SMB events):

| Field | Meaning |
|---|---|
| `tls_deprecated_version`, `tls_weak_cipher`, `tls_weak_offered` | ClientHello **offers** a version below TLS 1.2, or a suite with NULL, EXPORT, RC4, DES or 3DES encryption or anonymous key exchange (103 suites, generated from the IANA registry, reported by IANA name). TLS on any TCP port and decrypted QUIC |
| `tls_deprecated_version_negotiated`, `tls_weak_cipher_negotiated` | The ServerHello **selected** one |
| `ssh_version` | `2`, `1.99` or `1`, from each side's banner (tcp/22 and tcp/2222). `1.99` is a server saying it still accepts SSH-1 |
| `smb_version` | **Negotiated** dialect (`2.0.2`…`3.1.1`), read from the server's NEGOTIATE response; `1` when SMB1 traffic is seen |
| `smb_encrypted` | An SMB3 transform header was seen. It is never `false`: encryption can be proven present, never proven absent |
| `smb_transport` | `direct` (445), `netbios` (139/137/138), `quic` (QUIC ALPN `smb`) |

**With `--l7`** (each event is tagged `layer7: true`; the cleartext ones carry
`post_quantum_secure: "N/A"` and the Skynet report skips them):

| Event | Fields |
|---|---|
| HTTP (tcp/80) | `http_method`, `http_path`, `http_version`, `http_host`, `http_user_agent` |
| DNS (udp+tcp/53) | `dns_query`, `dns_qtype`, `dns_rcode`, `dns_answers`, `dns_records`, `dns_resolutions` (CNAME chains followed, minimum TTL) |
| DNS conformance | `dns_conforming` / `dns_nonconformance`: whether port 53 carries RFC 1035 DNS at all. This catches a different protocol sitting on :53 (SSH, TLS, HTTP, VPNs). It does **not** catch DNS tunnels: iodine and dnscat2 produce conforming DNS |
| NetBIOS (udp/137, udp/138) | `netbios_name`, `netbios_suffix`, `netbios_source_name`; a mailslot write on udp/138 proves SMB1 is on the wire (`smb_version: "1"`) |

`--l7` adds tcp/80, tcp/139, tcp/2222, udp/137 and udp/138 to the default
BPF filter. The capture summary ends with a count of each finding.

## Reassembly

Handshake messages often don't fit one packet. An X25519MLKEM768 key share
alone is ~1.2 KB, so a post-quantum TLS ClientHello usually spans two TCP
segments, and Chrome spreads its QUIC ClientHello over several Initial
packets with the pieces shuffled. Without reassembly the SNI and key shares
are simply not seen. quantum-sniffer rebuilds them before analysis:

- **TCP:** the first 64 KB of each direction is put back in order (out of
  order, retransmitted, TCP Fast Open data in the SYN) and cut into
  messages: TLS records, the SSH banner and binary packets up to KEXINIT,
  HTTP request headers, NBT-framed SMB, Kerberos, RDP TPKT, and
  length-prefixed DNS. Each complete message is analyzed once. After the
  handshake, or for traffic it doesn't recognise, packets are analyzed one
  at a time as before.
- **QUIC:** CRYPTO frames are collected across a connection's Initial
  packets in both directions. Keys come from the client's original DCID,
  and a Retry is honoured.
- **IP fragments** (IPv4 and IPv6) are reassembled first, so a large DNS
  response is not truncated into "not DNS".
- **Bounded:** 16,384 TCP flows, 64 MB buffered in total, 120 s idle expiry
  on capture time; 4,096 QUIC flows; 1,024 fragmented datagrams.

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

Cleartext `--l7` events (`post_quantum_secure: "N/A"`) are left out: they
carry no key exchange for a quantum computer to break.

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

### Quick Network Scan

```bash
# Use the included scan script
./scan-network.sh 10.1.1.0/24
```

## Testing

```bash
python3 -m pytest tests/
```

109 tests cover:
- **parsers:** bounds checks in the raw TLS parser (truncated
  session-id / cipher-list / extensions don't crash), PQ classification,
  SSH KEX parsing, IKEv2 SA parsing (including ML-KEM transform IDs)
- **output:** the dual CSV/JSONL writer, CLI argument handling, the Skynet
  report
- **layer 7** (`tests/test_l7.py`): weak TLS, SSH versions, HTTP, DNS
  conformance (including pointer loops, truncation, DSO and cookie-only
  queries), SMB dialects/encryption/transport, NetBIOS
- **reassembly** (`tests/test_reassembly.py`): split, out-of-order and
  retransmitted hellos; mid-stream joins; TCP Fast Open; STARTTLS;
  HelloRetryRequest; SMB on 139 after an NBT session request; IPv4/IPv6
  fragments; QUIC v1/v2 hellos split and shuffled across packets, the server
  reply and a Retry; and payloads staying byte-exact when scapy's TLS layer
  is loaded

QUIC tests need `cryptography`.

## Building for PyPI

```bash
pip install --user build twine
python3 -m build              # produces dist/*.whl + dist/*.tar.gz
python3 -m twine check dist/* # validates README + metadata
# python3 -m twine upload dist/*    # uncomment to actually publish
```

## Limitations

### Passive Capture

- Cannot decrypt application traffic — handshake metadata only
- Handshakes are reassembled only from the start of a connection's byte
  stream (first 64 KB per direction). A connection joined mid-stream is
  still read if a TLS hello or SSH banner starts on a segment boundary,
  otherwise per-packet; QUIC needs the client's first Initial
- PQ detection only catches algorithms whose IDs/names this tool knows
  about. New IANA assignments need updates to `quantum_sniffer/constants.py`
  and `quantum_sniffer/pq.py`
- TCP DNS is judged only on connections whose SYN was captured: bytes from
  mid-stream don't start at a message boundary, and a "not DNS" verdict on
  them would be wrong. HTTP is followed through `Content-Length` bodies;
  a chunked upload ends HTTP framing for that connection

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

## License

GNU General Public License v3.0

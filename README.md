# quantum-sniffer

A network traffic analyzer that captures and classifies cryptographic
handshakes from encrypted protocols (TLS, SSH, IPsec, WireGuard, DTLS, QUIC,
DoT, STARTTLS, SMB, RDP, Kerberos, SNMPv3, OpenVPN, RADIUS, AMQP, SIP/SIPS,
ZRTP, BGP, OPC-UA, and more) and tags each one as **post-quantum secure**,
**hybrid**, **classical**, or **unknown**.

> **Status: pre-alpha.** Public protocols and CLI flags may change.

## Install

From source (until published to PyPI):

```bash
git clone https://github.com/jfrancis/quantum-sniffer.git
cd quantum-sniffer
pip install .
# or, for development with editable install + tests:
pip install -e '.[dev]'
```

Requirements: Python 3.9+, `scapy`. `cryptography` is optional and unlocks
QUIC Initial-packet decryption.

After install, the `quantum-sniffer` console script is on `$PATH`. If
you'd rather not install, every example below works with
`python3 -m quantum_sniffer …` from the repo root.

## Quick reference

```bash
quantum-sniffer --help                        # show all flags
sudo quantum-sniffer -o capture -i eth0       # live capture (creates .csv + .jsonl)
quantum-sniffer -o capture -r some.pcap       # replay a saved pcap (no root)
quantum-sniffer --find-sarah-connor capture.jsonl # Skynet-readiness report
```

## Usage

### Live capture

```bash
sudo quantum-sniffer -o capture -i eth0
```

This creates **two files**:
- `capture.csv` — flattened data (17 columns) for spreadsheet analysis
- `capture.jsonl` — complete event data with nested structures

Live mode requires root (or `cap_net_raw` on Linux: `sudo setcap
cap_net_raw+ep $(readlink -f $(which python3))`).

### Replay a saved pcap

No root needed — useful for regression testing and analyzing captures
collected elsewhere.

```bash
quantum-sniffer -o capture -r some.pcap
```

### Flags

Optional for capture/replay modes:

- `-o, --output PATH` — base filename for output logs (extensions `.csv` 
  and `.jsonl` added automatically). Defaults to `quantum-log` if not specified.
  Not used by `--find-sarah-connor`.

Common flags:

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

## Output Format

Quantum-sniffer writes **dual output** to both CSV and JSONL formats simultaneously:

### CSV Format

Spreadsheet-friendly with 17 core columns:
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

### JSONL Format

Complete event data with nested structures. One JSON object per line, 
append-only — safe for long-running captures.

```jsonl
{"protocol":"TLS","type":"TLS ClientHello","timestamp":"2026-06-10T12:34:56.789",...,"supported_groups":["x25519kyber768","x25519"],...}
{"protocol":"WireGuard","type":"WireGuard Handshake Initiation",...}
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

## What Gets Captured

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
over-TLS, OPC-UA security policies, and a heuristic TLS detector for ~30
non-standard ports plus Tor (9001/9030/9050/9051/9150).

## Skynet readiness report

`--find-sarah-connor` reads a JSONL capture and reports how much of the
traffic would be readable by a sufficiently large quantum computer — i.e.,
the harvest-now-decrypt-later exposure surface, in Terminator drag.

```bash
quantum-sniffer --find-sarah-connor capture.jsonl
quantum-sniffer --find-sarah-connor capture.jsonl --with-skull
```

You get:

- Counts and percentages by classification (classical / hybrid / PQ /
  unknown)
- A ranked list of "high-value targets" — SNIs/IPs whose sessions were
  classical-only
- Per-protocol breakdown (TLS / WireGuard / SSH / …)
- A verdict that scales with the data ("JUDGMENT DAY IS INEVITABLE" all
  the way up to "HASTA LA VISTA, BABY")

This mode does not require `--output` and does no packet capture.

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

- Cannot decrypt application traffic — handshake metadata only.
- ClientHello fragmentation across TCP segments is detected and flagged
  but not yet reassembled. PQ key shares often push ClientHello past one
  segment, so flagged events deserve attention.
- PQ detection only catches algorithms whose IDs/names this tool knows
  about. New IANA assignments need updates to `quantum_sniffer/constants.py`
  and `quantum_sniffer/pq.py`.

## Legal

Authorized use only. Monitoring networks you don't own or lack written
permission to monitor likely violates the Computer Fraud and Abuse Act
(US), GDPR (EU), or similar laws elsewhere.

## License

GNU General Public License v3.0

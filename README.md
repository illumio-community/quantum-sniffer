# quantum-sniffer

**⚠️ PRE-ALPHA SOFTWARE - Under active development, expect breaking changes and bugs**

A network traffic analyzer that captures and analyzes cryptographic information from encrypted protocols including TLS, SSH, IPsec, WireGuard, DTLS, QUIC, and more. **Identifies post-quantum secure connections.**

## Features

### Monitored Encrypted Protocols (Default Mode)

- **TLS/HTTPS** (TCP 443) - ClientHello/ServerHello handshakes, cipher suites, SNI
- **SSH** (TCP 22) - Protocol exchange, version banners
- **IPsec/IKE** (UDP 500, 4500) - Key exchange negotiation
- **WireGuard** (UDP 51820) - Modern VPN handshakes
- **DTLS** (UDP, various) - TLS over UDP (WebRTC, VPN)
- **QUIC/HTTP3** (UDP 443) - Modern encrypted web protocol
- **DNS over TLS** (TCP 853) - Encrypted DNS
- **STARTTLS** - SMTP, IMAP, POP3, FTP, LDAP, XMPP, PostgreSQL, MySQL
- **SMB** (TCP 445) - File sharing with encryption
- **LDAPS** (TCP 636) - LDAP over SSL
- **IMAPS/POP3S** (TCP 993, 995) - Encrypted email
- **FTPS** (TCP 989, 990) - FTP over TLS
- **MQTT over TLS** (TCP 8883) - IoT messaging
- **SIP over TLS** (TCP 5061) - VoIP signaling

### Post-Quantum Security Analysis

Each connection is analyzed to determine quantum resistance:

- **✅ Post-Quantum Secure** - Uses PQ-safe algorithms (Kyber, NTRU, Dilithium, etc.)
- **🔐 Hybrid** - Mix of post-quantum and classical algorithms (transitional)
- **⚠️ Classical Crypto** - Uses only classical algorithms (RSA, ECDH, DH) - vulnerable to quantum attacks
- **❓ Unknown** - Cannot determine security level

### What It Captures

**TLS/DTLS:**
- Protocol versions (SSL 3.0, TLS 1.0-1.3, DTLS 1.0-1.3)
- Cipher suites offered and selected
- Key exchange groups (x25519, Kyber768, secp256r1, etc.)
- Server Name Indication (SNI)
- TLS extensions
- Post-quantum indicators

**SSH:**
- Protocol version (1.x, 2.0)
- Software version and implementation
- Post-quantum SSH detection

**IPsec/IKE:**
- IKE version (IKEv1, IKEv2)
- Key exchange proposals
- Encryption algorithms
- DH groups

**WireGuard:**
- Handshake initiation/response
- Message types
- Crypto algorithms (Curve25519, ChaCha20-Poly1305)

**QUIC:**
- QUIC version
- Initial packets
- TLS 1.3 integration

**Other Protocols:**
- STARTTLS upgrade detection
- SMB dialect negotiation
- Protocol-specific details

### Output Formats

**Screen (Real-time):**
- Pretty formatted with color indicators
- Post-quantum security status highlighted
- Connection details, crypto algorithms, key information

**JSON Log (quantum-sniffer.json):**
- Complete structured data
- Machine-readable format
- All captured fields preserved
- Includes `post_quantum_secure` field

## Installation

### Requirements
- Python 3.6+
- scapy library
- Root privileges (packet capture)

### Install Dependencies

```bash
cd ~/quantum-sniffer
pip3 install -r requirements.txt
```

Or:
```bash
pip3 install scapy
```

## Usage

### Basic Usage (Encrypted Only)

```bash
sudo ./quantum-sniffer.py
```

Monitors encrypted protocols on the default interface.

### Monitor All Protocols

```bash
sudo ./quantum-sniffer.py --all
```

Includes unencrypted protocols (HTTP, DNS, etc.).

### Specify Interface

```bash
sudo ./quantum-sniffer.py eth0
sudo ./quantum-sniffer.py -i wlan0
```

### All Options

```bash
sudo ./quantum-sniffer.py -a -i eth0        # All protocols on eth0
```

### Command-Line Arguments

```
-a, --all           Include unencrypted protocols
-i, --interface     Specify network interface
-h, --help          Show help message
```

## Example Output

### Screen Output

```
================================================================================
[2026-04-05T12:34:56.789] TLS ClientHello
Post-Quantum: 🔐 HYBRID (PQ + Classical)
================================================================================
Connection: 10.1.1.100:54321 -> 93.184.216.34:443
Direction:  outbound
Protocol:   TLS
TLS Version: TLS 1.3 (0x0304)
Server Name (SNI): example.com

Client Offered Ciphers (15):
  1. TLS_AES_128_GCM_SHA256 (0x1301)
  2. TLS_AES_256_GCM_SHA384 (0x1302)
  3. TLS_CHACHA20_POLY1305_SHA256 (0x1303)
  ...

Supported Key Exchange Groups:
  - x25519kyber768 ⭐ [POST-QUANTUM]
  - x25519
  - secp256r1
  - secp384r1
================================================================================

================================================================================
[2026-04-05T12:35:01.123] WireGuard Handshake Initiation
Post-Quantum: ⚠️  CLASSICAL CRYPTO (quantum-vulnerable)
================================================================================
Connection: 10.1.1.100:51820 -> 10.1.1.200:51820
Direction:  outbound
Protocol:   WireGuard
Message Type: Handshake Initiation
Crypto: Curve25519, ChaCha20-Poly1305
================================================================================
```

### JSON Log (quantum-sniffer.json)

```json
[
  {
    "protocol": "TLS",
    "type": "TLS ClientHello",
    "timestamp": "2026-04-05T12:34:56.789",
    "src_ip": "10.1.1.100",
    "src_port": 54321,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "connection": "10.1.1.100:54321 -> 93.184.216.34:443",
    "direction": "outbound",
    "encrypted": true,
    "tls_version": "TLS 1.3",
    "server_name": "example.com",
    "client_cipher_suites": [...],
    "supported_groups": ["x25519kyber768", "x25519", "secp256r1"],
    "post_quantum_secure": "Hybrid"
  },
  {
    "protocol": "WireGuard",
    "type": "WireGuard Handshake Initiation",
    "timestamp": "2026-04-05T12:35:01.123",
    "src_ip": "10.1.1.100",
    "src_port": 51820,
    "dst_ip": "10.1.1.200",
    "dst_port": 51820,
    "connection": "10.1.1.100:51820 -> 10.1.1.200:51820",
    "direction": "outbound",
    "encrypted": true,
    "message_type": "Handshake Initiation",
    "crypto_algorithms": "Curve25519, ChaCha20-Poly1305",
    "post_quantum_secure": "No"
  }
]
```

## Post-Quantum Cryptography

### What Is Post-Quantum Crypto?

Quantum computers can break current public-key cryptography (RSA, ECDH, DH) using Shor's algorithm. Post-quantum cryptography uses algorithms resistant to quantum attacks.

### PQ-Safe Algorithms Detected

**Key Exchange:**
- Kyber (CRYSTALS-Kyber) - NIST standard
- NTRU
- FrodoKEM
- Hybrid schemes (e.g., x25519kyber768)

**Signatures:**
- Dilithium (CRYSTALS-Dilithium)
- Falcon
- SPHINCS+

### Classical Algorithms (Quantum-Vulnerable)

**Key Exchange:**
- RSA
- Diffie-Hellman (DH)
- Elliptic Curve Diffie-Hellman (ECDH)
- x25519, x448, secp256r1, etc.

**Signatures:**
- RSA signatures
- ECDSA
- DSA

### Hybrid Approach

Many systems use hybrid key exchange:
- Classical algorithm (e.g., x25519) + PQ algorithm (e.g., Kyber768)
- Protects against both current attacks and future quantum attacks
- Transitional approach during PQ migration

## Security Analysis Use Cases

### 1. Audit Quantum Readiness

Find systems using only classical crypto:
```bash
jq '.[] | select(.post_quantum_secure == "No")' quantum-sniffer.json
```

### 2. Identify Weak Crypto

Find deprecated TLS versions:
```bash
jq '.[] | select(.tls_version == "TLS 1.0" or .tls_version == "TLS 1.1")' quantum-sniffer.json
```

Find weak ciphers:
```bash
jq '.[] | select(.selected_cipher.name | contains("RC4") or contains("DES") or contains("MD5"))' quantum-sniffer.json
```

### 3. Monitor Protocol Usage

Count protocols:
```bash
jq 'group_by(.protocol) | map({protocol: .[0].protocol, count: length})' quantum-sniffer.json
```

### 4. Track PQ Adoption

Post-quantum security summary:
```bash
jq 'group_by(.post_quantum_secure) | map({status: .[0].post_quantum_secure, count: length})' quantum-sniffer.json
```

### 5. Verify Forward Secrecy

Check for RSA key exchange (no forward secrecy):
```bash
jq '.[] | select(.selected_cipher.name | contains("RSA_WITH"))' quantum-sniffer.json
```

## Viewing Results

### Pretty Print

```bash
cat quantum-sniffer.json | jq .
```

### Count Captures

```bash
jq 'length' quantum-sniffer.json
```

### Filter by Protocol

```bash
jq '.[] | select(.protocol == "TLS")' quantum-sniffer.json
jq '.[] | select(.protocol == "WireGuard")' quantum-sniffer.json
jq '.[] | select(.protocol == "SSH")' quantum-sniffer.json
```

### Extract Server Names

```bash
jq '.[] | select(.server_name) | .server_name' quantum-sniffer.json | sort -u
```

### Show Selected Ciphers

```bash
jq '.[] | select(.selected_cipher) | .selected_cipher.name' quantum-sniffer.json | sort | uniq -c
```

### Find PQ-Secure Connections

```bash
jq '.[] | select(.post_quantum_secure == "Yes" or .post_quantum_secure == "Hybrid")' quantum-sniffer.json
```

### Export to CSV

```bash
jq -r '.[] | [.timestamp, .protocol, .post_quantum_secure, .connection, .tls_version // .ssh_protocol_version, .selected_cipher.name // "-"] | @csv' quantum-sniffer.json > report.csv
```

## Testing

### Generate Test Traffic

```bash
# Terminal 1: Start sniffer
sudo ./quantum-sniffer.py

# Terminal 2: Generate traffic
curl https://example.com
curl https://google.com
ssh user@host
ping 8.8.8.8  # ICMP (if --all mode)
```

### Test with WireGuard

If you have WireGuard configured:
```bash
sudo wg-quick up wg0
# quantum-sniffer will capture the handshake
```

### Test with OpenVPN

```bash
sudo openvpn client.conf
# quantum-sniffer will capture TLS handshake
```

## Limitations

- **Cannot decrypt traffic** - Only analyzes handshakes and metadata
- **PQ detection limitations** - Relies on recognizing known PQ algorithm names
- **Protocol coverage** - Covers major protocols, but not all possible encrypted protocols
- **Performance** - Processing many packets may impact system performance
- **False positives** - Some heuristics for protocol detection may occasionally misidentify packets

## Troubleshooting

### No packets captured

```bash
# Check interface
ip link show

# Generate traffic
curl https://example.com

# Try specific interface
sudo ./quantum-sniffer.py -i eth0
```

### Permission denied

```bash
# Use sudo
sudo ./quantum-sniffer.py
```

### Scapy not installed

```bash
pip3 install scapy
```

### Too many packets

```bash
# Filter by specific IP
# Edit quantum-sniffer.py, add to filter_str:
"and host 10.1.1.100"
```

## Legal Notice

**Authorized Use Only:**
- Your own networks
- Networks with explicit written permission
- Authorized security assessments
- Educational purposes in controlled environments

**Unauthorized network monitoring may violate:**
- Computer Fraud and Abuse Act (USA)
- Similar laws in other jurisdictions
- Privacy regulations (GDPR, etc.)
- Corporate policies

Use responsibly and legally.

## Future Enhancements

Potential additions:
- Full IKE proposal parsing
- Certificate extraction
- PCAP file analysis mode
- Real-time alerting (weak crypto detection)
- Database backend for long-term storage
- Web dashboard
- Machine learning for anomaly detection

## References

### Post-Quantum Cryptography
- NIST PQ Standardization: https://csrc.nist.gov/projects/post-quantum-cryptography
- Kyber: https://pq-crystals.org/kyber/
- Dilithium: https://pq-crystals.org/dilithium/

### Protocols
- TLS 1.3: RFC 8446
- IKEv2: RFC 7296
- WireGuard: https://www.wireguard.com/protocol/
- QUIC: RFC 9000

### Tools
- Scapy: https://scapy.net/

## Support

For issues or questions:
- Check QUICKSTART.md for common examples
- Review documentation in ~/quantum-sniffer/

Enjoy quantum-safe network analysis! 🔐

## License

[GNU General Public License v3.0](LICENSE)

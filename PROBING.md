# Active Probing Feature

## Overview

Quantum-sniffer now supports **active probing** - connecting to remote hosts to test their post-quantum cryptographic capabilities. This complements the existing passive packet capture functionality.

**Status**: ✅ v0.4.0 - Initial TLS probing implementation

## Use Cases

- **Security Auditing**: Scan your infrastructure to identify quantum-vulnerable endpoints
- **Compliance Checking**: Verify PQ crypto deployment across services
- **Migration Planning**: Identify which services need PQ upgrades
- **Monitoring**: Track PQ adoption over time
- **Integration with UPCE**: Probe workloads from inventory to assess security posture

## Quick Start

### CLI Usage

```bash
# Probe single target (scans default TLS ports)
quantum-sniffer --probe 10.1.1.100

# Probe specific port
quantum-sniffer --probe 10.1.1.100:443

# Probe hostname
quantum-sniffer --probe example.com

# Probe custom ports
quantum-sniffer --probe 10.1.1.100 --ports 443,8443,9443

# Adjust timeout
quantum-sniffer --probe example.com --timeout 10.0
```

### Library Usage

```python
from quantum_sniffer.lib import probe_target

# Probe a target
results = probe_target("10.1.1.100:443")
for result in results:
    print(f"Port {result.target_port}: {result.post_quantum_secure}")
    if result.is_pq_capable:
        print(f"  ✓ PQ-capable: {result.key_exchange_group}")
    else:
        print(f"  ✗ Classical only")

# Probe specific ports
results = probe_target("10.1.1.100", ports=[443, 8443])

# Probe multiple targets
targets = ["web1.example.com", "web2.example.com", "db.example.com"]
for target in targets:
    results = probe_target(target, ports=[443], timeout=5.0)
    # Process results...
```

## Output Format

### CLI Output

```
================================================================================
PROBE RESULTS
================================================================================

✓ 10.1.1.100:443   open       🔒 Hybrid     TLSv1.3, TLS_AES_256_GCM_SHA384
✗ 10.1.1.100:8443  closed
⏱ 10.1.1.100:9443  timeout    (Connection timeout (5.0s))

================================================================================
Summary: 1/3 ports open
         1/1 with PQ crypto support
================================================================================

DETAILED RESULTS (Open Ports)
================================================================================

Port: 443
  TLS Version:       TLSv1.3
  Cipher Suite:      TLS_AES_256_GCM_SHA384
  Key Exchange:      TLS 1.3 key exchange (check supported_groups)
  PQ Status:         Hybrid
  Server Name:       example.com
  Cert Subject:      CN=example.com
  Cert Issuer:       CN=Let's Encrypt Authority X3
  Cert Expires:      Dec 31 23:59:59 2024 GMT
  Probe Duration:    123.45ms
```

### Library Output

`ProbeResult` object with attributes:
- `target_ip` - Resolved IP address
- `target_port` - Port number
- `status` - PortStatus enum (OPEN, CLOSED, FILTERED, TIMEOUT, ERROR)
- `protocol` - "tls" (more protocols coming)
- `tls_version` - "TLSv1.3", "TLS 1.2", etc.
- `cipher_suite` - Selected cipher (e.g., "TLS_AES_256_GCM_SHA384")
- `key_exchange_group` - Key exchange info
- `post_quantum_secure` - "Yes", "Hybrid", "No", or "Unknown"
- `server_name` - Server name from certificate
- `certificate_info` - Certificate details (subject, issuer, expiry, SANs)
- `probe_duration_ms` - Time taken to probe
- `is_pq_capable` - Boolean property (True if Yes or Hybrid)

## Default Ports

When no ports specified, probes these TLS/HTTPS ports:

- 443 - HTTPS
- 8443, 4443, 9443 - Alternate HTTPS
- 853 - DNS over TLS
- 636 - LDAPS
- 989, 990 - FTPS
- 992 - Telnets
- 993 - IMAPS
- 995 - POP3S
- 5061 - SIPS

## How It Works

### TLS Probing Process

1. **DNS Resolution** - Resolve hostname to IP (if needed)
2. **TCP Connection** - Establish TCP connection with timeout
3. **TLS Handshake** - Perform full TLS handshake using Python's `ssl` module
4. **Extract Metadata** - Capture TLS version, cipher, certificate
5. **Classify PQ Status** - Analyze cryptographic parameters
6. **Return Result** - Structured ProbeResult object

### PQ Classification Logic

Currently, TLS probing uses Python's built-in `ssl` module, which has limited visibility into negotiated key exchange groups. Classification:

- **TLS 1.3** → Marked as "Unknown" (groups not exposed by Python ssl)
- **TLS 1.2 and earlier** → "No" (classical crypto)

**Future Enhancement**: Use lower-level libraries (`cryptography`, `scapy`) to craft custom ClientHello with PQ groups and parse ServerHello to detect actual PQ support.

## Limitations (Current)

### Python ssl Module Constraints

The current implementation uses Python's standard `ssl` module, which:
- ✅ Works reliably for basic TLS connections
- ✅ Extracts TLS version, cipher, certificate
- ❌ Doesn't expose negotiated key exchange groups
- ❌ Can't customize ClientHello to advertise specific PQ groups
- ❌ Limited control over TLS extension handling

**Result**: TLS 1.3 connections are marked "Unknown" because we can't determine if PQ groups were used.

### Protocol Support

- ✅ **TLS/HTTPS** - Fully implemented
- 🚧 **SSH** - Planned (easy to add)
- 🚧 **IKEv2/IPsec** - Planned (requires IKE packet crafting)
- ❌ **QUIC** - Planned (requires UDP + QUIC Initial packet handling)
- ❌ **WireGuard** - Not applicable (uses pre-shared keys, no negotiation)

## Future Enhancements

### Phase 2: Enhanced TLS Probing

Use `cryptography` or `scapy` to:
- Craft custom ClientHello with PQ groups (x25519kyber768, etc.)
- Parse ServerHello to see which group server selected
- Definitively classify PQ support as Yes/Hybrid/No

```python
# Future capability
result = probe_target("example.com:443", probe_mode="full")
# probe_mode options:
#   "basic" - Current behavior (Python ssl)
#   "full" - Custom ClientHello, parse ServerHello
#   "capability" - Multiple probes to test all scenarios
```

### Phase 3: SSH Probing

SSH is easier than TLS because KEX algorithms are in plaintext:

1. Connect to port 22
2. Send SSH version string
3. Send SSH_MSG_KEXINIT
4. Parse server's KEXINIT reply
5. Extract KEX algorithm list
6. Classify PQ status (sntrup761x25519, mlkem768x25519, etc.)

### Phase 4: Batch & Parallelism

```bash
# Probe from file
quantum-sniffer --probe-list targets.txt --workers 10

# Probe CIDR range
quantum-sniffer --probe 10.1.1.0/24 --ports 443

# UPCE integration
quantum-sniffer --probe-inventory ../common/inventory.json
```

Library API:
```python
from quantum_sniffer.lib import probe_many

# Async batch probing
results = await probe_many(
    targets=["10.1.1.1", "10.1.1.2", "10.1.1.3"],
    ports=[443, 8443],
    concurrency=10,
    timeout=5.0
)
```

### Phase 5: Comparison Probing

Test server's full PQ capabilities:

```bash
quantum-sniffer --probe example.com:443 --compare
```

Sends multiple ClientHellos:
1. Classical only (ECDHE, RSA) → What does server respond?
2. PQ only (Kyber, ML-KEM) → Does it work?
3. Hybrid (x25519kyber768) → Does server prefer it?

Result shows server's actual capabilities vs. preferences.

## Architecture

```
quantum_sniffer/lib/prober/
  ├── __init__.py          # Public API
  ├── probe.py             # Orchestration: probe_target(), probe_ports()
  ├── targets.py           # Target parsing (IP, hostname, future: CIDR)
  ├── tls_probe.py         # TLS-specific probing logic
  └── results.py           # ProbeResult, PortStatus models
```

**Design Principles**:
- Generic architecture for multiple protocols
- Extensible for future probe strategies
- Clean separation: target parsing, protocol-specific probing, result models
- Works as library or CLI

## Security & Ethics

### Legal Considerations

**Active probing = port scanning = may be illegal without authorization.**

- ✅ Probe your own infrastructure
- ✅ Probe with written permission
- ✅ Probe public services for research (respectfully)
- ❌ Scanning others' networks without permission
- ❌ Aggressive scanning (may trigger IDS/IPS)
- ❌ Scanning across jurisdictions with different laws

**Always**:
- Use reasonable timeouts (default: 5s)
- Respect rate limits
- Identify yourself (User-Agent if applicable)
- Comply with local laws (CFAA in US, Computer Misuse Act in UK, etc.)

### Detection & Fingerprinting

Probing is **observable**:
- Target logs will show connection attempts
- Firewalls/IDS may alert on port scans
- Some orgs treat scanning as hostile

**Best Practices**:
- Probe only authorized targets
- Use slow, sequential probing (not parallel floods)
- Monitor for adverse reactions (abuse complaints)
- Document authorization in writing

## Examples

### Example 1: Security Audit

```bash
# Scan your web servers
for host in web1 web2 web3 web4; do
    quantum-sniffer --probe $host.example.com:443
done > audit-results.txt
```

### Example 2: UPCE Integration

```python
#!/usr/bin/env python3
"""Probe all UPCE workloads for PQ crypto support."""

import json
from quantum_sniffer.lib import probe_target

# Load UPCE inventory
with open('../common/inventory.json') as f:
    inventory = json.load(f)

# Probe each workload
results = []
for workload in inventory['workloads']:
    name = workload['name']
    ips = workload['ips']

    for ip in ips:
        print(f"Probing {name} ({ip})...")
        probe_results = probe_target(ip, ports=[443], timeout=5.0)

        for r in probe_results:
            if r.status.value == "open":
                results.append({
                    'workload': name,
                    'ip': ip,
                    'port': r.target_port,
                    'pq_status': r.post_quantum_secure,
                    'tls_version': r.tls_version,
                    'cipher': r.cipher_suite,
                })

# Save results
with open('pq-audit.json', 'w') as f:
    json.dump(results, f, indent=2)

print(f"\nProbed {len(inventory['workloads'])} workloads")
print(f"Found {len(results)} open TLS ports")
pq_count = sum(1 for r in results if r['pq_status'] in ('Yes', 'Hybrid'))
print(f"PQ-capable: {pq_count}/{len(results)}")
```

### Example 3: Library - Batch Scanning

```python
from quantum_sniffer.lib import probe_target, PortStatus

targets = [
    "web.example.com",
    "api.example.com",
    "db.example.com",
]

print("Scanning targets...")
for target in targets:
    results = probe_target(target, ports=[443], timeout=3.0)
    for r in results:
        if r.status == PortStatus.OPEN:
            status_icon = "✓" if r.is_pq_capable else "✗"
            print(f"{status_icon} {target:20} {r.post_quantum_secure:10} {r.tls_version}")
        else:
            print(f"✗ {target:20} {r.status.value}")
```

## Troubleshooting

### Timeouts

```
⏱ 10.1.1.100:443  timeout    (Connection timeout (5.0s))
```

**Causes**:
- Port is filtered by firewall
- Host is down/unreachable
- Network latency is high
- Service is slow to respond

**Solutions**:
- Increase timeout: `--timeout 10.0`
- Check firewall rules
- Verify host is reachable: `ping 10.1.1.100`
- Use `telnet` or `nc` to test manually

### Connection Refused

```
✗ 10.1.1.100:8443  closed     (Connection refused)
```

**Cause**: Port is not listening (service not running or wrong port)

**Solution**: Verify correct port, check if service is running

### SSL Errors

```
! 10.1.1.100:443   error      (SSL error: CERTIFICATE_VERIFY_FAILED)
```

**Cause**: Certificate validation failure (self-signed, expired, hostname mismatch)

**Note**: Probing disables certificate validation by default. If you see SSL errors, it's likely a protocol/version mismatch.

### Hostname Resolution Failure

```
ERROR: Unable to resolve hostname: invalid.example.com
```

**Cause**: DNS failure, typo in hostname

**Solution**: Check hostname, DNS configuration

## Comparison: Probing vs. Passive Capture

| Feature | Passive Capture | Active Probing |
|---------|----------------|----------------|
| **Trigger** | Wait for traffic | Immediate test |
| **Authorization** | Monitor your network | May need permission |
| **Detection Risk** | Invisible | Visible in logs |
| **Speed** | Slow (wait for events) | Fast (seconds) |
| **Coverage** | Only active connections | Test dormant services |
| **PQ Detection** | Full visibility | Limited (current) |
| **Protocols** | All supported | TLS only (current) |
| **Best For** | Production monitoring | Audits, compliance |

**Recommendation**: Use both!
- **Probing**: Initial audit, compliance checks
- **Passive**: Ongoing monitoring, validation

## Related Documentation

- **Library API**: See `example_library_usage.py`
- **Refactoring**: See `REFACTORING_SUMMARY.md`
- **CLI Usage**: Run `quantum-sniffer --help`

## Changelog

### v0.4.0 (2024-06-24)
- ✨ Initial probing implementation
- ✅ TLS probing via Python ssl module
- ✅ CLI: `--probe TARGET --ports PORTS`
- ✅ Library API: `probe_target()`, `ProbeResult`
- ✅ Default TLS port scanning
- ✅ Hostname resolution
- ✅ Certificate extraction
- ⚠️ Limited PQ classification (Python ssl constraints)

### Future Versions
- 🚧 v0.5.0: Enhanced TLS probing (custom ClientHello, full PQ detection)
- 🚧 v0.6.0: SSH probing support
- 🚧 v0.7.0: Batch probing, CIDR ranges, parallel execution
- 🚧 v0.8.0: IKEv2/IPsec probing
- 🚧 v0.9.0: QUIC probing

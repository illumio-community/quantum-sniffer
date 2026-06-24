"""quantum-sniffer core library.

Public API for analyzing network protocol handshakes and classifying
post-quantum cryptographic security.
"""

from .analyzer import ProtocolAnalyzer, analyze_packet
from .models import HandshakeResult, ProtocolType, PQStatus
from .pq import classify_connection, classify_tls_group, classify_ike_dh, classify_ssh_kex
from .prober import probe_target, probe_ports, ProbeResult, PortStatus

__all__ = [
    # Passive Analysis
    "ProtocolAnalyzer",
    "analyze_packet",
    # Active Probing
    "probe_target",
    "probe_ports",
    # Models
    "HandshakeResult",
    "ProbeResult",
    "ProtocolType",
    "PQStatus",
    "PortStatus",
    # PQ Classification
    "classify_connection",
    "classify_tls_group",
    "classify_ike_dh",
    "classify_ssh_kex",
]

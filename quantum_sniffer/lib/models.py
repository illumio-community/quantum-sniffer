"""Domain models for protocol analysis."""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union


class PQStatus(str, Enum):
    """Post-quantum security status."""
    YES = "Yes"
    HYBRID = "Hybrid"
    NO = "No"
    UNKNOWN = "Unknown"


class ProtocolType(str, Enum):
    """Supported protocol types."""
    TLS = "TLS"
    DTLS = "DTLS"
    QUIC = "QUIC"
    SSH = "SSH"
    IPSEC = "IPsec"
    WIREGUARD = "WireGuard"
    DNS_OVER_TLS = "DNS-over-TLS"
    DNSSEC = "DNSSEC"
    STARTTLS = "STARTTLS"
    SMB = "SMB"
    RDP = "RDP"
    KERBEROS = "Kerberos"
    SNMPV3 = "SNMPv3"
    OPENVPN = "OpenVPN"
    RADIUS = "RADIUS"
    AMQP = "AMQP"
    SIP = "SIP"
    ZRTP = "ZRTP"
    BGP = "BGP"
    OPCUA = "OPC-UA"
    UNKNOWN = "Unknown"


@dataclass
class HandshakeResult:
    """Result of analyzing a network protocol handshake.

    This is the core data structure returned by the library. It contains
    both common fields (present for all protocols) and protocol-specific
    fields (stored in the extras dict).
    """

    # Common fields - always present
    protocol: str
    type: str
    timestamp: str  # ISO format
    post_quantum_secure: str  # PQStatus enum value
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    connection: str
    direction: str
    encrypted: bool

    # Protocol-specific fields
    extras: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization.

        Flattens the structure by merging common fields with extras.
        This maintains backward compatibility with the CLI output format.
        """
        result = {
            "protocol": self.protocol,
            "type": self.type,
            "timestamp": self.timestamp,
            "post_quantum_secure": self.post_quantum_secure,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "connection": self.connection,
            "direction": self.direction,
            "encrypted": self.encrypted,
        }
        # Merge protocol-specific fields
        result.update(self.extras)
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HandshakeResult":
        """Create from dictionary (inverse of to_dict)."""
        # Extract common fields
        common_fields = {
            "protocol": data.get("protocol", "Unknown"),
            "type": data.get("type", "Unknown"),
            "timestamp": data.get("timestamp", datetime.now().isoformat()),
            "post_quantum_secure": data.get("post_quantum_secure", "Unknown"),
            "src_ip": data.get("src_ip", ""),
            "src_port": data.get("src_port", 0),
            "dst_ip": data.get("dst_ip", ""),
            "dst_port": data.get("dst_port", 0),
            "connection": data.get("connection", ""),
            "direction": data.get("direction", ""),
            "encrypted": data.get("encrypted", False),
        }

        # Everything else goes into extras
        extras = {
            k: v for k, v in data.items()
            if k not in common_fields
        }

        return cls(**common_fields, extras=extras)

    # Convenience accessors for common protocol-specific fields

    @property
    def tls_version(self) -> Optional[str]:
        """TLS/DTLS version string."""
        return self.extras.get("tls_version")

    @property
    def server_name(self) -> Optional[str]:
        """TLS SNI (Server Name Indication)."""
        return self.extras.get("server_name")

    @property
    def selected_cipher(self) -> Optional[str]:
        """Selected cipher suite (TLS ServerHello)."""
        return self.extras.get("selected_cipher")

    @property
    def ssh_banner(self) -> Optional[str]:
        """SSH server banner."""
        return self.extras.get("ssh_banner")

    @property
    def supported_groups(self) -> List[str]:
        """TLS supported groups (key exchange)."""
        return self.extras.get("supported_groups", [])

    @property
    def supported_group_ids(self) -> List[int]:
        """TLS supported group IDs (numeric)."""
        return self.extras.get("supported_group_ids", [])

    @property
    def ssh_kex_algorithms(self) -> List[str]:
        """SSH key exchange algorithms."""
        return self.extras.get("ssh_kex_algorithms", [])

    @property
    def ike_proposals(self) -> List[Dict[str, Any]]:
        """IKEv2 SA proposals."""
        return self.extras.get("ike_proposals", [])

    @property
    def application(self) -> Optional[str]:
        """Detected application (e.g., "gRPC / HTTP2", "Tor")."""
        return self.extras.get("application")

    @property
    def note(self) -> Optional[str]:
        """Additional notes or warnings."""
        return self.extras.get("note")

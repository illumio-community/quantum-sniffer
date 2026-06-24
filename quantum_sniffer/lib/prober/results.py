"""Result models for probing operations."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Any


class PortStatus(str, Enum):
    """Status of a probed port."""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ProbeResult:
    """Result of probing a single target:port.

    Represents the outcome of attempting to connect and analyze
    cryptographic capabilities of a network service.
    """

    # Target information
    target_ip: str
    target_port: int
    protocol: str  # "tls", "ssh", etc.

    # Connection status
    status: PortStatus
    error_message: Optional[str] = None

    # TLS-specific results (when protocol="tls" and status="open")
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange_group: Optional[str] = None
    server_name: Optional[str] = None

    # PQ assessment
    post_quantum_secure: Optional[str] = None  # "Yes", "Hybrid", "No", "Unknown"

    # Additional details
    supported_groups: List[str] = field(default_factory=list)
    alpn_protocols: List[str] = field(default_factory=list)
    certificate_info: Optional[Dict[str, Any]] = None

    # Protocol-specific extras (for SSH KEX, IKE proposals, etc.)
    extras: Dict[str, Any] = field(default_factory=dict)

    # Metadata
    probe_duration_ms: Optional[float] = None
    timestamp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        result = {
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "protocol": self.protocol,
            "status": self.status.value,
        }

        if self.error_message:
            result["error_message"] = self.error_message

        if self.status == PortStatus.OPEN:
            result.update({
                "tls_version": self.tls_version,
                "cipher_suite": self.cipher_suite,
                "key_exchange_group": self.key_exchange_group,
                "server_name": self.server_name,
                "post_quantum_secure": self.post_quantum_secure,
                "supported_groups": self.supported_groups,
                "alpn_protocols": self.alpn_protocols,
            })

            if self.certificate_info:
                result["certificate_info"] = self.certificate_info

            # Include protocol-specific extras
            if self.extras:
                result.update(self.extras)

        if self.probe_duration_ms:
            result["probe_duration_ms"] = self.probe_duration_ms
        if self.timestamp:
            result["timestamp"] = self.timestamp

        return result

    @property
    def is_pq_capable(self) -> bool:
        """Check if target supports any level of PQ crypto."""
        return self.post_quantum_secure in ("Yes", "Hybrid")

    @property
    def summary(self) -> str:
        """Human-readable one-line summary."""
        if self.status != PortStatus.OPEN:
            return f"{self.target_ip}:{self.target_port} - {self.status.value}"

        pq_indicator = "✓" if self.is_pq_capable else "✗"
        return (
            f"{self.target_ip}:{self.target_port} - {pq_indicator} "
            f"{self.post_quantum_secure} ({self.tls_version}, {self.key_exchange_group})"
        )

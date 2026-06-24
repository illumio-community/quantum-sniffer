"""Utility functions for protocol analysis."""

from datetime import datetime
from typing import Any


def now_iso() -> str:
    """Return current timestamp in ISO format."""
    return datetime.now().isoformat()


def get_ip_layer(pkt: Any) -> Any:
    """Extract IP or IPv6 layer from packet.

    Args:
        pkt: Scapy packet

    Returns:
        IP or IPv6 layer
    """
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    return pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]


def connection_id(ip: Any, transport: Any) -> str:
    """Create connection identifier string.

    Args:
        ip: IP or IPv6 layer
        transport: TCP or UDP layer

    Returns:
        String like "10.1.1.1:443 -> 10.1.1.2:53234"
    """
    return f"{ip.src}:{transport.sport} -> {ip.dst}:{transport.dport}"


def extract_connection_info(pkt: Any, transport_layer: Any) -> dict:
    """Extract common connection information from packet.

    Args:
        pkt: Scapy packet with IP layer
        transport_layer: TCP or UDP layer

    Returns:
        Dictionary with src_ip, dst_ip, src_port, dst_port, connection
    """
    ip = get_ip_layer(pkt)
    return {
        "src_ip": ip.src,
        "src_port": transport_layer.sport,
        "dst_ip": ip.dst,
        "dst_port": transport_layer.dport,
        "connection": connection_id(ip, transport_layer),
    }

"""Main protocol analyzer API."""

from typing import Any, List, Optional, Union

from .models import HandshakeResult
from .pq import classify_connection


class ProtocolAnalyzer:
    """High-level protocol analyzer.

    Orchestrates protocol detection and analysis across all supported
    protocols. Use this class for batch analysis or when building a
    stateful analyzer.

    Example:
        analyzer = ProtocolAnalyzer()
        for packet in packets:
            result = analyzer.process(packet)
            if result:
                print(f"Found {result.protocol}: {result.post_quantum_secure}")
    """

    def __init__(self, encrypted_only: bool = True, debug: bool = False):
        """Initialize analyzer.

        Args:
            encrypted_only: If True, skip unencrypted protocols
            debug: If True, re-raise exceptions instead of catching them
        """
        self.encrypted_only = encrypted_only
        self.debug = debug
        self._handlers = None
        self.event_count = 0
        self.protocol_counts = {}
        self.pq_counts = {"Yes": 0, "Hybrid": 0, "No": 0, "Unknown": 0}

    def _get_handlers(self):
        """Lazy-load protocol handlers to avoid circular imports."""
        if self._handlers is None:
            # Import the legacy analyzers for now
            # TODO: Replace with new protocol handlers as they're created
            from ..analyzers import ANALYZERS
            self._handlers = ANALYZERS
        return self._handlers

    def process(self, packet: Any) -> Optional[HandshakeResult]:
        """Analyze a single packet.

        Args:
            packet: Scapy Packet object or raw bytes

        Returns:
            HandshakeResult if handshake detected, None otherwise
        """
        # For now, delegate to legacy analyzers
        # This will be refactored as we create proper protocol handlers
        handlers = self._get_handlers()

        # Check if packet has IP layer
        if not (packet.haslayer("IP") or packet.haslayer("IPv6")):
            return None

        info = None
        for analyzer_func in handlers:
            try:
                info = analyzer_func(packet)
            except Exception as exc:
                if self.debug:
                    raise
                # Silently skip failed analyzers unless in debug mode
                continue
            if info:
                break

        if not info:
            return None

        # Skip unencrypted if requested
        if self.encrypted_only and not info.get("encrypted", False):
            return None

        # Convert dict to HandshakeResult
        result = HandshakeResult.from_dict(info)

        # Update statistics
        self.event_count += 1
        proto = result.protocol
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1
        pq = result.post_quantum_secure
        self.pq_counts[pq] = self.pq_counts.get(pq, 0) + 1

        return result

    def summary(self) -> dict:
        """Get analysis statistics.

        Returns:
            Dictionary with event counts, protocol breakdown, and PQ status summary
        """
        return {
            "events": self.event_count,
            "protocols": dict(sorted(self.protocol_counts.items(), key=lambda x: -x[1])),
            "post_quantum": dict(self.pq_counts),
        }


def analyze_packet(
    packet: Any,
    encrypted_only: bool = True,
    debug: bool = False
) -> Optional[HandshakeResult]:
    """Analyze a single packet (convenience function).

    This is a stateless wrapper around ProtocolAnalyzer.process() for
    one-off packet analysis.

    Args:
        packet: Scapy Packet object or raw bytes
        encrypted_only: If True, skip unencrypted protocols
        debug: If True, re-raise exceptions instead of catching them

    Returns:
        HandshakeResult if handshake detected, None otherwise

    Example:
        from scapy.all import rdpcap
        packets = rdpcap("capture.pcap")
        for pkt in packets:
            result = analyze_packet(pkt)
            if result:
                print(f"{result.protocol}: {result.post_quantum_secure}")
    """
    analyzer = ProtocolAnalyzer(encrypted_only=encrypted_only, debug=debug)
    return analyzer.process(packet)

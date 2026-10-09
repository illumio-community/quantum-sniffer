"""Main protocol analyzer API."""

from datetime import datetime
from typing import Any, List, Optional

from ..context import AnalysisContext
from ..reassembly import IpDefragmenter, TcpReassembler
from .models import HandshakeResult


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

    def __init__(self, encrypted_only: bool = True, debug: bool = False,
                 l7: bool = False):
        """Initialize analyzer.

        Args:
            encrypted_only: If True, skip unencrypted protocols. Layer-7
                events (``layer7: True``) are exempt.
            debug: If True, re-raise exceptions instead of catching them
            l7: If True, also run the layer-7 analyzers (HTTP, DNS,
                NetBIOS). Detection and reporting only.
        """
        self.encrypted_only = encrypted_only
        self.debug = debug
        self.l7 = l7
        self._handlers = None
        self.event_count = 0
        self.protocol_counts = {}
        self.pq_counts = {"Yes": 0, "Hybrid": 0, "No": 0, "Unknown": 0}
        self.findings = {}
        self.ctx = AnalysisContext()
        self._defrag = IpDefragmenter()
        self._tcp = TcpReassembler()

    def _get_handlers(self):
        """Lazy-load protocol handlers to avoid circular imports."""
        if self._handlers is None:
            # Import the legacy analyzers for now
            # TODO: Replace with new protocol handlers as they're created
            from ..analyzers import ANALYZERS
            from ..l7_analyzers import L7_ANALYZERS, analyze_smb
            if self.l7:
                # L7 first: the DNS analyzer folds DNSSEC data into its event.
                self._handlers = L7_ANALYZERS + ANALYZERS
            else:
                self._handlers = [analyze_smb] + ANALYZERS
        return self._handlers

    def process_all(self, packet: Any) -> List[HandshakeResult]:
        """Analyze one captured packet; return every event it completes.

        Packets go through IP defragmentation and TCP handshake reassembly
        first, so one captured packet can complete zero events (it was
        buffered) or several (a segment finishing an SSH banner and KEXINIT).
        Feed packets in capture order to the same analyzer.
        """
        if not (packet.haslayer("IP") or packet.haslayer("IPv6")):
            return []
        packet = self._defrag.feed(packet)
        if packet is None:
            return []
        results = []
        for unit in self._tcp.feed(packet):
            unit.qs_ctx = self.ctx
            results.extend(self._analyze(unit))
        return results

    def process(self, packet: Any) -> Optional[HandshakeResult]:
        """Analyze a single packet; return its first event, if any.

        Prefer ``process_all``: when one packet completes several events,
        this returns only the first.
        """
        results = self.process_all(packet)
        return results[0] if results else None

    def _analyze(self, packet: Any) -> List[HandshakeResult]:
        """Run the analyzers on one unit; the first that recognises it wins.
        An analyzer may return one event dict or a list of them."""
        found = None
        for analyzer_func in self._get_handlers():
            try:
                found = analyzer_func(packet)
            except Exception:
                if self.debug:
                    raise
                continue
            if found:
                break
        if not found:
            return []
        events = found if isinstance(found, list) else [found]
        return [r for r in (self._record(info, packet) for info in events) if r]

    def _record(self, info: dict, packet: Any) -> Optional[HandshakeResult]:

        # Skip unencrypted if requested
        if (self.encrypted_only and not info.get("encrypted", False)
                and not info.get("layer7")):
            return None

        # Event time is the packet's capture time (pcap replay included), not
        # the time we got round to analyzing it.
        ptime = getattr(packet, "time", None)
        if ptime:
            info["timestamp"] = datetime.fromtimestamp(float(ptime)).isoformat()

        result = HandshakeResult.from_dict(info)

        # Update statistics
        self.event_count += 1
        proto = result.protocol
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1
        pq = result.post_quantum_secure
        self.pq_counts[pq] = self.pq_counts.get(pq, 0) + 1
        for finding in l7_findings(info):
            self.findings[finding] = self.findings.get(finding, 0) + 1

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
            "findings": dict(sorted(self.findings.items(), key=lambda x: -x[1])),
        }


def l7_findings(info: dict) -> List[str]:
    """Name the layer-7 findings an event carries (for summaries)."""
    out = []
    if info.get("tls_deprecated_version"):
        out.append("deprecated TLS version offered")
    if info.get("tls_weak_cipher"):
        out.append("weak TLS cipher offered")
    if info.get("tls_deprecated_version_negotiated"):
        out.append("deprecated TLS version negotiated")
    if info.get("tls_weak_cipher_negotiated"):
        out.append("weak TLS cipher negotiated")
    if info.get("ssh_version") in ("1", "1.99"):
        out.append("SSH-1 offered")
    if info.get("smb_version") == "1":
        out.append("SMB1 in use")
    if info.get("smb_encrypted"):
        out.append("SMB3 encrypted session")
    if info.get("smb_transport") == "quic":
        out.append("SMB over QUIC")
    if info.get("dns_conforming") is False:
        out.append("non-DNS traffic on port 53")
    if info.get("protocol") == "HTTP":
        out.append("cleartext HTTP request")
    return out


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

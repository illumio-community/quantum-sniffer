"""Base protocol handler interface."""

from abc import ABC, abstractmethod
from typing import Any, Optional

from ..models import HandshakeResult


class ProtocolHandler(ABC):
    """Abstract base class for protocol handlers.

    Each protocol handler is responsible for:
    1. Detecting if a packet belongs to its protocol
    2. Extracting relevant handshake information
    3. Building a HandshakeResult with appropriate metadata
    """

    @abstractmethod
    def can_handle(self, packet: Any) -> bool:
        """Check if this handler can process the given packet.

        Args:
            packet: A scapy Packet object or raw bytes

        Returns:
            True if this handler should process this packet
        """
        pass

    @abstractmethod
    def analyze(self, packet: Any) -> Optional[HandshakeResult]:
        """Analyze a packet and return handshake information.

        Args:
            packet: A scapy Packet object

        Returns:
            HandshakeResult if analysis succeeded, None otherwise
        """
        pass

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        """Human-readable protocol name."""
        pass

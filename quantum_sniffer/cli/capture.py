"""Packet capture and sniffing logic for CLI."""

import sys
import traceback
from typing import Any, Callable

from ..lib.analyzer import ProtocolAnalyzer
from .output import DualWriter, print_info


class CaptureEngine:
    """Manages packet capture and analysis for the CLI.

    Wraps ProtocolAnalyzer with CLI-specific concerns like output
    formatting, error handling, and statistics.
    """

    def __init__(
        self,
        writer: DualWriter,
        encrypted_only: bool = True,
        debug: bool = False,
        quiet: bool = False,
        l7: bool = False,
    ):
        """Initialize capture engine.

        Args:
            writer: Output writer for results
            encrypted_only: Skip unencrypted protocols
            debug: Re-raise analyzer exceptions
            quiet: Suppress per-event console output
            l7: Run the layer-7 analyzers (detection/reporting only)
        """
        self.writer = writer
        self.analyzer = ProtocolAnalyzer(encrypted_only=encrypted_only, debug=debug, l7=l7)
        self.quiet = quiet
        self.debug = debug

    def process_packet(self, pkt: Any) -> None:
        """Process a single packet (callback for scapy sniff).

        Args:
            pkt: Scapy Packet object
        """
        try:
            for result in self.analyzer.process_all(pkt):
                info = result.to_dict()
                if not self.quiet:
                    print_info(info)
                self.writer.write(info)

        except Exception as exc:
            if self.debug:
                raise
            print(
                f"[!] Packet processing failed: {exc.__class__.__name__}: {exc}",
                file=sys.stderr,
            )
            if self.debug:
                traceback.print_exc(file=sys.stderr)

    def summary(self) -> dict:
        """Get capture statistics.

        Returns:
            Dictionary with event counts, protocol breakdown, PQ summary
        """
        return self.analyzer.summary()

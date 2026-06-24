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
        quiet: bool = False
    ):
        """Initialize capture engine.

        Args:
            writer: Output writer for results
            encrypted_only: Skip unencrypted protocols
            debug: Re-raise analyzer exceptions
            quiet: Suppress per-event console output
        """
        self.writer = writer
        self.analyzer = ProtocolAnalyzer(encrypted_only=encrypted_only, debug=debug)
        self.quiet = quiet
        self.debug = debug

    def process_packet(self, pkt: Any) -> None:
        """Process a single packet (callback for scapy sniff).

        Args:
            pkt: Scapy Packet object
        """
        try:
            result = self.analyzer.process(pkt)
            if result:
                # Convert to dict for output
                info = result.to_dict()

                # Print to console unless quiet
                if not self.quiet:
                    print_info(info)

                # Write to output files
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

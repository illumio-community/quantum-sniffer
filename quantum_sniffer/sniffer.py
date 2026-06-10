"""Top-level sniffer engine: dispatch packets to analyzers, write output."""

import sys
import traceback

from .analyzers import ANALYZERS
from .output import JsonlWriter, print_info


class Sniffer:
    def __init__(self, writer, encrypted_only=True, debug=False, quiet=False):
        self.writer = writer
        self.encrypted_only = encrypted_only
        self.debug = debug
        self.quiet = quiet
        self.event_count = 0
        self.protocol_counts = {}
        self.pq_counts = {"Yes": 0, "Hybrid": 0, "No": 0, "Unknown": 0}

    def process_packet(self, pkt):
        if not (pkt.haslayer("IP") or pkt.haslayer("IPv6")):
            return
        info = None
        for analyzer in ANALYZERS:
            try:
                info = analyzer(pkt)
            except Exception as exc:
                if self.debug:
                    raise
                print(
                    f"[!] {analyzer.__name__} failed: {exc.__class__.__name__}: {exc}",
                    file=sys.stderr,
                )
                if self.debug:
                    traceback.print_exc(file=sys.stderr)
                continue
            if info:
                break
        if not info:
            return
        if self.encrypted_only and not info.get("encrypted", False):
            return
        self.event_count += 1
        proto = info.get("protocol", "Unknown")
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1
        pq = info.get("post_quantum_secure", "Unknown")
        self.pq_counts[pq] = self.pq_counts.get(pq, 0) + 1
        if not self.quiet:
            print_info(info)
        self.writer.write(info)

    def summary(self):
        return {
            "events": self.event_count,
            "protocols": dict(sorted(self.protocol_counts.items(), key=lambda x: -x[1])),
            "post_quantum": dict(self.pq_counts),
        }

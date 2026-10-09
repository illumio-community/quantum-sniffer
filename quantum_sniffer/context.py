"""Per-analyzer state shared by the stateful analyzers.

``ProtocolAnalyzer`` owns one ``AnalysisContext`` and attaches it to every
packet it hands to an analyzer as ``pkt.qs_ctx``. An analyzer called on a bare
packet (no context) gets a fresh one, i.e. stateless one-packet behaviour.
"""

from collections import OrderedDict

from .parsers.quic import QuicFlowTracker


class Bounded(OrderedDict):
    """Insertion-ordered dict that evicts its oldest entries past ``limit``."""

    def __init__(self, limit=8192):
        super().__init__()
        self.limit = limit

    def put(self, key, value):
        self[key] = value
        self.move_to_end(key)
        while len(self) > self.limit:
            self.popitem(last=False)


class AnalysisContext:
    def __init__(self):
        self.quic = QuicFlowTracker()
        self.reported = Bounded()   # (connection, finding) -> True, for dedupe


def get_ctx(pkt):
    ctx = getattr(pkt, "qs_ctx", None)
    return ctx if ctx is not None else AnalysisContext()

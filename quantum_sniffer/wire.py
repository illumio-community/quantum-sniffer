"""Original wire bytes of a dissected packet's payload.

``bytes(layer.payload)`` asks scapy to re-serialise whatever it decoded, and
that is not always the bytes that were captured: scapy's stateful TLS layer
(loaded by anyone importing ``scapy.layers.tls``) rebuilds handshake records
differently, same length, different content. Every parser here wants the
captured bytes, so they are sliced out of the packet's ``original`` buffer
using each layer's ``raw_packet_cache`` (the bytes its own header consumed).
Re-serialisation is only the fallback for packets that were built in code
rather than dissected.
"""

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.packet import NoPayload


def payload_after(pkt, layer_cls):
    """Bytes following the ``layer_cls`` header, up to the end of the IP
    datagram (so Ethernet trailer padding is excluded; scapy's ``Padding``
    layer is NOT used for that, because scapy's TLS layer also labels an
    incomplete record as Padding)."""
    orig = getattr(pkt, "original", None)
    if orig:
        off, ip_end, layer = 0, len(orig), pkt
        while layer is not None and not isinstance(layer, NoPayload):
            cache = layer.raw_packet_cache
            if cache is None:
                break
            if isinstance(layer, IP) and layer.len:
                ip_end = min(len(orig), off + layer.len)
            elif isinstance(layer, IPv6) and layer.plen:
                ip_end = min(len(orig), off + 40 + layer.plen)
            off += len(cache)
            if isinstance(layer, layer_cls):
                if off <= ip_end:
                    return bytes(orig[off:ip_end])
                break
            layer = layer.payload
    try:
        return bytes(pkt[layer_cls].payload)
    except Exception:
        return b""

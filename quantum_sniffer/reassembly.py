"""TCP handshake reassembly.

Analyzers look at one packet at a time. Handshake messages do not respect
that: a post-quantum TLS ClientHello (X25519MLKEM768 adds ~1.2 KB of key
share) no longer fits one segment, an SSH KEXINIT often doesn't either, and an
HTTP request's headers can span several. This module rebuilds the first part
of each TCP direction in order, cuts it into protocol messages ("PDUs") with a
per-protocol framer, and hands each complete PDU to the analyzers as a
synthetic single-segment packet. Analyzers need no changes.

Scope is deliberately the HANDSHAKE, not the whole stream:
  * at most ``MAX_STREAM_BYTES`` per direction are reassembled; a framer also
    declares itself done once the handshake it cares about is over
  * after that, or for traffic no framer recognises, packets pass through to
    the analyzers unchanged (the old per-packet behaviour)
  * flows, out-of-order data and total buffered bytes are all bounded, and
    idle flows expire on capture time

Joining a connection mid-stream is handled: a direction whose start we never
saw is framed from the first segment that begins a recognisable message (a
TLS hello record or an SSH banner), and otherwise passes through. DNS over TCP
is the exception: it is only framed from a captured SYN, because judging
unaligned bytes as "not DNS" would condemn healthy resolvers.
"""

import struct
from collections import OrderedDict

from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw

from .wire import payload_after

SEQ_MOD = 1 << 32
MAX_STREAM_BYTES = 65536        # reassembled per direction
MAX_FLOWS = 16384
MAX_TOTAL_BUFFERED = 64 << 20   # bytes held across all flows
IDLE_SECONDS = 120.0
MAX_PDU = 65000                 # must fit in one synthetic IPv4 packet

HTTP_PORTS = {80}
SMB_PORTS = {139, 445}
SSH_PORTS = {22, 2222}
DNS_PORT = 53
KERBEROS_PORT = 88
RDP_PORT = 3389

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ",
                b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT ")

MORE, DONE, LOST = "more", "done", "lost"


def _is_tls_hello_start(b):
    return (len(b) >= 6 and b[0] == 0x16 and b[1] == 0x03 and b[2] <= 0x04
            and b[5] in (0x01, 0x02))


# ---------------------------------------------------------------------------
# Framers: feed(buf) -> (pdus, consumed, status)
# ---------------------------------------------------------------------------

class TlsFramer:
    """TLS records -> one synthetic record per ClientHello/ServerHello.

    Handshake messages are reassembled across records (a hello larger than
    one record, or several messages in one record). Stops after the hellos:
    everything after ChangeCipherSpec or the first non-handshake record is
    encrypted. A TLS 1.3 HelloRetryRequest exchange yields both hellos.
    """

    def __init__(self):
        self.hs = bytearray()
        self.version = b"\x03\x03"
        self.hellos = 0
        self.after_ccs = False

    def _emit(self, msg):
        return b"\x16" + self.version + struct.pack(">H", len(msg)) + bytes(msg)

    def feed(self, buf):
        pdus, o = [], 0
        while True:
            if len(buf) - o < 5:
                return pdus, o, MORE
            ctype, major = buf[o], buf[o + 1]
            if major != 0x03 or ctype not in (20, 21, 22, 23):
                return pdus, o, LOST
            rlen = struct.unpack(">H", buf[o + 3:o + 5])[0]
            if rlen > 18432:
                return pdus, o, LOST
            if len(buf) - o < 5 + rlen:
                return pdus, o, MORE
            payload = bytes(buf[o + 5:o + 5 + rlen])
            version = bytes(buf[o + 1:o + 3])
            o += 5 + rlen
            if ctype == 20:                      # ChangeCipherSpec
                self.after_ccs = True
                self.hs.clear()
                continue
            if ctype != 22:                      # alert / application data
                return pdus, o, DONE
            if self.after_ccs:
                # Encrypted from here (TLS <= 1.2 Finished), except a TLS 1.3
                # client's second ClientHello after a HelloRetryRequest, which
                # follows a compatibility CCS in plaintext: accept only a
                # record that is exactly one hello.
                if (len(payload) >= 4 and payload[0] in (1, 2)
                        and 4 + int.from_bytes(payload[1:4], "big") == len(payload)):
                    self.version = version
                    pdus.append(self._emit(payload))
                    self.hellos += 1
                    if self.hellos >= 2:
                        return pdus, o, DONE
                    continue
                return pdus, o, DONE
            self.version = version
            self.hs += payload
            while len(self.hs) >= 4:
                mlen = int.from_bytes(self.hs[1:4], "big")
                if 4 + mlen > MAX_PDU:
                    return pdus, o, LOST
                if len(self.hs) < 4 + mlen:
                    break
                msg = bytes(self.hs[:4 + mlen])
                del self.hs[:4 + mlen]
                if msg[0] in (1, 2):
                    pdus.append(self._emit(msg))
                    self.hellos += 1
            if self.hellos >= 2:
                return pdus, o, DONE


class SshFramer:
    """Identification line, then binary packets up to and including KEXINIT.

    A server may send other lines before its "SSH-" line (RFC 4253 §4.2);
    those are skipped.
    """

    def __init__(self):
        self.banner_seen = False
        self.packets = 0

    def feed(self, buf):
        pdus, o = [], 0
        while not self.banner_seen:
            nl = buf.find(b"\n", o)
            if nl < 0:
                return pdus, o, (LOST if len(buf) - o > 8192 else MORE)
            line = bytes(buf[o:nl + 1])
            o = nl + 1
            if line.startswith(b"SSH-"):
                self.banner_seen = True
                pdus.append(line)
        while True:
            if len(buf) - o < 6:
                return pdus, o, MORE
            plen = struct.unpack(">I", buf[o:o + 4])[0]
            if plen < 5 or plen > 35000:
                return pdus, o, LOST
            if len(buf) - o < 4 + plen:
                return pdus, o, MORE
            pkt = bytes(buf[o:o + 4 + plen])
            o += 4 + plen
            pdus.append(pkt)
            self.packets += 1
            if pkt[5] == 20 or self.packets >= 4:   # SSH_MSG_KEXINIT
                return pdus, o, DONE


class LengthPrefixFramer:
    """Messages preceded by a big-endian length: NetBIOS session service
    (4-byte header, 24-bit length: SMB on 139/445), Kerberos over TCP (4-byte,
    top bit reserved), RDP TPKT (03 00 + 16-bit length incl. header).

    Messages too big to buffer are skipped rather than reassembled: every
    message these analyzers read is small.
    """

    def __init__(self, kind, max_messages=32):
        self.kind = kind
        self.max_messages = max_messages
        self.count = 0
        self.skip = 0

    def _length(self, b, o):
        if self.kind == "nbt":
            return 4, 4 + ((b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3])
        if self.kind == "krb":
            return 4, 4 + (struct.unpack(">I", b[o:o + 4])[0] & 0x7FFFFFFF)
        if self.kind == "tpkt":
            if b[o] != 0x03 or b[o + 1] != 0x00:
                return 4, None
            n = struct.unpack(">H", b[o + 2:o + 4])[0]
            return 4, (n if n >= 4 else None)
        raise ValueError(self.kind)

    def feed(self, buf):
        pdus, o = [], 0
        while True:
            if self.skip:
                take = min(self.skip, len(buf) - o)
                self.skip -= take
                o += take
                if self.skip:
                    return pdus, o, MORE
            hdr, total = (4, None) if len(buf) - o < 4 else self._length(buf, o)
            if len(buf) - o < hdr:
                return pdus, o, MORE
            if total is None:
                return pdus, o, LOST
            if total > MAX_PDU:
                self.skip = total
                continue
            if len(buf) - o < total:
                return pdus, o, MORE
            pdus.append(bytes(buf[o:o + total]))
            o += total
            self.count += 1
            if self.count >= self.max_messages:
                return pdus, o, DONE


class DnsTcpFramer:
    """DNS over TCP (2-byte length prefix). Only used from a captured SYN.

    A stream that is plainly not DNS (implausible length or header) is handed
    over as-is so the analyzer can say so, instead of waiting for a body that
    will never be DNS.
    """

    def __init__(self, from_client):
        from .parsers import l7
        self.l7 = l7
        self.from_client = from_client
        self.count = 0

    def feed(self, buf):
        pdus, o = [], 0
        while self.count < self.l7.DNS_TCP_MAX_MESSAGES:
            if len(buf) - o < 2:
                return pdus, o, MORE
            declared = struct.unpack(">H", buf[o:o + 2])[0]
            bad = declared < 12 or (self.from_client
                                    and declared > self.l7.DNS_TCP_MAX_CLIENT_MESSAGE)
            if not bad and len(buf) - o >= 14:
                bad = self.l7.dns_header_plausible(bytes(buf[o + 2:]), declared) is not None
            if bad:
                pdus.append(bytes(buf[o:]))
                return pdus, len(buf), DONE
            if len(buf) - o < 2 + declared:
                return pdus, o, MORE
            pdus.append(bytes(buf[o:o + 2 + declared]))
            o += 2 + declared
            self.count += 1
        return pdus, o, DONE


class HttpFramer:
    """HTTP/1.x request headers. Skips Content-Length bodies; anything it
    cannot delimit (chunked uploads) ends framing for the direction."""

    MAX_HEADERS = 16384

    def __init__(self):
        self.skip = 0

    def feed(self, buf):
        pdus, o = [], 0
        while True:
            if self.skip:
                take = min(self.skip, len(buf) - o)
                self.skip -= take
                o += take
                if self.skip:
                    return pdus, o, MORE
            if len(buf) - o < 8:
                return pdus, o, MORE
            if not bytes(buf[o:o + 8]).startswith(HTTP_METHODS):
                return pdus, o, LOST
            end = buf.find(b"\r\n\r\n", o, o + self.MAX_HEADERS)
            if end < 0:
                return pdus, o, (LOST if len(buf) - o > self.MAX_HEADERS else MORE)
            head = bytes(buf[o:end + 4])
            pdus.append(head)
            o = end + 4
            low = head.lower()
            if b"\ntransfer-encoding:" in low and b"chunked" in low:
                return pdus, o, LOST
            i = low.find(b"\ncontent-length:")
            if i >= 0:
                try:
                    self.skip = int(low[i + 16:low.find(b"\n", i + 1)].strip() or b"0")
                except ValueError:
                    return pdus, o, LOST


# ---------------------------------------------------------------------------
# Streams and flows
# ---------------------------------------------------------------------------

class _Direction:
    __slots__ = ("base", "from_syn", "next", "buf", "pending", "framer", "mode", "fed")

    def __init__(self):
        self.base = None        # sequence number of stream offset 0
        self.from_syn = False
        self.next = 0           # stream offset of the next byte expected
        self.buf = bytearray()  # in-order bytes the framer has not consumed
        self.pending = {}       # offset -> bytes, received ahead of `next`
        self.framer = None
        self.mode = "start"     # start | frame | pass | ignore
        self.fed = 0            # bytes delivered in order (for the cap)

    def held(self):
        return len(self.buf) + sum(len(v) for v in self.pending.values())

    def reset(self, seq):
        self.base, self.next, self.fed = seq, 0, 0
        self.buf = bytearray()
        self.pending = {}


class _Flow:
    __slots__ = ("c", "s", "client", "server_port", "last", "fin")

    def __init__(self, client, server_port):
        self.c = _Direction()
        self.s = _Direction()
        self.client = client          # (ip, port) of the side that opened
        self.server_port = server_port
        self.last = 0.0
        self.fin = 0


class TcpReassembler:
    """Turns captured packets into the packets the analyzers should see."""

    def __init__(self):
        self.flows = OrderedDict()
        self.total = 0
        self._count = 0

    # -- public ---------------------------------------------------------------

    def feed(self, pkt):
        """Return the list of packets to analyze for this captured packet:
        the packet itself (pass-through), nothing (buffered or
        uninteresting), or one synthetic packet per completed PDU."""
        if not pkt.haslayer(TCP):
            return [pkt]
        ip = pkt[IP] if pkt.haslayer(IP) else (pkt[IPv6] if pkt.haslayer(IPv6) else None)
        if ip is None:
            return [pkt]
        tcp = pkt[TCP]
        now = float(getattr(pkt, "time", 0) or 0)
        self._count += 1
        if self._count % 4096 == 0:
            self._expire(now)

        flags = int(tcp.flags)
        syn, ack, fin, rst = flags & 0x02, flags & 0x10, flags & 0x01, flags & 0x04
        a, b = (ip.src, tcp.sport), (ip.dst, tcp.dport)
        key = (a, b) if a <= b else (b, a)
        flow = self.flows.get(key)
        data = payload_after(pkt, TCP)

        if flow is None:
            if rst or (not syn and not data):
                return [pkt] if data else []
            if syn and not ack:
                client, server_port = a, tcp.dport
            elif syn and ack:
                client, server_port = b, tcp.sport
            else:
                server_port = _guess_server_port(tcp.sport, tcp.dport)
                client = a if server_port == tcp.dport else b
            flow = _Flow(client, server_port)
            self.flows[key] = flow
            if len(self.flows) > MAX_FLOWS:
                self._drop(next(iter(self.flows)))
        self.flows.move_to_end(key)
        flow.last = now

        from_client = a == flow.client
        d = flow.c if from_client else flow.s
        if syn:
            d.reset((tcp.seq + 1) % SEQ_MOD)
            d.from_syn = True
            d.mode = "start"
            d.framer = None
        out = []
        if data:
            before = d.held()
            # Data carried in a SYN (TCP Fast Open) starts at seq + 1.
            dseq = (tcp.seq + 1) % SEQ_MOD if syn else tcp.seq
            out = self._data(flow, d, from_client, pkt, dseq, data)
            self.total += d.held() - before
        if rst:
            self._drop(key)
        elif fin:
            flow.fin |= 1 if from_client else 2
            if flow.fin == 3:
                self._drop(key)
        if self.total > MAX_TOTAL_BUFFERED:
            while self.flows and self.total > MAX_TOTAL_BUFFERED // 2:
                self._drop(next(iter(self.flows)))
        return out

    # -- internals ------------------------------------------------------------

    def _data(self, flow, d, from_client, pkt, seq, data):
        if d.mode == "ignore":
            return []
        if d.mode == "pass":
            framer = self._framer_for(flow, from_client, data, aligned=False)
            if framer is None:
                return [pkt]
            d.reset(seq)
            d.framer, d.mode = framer, "frame"
        elif d.base is None:
            # Never saw this direction start: frame only if this segment
            # begins a recognisable message.
            framer = self._framer_for(flow, from_client, data, aligned=False)
            if framer is None:
                d.mode = "ignore" if flow.server_port == DNS_PORT else "pass"
                return [] if d.mode == "ignore" else [pkt]
            d.reset(seq)
            d.framer, d.mode = framer, "frame"

        rel = (seq - d.base) % SEQ_MOD
        if rel >= SEQ_MOD // 2:            # before the stream start: stale
            return []
        if rel + len(data) <= d.next:      # retransmission
            return []
        if rel < d.next:
            data = data[d.next - rel:]
            rel = d.next
        if rel > d.next:
            if rel + len(data) <= MAX_STREAM_BYTES:
                prev = d.pending.get(rel)
                if prev is None or len(data) > len(prev):
                    d.pending[rel] = data
            return []
        d.buf += data
        d.next += len(data)
        while d.pending:
            k = next((k for k, v in d.pending.items() if k <= d.next < k + len(v)), None)
            if k is None:
                break
            chunk = d.pending.pop(k)[d.next - k:]
            d.buf += chunk
            d.next += len(chunk)
        for k in [k for k, v in d.pending.items() if k + len(v) <= d.next]:
            del d.pending[k]

        if d.mode == "start":
            framer = self._framer_for(flow, from_client, d.buf, aligned=d.from_syn)
            if framer is None:
                if len(d.buf) < 8 and d.next < 8:
                    return []              # too few bytes to recognise yet
                buffered = bytes(d.buf)
                d.mode, d.buf = "pass", bytearray()
                if flow.server_port == DNS_PORT:
                    d.mode = "ignore"
                    return []
                return [self._synth(pkt, buffered, d, 0)]
            d.framer, d.mode = framer, "frame"

        pdus, consumed, status = d.framer.feed(d.buf)
        start_off = d.next - len(d.buf)
        out = []
        off = start_off
        for pdu in pdus:
            out.append(self._synth(pkt, pdu, d, off))
            off += len(pdu)
        del d.buf[:consumed]
        if status != MORE or d.next > MAX_STREAM_BYTES:
            # Done: the handshake is over. Lost or capped: we no longer know
            # where messages start. Either way fall back to per-packet
            # analysis, except DNS, which is never judged unaligned.
            d.mode = "ignore" if flow.server_port == DNS_PORT else "pass"
            d.buf = bytearray()
            d.pending = {}
            d.framer = None
        return out

    def _framer_for(self, flow, from_client, b, aligned):
        port = flow.server_port
        if _is_tls_hello_start(b):
            return TlsFramer()
        if bytes(b[:4]) == b"SSH-":
            return SshFramer()
        if not aligned:
            return None
        if port in SSH_PORTS:
            return SshFramer()
        if port == DNS_PORT:
            return DnsTcpFramer(from_client)
        if port in SMB_PORTS:
            return LengthPrefixFramer("nbt")
        if port == KERBEROS_PORT:
            return LengthPrefixFramer("krb", max_messages=8)
        if port == RDP_PORT and len(b) >= 1 and b[0] == 0x03:
            return LengthPrefixFramer("tpkt", max_messages=4)
        if port in HTTP_PORTS and from_client and bytes(b[:8]).startswith(HTTP_METHODS):
            return HttpFramer()
        return None

    def _synth(self, orig, pdu, d, offset):
        ip = orig[IP] if orig.haslayer(IP) else orig[IPv6]
        tcp = orig[TCP]
        cls = type(ip)
        seq = ((d.base or 0) + offset) % SEQ_MOD
        built = cls(src=ip.src, dst=ip.dst) / TCP(
            sport=tcp.sport, dport=tcp.dport, flags="PA", seq=seq) / Raw(pdu[:MAX_PDU])
        out = cls(bytes(built))
        out.time = orig.time
        out.qs_stream = {"from_syn": d.from_syn, "offset": offset}
        return out

    def _drop(self, key):
        flow = self.flows.pop(key, None)
        if flow:
            self.total -= flow.c.held() + flow.s.held()

    def _expire(self, now):
        stale = [k for k, f in self.flows.items() if now - f.last > IDLE_SECONDS]
        for k in stale:
            self._drop(k)


_WELL_KNOWN = {22, 53, 80, 88, 139, 443, 445, 853, 2222, 3389}


def _guess_server_port(sport, dport):
    """Which side is the server when we never saw the SYN."""
    if dport in _WELL_KNOWN and sport not in _WELL_KNOWN:
        return dport
    if sport in _WELL_KNOWN and dport not in _WELL_KNOWN:
        return sport
    return min(sport, dport)


# ---------------------------------------------------------------------------
# IP defragmentation
# ---------------------------------------------------------------------------

class IpDefragmenter:
    """Reassemble IPv4 and IPv6 fragments before analysis.

    Without it the first fragment of a large UDP datagram (an EDNS response
    over ~1472 bytes, a big Kerberos reply) reaches the analyzers truncated,
    and the DNS conformance check calls a healthy resolver "not DNS".
    Non-first fragments are swallowed; the reassembled datagram is returned
    when the last piece arrives.
    """

    MAX_DATAGRAMS = 1024
    MAX_BYTES = 65535
    TIMEOUT = 30.0

    def __init__(self):
        self.parts = OrderedDict()   # key -> {"frags": {off: bytes}, "total": n|None, ...}

    def feed(self, pkt):
        from scapy.layers.inet6 import IPv6ExtHdrFragment
        now = float(getattr(pkt, "time", 0) or 0)
        if pkt.haslayer(IP):
            ip = pkt[IP]
            more, off = bool(int(ip.flags) & 0x1), ip.frag * 8
            if not more and off == 0:
                return pkt
            key = (4, ip.src, ip.dst, ip.id, ip.proto)
            data = payload_after(pkt, IP)
            build = lambda payload: IP(src=ip.src, dst=ip.dst, proto=ip.proto, id=ip.id,
                                       ttl=ip.ttl) / Raw(payload)
        elif pkt.haslayer(IPv6ExtHdrFragment):
            ip6, fh = pkt[IPv6], pkt[IPv6ExtHdrFragment]
            more, off = bool(fh.m), fh.offset * 8
            key = (6, ip6.src, ip6.dst, fh.id, fh.nh)
            data = payload_after(pkt, IPv6ExtHdrFragment)
            build = lambda payload: IPv6(src=ip6.src, dst=ip6.dst, nh=fh.nh,
                                         hlim=ip6.hlim) / Raw(payload)
        else:
            return pkt
        for k in [k for k, v in self.parts.items() if now - v["t"] > self.TIMEOUT]:
            del self.parts[k]
        entry = self.parts.setdefault(key, {"frags": {}, "total": None, "t": now})
        if off + len(data) > self.MAX_BYTES:
            del self.parts[key]
            return None
        entry["frags"][off] = data
        entry["t"] = now
        if not more:
            entry["total"] = off + len(data)
        while len(self.parts) > self.MAX_DATAGRAMS:
            self.parts.popitem(last=False)
        if entry["total"] is None:
            return None
        buf, pos = bytearray(), 0
        for o in sorted(entry["frags"]):
            if o > pos:
                return None           # still a hole
            chunk = entry["frags"][o]
            if o + len(chunk) > pos:
                buf += chunk[pos - o:]
                pos = o + len(chunk)
        if pos < entry["total"]:
            return None
        del self.parts[key]
        cls = IP if key[0] == 4 else IPv6
        out = cls(bytes(build(bytes(buf[:entry["total"]]))))
        out.time = pkt.time
        return out

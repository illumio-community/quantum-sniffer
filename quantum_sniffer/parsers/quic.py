"""QUIC Initial-packet decryption helpers (RFC 9000 / RFC 9001)."""

import hashlib
import hmac as _hmac
import struct

from ..constants import QUIC_INITIAL_SALT_V1, QUIC_INITIAL_SALT_V2

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


def parse_varint(data, offset):
    if offset >= len(data):
        return 0, offset
    first = data[offset]
    prefix = (first & 0xc0) >> 6
    if prefix == 0:
        return first & 0x3f, offset + 1
    if prefix == 1:
        if offset + 2 > len(data):
            return 0, offset
        return struct.unpack(">H", data[offset:offset + 2])[0] & 0x3fff, offset + 2
    if prefix == 2:
        if offset + 4 > len(data):
            return 0, offset
        return struct.unpack(">I", data[offset:offset + 4])[0] & 0x3fffffff, offset + 4
    if offset + 8 > len(data):
        return 0, offset
    return struct.unpack(">Q", data[offset:offset + 8])[0] & 0x3fffffffffffffff, offset + 8


def _hkdf_expand(prk, info, length):
    n = (length + 31) // 32
    t = b""
    t_prev = b""
    for i in range(1, n + 1):
        t_prev = _hmac.new(prk, t_prev + info + bytes([i]), hashlib.sha256).digest()
        t += t_prev
    return t[:length]


def _hkdf_expand_label(secret, label, context, length):
    full_label = b"tls13 " + label
    hkdf_label = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)]) + full_label
        + bytes([len(context)]) + context
    )
    return _hkdf_expand(secret, hkdf_label, length)


QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF
SUPPORTED_VERSIONS = (QUIC_V1, QUIC_V2)


def initial_packet_type(version):
    """Long-header packet-type bits of an Initial: 0b00 in v1, 0b01 in v2
    (RFC 9369 §3.2)."""
    return 0x1 if version == QUIC_V2 else 0x0


def retry_packet_type(version):
    """Long-header packet-type bits of a Retry: 0b11 in v1, 0b00 in v2."""
    return 0x0 if version == QUIC_V2 else 0x3


def derive_initial_keys(dcid, version, server=False):
    """Initial packet protection keys (RFC 9001 §5.2, RFC 9369 §3.3).

    ``dcid`` is the Destination Connection ID of the client's FIRST Initial;
    both directions' keys derive from it. v2 has its own salt and its own
    "quicv2 *" labels.
    """
    v2 = version == QUIC_V2
    salt = QUIC_INITIAL_SALT_V2 if v2 else QUIC_INITIAL_SALT_V1
    initial_secret = _hmac.new(salt, dcid, hashlib.sha256).digest()
    secret = _hkdf_expand_label(initial_secret, b"server in" if server else b"client in", b"", 32)
    prefix = b"quicv2 " if v2 else b"quic "
    key = _hkdf_expand_label(secret, prefix + b"key", b"", 16)
    iv = _hkdf_expand_label(secret, prefix + b"iv", b"", 12)
    hp = _hkdf_expand_label(secret, prefix + b"hp", b"", 16)
    return key, iv, hp


def remove_header_protection(raw_header, payload, hp_key):
    """Unmask the first header byte and the packet number.

    ``raw_header`` is the header through pn_offset + 4 (the maximum packet
    number length). Returns the unprotected header truncated to the REAL
    packet-number length, and that length.
    """
    if not CRYPTO_AVAILABLE or len(payload) < 20:
        return None, 0
    sample = payload[4:20]
    cipher = Cipher(algorithms.AES(hp_key), modes.ECB(), backend=default_backend())
    mask = cipher.encryptor().update(sample)
    header = bytearray(raw_header)
    if header[0] & 0x80:
        header[0] ^= mask[0] & 0x0f
    else:
        header[0] ^= mask[0] & 0x1f
    pn_len = (header[0] & 0x03) + 1
    pn_offset = len(header) - 4
    for i in range(pn_len):
        header[pn_offset + i] ^= mask[1 + i]
    return bytes(header[:pn_offset + pn_len]), pn_len


def decrypt_payload(key, iv, packet_number, payload_ciphertext, aad):
    if not CRYPTO_AVAILABLE:
        return None
    nonce = bytearray(iv)
    pn_bytes = packet_number.to_bytes(len(iv), "big")
    for i in range(len(iv)):
        nonce[i] ^= pn_bytes[i]
    try:
        return AESGCM(key).decrypt(bytes(nonce), payload_ciphertext, aad)
    except Exception:
        return None


def extract_tls_clienthello(frames):
    """Reassemble TLS ClientHello bytes from QUIC CRYPTO frames."""
    crypto_data = {}
    offset = 0
    while offset < len(frames):
        frame_type, offset = parse_varint(frames, offset)
        if frame_type == 0x06:
            crypto_offset, offset = parse_varint(frames, offset)
            crypto_len, offset = parse_varint(frames, offset)
            if offset + crypto_len > len(frames):
                break
            crypto_data[crypto_offset] = frames[offset:offset + crypto_len]
            offset += crypto_len
        elif frame_type == 0x00:
            while offset < len(frames) and frames[offset] == 0:
                offset += 1
        elif frame_type == 0x01:
            pass
        else:
            break
    if not crypto_data:
        return None
    assembled = b"".join(v for _, v in sorted(crypto_data.items()))
    if len(assembled) < 4:
        return None
    if assembled[0] == 0x01:
        return assembled
    return None


# ---------------------------------------------------------------------------
# Initial packets across a datagram, frames, and per-connection reassembly
# ---------------------------------------------------------------------------

def parse_long_header(raw, off=0):
    """Parse one long-header packet at ``off``. Returns a dict with version,
    ptype, dcid, scid, pn_offset and end (offset just past this packet), or
    None if this is not a long-header packet we can delimit."""
    if off + 7 > len(raw):
        return None
    first = raw[off]
    if not (first & 0x80):
        return None
    version = struct.unpack(">I", raw[off + 1:off + 5])[0]
    o = off + 5
    dl = raw[o]
    o += 1
    if dl > 20 or o + dl > len(raw):
        return None
    dcid = raw[o:o + dl]
    o += dl
    if o >= len(raw):
        return None
    sl = raw[o]
    o += 1
    if sl > 20 or o + sl > len(raw):
        return None
    scid = raw[o:o + sl]
    o += sl
    ptype = (first & 0x30) >> 4
    hdr = {"version": version, "ptype": ptype, "dcid": dcid, "scid": scid}
    if version not in SUPPORTED_VERSIONS:
        hdr["end"] = len(raw)
        return hdr
    if ptype == initial_packet_type(version):
        token_len, o2 = parse_varint(raw, o)
        if o2 == o:
            return None
        o = o2 + token_len
    elif ptype == retry_packet_type(version):  # Retry: no length field
        hdr["end"] = len(raw)
        return hdr
    length, o2 = parse_varint(raw, o)
    if o2 == o or o2 + length > len(raw):
        return None
    hdr["pn_offset"] = o2
    hdr["end"] = o2 + length
    return hdr


def initial_packets(raw):
    """Yield the long-header packets coalesced in one datagram."""
    off = 0
    while off < len(raw):
        hdr = parse_long_header(raw, off)
        if not hdr:
            return
        hdr["start"] = off
        yield hdr
        if hdr["end"] <= off:
            return
        off = hdr["end"]


def decrypt_initial(raw, hdr, keys):
    """Decrypt one Initial packet. Returns the frame plaintext or None."""
    key, iv, hp = keys
    pn_offset, end = hdr["pn_offset"], hdr["end"]
    payload = raw[pn_offset:end]
    if len(payload) < 20:
        return None
    header = bytearray(raw[hdr["start"]:pn_offset + 4])
    unprot, pn_len = remove_header_protection(header, payload, hp)
    if not unprot:
        return None
    pn = int.from_bytes(unprot[-pn_len:], "big")
    return decrypt_payload(key, iv, pn, bytes(payload[pn_len:]), bytes(unprot))


def crypto_frames(plaintext):
    """Return [(offset, data)] for every CRYPTO frame in an Initial's frames.

    Understands the frames allowed in Initial packets (RFC 9000 §12.4):
    PADDING, PING, ACK, ACK_ECN, CRYPTO, CONNECTION_CLOSE. Stops at anything
    else rather than mis-parsing.
    """
    out = []
    o, n = 0, len(plaintext)
    while o < n:
        ftype, o2 = parse_varint(plaintext, o)
        if o2 == o:
            break
        o = o2
        if ftype == 0x00:
            while o < n and plaintext[o] == 0:
                o += 1
        elif ftype == 0x01:
            continue
        elif ftype in (0x02, 0x03):
            _, o = parse_varint(plaintext, o)          # largest acknowledged
            _, o = parse_varint(plaintext, o)          # ack delay
            count, o = parse_varint(plaintext, o)      # range count
            _, o = parse_varint(plaintext, o)          # first range
            if count > 256:
                break
            for _ in range(2 * count):
                _, o = parse_varint(plaintext, o)
            if ftype == 0x03:
                for _ in range(3):
                    _, o = parse_varint(plaintext, o)
        elif ftype == 0x06:
            coff, o = parse_varint(plaintext, o)
            clen, o = parse_varint(plaintext, o)
            if o + clen > n:
                break
            out.append((coff, plaintext[o:o + clen]))
            o += clen
        elif ftype == 0x1C:
            _, o = parse_varint(plaintext, o)
            _, o = parse_varint(plaintext, o)
            rlen, o = parse_varint(plaintext, o)
            o += rlen
        else:
            break
    return out


class _CryptoStream:
    """Out-of-order CRYPTO frame reassembly for one direction."""

    MAX_BYTES = 65536

    def __init__(self):
        self.chunks = {}
        self.done = False
        self.consumed = 0   # stream offset of the next unread message
        self.hellos = 0

    def add(self, offset, data):
        if offset + len(data) > self.MAX_BYTES:
            return
        prev = self.chunks.get(offset)
        if prev is None or len(data) > len(prev):
            self.chunks[offset] = bytes(data)

    def contiguous(self):
        buf = bytearray()
        for off in sorted(self.chunks):
            data = self.chunks[off]
            if off > len(buf):
                break
            if off + len(data) > len(buf):
                buf += data[len(buf) - off:]
        return bytes(buf)

    def handshake_messages(self):
        """Complete handshake messages not yet returned, in stream order."""
        buf = self.contiguous()
        out = []
        while len(buf) - self.consumed >= 4:
            o = self.consumed
            need = 4 + int.from_bytes(buf[o + 1:o + 4], "big")
            if len(buf) - o < need:
                break
            out.append(buf[o:o + need])
            self.consumed += need
        return out


class QuicFlowTracker:
    """Reassemble the TLS ClientHello and ServerHello of QUIC connections.

    Chrome and other clients split a post-quantum ClientHello across several
    Initial packets and shuffle the CRYPTO frames, so nothing short of
    per-connection reassembly sees the SNI or key shares. Both directions'
    Initial keys derive from the client's ORIGINAL Destination Connection ID,
    which is why the client's first Initial must be seen to read the server's.
    """

    MAX_FLOWS = 4096

    def __init__(self):
        from collections import OrderedDict
        self.flows = OrderedDict()

    def _flow(self, key, create_with=None):
        flow = self.flows.get(key)
        if flow is None and create_with is not None:
            flow = create_with
            self.flows[key] = flow
            while len(self.flows) > self.MAX_FLOWS:
                self.flows.popitem(last=False)
        if flow is not None:
            self.flows.move_to_end(key)
        return flow

    def handle(self, raw, key, from_client):
        """Feed one datagram. ``key`` is (client_ip, client_port, server_ip,
        server_port). Returns a list of result dicts:
          {"kind": "client_hello" | "server_hello", "handshake": bytes, ...}
          {"kind": "initial", "error": str}   (first Initial we cannot read)
        """
        results = []
        for hdr in initial_packets(raw):
            version = hdr["version"]
            if version not in SUPPORTED_VERSIONS:
                continue
            if not from_client and hdr["ptype"] == retry_packet_type(version):
                # A Retry is the one thing that changes the Initial keys: the
                # client restarts with the Retry's SCID as its DCID.
                flow = self.flows.get(key)
                if flow is not None and not flow["c"].done:
                    flow.update(odcid=bytes(hdr["scid"]), c=_CryptoStream(),
                                s=_CryptoStream(), keys={})
                continue
            if "pn_offset" not in hdr:
                continue
            if hdr["ptype"] != initial_packet_type(version):
                continue
            if from_client:
                flow = self._flow(key, {"odcid": bytes(hdr["dcid"]), "version": version,
                                        "c": _CryptoStream(), "s": _CryptoStream(),
                                        "keys": {}, "reported_error": False})
            else:
                flow = self._flow(key)
                if flow is None:
                    continue  # missed the client's first Initial: no keys
            side = flow["c"] if from_client else flow["s"]
            if side.done:
                continue
            base = {"version": version, "dcid": bytes(hdr["dcid"]).hex(),
                    "odcid": flow["odcid"].hex()}
            if not CRYPTO_AVAILABLE:
                if from_client and not flow["reported_error"]:
                    flow["reported_error"] = True
                    results.append(dict(base, kind="initial",
                                        error="cryptography not installed"))
                continue
            # Keys come from the original DCID and THIS packet's version (a
            # compatible version upgrade, RFC 9368, can change it mid-handshake).
            kk = (from_client, version)
            if kk not in flow["keys"]:
                flow["keys"][kk] = derive_initial_keys(flow["odcid"], version,
                                                       server=not from_client)
            keys = flow["keys"][kk]
            plaintext = decrypt_initial(raw, hdr, keys)
            if plaintext is None:
                if from_client and not flow["reported_error"]:
                    flow["reported_error"] = True
                    results.append(dict(base, kind="initial", error="Initial packet did not decrypt (capture may have missed the connection's first Initial)"))
                continue
            for off, data in crypto_frames(plaintext):
                side.add(off, data)
            for msg in side.handshake_messages():
                kind = {0x01: "client_hello", 0x02: "server_hello"}.get(msg[0])
                if not kind:
                    side.done = True
                    break
                results.append(dict(base, kind=kind, handshake=msg))
                # Two hellos per side covers a HelloRetryRequest exchange.
                side.hellos += 1
                if side.hellos >= 2:
                    side.done = True
                    break
        # Finished flows are kept (LRU-bounded), not deleted: a client keeps
        # sending Initials under the server's new DCID, which only the
        # remembered original DCID can decrypt.
        return results

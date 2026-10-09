"""TCP/IP/QUIC reassembly, and the bugs it was built to fix."""

import random
import struct

import pytest
from scapy.all import IP, TCP, UDP, IPv6, Raw, IPv6ExtHdrFragment, DNS, DNSQR, DNSRR, fragment

from quantum_sniffer.lib.analyzer import ProtocolAnalyzer


def _ext(etype, body):
    return struct.pack(">HH", etype, len(body)) + body


def client_hello(sni="pq.example", groups=(0x11EC, 0x001D), key_share_len=1216,
                 ciphers=(0x1301, 0x1302), versions=(0x0304, 0x0303), alpn=None):
    exts = b""
    host = sni.encode()
    exts += _ext(0, struct.pack(">HBH", len(host) + 3, 0, len(host)) + host)
    exts += _ext(10, struct.pack(">H", 2 * len(groups)) + b"".join(struct.pack(">H", g) for g in groups))
    exts += _ext(43, bytes([2 * len(versions)]) + b"".join(struct.pack(">H", v) for v in versions))
    share = struct.pack(">HH", groups[0], key_share_len) + b"\x42" * key_share_len
    exts += _ext(51, struct.pack(">H", len(share)) + share)
    if alpn:
        a = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
        exts += _ext(16, struct.pack(">H", len(a)) + a)
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack(">H", 2 * len(ciphers))
            + b"".join(struct.pack(">H", c) for c in ciphers) + b"\x01\x00"
            + struct.pack(">H", len(exts)) + exts)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def server_hello(group=0x11EC, random_=b"\x22" * 32, cipher=0x1301):
    exts = _ext(43, b"\x03\x04") + _ext(51, struct.pack(">HH", group, 32) + b"\x33" * 32)
    body = (b"\x03\x03" + random_ + b"\x00" + struct.pack(">H", cipher) + b"\x00"
            + struct.pack(">H", len(exts)) + exts)
    return b"\x02" + len(body).to_bytes(3, "big") + body


def record(msg, ctype=22):
    return bytes([ctype, 3, 3]) + struct.pack(">H", len(msg)) + msg


C, S = "10.0.0.1", "10.0.0.2"


def seg(payload=b"", sport=40000, dport=443, seq=1001, flags="PA", src=C, dst=S, t=1000.0):
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, seq=seq, flags=flags)
    if payload:
        p = p / Raw(payload)
    p = IP(bytes(p))
    p.time = t
    return p


def run(packets, **kw):
    a = ProtocolAnalyzer(debug=True, **kw)
    out = []
    for p in packets:
        out.extend(r.to_dict() for r in a.process_all(p))
    return out, a


# --- TCP: TLS -------------------------------------------------------------------

def _split(data, sizes):
    out, o = [], 0
    for n in sizes:
        out.append((o, data[o:o + n]))
        o += n
    if o < len(data):
        out.append((o, data[o:]))
    return out


def test_split_clienthello_yields_sni_and_pq_groups():
    rec = record(client_hello())
    assert len(rec) > 1300  # needs more than one segment
    pkts = [seg(flags="S", seq=1000)] + [seg(d, seq=1001 + o) for o, d in _split(rec, [700, 500])]
    events, _ = run(pkts)
    assert len(events) == 1
    e = events[0]
    assert e["server_name"] == "pq.example"
    assert e["key_share_groups"] == ["X25519MLKEM768"]
    assert e["post_quantum_secure"] == "Hybrid"


def test_out_of_order_and_retransmitted_segments():
    rec = record(client_hello())
    parts = _split(rec, [400, 400, 400])
    pkts = [seg(flags="S", seq=1000)]
    order = [parts[2], parts[0], parts[0], parts[3], parts[1], parts[2]]  # dupes too
    pkts += [seg(d, seq=1001 + o) for o, d in order]
    events, _ = run(pkts)
    assert [e["server_name"] for e in events] == ["pq.example"]


def test_mid_stream_join_still_frames_a_hello():
    rec = record(client_hello())
    pkts = [seg(d, seq=5000 + o) for o, d in _split(rec, [900])]   # no SYN
    events, _ = run(pkts)
    assert events[0]["server_name"] == "pq.example"


def test_tcp_fast_open_data_in_syn():
    rec = record(client_hello(key_share_len=32))
    events, _ = run([seg(rec, flags="S", seq=777)])
    assert events and events[0]["server_name"] == "pq.example"


def test_tls_on_any_port_and_relabelled_ports():
    rec = record(client_hello(key_share_len=32))
    for port, proto in [(993, "TLS"), (853, "DNS over TLS (DoT)"), (5061, "SIPS (SIP over TLS)"),
                        (8443, "TLS")]:
        events, _ = run([seg(rec, dport=port)])
        assert events[0]["protocol"] == proto, port


def test_starttls_then_hello_mid_stream():
    pkts = [seg(flags="S", seq=1, dport=587),
            seg(b"EHLO x\r\n", seq=2, dport=587),
            seg(b"STARTTLS\r\n", seq=10, dport=587),
            seg(record(client_hello(key_share_len=32)), seq=20, dport=587)]
    events, _ = run(pkts)
    assert any(e.get("server_name") == "pq.example" for e in events)


def test_hello_retry_request_then_real_server_hello():
    hrr_random = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
    hrr = server_hello(group=0x0018, random_=hrr_random)
    server_stream = record(hrr) + record(b"\x01", ctype=20) + record(server_hello(group=0x0018)) \
        + record(b"\x00" * 40, ctype=23)
    pkts = [seg(flags="S", seq=100), seg(flags="SA", seq=900, sport=443, dport=40000, src=S, dst=C),
            seg(server_stream, seq=901, sport=443, dport=40000, src=S, dst=C)]
    events, _ = run(pkts)
    assert [e["type"] for e in events] == ["TLS HelloRetryRequest", "TLS ServerHello"]
    assert events[1]["tls_version"] == "TLS 1.3"
    assert events[1]["post_quantum_secure"] == "No"


def test_grease_named_in_groups():
    rec = record(client_hello(groups=(0x0A0A, 0x11EC, 0x001D), key_share_len=32))
    events, _ = run([seg(rec)])
    assert events[0]["supported_groups"][0] == "GREASE(0x0a0a)"
    assert events[0]["key_share_groups"] == ["GREASE(0x0a0a)"]


def test_clienthello_key_share_length_is_not_a_group():
    """Regression: the 2-byte client_shares length was reported as a group."""
    events, _ = run([seg(record(client_hello()))])
    assert all("0x04" not in g for g in events[0]["supported_groups"])


# --- TCP: SSH, HTTP, SMB, Kerberos, DNS ------------------------------------------

def _ssh_packet(msg_type, payload):
    body = bytes([msg_type]) + payload
    pad = 8 - (len(body) + 5) % 8 or 8
    return struct.pack(">IB", len(body) + 1 + pad, pad) + body + b"\x00" * pad


def _kexinit(kex):
    def nl(s):
        return struct.pack(">I", len(s)) + s.encode()
    return _ssh_packet(20, b"\x00" * 16 + nl(kex) + nl("ssh-ed25519") + nl("aes128-ctr") * 2
                       + nl("hmac-sha2-256") * 2 + nl("none") * 2 + nl("") * 2 + b"\x00" + b"\x00" * 4)


def test_ssh_banner_and_split_kexinit_from_one_stream():
    stream = b"SSH-2.0-OpenSSH_9.9\r\n" + _kexinit("mlkem768x25519-sha256,curve25519-sha256")
    pkts = [seg(flags="S", seq=1, dport=22)]
    pkts += [seg(d, seq=2 + o, dport=22) for o, d in _split(stream, [40])]
    events, _ = run(pkts)
    assert [e["type"] for e in events] == ["SSH Banner", "SSH KEX Init"]
    assert events[1]["post_quantum_secure"] == "Hybrid"


def test_http_headers_split_across_segments():
    req = b"GET /a HTTP/1.1\r\nHost: split.example\r\nUser-Agent: t\r\n\r\n"
    pkts = [seg(flags="S", seq=1, dport=80)] + [seg(d, seq=2 + o, dport=80) for o, d in _split(req, [20])]
    events, _ = run(pkts, l7=True)
    assert events[0]["http_host"] == "split.example"
    assert "http_headers_partial" not in events[0]


def test_http_keepalive_second_request_after_body():
    body = b"x" * 3000
    stream = (b"POST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 3000\r\n\r\n" + body
              + b"GET /second HTTP/1.1\r\nHost: b\r\n\r\n")
    pkts = [seg(flags="S", seq=1, dport=80)] + [seg(d, seq=2 + o, dport=80)
                                              for o, d in _split(stream, [1400, 1400])]
    events, _ = run(pkts, l7=True)
    assert [e["http_path"] for e in events] == ["/p", "/second"]


def _nbt(msg, mtype=0):
    return bytes([mtype]) + len(msg).to_bytes(3, "big") + msg


def _smb2_negotiate_response(dialect):
    hdr = b"\xfeSMB" + struct.pack("<HHIHHI", 64, 0, 0, 0, 1, 1) + b"\x00" * 44
    return _nbt(hdr + struct.pack("<HHH", 65, 0, dialect) + b"\x00" * 58)


def test_smb_on_139_after_nbt_session_request():
    """The NBT SESSION REQUEST that opens tcp/139 must not end inspection."""
    sess_req = _nbt(b"\x20" + b"CA" * 16 + b"\x00" + b"\x20" + b"CA" * 16 + b"\x00", mtype=0x81)
    pkts = [seg(flags="S", seq=1, dport=139),
            seg(flags="SA", seq=50, sport=139, dport=40000, src=S, dst=C),
            seg(sess_req, seq=2, dport=139),
            seg(_nbt(b"", mtype=0x82), seq=51, sport=139, dport=40000, src=S, dst=C),
            seg(_smb2_negotiate_response(0x0210), seq=55, sport=139, dport=40000, src=S, dst=C)]
    events, _ = run(pkts)
    assert events[0]["smb_version"] == "2.1"
    assert events[0]["smb_transport"] == "netbios"


def test_kerberos_tcp_length_prefix_not_double_stripped():
    as_req = b"\x6a\x81\x10" + b"\x30" * 0x10
    pkt = seg(struct.pack(">I", len(as_req)) + as_req, dport=88)
    events, _ = run([pkt], encrypted_only=False)
    assert events and events[0]["protocol"] == "Kerberos"


def test_dns_tcp_split_message_judged_once_aligned():
    msg = bytes(DNS(rd=1, qd=DNSQR(qname="split.example")))
    framed = struct.pack(">H", len(msg)) + msg
    pkts = [seg(flags="S", seq=1, dport=53)] + [seg(d, seq=2 + o, dport=53)
                                               for o, d in _split(framed, [5])]
    events, _ = run(pkts, l7=True)
    assert len(events) == 1 and events[0]["dns_query"] == "split.example"


# --- IP fragmentation ------------------------------------------------------------

def _big_dns_response():
    an = [DNSRR(rrname="big.example", type="TXT", rdata="x" * 200) for _ in range(12)]
    return DNS(id=1, qr=1, qd=DNSQR(qname="big.example", qtype="TXT"), an=an)


def test_ipv4_fragmented_dns_is_reassembled_not_called_non_dns():
    """The first fragment alone looks like truncated, non-DNS bytes."""
    whole = IP(src=S, dst=C, id=77) / UDP(sport=53, dport=5353) / _big_dns_response()
    frags = fragment(IP(bytes(whole)), fragsize=600)
    assert len(frags) > 2
    random.Random(1).shuffle(frags)
    events, _ = run([IP(bytes(f)) for f in frags], l7=True)
    assert len(events) == 1
    assert events[0]["dns_conforming"] is True
    assert len(events[0]["dns_records"]) == 12


def test_ipv6_fragmented_dns_is_reassembled():
    payload = bytes(UDP(sport=53, dport=5353) / _big_dns_response())
    # build UDP checksum-free fragments by hand
    chunks = [payload[i:i + 600] for i in range(0, len(payload), 600)]
    pkts, off = [], 0
    for i, ch in enumerate(chunks):
        p = IPv6(src="2001:db8::2", dst="2001:db8::1") / IPv6ExtHdrFragment(
            nh=17, id=9, offset=off // 8, m=int(i < len(chunks) - 1)) / Raw(ch)
        pkts.append(IPv6(bytes(p)))
        off += len(ch)
    events, _ = run(pkts, l7=True)
    assert len(events) == 1 and events[0]["dns_conforming"] is True


# --- timestamps, WireGuard, RADIUS/IKE ---------------------------------------------

def test_event_timestamp_is_capture_time():
    events, _ = run([seg(record(client_hello(key_share_len=32)), t=1700000000.5)])
    assert events[0]["timestamp"].startswith("2023-11-1")


def test_dhcp_and_radius_are_not_wireguard():
    dhcp = IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) / Raw(
        b"\x01\x01\x06\x00" + b"\x00" * 296)
    radius = IP() / UDP(sport=40000, dport=51820) / Raw(b"\x01\x07\x00\xc8" + b"\x00" * 196)
    for p in (dhcp, radius):
        events, _ = run([IP(bytes(p))], encrypted_only=False)
        assert all(e["protocol"] != "WireGuard" for e in events)


def test_real_wireguard_initiation():
    wg = IP() / UDP(sport=40000, dport=51820) / Raw(b"\x01\x00\x00\x00" + b"\x55" * 144)
    events, _ = run([IP(bytes(wg))])
    assert events[0]["protocol"] == "WireGuard"
    assert "pq_wireguard_suspected" not in events[0]


def test_radius_is_detected_despite_scapy_dissection():
    """scapy.all decodes udp/1812 as its own Radius layer: no Raw."""
    radius = IP() / UDP(sport=40000, dport=1812) / Raw(
        b"\x01\x07\x00\x14" + b"\x00" * 16)
    events, _ = run([IP(bytes(radius))], encrypted_only=False)
    assert events and events[0]["protocol"] == "RADIUS"


# --- QUIC ------------------------------------------------------------------------

crypto = pytest.importorskip("cryptography")


def _quic_initial(dcid, scid, frames, version=1, server=False, pn=0, odcid=None):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from quantum_sniffer.parsers import quic as q
    key, iv, hp = q.derive_initial_keys(odcid or dcid, version, server=server)
    payload = frames + b"\x00" * max(0, 1100 - len(frames)) if not server else frames + b"\x00" * 30
    ptype = q.initial_packet_type(version)
    first = 0xC0 | (ptype << 4) | 0x01   # 2-byte packet number
    length = 2 + len(payload) + 16
    hdr = (bytes([first]) + struct.pack(">I", version) + bytes([len(dcid)]) + dcid
           + bytes([len(scid)]) + scid + b"\x00" + struct.pack(">H", 0x4000 | length))
    pn_off = len(hdr)
    hdr += pn.to_bytes(2, "big")
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    pkt = bytearray(hdr + AESGCM(key).encrypt(nonce, payload, hdr))
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(bytes(pkt[pn_off + 4:pn_off + 20]))
    pkt[0] ^= mask[0] & 0x0F
    pkt[pn_off] ^= mask[1]
    pkt[pn_off + 1] ^= mask[2]
    return bytes(pkt)


def _crypto_frame(off, data):
    def vi(n):
        return struct.pack(">I", 0x80000000 | n)
    return b"\x06" + vi(off) + vi(len(data)) + data


def _udp(raw, from_client=True):
    if from_client:
        p = IP(src=C, dst=S) / UDP(sport=50000, dport=443) / Raw(raw)
    else:
        p = IP(src=S, dst=C) / UDP(sport=443, dport=50000) / Raw(raw)
    return IP(bytes(p))


@pytest.mark.parametrize("version", [1, 0x6B3343CF])
def test_quic_clienthello_split_and_shuffled_across_packets(version):
    ch = client_hello(alpn=["h3"])
    dcid, scid = b"\xaa" * 8, b"\xbb" * 8
    pieces = [(o, ch[o:o + 300]) for o in range(0, len(ch), 300)]
    random.Random(3).shuffle(pieces)
    half = len(pieces) // 2
    p1 = _quic_initial(dcid, scid, b"".join(_crypto_frame(o, d) for o, d in pieces[:half]), version, pn=0)
    p2 = _quic_initial(dcid, scid, b"".join(_crypto_frame(o, d) for o, d in pieces[half:]), version, pn=1)
    sh = _quic_initial(scid, b"\xcc" * 8, b"\x02\x00\x00\x00\x00" + _crypto_frame(0, server_hello()),
                       version, server=True, odcid=dcid)
    # After the server's Initial the client switches DCID; keys must not change.
    p3 = _quic_initial(b"\xcc" * 8, scid, b"\x01", version, pn=2, odcid=dcid)
    events, _ = run([_udp(p1), _udp(p2), _udp(sh, False), _udp(p3)])
    assert [e["type"] for e in events] == ["QUIC ClientHello", "QUIC ServerHello"]
    assert events[0]["server_name"] == "pq.example"
    assert events[0]["alpn_protocols"] == ["h3"]
    assert events[1]["supported_groups"] == ["X25519MLKEM768"]
    assert events[1]["post_quantum_secure"] == "Hybrid"


def test_quic_retry_changes_keys():
    ch = client_hello(key_share_len=32)
    dcid, scid, retry_scid = b"\x01" * 8, b"\x02" * 8, b"\x03" * 8
    first = _quic_initial(dcid, scid, b"\x01", pn=0)            # PING only
    retry = (bytes([0xF0]) + struct.pack(">I", 1) + bytes([8]) + scid + bytes([8]) + retry_scid
             + b"token" + b"\x00" * 16)
    second = _quic_initial(retry_scid, scid, _crypto_frame(0, ch), pn=1)
    events, _ = run([_udp(first), _udp(retry, False), _udp(second)])
    assert [e.get("server_name") for e in events] == ["pq.example"]


def test_payload_is_wire_bytes_even_with_scapy_tls_loaded():
    """scapy's TLS layer re-serialises records differently (and labels a
    partial record Padding); analyzers must see the captured bytes."""
    import scapy.layers.tls.all  # noqa: F401  binds TLS to tcp/443 globally
    from quantum_sniffer.wire import payload_after
    hrr_random = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
    stream = record(server_hello(random_=hrr_random)) + record(b"\x01", ctype=20)
    p = seg(stream, sport=443, dport=40000, src=S, dst=C)
    assert payload_after(p, TCP) == stream
    partial = record(client_hello())[:900]
    assert payload_after(seg(partial), TCP) == partial

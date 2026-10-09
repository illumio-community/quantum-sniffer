"""Layer-7 detections."""

import csv
import struct

import pytest
# scapy.all, as the CLI uses: it binds scapy's own SMB/NetBIOS/HTTP dissectors
# to their ports, which the analyzers must cope with.
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Raw
from scapy.layers.tls.all import TLS, TLSClientHello

from quantum_sniffer.cli.output import DualWriter
from quantum_sniffer.lib.analyzer import ProtocolAnalyzer
from quantum_sniffer.parsers import l7


def _run(pkt, l7_on=True, encrypted_only=True):
    pkt = IP(bytes(pkt))  # dissect from wire bytes, as a capture would
    r = ProtocolAnalyzer(encrypted_only=encrypted_only, debug=True, l7=l7_on).process(pkt)
    return r.to_dict() if r else None


# --- weak TLS -------------------------------------------------------------------

def test_weak_tls_rc4_and_tls10():
    out = l7.classify_weak_tls([0x0005, 0xC02F], 0x0301, [])
    assert out["tls_deprecated_version"] is True
    assert out["tls_weak_cipher"] is True
    assert out["tls_weak_offered"] == ["TLS 1.0", "TLS_RSA_WITH_RC4_128_SHA"]


def test_weak_tls_supported_versions_beats_legacy_and_grease_ignored():
    # legacy 0x0303 is always sent by TLS 1.3 clients; supported_versions rules.
    assert l7.classify_weak_tls([0x1301, 0x0A0A], 0x0303, [0x2A2A, 0x0304, 0x0303]) == {}
    # GREASE in a list that otherwise tops out at TLS 1.1 is still deprecated.
    out = l7.classify_weak_tls([0x1301], 0x0303, [0xFAFA, 0x0302])
    assert out["tls_deprecated_version"] is True


def test_clienthello_event_carries_weak_tls_and_absent_when_clean():
    weak = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=40000, dport=443) / TLS(
        msg=[TLSClientHello(version=0x0301, ciphers=[0x0004, 0x002F])])
    info = _run(weak, l7_on=False)
    assert info["tls_weak_offered"] == ["TLS 1.0", "TLS_RSA_WITH_RC4_128_MD5"]
    clean = IP() / TCP(sport=40000, dport=443) / TLS(
        msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F])])
    info = _run(clean, l7_on=False)
    # NULL is not false: no key at all, rather than False.
    assert "tls_weak_cipher" not in info and "tls_deprecated_version" not in info


def test_weak_negotiated():
    assert l7.classify_weak_negotiated(0x000A, 0x0303) == {
        "tls_weak_cipher_negotiated": "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}
    assert l7.classify_weak_negotiated(0xC02F, 0x0302) == {"tls_deprecated_version_negotiated": True}


# --- SSH -----------------------------------------------------------------------

@pytest.mark.parametrize("banner,ver", [
    ("SSH-2.0-OpenSSH_9.6", "2"), ("SSH-1.99-Cisco-1.25", "1.99"),
    ("SSH-1.5-old", "1"), ("HTTP/1.1 200", None),
])
def test_ssh_version(banner, ver):
    assert l7.ssh_version_from_banner(banner) == ver


def test_ssh_banner_event_on_2222():
    pkt = IP() / TCP(sport=2222, dport=50000) / Raw(b"SSH-1.99-Cisco-1.25\r\n")
    info = _run(pkt, l7_on=False)
    assert info["ssh_version"] == "1.99"


# --- HTTP ----------------------------------------------------------------------

def test_http_request():
    req = (b"GET /index.html?q=1 HTTP/1.1\r\nHost: example.com\r\n"
           b"User-Agent: curl/8.0\r\nAccept: */*\r\n\r\n")
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=41000, dport=80) / Raw(req)
    info = _run(pkt)
    assert info["protocol"] == "HTTP"
    assert info["http_method"] == "GET"
    assert info["http_path"] == "/index.html?q=1"
    assert info["http_host"] == "example.com"
    assert info["http_user_agent"] == "curl/8.0"
    assert info["post_quantum_secure"] == "N/A"
    assert info["layer7"] is True


def test_http_absent_when_l7_off_and_non_http_declined():
    pkt = IP() / TCP(sport=41000, dport=80) / Raw(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
    assert _run(pkt, l7_on=False, encrypted_only=False) is None
    assert l7.parse_http_request(b"\x16\x03\x01\x00\x10") is None
    assert l7.parse_http_request(b"GET nothing") is None


def test_http_partial_headers():
    out = l7.parse_http_request(b"POST /api HTTP/1.1\r\nHost: a.b\r\nContent-Le")
    assert out["http_host"] == "a.b" and out["http_headers_partial"] is True


# --- DNS -----------------------------------------------------------------------

def test_dns_query_conforming():
    pkt = IP() / UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname="Example.COM", qtype="AAAA"))
    info = _run(pkt)
    assert info["dns_conforming"] is True
    assert info["dns_query"] == "example.com"
    assert info["dns_qtype"] == "AAAA"
    assert info["type"] == "DNS Query"


def test_dns_response_cname_chain_flattened():
    pkt = IP() / UDP(sport=53, dport=5353) / DNS(
        id=7, qr=1, qd=DNSQR(qname="www.example.com"),
        an=[DNSRR(rrname="www.example.com", type="CNAME", ttl=300, rdata="cdn.example.net"),
            DNSRR(rrname="cdn.example.net", type="A", ttl=60, rdata="192.0.2.7")])
    info = _run(pkt)
    assert info["dns_conforming"] is True
    assert info["dns_rcode"] == "NOERROR"
    assert "192.0.2.7" in info["dns_answers"]
    res = {(r["name"], r["ip"]): r for r in info["dns_resolutions"]}
    assert res[("www.example.com", "192.0.2.7")]["ttl"] == 60
    assert res[("www.example.com", "192.0.2.7")]["via"] == "cdn.example.net"


@pytest.mark.parametrize("payload,reason", [
    (b"SSH-2.0-OpenSSH_9.6\r\n", "opcode-unassigned"),
    (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", "opcode-unassigned"),
    (b"\x00\x01", "short-header"),
])
def test_non_dns_on_port_53(payload, reason):
    pkt = IP() / UDP(sport=40000, dport=53) / Raw(payload)
    info = _run(pkt)
    assert info["dns_conforming"] is False
    assert info["dns_nonconformance"] == reason
    assert info["type"] == "Non-DNS traffic on port 53"


def test_dns_trailing_bytes_rejected_and_truncated_forgiven():
    msg = bytes(DNS(rd=1, qd=DNSQR(qname="a.example")))
    assert l7.dns_inspect_message(msg)["dns_conforming"] is True
    bad = l7.dns_inspect_message(msg + b"\x00\x00")
    assert bad == {"dns_conforming": False, "dns_is_response": False, "dns_opcode": "QUERY",
                   "dns_query": "a.example", "dns_qtype": "A",
                   "dns_nonconformance": "trailing-bytes"}
    # TC=1 response cut off mid-answer: as much as fitted, still DNS.
    resp = bytes(DNS(qr=1, tc=1, qd=DNSQR(qname="a.example"),
                     an=DNSRR(rrname="a.example", rdata="192.0.2.1")))
    assert l7.dns_inspect_message(resp[:-3])["dns_conforming"] is True


def test_dns_pointer_loop_rejected():
    hdr = struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0)
    # Name is a pointer to itself (offset 12): must not hang.
    assert l7.dns_inspect_message(hdr + b"\xc0\x0c\x00\x01\x00\x01")["dns_nonconformance"] == "bad-pointer"


def _tcp(sport, dport, flags, seq, payload=b""):
    pkt = IP(src="10.0.0.1" if dport == 53 else "10.0.0.53",
             dst="10.0.0.53" if dport == 53 else "10.0.0.1") / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq)
    return pkt / Raw(payload) if payload else pkt


def test_dns_tcp_judged_only_from_aligned_first_segment():
    a = ProtocolAnalyzer(debug=True, l7=True)
    assert a.process(_tcp(41000, 53, "S", 1000)) is None
    assert a.process(_tcp(53, 41000, "SA", 5000)) is None
    r = a.process(_tcp(41000, 53, "PA", 1001, b"SSH-2.0-OpenSSH_9.6\r\n"))
    assert r.to_dict()["dns_conforming"] is False
    assert r.to_dict()["dns_nonconformance"] == "length-implausible"
    # Second segment of the same direction is not judged.
    assert a.process(_tcp(41000, 53, "PA", 1023, b"more bytes")) is None


def test_dns_tcp_conforming_query():
    a = ProtocolAnalyzer(debug=True, l7=True)
    a.process(_tcp(41001, 53, "S", 1))
    msg = bytes(DNS(rd=1, qd=DNSQR(qname="example.org")))
    r = a.process(_tcp(41001, 53, "PA", 2, struct.pack(">H", len(msg)) + msg)).to_dict()
    assert r["dns_conforming"] is True and r["dns_query"] == "example.org"


def test_dns_tcp_midstream_says_nothing():
    a = ProtocolAnalyzer(debug=True, l7=True)
    assert a.process(_tcp(41002, 53, "PA", 777, b"garbage that is not dns at all")) is None


# --- SMB -----------------------------------------------------------------------

def _nbt(msg):
    return struct.pack(">I", len(msg)) + msg


def _smb2_negotiate_response(dialect):
    hdr = b"\xfeSMB" + struct.pack("<HHIHHI", 64, 0, 0, 0x0000, 1, 0x00000001) + b"\x00" * 44
    body = struct.pack("<HHH", 65, 0, dialect) + b"\x00" * 58
    return _nbt(hdr + body)


@pytest.mark.parametrize("rev,name", [(0x0202, "2.0.2"), (0x0210, "2.1"), (0x0300, "3.0"),
                                      (0x0302, "3.0.2"), (0x0311, "3.1.1")])
def test_smb2_dialect_from_server_negotiate_response(rev, name):
    assert l7.smb_inspect_segment(_smb2_negotiate_response(rev), True) == {"smb_version": name}


def test_smb2_wildcard_and_client_request_are_not_verdicts():
    assert l7.smb_inspect_segment(_smb2_negotiate_response(0x02FF), True) is None
    assert l7.smb_inspect_segment(_smb2_negotiate_response(0x0311), False) is None


def test_smb1_and_encrypted():
    smb1_session_setup = _nbt(b"\xffSMB\x73" + b"\x00" * 27)
    assert l7.smb_inspect_segment(smb1_session_setup, True) == {"smb_version": "1"}
    smb1_negotiate = _nbt(b"\xffSMB\x72" + b"\x00" * 27)
    assert l7.smb_inspect_segment(smb1_negotiate, True) == {"smb1_negotiate_response": True}
    transform = _nbt(b"\xfdSMB" + b"\x00" * 48)
    assert l7.smb_inspect_segment(transform, False) == {"smb_encrypted": True}


def test_smb_event_runs_without_l7_and_dedupes():
    pkt = IP(src="10.0.0.9", dst="10.0.0.1") / TCP(sport=445, dport=50000) / Raw(
        _smb2_negotiate_response(0x0311))
    pkt = IP(bytes(pkt))
    a = ProtocolAnalyzer(debug=True, l7=False)
    info = a.process(pkt).to_dict()
    assert info["smb_version"] == "3.1.1"
    assert info["smb_transport"] == "direct"
    assert info["connection"] == "10.0.0.1:50000 -> 10.0.0.9:445"
    assert a.process(pkt) is None  # same finding, same connection: once
    pkt139 = IP() / TCP(sport=139, dport=50001) / Raw(_nbt(b"\xffSMB\x73" + b"\x00" * 27))
    info = a.process(IP(bytes(pkt139))).to_dict()
    assert info["smb_transport"] == "netbios" and info["smb_version"] == "1"
    assert a.summary()["findings"]["SMB1 in use"] == 1


# --- NetBIOS -------------------------------------------------------------------

def _nb_encode(name, suffix=0x20):
    raw = name.upper().ljust(15).encode() + bytes([suffix])
    return b"\x20" + bytes(c for b in raw for c in (0x41 + (b >> 4), 0x41 + (b & 0xF))) + b"\x00"


def test_nbns_query():
    msg = struct.pack(">HHHHHH", 0x1234, 0x0110, 1, 0, 0, 0) + _nb_encode("FILESRV") + b"\x00\x20\x00\x01"
    info = _run(IP() / UDP(sport=137, dport=137) / Raw(msg))
    assert info["netbios_name"] == "FILESRV"
    assert info["netbios_suffix"] == "0x20"
    assert info["smb_transport"] == "netbios"
    assert "smb_version" not in info  # a name lookup says nothing about the dialect


def test_nbds_mailslot_proves_smb1():
    hdr = bytes([0x11, 0x02]) + struct.pack(">H", 1) + bytes([10, 0, 0, 5]) + struct.pack(">HHH", 138, 0, 0)
    msg = hdr + _nb_encode("WORKSTATION", 0x00) + _nb_encode("WORKGROUP", 0x1D) + b"\xffSMB\x25" + b"\x00" * 20
    info = _run(IP() / UDP(sport=138, dport=138) / Raw(msg))
    assert info["smb_version"] == "1"
    assert info["netbios_source_name"] == "WORKSTATION"
    assert info["netbios_name"] == "WORKGROUP"


def test_netbios_rejects_garbage():
    assert l7.parse_nbns(b"\x00" * 50) is None
    assert l7.parse_nbds(b"\x99" + b"\x00" * 40) is None


# --- SMB over QUIC, output, Skynet -----------------------------------------------

def test_smb_over_quic_alpn():
    from quantum_sniffer.analyzers import _add_smb_over_quic
    info = {"alpn_protocols": ["smb"]}
    _add_smb_over_quic(info)
    assert info["smb_transport"] == "quic"


def test_csv_append_keeps_existing_header(tmp_path):
    base = tmp_path / "cap"
    (tmp_path / "cap.csv").write_text("timestamp,protocol\n")
    w = DualWriter(str(base))
    w.write({"timestamp": "t", "protocol": "HTTP", "http_host": "x"})
    w.close()
    rows = list(csv.reader(open(tmp_path / "cap.csv")))
    assert rows == [["timestamp", "protocol"], ["t", "HTTP"]]


def test_skynet_ignores_cleartext_l7_events():
    from quantum_sniffer.cli.skynet import render_report
    report = render_report([
        {"protocol": "TLS", "post_quantum_secure": "No", "server_name": "a"},
        {"protocol": "HTTP", "post_quantum_secure": "N/A"},
    ])
    assert "Sessions intercepted:    1" in report


# --- QUIC header protection (regression: only 4-byte packet numbers worked) ----

@pytest.mark.parametrize("pn_len", [1, 2, 4])
def test_quic_initial_decrypts_with_any_pn_length(pn_len):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from quantum_sniffer.parsers import quic as q

    dcid = bytes(range(8))
    key, iv, hp = q.derive_initial_keys(dcid, 1)
    pn = 2
    plaintext = b"\x06\x00\x04\x01\x00\x00\x00" + b"\x00" * 60  # CRYPTO + PADDING
    first = 0xC0 | (pn_len - 1)
    length = pn_len + len(plaintext) + 16
    header = (bytes([first]) + b"\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid
              + b"\x00" + b"\x00" + struct.pack(">H", 0x4000 | length))
    pn_offset = len(header)
    header += pn.to_bytes(pn_len, "big")
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    ct = AESGCM(key).encrypt(nonce, plaintext, header)
    packet = bytearray(header + ct)
    sample = packet[pn_offset + 4:pn_offset + 20]
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(bytes(sample))
    packet[0] ^= mask[0] & 0x0F
    for i in range(pn_len):
        packet[pn_offset + i] ^= mask[1 + i]

    unprot, got_len = q.remove_header_protection(
        bytearray(packet[:pn_offset + 4]), bytes(packet[pn_offset:]), hp)
    assert got_len == pn_len
    got_pn = int.from_bytes(unprot[-pn_len:], "big")
    assert got_pn == pn
    assert q.decrypt_payload(key, iv, got_pn, bytes(packet[pn_offset + pn_len:]), unprot) == plaintext

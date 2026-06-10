"""SSH KEXINIT parser test."""

import struct

from quantum_sniffer.parsers.ssh import parse_kexinit


def _name_list(*names):
    raw = ",".join(names).encode()
    return struct.pack(">I", len(raw)) + raw


def _build_kexinit(kex_algs):
    cookie = b"\x00" * 16
    body = b"\x14" + cookie  # msg_type=20 + cookie
    body += _name_list(*kex_algs)
    body += _name_list("ssh-ed25519")
    body += _name_list("aes256-gcm@openssh.com")
    body += _name_list("aes256-gcm@openssh.com")
    body += _name_list("hmac-sha2-256")
    body += _name_list("hmac-sha2-256")
    body += _name_list("none")
    body += _name_list("none")
    body += _name_list()
    body += _name_list()
    body += b"\x00" + b"\x00" * 4  # first_kex_packet_follows + reserved
    payload_len = len(body)
    pkt = struct.pack(">I", payload_len) + b"\x00" + body
    return pkt


def test_parses_pq_kex_algorithm():
    pkt = _build_kexinit(["sntrup761x25519-sha512@openssh.com", "curve25519-sha256"])
    parsed = parse_kexinit(pkt)
    assert parsed is not None
    assert "sntrup761x25519-sha512@openssh.com" in parsed["ssh_kex_algorithms"]


def test_returns_none_for_non_kexinit():
    assert parse_kexinit(b"SSH-2.0-OpenSSH_9.0\r\n") is None
    assert parse_kexinit(b"") is None

"""TLS raw parser bounds-check tests — the BUGS_FOUND.md issues should not crash."""

import struct

from quantum_sniffer.parsers import tls_raw


def _build_clienthello(extensions=b""):
    """Minimal valid TLS ClientHello record. Returns bytes starting at record header."""
    body = b"\x03\x03"  # legacy_version
    body += b"\x00" * 32  # random
    body += b"\x00"  # session_id length 0
    body += struct.pack(">H", 4) + b"\x13\x01\x13\x02"  # 2 cipher suites
    body += b"\x01\x00"  # compression methods length=1, null
    body += struct.pack(">H", len(extensions)) + extensions
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
    return record


def test_well_formed_clienthello_parses():
    record = _build_clienthello()
    parsed = tls_raw.parse_hello_record(record)
    assert parsed is not None
    assert parsed["hs_type"] == "ClientHello"
    assert parsed["cipher_count"] == 2


def test_truncated_session_id_does_not_crash():
    """sid_len=255 with no following bytes — must not blow past buffer."""
    body = b"\x03\x03" + b"\x00" * 32 + b"\xff"  # claims sid_len=255 but truncated
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
    parsed = tls_raw.parse_hello_record(record)
    assert parsed is not None
    assert parsed["hs_type"] == "ClientHello"


def test_truncated_cipher_list_does_not_crash():
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", 0xffff) + b"\x13\x01"
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
    parsed = tls_raw.parse_hello_record(record)
    assert parsed is not None  # parser bails gracefully without raising


def test_oversized_compression_length_handled():
    body = b"\x03\x03" + b"\x00" * 32
    body += b"\x00"
    body += struct.pack(">H", 2) + b"\x13\x01"
    body += b"\xff"  # comp_len=255 with nothing following
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
    parsed = tls_raw.parse_hello_record(record)
    assert parsed is not None


def test_oversized_extension_length_handled():
    ext = struct.pack(">H", 0) + struct.pack(">H", 0xffff) + b"\x00"
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00"
    body += struct.pack(">H", 2) + b"\x13\x01"
    body += b"\x01\x00"
    body += struct.pack(">H", len(ext)) + ext
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    record = b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
    parsed = tls_raw.parse_hello_record(record)
    assert parsed is not None


def test_fragmentation_is_flagged():
    """Record claims more bytes than buffer carries -> fragmented=True."""
    record = b"\x16\x03\x03" + struct.pack(">H", 4096) + b"\x01\x00"
    parsed = tls_raw.parse_hello_record(record)
    assert parsed is None or parsed.get("fragmented") is True


def test_supported_groups_extension_extracts_ids():
    # ext type 10 (supported_groups), data: list_len(2) + group ids
    groups = struct.pack(">HHHH", 4, 29, 0x6399, 0x639a)  # list_len=4 then 3 groups (oops: list_len wrong)
    # Build correctly: list_len (2 bytes) followed by N two-byte group IDs
    group_ids = [29, 0x6399, 0x639a]
    list_body = b"".join(struct.pack(">H", g) for g in group_ids)
    groups = struct.pack(">H", len(list_body)) + list_body
    ext = struct.pack(">HH", 10, len(groups)) + groups
    record = _build_clienthello(extensions=ext)
    parsed = tls_raw.parse_hello_record(record)
    assert parsed["supported_group_ids"] == group_ids


def test_alpn_extension_parses():
    # ext type 16 (ALPN): list_len(2) + entries: 1 length-prefixed
    entries = b"\x02h2"
    list_blob = struct.pack(">H", len(entries)) + entries
    ext = struct.pack(">HH", 16, len(list_blob)) + list_blob
    record = _build_clienthello(extensions=ext)
    parsed = tls_raw.parse_hello_record(record)
    assert parsed["alpn_protocols"] == ["h2"]


def test_ech_extension_flagged():
    # ext type 65037 with empty payload — just record presence
    ext = struct.pack(">HH", 65037, 0)
    record = _build_clienthello(extensions=ext)
    parsed = tls_raw.parse_hello_record(record)
    assert parsed.get("ech") is True


def test_session_ticket_extension_flagged():
    ext = struct.pack(">HH", 35, 0)
    record = _build_clienthello(extensions=ext)
    parsed = tls_raw.parse_hello_record(record)
    assert parsed.get("session_resumption") == "session_ticket"

"""IKEv2 SA proposal parser test — exercises PQ DH IDs."""

import struct

from quantum_sniffer.parsers.ikev2 import parse_sa


def _transform(t_type, t_id, last):
    """Build one IKEv2 transform substructure."""
    last_byte = 0 if last else 3
    return struct.pack(">BBHBBH", last_byte, 0, 8, t_type, 0, t_id)


def _proposal(transforms, last):
    last_byte = 0 if last else 2
    body = b""
    for i, t in enumerate(transforms):
        body += t
    prop_num = 1
    proto_id = 1
    spi_size = 0
    n = len(transforms)
    header = struct.pack(">BBHBBBB", last_byte, 0, 8 + len(body), prop_num, proto_id, spi_size, n)
    return header + body


def test_pq_dh_group_id_35_parses():
    transforms = [
        _transform(1, 20, last=False),  # ENCR AES-GCM-128
        _transform(2, 5, last=False),   # PRF SHA-256
        _transform(4, 35, last=True),   # D-H ML-KEM-512
    ]
    sa = _proposal(transforms, last=True)
    parsed = parse_sa(sa)
    assert parsed
    dh = [t for t in parsed[0]["transforms"] if t["type"] == "D-H"]
    assert dh and dh[0]["id"] == 35
    assert dh[0]["name"] == "ML-KEM-512"


def test_classical_dh_group_19_parses():
    transforms = [_transform(4, 19, last=True)]
    sa = _proposal(transforms, last=True)
    parsed = parse_sa(sa)
    dh = [t for t in parsed[0]["transforms"] if t["type"] == "D-H"]
    assert dh and dh[0]["name"] == "256-bit ECP (P-256)"

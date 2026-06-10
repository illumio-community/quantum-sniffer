"""PQ classification: drives off (group_id -> classification) tables, not strings."""

from quantum_sniffer import pq


def test_classical_x25519_classifies_no():
    info = {"protocol": "TLS", "supported_group_ids": [29], "selected_cipher": {"name": "x"}}
    assert pq.classify_connection(info) == "No"


def test_pq_kyber_alone_classifies_yes():
    info = {"protocol": "TLS", "supported_group_ids": [0x0201]}
    assert pq.classify_connection(info) == "Yes"


def test_hybrid_x25519kyber768_classifies_hybrid():
    info = {"protocol": "TLS", "supported_group_ids": [0x6399]}
    assert pq.classify_connection(info) == "Hybrid"


def test_x25519_plus_kyber_classifies_hybrid():
    """Client offers both classical and pure PQ -> hybrid posture."""
    info = {"protocol": "TLS", "supported_group_ids": [29, 0x0201]}
    assert pq.classify_connection(info) == "Hybrid"


def test_unknown_group_does_not_classify():
    info = {"protocol": "TLS", "supported_group_ids": [0xabcd]}
    assert pq.classify_connection(info) == "Unknown"


def test_ssh_kex_pq():
    info = {"protocol": "SSH", "ssh_kex_algorithms": ["sntrup761x25519-sha512@openssh.com"]}
    assert pq.classify_connection(info) == "Yes"


def test_ssh_kex_classical_only():
    info = {"protocol": "SSH", "ssh_kex_algorithms": ["curve25519-sha256", "ecdh-sha2-nistp256"]}
    assert pq.classify_connection(info) == "No"


def test_ike_pq_dh_group_classifies_yes():
    info = {
        "protocol": "IPsec/IKE",
        "ike_proposals": [{"transforms": [{"type": "D-H", "id": 35, "name": "ML-KEM-512"}]}],
    }
    assert pq.classify_connection(info) == "Yes"


def test_ike_classical_dh_group_classifies_no():
    info = {
        "protocol": "IPsec/IKE",
        "ike_proposals": [{"transforms": [{"type": "D-H", "id": 19, "name": "P-256"}]}],
    }
    assert pq.classify_connection(info) == "No"


def test_wireguard_oversized_classifies_hybrid():
    info = {"protocol": "WireGuard", "pq_wireguard_suspected": True}
    assert pq.classify_connection(info) == "Hybrid"


def test_wireguard_normal_classifies_no():
    info = {"protocol": "WireGuard"}
    assert pq.classify_connection(info) == "No"

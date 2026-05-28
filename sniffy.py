#!/usr/bin/env python3
"""
sniffy - Superposition Network Inspector For Funky Yields

Captures and analyzes encrypted protocol handshakes including TLS, SSH, IPsec,
DTLS, QUIC, WireGuard, RDP, Kerberos, RADIUS, and more. Identifies post-quantum
secure connections.

Usage: sudo ./sniffy.py [options] [interface]
       -a, --all          Include unencrypted protocols (default: encrypted only)
       -i, --interface    Network interface to monitor

Requires: scapy
Optional: cryptography  (enables QUIC Initial packet decryption)
"""

import sys
import json
import time
import hmac as _hmac
import hashlib
import struct
import argparse
from datetime import datetime
from collections import defaultdict
from pathlib import Path

try:
    from scapy.all import sniff, Raw
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello
    from scapy.layers.dns import DNS, DNSQR, DNSRR
except ImportError:
    print("ERROR: scapy not installed.  pip install scapy", file=sys.stderr)
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

# ---------------------------------------------------------------------------
# Post-quantum algorithm sets
# ---------------------------------------------------------------------------

PQ_SAFE_KEX = {
    "x25519kyber512", "x25519kyber768", "x448kyber768",
    "kyber512", "kyber768", "kyber1024",
    "mlkem512", "mlkem768", "mlkem1024",
    "x25519mlkem768",
    "ntru", "sike", "frodokem",
    "sntrup761x25519-sha512@openssh.com",
    "sntrup4591761x25519-sha512@tinyssh.org",
    "mlkem768x25519-sha256",
    "kyber-ike",
}

PQ_SAFE_SIG = {
    "dilithium2", "dilithium3", "dilithium5",
    "mldsa44", "mldsa65", "mldsa87",
    "falcon512", "falcon1024",
    "slhdsa-sha2-128f", "slhdsa-sha2-192f", "slhdsa-sha2-256f",
    "sphincssha256128f", "sphincssha256192f", "sphincssha256256f",
}

CLASSICAL_KEX = {
    "x25519", "x448", "secp256r1", "secp384r1", "secp521r1",
    "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192",
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
    "diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
    "curve25519-sha256", "curve25519-sha256@libssh.org",
}

# ---------------------------------------------------------------------------
# TLS constants
# ---------------------------------------------------------------------------

TLS_CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
}

TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0x0300: "SSL 3.0",
}

TLS_EXTENSIONS = {
    0: "server_name",
    1: "max_fragment_length",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "alpn",
    18: "signed_certificate_timestamp",
    23: "extended_master_secret",
    35: "session_ticket",
    43: "supported_versions",
    44: "cookie",
    45: "psk_key_exchange_modes",
    51: "key_share",
    57: "quic_transport_parameters",
}

TLS_NAMED_GROUPS = {
    23: "secp256r1", 24: "secp384r1", 25: "secp521r1",
    29: "x25519", 30: "x448",
    256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096",
    259: "ffdhe6144", 260: "ffdhe8192",
    # IANA-assigned PQ groups (draft-ietf-tls-hybrid-design)
    0x0200: "kyber512",   0x0201: "kyber768",   0x0202: "kyber1024",
    0x11eb: "x25519kyber512",
    0x6399: "x25519kyber768",   # Chrome/BoringSSL
    0x639a: "x25519mlkem768",   # Chrome/BoringSSL draft
}

# ---------------------------------------------------------------------------
# IKEv2 constants
# ---------------------------------------------------------------------------

IKE_ENCR = {
    1: "DES-IV64", 2: "DES", 3: "3DES", 5: "CAST", 7: "BLOWFISH",
    11: "NULL", 12: "AES-CBC-128", 13: "AES-CBC-192", 14: "AES-CBC-256",
    18: "AES-CTR", 20: "AES-GCM-128", 21: "AES-GCM-192", 22: "AES-GCM-256",
    23: "NULL_AUTH_AES-GMAC", 28: "CHACHA20-POLY1305",
}

IKE_PRF = {
    1: "PRF_HMAC_MD5", 2: "PRF_HMAC_SHA1", 3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC", 5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384", 7: "PRF_HMAC_SHA2_512",
}

IKE_INTEG = {
    1: "AUTH_HMAC_MD5_96", 2: "AUTH_HMAC_SHA1_96", 3: "AUTH_DES_MAC",
    4: "AUTH_KPDK_MD5", 5: "AUTH_AES_XCBC_96",
    12: "AUTH_HMAC_SHA2_256_128", 13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}

IKE_DH = {
    1: "768-bit MODP", 2: "1024-bit MODP", 5: "1536-bit MODP",
    14: "2048-bit MODP", 15: "3072-bit MODP", 16: "4096-bit MODP",
    17: "6144-bit MODP", 18: "8192-bit MODP",
    19: "256-bit ECP (P-256)", 20: "384-bit ECP (P-384)",
    21: "521-bit ECP (P-521)", 31: "Curve25519", 32: "Curve448",
}

IKE_EXCHANGE_TYPES = {
    34: "IKE_SA_INIT", 35: "IKE_AUTH",
    36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
}

# ---------------------------------------------------------------------------
# Protocol-specific constants
# ---------------------------------------------------------------------------

KERBEROS_ETYPES = {
    1:   "DES-CBC-CRC (broken)",
    3:   "DES-CBC-MD5 (broken)",
    17:  "AES128-CTS-HMAC-SHA1-96",
    18:  "AES256-CTS-HMAC-SHA1-96",
    19:  "AES128-CTS-HMAC-SHA256-128",
    20:  "AES256-CTS-HMAC-SHA384-192",
    23:  "RC4-HMAC (NTLM-style)",
    24:  "RC4-HMAC-EXP (weak)",
    -128: "AES128-CTS-HMAC-SHA256-128",
    -129: "AES256-CTS-HMAC-SHA384-192",
}

DNSSEC_ALGORITHMS = {
    1:  "RSA/MD5 (deprecated)",
    3:  "DSA/SHA-1 (deprecated)",
    5:  "RSA/SHA-1",
    6:  "DSA-NSEC3-SHA1",
    7:  "RSASHA1-NSEC3-SHA1",
    8:  "RSA/SHA-256",
    10: "RSA/SHA-512",
    12: "GOST R 34.10-2001",
    13: "ECDSA P-256/SHA-256",
    14: "ECDSA P-384/SHA-384",
    15: "Ed25519",
    16: "Ed448",
    # Future PQ assignments (not yet assigned as of 2025)
    # 17+: reserved for PQ algorithms (ML-DSA, SLH-DSA etc.)
}

RADIUS_CODES = {
    1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject",
    4: "Accounting-Request", 5: "Accounting-Response",
    11: "Access-Challenge", 12: "Status-Server", 13: "Status-Client",
}

EAP_METHODS = {
    1: "Identity", 2: "Notification", 3: "Nak",
    4: "MD5-Challenge", 13: "EAP-TLS", 17: "LEAP",
    18: "EAP-SIM", 21: "EAP-TTLS", 23: "EAP-AKA",
    25: "EAP-PEAP", 43: "EAP-FAST", 50: "EAP-AKA-Prime",
    55: "EAP-TEAP",
}

OPENVPN_OPCODES = {
    1: "P_CONTROL_HARD_RESET_CLIENT_V1",
    2: "P_CONTROL_HARD_RESET_SERVER_V1",
    3: "P_CONTROL_SOFT_RESET_V1",
    4: "P_CONTROL_V1",
    5: "P_ACK_V1",
    6: "P_DATA_V1",
    7: "P_CONTROL_HARD_RESET_CLIENT_V2",
    8: "P_CONTROL_HARD_RESET_SERVER_V2",
    9: "P_DATA_V2",
}

RDP_PROTOCOLS = {
    0x00000000: "Standard RDP (RC4 — no TLS)",
    0x00000001: "TLS",
    0x00000002: "CredSSP/NLA",
    0x00000004: "RDSTLS",
    0x00000008: "CredSSP with early user auth",
}

QUIC_INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
QUIC_INITIAL_SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")

ZRTP_MSG_TYPES = {
    "Hello   ": "Hello",     "HelloACK": "HelloACK",
    "Commit  ": "Commit",    "DHPart1 ": "DHPart1",
    "DHPart2 ": "DHPart2",   "Confirm1": "Confirm1",
    "Confirm2": "Confirm2",  "Conf2ACK": "Conf2ACK",
    "Error   ": "Error",     "GoClear ": "GoClear",
    "SASrelay": "SASrelay",  "Ping    ": "Ping",
    "PingACK ": "PingACK",
}

ZRTP_KEY_AGREEMENT = {
    "DH3K": "DH-3072 (classical)",  "DH2K": "DH-2048 (classical)",
    "EC25": "ECDH-P-256 (classical)", "EC38": "ECDH-P-384 (classical)",
    "EC52": "ECDH-P-521 (classical)", "Prsh": "preshared",
    "Mult": "multistream",
}

BGP_MSG_TYPES = {
    1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH",
}

OPC_UA_MSG_TYPES = {
    b"HEL": "Hello",         b"ACK": "Acknowledge",
    b"OPN": "OpenSecureChannel", b"CLO": "CloseSecureChannel",
    b"MSG": "Message",       b"ERR": "Error",
}

OPC_UA_SECURITY_MODES = {1: "None", 2: "Sign", 3: "SignAndEncrypt"}

# Non-standard ports for heuristic TLS detection
TLS_HEURISTIC_PORTS = {
    8443, 8444, 9443, 4433, 4434, 4444,   # HTTPS alternates
    2376, 2377,                             # Docker daemon
    6443,                                   # Kubernetes API server
    10250, 10255,                           # Kubelet
    2379, 2380,                             # etcd
    9200, 9300,                             # Elasticsearch
    27017,                                  # MongoDB
    6380,                                   # Redis TLS (convention)
    9090, 9091, 9093, 9094,                 # Prometheus / Alertmanager
    8080, 8081, 8888, 8889,                 # Generic app servers
    5000, 5001,                             # Docker registry / Flask
}

# ---------------------------------------------------------------------------
# Module-level parsing helpers
# ---------------------------------------------------------------------------

def _ssh_parse_name_list(data, offset):
    """Parse SSH uint32-prefixed comma-separated name-list. Returns (names, new_offset)."""
    if offset + 4 > len(data):
        return [], offset
    length = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    if length == 0:
        return [], offset
    if offset + length > len(data):
        return [], offset
    raw = data[offset:offset + length].decode("utf-8", errors="ignore")
    return [n for n in raw.split(",") if n], offset + length


def _der_read_tlv(data, offset):
    """Read one DER TLV. Returns (tag, value_bytes, next_offset) or (None, None, offset)."""
    if offset >= len(data):
        return None, None, offset
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        return tag, b"", offset
    fb = data[offset]
    offset += 1
    if fb & 0x80:
        n = fb & 0x7f
        if n == 0 or n > 4 or offset + n > len(data):
            return tag, b"", offset
        length = int.from_bytes(data[offset:offset + n], "big")
        offset += n
    else:
        length = fb
    if offset + length > len(data):
        return tag, data[offset:], len(data)
    return tag, data[offset:offset + length], offset + length


def _find_kerberos_etypes(data):
    """Scan DER-encoded Kerberos AS-REQ for the etype list ([8] context tag)."""
    i = 0
    while i < len(data) - 4:
        if data[i] == 0xa8:  # [8] CONTEXT-CONSTRUCTED
            j = i + 1
            fb = data[j]; j += 1
            if fb & 0x80:
                n = fb & 0x7f
                j += n
            # Expect SEQUENCE inside
            if j < len(data) and data[j] == 0x30:
                _, seq_val, _ = _der_read_tlv(data, j)
                etypes = []
                k = 0
                while k < len(seq_val):
                    if seq_val[k] != 0x02:  # INTEGER
                        break
                    _, int_val, k2 = _der_read_tlv(seq_val, k)
                    k = k2
                    if int_val:
                        raw = int_val
                        val = int.from_bytes(raw, "big")
                        if raw[0] & 0x80:  # negative
                            val -= 1 << (8 * len(raw))
                        etypes.append(val)
                if etypes:
                    return etypes
        i += 1
    return []


def _parse_ikev2_payloads(data, start_offset, first_payload_type, total_len):
    """Walk IKEv2 payload chain. Returns dict keyed by payload type."""
    payloads = {}
    offset = start_offset
    current_type = first_payload_type
    while current_type != 0 and offset + 4 <= min(total_len, len(data)):
        next_type = data[offset]
        payload_len = struct.unpack(">H", data[offset + 2:offset + 4])[0]
        if payload_len < 4 or offset + payload_len > len(data):
            break
        payload_body = data[offset + 4:offset + payload_len]
        payloads[current_type] = payload_body
        current_type = next_type
        offset += payload_len
    return payloads


def _parse_ikev2_sa(sa_data):
    """Parse IKEv2 SA payload. Returns list of proposal dicts."""
    proposals = []
    offset = 0
    while offset + 8 <= len(sa_data):
        last_sub = sa_data[offset]
        prop_len = struct.unpack(">H", sa_data[offset + 2:offset + 4])[0]
        if prop_len < 8 or offset + prop_len > len(sa_data):
            break
        prop_num = sa_data[offset + 4]
        proto_id = sa_data[offset + 5]
        spi_size = sa_data[offset + 6]
        num_transforms = sa_data[offset + 7]
        proto_names = {1: "IKE", 2: "AH", 3: "ESP"}
        proposal = {
            "proposal_num": prop_num,
            "protocol": proto_names.get(proto_id, f"proto_{proto_id}"),
            "transforms": [],
        }
        t_offset = offset + 8 + spi_size
        for _ in range(num_transforms):
            if t_offset + 8 > offset + prop_len:
                break
            last_t = sa_data[t_offset]
            t_len = struct.unpack(">H", sa_data[t_offset + 2:t_offset + 4])[0]
            if t_len < 8:
                break
            t_type = sa_data[t_offset + 4]
            t_id = struct.unpack(">H", sa_data[t_offset + 6:t_offset + 8])[0]
            type_names = {1: "ENCR", 2: "PRF", 3: "INTEG", 4: "D-H", 5: "ESN"}
            id_maps = {1: IKE_ENCR, 2: IKE_PRF, 3: IKE_INTEG, 4: IKE_DH}
            t_name = id_maps.get(t_type, {}).get(t_id, f"{type_names.get(t_type,'?')}_{t_id}")
            proposal["transforms"].append({
                "type": type_names.get(t_type, f"type_{t_type}"),
                "id": t_id,
                "name": t_name,
            })
            if last_t == 0:
                break
            t_offset += t_len
        proposals.append(proposal)
        if last_sub == 0:
            break
        offset += prop_len
    return proposals


def _parse_quic_varint(data, offset):
    """Parse QUIC variable-length integer. Returns (value, new_offset)."""
    if offset >= len(data):
        return 0, offset
    first = data[offset]
    prefix = (first & 0xc0) >> 6
    if prefix == 0:
        return first & 0x3f, offset + 1
    elif prefix == 1:
        if offset + 2 > len(data):
            return 0, offset
        return struct.unpack(">H", data[offset:offset + 2])[0] & 0x3fff, offset + 2
    elif prefix == 2:
        if offset + 4 > len(data):
            return 0, offset
        return struct.unpack(">I", data[offset:offset + 4])[0] & 0x3fffffff, offset + 4
    else:
        if offset + 8 > len(data):
            return 0, offset
        return struct.unpack(">Q", data[offset:offset + 8])[0] & 0x3fffffffffffffff, offset + 8


def _quic_hkdf_expand(prk, info, length):
    """HKDF-Expand using HMAC-SHA256 (RFC 5869)."""
    n = (length + 31) // 32
    t = b""
    t_prev = b""
    for i in range(1, n + 1):
        t_prev = _hmac.new(prk, t_prev + info + bytes([i]), hashlib.sha256).digest()
        t += t_prev
    return t[:length]


def _quic_hkdf_expand_label(secret, label, context, length):
    """TLS 1.3 HKDF-Expand-Label (RFC 8446 §7.1)."""
    full_label = b"tls13 " + label
    hkdf_label = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)]) + full_label
        + bytes([len(context)]) + context
    )
    return _quic_hkdf_expand(secret, hkdf_label, length)


def _quic_derive_keys(dcid, version):
    """Derive QUIC Initial packet keys from destination connection ID."""
    salt = QUIC_INITIAL_SALT_V1 if version == 0x00000001 else QUIC_INITIAL_SALT_V2
    initial_secret = _hmac.new(salt, dcid, hashlib.sha256).digest()
    client_secret = _quic_hkdf_expand_label(initial_secret, b"client in", b"", 32)
    key = _quic_hkdf_expand_label(client_secret, b"quic key", b"", 16)
    iv  = _quic_hkdf_expand_label(client_secret, b"quic iv",  b"", 12)
    hp  = _quic_hkdf_expand_label(client_secret, b"quic hp",  b"", 16)
    return key, iv, hp


def _quic_remove_header_protection(raw_header, payload, hp_key):
    """Remove QUIC header protection. Returns (unprotected_header_bytes, pn_length)."""
    if not _CRYPTO_AVAILABLE or len(payload) < 20:
        return None, 0
    sample = payload[4:20]
    cipher = Cipher(algorithms.AES(hp_key), modes.ECB(), backend=default_backend())
    mask = cipher.encryptor().update(sample)
    header = bytearray(raw_header)
    if header[0] & 0x80:  # long header
        header[0] ^= mask[0] & 0x0f
    else:
        header[0] ^= mask[0] & 0x1f
    pn_len = (header[0] & 0x03) + 1
    for i in range(pn_len):
        header[len(header) - pn_len + i] ^= mask[1 + i]
    return bytes(header), pn_len


def _quic_decrypt_payload(key, iv, packet_number, payload_ciphertext, aad):
    """Decrypt QUIC packet payload with AES-128-GCM."""
    if not _CRYPTO_AVAILABLE:
        return None
    nonce = bytearray(iv)
    pn_bytes = packet_number.to_bytes(len(iv), "big")
    for i in range(len(iv)):
        nonce[i] ^= pn_bytes[i]
    try:
        return AESGCM(key).decrypt(bytes(nonce), payload_ciphertext, aad)
    except Exception:
        return None


def _extract_quic_tls_hello(frames):
    """Find TLS ClientHello bytes in QUIC CRYPTO frames."""
    crypto_data = {}
    offset = 0
    while offset < len(frames):
        frame_type, offset = _parse_quic_varint(frames, offset)
        if frame_type == 0x06:  # CRYPTO
            crypto_offset, offset = _parse_quic_varint(frames, offset)
            crypto_len, offset = _parse_quic_varint(frames, offset)
            if offset + crypto_len > len(frames):
                break
            crypto_data[crypto_offset] = frames[offset:offset + crypto_len]
            offset += crypto_len
        elif frame_type == 0x00:  # PADDING
            while offset < len(frames) and frames[offset] == 0:
                offset += 1
        elif frame_type == 0x01:  # PING
            pass
        else:
            break  # Unknown frame type — stop
    if not crypto_data:
        return None
    assembled = b"".join(v for _, v in sorted(crypto_data.items()))
    # TLS record: type(1) + legacy_version(2) + length(2) + data
    # For TLS 1.3 in QUIC there's no record layer — just handshake messages
    # Handshake: msg_type(1) + length(3) + body
    if len(assembled) < 4:
        return None
    if assembled[0] == 0x01:  # ClientHello
        return assembled
    return None


def _parse_tls_extensions_raw(data, pos, end):
    """Parse TLS extensions from a ClientHello/ServerHello body."""
    result = {}
    ext_names = []
    server_name = None
    supported_groups = []
    supported_versions = []
    alpn_protocols = []

    while pos + 4 <= min(end, len(data)):
        ext_type = struct.unpack(">H", data[pos:pos + 2])[0]
        ext_dlen = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        ext_data = data[pos + 4:pos + 4 + ext_dlen]
        ext_names.append(TLS_EXTENSIONS.get(ext_type, f"unknown_{ext_type}"))

        if ext_type == 0 and len(ext_data) >= 5:  # SNI
            nlen = struct.unpack(">H", ext_data[3:5])[0]
            server_name = ext_data[5:5 + nlen].decode("utf-8", errors="ignore")

        elif ext_type == 10 and len(ext_data) >= 2:  # supported_groups
            gl = struct.unpack(">H", ext_data[0:2])[0]
            for gi in range(2, 2 + gl, 2):
                if gi + 2 <= len(ext_data):
                    gid = struct.unpack(">H", ext_data[gi:gi + 2])[0]
                    supported_groups.append(TLS_NAMED_GROUPS.get(gid, f"group_0x{gid:04x}"))

        elif ext_type == 43 and ext_data:  # supported_versions
            if ext_data[0] % 2 == 0 and len(ext_data) > 1:  # ClientHello: length + list
                for vi in range(1, ext_data[0] + 1, 2):
                    if vi + 2 <= len(ext_data):
                        ver = struct.unpack(">H", ext_data[vi:vi + 2])[0]
                        supported_versions.append(TLS_VERSIONS.get(ver, f"0x{ver:04x}"))
            elif len(ext_data) >= 2:  # ServerHello: single value
                ver = struct.unpack(">H", ext_data[0:2])[0]
                supported_versions.append(TLS_VERSIONS.get(ver, f"0x{ver:04x}"))

        elif ext_type == 16 and len(ext_data) >= 2:  # ALPN
            off = 2
            while off < len(ext_data):
                plen = ext_data[off]; off += 1
                if off + plen <= len(ext_data):
                    alpn_protocols.append(ext_data[off:off + plen].decode("utf-8", errors="ignore"))
                off += plen

        pos += 4 + ext_dlen

    result["extensions"] = ext_names
    if server_name:        result["server_name"] = server_name
    if supported_groups:   result["supported_groups"] = supported_groups
    if supported_versions: result["supported_versions"] = supported_versions
    if alpn_protocols:     result["alpn_protocols"] = alpn_protocols
    return result


def _parse_tls_hello_raw(data):
    """
    Parse a TLS ClientHello or ServerHello from raw bytes without scapy.
    data must start at the TLS record header (0x16 0x03 ...).
    Returns a dict of parsed fields, or None if not a recognisable hello.
    """
    if len(data) < 9:
        return None
    if data[0] != 0x16 or data[1] != 0x03 or data[2] not in (0x00, 0x01, 0x02, 0x03, 0x04):
        return None
    record_version = (data[1] << 8) | data[2]
    hs_type = data[5]
    if hs_type not in (0x01, 0x02):
        return None
    hs_len = struct.unpack(">I", b"\x00" + data[6:9])[0]
    body = data[9:9 + hs_len]
    if len(body) < 34:
        return None

    result = {
        "hs_type": "ClientHello" if hs_type == 0x01 else "ServerHello",
        "record_version": TLS_VERSIONS.get(record_version, f"0x{record_version:04x}"),
    }
    pos = 34  # skip legacy_version (2) + random (32)

    if hs_type == 0x01:  # ClientHello
        if pos >= len(body): return result
        sid_len = body[pos]
        if pos + 1 + sid_len > len(body): return result
        pos += 1 + sid_len
        if pos + 2 > len(body): return result
        cs_len = struct.unpack(">H", body[pos:pos + 2])[0]
        if pos + 2 + cs_len > len(body): return result
        pos += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            if pos + i + 2 <= len(body):
                cs = struct.unpack(">H", body[pos + i:pos + i + 2])[0]
                ciphers.append({"name": TLS_CIPHER_SUITES.get(cs, f"UNKNOWN_0x{cs:04x}"),
                                "value": f"0x{cs:04x}"})
        result["client_cipher_suites"] = ciphers
        result["cipher_count"] = len(ciphers)
        pos += cs_len
        if pos < len(body):
            comp_len = body[pos]
            if pos + 1 + comp_len > len(body): return result
            pos += 1 + comp_len
        if pos + 2 <= len(body):
            ext_len = struct.unpack(">H", body[pos:pos + 2])[0]; pos += 2
            result.update(_parse_tls_extensions_raw(body, pos, pos + ext_len))

    elif hs_type == 0x02:  # ServerHello
        if pos >= len(body): return result
        sid_len = body[pos]
        if pos + 1 + sid_len > len(body): return result
        pos += 1 + sid_len
        if pos + 3 > len(body): return result
        cs = struct.unpack(">H", body[pos:pos + 2])[0]
        result["selected_cipher"] = {"name": TLS_CIPHER_SUITES.get(cs, f"UNKNOWN_0x{cs:04x}"),
                                      "value": f"0x{cs:04x}"}
        pos += 3
        if pos + 2 <= len(body):
            ext_len = struct.unpack(">H", body[pos:pos + 2])[0]; pos += 2
            result.update(_parse_tls_extensions_raw(body, pos, pos + ext_len))

    return result


# ---------------------------------------------------------------------------
# Main sniffer class
# ---------------------------------------------------------------------------

class CryptoSniffer:
    def __init__(self, interface=None, log_file="sniffy.json", encrypted_only=True):
        self.interface = interface
        self.log_file = Path(log_file)
        self.encrypted_only = encrypted_only
        self.connections = defaultdict(dict)
        self.log_entries = []

    def get_cipher_name(self, cipher_value):
        return TLS_CIPHER_SUITES.get(cipher_value, f"UNKNOWN_0x{cipher_value:04x}")

    def get_version_name(self, version_value):
        return TLS_VERSIONS.get(version_value, f"UNKNOWN_0x{version_value:04x}")

    def check_pq_security(self, info):
        """
        Determine if connection is post-quantum secure.

        Returns:
          "Yes"     — uses a PQ-safe algorithm
          "Hybrid"  — mix of PQ and classical
          "No"      — classical only (quantum-vulnerable)
          "Unknown" — cannot determine
        """
        pq_kex = False
        classical_kex = False

        # TLS / QUIC: supported_groups or key_share
        for group in info.get("supported_groups", []):
            g = group.lower()
            if any(pq in g for pq in PQ_SAFE_KEX):
                pq_kex = True
            if any(c in g for c in CLASSICAL_KEX):
                classical_kex = True

        # SSH KEX Init
        for kex in info.get("ssh_kex_algorithms", []):
            k = kex.lower()
            if k in PQ_SAFE_KEX or any(pq in k for pq in PQ_SAFE_KEX):
                pq_kex = True
            if k in CLASSICAL_KEX or any(c in k for c in CLASSICAL_KEX):
                classical_kex = True

        # IKEv2: check D-H transforms across all proposals
        for proposal in info.get("ike_proposals", []):
            for t in proposal.get("transforms", []):
                if t["type"] == "D-H":
                    name = t["name"].lower()
                    if any(pq in name for pq in ["kyber", "ntru", "mlkem", "frodo"]):
                        pq_kex = True
                    else:
                        classical_kex = True

        # TLS cipher suite PQ indicators
        if "selected_cipher" in info:
            cipher = info["selected_cipher"].get("name", "").lower()
            if any(pq in cipher for pq in ["kyber", "ntru", "frodo", "mlkem"]):
                pq_kex = True

        # ALPN: label gRPC/h2 but don't affect PQ determination
        # (PQ status comes from TLS layer, already captured above)

        # Kerberos: no PQ etype exists yet
        if "kerberos_etypes" in info:
            return "No"

        # DNSSEC: no PQ signing algorithm deployed yet (2025)
        if "dnssec_algorithms" in info:
            return "No"

        # RADIUS: MD5-based shared secret — never PQ
        if info.get("protocol") in ("RADIUS",):
            return "No"

        # SNMPv3: pre-shared key, no asymmetric exchange — never PQ
        if info.get("protocol") == "SNMPv3":
            return "No"

        # WireGuard: Curve25519 unless oversized handshake (experimental PQ variant)
        if info.get("protocol") == "WireGuard":
            if info.get("pq_wireguard_suspected"):
                return "Hybrid"
            return "No"

        # RDP: never PQ in current implementations
        if info.get("protocol") == "RDP":
            return "No"

        # OpenVPN: TLS control channel — flag Unknown unless TLS tells us
        if info.get("protocol") == "OpenVPN" and not pq_kex and not classical_kex:
            return "Unknown"

        # SIP (plain): no crypto
        if info.get("protocol") == "SIP" and not pq_kex and not classical_kex:
            return "No"

        # QUIC: If we couldn't decrypt to determine PQ status, default to "No"
        # QUIC uses TLS 1.3 which is classical (ECDHE) unless PQ extensions are present
        # As of 2026, PQ in QUIC/TLS 1.3 is still experimental/rare
        if info.get("protocol") == "QUIC" and not pq_kex and not classical_kex:
            # Check if we successfully decrypted - if so, we would have seen supported_groups
            # If decryption failed or no PQ groups found, assume classical
            return "No"

        # TLS ServerHello: If we have a cipher but no key exchange info, it's classical
        # This handles cases where key_share parsing failed but we know it's TLS 1.3
        # PQ TLS is still experimental as of 2026; standard TLS 1.3 is classical ECDHE
        if (info.get("protocol") == "TLS" and
            info.get("type") == "TLS ServerHello" and
            "selected_cipher" in info and
            not pq_kex and not classical_kex):
            return "No"

        if pq_kex and classical_kex:
            return "Hybrid"
        elif pq_kex:
            return "Yes"
        elif classical_kex:
            return "No"
        else:
            return "Unknown"

    # -----------------------------------------------------------------------
    # TLS
    # -----------------------------------------------------------------------

    def _parse_alpn_ext(self, ext_data):
        """Parse ALPN extension data. Returns list of protocol strings."""
        if len(ext_data) < 4:
            return []
        # protocol_list_length (2) then entries: length (1) + bytes
        list_len = struct.unpack(">H", ext_data[0:2])[0]
        offset = 2
        protocols = []
        while offset < 2 + list_len and offset < len(ext_data):
            plen = ext_data[offset]; offset += 1
            if offset + plen > len(ext_data):
                break
            protocols.append(ext_data[offset:offset + plen].decode("utf-8", errors="ignore"))
            offset += plen
        return protocols

    def analyze_tls_client_hello(self, pkt):
        if not pkt.haslayer(TLSClientHello):
            return None
        ch = pkt[TLSClientHello]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        tcp = pkt[TCP]
        conn_id = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"

        info = {
            "protocol": "TLS",
            "type": "TLS ClientHello",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": tcp.sport,
            "dst_ip": ip.dst, "dst_port": tcp.dport,
            "connection": conn_id,
            "direction": "outbound",
            "encrypted": True,
        }

        if hasattr(ch, "version"):
            info["tls_version"] = self.get_version_name(ch.version)
            info["tls_version_value"] = f"0x{ch.version:04x}"

        if hasattr(ch, "ciphers") and ch.ciphers:
            clist = [{"name": self.get_cipher_name(c), "value": f"0x{c:04x}"} for c in ch.ciphers]
            info["client_cipher_suites"] = clist
            info["cipher_count"] = len(clist)

        if hasattr(ch, "ext") and ch.ext:
            extensions = []
            server_name = None
            supported_versions = []
            supported_groups = []
            alpn_protocols = []

            for ext in ch.ext:
                ext_type = getattr(ext, "type", None)
                ext_name = TLS_EXTENSIONS.get(ext_type, f"unknown_{ext_type}")

                if ext_type == 0 and hasattr(ext, "servernames"):
                    for sn in ext.servernames:
                        if hasattr(sn, "servername"):
                            server_name = sn.servername.decode("utf-8", errors="ignore")

                if ext_type == 43 and hasattr(ext, "versions"):
                    for ver in ext.versions:
                        supported_versions.append(self.get_version_name(ver))

                if ext_type == 10 and hasattr(ext, "groups"):
                    for grp in ext.groups:
                        supported_groups.append(TLS_NAMED_GROUPS.get(grp, f"group_0x{grp:04x}"))

                if ext_type == 16:  # ALPN
                    raw = bytes(ext)
                    # skip 4-byte generic header
                    alpn_protocols = self._parse_alpn_ext(raw[4:]) if len(raw) > 4 else []

                extensions.append(ext_name)

            info["extensions"] = extensions
            if server_name:
                info["server_name"] = server_name
            if supported_versions:
                info["supported_versions"] = supported_versions
            if supported_groups:
                info["supported_groups"] = supported_groups
            if alpn_protocols:
                info["alpn_protocols"] = alpn_protocols
                if "h2" in alpn_protocols:
                    info["application"] = "gRPC / HTTP2"

        info["post_quantum_secure"] = self.check_pq_security(info)
        return info

    def analyze_tls_server_hello(self, pkt):
        if not pkt.haslayer(TLSServerHello):
            return None
        sh = pkt[TLSServerHello]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        tcp = pkt[TCP]
        conn_id = f"{ip.dst}:{tcp.dport} -> {ip.src}:{tcp.sport}"

        info = {
            "protocol": "TLS",
            "type": "TLS ServerHello",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": tcp.sport,
            "dst_ip": ip.dst, "dst_port": tcp.dport,
            "connection": conn_id,
            "direction": "inbound",
            "encrypted": True,
        }

        if hasattr(sh, "version"):
            info["tls_version"] = self.get_version_name(sh.version)
            info["tls_version_value"] = f"0x{sh.version:04x}"

        if hasattr(sh, "cipher"):
            info["selected_cipher"] = {
                "name": self.get_cipher_name(sh.cipher),
                "value": f"0x{sh.cipher:04x}",
            }

        if hasattr(sh, "ext") and sh.ext:
            extensions = []
            supported_groups = []
            alpn_protocols = []

            for ext in sh.ext:
                ext_type = getattr(ext, "type", None)
                ext_name = TLS_EXTENSIONS.get(ext_type, f"unknown_{ext_type}")
                extensions.append(ext_name)

                # key_share extension (type 51) - extract group from ServerHello
                if ext_type == 51:
                    # Try multiple ways to extract the group
                    group = None
                    if hasattr(ext, "group"):
                        group = ext.group
                    elif hasattr(ext, "server_share") and hasattr(ext.server_share, "group"):
                        group = ext.server_share.group
                    else:
                        # Manual parse: ServerHello key_share format is:
                        # type(2) | length(2) | group(2) | key_length(2) | key_exchange(n)
                        try:
                            raw = bytes(ext)
                            if len(raw) >= 6:
                                # Skip type(2) + length(2), read group(2)
                                group = struct.unpack("!H", raw[4:6])[0]
                        except Exception:
                            pass

                    if group is not None:
                        supported_groups.append(
                            TLS_NAMED_GROUPS.get(group, f"group_0x{group:04x}")
                        )

                if ext_type == 16:
                    raw = bytes(ext)
                    alpn_protocols = self._parse_alpn_ext(raw[4:]) if len(raw) > 4 else []

            info["extensions"] = extensions
            if supported_groups:
                info["supported_groups"] = supported_groups
            if alpn_protocols:
                info["alpn_protocols"] = alpn_protocols
                if "h2" in alpn_protocols:
                    info["application"] = "gRPC / HTTP2"

        info["post_quantum_secure"] = self.check_pq_security(info)
        return info

    # -----------------------------------------------------------------------
    # SSH — banner (existing)
    # -----------------------------------------------------------------------

    def analyze_ssh(self, pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None
        tcp = pkt[TCP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        if tcp.dport != 22 and tcp.sport != 22:
            return None
        payload = bytes(pkt[Raw].load)
        if not payload.startswith(b"SSH-"):
            return None
        try:
            banner = payload.split(b"\r\n")[0].decode("utf-8", errors="ignore")
        except Exception:
            return None
        conn_id = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
        info = {
            "protocol": "SSH",
            "type": "SSH Banner",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": tcp.sport,
            "dst_ip": ip.dst, "dst_port": tcp.dport,
            "connection": conn_id,
            "direction": "outbound" if tcp.dport == 22 else "inbound",
            "ssh_banner": banner,
            "encrypted": True,
        }
        parts = banner.split("-")
        if len(parts) >= 3:
            info["ssh_protocol_version"] = parts[1]
            info["ssh_software_version"] = "-".join(parts[2:])
        # Banner alone doesn't reveal KEX — mark Unknown; KEX_INIT will follow
        info["post_quantum_secure"] = "Unknown"
        return info

    # -----------------------------------------------------------------------
    # SSH — KEX Init (FIX: was missing entirely)
    # -----------------------------------------------------------------------

    def analyze_ssh_kexinit(self, pkt):
        """Parse SSH_MSG_KEXINIT binary message for actual algorithm negotiation."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None
        tcp = pkt[TCP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        if tcp.dport != 22 and tcp.sport != 22:
            return None
        payload = bytes(pkt[Raw].load)
        if payload.startswith(b"SSH-"):  # banner packet, not binary
            return None

        # SSH binary packet: uint32 length | byte padding_len | byte msg_type | ...
        offset = 0
        while offset + 6 <= len(payload):
            try:
                pkt_len = struct.unpack(">I", payload[offset:offset + 4])[0]
                if pkt_len < 2 or pkt_len > 65536:
                    break
                pad_len = payload[offset + 4]
                msg_type = payload[offset + 5]
                if msg_type == 20:  # SSH_MSG_KEXINIT
                    # 16-byte cookie follows msg_type
                    d = offset + 6
                    if d + 16 > len(payload):
                        break
                    d += 16  # skip cookie
                    kex_algs,      d = _ssh_parse_name_list(payload, d)
                    host_key_algs, d = _ssh_parse_name_list(payload, d)
                    enc_c2s,       d = _ssh_parse_name_list(payload, d)
                    enc_s2c,       d = _ssh_parse_name_list(payload, d)
                    mac_c2s,       d = _ssh_parse_name_list(payload, d)
                    mac_s2c,       d = _ssh_parse_name_list(payload, d)

                    conn_id = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
                    info = {
                        "protocol": "SSH",
                        "type": "SSH KEX Init",
                        "timestamp": datetime.now().isoformat(),
                        "src_ip": ip.src, "src_port": tcp.sport,
                        "dst_ip": ip.dst, "dst_port": tcp.dport,
                        "connection": conn_id,
                        "direction": "outbound" if tcp.dport == 22 else "inbound",
                        "encrypted": True,
                        "ssh_kex_algorithms": kex_algs,
                        "ssh_host_key_algorithms": host_key_algs,
                        "ssh_encryption_c2s": enc_c2s,
                        "ssh_encryption_s2c": enc_s2c,
                        "ssh_mac_c2s": mac_c2s,
                        "ssh_mac_s2c": mac_s2c,
                    }
                    info["post_quantum_secure"] = self.check_pq_security(info)
                    return info
                offset += 4 + pkt_len
            except (struct.error, IndexError):
                break
        return None

    # -----------------------------------------------------------------------
    # IPsec / IKEv2 (FIX: replaced stub with full SA proposal parsing)
    # -----------------------------------------------------------------------

    def analyze_ipsec_ike(self, pkt):
        if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
            return None
        udp = pkt[UDP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        if udp.dport not in (500, 4500) and udp.sport not in (500, 4500):
            return None

        raw = bytes(pkt[Raw].load)

        # NAT-T (port 4500) prefixes IKE with 4 zero bytes; ESP starts with non-zero
        if udp.dport == 4500 or udp.sport == 4500:
            if len(raw) < 4:
                return None
            if raw[0:4] == b"\x00\x00\x00\x00":
                raw = raw[4:]  # strip non-ESP marker
            elif raw[0] != 0:
                return None  # ESP data, not IKE

        if len(raw) < 28:
            return None

        # IKEv2 header
        version_byte = raw[17]
        major = (version_byte >> 4) & 0x0f
        if major not in (1, 2):
            return None

        first_payload = raw[16]
        exchange_type = raw[18]
        total_len = struct.unpack(">I", raw[24:28])[0]
        is_initiator = bool(raw[19] & 0x08)

        conn_id = f"{ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"
        info = {
            "protocol": "IPsec/IKE",
            "type": f"IKEv{major} {IKE_EXCHANGE_TYPES.get(exchange_type, f'exchange_{exchange_type}')}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": udp.sport,
            "dst_ip": ip.dst, "dst_port": udp.dport,
            "connection": conn_id,
            "direction": "outbound" if udp.dport in (500, 4500) else "inbound",
            "encrypted": True,
            "ike_version": f"IKEv{major}",
            "ike_exchange": IKE_EXCHANGE_TYPES.get(exchange_type, f"type_{exchange_type}"),
            "ike_role": "initiator" if is_initiator else "responder",
        }

        # Walk payloads to find SA (type 33)
        payloads = _parse_ikev2_payloads(raw, 28, first_payload, total_len)
        if 33 in payloads:  # SA payload
            proposals = _parse_ikev2_sa(payloads[33])
            if proposals:
                info["ike_proposals"] = proposals
                # Summarise D-H groups for quick scanning
                dh_groups = [
                    t["name"] for p in proposals for t in p["transforms"] if t["type"] == "D-H"
                ]
                if dh_groups:
                    info["ike_dh_groups"] = dh_groups

        info["post_quantum_secure"] = self.check_pq_security(info)
        return info

    # -----------------------------------------------------------------------
    # WireGuard (updated: flag oversized handshake as possible PQ variant)
    # -----------------------------------------------------------------------

    def analyze_wireguard(self, pkt):
        if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
            return None
        udp = pkt[UDP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        raw = bytes(pkt[Raw].load)
        if len(raw) < 4:
            return None

        msg_type = raw[0]
        if msg_type not in (1, 2, 3, 4):
            return None

        # Standard WireGuard sizes
        EXPECTED = {1: 148, 2: 92, 3: 64}
        expected = EXPECTED.get(msg_type)
        pq_suspected = False

        if msg_type in (1, 2, 3):
            if expected and len(raw) != expected:
                if len(raw) > expected:
                    pq_suspected = True  # Larger handshake — possible PQ KEM appended
                else:
                    return None  # Smaller than expected — not WireGuard

        msg_labels = {1: "Handshake Initiation", 2: "Handshake Response",
                      3: "Cookie Reply", 4: "Transport Data"}
        conn_id = f"{ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"

        info = {
            "protocol": "WireGuard",
            "type": f"WireGuard {msg_labels.get(msg_type, 'Unknown')}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": udp.sport,
            "dst_ip": ip.dst, "dst_port": udp.dport,
            "connection": conn_id,
            "direction": "outbound",
            "encrypted": True,
            "message_type": msg_labels.get(msg_type, f"type_{msg_type}"),
            "crypto_algorithms": "Curve25519, ChaCha20-Poly1305, BLAKE2s",
            "handshake_size": len(raw),
        }
        if pq_suspected:
            info["pq_wireguard_suspected"] = True
            info["note"] = (
                f"Handshake size {len(raw)} differs from standard {expected} — "
                "may be experimental PQ WireGuard variant"
            )
        info["post_quantum_secure"] = self.check_pq_security(info)
        return info

    # -----------------------------------------------------------------------
    # DTLS
    # -----------------------------------------------------------------------

    def analyze_dtls(self, pkt):
        if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
            return None
        udp = pkt[UDP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        raw = bytes(pkt[Raw].load)
        if len(raw) < 13:
            return None
        content_type = raw[0]
        if content_type not in (20, 21, 22, 23):
            return None
        version = struct.unpack(">H", raw[1:3])[0]
        dtls_versions = {0xFEFF: "DTLS 1.0", 0xFEFD: "DTLS 1.2", 0xFEFC: "DTLS 1.3"}
        if version not in dtls_versions:
            return None
        content_labels = {20: "ChangeCipherSpec", 21: "Alert",
                          22: "Handshake", 23: "Application Data"}
        conn_id = f"{ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"
        info = {
            "protocol": "DTLS",
            "type": f"DTLS {content_labels.get(content_type, 'Unknown')}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": udp.sport,
            "dst_ip": ip.dst, "dst_port": udp.dport,
            "connection": conn_id,
            "direction": "outbound",
            "encrypted": True,
            "dtls_version": dtls_versions[version],
            "content_type": content_labels.get(content_type, f"type_{content_type}"),
        }
        info["post_quantum_secure"] = "No"
        return info

    # -----------------------------------------------------------------------
    # QUIC (FIX: attempt to decrypt Initial packet and extract TLS ClientHello)
    # -----------------------------------------------------------------------

    def analyze_quic(self, pkt):
        if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
            return None
        udp = pkt[UDP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        if udp.dport != 443 and udp.sport != 443:
            return None
        raw = bytes(pkt[Raw].load)
        if len(raw) < 7:
            return None

        first_byte = raw[0]
        if not (first_byte & 0x80):  # short header — encrypted data
            return None
        # Long header: fixed bit must be set
        if not (first_byte & 0x40):
            return None
        # Initial packet type: bits 4-5 of first byte = 00
        if (first_byte & 0x30) != 0x00:
            return None
        if len(raw) < 5:
            return None
        version = struct.unpack(">I", raw[1:5])[0]
        if version not in (0x00000001, 0x6b3343cf):  # QUICv1, QUICv2
            return None

        offset = 5
        dcid_len = raw[offset]; offset += 1
        if offset + dcid_len > len(raw):
            return None
        dcid = raw[offset:offset + dcid_len]; offset += dcid_len
        scid_len = raw[offset]; offset += 1
        if offset + scid_len > len(raw):
            return None
        offset += scid_len  # skip SCID

        token_len, offset = _parse_quic_varint(raw, offset)
        offset += token_len  # skip token

        pkt_len, offset = _parse_quic_varint(raw, offset)
        pn_offset = offset  # packet number starts here (protected)

        conn_id = f"{ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"
        info = {
            "protocol": "QUIC",
            "type": "QUIC Initial",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": udp.sport,
            "dst_ip": ip.dst, "dst_port": udp.dport,
            "connection": conn_id,
            "direction": "outbound" if udp.dport == 443 else "inbound",
            "encrypted": True,
            "quic_version": f"0x{version:08x}",
            "quic_dcid": dcid.hex(),
            "note": "QUIC carries TLS 1.3 internally",
        }

        # Attempt to decrypt the QUIC Initial packet using known initial keys
        if _CRYPTO_AVAILABLE and dcid_len > 0 and pkt_len > 4:
            try:
                key, iv, hp = _quic_derive_keys(dcid, version)

                # Extract the complete QUIC packet payload
                # pkt_len is the length field from the QUIC header (includes PN + encrypted payload)
                if pn_offset + pkt_len > len(raw):
                    raise ValueError("Packet length exceeds available data")

                packet_payload = raw[pn_offset:pn_offset + pkt_len]

                # For header protection removal, we need the first byte + up to PN + sample (16 bytes at PN+4)
                # Build header with maximum PN length (4 bytes) for HP removal
                if len(packet_payload) < 20:  # Need at least 4 (max PN) + 16 (sample)
                    raise ValueError("Packet too short for decryption")

                # Header protection removal needs header up to and including PN
                # Create a working copy with enough bytes for the sample
                raw_header_with_pn = bytearray(raw[:pn_offset + 4])

                # Remove header protection
                unprotected_header, pn_len = _quic_remove_header_protection(
                    raw_header_with_pn, packet_payload, hp
                )

                if unprotected_header and pn_len > 0:
                    # Extract actual packet number bytes
                    pn_bytes = unprotected_header[-pn_len:]
                    packet_number = int.from_bytes(pn_bytes, "big")

                    # Build AAD: The AAD for QUIC is the complete unprotected header
                    # from the first byte up to and including the packet number.
                    # unprotected_header has the form: [all header bytes up to PN + 4 bytes for PN]
                    # We need: [all header bytes up to PN + actual pn_len bytes]
                    # The unprotected_header length is pn_offset + 4
                    # We want length pn_offset + pn_len
                    aad_len = pn_offset + pn_len
                    aad = unprotected_header[:aad_len]

                    # Encrypted payload is everything after the PN
                    encrypted_payload = packet_payload[pn_len:]

                    # Decrypt
                    plaintext = _quic_decrypt_payload(key, iv, packet_number, encrypted_payload, aad)
                    if plaintext:
                        tls_hello = _extract_quic_tls_hello(plaintext)
                        if tls_hello and len(tls_hello) > 38:
                            # Parse TLS ClientHello from QUIC CRYPTO frame
                            # Offset 0: msg_type (1), 1-3: length (3), then ClientHello body
                            body = tls_hello[4:]  # skip handshake header
                            if len(body) > 34:
                                # Legacy version (2) + random (32) + session_id_len (1)
                                sid_len = body[34]
                                if 35 + sid_len <= len(body):
                                    pos = 35 + sid_len
                                    if pos + 2 <= len(body):
                                        cs_len = struct.unpack(">H", body[pos:pos+2])[0]
                                        if pos + 2 + cs_len <= len(body):
                                            pos += 2 + cs_len
                                            # Read compression methods length
                                            if pos < len(body):
                                                comp_len = body[pos]
                                                if pos + 1 + comp_len <= len(body):
                                                    pos += 1 + comp_len
                                                    if pos + 2 <= len(body):
                                                        ext_len = struct.unpack(">H", body[pos:pos+2])[0]
                                                        pos += 2
                                                        ext_end = pos + ext_len
                                                        supported_groups = []
                                                        alpn_protocols = []
                                                        while pos + 4 <= ext_end and pos + 4 <= len(body):
                                                            ext_type = struct.unpack(">H", body[pos:pos+2])[0]
                                                            ext_data_len = struct.unpack(">H", body[pos+2:pos+4])[0]
                                                            if pos + 4 + ext_data_len > len(body):
                                                                break
                                                            ext_data = body[pos+4:pos+4+ext_data_len]
                                                            if ext_type == 10 and len(ext_data) >= 2:  # supported_groups
                                                                gl = struct.unpack(">H", ext_data[0:2])[0]
                                                                for gi in range(2, 2 + gl, 2):
                                                                    if gi + 2 <= len(ext_data):
                                                                        gid = struct.unpack(">H", ext_data[gi:gi+2])[0]
                                                                        supported_groups.append(
                                                                            TLS_NAMED_GROUPS.get(gid, f"group_0x{gid:04x}")
                                                                        )
                                                            if ext_type == 16:
                                                                alpn_protocols = self._parse_alpn_ext(ext_data)
                                                            pos += 4 + ext_data_len
                                                        if supported_groups:
                                                            info["supported_groups"] = supported_groups
                                                        if alpn_protocols:
                                                            info["alpn_protocols"] = alpn_protocols
                                                        info["quic_tls_decrypted"] = True
            except Exception as e:
                # Store decryption failure info for debugging
                info["quic_decrypt_error"] = str(e)
                pass  # fall through to base detection

        info["post_quantum_secure"] = self.check_pq_security(info)
        return info

    # -----------------------------------------------------------------------
    # DNS over TLS
    # -----------------------------------------------------------------------

    def analyze_dns_over_tls(self, pkt):
        if not pkt.haslayer(TCP):
            return None
        tcp = pkt[TCP]
        if tcp.dport != 853 and tcp.sport != 853:
            return None
        if pkt.haslayer(TLSClientHello) or pkt.haslayer(TLSServerHello):
            info = self.analyze_tls_client_hello(pkt) or self.analyze_tls_server_hello(pkt)
            if info:
                info["protocol"] = "DNS over TLS (DoT)"
                info["type"] = f"DoT {info['type']}"
            return info
        return None

    # -----------------------------------------------------------------------
    # DNSSEC (NEW)
    # -----------------------------------------------------------------------

    def analyze_dnssec(self, pkt):
        if not pkt.haslayer(DNS):
            return None
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        transport = pkt[TCP] if pkt.haslayer(TCP) else pkt[UDP]
        dns = pkt[DNS]

        # Only care about responses that contain security records
        if dns.qr != 1:  # not a response
            return None

        rrsig_algs = []
        dnskey_algs = []
        ds_algs = []

        for i in range(dns.ancount + dns.nscount + dns.arcount):
            try:
                rr = dns.an[i] if i < dns.ancount else (
                    dns.ns[i - dns.ancount] if i < dns.ancount + dns.nscount
                    else dns.ar[i - dns.ancount - dns.nscount]
                )
                rtype = getattr(rr, "type", 0)
                if rtype == 46:  # RRSIG
                    alg = getattr(rr, "algorithm", None)
                    if alg is not None and alg not in rrsig_algs:
                        rrsig_algs.append(alg)
                elif rtype == 48:  # DNSKEY
                    alg = getattr(rr, "algorithm", None)
                    if alg is not None and alg not in dnskey_algs:
                        dnskey_algs.append(alg)
                elif rtype == 43:  # DS
                    alg = getattr(rr, "algorithm", None)
                    if alg is not None and alg not in ds_algs:
                        ds_algs.append(alg)
            except (IndexError, AttributeError):
                pass

        if not rrsig_algs and not dnskey_algs and not ds_algs:
            return None

        all_algs = list(set(rrsig_algs + dnskey_algs + ds_algs))
        alg_names = [DNSSEC_ALGORITHMS.get(a, f"alg_{a}") for a in all_algs]

        sport = getattr(transport, "sport", 0)
        dport = getattr(transport, "dport", 0)
        conn_id = f"{ip.src}:{sport} -> {ip.dst}:{dport}"
        qname = dns.qd.qname.decode("utf-8", errors="ignore") if dns.qdcount > 0 else ""

        info = {
            "protocol": "DNSSEC",
            "type": "DNSSEC Response",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": sport,
            "dst_ip": ip.dst, "dst_port": dport,
            "connection": conn_id,
            "direction": "inbound",
            "encrypted": False,  # DNS is cleartext unless DoT/DoH
            "query_name": qname,
            "dnssec_algorithms": alg_names,
            "dnssec_algorithm_ids": all_algs,
        }
        info["post_quantum_secure"] = self.check_pq_security(info)
        return info

    # -----------------------------------------------------------------------
    # STARTTLS
    # -----------------------------------------------------------------------

    def analyze_starttls(self, pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None
        tcp = pkt[TCP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        STARTTLS_PORTS = {
            25: "SMTP", 587: "SMTP Submission", 143: "IMAP", 110: "POP3",
            21: "FTP", 389: "LDAP", 5222: "XMPP", 5432: "PostgreSQL", 3306: "MySQL",
        }
        if tcp.dport not in STARTTLS_PORTS and tcp.sport not in STARTTLS_PORTS:
            return None
        try:
            text = bytes(pkt[Raw].load).decode("utf-8", errors="ignore").upper()
        except Exception:
            return None
        if "STARTTLS" not in text:
            return None
        proto = STARTTLS_PORTS.get(tcp.dport) or STARTTLS_PORTS.get(tcp.sport, "Unknown")
        conn_id = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
        info = {
            "protocol": f"{proto} STARTTLS",
            "type": f"{proto} STARTTLS Upgrade",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": tcp.sport,
            "dst_ip": ip.dst, "dst_port": tcp.dport,
            "connection": conn_id,
            "direction": "outbound",
            "encrypted": True,
            "note": "Protocol upgrading to TLS",
        }
        info["post_quantum_secure"] = "Unknown"
        return info

    # -----------------------------------------------------------------------
    # SMB
    # -----------------------------------------------------------------------

    def analyze_smb(self, pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None
        tcp = pkt[TCP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        if tcp.dport != 445 and tcp.sport != 445:
            return None
        raw = bytes(pkt[Raw].load)
        if len(raw) < 4 or raw[0:4] not in (b"\xffSMB", b"\xfeSMB"):
            return None
        smb_ver = "SMB2/3" if raw[0:4] == b"\xfeSMB" else "SMB1"
        conn_id = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
        info = {
            "protocol": "SMB",
            "type": f"{smb_ver} Negotiate",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": tcp.sport,
            "dst_ip": ip.dst, "dst_port": tcp.dport,
            "connection": conn_id,
            "direction": "outbound" if tcp.dport == 445 else "inbound",
            "encrypted": True,
            "smb_version": smb_ver,
            "note": "SMB3 supports AES-128/256 encryption",
        }
        info["post_quantum_secure"] = "No"
        return info

    # -----------------------------------------------------------------------
    # RDP / CredSSP (NEW)
    # -----------------------------------------------------------------------

    def analyze_rdp(self, pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None
        tcp = pkt[TCP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        if tcp.dport != 3389 and tcp.sport != 3389:
            return None
        raw = bytes(pkt[Raw].load)
        if len(raw) < 11:
            return None
        # TPKT header: version=3, reserved=0
        if raw[0] != 3 or raw[1] != 0:
            return None
        tpkt_len = struct.unpack(">H", raw[2:4])[0]
        if tpkt_len < 11 or tpkt_len > len(raw) + 4:
            return None
        # X.224 CR (0xe0) or CC (0xd0)
        x224_code = raw[5]
        if x224_code not in (0xe0, 0xd0):
            return None

        msg_type = "RDP Connection Request" if x224_code == 0xe0 else "RDP Connection Confirm"
        conn_id = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"

        info = {
            "protocol": "RDP",
            "type": msg_type,
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": tcp.sport,
            "dst_ip": ip.dst, "dst_port": tcp.dport,
            "connection": conn_id,
            "direction": "outbound" if tcp.dport == 3389 else "inbound",
            "encrypted": True,
        }

        # Look for RDP Negotiation Request (type=0x01) or Response (type=0x02)
        neg_req = raw.find(b"\x01\x00\x08\x00", 4)
        neg_rsp = raw.find(b"\x02\x00\x08\x00", 4)

        if neg_req != -1 and neg_req + 8 <= len(raw):
            requested = struct.unpack("<I", raw[neg_req + 4:neg_req + 8])[0]
            proto_names = []
            for bit, name in [(0x01, "TLS"), (0x02, "CredSSP/NLA"),
                               (0x04, "RDSTLS"), (0x08, "CredSSP-EarlyAuth")]:
                if requested & bit:
                    proto_names.append(name)
            if not proto_names:
                proto_names = ["Standard RDP (RC4)"]
            info["rdp_requested_protocols"] = proto_names

        elif neg_rsp != -1 and neg_rsp + 8 <= len(raw):
            selected = struct.unpack("<I", raw[neg_rsp + 4:neg_rsp + 8])[0]
            info["rdp_selected_protocol"] = RDP_PROTOCOLS.get(selected, f"proto_{selected:#010x}")

        info["post_quantum_secure"] = self.check_pq_security(info)
        return info

    # -----------------------------------------------------------------------
    # Kerberos (NEW)
    # -----------------------------------------------------------------------

    def analyze_kerberos(self, pkt):
        if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)) or not pkt.haslayer(Raw):
            return None
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        is_tcp = pkt.haslayer(TCP)
        transport = pkt[TCP] if is_tcp else pkt[UDP]
        if transport.dport != 88 and transport.sport != 88:
            return None

        raw = bytes(pkt[Raw].load)
        # TCP Kerberos has a 4-byte length prefix
        data = raw[4:] if is_tcp and len(raw) > 4 else raw
        if len(data) < 2:
            return None

        # Kerberos application tags (ASN.1 APPLICATION CONSTRUCTED):
        # AS-REQ=0x6a, AS-REP=0x6b, TGS-REQ=0x6c, TGS-REP=0x6d
        # AP-REQ=0x6e, AP-REP=0x6f, KRB-ERROR=0x7e
        tag = data[0]
        msg_types = {
            0x6a: "AS-REQ",   0x6b: "AS-REP",
            0x6c: "TGS-REQ",  0x6d: "TGS-REP",
            0x6e: "AP-REQ",   0x6f: "AP-REP",
            0x7e: "KRB-ERROR",
        }
        if tag not in msg_types:
            return None

        msg_name = msg_types[tag]
        conn_id = f"{ip.src}:{transport.sport} -> {ip.dst}:{transport.dport}"
        info = {
            "protocol": "Kerberos",
            "type": f"Kerberos {msg_name}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": transport.sport,
            "dst_ip": ip.dst, "dst_port": transport.dport,
            "connection": conn_id,
            "direction": "outbound" if transport.dport == 88 else "inbound",
            "encrypted": False,  # pre-auth exchange is cleartext
            "kerberos_message": msg_name,
        }

        # Extract etype list from AS-REQ or TGS-REQ
        if tag in (0x6a, 0x6c):
            etypes = _find_kerberos_etypes(data)
            if etypes:
                etype_names = [KERBEROS_ETYPES.get(e, f"etype_{e}") for e in etypes]
                info["kerberos_etypes"] = etype_names
                info["kerberos_etype_ids"] = etypes

        info["post_quantum_secure"] = self.check_pq_security(info)
        return info

    # -----------------------------------------------------------------------
    # SNMPv3 (NEW)
    # -----------------------------------------------------------------------

    def analyze_snmpv3(self, pkt):
        if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
            return None
        udp = pkt[UDP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        if udp.dport not in (161, 162) and udp.sport not in (161, 162):
            return None
        raw = bytes(pkt[Raw].load)
        if len(raw) < 7:
            return None
        # SNMP is BER SEQUENCE
        if raw[0] != 0x30:
            return None

        # Parse outer SEQUENCE to reach version INTEGER
        tag, seq_val, _ = _der_read_tlv(raw, 0)
        if tag != 0x30 or not seq_val:
            return None
        ver_tag, ver_val, rest_offset = _der_read_tlv(seq_val, 0)
        if ver_tag != 0x02 or not ver_val:
            return None
        version = int.from_bytes(ver_val, "big")
        if version != 3:  # 0=v1, 1=v2c, 3=v3
            return None

        conn_id = f"{ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"
        info = {
            "protocol": "SNMPv3",
            "type": "SNMPv3 Message",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": udp.sport,
            "dst_ip": ip.dst, "dst_port": udp.dport,
            "connection": conn_id,
            "direction": "outbound" if udp.dport == 161 else "inbound",
            "encrypted": False,
        }

        # Parse msgGlobalData SEQUENCE to get msgFlags
        gd_tag, gd_val, _ = _der_read_tlv(seq_val, rest_offset)
        if gd_tag == 0x30 and gd_val:
            # msgID, msgMaxSize, msgFlags (OCTET STRING), msgSecurityModel
            o = 0
            for _ in range(3):  # skip msgID and msgMaxSize
                _, _, o = _der_read_tlv(gd_val, o)
                if o is None:
                    break
            flag_tag, flag_val, _ = _der_read_tlv(gd_val, o)
            if flag_tag == 0x04 and flag_val:
                flags = flag_val[0]
                auth = bool(flags & 0x01)
                priv = bool(flags & 0x02)
                info["snmpv3_auth"] = auth
                info["snmpv3_priv"] = priv
                if priv:
                    info["encrypted"] = True
                level = ("authPriv" if auth and priv
                         else "authNoPriv" if auth
                         else "noAuthNoPriv")
                info["snmpv3_security_level"] = level

        info["post_quantum_secure"] = self.check_pq_security(info)
        return info

    # -----------------------------------------------------------------------
    # OpenVPN (NEW)
    # -----------------------------------------------------------------------

    def analyze_openvpn(self, pkt):
        if not (pkt.haslayer(UDP) or pkt.haslayer(TCP)) or not pkt.haslayer(Raw):
            return None
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        is_tcp = pkt.haslayer(TCP)
        transport = pkt[TCP] if is_tcp else pkt[UDP]
        if transport.dport not in (1194,) and transport.sport not in (1194,):
            return None
        raw = bytes(pkt[Raw].load)
        # TCP OpenVPN has a 2-byte length prefix
        if is_tcp:
            if len(raw) < 3:
                return None
            raw = raw[2:]
        if len(raw) < 2:
            return None

        opcode = (raw[0] >> 3) & 0x1f
        key_id = raw[0] & 0x07
        if opcode not in OPENVPN_OPCODES:
            return None

        # Only report control/reset packets, not bulk data
        if opcode in (6, 9):  # P_DATA_V1, P_DATA_V2
            return None

        conn_id = f"{ip.src}:{transport.sport} -> {ip.dst}:{transport.dport}"
        info = {
            "protocol": "OpenVPN",
            "type": f"OpenVPN {OPENVPN_OPCODES[opcode]}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": transport.sport,
            "dst_ip": ip.dst, "dst_port": transport.dport,
            "connection": conn_id,
            "direction": "outbound" if transport.dport == 1194 else "inbound",
            "encrypted": True,
            "openvpn_opcode": OPENVPN_OPCODES[opcode],
            "openvpn_key_id": key_id,
            "note": "PQ status depends on TLS cipher negotiated in control channel",
        }
        info["post_quantum_secure"] = self.check_pq_security(info)
        return info

    # -----------------------------------------------------------------------
    # RADIUS (NEW)
    # -----------------------------------------------------------------------

    def analyze_radius(self, pkt):
        if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
            return None
        udp = pkt[UDP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        if udp.dport not in (1812, 1813) and udp.sport not in (1812, 1813):
            return None
        raw = bytes(pkt[Raw].load)
        if len(raw) < 20:
            return None

        code = raw[0]
        if code not in RADIUS_CODES:
            return None
        radius_len = struct.unpack(">H", raw[2:4])[0]
        if radius_len < 20 or radius_len > len(raw):
            return None

        conn_id = f"{ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"
        info = {
            "protocol": "RADIUS",
            "type": f"RADIUS {RADIUS_CODES.get(code, f'code_{code}')}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": udp.sport,
            "dst_ip": ip.dst, "dst_port": udp.dport,
            "connection": conn_id,
            "direction": "outbound" if udp.dport in (1812, 1813) else "inbound",
            "encrypted": False,  # RADIUS uses MD5 for auth, not TLS (unless RadSec)
            "radius_code": RADIUS_CODES.get(code, f"code_{code}"),
        }

        # Walk attributes looking for EAP-Message (type 79)
        offset = 20
        while offset + 2 <= radius_len and offset + 2 <= len(raw):
            attr_type = raw[offset]
            attr_len = raw[offset + 1]
            if attr_len < 2 or offset + attr_len > len(raw):
                break
            attr_val = raw[offset + 2:offset + attr_len]
            if attr_type == 79 and len(attr_val) >= 4:  # EAP-Message
                eap_code = attr_val[0]
                eap_type = attr_val[4] if eap_code in (1, 2) and len(attr_val) > 4 else None
                if eap_type is not None:
                    info["radius_eap_type"] = EAP_METHODS.get(eap_type, f"eap_{eap_type}")
                    info["radius_eap_type_id"] = eap_type
            offset += attr_len

        info["note"] = "RADIUS uses MD5 shared-secret auth — never PQ-safe"
        info["post_quantum_secure"] = self.check_pq_security(info)
        return info

    # -----------------------------------------------------------------------
    # AMQP (NEW)
    # -----------------------------------------------------------------------

    def analyze_amqp(self, pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None
        tcp = pkt[TCP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        if tcp.dport not in (5671, 5672) and tcp.sport not in (5671, 5672):
            return None

        # TLS on port 5671: delegate to TLS analyzer
        if (tcp.dport == 5671 or tcp.sport == 5671) and (
            pkt.haslayer(TLSClientHello) or pkt.haslayer(TLSServerHello)
        ):
            info = self.analyze_tls_client_hello(pkt) or self.analyze_tls_server_hello(pkt)
            if info:
                info["protocol"] = "AMQP over TLS"
                info["type"] = f"AMQP/TLS {info['type']}"
            return info

        raw = bytes(pkt[Raw].load)
        if len(raw) < 8 or raw[0:4] != b"AMQP":
            return None

        # AMQP protocol header: "AMQP" + id(1) + major(1) + minor(1) + revision(1)
        proto_id = raw[4]
        major = raw[5]
        minor = raw[6]
        revision = raw[7]
        is_tls_port = tcp.dport == 5671 or tcp.sport == 5671
        conn_id = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
        info = {
            "protocol": "AMQP over TLS" if is_tls_port else "AMQP",
            "type": "AMQP Protocol Header",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": tcp.sport,
            "dst_ip": ip.dst, "dst_port": tcp.dport,
            "connection": conn_id,
            "direction": "outbound" if tcp.dport in (5671, 5672) else "inbound",
            "encrypted": is_tls_port,
            "amqp_version": f"{major}.{minor}.{revision}",
        }
        if not is_tls_port:
            info["note"] = "Plaintext AMQP — use port 5671 with TLS"
        info["post_quantum_secure"] = "Unknown" if is_tls_port else "No"
        return info

    # -----------------------------------------------------------------------
    # SIP / SIPS (NEW)
    # -----------------------------------------------------------------------

    def analyze_sip(self, pkt):
        if not pkt.haslayer(Raw):
            return None
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        is_tcp = pkt.haslayer(TCP)
        transport = pkt[TCP] if is_tcp else (pkt[UDP] if pkt.haslayer(UDP) else None)
        if transport is None:
            return None

        SIP_PORTS = (5060, 5061)
        if transport.dport not in SIP_PORTS and transport.sport not in SIP_PORTS:
            return None

        # TLS on 5061: delegate
        if (transport.dport == 5061 or transport.sport == 5061) and (
            pkt.haslayer(TLSClientHello) or pkt.haslayer(TLSServerHello)
        ):
            info = self.analyze_tls_client_hello(pkt) or self.analyze_tls_server_hello(pkt)
            if info:
                info["protocol"] = "SIPS (SIP over TLS)"
                info["type"] = f"SIPS {info['type']}"
            return info

        try:
            text = bytes(pkt[Raw].load).decode("utf-8", errors="ignore")
        except Exception:
            return None

        lines = text.split("\r\n")
        if not lines:
            return None

        first_line = lines[0]
        is_sip = False
        method = None
        status_code = None

        if first_line.endswith("SIP/2.0"):
            is_sip = True
            method = first_line.split()[0]
        elif first_line.startswith("SIP/2.0 "):
            is_sip = True
            parts = first_line.split(None, 2)
            if len(parts) >= 2:
                status_code = parts[1]
        if not is_sip:
            return None

        conn_id = f"{ip.src}:{transport.sport} -> {ip.dst}:{transport.dport}"
        info = {
            "protocol": "SIP",
            "type": f"SIP {method or f'Response {status_code}'}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": transport.sport,
            "dst_ip": ip.dst, "dst_port": transport.dport,
            "connection": conn_id,
            "direction": "outbound" if transport.dport in SIP_PORTS else "inbound",
            "encrypted": False,
            "sip_transport": "TCP" if is_tcp else "UDP",
        }
        if method:
            info["sip_method"] = method
        if status_code:
            info["sip_status"] = status_code

        # Check Via header for transport
        for line in lines[1:]:
            if line.lower().startswith("via:"):
                info["sip_via"] = line[4:].strip()
                break

        info["note"] = "Plaintext SIP — use SIPS (port 5061) for TLS"
        info["post_quantum_secure"] = self.check_pq_security(info)
        return info

    # -----------------------------------------------------------------------
    # ZRTP (NEW)
    # -----------------------------------------------------------------------

    def analyze_zrtp(self, pkt):
        """Detect ZRTP VoIP end-to-end encryption handshake (RFC 6189)."""
        if not pkt.haslayer(UDP) or not pkt.haslayer(Raw):
            return None
        udp = pkt[UDP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        raw = bytes(pkt[Raw].load)
        if len(raw) < 12:
            return None
        # ZRTP: first byte = 0x10, magic cookie "ZRTP" at bytes 4–7
        if raw[0] != 0x10 or (raw[1] & 0x80):
            return None
        if raw[4:8] != b"ZRTP":
            return None

        seq_no = struct.unpack(">H", raw[1:3])[0] & 0x7fff
        ssrc   = struct.unpack(">I", raw[8:12])[0]

        msg_label = "Unknown"
        msg_type_raw = None
        if len(raw) >= 22:
            try:
                mt = raw[14:22].decode("ascii", errors="replace")
                msg_label = ZRTP_MSG_TYPES.get(mt, mt.strip())
                msg_type_raw = mt
            except Exception:
                pass

        conn_id = f"{ip.src}:{udp.sport} -> {ip.dst}:{udp.dport}"
        info = {
            "protocol": "ZRTP",
            "type": f"ZRTP {msg_label}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": udp.sport,
            "dst_ip": ip.dst, "dst_port": udp.dport,
            "connection": conn_id,
            "direction": "outbound",
            "encrypted": True,
            "zrtp_message": msg_label,
            "zrtp_ssrc": f"0x{ssrc:08x}",
            "zrtp_seq": seq_no,
        }

        # Commit message carries key agreement type
        # Body layout (after 22-byte header): H2(32) + ZID(12) + hash(4) + cipher(4) + authTag(4) + keyAgree(4) + sas(4)
        if msg_type_raw and msg_type_raw.startswith("Commit"):
            ka_offset = 22 + 32 + 12 + 4 + 4 + 4
            if len(raw) >= ka_offset + 4:
                try:
                    ka = raw[ka_offset:ka_offset + 4].decode("ascii", errors="ignore")
                    info["zrtp_key_agreement"] = ZRTP_KEY_AGREEMENT.get(ka, f"unknown ({ka})")
                except Exception:
                    pass

        info["note"] = "ZRTP uses DH/ECDH — no PQ key agreement in any deployed implementation"
        info["post_quantum_secure"] = "No"
        return info

    # -----------------------------------------------------------------------
    # BGP / BGP over TLS (NEW)
    # -----------------------------------------------------------------------

    def analyze_bgp(self, pkt):
        """Detect BGP OPEN messages (plain TCP) and BGP over TLS (RFC 9072)."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None
        tcp = pkt[TCP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        if tcp.dport != 179 and tcp.sport != 179:
            return None
        raw = bytes(pkt[Raw].load)
        if not raw:
            return None

        conn_id = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
        direction = "outbound" if tcp.dport == 179 else "inbound"

        # BGP over TLS (RFC 9072): TLS handshake on port 179
        if len(raw) >= 6 and raw[0] == 0x16 and raw[1] == 0x03 and raw[2] in (0x01, 0x02, 0x03, 0x04):
            parsed = _parse_tls_hello_raw(raw)
            if parsed:
                info = {
                    "protocol": "BGP over TLS",
                    "type": f"BGP/TLS {parsed['hs_type']}",
                    "timestamp": datetime.now().isoformat(),
                    "src_ip": ip.src, "src_port": tcp.sport,
                    "dst_ip": ip.dst, "dst_port": tcp.dport,
                    "connection": conn_id,
                    "direction": direction,
                    "encrypted": True,
                    "tls_version": parsed.get("record_version"),
                    "note": "BGP session protected by TLS (RFC 9072)",
                }
                for k in ("client_cipher_suites", "cipher_count", "selected_cipher",
                          "server_name", "supported_versions", "supported_groups",
                          "alpn_protocols", "extensions"):
                    if k in parsed:
                        info[k] = parsed[k]
                info["post_quantum_secure"] = self.check_pq_security(info)
                return info
            return None

        # Plain BGP: 16-byte all-0xff marker
        if len(raw) < 19 or raw[0:16] != b"\xff" * 16:
            return None
        msg_type = raw[18]
        if msg_type not in BGP_MSG_TYPES:
            return None

        info = {
            "protocol": "BGP",
            "type": f"BGP {BGP_MSG_TYPES[msg_type]}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": tcp.sport,
            "dst_ip": ip.dst, "dst_port": tcp.dport,
            "connection": conn_id,
            "direction": direction,
            "encrypted": False,
            "bgp_message": BGP_MSG_TYPES[msg_type],
            "note": "Plaintext BGP — consider RFC 9072 (BGP over TLS)",
        }
        if msg_type == 1 and len(raw) >= 29:  # OPEN
            info["bgp_version"]    = raw[19]
            info["bgp_as"]         = struct.unpack(">H", raw[20:22])[0]
            info["bgp_hold_time"]  = struct.unpack(">H", raw[22:24])[0]
            info["bgp_id"]         = ".".join(str(b) for b in raw[24:28])
        info["post_quantum_secure"] = "No"
        return info

    # -----------------------------------------------------------------------
    # OPC-UA / OPC-UA over TLS (NEW)
    # -----------------------------------------------------------------------

    def analyze_opcua(self, pkt):
        """Detect OPC-UA binary protocol (port 4840) and OPC-UA over TLS (port 4843)."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None
        tcp = pkt[TCP]
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        port = (tcp.dport if tcp.dport in (4840, 4843)
                else tcp.sport if tcp.sport in (4840, 4843)
                else None)
        if port is None:
            return None
        raw = bytes(pkt[Raw].load)
        conn_id = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
        direction = "outbound" if tcp.dport == port else "inbound"

        # OPC-UA over TLS (port 4843)
        if port == 4843:
            if len(raw) >= 6 and raw[0] == 0x16 and raw[1] == 0x03 and raw[2] in (0x01, 0x02, 0x03, 0x04):
                parsed = _parse_tls_hello_raw(raw)
                if parsed:
                    info = {
                        "protocol": "OPC-UA over TLS",
                        "type": f"OPC-UA/TLS {parsed['hs_type']}",
                        "timestamp": datetime.now().isoformat(),
                        "src_ip": ip.src, "src_port": tcp.sport,
                        "dst_ip": ip.dst, "dst_port": tcp.dport,
                        "connection": conn_id,
                        "direction": direction,
                        "encrypted": True,
                        "tls_version": parsed.get("record_version"),
                    }
                    for k in ("client_cipher_suites", "cipher_count", "selected_cipher",
                              "server_name", "supported_versions", "supported_groups",
                              "alpn_protocols", "extensions"):
                        if k in parsed:
                            info[k] = parsed[k]
                    info["post_quantum_secure"] = self.check_pq_security(info)
                    return info
            return None

        # Plain OPC-UA binary (port 4840): 3-byte message type + chunk type
        if len(raw) < 8:
            return None
        msg_key = raw[0:3]
        if msg_key not in OPC_UA_MSG_TYPES:
            return None
        chunk = chr(raw[3])
        if chunk not in ("F", "C", "A"):
            return None

        info = {
            "protocol": "OPC-UA",
            "type": f"OPC-UA {OPC_UA_MSG_TYPES[msg_key]}",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": tcp.sport,
            "dst_ip": ip.dst, "dst_port": tcp.dport,
            "connection": conn_id,
            "direction": direction,
            "encrypted": False,
            "opcua_message": OPC_UA_MSG_TYPES[msg_key],
        }

        # OpenSecureChannel: scan payload for security policy URI
        if msg_key == b"OPN" and len(raw) > 32:
            prefix = b"http://opcfoundation.org/UA/SecurityPolicy#"
            idx = raw.find(prefix)
            if idx != -1:
                end = min(idx + 200, len(raw))
                policy = raw[idx:end].split(b"\x00")[0].decode("utf-8", errors="ignore")
                info["opcua_security_policy"] = policy
                # Security mode is a uint32 encoded as little-endian somewhere nearby
                for offset in range(8, 48):
                    pos = idx + len(policy) + offset
                    if pos + 4 <= len(raw):
                        mode = struct.unpack("<I", raw[pos:pos + 4])[0]
                        if mode in OPC_UA_SECURITY_MODES:
                            info["opcua_security_mode"] = OPC_UA_SECURITY_MODES[mode]
                            if mode == 3:
                                info["encrypted"] = True
                            break

        if not info.get("opcua_security_policy"):
            info["note"] = "Plaintext OPC-UA — use port 4843 with TLS for encryption"
        info["post_quantum_secure"] = "No"
        return info

    # -----------------------------------------------------------------------
    # Heuristic TLS on non-standard ports (NEW — must run last)
    # -----------------------------------------------------------------------

    def analyze_tls_heuristic(self, pkt):
        """Detect TLS ClientHello/ServerHello on non-standard ports by raw header inspection."""
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return None
        tcp = pkt[TCP]
        port = (tcp.dport if tcp.dport in TLS_HEURISTIC_PORTS
                else tcp.sport if tcp.sport in TLS_HEURISTIC_PORTS
                else None)
        if port is None:
            return None
        raw = bytes(pkt[Raw].load)
        parsed = _parse_tls_hello_raw(raw)
        if not parsed:
            return None
        ip = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]
        conn_id = f"{ip.src}:{tcp.sport} -> {ip.dst}:{tcp.dport}"
        info = {
            "protocol": "TLS",
            "type": f"TLS {parsed['hs_type']} (port {port})",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip.src, "src_port": tcp.sport,
            "dst_ip": ip.dst, "dst_port": tcp.dport,
            "connection": conn_id,
            "direction": "outbound" if tcp.dport == port else "inbound",
            "encrypted": True,
            "tls_version": parsed.get("record_version", "Unknown"),
            "heuristic_port": port,
            "note": f"TLS detected on non-standard port {port}",
        }
        for k in ("client_cipher_suites", "cipher_count", "selected_cipher",
                  "server_name", "supported_versions", "supported_groups",
                  "alpn_protocols", "extensions"):
            if k in parsed:
                info[k] = parsed[k]
        if "alpn_protocols" in info and "h2" in info["alpn_protocols"]:
            info["application"] = "gRPC / HTTP2"
        info["post_quantum_secure"] = self.check_pq_security(info)
        return info

    # -----------------------------------------------------------------------
    # Dispatcher
    # -----------------------------------------------------------------------

    def process_packet(self, pkt):
        if not (pkt.haslayer(IP) or pkt.haslayer(IPv6)):
            return

        analyzers = [
            self.analyze_dns_over_tls,
            self.analyze_tls_client_hello,
            self.analyze_tls_server_hello,
            self.analyze_ssh_kexinit,        # before banner — KEX is more informative
            self.analyze_ssh,
            self.analyze_ipsec_ike,
            self.analyze_wireguard,
            self.analyze_dtls,
            self.analyze_quic,
            self.analyze_dnssec,
            self.analyze_starttls,
            self.analyze_smb,
            self.analyze_rdp,
            self.analyze_kerberos,
            self.analyze_snmpv3,
            self.analyze_openvpn,
            self.analyze_radius,
            self.analyze_amqp,
            self.analyze_sip,
            self.analyze_zrtp,
            self.analyze_bgp,
            self.analyze_opcua,
            self.analyze_tls_heuristic,   # must be last — matches non-standard ports
        ]

        info = None
        for analyzer in analyzers:
            try:
                info = analyzer(pkt)
                if info:
                    break
            except Exception:
                pass

        if info:
            if self.encrypted_only and not info.get("encrypted", False):
                return
            self.print_info(info)
            self.log_entries.append(info)
            self.save_log()

    # -----------------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------------

    def print_info(self, info):
        pq = info.get("post_quantum_secure", "Unknown")
        pq_label = {
            "Yes":     "POST-QUANTUM SECURE",
            "Hybrid":  "HYBRID (PQ + Classical)",
            "No":      "CLASSICAL CRYPTO (quantum-vulnerable)",
            "Unknown": "UNKNOWN",
        }.get(pq, "UNKNOWN")

        print("\n" + "=" * 80)
        print(f"[{info['timestamp']}] {info['type']}")
        print(f"Post-Quantum: {pq_label}")
        print("=" * 80)
        print(f"Connection:  {info['connection']}")
        print(f"Direction:   {info['direction']}")
        print(f"Protocol:    {info.get('protocol', 'Unknown')}")

        if "application" in info:
            print(f"Application: {info['application']}")

        if "tls_version" in info:
            version_val = f" ({info['tls_version_value']})" if "tls_version_value" in info else ""
            print(f"TLS Version: {info['tls_version']}{version_val}")

        if "server_name" in info:
            print(f"SNI:         {info['server_name']}")

        if "alpn_protocols" in info:
            print(f"ALPN:        {', '.join(info['alpn_protocols'])}")

        if "client_cipher_suites" in info:
            n = info["cipher_count"]
            print(f"\nClient Offered Ciphers ({n}):")
            for i, c in enumerate(info["client_cipher_suites"][:10], 1):
                print(f"  {i:2}. {c['name']} ({c['value']})")
            if n > 10:
                print(f"      ... and {n - 10} more")

        if "selected_cipher" in info:
            c = info["selected_cipher"]
            print(f"Selected Cipher: {c['name']} ({c['value']})")

        if "supported_versions" in info:
            print(f"TLS Versions: {', '.join(info['supported_versions'])}")

        if "supported_groups" in info:
            print("\nKey Exchange Groups:")
            for g in info["supported_groups"]:
                tag = " [POST-QUANTUM]" if any(pq in g.lower() for pq in ["kyber", "ntru", "mlkem", "frodo"]) else ""
                print(f"  - {g}{tag}")

        if "quic_tls_decrypted" in info:
            print("QUIC: Initial packet decrypted (TLS ClientHello extracted)")

        # SSH
        if "ssh_banner" in info:
            print(f"SSH Banner:  {info['ssh_banner']}")
        if "ssh_kex_algorithms" in info:
            print(f"\nSSH KEX Algorithms ({len(info['ssh_kex_algorithms'])}):")
            for alg in info["ssh_kex_algorithms"][:8]:
                tag = " [PQ]" if alg.lower() in PQ_SAFE_KEX or any(p in alg.lower() for p in PQ_SAFE_KEX) else ""
                print(f"  - {alg}{tag}")
        if "ssh_encryption_c2s" in info:
            print(f"SSH Encryption (C→S): {', '.join(info['ssh_encryption_c2s'][:4])}")

        # IKEv2
        if "ike_proposals" in info:
            print(f"\nIKEv2 Proposals:")
            for p in info["ike_proposals"]:
                names = [t["name"] for t in p["transforms"]]
                print(f"  #{p['proposal_num']} {p['protocol']}: {' | '.join(names)}")

        # WireGuard
        if "message_type" in info and info.get("protocol") == "WireGuard":
            print(f"WG Message:  {info['message_type']} ({info.get('handshake_size', '?')} bytes)")
        if info.get("pq_wireguard_suspected"):
            print("  ** Non-standard size — possible PQ WireGuard variant **")

        # RDP
        if "rdp_requested_protocols" in info:
            print(f"RDP Requested Protocols: {', '.join(info['rdp_requested_protocols'])}")
        if "rdp_selected_protocol" in info:
            print(f"RDP Selected Protocol: {info['rdp_selected_protocol']}")

        # Kerberos
        if "kerberos_message" in info:
            print(f"Kerberos:    {info['kerberos_message']}")
        if "kerberos_etypes" in info:
            print(f"Kerberos Etypes: {', '.join(info['kerberos_etypes'])}")

        # SNMPv3
        if "snmpv3_security_level" in info:
            print(f"SNMPv3 Level: {info['snmpv3_security_level']}")

        # OpenVPN
        if "openvpn_opcode" in info:
            print(f"OpenVPN:     {info['openvpn_opcode']} (key_id={info['openvpn_key_id']})")

        # RADIUS
        if "radius_code" in info:
            print(f"RADIUS:      {info['radius_code']}")
        if "radius_eap_type" in info:
            print(f"EAP Method:  {info['radius_eap_type']}")

        # AMQP
        if "amqp_version" in info:
            print(f"AMQP:        v{info['amqp_version']}")

        # SIP
        if "sip_method" in info:
            print(f"SIP Method:  {info['sip_method']}")
        if "sip_status" in info:
            print(f"SIP Status:  {info['sip_status']}")

        # ZRTP
        if "zrtp_message" in info:
            print(f"ZRTP Msg:    {info['zrtp_message']}  (SSRC={info.get('zrtp_ssrc', '?')})")
        if "zrtp_key_agreement" in info:
            print(f"ZRTP KA:     {info['zrtp_key_agreement']}")

        # BGP
        if "bgp_message" in info:
            print(f"BGP Msg:     {info['bgp_message']}")
        if "bgp_as" in info:
            print(f"BGP AS:      {info['bgp_as']}  (router-id={info.get('bgp_id', '?')})")

        # OPC-UA
        if "opcua_message" in info:
            print(f"OPC-UA Msg:  {info['opcua_message']}")
        if "opcua_security_policy" in info:
            print(f"OPC-UA Policy: {info['opcua_security_policy']}")
        if "opcua_security_mode" in info:
            print(f"OPC-UA Mode: {info['opcua_security_mode']}")

        # Heuristic TLS
        if "heuristic_port" in info:
            print(f"Heuristic:   TLS detected on non-standard port {info['heuristic_port']}")

        # DTLS
        if "dtls_version" in info:
            print(f"DTLS:        {info['dtls_version']}")

        # DNSSEC
        if "dnssec_algorithms" in info:
            print(f"DNSSEC Algs: {', '.join(info['dnssec_algorithms'])}")
        if "query_name" in info and info["query_name"]:
            print(f"Query:       {info['query_name']}")

        if "note" in info:
            print(f"Note:        {info['note']}")

        print("=" * 80)

    def save_log(self):
        try:
            with open(self.log_file, "w") as f:
                json.dump(self.log_entries, f, indent=2)
        except Exception as e:
            print(f"ERROR: Failed to write log: {e}", file=sys.stderr)

    def start_sniffing(self):
        print(f"[*] Starting sniffy crypto sniffer")
        print(f"[*] Interface: {self.interface or 'default'}")
        print(f"[*] Log file:  {self.log_file}")
        print(f"[*] Mode:      {'Encrypted only' if self.encrypted_only else 'All protocols'}")
        print(f"[*] QUIC decryption: {'enabled' if _CRYPTO_AVAILABLE else 'disabled (pip install cryptography)'}")
        print(f"[*] Press Ctrl+C to stop\n")

        filter_parts = [
            "tcp port 443",    # HTTPS/TLS/QUIC
            "tcp port 22",     # SSH
            "tcp port 853",    # DoT
            "tcp port 636",    # LDAPS
            "tcp port 989", "tcp port 990",  # FTPS
            "tcp port 992",    # Telnet/TLS
            "tcp port 993",    # IMAPS
            "tcp port 995",    # POP3S
            "tcp port 8883",   # MQTT/TLS
            "tcp port 5061",   # SIPS
            "tcp port 5060",   # SIP
            "tcp port 445",    # SMB
            "tcp port 3389",   # RDP
            "tcp port 88",     # Kerberos/TCP
            "tcp port 1194",   # OpenVPN/TCP
            "tcp port 5671",   # AMQP/TLS
            "tcp port 5672",   # AMQP plaintext
            "udp port 500",    # IKE
            "udp port 4500",   # IKE NAT-T
            "udp port 443",    # QUIC
            "udp port 51820",  # WireGuard
            "udp port 88",     # Kerberos/UDP
            "udp port 161",    # SNMP
            "udp port 162",    # SNMP trap
            "udp port 1194",   # OpenVPN/UDP
            "udp port 1812",   # RADIUS auth
            "udp port 1813",   # RADIUS accounting
            "udp port 53",     # DNS (for DNSSEC)
            "tcp port 53",     # DNS/TCP (for DNSSEC)
            "tcp port 179",    # BGP / BGP over TLS
            "tcp port 4840",   # OPC-UA binary
            "tcp port 4843",   # OPC-UA over TLS
            # Heuristic TLS ports
            "tcp port 8443", "tcp port 8444", "tcp port 9443",
            "tcp port 4433", "tcp port 4434", "tcp port 4444",
            "tcp port 2376", "tcp port 2377",
            "tcp port 6443",
            "tcp port 10250", "tcp port 10255",
            "tcp port 2379", "tcp port 2380",
            "tcp port 9200", "tcp port 9300",
            "tcp port 27017",
            "tcp port 6380",
            "tcp port 9090", "tcp port 9091", "tcp port 9093", "tcp port 9094",
            "tcp port 8080", "tcp port 8081", "tcp port 8888", "tcp port 8889",
            "tcp port 5000", "tcp port 5001",
            # ZRTP (RTP-based — broad UDP range; capture in ZRTP-likely ranges)
            "udp portrange 5004-5005",   # RTP/RTCP
            "udp portrange 16384-32767", # common RTP ephemeral range
        ]

        if not self.encrypted_only:
            filter_parts += [
                "tcp port 25", "tcp port 587",   # SMTP
                "tcp port 143", "tcp port 110",  # IMAP, POP3
                "tcp port 21",                   # FTP
                "tcp port 389",                  # LDAP
                "tcp port 5432", "tcp port 3306",# PostgreSQL, MySQL
            ]

        bpf = " or ".join(filter_parts)

        try:
            sniff(
                iface=self.interface,
                filter=bpf,
                prn=self.process_packet,
                store=False,
            )
        except KeyboardInterrupt:
            print(f"\n[*] Stopped. Captured {len(self.log_entries)} events.")
            print(f"[*] Log saved to: {self.log_file}")
            if self.log_entries:
                protos = {}
                pq_stats = {"Yes": 0, "Hybrid": 0, "No": 0, "Unknown": 0}
                for e in self.log_entries:
                    p = e.get("protocol", "Unknown")
                    protos[p] = protos.get(p, 0) + 1
                    pq = e.get("post_quantum_secure", "Unknown")
                    pq_stats[pq] = pq_stats.get(pq, 0) + 1
                print("\n[*] Protocol Summary:")
                for p, cnt in sorted(protos.items(), key=lambda x: -x[1]):
                    print(f"    {p}: {cnt}")
                print("\n[*] Post-Quantum Summary:")
                print(f"    PQ Secure: {pq_stats['Yes']}")
                print(f"    Hybrid:    {pq_stats['Hybrid']}")
                print(f"    Classical: {pq_stats['No']}")
                print(f"    Unknown:   {pq_stats['Unknown']}")
        except PermissionError:
            print("ERROR: Requires root.  Run with sudo.", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)


# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="sniffy — Superposition Network Inspector For Funky Yields",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Monitored protocols:
  TLS/HTTPS, QUIC/HTTP3, SSH (banner + KEX Init), IKEv2/IPsec, WireGuard,
  DTLS, DNS-over-TLS, DNSSEC, STARTTLS (SMTP/IMAP/POP3/FTP/LDAP),
  SMB3, RDP/CredSSP, Kerberos, SNMPv3, OpenVPN, RADIUS, AMQP, SIP/SIPS,
  ZRTP, BGP/BGP-over-TLS, OPC-UA/OPC-UA-over-TLS,
  heuristic TLS on 30+ non-standard ports (Kubernetes, Docker, MongoDB, etc.)

Post-quantum indicators:
  Yes     — PQ-safe KEX/signature algorithm confirmed
  Hybrid  — PQ + classical (transition mode)
  No      — classical crypto only (harvest-now-decrypt-later risk)
  Unknown — cannot determine from observable handshake

QUIC Initial packet decryption requires: pip install cryptography
        """,
    )
    parser.add_argument("-a", "--all", action="store_true",
                        help="Include unencrypted protocols")
    parser.add_argument("-i", "--interface", type=str,
                        help="Network interface to capture on")
    parser.add_argument("interface_positional", nargs="?",
                        help="Interface (positional alternative to -i)")
    args = parser.parse_args()

    interface = args.interface or args.interface_positional

    print("""
╔═══════════════════════════════════════════════════════════════════╗
║                            SNIFFY                                 ║
║   Superposition Network Inspector For Funky Yields                ║
╚═══════════════════════════════════════════════════════════════════╝
""")

    sniffer = CryptoSniffer(
        interface=interface,
        log_file="sniffy.json",
        encrypted_only=not args.all,
    )
    sniffer.start_sniffing()


if __name__ == "__main__":
    main()

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


def derive_initial_keys(dcid, version):
    salt = QUIC_INITIAL_SALT_V1 if version == 0x00000001 else QUIC_INITIAL_SALT_V2
    initial_secret = _hmac.new(salt, dcid, hashlib.sha256).digest()
    client_secret = _hkdf_expand_label(initial_secret, b"client in", b"", 32)
    key = _hkdf_expand_label(client_secret, b"quic key", b"", 16)
    iv = _hkdf_expand_label(client_secret, b"quic iv", b"", 12)
    hp = _hkdf_expand_label(client_secret, b"quic hp", b"", 16)
    return key, iv, hp


def remove_header_protection(raw_header, payload, hp_key):
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
    for i in range(pn_len):
        header[len(header) - pn_len + i] ^= mask[1 + i]
    return bytes(header), pn_len


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

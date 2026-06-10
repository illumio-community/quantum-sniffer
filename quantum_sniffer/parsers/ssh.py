"""SSH binary-protocol parsers."""

import struct


def parse_name_list(data, offset):
    """Parse SSH uint32-prefixed comma-separated name-list."""
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


def parse_kexinit(payload):
    """Parse SSH_MSG_KEXINIT message bodies in a TCP payload.

    Walks the SSH binary packet framing looking for msg_type=20. Returns the
    parsed fields dict, or None.
    """
    offset = 0
    while offset + 6 <= len(payload):
        try:
            pkt_len = struct.unpack(">I", payload[offset:offset + 4])[0]
            if pkt_len < 2 or pkt_len > 65536:
                break
            msg_type = payload[offset + 5]
            if msg_type != 20:
                offset += 4 + pkt_len
                continue
            d = offset + 6
            if d + 16 > len(payload):
                break
            d += 16  # skip cookie
            kex_algs, d = parse_name_list(payload, d)
            host_key_algs, d = parse_name_list(payload, d)
            enc_c2s, d = parse_name_list(payload, d)
            enc_s2c, d = parse_name_list(payload, d)
            mac_c2s, d = parse_name_list(payload, d)
            mac_s2c, d = parse_name_list(payload, d)
            return {
                "ssh_kex_algorithms": kex_algs,
                "ssh_host_key_algorithms": host_key_algs,
                "ssh_encryption_c2s": enc_c2s,
                "ssh_encryption_s2c": enc_s2c,
                "ssh_mac_c2s": mac_c2s,
                "ssh_mac_s2c": mac_s2c,
            }
        except (struct.error, IndexError):
            break
    return None

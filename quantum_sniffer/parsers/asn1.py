"""Minimal DER/ASN.1 helpers used by Kerberos and SNMPv3 analyzers."""


def read_tlv(data, offset):
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


def find_kerberos_etypes(data):
    """Scan DER-encoded Kerberos AS-REQ for the etype list ([8] context tag)."""
    i = 0
    while i < len(data) - 4:
        if data[i] == 0xa8:
            j = i + 1
            fb = data[j]; j += 1
            if fb & 0x80:
                n = fb & 0x7f
                j += n
            if j < len(data) and data[j] == 0x30:
                _, seq_val, _ = read_tlv(data, j)
                etypes = []
                k = 0
                while k < len(seq_val):
                    if seq_val[k] != 0x02:
                        break
                    _, int_val, k2 = read_tlv(seq_val, k)
                    k = k2
                    if int_val:
                        raw = int_val
                        val = int.from_bytes(raw, "big")
                        if raw[0] & 0x80:
                            val -= 1 << (8 * len(raw))
                        etypes.append(val)
                if etypes:
                    return etypes
        i += 1
    return []

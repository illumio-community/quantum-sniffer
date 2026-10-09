"""Raw-byte TLS ClientHello/ServerHello parser.

All length fields are bounds-checked before they're used to advance position
or slice the buffer. See ../../add-ons/BUGS_FOUND.md (gitignored) for the
adversarial-input issues this addresses.
"""

import struct

from ..constants import TLS_CIPHER_SUITES, TLS_EXTENSIONS, TLS_NAMED_GROUPS, TLS_VERSIONS


# RFC 8446 §4.1.3: a ServerHello with this random is a HelloRetryRequest.
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def _is_grease(v):
    return (v >> 8) == (v & 0xFF) and (v & 0x0F) == 0x0A


def _group_name(gid):
    if _is_grease(gid):
        return f"GREASE(0x{gid:04x})"
    return TLS_NAMED_GROUPS.get(gid, f"group_0x{gid:04x}")


def parse_extensions(data, pos, end, hs_type=0x01):
    """Parse TLS extensions block. Returns dict with parsed fields.

    ``hs_type`` (1 ClientHello, 2 ServerHello) decides how key_share is read:
    a ClientHello carries a list of shares, a ServerHello exactly one (or, in
    a HelloRetryRequest, just the selected group).
    """
    result = {}
    ext_names = []
    server_name = None
    supported_groups = []
    supported_group_ids = []
    supported_versions = []
    supported_version_ids = []
    alpn_protocols = []
    key_share_group_ids = []
    has_ech = False
    has_session_ticket = False
    has_pre_shared_key = False

    end = min(end, len(data))
    while pos + 4 <= end:
        ext_type = struct.unpack(">H", data[pos:pos + 2])[0]
        ext_dlen = struct.unpack(">H", data[pos + 2:pos + 4])[0]
        if pos + 4 + ext_dlen > end:
            break
        ext_data = data[pos + 4:pos + 4 + ext_dlen]
        ext_names.append(TLS_EXTENSIONS.get(ext_type, f"unknown_{ext_type}"))

        if ext_type == 0 and len(ext_data) >= 5:
            nlen = struct.unpack(">H", ext_data[3:5])[0]
            if 5 + nlen <= len(ext_data):
                server_name = ext_data[5:5 + nlen].decode("utf-8", errors="ignore")

        elif ext_type == 10 and len(ext_data) >= 2:
            gl = struct.unpack(">H", ext_data[0:2])[0]
            if 2 + gl <= len(ext_data):
                for gi in range(2, 2 + gl, 2):
                    if gi + 2 <= len(ext_data):
                        gid = struct.unpack(">H", ext_data[gi:gi + 2])[0]
                        supported_groups.append(_group_name(gid))
                        supported_group_ids.append(gid)

        elif ext_type == 43 and ext_data:
            if ext_data[0] % 2 == 0 and len(ext_data) > 1 and ext_data[0] + 1 <= len(ext_data):
                for vi in range(1, ext_data[0] + 1, 2):
                    if vi + 2 <= len(ext_data):
                        ver = struct.unpack(">H", ext_data[vi:vi + 2])[0]
                        supported_versions.append(TLS_VERSIONS.get(ver, f"0x{ver:04x}"))
                        supported_version_ids.append(ver)
            elif len(ext_data) >= 2:
                ver = struct.unpack(">H", ext_data[0:2])[0]
                supported_versions.append(TLS_VERSIONS.get(ver, f"0x{ver:04x}"))
                supported_version_ids.append(ver)

        elif ext_type == 16 and len(ext_data) >= 2:
            list_len = struct.unpack(">H", ext_data[0:2])[0]
            off = 2
            limit = min(2 + list_len, len(ext_data))
            while off < limit:
                plen = ext_data[off]
                off += 1
                if off + plen > limit:
                    break
                alpn_protocols.append(ext_data[off:off + plen].decode("utf-8", errors="ignore"))
                off += plen

        elif ext_type == 51 and len(ext_data) >= 2:
            if hs_type == 0x01:
                # ClientHello: client_shares_len(2) + {group(2) len(2) key}*
                lim = min(2 + struct.unpack(">H", ext_data[0:2])[0], len(ext_data))
                ko = 2
                while ko + 4 <= lim:
                    gid, klen = struct.unpack(">HH", ext_data[ko:ko + 4])
                    key_share_group_ids.append(gid)
                    ko += 4 + klen
            else:
                # ServerHello: group(2) len(2) key; HelloRetryRequest: group(2).
                # This is the negotiated group.
                gid = struct.unpack(">H", ext_data[0:2])[0]
                supported_groups.append(_group_name(gid))
                supported_group_ids.append(gid)

        elif ext_type == 41:
            has_pre_shared_key = True
        elif ext_type == 35:
            has_session_ticket = True
        elif ext_type == 65037:
            has_ech = True

        pos += 4 + ext_dlen

    result["extensions"] = ext_names
    if server_name:
        result["server_name"] = server_name
    if supported_groups:
        result["supported_groups"] = supported_groups
    if supported_group_ids:
        result["supported_group_ids"] = supported_group_ids
    if supported_versions:
        result["supported_versions"] = supported_versions
        result["supported_version_ids"] = supported_version_ids
    if alpn_protocols:
        result["alpn_protocols"] = alpn_protocols
    if key_share_group_ids:
        result["key_share_group_ids"] = key_share_group_ids
        result["key_share_groups"] = [_group_name(g)
                                      for g in key_share_group_ids]
    if has_ech:
        result["ech"] = True
    if has_session_ticket:
        result["session_resumption"] = "session_ticket"
    if has_pre_shared_key:
        result["session_resumption"] = "pre_shared_key"
    return result


def parse_hello_record(data):
    """Parse a TLS ClientHello/ServerHello starting at the record header (0x16).

    Returns dict of parsed fields, or None if not a recognisable hello.
    Adds ``fragmented=True`` if the record claims more bytes than ``data`` carries.
    """
    if len(data) < 9:
        return None
    if data[0] != 0x16 or data[1] != 0x03 or data[2] not in (0x00, 0x01, 0x02, 0x03, 0x04):
        return None
    record_version = (data[1] << 8) | data[2]
    record_len = struct.unpack(">H", data[3:5])[0]
    fragmented = (5 + record_len) > len(data)

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
    if fragmented:
        result["fragmented"] = True
    result["hello_version_id"] = struct.unpack(">H", body[0:2])[0]
    if hs_type == 0x02 and body[2:34] == HRR_RANDOM:
        result["hello_retry_request"] = True

    pos = 34  # legacy_version (2) + random (32)

    if hs_type == 0x01:
        if pos >= len(body):
            return result
        sid_len = body[pos]
        if pos + 1 + sid_len > len(body):
            return result
        pos += 1 + sid_len

        if pos + 2 > len(body):
            return result
        cs_len = struct.unpack(">H", body[pos:pos + 2])[0]
        pos += 2
        if pos + cs_len > len(body):
            return result
        ciphers = []
        for i in range(0, cs_len, 2):
            if pos + i + 2 <= len(body):
                cs = struct.unpack(">H", body[pos + i:pos + i + 2])[0]
                ciphers.append({"name": TLS_CIPHER_SUITES.get(cs, f"UNKNOWN_0x{cs:04x}"),
                                "value": f"0x{cs:04x}"})
        result["client_cipher_suites"] = ciphers
        result["cipher_count"] = len(ciphers)
        pos += cs_len

        if pos >= len(body):
            return result
        comp_len = body[pos]
        if pos + 1 + comp_len > len(body):
            return result
        pos += 1 + comp_len

        if pos + 2 <= len(body):
            ext_len = struct.unpack(">H", body[pos:pos + 2])[0]
            pos += 2
            if pos + ext_len <= len(body):
                result.update(parse_extensions(body, pos, pos + ext_len, hs_type))

    elif hs_type == 0x02:
        if pos >= len(body):
            return result
        sid_len = body[pos]
        if pos + 1 + sid_len > len(body):
            return result
        pos += 1 + sid_len

        if pos + 3 > len(body):
            return result
        cs = struct.unpack(">H", body[pos:pos + 2])[0]
        result["selected_cipher"] = {"name": TLS_CIPHER_SUITES.get(cs, f"UNKNOWN_0x{cs:04x}"),
                                     "value": f"0x{cs:04x}"}
        pos += 3  # cipher (2) + compression (1)

        if pos + 2 <= len(body):
            ext_len = struct.unpack(">H", body[pos:pos + 2])[0]
            pos += 2
            if pos + ext_len <= len(body):
                result.update(parse_extensions(body, pos, pos + ext_len, hs_type))

    return result


def parse_clienthello_handshake(handshake):
    """Parse a bare TLS handshake message (no record header) starting with msg_type=0x01."""
    if len(handshake) < 4 or handshake[0] != 0x01:
        return None
    body = handshake[4:]
    if len(body) < 34:
        return None
    pos = 34
    result = {"hs_type": "ClientHello",
              "hello_version_id": struct.unpack(">H", body[0:2])[0]}
    if pos >= len(body):
        return result
    sid_len = body[pos]
    if pos + 1 + sid_len > len(body):
        return result
    pos += 1 + sid_len
    if pos + 2 > len(body):
        return result
    cs_len = struct.unpack(">H", body[pos:pos + 2])[0]
    pos += 2
    if pos + cs_len > len(body):
        return result
    ciphers = []
    for i in range(0, cs_len - 1, 2):
        cs = struct.unpack(">H", body[pos + i:pos + i + 2])[0]
        ciphers.append({"name": TLS_CIPHER_SUITES.get(cs, f"UNKNOWN_0x{cs:04x}"),
                        "value": f"0x{cs:04x}"})
    result["client_cipher_suites"] = ciphers
    result["cipher_count"] = len(ciphers)
    pos += cs_len
    if pos >= len(body):
        return result
    comp_len = body[pos]
    if pos + 1 + comp_len > len(body):
        return result
    pos += 1 + comp_len
    if pos + 2 <= len(body):
        ext_len = struct.unpack(">H", body[pos:pos + 2])[0]
        pos += 2
        if pos + ext_len <= len(body):
            result.update(parse_extensions(body, pos, pos + ext_len, 0x01))
    return result

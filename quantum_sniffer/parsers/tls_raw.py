"""Raw-byte TLS ClientHello/ServerHello parser.

All length fields are bounds-checked before they're used to advance position
or slice the buffer. See ../../add-ons/BUGS_FOUND.md (gitignored) for the
adversarial-input issues this addresses.
"""

import struct

from ..constants import TLS_CIPHER_SUITES, TLS_EXTENSIONS, TLS_NAMED_GROUPS, TLS_VERSIONS


def parse_extensions(data, pos, end):
    """Parse TLS extensions block. Returns dict with parsed fields."""
    result = {}
    ext_names = []
    server_name = None
    supported_groups = []
    supported_group_ids = []
    supported_versions = []
    alpn_protocols = []
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
                        supported_groups.append(TLS_NAMED_GROUPS.get(gid, f"group_0x{gid:04x}"))
                        supported_group_ids.append(gid)

        elif ext_type == 43 and ext_data:
            if ext_data[0] % 2 == 0 and len(ext_data) > 1 and ext_data[0] + 1 <= len(ext_data):
                for vi in range(1, ext_data[0] + 1, 2):
                    if vi + 2 <= len(ext_data):
                        ver = struct.unpack(">H", ext_data[vi:vi + 2])[0]
                        supported_versions.append(TLS_VERSIONS.get(ver, f"0x{ver:04x}"))
            elif len(ext_data) >= 2:
                ver = struct.unpack(">H", ext_data[0:2])[0]
                supported_versions.append(TLS_VERSIONS.get(ver, f"0x{ver:04x}"))

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
            # ServerHello key_share is selected_group(2) + key_exchange_len(2) + ...
            gid = struct.unpack(">H", ext_data[0:2])[0]
            # Heuristic: in ClientHello key_share starts with client_shares_len(2),
            # in which case ext_data[0:2] won't be a valid group ID. Only record
            # when it matches a known group.
            if gid in TLS_NAMED_GROUPS or 0x0100 <= gid <= 0x6500:
                if not supported_group_ids:  # don't duplicate if supported_groups already present
                    supported_groups.append(TLS_NAMED_GROUPS.get(gid, f"group_0x{gid:04x}"))
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
    if alpn_protocols:
        result["alpn_protocols"] = alpn_protocols
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
                result.update(parse_extensions(body, pos, pos + ext_len))

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
                result.update(parse_extensions(body, pos, pos + ext_len))

    return result


def parse_clienthello_handshake(handshake):
    """Parse a bare TLS handshake message (no record header) starting with msg_type=0x01."""
    if len(handshake) < 4 or handshake[0] != 0x01:
        return None
    body = handshake[4:]
    if len(body) < 34:
        return None
    pos = 34
    result = {"hs_type": "ClientHello"}
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
            result.update(parse_extensions(body, pos, pos + ext_len))
    return result

"""Layer-7 detection parsers (pure, no scapy, no I/O).

Weak-TLS classification, the DNS "is this really DNS" conformance verdict,
the HTTP request line, SSH version normalisation, the SMB negotiated dialect /
encryption / transport, and the NetBIOS name and datagram services. Detection
only: nothing here blocks or alters traffic.

Every reader is bounds-checked; these run on attacker-influenced wire bytes.
"""

import struct

from ..constants import TLS_VERSIONS


def _be16(b, o):
    return (b[o] << 8) | b[o + 1]


def _be32(b, o):
    return struct.unpack(">I", b[o:o + 4])[0]


def _le16(b, o):
    return b[o] | (b[o + 1] << 8)


# ---------------------------------------------------------------------------
# Weak TLS (offered by the client)
# ---------------------------------------------------------------------------

# Every IANA TLS cipher suite whose encryption is NULL, EXPORT-grade, RC4,
# DES or 3DES, or whose key exchange is anonymous. Generated from the IANA
# "TLS Cipher Suites" registry (tls-parameters-4.csv, 2026-10-09), plus the
# never-registered EXPORT1024 suites old OpenSSL offered (0x0062-0x0065).
# The RFC 9150 integrity-only TLS 1.3 suites (TLS_SHA256_SHA256,
# TLS_SHA384_SHA384) are NULL encryption and listed as such.
# code -> (category, IANA name); findings report the IANA name.
WEAK_CIPHERS = {
    0x0000: ("NULL", "TLS_NULL_WITH_NULL_NULL"),
    0x0001: ("NULL", "TLS_RSA_WITH_NULL_MD5"),
    0x0002: ("NULL", "TLS_RSA_WITH_NULL_SHA"),
    0x0003: ("EXPORT", "TLS_RSA_EXPORT_WITH_RC4_40_MD5"),
    0x0004: ("RC4", "TLS_RSA_WITH_RC4_128_MD5"),
    0x0005: ("RC4", "TLS_RSA_WITH_RC4_128_SHA"),
    0x0006: ("EXPORT", "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5"),
    0x0008: ("EXPORT", "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA"),
    0x0009: ("DES", "TLS_RSA_WITH_DES_CBC_SHA"),
    0x000A: ("3DES", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    0x000B: ("EXPORT", "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA"),
    0x000C: ("DES", "TLS_DH_DSS_WITH_DES_CBC_SHA"),
    0x000D: ("3DES", "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA"),
    0x000E: ("EXPORT", "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA"),
    0x000F: ("DES", "TLS_DH_RSA_WITH_DES_CBC_SHA"),
    0x0010: ("3DES", "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA"),
    0x0011: ("EXPORT", "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA"),
    0x0012: ("DES", "TLS_DHE_DSS_WITH_DES_CBC_SHA"),
    0x0013: ("3DES", "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"),
    0x0014: ("EXPORT", "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA"),
    0x0015: ("DES", "TLS_DHE_RSA_WITH_DES_CBC_SHA"),
    0x0016: ("3DES", "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    0x0017: ("EXPORT", "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5"),
    0x0018: ("RC4", "TLS_DH_anon_WITH_RC4_128_MD5"),
    0x0019: ("EXPORT", "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA"),
    0x001A: ("DES", "TLS_DH_anon_WITH_DES_CBC_SHA"),
    0x001B: ("3DES", "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA"),
    0x001E: ("DES", "TLS_KRB5_WITH_DES_CBC_SHA"),
    0x001F: ("3DES", "TLS_KRB5_WITH_3DES_EDE_CBC_SHA"),
    0x0020: ("RC4", "TLS_KRB5_WITH_RC4_128_SHA"),
    0x0022: ("DES", "TLS_KRB5_WITH_DES_CBC_MD5"),
    0x0023: ("3DES", "TLS_KRB5_WITH_3DES_EDE_CBC_MD5"),
    0x0024: ("RC4", "TLS_KRB5_WITH_RC4_128_MD5"),
    0x0026: ("EXPORT", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA"),
    0x0027: ("EXPORT", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA"),
    0x0028: ("EXPORT", "TLS_KRB5_EXPORT_WITH_RC4_40_SHA"),
    0x0029: ("EXPORT", "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5"),
    0x002A: ("EXPORT", "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5"),
    0x002B: ("EXPORT", "TLS_KRB5_EXPORT_WITH_RC4_40_MD5"),
    0x002C: ("NULL", "TLS_PSK_WITH_NULL_SHA"),
    0x002D: ("NULL", "TLS_DHE_PSK_WITH_NULL_SHA"),
    0x002E: ("NULL", "TLS_RSA_PSK_WITH_NULL_SHA"),
    0x0034: ("anon", "TLS_DH_anon_WITH_AES_128_CBC_SHA"),
    0x003A: ("anon", "TLS_DH_anon_WITH_AES_256_CBC_SHA"),
    0x003B: ("NULL", "TLS_RSA_WITH_NULL_SHA256"),
    0x0046: ("anon", "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA"),
    0x006C: ("anon", "TLS_DH_anon_WITH_AES_128_CBC_SHA256"),
    0x006D: ("anon", "TLS_DH_anon_WITH_AES_256_CBC_SHA256"),
    0x0089: ("anon", "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA"),
    0x008A: ("RC4", "TLS_PSK_WITH_RC4_128_SHA"),
    0x008B: ("3DES", "TLS_PSK_WITH_3DES_EDE_CBC_SHA"),
    0x008E: ("RC4", "TLS_DHE_PSK_WITH_RC4_128_SHA"),
    0x008F: ("3DES", "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA"),
    0x0092: ("RC4", "TLS_RSA_PSK_WITH_RC4_128_SHA"),
    0x0093: ("3DES", "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA"),
    0x009B: ("anon", "TLS_DH_anon_WITH_SEED_CBC_SHA"),
    0x00A6: ("anon", "TLS_DH_anon_WITH_AES_128_GCM_SHA256"),
    0x00A7: ("anon", "TLS_DH_anon_WITH_AES_256_GCM_SHA384"),
    0x00B0: ("NULL", "TLS_PSK_WITH_NULL_SHA256"),
    0x00B1: ("NULL", "TLS_PSK_WITH_NULL_SHA384"),
    0x00B4: ("NULL", "TLS_DHE_PSK_WITH_NULL_SHA256"),
    0x00B5: ("NULL", "TLS_DHE_PSK_WITH_NULL_SHA384"),
    0x00B8: ("NULL", "TLS_RSA_PSK_WITH_NULL_SHA256"),
    0x00B9: ("NULL", "TLS_RSA_PSK_WITH_NULL_SHA384"),
    0x00BF: ("anon", "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256"),
    0x00C5: ("anon", "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256"),
    0xC001: ("NULL", "TLS_ECDH_ECDSA_WITH_NULL_SHA"),
    0xC002: ("RC4", "TLS_ECDH_ECDSA_WITH_RC4_128_SHA"),
    0xC003: ("3DES", "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    0xC006: ("NULL", "TLS_ECDHE_ECDSA_WITH_NULL_SHA"),
    0xC007: ("RC4", "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
    0xC008: ("3DES", "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    0xC00B: ("NULL", "TLS_ECDH_RSA_WITH_NULL_SHA"),
    0xC00C: ("RC4", "TLS_ECDH_RSA_WITH_RC4_128_SHA"),
    0xC00D: ("3DES", "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA"),
    0xC010: ("NULL", "TLS_ECDHE_RSA_WITH_NULL_SHA"),
    0xC011: ("RC4", "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
    0xC012: ("3DES", "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    0xC015: ("NULL", "TLS_ECDH_anon_WITH_NULL_SHA"),
    0xC016: ("RC4", "TLS_ECDH_anon_WITH_RC4_128_SHA"),
    0xC017: ("3DES", "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA"),
    0xC018: ("anon", "TLS_ECDH_anon_WITH_AES_128_CBC_SHA"),
    0xC019: ("anon", "TLS_ECDH_anon_WITH_AES_256_CBC_SHA"),
    0xC01A: ("3DES", "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA"),
    0xC01B: ("3DES", "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA"),
    0xC01C: ("3DES", "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA"),
    0xC033: ("RC4", "TLS_ECDHE_PSK_WITH_RC4_128_SHA"),
    0xC034: ("3DES", "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA"),
    0xC039: ("NULL", "TLS_ECDHE_PSK_WITH_NULL_SHA"),
    0xC03A: ("NULL", "TLS_ECDHE_PSK_WITH_NULL_SHA256"),
    0xC03B: ("NULL", "TLS_ECDHE_PSK_WITH_NULL_SHA384"),
    0xC046: ("anon", "TLS_DH_anon_WITH_ARIA_128_CBC_SHA256"),
    0xC047: ("anon", "TLS_DH_anon_WITH_ARIA_256_CBC_SHA384"),
    0xC05A: ("anon", "TLS_DH_anon_WITH_ARIA_128_GCM_SHA256"),
    0xC05B: ("anon", "TLS_DH_anon_WITH_ARIA_256_GCM_SHA384"),
    0xC084: ("anon", "TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256"),
    0xC085: ("anon", "TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384"),
    0xC0B4: ("NULL", "TLS_SHA256_SHA256"),
    0xC0B5: ("NULL", "TLS_SHA384_SHA384"),
    0x0062: ("EXPORT", "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA"),
    0x0063: ("EXPORT", "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA"),
    0x0064: ("EXPORT", "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA"),
    0x0065: ("EXPORT", "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA"),
}


def is_grease(v):
    """RFC 8701 GREASE code point: both bytes equal, low nibble 0xA."""
    return (v >> 8) == (v & 0xFF) and (v & 0x0F) == 0x0A


def _weak_name(code):
    return WEAK_CIPHERS[code][1]


def classify_weak_tls(cipher_ids, legacy_version=None, supported_version_ids=()):
    """Weak crypto a ClientHello OFFERS (offered, not negotiated).

    The highest offered version comes from supported_versions when present,
    else from legacy_version; GREASE is ignored. Below TLS 1.2 is deprecated.

    Returns a dict with ``tls_deprecated_version`` / ``tls_weak_cipher`` set
    only when True (absent means "not seen", not "clean"), plus
    ``tls_weak_offered`` naming the offenders. Empty dict when nothing found.
    """
    real = [v for v in supported_version_ids if not is_grease(v)]
    highest = max(real) if real else (legacy_version or 0)
    out = {}
    offered = []
    if highest and highest < 0x0303:
        out["tls_deprecated_version"] = True
        offered.append(TLS_VERSIONS.get(highest, f"0x{highest:04x}"))
    for c in cipher_ids:
        if is_grease(c):
            continue
        if c in WEAK_CIPHERS:
            out["tls_weak_cipher"] = True
            name = _weak_name(c)
            if name not in offered:
                offered.append(name)
    if offered:
        out["tls_weak_offered"] = offered
    return out


def classify_weak_negotiated(cipher_id=None, version=None):
    """Same tables, applied to what a ServerHello actually SELECTED."""
    out = {}
    if version and version < 0x0303:
        out["tls_deprecated_version_negotiated"] = True
    if cipher_id is not None and cipher_id in WEAK_CIPHERS:
        out["tls_weak_cipher_negotiated"] = _weak_name(cipher_id)
    return out


# ---------------------------------------------------------------------------
# SSH
# ---------------------------------------------------------------------------

def ssh_version_from_banner(banner):
    """``SSH-<proto>-<software>`` -> "2" / "1.99" / "1" / raw token, or None."""
    if not banner.startswith("SSH-"):
        return None
    parts = banner.split("-", 2)
    if len(parts) < 3:
        return None
    ver = parts[1]
    if ver == "2.0":
        return "2"
    if ver == "1.99":
        return "1.99"
    if ver.startswith("1"):
        return "1"
    return ver


# ---------------------------------------------------------------------------
# HTTP (cleartext request line + Host / User-Agent)
# ---------------------------------------------------------------------------

HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ",
                b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT ")

_HTTP_MAX_HEADER_BYTES = 16384


def _printable(s, limit=512):
    s = "".join(c if 0x20 <= ord(c) < 0x7F else "?" for c in s)
    return s[:limit]


def parse_http_request(data):
    """Parse the start of a cleartext HTTP request.

    Returns dict with http_method / http_path / http_version and, when present,
    http_host / http_user_agent; None if this is not the start of a request.
    Works on a single segment: a request whose headers span segments still
    yields the request line plus whatever headers arrived (``http_headers_partial``).
    """
    if not data.startswith(HTTP_METHODS):
        return None
    data = data[:_HTTP_MAX_HEADER_BYTES]
    text = data.decode("latin-1")
    end = text.find("\r\n\r\n")
    if end < 0:
        end = text.find("\n\n")
    partial = end < 0
    head = text if partial else text[:end]
    lines = head.replace("\r\n", "\n").split("\n")
    req = lines[0].split(" ")
    if len(req) < 3 or not req[2].startswith("HTTP/"):
        return None
    out = {
        "http_method": req[0],
        "http_path": _printable(req[1], 2048),
        "http_version": _printable(req[2], 16),
    }
    for line in lines[1:]:
        key, sep, val = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower()
        if key == "host":
            out["http_host"] = _printable(val.strip(), 255)
        elif key == "user-agent":
            out["http_user_agent"] = _printable(val.strip())
    if partial:
        out["http_headers_partial"] = True
    return out


# ---------------------------------------------------------------------------
# DNS conformance ("is this port actually carrying DNS?") + decode
# ---------------------------------------------------------------------------

DNS_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    28: "AAAA", 33: "SRV", 39: "DNAME", 41: "OPT", 43: "DS", 46: "RRSIG",
    48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 251: "IXFR", 252: "AXFR", 255: "ANY",
}
DNS_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
              4: "NOTIMP", 5: "REFUSED"}
DNS_OPCODES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE",
               6: "DSO"}  # DNS Stateful Operations, RFC 8490

DNS_MAX_RECORDS = 64
_OVERRUN_REASONS = {"name-overrun", "question-overrun", "record-overrun",
                    "rdlength-overrun"}


class _DnsError(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _class_known(cls):
    return cls in (1, 3, 4, 254, 255)


def _read_name(b, off):
    """Read a possibly-compressed name. Returns (lowercased name, next offset).

    Pointers must go strictly backwards and never into the header; a jump
    counter is a second bound against slow cycles.
    """
    total = len(b)
    cursor = off
    resume = None
    jumps = 0
    namelen = 0
    labels = []
    while True:
        if cursor >= total:
            raise _DnsError("name-overrun")
        lab = b[cursor]
        if lab & 0xC0 == 0xC0:
            if cursor + 2 > total:
                raise _DnsError("name-overrun")
            ptr = ((lab & 0x3F) << 8) | b[cursor + 1]
            if resume is None:
                resume = cursor + 2
            if ptr >= cursor or ptr < 12:
                raise _DnsError("bad-pointer")
            jumps += 1
            if jumps > 20:
                raise _DnsError("pointer-loop")
            cursor = ptr
            continue
        if lab & 0xC0:
            raise _DnsError("bad-label")
        if lab == 0:
            cursor += 1
            return ".".join(labels), (resume if resume is not None else cursor)
        cursor += 1
        if cursor + lab > total:
            raise _DnsError("name-overrun")
        namelen += lab + 1
        if namelen > 255:
            raise _DnsError("name-too-long")
        labels.append(b[cursor:cursor + lab].decode("latin-1").lower())
        cursor += lab


def _name_at(b, off):
    try:
        return _read_name(b, off)[0]
    except _DnsError:
        return None


def _render_rdata(rtype, b, off, rdlen):
    rd = b[off:off + rdlen]
    if rtype == 1 and rdlen == 4:
        return ".".join(str(x) for x in rd)
    if rtype == 28 and rdlen == 16:
        import ipaddress
        return str(ipaddress.IPv6Address(bytes(rd)))
    if rtype in (2, 5, 12, 39):
        return _name_at(b, off) or ""
    if rtype == 15 and rdlen >= 3:
        n = _name_at(b, off + 2)
        return f"{_be16(rd, 0)} {n}" if n is not None else ""
    if rtype == 33 and rdlen >= 7:
        n = _name_at(b, off + 6)
        if n is None:
            return ""
        return f"{_be16(rd, 0)} {_be16(rd, 2)} {_be16(rd, 4)} {n}"
    if rtype == 16:
        parts, i = [], 0
        while i < rdlen:
            n = rd[i]
            if i + 1 + n > rdlen:
                break
            parts.append("".join(chr(c) if 0x20 <= c <= 0x7E else "." for c in rd[i + 1:i + 1 + n]))
            i += 1 + n
        return " ".join(parts)
    if rtype in (64, 65) and rdlen >= 3:
        n = _name_at(b, off + 2)
        return f"{_be16(rd, 0)} {n or '.'}" if n is not None else str(_be16(rd, 0))
    s = bytes(rd[:32]).hex()
    return s + ("..." if rdlen > 32 else "")


def dns_header_plausible(b, total_len=None):
    """Cheap verdict from the 12-byte header alone. Returns reason or None."""
    if total_len is None:
        total_len = len(b)
    if len(b) < 12:
        return "short-header"
    flags = _be16(b, 2)
    qr = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0x0F
    tc = bool(flags & 0x0200)
    rcode = flags & 0x0F
    if flags & 0x0040:
        return "reserved-bit-set"
    if opcode not in DNS_OPCODES:
        # What rejects most non-DNS on :53 — SSH banners, HTTP request lines
        # and TLS records all land on an unassigned opcode.
        return "opcode-unassigned"
    qd, an, ns, ar = _be16(b, 4), _be16(b, 6), _be16(b, 8), _be16(b, 10)
    if opcode == 6:
        # DSO (RFC 8490 §5.4): all four counts MUST be zero; TLVs follow.
        return None if qd == an == ns == ar == 0 else "dso-counts"
    if not qr:
        if rcode != 0:
            return "rcode-in-request"
        if opcode == 0 and qd == 0 and ar >= 1:
            pass  # cookie-only query (RFC 7873 §5.4): no question, an OPT
        elif opcode in (0, 4, 5):
            if qd != 1:
                return "question-count"
        elif qd > 1:
            return "question-count"
    if not tc and 12 + qd * 5 + (an + ns + ar) * 11 > total_len:
        return "counts-exceed-length"
    return None


def dns_inspect_message(b):
    """Judge and decode ONE complete DNS message (``b`` is exactly the message).

    Returns dict: dns_conforming (bool), dns_nonconformance (reason, when
    False), and what was decoded: query/qtype/opcode/rcode/flags/records.
    Accepts everything real DNS contains (all assigned opcodes, AXFR/IXFR,
    EDNS OPT, TSIG, TC-truncated replies, empty-question responses); rejects a
    different protocol wearing port 53. NOT tunnel detection — iodine and
    dnscat2 produce conforming DNS by necessity.
    """
    b = bytes(b)
    info = {"dns_conforming": False}
    reason = dns_header_plausible(b)
    if reason:
        info["dns_nonconformance"] = reason
        return info
    flags = _be16(b, 2)
    info["dns_is_response"] = bool(flags & 0x8000)
    info["dns_opcode"] = DNS_OPCODES[(flags >> 11) & 0x0F]
    truncated = bool(flags & 0x0200)
    if truncated:
        info["dns_truncated"] = True
    rcode = flags & 0x0F
    if info["dns_is_response"]:
        info["dns_rcode"] = DNS_RCODES.get(rcode, str(rcode))
    if (flags >> 11) & 0x0F == 6:
        off = 12
        while off + 4 <= len(b):
            off += 4 + _be16(b, off + 2)
        if off != len(b):
            info["dns_nonconformance"] = "dso-tlv-overrun"
            return info
        info["dns_conforming"] = True
        return info
    qd = _be16(b, 4)
    counts = (_be16(b, 6), _be16(b, 8), _be16(b, 10))
    records = []
    off = 12
    try:
        for i in range(qd):
            name, off = _read_name(b, off)
            if off + 4 > len(b):
                raise _DnsError("question-overrun")
            qtype, qclass = _be16(b, off), _be16(b, off + 2)
            off += 4
            if not _class_known(qclass):
                raise _DnsError("bad-class")
            if i == 0:
                info["dns_query"] = name
                info["dns_qtype"] = DNS_TYPES.get(qtype, str(qtype))
        for section, count in zip(("answer", "authority", "additional"), counts):
            for _ in range(count):
                owner, off = _read_name(b, off)
                if off + 10 > len(b):
                    raise _DnsError("record-overrun")
                rtype, cls = _be16(b, off), _be16(b, off + 2)
                ttl, rdlen = _be32(b, off + 4), _be16(b, off + 8)
                off += 10
                if off + rdlen > len(b):
                    raise _DnsError("rdlength-overrun")
                if rtype != 41:  # OPT is EDNS signalling, not a record
                    if not _class_known(cls):
                        raise _DnsError("bad-class")
                    if len(records) < DNS_MAX_RECORDS:
                        records.append({
                            "section": section, "name": owner,
                            "type": DNS_TYPES.get(rtype, str(rtype)),
                            "ttl": ttl, "value": _render_rdata(rtype, b, off, rdlen),
                        })
                    else:
                        info["dns_records_capped"] = True
                off += rdlen
        if off != len(b):
            raise _DnsError("trailing-bytes")
    except _DnsError as e:
        # A TC-truncated reply legitimately stops mid-section.
        if not (truncated and e.reason in _OVERRUN_REASONS):
            info["dns_nonconformance"] = e.reason
            if records:
                info["dns_records"] = records
            return info
    info["dns_conforming"] = True
    if records:
        info["dns_records"] = records
        answers = [r["value"] for r in records
                   if r["section"] == "answer" and r["type"] in ("A", "AAAA", "CNAME") and r["value"]]
        if answers:
            info["dns_answers"] = answers
        res = dns_flatten(info.get("dns_query", ""), records)
        if res:
            info["dns_resolutions"] = res
    return info


def dns_flatten(query, records):
    """Answer-section name -> address edges, CNAME chains followed, min TTL.

    Authority/additional records are excluded (glue is not an answer).
    """
    ans = [r for r in records if r["section"] == "answer"]
    cnames = [(r["name"], r["value"], r["ttl"]) for r in ans
              if r["type"] in ("CNAME", "DNAME") and r["value"]]
    addrs = [r for r in ans if r["type"] in ("A", "AAAA") and r["value"]]
    out = {}

    def emit(name, ip, ttl, via):
        if not name or not ip:
            return
        key = (name, ip)
        if key not in out or ttl < out[key]["ttl"]:
            out[key] = {"name": name, "ip": ip, "ttl": ttl}
            if via:
                out[key]["via"] = via

    for r in addrs:
        emit(r["name"], r["value"], r["ttl"], "")
    seeds = ([query] if query else []) + [c[0] for c in cnames]
    for seed in dict.fromkeys(seeds):
        cur, via, min_ttl, visited = seed, [], 0xFFFFFFFF, {seed}
        for _ in range(16):
            nxt = next((c for c in cnames if c[0] == cur), None)
            if not nxt or nxt[1] in visited:
                break
            min_ttl = min(min_ttl, nxt[2])
            via.append(nxt[1])
            cur = nxt[1]
            visited.add(cur)
            for r in addrs:
                if r["name"] == cur:
                    emit(seed, r["value"], min(min_ttl, r["ttl"]), " -> ".join(via))
    return list(out.values())


DNS_TCP_MAX_CLIENT_MESSAGE = 8192
DNS_TCP_MAX_MESSAGES = 8


def dns_inspect_tcp_segment(b, from_client):
    """Judge the FIRST payload segment of a TCP :53 direction.

    The caller must only pass a segment that starts at a message boundary
    (i.e. the first payload after the handshake) — judging mid-stream bytes
    would condemn healthy resolvers. Returns a merged info dict, or None if the
    segment holds too little to say anything.
    """
    b = bytes(b)
    off, msgs, merged = 0, 0, None
    while msgs < DNS_TCP_MAX_MESSAGES and len(b) - off >= 2:
        declared = _be16(b, off)
        if declared < 12:
            return {"dns_conforming": False, "dns_nonconformance": "short-message"}
        if from_client and declared > DNS_TCP_MAX_CLIENT_MESSAGE:
            return {"dns_conforming": False, "dns_nonconformance": "length-implausible"}
        if len(b) - off >= 14:
            reason = dns_header_plausible(b[off + 2:], declared)
            if reason:
                return {"dns_conforming": False, "dns_nonconformance": reason}
        if len(b) - off < 2 + declared:
            # Header plausible, body continues in later segments.
            if merged is None and len(b) - off >= 14:
                merged = {"dns_conforming": True, "dns_partial": True}
            break
        info = dns_inspect_message(b[off + 2:off + 2 + declared])
        if merged is None or merged.get("dns_partial"):
            merged = info
        elif not info["dns_conforming"]:
            merged["dns_conforming"] = False
            merged["dns_nonconformance"] = info.get("dns_nonconformance")
        off += 2 + declared
        msgs += 1
        if not info["dns_conforming"]:
            break
    return merged


# ---------------------------------------------------------------------------
# SMB (negotiated dialect, encryption, transport)
# ---------------------------------------------------------------------------

SMB_DIALECTS = {0x0202: "2.0.2", 0x0210: "2.1", 0x0300: "3.0",
                0x0302: "3.0.2", 0x0311: "3.1.1"}
_SMB2_HEADER_LEN = 64


def _smb_magic(b, o):
    if o + 4 <= len(b) and b[o + 1:o + 4] == b"SMB" and b[o] in (0xFF, 0xFE, 0xFD):
        return b[o]
    return 0


def smb_inspect_segment(b, from_server):
    """Inspect one TCP segment of an SMB flow (tcp/445 or tcp/139).

    Walks whole NBT-framed messages (4-byte type + 24-bit length). Only the
    server's NEGOTIATE response names the session dialect — a client's request
    lists everything it would accept. Returns a dict of findings or None:
      smb_version    "1" | "2.0.2" | "2.1" | "3.0" | "3.0.2" | "3.1.1"
      smb_encrypted  True when a TRANSFORM_HEADER (0xFD) is seen. Never False:
                     encryption can be proven present, never proven absent.
      smb1_negotiate_response  server answered NEGOTIATE in SMB1 (an upgrade
                     may still follow, so not by itself a version verdict)
    """
    b = bytes(b)
    out = {}
    off = 0
    while off + 4 <= len(b):
        declared = (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]
        body_off = off + 4
        magic = _smb_magic(b, body_off)
        if magic == 0xFD:
            out["smb_encrypted"] = True
            break  # encrypted from here on; nothing more to read
        if not from_server:
            # Client side: only the encrypted case is a finding.
            if not magic:
                break
            off = body_off + declared
            continue
        if off + 4 + declared > len(b):
            break
        m = b[body_off:body_off + declared]
        off = body_off + declared
        if magic == 0xFE:
            if len(m) < _SMB2_HEADER_LEN + 6:
                continue
            if _le16(m, 4) != _SMB2_HEADER_LEN or _le16(m, 12) != 0x0000:
                continue
            flags = struct.unpack("<I", m[16:20])[0]
            if not flags & 0x1:  # SERVER_TO_REDIR: a response
                continue
            if _le16(m, _SMB2_HEADER_LEN) != 65:
                continue
            name = SMB_DIALECTS.get(_le16(m, _SMB2_HEADER_LEN + 4))
            if name:  # 0x02FF ("ask again in SMB2") is not a verdict
                out["smb_version"] = name
        elif magic == 0xFF:
            if len(m) >= 9 and m[4] == 0x72:
                out["smb1_negotiate_response"] = True
                continue
            if len(m) >= 9:
                out["smb_version"] = "1"
        elif not magic:
            break
    return out or None


# ---------------------------------------------------------------------------
# NetBIOS name service (udp/137) and datagram service (udp/138)
# ---------------------------------------------------------------------------

def decode_netbios_name(b, off):
    """First-level decode of one encoded NetBIOS name. Returns
    (name, suffix, next_off) or None."""
    if off >= len(b):
        return None
    if b[off] != 0x20 or off + 33 > len(b):
        return None
    raw = bytearray()
    for i in range(16):
        c1, c2 = b[off + 1 + i * 2], b[off + 2 + i * 2]
        if not (0x41 <= c1 <= 0x50 and 0x41 <= c2 <= 0x50):
            return None
        raw.append(((c1 - 0x41) << 4) | (c2 - 0x41))
    suffix = raw[15]
    name = bytes(raw[:15]).rstrip(b" \x00")
    name = "".join(chr(c) if 0x20 <= c < 0x7F else "?" for c in name)
    off += 33
    while off < len(b):  # scope id
        lab = b[off]
        if lab == 0:
            return name, suffix, off + 1
        if lab & 0xC0 == 0xC0:
            return (name, suffix, off + 2) if off + 2 <= len(b) else None
        if off + 1 + lab > len(b):
            return None
        off += 1 + lab
    return None


def parse_nbns(b):
    """NetBIOS Name Service message. Returns {"netbios_name", "netbios_suffix",
    "nbns_type", "nbns_response"} or None. Never yields an SMB version: modern
    Windows resolves over NBNS while speaking SMB 3.1.1."""
    b = bytes(b)
    if len(b) < 12:
        return None
    if _be16(b, 4) == 0 and _be16(b, 6) == 0:
        return None
    dec = decode_netbios_name(b, 12)
    if not dec:
        return None
    name, suffix, off = dec
    if off + 4 > len(b):
        return None
    qtype, qclass = _be16(b, off), _be16(b, off + 2)
    if qtype not in (0x20, 0x21) or qclass != 1:
        return None
    out = {
        "netbios_suffix": f"0x{suffix:02x}",
        "nbns_type": "NB" if qtype == 0x20 else "NBSTAT",
        "nbns_response": bool(b[2] & 0x80),
    }
    if name:
        out["netbios_name"] = name
    return out


_NBDS_TYPES = {0x10: "DIRECT_UNIQUE", 0x11: "DIRECT_GROUP", 0x12: "BROADCAST",
               0x13: "ERROR", 0x14: "QUERY_REQUEST", 0x15: "POSITIVE_RESPONSE",
               0x16: "NEGATIVE_RESPONSE"}


def parse_nbds(b):
    """NetBIOS Datagram Service message. A first-fragment datagram whose user
    data is an SMB1 message (a browser-protocol mailslot write) is the one
    place SMB1 is PROVEN on the wire: ``smb_version`` "1"."""
    b = bytes(b)
    if len(b) < 11 or b[0] not in _NBDS_TYPES:
        return None
    mtype = b[0]
    out = {"nbds_type": _NBDS_TYPES[mtype]}
    if mtype in (0x10, 0x11, 0x12):
        if len(b) < 14:
            return None
        packet_offset = _be16(b, 12)
        src = decode_netbios_name(b, 14)
        if not src:
            return None
        dst = decode_netbios_name(b, src[2])
        if not dst:
            return None
        if src[0]:
            out["netbios_source_name"] = src[0]
        if dst[0]:
            out["netbios_name"] = dst[0]
        off = dst[2]
        if packet_offset == 0 and b[off:off + 4] == b"\xffSMB":
            out["smb_version"] = "1"
    elif mtype in (0x14, 0x15, 0x16):
        dec = decode_netbios_name(b, 10)
        if not dec:
            return None
        if dec[0]:
            out["netbios_name"] = dec[0]
    return out

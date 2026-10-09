"""Per-protocol analyzers.

Each analyzer takes a scapy packet and returns either an ``info`` dict or
``None``. Analyzers do not mutate global state; the dispatcher in
``sniffer.py`` is responsible for ordering and PQ classification.
"""

import struct
from datetime import datetime

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

from . import pq
from .context import get_ctx
from .wire import payload_after
from .constants import (
    BGP_MSG_TYPES,
    DNSSEC_ALGORITHMS,
    EAP_METHODS,
    IKE_EXCHANGE_TYPES,
    KERBEROS_ETYPES,
    OPC_UA_MSG_TYPES,
    OPC_UA_SECURITY_MODES,
    OPENVPN_OPCODES,
    RADIUS_CODES,
    RDP_PROTOCOLS,
    TLS_VERSIONS,
    TLS_HEURISTIC_PORTS,
    TOR_PORTS,
    ZRTP_KEY_AGREEMENT,
    ZRTP_MSG_TYPES,
)
from .parsers import asn1, ikev2, l7, ssh as ssh_parser, tls_raw

SSH_PORTS = {22, 2222}


def _now():
    return datetime.now().isoformat()


def _ip_layer(pkt):
    return pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]


def _l4_payload(pkt):
    """The complete TCP/UDP payload as bytes.

    Never ``pkt[Raw]``: scapy.all decodes many ports into its own layers
    (RADIUS on 1812, ESP on 4500, ISAKMP on 500, a Kerberos TCP length header
    on 88, SMB, NetBIOS, DNS), leaving either no Raw layer or a Raw holding
    only what follows scapy's header.
    """
    for layer in (TCP, UDP):
        if pkt.haslayer(layer):
            return payload_after(pkt, layer)
    return b""


def _conn_id(ip, transport):
    return f"{ip.src}:{transport.sport} -> {ip.dst}:{transport.dport}"


def _tls_alpn_application(alpn_protocols):
    if "h2" in alpn_protocols or any(p.startswith("grpc") for p in alpn_protocols):
        return "gRPC / HTTP2"
    return None


def _classify(info):
    info["post_quantum_secure"] = pq.classify_connection(info)
    return info


def _hex_ids(suites):
    return [int(c["value"], 16) for c in suites]


def _add_weak_tls_offered(info, cipher_ids, legacy_version, supported_version_ids):
    """Weak-TLS findings for a ClientHello (what the client OFFERED)."""
    info.update(l7.classify_weak_tls(cipher_ids, legacy_version, supported_version_ids))


def _add_smb_over_quic(info):
    """ALPN "smb" on QUIC is SMB over QUIC (Windows Server 2022+)."""
    if "smb" in info.get("alpn_protocols", []):
        info["smb_transport"] = "quic"
        info["application"] = "SMB over QUIC"


_TLS_FIELDS = ("client_cipher_suites", "cipher_count", "selected_cipher",
               "server_name", "supported_versions", "supported_groups",
               "supported_group_ids", "key_share_groups", "key_share_group_ids",
               "alpn_protocols", "extensions", "fragmented", "ech",
               "session_resumption")


# Protocols whose dedicated port carries TLS from the first byte.
_TLS_PORT_PROTOCOLS = {
    853: ("DNS over TLS (DoT)", "DoT"),
    5671: ("AMQP over TLS", "AMQP/TLS"),
    5061: ("SIPS (SIP over TLS)", "SIPS"),
}


def analyze_tls(pkt):
    """TLS ClientHello / ServerHello on any TCP port.

    Reads raw bytes rather than scapy's TLS layer: scapy only decodes TLS on
    port 443, which silently left DoT (853), IMAPS, POP3S, LDAPS, MQTTS, SIPS
    and STARTTLS-upgraded sessions unanalyzed. With reassembly in front, the
    payload is one complete hello even when it spanned several segments.
    """
    if not pkt.haslayer(TCP):
        return None
    payload = _l4_payload(pkt)
    if len(payload) < 9 or payload[0] != 0x16 or payload[1] != 0x03 or payload[5] not in (1, 2):
        return None
    parsed = tls_raw.parse_hello_record(payload)
    if not parsed:
        return None
    tcp = pkt[TCP]
    ip = _ip_layer(pkt)
    client = parsed["hs_type"] == "ClientHello"
    server_port = tcp.dport if client else tcp.sport
    info = {
        "protocol": "TLS",
        "type": f"TLS {parsed['hs_type']}",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": tcp.sport,
        "dst_ip": ip.dst, "dst_port": tcp.dport,
        "connection": (_conn_id(ip, tcp) if client
                       else f"{ip.dst}:{tcp.dport} -> {ip.src}:{tcp.sport}"),
        "direction": "outbound" if client else "inbound",
        "encrypted": True,
    }
    for k in _TLS_FIELDS:
        if k in parsed:
            info[k] = parsed[k]
    hello_version = parsed.get("hello_version_id")
    sv_ids = parsed.get("supported_version_ids", [])
    if client:
        version = hello_version
    else:
        # TLS 1.3 negotiates through supported_versions; legacy_version says 1.2.
        version = sv_ids[0] if sv_ids else hello_version
    if version is not None:
        info["tls_version"] = TLS_VERSIONS.get(version, f"UNKNOWN_0x{version:04x}")
        info["tls_version_value"] = f"0x{version:04x}"
    if parsed.get("hello_retry_request"):
        info["type"] = "TLS HelloRetryRequest"
        info["hello_retry_request"] = True
        info["note"] = ("Server asked the client to retry with a different key share "
                        "(group in supported_groups)")
    if not client and "key_share" in info.get("extensions", []) and "supported_group_ids" not in info:
        info["key_share_parse_failed"] = True
        info["note"] = "TLS key_share extension detected but group parsing failed"
    if "alpn_protocols" in info:
        app = _tls_alpn_application(info["alpn_protocols"])
        if app:
            info["application"] = app
    if client:
        _add_weak_tls_offered(info, _hex_ids(parsed.get("client_cipher_suites", [])),
                              hello_version, sv_ids)
    else:
        sel = parsed.get("selected_cipher")
        info.update(l7.classify_weak_negotiated(
            int(sel["value"], 16) if sel else None, version))

    relabel = _TLS_PORT_PROTOCOLS.get(server_port)
    if relabel:
        info["protocol"] = relabel[0]
        info["type"] = f"{relabel[1]} {info['type']}"
    elif server_port in TLS_HEURISTIC_PORTS or server_port in TOR_PORTS:
        info["type"] += f" (port {server_port})"
        info["heuristic_port"] = server_port
        if server_port in TOR_PORTS:
            info["application"] = "Tor (heuristic)"
            info["note"] = f"TLS detected on Tor port {server_port}"
        else:
            info["note"] = f"TLS detected on non-standard port {server_port}"
    return _classify(info)


def analyze_ssh_kexinit(pkt):
    if not pkt.haslayer(TCP) or not _l4_payload(pkt):
        return None
    tcp = pkt[TCP]
    if tcp.dport not in SSH_PORTS and tcp.sport not in SSH_PORTS:
        return None
    payload = _l4_payload(pkt)
    if payload.startswith(b"SSH-"):
        return None
    parsed = ssh_parser.parse_kexinit(payload)
    if not parsed:
        return None
    ip = _ip_layer(pkt)
    info = {
        "protocol": "SSH",
        "type": "SSH KEX Init",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": tcp.sport,
        "dst_ip": ip.dst, "dst_port": tcp.dport,
        "connection": _conn_id(ip, tcp),
        "direction": "outbound" if tcp.dport in SSH_PORTS else "inbound",
        "encrypted": True,
    }
    info.update(parsed)
    return _classify(info)


def analyze_ssh_banner(pkt):
    if not pkt.haslayer(TCP) or not _l4_payload(pkt):
        return None
    tcp = pkt[TCP]
    if tcp.dport not in SSH_PORTS and tcp.sport not in SSH_PORTS:
        return None
    payload = _l4_payload(pkt)
    if not payload.startswith(b"SSH-"):
        return None
    banner = payload.split(b"\r\n")[0].decode("utf-8", errors="ignore")
    ip = _ip_layer(pkt)
    info = {
        "protocol": "SSH",
        "type": "SSH Banner",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": tcp.sport,
        "dst_ip": ip.dst, "dst_port": tcp.dport,
        "connection": _conn_id(ip, tcp),
        "direction": "outbound" if tcp.dport in SSH_PORTS else "inbound",
        "ssh_banner": banner,
        "encrypted": True,
    }
    parts = banner.split("-")
    if len(parts) >= 3:
        info["ssh_protocol_version"] = parts[1]
        info["ssh_software_version"] = "-".join(parts[2:])
    ssh_version = l7.ssh_version_from_banner(banner)
    if ssh_version:
        info["ssh_version"] = ssh_version
        if ssh_version in ("1", "1.99"):
            info["note"] = f"SSH protocol {ssh_version}: SSH-1 is broken and deprecated"
    info["post_quantum_secure"] = "Unknown"
    return info


def analyze_ipsec_ike(pkt):
    if not pkt.haslayer(UDP) or not _l4_payload(pkt):
        return None
    udp = pkt[UDP]
    ip = _ip_layer(pkt)
    if udp.dport not in (500, 4500) and udp.sport not in (500, 4500):
        return None
    raw = _l4_payload(pkt)
    if udp.dport == 4500 or udp.sport == 4500:
        if len(raw) < 4:
            return None
        if raw[0:4] == b"\x00\x00\x00\x00":
            raw = raw[4:]
        elif raw[0] != 0:
            return None
    if len(raw) < 28:
        return None
    version_byte = raw[17]
    major = (version_byte >> 4) & 0x0f
    if major not in (1, 2):
        return None
    first_payload = raw[16]
    exchange_type = raw[18]
    total_len = struct.unpack(">I", raw[24:28])[0]
    is_initiator = bool(raw[19] & 0x08)
    info = {
        "protocol": "IPsec/IKE",
        "type": f"IKEv{major} {IKE_EXCHANGE_TYPES.get(exchange_type, f'exchange_{exchange_type}')}",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": udp.sport,
        "dst_ip": ip.dst, "dst_port": udp.dport,
        "connection": _conn_id(ip, udp),
        "direction": "outbound" if udp.dport in (500, 4500) else "inbound",
        "encrypted": True,
        "ike_version": f"IKEv{major}",
        "ike_exchange": IKE_EXCHANGE_TYPES.get(exchange_type, f"type_{exchange_type}"),
        "ike_role": "initiator" if is_initiator else "responder",
    }
    payloads = ikev2.parse_payloads(raw, 28, first_payload, total_len)
    if 33 in payloads:
        proposals = ikev2.parse_sa(payloads[33])
        if proposals:
            info["ike_proposals"] = proposals
            dh_groups = [
                t["name"] for p in proposals for t in p["transforms"] if t["type"] == "D-H"
            ]
            if dh_groups:
                info["ike_dh_groups"] = dh_groups
    return _classify(info)


def analyze_wireguard(pkt):
    if not pkt.haslayer(UDP) or not _l4_payload(pkt):
        return None
    udp = pkt[UDP]
    ip = _ip_layer(pkt)
    raw = _l4_payload(pkt)
    if len(raw) < 4:
        return None
    msg_type = raw[0]
    if msg_type not in (1, 2, 3, 4):
        return None
    # The type is a little-endian u32: three zero reserved bytes follow it.
    # Without this check every DHCP request (01 01 06 00) and RADIUS
    # Access-Request (code 1) matched, and oversized ones were labelled
    # "possible PQ WireGuard" -> Hybrid.
    if raw[1:4] != b"\x00\x00\x00":
        return None
    if msg_type == 4 and (len(raw) < 32 or (len(raw) - 16) % 16):
        return None
    expected = {1: 148, 2: 92, 3: 64}.get(msg_type)
    pq_suspected = False
    if msg_type in (1, 2, 3):
        if expected and len(raw) != expected:
            if len(raw) > expected:
                pq_suspected = True
            else:
                return None
    msg_labels = {1: "Handshake Initiation", 2: "Handshake Response",
                  3: "Cookie Reply", 4: "Transport Data"}
    info = {
        "protocol": "WireGuard",
        "type": f"WireGuard {msg_labels.get(msg_type, 'Unknown')}",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": udp.sport,
        "dst_ip": ip.dst, "dst_port": udp.dport,
        "connection": _conn_id(ip, udp),
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
    return _classify(info)


def analyze_dtls(pkt):
    if not pkt.haslayer(UDP) or not _l4_payload(pkt):
        return None
    udp = pkt[UDP]
    ip = _ip_layer(pkt)
    raw = _l4_payload(pkt)
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
    info = {
        "protocol": "DTLS",
        "type": f"DTLS {content_labels.get(content_type, 'Unknown')}",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": udp.sport,
        "dst_ip": ip.dst, "dst_port": udp.dport,
        "connection": _conn_id(ip, udp),
        "direction": "outbound",
        "encrypted": True,
        "dtls_version": dtls_versions[version],
        "content_type": content_labels.get(content_type, f"type_{content_type}"),
    }
    info["post_quantum_secure"] = "No"
    return info


def _wrap_handshake(msg):
    """Bare TLS handshake message -> a TLS record, for parse_hello_record."""
    return b"\x16\x03\x03" + struct.pack(">H", len(msg)) + msg


def analyze_quic(pkt):
    """QUIC Initial packets: reassemble and parse the ClientHello (SNI, offered
    groups) and the ServerHello (the group actually negotiated)."""
    if not pkt.haslayer(UDP):
        return None
    udp = pkt[UDP]
    if udp.dport != 443 and udp.sport != 443:
        return None
    raw = _l4_payload(pkt)
    if len(raw) < 7 or not (raw[0] & 0x80) or not (raw[0] & 0x40):
        return None
    from_client = udp.dport == 443
    ip = _ip_layer(pkt)
    if from_client:
        key = (ip.src, udp.sport, ip.dst, udp.dport)
    else:
        key = (ip.dst, udp.dport, ip.src, udp.sport)
    results = get_ctx(pkt).quic.handle(raw, key, from_client)
    events = [_quic_event(res, ip, udp, key, from_client) for res in results]
    if not events:
        return None
    return events[0] if len(events) == 1 else events


def _quic_event(res, ip, udp, key, from_client):
    info = {
        "protocol": "QUIC",
        "type": "QUIC Initial",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": udp.sport,
        "dst_ip": ip.dst, "dst_port": udp.dport,
        "connection": f"{key[0]}:{key[1]} -> {key[2]}:{key[3]}",
        "direction": "outbound" if from_client else "inbound",
        "encrypted": True,
        "quic_version": f"0x{res['version']:08x}",
        "quic_dcid": res["odcid"],
        "note": "QUIC carries TLS 1.3 internally",
    }
    if res["kind"] == "initial":
        info["quic_decrypt_error"] = res["error"]
        return _classify(info)
    parsed = tls_raw.parse_hello_record(_wrap_handshake(res["handshake"])) or {}
    info["quic_tls_decrypted"] = True
    if res["kind"] == "client_hello":
        info["type"] = "QUIC ClientHello"
        for field in ("supported_groups", "supported_group_ids", "alpn_protocols",
                      "server_name", "extensions", "supported_versions", "ech",
                      "session_resumption", "client_cipher_suites", "cipher_count",
                      "key_share_groups", "key_share_group_ids"):
            if field in parsed:
                info[field] = parsed[field]
        _add_weak_tls_offered(info, _hex_ids(parsed.get("client_cipher_suites", [])),
                              parsed.get("hello_version_id"),
                              parsed.get("supported_version_ids", []))
        _add_smb_over_quic(info)
    else:
        info["type"] = "QUIC ServerHello"
        if parsed.get("hello_retry_request"):
            info["type"] = "QUIC HelloRetryRequest"
            info["hello_retry_request"] = True
        for field in ("selected_cipher", "supported_groups", "supported_group_ids",
                      "extensions", "supported_versions"):
            if field in parsed:
                info[field] = parsed[field]
        sel = parsed.get("selected_cipher")
        info.update(l7.classify_weak_negotiated(int(sel["value"], 16) if sel else None, None))
    return _classify(info)


def analyze_dnssec(pkt):
    if not pkt.haslayer(DNS):
        return None
    ip = _ip_layer(pkt)
    transport = pkt[TCP] if pkt.haslayer(TCP) else pkt[UDP]
    dns = pkt[DNS]
    if dns.qr != 1:
        return None
    rrsig_algs, dnskey_algs, ds_algs = [], [], []
    ancount, nscount, arcount = dns.ancount or 0, dns.nscount or 0, dns.arcount or 0
    for i in range(ancount + nscount + arcount):
        try:
            if i < ancount:
                rr = dns.an[i]
            elif i < ancount + nscount:
                rr = dns.ns[i - ancount]
            else:
                rr = dns.ar[i - ancount - nscount]
            rtype = getattr(rr, "type", 0)
            alg = getattr(rr, "algorithm", None)
            if alg is None:
                continue
            if rtype == 46 and alg not in rrsig_algs:
                rrsig_algs.append(alg)
            elif rtype == 48 and alg not in dnskey_algs:
                dnskey_algs.append(alg)
            elif rtype == 43 and alg not in ds_algs:
                ds_algs.append(alg)
        except (IndexError, AttributeError):
            continue
    if not rrsig_algs and not dnskey_algs and not ds_algs:
        return None
    all_algs = list(set(rrsig_algs + dnskey_algs + ds_algs))
    sport = getattr(transport, "sport", 0)
    dport = getattr(transport, "dport", 0)
    qname = dns.qd.qname.decode("utf-8", errors="ignore") if dns.qdcount > 0 else ""
    info = {
        "protocol": "DNSSEC",
        "type": "DNSSEC Response",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": sport,
        "dst_ip": ip.dst, "dst_port": dport,
        "connection": f"{ip.src}:{sport} -> {ip.dst}:{dport}",
        "direction": "inbound",
        "encrypted": False,
        "query_name": qname,
        "dnssec_algorithms": [DNSSEC_ALGORITHMS.get(a, f"alg_{a}") for a in all_algs],
        "dnssec_algorithm_ids": all_algs,
    }
    return _classify(info)


_STARTTLS_PORTS = {
    25: "SMTP", 587: "SMTP Submission", 143: "IMAP", 110: "POP3",
    21: "FTP", 389: "LDAP", 5222: "XMPP", 5432: "PostgreSQL", 3306: "MySQL",
}


def analyze_starttls(pkt):
    if not pkt.haslayer(TCP) or not _l4_payload(pkt):
        return None
    tcp = pkt[TCP]
    if tcp.dport not in _STARTTLS_PORTS and tcp.sport not in _STARTTLS_PORTS:
        return None
    try:
        text = _l4_payload(pkt).decode("utf-8", errors="ignore").upper()
    except Exception:
        return None
    if "STARTTLS" not in text:
        return None
    proto = _STARTTLS_PORTS.get(tcp.dport) or _STARTTLS_PORTS.get(tcp.sport, "Unknown")
    ip = _ip_layer(pkt)
    info = {
        "protocol": f"{proto} STARTTLS",
        "type": f"{proto} STARTTLS Upgrade",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": tcp.sport,
        "dst_ip": ip.dst, "dst_port": tcp.dport,
        "connection": _conn_id(ip, tcp),
        "direction": "outbound",
        "encrypted": True,
        "note": "Protocol upgrading to TLS",
    }
    info["post_quantum_secure"] = "Unknown"
    return info


def analyze_rdp(pkt):
    if not pkt.haslayer(TCP) or not _l4_payload(pkt):
        return None
    tcp = pkt[TCP]
    if tcp.dport != 3389 and tcp.sport != 3389:
        return None
    raw = _l4_payload(pkt)
    if len(raw) < 11:
        return None
    if raw[0] != 3 or raw[1] != 0:
        return None
    tpkt_len = struct.unpack(">H", raw[2:4])[0]
    if tpkt_len < 11 or tpkt_len > len(raw) + 4:
        return None
    x224_code = raw[5]
    if x224_code not in (0xe0, 0xd0):
        return None
    msg_type = "RDP Connection Request" if x224_code == 0xe0 else "RDP Connection Confirm"
    ip = _ip_layer(pkt)
    info = {
        "protocol": "RDP",
        "type": msg_type,
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": tcp.sport,
        "dst_ip": ip.dst, "dst_port": tcp.dport,
        "connection": _conn_id(ip, tcp),
        "direction": "outbound" if tcp.dport == 3389 else "inbound",
        "encrypted": True,
    }
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
    return _classify(info)


def analyze_kerberos(pkt):
    if not (pkt.haslayer(TCP) or pkt.haslayer(UDP)) or not _l4_payload(pkt):
        return None
    ip = _ip_layer(pkt)
    is_tcp = pkt.haslayer(TCP)
    transport = pkt[TCP] if is_tcp else pkt[UDP]
    if transport.dport != 88 and transport.sport != 88:
        return None
    raw = _l4_payload(pkt)
    data = raw[4:] if is_tcp and len(raw) > 4 else raw
    if len(data) < 2:
        return None
    tag = data[0]
    msg_types = {
        0x6a: "AS-REQ", 0x6b: "AS-REP",
        0x6c: "TGS-REQ", 0x6d: "TGS-REP",
        0x6e: "AP-REQ", 0x6f: "AP-REP",
        0x7e: "KRB-ERROR",
    }
    if tag not in msg_types:
        return None
    info = {
        "protocol": "Kerberos",
        "type": f"Kerberos {msg_types[tag]}",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": transport.sport,
        "dst_ip": ip.dst, "dst_port": transport.dport,
        "connection": _conn_id(ip, transport),
        "direction": "outbound" if transport.dport == 88 else "inbound",
        "encrypted": False,
        "kerberos_message": msg_types[tag],
    }
    if tag in (0x6a, 0x6c):
        etypes = asn1.find_kerberos_etypes(data)
        if etypes:
            info["kerberos_etypes"] = [KERBEROS_ETYPES.get(e, f"etype_{e}") for e in etypes]
            info["kerberos_etype_ids"] = etypes
    return _classify(info)


def analyze_snmpv3(pkt):
    if not pkt.haslayer(UDP) or not _l4_payload(pkt):
        return None
    udp = pkt[UDP]
    ip = _ip_layer(pkt)
    if udp.dport not in (161, 162) and udp.sport not in (161, 162):
        return None
    raw = _l4_payload(pkt)
    if len(raw) < 7 or raw[0] != 0x30:
        return None
    tag, seq_val, _ = asn1.read_tlv(raw, 0)
    if tag != 0x30 or not seq_val:
        return None
    ver_tag, ver_val, rest_offset = asn1.read_tlv(seq_val, 0)
    if ver_tag != 0x02 or not ver_val:
        return None
    if int.from_bytes(ver_val, "big") != 3:
        return None
    info = {
        "protocol": "SNMPv3",
        "type": "SNMPv3 Message",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": udp.sport,
        "dst_ip": ip.dst, "dst_port": udp.dport,
        "connection": _conn_id(ip, udp),
        "direction": "outbound" if udp.dport == 161 else "inbound",
        "encrypted": False,
    }
    gd_tag, gd_val, _ = asn1.read_tlv(seq_val, rest_offset)
    if gd_tag == 0x30 and gd_val:
        o = 0
        for _ in range(3):
            _, _, o = asn1.read_tlv(gd_val, o)
            if o is None:
                break
        flag_tag, flag_val, _ = asn1.read_tlv(gd_val, o or 0)
        if flag_tag == 0x04 and flag_val:
            flags = flag_val[0]
            auth = bool(flags & 0x01)
            priv = bool(flags & 0x02)
            info["snmpv3_auth"] = auth
            info["snmpv3_priv"] = priv
            if priv:
                info["encrypted"] = True
            info["snmpv3_security_level"] = (
                "authPriv" if auth and priv
                else "authNoPriv" if auth
                else "noAuthNoPriv"
            )
    return _classify(info)


def analyze_openvpn(pkt):
    if not (pkt.haslayer(UDP) or pkt.haslayer(TCP)) or not _l4_payload(pkt):
        return None
    ip = _ip_layer(pkt)
    is_tcp = pkt.haslayer(TCP)
    transport = pkt[TCP] if is_tcp else pkt[UDP]
    if transport.dport != 1194 and transport.sport != 1194:
        return None
    raw = _l4_payload(pkt)
    if is_tcp:
        if len(raw) < 3:
            return None
        raw = raw[2:]
    if len(raw) < 2:
        return None
    opcode = (raw[0] >> 3) & 0x1f
    key_id = raw[0] & 0x07
    if opcode not in OPENVPN_OPCODES or opcode in (6, 9):
        return None
    info = {
        "protocol": "OpenVPN",
        "type": f"OpenVPN {OPENVPN_OPCODES[opcode]}",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": transport.sport,
        "dst_ip": ip.dst, "dst_port": transport.dport,
        "connection": _conn_id(ip, transport),
        "direction": "outbound" if transport.dport == 1194 else "inbound",
        "encrypted": True,
        "openvpn_opcode": OPENVPN_OPCODES[opcode],
        "openvpn_key_id": key_id,
        "note": "PQ status depends on TLS cipher negotiated in control channel",
    }
    info["post_quantum_secure"] = "Unknown"
    return info


def analyze_radius(pkt):
    if not pkt.haslayer(UDP) or not _l4_payload(pkt):
        return None
    udp = pkt[UDP]
    ip = _ip_layer(pkt)
    if udp.dport not in (1812, 1813) and udp.sport not in (1812, 1813):
        return None
    raw = _l4_payload(pkt)
    if len(raw) < 20:
        return None
    code = raw[0]
    if code not in RADIUS_CODES:
        return None
    radius_len = struct.unpack(">H", raw[2:4])[0]
    if radius_len < 20 or radius_len > len(raw):
        return None
    info = {
        "protocol": "RADIUS",
        "type": f"RADIUS {RADIUS_CODES.get(code, f'code_{code}')}",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": udp.sport,
        "dst_ip": ip.dst, "dst_port": udp.dport,
        "connection": _conn_id(ip, udp),
        "direction": "outbound" if udp.dport in (1812, 1813) else "inbound",
        "encrypted": False,
        "radius_code": RADIUS_CODES.get(code, f"code_{code}"),
    }
    offset = 20
    while offset + 2 <= radius_len and offset + 2 <= len(raw):
        attr_type = raw[offset]
        attr_len = raw[offset + 1]
        if attr_len < 2 or offset + attr_len > len(raw):
            break
        attr_val = raw[offset + 2:offset + attr_len]
        if attr_type == 79 and len(attr_val) >= 4:
            eap_code = attr_val[0]
            eap_type = attr_val[4] if eap_code in (1, 2) and len(attr_val) > 4 else None
            if eap_type is not None:
                info["radius_eap_type"] = EAP_METHODS.get(eap_type, f"eap_{eap_type}")
                info["radius_eap_type_id"] = eap_type
        offset += attr_len
    info["note"] = "RADIUS uses MD5 shared-secret auth — never PQ-safe"
    return _classify(info)


def analyze_amqp(pkt):
    if not pkt.haslayer(TCP) or not _l4_payload(pkt):
        return None
    tcp = pkt[TCP]
    if tcp.dport not in (5671, 5672) and tcp.sport not in (5671, 5672):
        return None
    raw = _l4_payload(pkt)
    if len(raw) < 8 or raw[0:4] != b"AMQP":
        return None
    major, minor, revision = raw[5], raw[6], raw[7]
    is_tls_port = tcp.dport == 5671 or tcp.sport == 5671
    ip = _ip_layer(pkt)
    info = {
        "protocol": "AMQP over TLS" if is_tls_port else "AMQP",
        "type": "AMQP Protocol Header",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": tcp.sport,
        "dst_ip": ip.dst, "dst_port": tcp.dport,
        "connection": _conn_id(ip, tcp),
        "direction": "outbound" if tcp.dport in (5671, 5672) else "inbound",
        "encrypted": is_tls_port,
        "amqp_version": f"{major}.{minor}.{revision}",
    }
    if not is_tls_port:
        info["note"] = "Plaintext AMQP — use port 5671 with TLS"
    info["post_quantum_secure"] = "Unknown" if is_tls_port else "No"
    return info


def analyze_sip(pkt):
    if not _l4_payload(pkt):
        return None
    ip = _ip_layer(pkt)
    is_tcp = pkt.haslayer(TCP)
    transport = pkt[TCP] if is_tcp else (pkt[UDP] if pkt.haslayer(UDP) else None)
    if transport is None:
        return None
    SIP_PORTS = (5060, 5061)
    if transport.dport not in SIP_PORTS and transport.sport not in SIP_PORTS:
        return None
    try:
        text = _l4_payload(pkt).decode("utf-8", errors="ignore")
    except Exception:
        return None
    lines = text.split("\r\n")
    if not lines:
        return None
    first_line = lines[0]
    method = None
    status_code = None
    if first_line.endswith("SIP/2.0"):
        method = first_line.split()[0]
    elif first_line.startswith("SIP/2.0 "):
        parts = first_line.split(None, 2)
        if len(parts) >= 2:
            status_code = parts[1]
    else:
        return None
    info = {
        "protocol": "SIP",
        "type": f"SIP {method or f'Response {status_code}'}",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": transport.sport,
        "dst_ip": ip.dst, "dst_port": transport.dport,
        "connection": _conn_id(ip, transport),
        "direction": "outbound" if transport.dport in SIP_PORTS else "inbound",
        "encrypted": False,
        "sip_transport": "TCP" if is_tcp else "UDP",
    }
    if method:
        info["sip_method"] = method
    if status_code:
        info["sip_status"] = status_code
    for line in lines[1:]:
        if line.lower().startswith("via:"):
            info["sip_via"] = line[4:].strip()
            break
    info["note"] = "Plaintext SIP — use SIPS (port 5061) for TLS"
    return _classify(info)


def analyze_zrtp(pkt):
    if not pkt.haslayer(UDP) or not _l4_payload(pkt):
        return None
    udp = pkt[UDP]
    ip = _ip_layer(pkt)
    raw = _l4_payload(pkt)
    if len(raw) < 12:
        return None
    if raw[0] != 0x10 or (raw[1] & 0x80):
        return None
    if raw[4:8] != b"ZRTP":
        return None
    seq_no = struct.unpack(">H", raw[1:3])[0] & 0x7fff
    ssrc = struct.unpack(">I", raw[8:12])[0]
    msg_label = "Unknown"
    msg_type_raw = None
    if len(raw) >= 22:
        try:
            mt = raw[14:22].decode("ascii", errors="replace")
            msg_label = ZRTP_MSG_TYPES.get(mt, mt.strip())
            msg_type_raw = mt
        except Exception:
            pass
    info = {
        "protocol": "ZRTP",
        "type": f"ZRTP {msg_label}",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": udp.sport,
        "dst_ip": ip.dst, "dst_port": udp.dport,
        "connection": _conn_id(ip, udp),
        "direction": "outbound",
        "encrypted": True,
        "zrtp_message": msg_label,
        "zrtp_ssrc": f"0x{ssrc:08x}",
        "zrtp_seq": seq_no,
    }
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


def analyze_bgp(pkt):
    if not pkt.haslayer(TCP) or not _l4_payload(pkt):
        return None
    tcp = pkt[TCP]
    ip = _ip_layer(pkt)
    if tcp.dport != 179 and tcp.sport != 179:
        return None
    raw = _l4_payload(pkt)
    if not raw:
        return None
    direction = "outbound" if tcp.dport == 179 else "inbound"
    if len(raw) >= 6 and raw[0] == 0x16 and raw[1] == 0x03 and raw[2] in (0x01, 0x02, 0x03, 0x04):
        parsed = tls_raw.parse_hello_record(raw)
        if parsed:
            info = {
                "protocol": "BGP over TLS",
                "type": f"BGP/TLS {parsed['hs_type']}",
                "timestamp": _now(),
                "src_ip": ip.src, "src_port": tcp.sport,
                "dst_ip": ip.dst, "dst_port": tcp.dport,
                "connection": _conn_id(ip, tcp),
                "direction": direction,
                "encrypted": True,
                "tls_version": parsed.get("record_version"),
                "note": "BGP session protected by TLS (RFC 9072)",
            }
            for k in ("client_cipher_suites", "cipher_count", "selected_cipher",
                      "server_name", "supported_versions", "supported_groups",
                      "supported_group_ids", "alpn_protocols", "extensions",
                      "fragmented", "ech", "session_resumption"):
                if k in parsed:
                    info[k] = parsed[k]
            return _classify(info)
        return None
    if len(raw) < 19 or raw[0:16] != b"\xff" * 16:
        return None
    msg_type = raw[18]
    if msg_type not in BGP_MSG_TYPES:
        return None
    info = {
        "protocol": "BGP",
        "type": f"BGP {BGP_MSG_TYPES[msg_type]}",
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": tcp.sport,
        "dst_ip": ip.dst, "dst_port": tcp.dport,
        "connection": _conn_id(ip, tcp),
        "direction": direction,
        "encrypted": False,
        "bgp_message": BGP_MSG_TYPES[msg_type],
        "note": "Plaintext BGP — consider RFC 9072 (BGP over TLS)",
    }
    if msg_type == 1 and len(raw) >= 29:
        info["bgp_version"] = raw[19]
        info["bgp_as"] = struct.unpack(">H", raw[20:22])[0]
        info["bgp_hold_time"] = struct.unpack(">H", raw[22:24])[0]
        info["bgp_id"] = ".".join(str(b) for b in raw[24:28])
    info["post_quantum_secure"] = "No"
    return info


def analyze_opcua(pkt):
    if not pkt.haslayer(TCP) or not _l4_payload(pkt):
        return None
    tcp = pkt[TCP]
    ip = _ip_layer(pkt)
    port = (tcp.dport if tcp.dport in (4840, 4843)
            else tcp.sport if tcp.sport in (4840, 4843)
            else None)
    if port is None:
        return None
    raw = _l4_payload(pkt)
    direction = "outbound" if tcp.dport == port else "inbound"
    if port == 4843:
        if len(raw) >= 6 and raw[0] == 0x16 and raw[1] == 0x03 and raw[2] in (0x01, 0x02, 0x03, 0x04):
            parsed = tls_raw.parse_hello_record(raw)
            if parsed:
                info = {
                    "protocol": "OPC-UA over TLS",
                    "type": f"OPC-UA/TLS {parsed['hs_type']}",
                    "timestamp": _now(),
                    "src_ip": ip.src, "src_port": tcp.sport,
                    "dst_ip": ip.dst, "dst_port": tcp.dport,
                    "connection": _conn_id(ip, tcp),
                    "direction": direction,
                    "encrypted": True,
                    "tls_version": parsed.get("record_version"),
                }
                for k in ("client_cipher_suites", "cipher_count", "selected_cipher",
                          "server_name", "supported_versions", "supported_groups",
                          "supported_group_ids", "alpn_protocols", "extensions",
                          "fragmented", "ech", "session_resumption"):
                    if k in parsed:
                        info[k] = parsed[k]
                return _classify(info)
        return None
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
        "timestamp": _now(),
        "src_ip": ip.src, "src_port": tcp.sport,
        "dst_ip": ip.dst, "dst_port": tcp.dport,
        "connection": _conn_id(ip, tcp),
        "direction": direction,
        "encrypted": False,
        "opcua_message": OPC_UA_MSG_TYPES[msg_key],
    }
    if msg_key == b"OPN" and len(raw) > 32:
        prefix = b"http://opcfoundation.org/UA/SecurityPolicy#"
        idx = raw.find(prefix)
        if idx != -1:
            end = min(idx + 200, len(raw))
            policy = raw[idx:end].split(b"\x00")[0].decode("utf-8", errors="ignore")
            info["opcua_security_policy"] = policy
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


ANALYZERS = [
    analyze_tls,
    analyze_ssh_kexinit,
    analyze_ssh_banner,
    analyze_ipsec_ike,
    analyze_wireguard,
    analyze_dtls,
    analyze_quic,
    analyze_dnssec,
    analyze_starttls,
    analyze_rdp,
    analyze_kerberos,
    analyze_snmpv3,
    analyze_openvpn,
    analyze_radius,
    analyze_amqp,
    analyze_sip,
    analyze_zrtp,
    analyze_bgp,
    analyze_opcua,
]

"""Layer-7 analyzers (enabled with ``--l7``).

Detection and reporting only: cleartext HTTP requests, DNS (with the "is :53 really DNS" verdict), the SMB negotiated
dialect / encryption / transport, and the NetBIOS name and datagram services.
The pure parsing lives in ``parsers/l7.py``.

Every event these return carries ``layer7: True``. Such events bypass the
encrypted-only filter (they are only produced when --l7 is on), and the ones
describing cleartext protocols carry ``post_quantum_secure: "N/A"`` so they do
not dilute the harvest-now-decrypt-later numbers.

TCP input arrives already reassembled and cut into protocol messages (see
``reassembly.py``). DNS over TCP is only judged on messages from a connection
whose SYN was captured: joined mid-stream, bytes are not aligned to a message
and a "not DNS" verdict would be a false accusation. SMB findings are
reported once per (connection, finding) via the analysis context; otherwise
an encrypted session would report every packet.
"""

from datetime import datetime

from scapy.layers.inet import TCP, UDP

from . import pq
from .analyzers import _conn_id, _ip_layer, _l4_payload, analyze_dnssec
from .context import get_ctx
from .parsers import l7

HTTP_PORTS = {80}
SMB_PORTS = {139, 445}
DNS_PORT = 53
NBNS_PORT = 137
NBDS_PORT = 138

# BPF additions for --l7 (53 and 445 are already in the default filter).
L7_EXTRA_PORTS = [
    "tcp port 80", "tcp port 139", "tcp port 2222",
    "udp port 137", "udp port 138",
]

def _event(pkt, transport, protocol, etype, direction, encrypted=False):
    ip = _ip_layer(pkt)
    return {
        "protocol": protocol,
        "type": etype,
        "timestamp": datetime.now().isoformat(),
        "src_ip": ip.src, "src_port": transport.sport,
        "dst_ip": ip.dst, "dst_port": transport.dport,
        "connection": _conn_id(ip, transport),
        "direction": direction,
        "encrypted": encrypted,
        "layer7": True,
        "post_quantum_secure": "N/A",
    }


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------

def analyze_http(pkt):
    if not pkt.haslayer(TCP):
        return None
    tcp = pkt[TCP]
    if tcp.dport not in HTTP_PORTS:
        return None
    parsed = l7.parse_http_request(_l4_payload(pkt))
    if not parsed:
        return None
    info = _event(pkt, tcp, "HTTP", f"HTTP {parsed['http_method']} Request", "outbound")
    info.update(parsed)
    info["note"] = "Cleartext HTTP request"
    return info


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def _dns_event(pkt, transport, verdict, tcp=False):
    response = verdict.get("dns_is_response")
    if not verdict["dns_conforming"]:
        etype = "Non-DNS traffic on port 53"
    elif response:
        etype = "DNS Response"
    else:
        etype = "DNS Query"
    to_server = transport.dport == DNS_PORT
    info = _event(pkt, transport, "DNS", etype + (" (TCP)" if tcp else ""),
                  "outbound" if to_server else "inbound")
    info.update(verdict)
    if not verdict["dns_conforming"]:
        info["note"] = (f"Port 53 traffic is not DNS ({verdict.get('dns_nonconformance')}). "
                        "Conforming DNS can still be a tunnel; this flags a different protocol.")
    elif response:
        # Fold in DNSSEC algorithm data so --l7 does not lose the DNSSEC event.
        sec = analyze_dnssec(pkt) if not tcp else None
        if sec:
            info["protocol"] = "DNSSEC"
            for k in ("query_name", "dnssec_algorithms", "dnssec_algorithm_ids"):
                info[k] = sec[k]
            info["post_quantum_secure"] = pq.classify_connection(info)
    return info


def analyze_dns_udp(pkt):
    if not pkt.haslayer(UDP):
        return None
    udp = pkt[UDP]
    if DNS_PORT not in (udp.sport, udp.dport):
        return None
    data = _l4_payload(pkt)
    if not data:
        return None
    return _dns_event(pkt, udp, l7.dns_inspect_message(data))


def analyze_dns_tcp(pkt):
    """One reassembled DNS-over-TCP message (or, for a stream that is plainly
    not DNS, the bytes that prove it). Only from SYN-aligned streams."""
    if not pkt.haslayer(TCP):
        return None
    tcp = pkt[TCP]
    if DNS_PORT not in (tcp.sport, tcp.dport):
        return None
    stream = getattr(pkt, "qs_stream", None)
    if not stream or not stream.get("from_syn"):
        return None
    data = _l4_payload(pkt)
    if not data:
        return None
    verdict = l7.dns_inspect_tcp_segment(data, tcp.dport == DNS_PORT)
    if verdict is None:
        return None
    return _dns_event(pkt, tcp, verdict, tcp=True)


# ---------------------------------------------------------------------------
# SMB (tcp/445 direct, tcp/139 NetBIOS session service)
# ---------------------------------------------------------------------------

def analyze_smb(pkt):
    if not pkt.haslayer(TCP):
        return None
    tcp = pkt[TCP]
    if tcp.sport in SMB_PORTS:
        from_server, srv_port = True, tcp.sport
    elif tcp.dport in SMB_PORTS:
        from_server, srv_port = False, tcp.dport
    else:
        return None
    data = _l4_payload(pkt)
    if not data:
        return None
    found = l7.smb_inspect_segment(data, from_server)
    if not found:
        return None
    ip = _ip_layer(pkt)
    if from_server:
        conn = f"{ip.dst}:{tcp.dport} -> {ip.src}:{tcp.sport}"
    else:
        conn = _conn_id(ip, tcp)
    fkey = (conn, found.get("smb_version"), bool(found.get("smb_encrypted")),
            bool(found.get("smb1_negotiate_response")))
    reported = get_ctx(pkt).reported
    if fkey in reported:
        return None
    reported.put(fkey, True)

    if found.get("smb_encrypted"):
        etype = "SMB3 Encrypted Session"
    elif "smb_version" in found:
        etype = f"SMB {found['smb_version']} Negotiated"
    else:
        etype = "SMB1 Negotiate Response"
    info = _event(pkt, tcp, "SMB", etype, "inbound" if from_server else "outbound",
                  encrypted=bool(found.get("smb_encrypted")))
    info["connection"] = conn
    info["smb_transport"] = "netbios" if srv_port == 139 else "direct"
    info.update(found)
    if found.get("smb_version") == "1":
        info["note"] = "SMB1 in use (deprecated, no encryption support)"
    elif found.get("smb_encrypted"):
        info["note"] = "SMB3 transform header seen: session traffic is encrypted"
    elif found.get("smb1_negotiate_response"):
        info["note"] = "Server answered NEGOTIATE in SMB1; an SMB2 upgrade may follow"
    info["post_quantum_secure"] = pq.classify_connection(info)
    return info


# ---------------------------------------------------------------------------
# NetBIOS (udp/137 name service, udp/138 datagram service)
# ---------------------------------------------------------------------------

def analyze_netbios(pkt):
    if not pkt.haslayer(UDP):
        return None
    udp = pkt[UDP]
    ports = (udp.sport, udp.dport)
    data = _l4_payload(pkt)
    if NBNS_PORT in ports:
        parsed = l7.parse_nbns(data)
        if not parsed:
            return None
        kind = "Response" if parsed["nbns_response"] else "Query"
        info = _event(pkt, udp, "NetBIOS", f"NBNS {parsed['nbns_type']} {kind}",
                      "inbound" if parsed["nbns_response"] else "outbound")
    elif NBDS_PORT in ports:
        parsed = l7.parse_nbds(data)
        if not parsed:
            return None
        info = _event(pkt, udp, "NetBIOS", f"NBDS {parsed['nbds_type']}", "outbound")
        if parsed.get("smb_version") == "1":
            info["note"] = "SMB1 mailslot write on the NetBIOS datagram service: SMB1 proven on the wire"
    else:
        return None
    info["smb_transport"] = "netbios"
    info.update(parsed)
    return info


L7_ANALYZERS = [
    analyze_http,
    analyze_dns_udp,
    analyze_dns_tcp,
    analyze_smb,
    analyze_netbios,
]

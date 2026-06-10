"""Output formatters: pretty console output and JSONL append-only logging."""

import json
import sys

from .constants import TOR_PORTS

PQ_LABEL = {
    "Yes":     "POST-QUANTUM SECURE",
    "Hybrid":  "HYBRID (PQ + Classical)",
    "No":      "CLASSICAL CRYPTO (quantum-vulnerable)",
    "Unknown": "UNKNOWN",
}


class JsonlWriter:
    """Append one JSON object per line. Flushes on every write."""

    def __init__(self, path):
        self.path = path
        self._fh = open(path, "a", buffering=1)

    def write(self, info):
        json.dump(info, self._fh, separators=(",", ":"))
        self._fh.write("\n")

    def close(self):
        try:
            self._fh.close()
        except Exception:
            pass


def print_info(info, file=sys.stdout):
    """Pretty-print one event."""
    pq_label = PQ_LABEL.get(info.get("post_quantum_secure", "Unknown"), "UNKNOWN")
    p = lambda *a, **k: print(*a, **k, file=file)

    p("\n" + "=" * 80)
    p(f"[{info['timestamp']}] {info['type']}")
    p(f"Post-Quantum: {pq_label}")
    p("=" * 80)
    p(f"Connection:  {info['connection']}")
    p(f"Direction:   {info['direction']}")
    p(f"Protocol:    {info.get('protocol', 'Unknown')}")

    if "application" in info:
        p(f"Application: {info['application']}")
    if "tls_version" in info:
        version_val = f" ({info['tls_version_value']})" if "tls_version_value" in info else ""
        p(f"TLS Version: {info['tls_version']}{version_val}")
    if "server_name" in info:
        p(f"SNI:         {info['server_name']}")
    if info.get("ech"):
        p("ECH:         present (ClientHelloOuter)")
    if "session_resumption" in info:
        p(f"Resumption:  {info['session_resumption']}")
    if "alpn_protocols" in info:
        p(f"ALPN:        {', '.join(info['alpn_protocols'])}")

    if "client_cipher_suites" in info:
        n = info["cipher_count"]
        p(f"\nClient Offered Ciphers ({n}):")
        for i, c in enumerate(info["client_cipher_suites"][:10], 1):
            p(f"  {i:2}. {c['name']} ({c['value']})")
        if n > 10:
            p(f"      ... and {n - 10} more")

    if "selected_cipher" in info:
        c = info["selected_cipher"]
        p(f"Selected Cipher: {c['name']} ({c['value']})")
    if "supported_versions" in info:
        p(f"TLS Versions: {', '.join(info['supported_versions'])}")

    if "supported_groups" in info:
        p("\nKey Exchange Groups:")
        for g in info["supported_groups"]:
            tag = ""
            gl = g.lower()
            if any(t in gl for t in ("kyber", "mlkem", "ntru", "frodo")):
                tag = " [POST-QUANTUM]"
            p(f"  - {g}{tag}")

    if info.get("fragmented"):
        p("\n** TLS handshake spans multiple TCP segments — analysis is partial **")
    if info.get("quic_tls_decrypted"):
        p("QUIC: Initial packet decrypted (TLS ClientHello extracted)")

    if "ssh_banner" in info:
        p(f"SSH Banner:  {info['ssh_banner']}")
    if "ssh_kex_algorithms" in info:
        p(f"\nSSH KEX Algorithms ({len(info['ssh_kex_algorithms'])}):")
        for alg in info["ssh_kex_algorithms"][:8]:
            tag = " [PQ]" if any(t in alg.lower() for t in ("kyber", "mlkem", "sntrup", "frodo")) else ""
            p(f"  - {alg}{tag}")
    if "ssh_encryption_c2s" in info:
        p(f"SSH Encryption (C->S): {', '.join(info['ssh_encryption_c2s'][:4])}")

    if "ike_proposals" in info:
        p("\nIKEv2 Proposals:")
        for prop in info["ike_proposals"]:
            names = [t["name"] for t in prop["transforms"]]
            p(f"  #{prop['proposal_num']} {prop['protocol']}: {' | '.join(names)}")

    if info.get("protocol") == "WireGuard" and "message_type" in info:
        p(f"WG Message:  {info['message_type']} ({info.get('handshake_size', '?')} bytes)")
    if info.get("pq_wireguard_suspected"):
        p("  ** Non-standard size — possible PQ WireGuard variant **")

    for label, key in [
        ("RDP Requested Protocols", "rdp_requested_protocols"),
        ("RDP Selected Protocol",   "rdp_selected_protocol"),
        ("Kerberos",                "kerberos_message"),
        ("Kerberos Etypes",         "kerberos_etypes"),
        ("SNMPv3 Level",            "snmpv3_security_level"),
        ("OpenVPN",                 "openvpn_opcode"),
        ("RADIUS",                  "radius_code"),
        ("EAP Method",              "radius_eap_type"),
        ("AMQP",                    "amqp_version"),
        ("SIP Method",              "sip_method"),
        ("SIP Status",              "sip_status"),
        ("ZRTP Msg",                "zrtp_message"),
        ("ZRTP KA",                 "zrtp_key_agreement"),
        ("BGP Msg",                 "bgp_message"),
        ("OPC-UA Msg",              "opcua_message"),
        ("OPC-UA Policy",           "opcua_security_policy"),
        ("OPC-UA Mode",             "opcua_security_mode"),
        ("DTLS",                    "dtls_version"),
        ("DNSSEC Algs",             "dnssec_algorithms"),
        ("Query",                   "query_name"),
    ]:
        v = info.get(key)
        if v:
            if isinstance(v, list):
                p(f"{label}: {', '.join(map(str, v))}")
            else:
                p(f"{label}: {v}")

    if "heuristic_port" in info:
        port = info["heuristic_port"]
        suffix = " (Tor)" if port in TOR_PORTS else ""
        p(f"Heuristic:   TLS detected on port {port}{suffix}")

    if "note" in info:
        p(f"Note:        {info['note']}")

    p("=" * 80)

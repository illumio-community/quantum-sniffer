"""Post-quantum cryptography classification.

Drives PQ status from explicit (id -> classification) tables, not substring
matching, so novel hybrid names can't be silently misclassified.
"""

from typing import Dict, List, Optional, Any

CLASSICAL = "classical"
PQ = "pq"
HYBRID = "hybrid"

# TLS named-group IDs. Hybrid groups (x25519+kyber, x25519+mlkem) are HYBRID,
# pure PQ groups are PQ, classical curves/FFDHE are CLASSICAL.
TLS_GROUP_CLASS = {
    23: CLASSICAL, 24: CLASSICAL, 25: CLASSICAL,
    29: CLASSICAL, 30: CLASSICAL,
    256: CLASSICAL, 257: CLASSICAL, 258: CLASSICAL,
    259: CLASSICAL, 260: CLASSICAL,
    0x0200: PQ, 0x0201: PQ, 0x0202: PQ,
    0x11eb: HYBRID,
    0x11ec: HYBRID,
    0x6399: HYBRID,
    0x639a: HYBRID,
    0x11ee: HYBRID,
    0x768:  PQ,
}

# IKEv2 D-H transform IDs (subset of IKE_DH that we want to classify)
IKE_DH_CLASS = {
    1: CLASSICAL, 2: CLASSICAL, 5: CLASSICAL,
    14: CLASSICAL, 15: CLASSICAL, 16: CLASSICAL,
    17: CLASSICAL, 18: CLASSICAL,
    19: CLASSICAL, 20: CLASSICAL, 21: CLASSICAL,
    31: CLASSICAL, 32: CLASSICAL,
    35: PQ, 36: PQ, 37: PQ,
}

# SSH KEX names. SSH leaks human-readable algorithm strings, so we still need
# string-based lookup, but we make it exact (set membership) rather than
# substring.
SSH_KEX_PQ = {
    "sntrup761x25519-sha512@openssh.com",
    "sntrup4591761x25519-sha512@tinyssh.org",
    "mlkem768x25519-sha256",
    "mlkem768nistp256-sha256",
}

SSH_KEX_CLASSICAL = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group-exchange-sha256",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
}

# Unambiguous PQ tokens that may appear in vendor-specific SSH KEX names.
# These tokens never appear in classical KEX names, so substring matching
# against this small allow-list is safe.
SSH_PQ_TOKENS = ("kyber", "mlkem", "sntrup", "frodo")


def classify_tls_group(group_id: int) -> Optional[str]:
    """Classify a TLS named-group ID.

    Args:
        group_id: TLS named group numeric ID

    Returns:
        One of CLASSICAL, PQ, HYBRID, or None if unknown
    """
    return TLS_GROUP_CLASS.get(group_id)


def classify_ike_dh(transform_id: int) -> Optional[str]:
    """Classify an IKEv2 Diffie-Hellman transform ID.

    Args:
        transform_id: IKEv2 DH transform numeric ID

    Returns:
        One of CLASSICAL, PQ, HYBRID, or None if unknown
    """
    return IKE_DH_CLASS.get(transform_id)


def classify_ssh_kex(name: str) -> Optional[str]:
    """Classify an SSH key exchange algorithm by name.

    Args:
        name: SSH KEX algorithm name

    Returns:
        One of CLASSICAL, PQ, HYBRID, or None if unknown
    """
    n = name.lower()
    if n in SSH_KEX_PQ:
        return PQ
    if n in SSH_KEX_CLASSICAL:
        return CLASSICAL
    if any(tok in n for tok in SSH_PQ_TOKENS):
        return PQ
    return None


def classify_connection(info: Dict[str, Any]) -> str:
    """Determine overall PQ status of a connection.

    Analyzes all available cryptographic indicators (TLS groups, SSH KEX,
    IKE proposals, protocol-specific knowledge) and returns a final verdict.

    Args:
        info: Dictionary with protocol analysis results. May contain:
            - supported_group_ids: List[int] - TLS named groups
            - ssh_kex_algorithms: List[str] - SSH KEX algorithms
            - ike_proposals: List[Dict] - IKEv2 proposals with transforms
            - protocol: str - Protocol name
            - Various protocol-specific flags

    Returns:
        One of "Yes" (PQ-secure), "Hybrid" (mixed PQ+classical),
        "No" (classical only), or "Unknown" (cannot determine)
    """
    saw_pq = False
    saw_hybrid = False
    saw_classical = False

    # Check TLS supported groups
    for gid in info.get("supported_group_ids", []):
        cls = classify_tls_group(gid)
        if cls == PQ:
            saw_pq = True
        elif cls == HYBRID:
            saw_hybrid = True
        elif cls == CLASSICAL:
            saw_classical = True

    # Check SSH KEX algorithms
    for kex in info.get("ssh_kex_algorithms", []):
        cls = classify_ssh_kex(kex)
        if cls == PQ:
            saw_pq = True
        elif cls == CLASSICAL:
            saw_classical = True

    # Check IKEv2 proposals
    for proposal in info.get("ike_proposals", []):
        for t in proposal.get("transforms", []):
            if t.get("type") != "D-H":
                continue
            cls = classify_ike_dh(t.get("id"))
            if cls == PQ:
                saw_pq = True
            elif cls == CLASSICAL:
                saw_classical = True

    # Protocol-specific knowledge (fixed crypto that's not PQ-ready)
    protocol = info.get("protocol")
    if protocol in ("Kerberos",) and "kerberos_etypes" in info:
        return "No"
    if protocol == "RADIUS":
        return "No"
    if protocol == "SNMPv3":
        return "No"
    if protocol == "RDP":
        return "No"
    if protocol == "DNSSEC":
        return "No"
    if protocol == "WireGuard":
        return "Hybrid" if info.get("pq_wireguard_suspected") else "No"
    if protocol in ("DTLS", "BGP", "OPC-UA", "ZRTP", "SMB", "SIP"):
        # Only flagged "No" when there's no TLS layer carrying PQ info
        if not (saw_pq or saw_hybrid or saw_classical):
            return "No"

    # Determine final status based on what we saw
    if saw_hybrid or (saw_pq and saw_classical):
        return "Hybrid"
    if saw_pq:
        return "Yes"
    if saw_classical:
        return "No"

    # Special cases for Unknown
    if info.get("key_share_parse_failed"):
        return "Unknown"
    if protocol == "TLS" and "selected_cipher" in info:
        return "No"

    return "Unknown"

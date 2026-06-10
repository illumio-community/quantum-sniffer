"""Protocol constants — IANA registries, version maps, etype tables."""

TLS_CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xc027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xc028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xc023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xc024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009f: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x006b: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x003d: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x003c: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
}

TLS_VERSIONS = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0x0300: "SSL 3.0",
}

TLS_EXTENSIONS = {
    0: "server_name",
    1: "max_fragment_length",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "alpn",
    18: "signed_certificate_timestamp",
    23: "extended_master_secret",
    35: "session_ticket",
    41: "pre_shared_key",
    43: "supported_versions",
    44: "cookie",
    45: "psk_key_exchange_modes",
    51: "key_share",
    57: "quic_transport_parameters",
    65037: "encrypted_client_hello",
}

TLS_NAMED_GROUPS = {
    23: "secp256r1", 24: "secp384r1", 25: "secp521r1",
    29: "x25519", 30: "x448",
    256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096",
    259: "ffdhe6144", 260: "ffdhe8192",
    0x0200: "kyber512",   0x0201: "kyber768",   0x0202: "kyber1024",
    0x11eb: "x25519kyber512",
    0x11ec: "x25519kyber768",
    0x6399: "x25519kyber768",
    0x639a: "x25519mlkem768",
    0x11ee: "x25519mlkem768",
    0x768:  "mlkem768",
}

IKE_ENCR = {
    1: "DES-IV64", 2: "DES", 3: "3DES", 5: "CAST", 7: "BLOWFISH",
    11: "NULL", 12: "AES-CBC-128", 13: "AES-CBC-192", 14: "AES-CBC-256",
    18: "AES-CTR", 20: "AES-GCM-128", 21: "AES-GCM-192", 22: "AES-GCM-256",
    23: "NULL_AUTH_AES-GMAC", 28: "CHACHA20-POLY1305",
}

IKE_PRF = {
    1: "PRF_HMAC_MD5", 2: "PRF_HMAC_SHA1", 3: "PRF_HMAC_TIGER",
    4: "PRF_AES128_XCBC", 5: "PRF_HMAC_SHA2_256",
    6: "PRF_HMAC_SHA2_384", 7: "PRF_HMAC_SHA2_512",
}

IKE_INTEG = {
    1: "AUTH_HMAC_MD5_96", 2: "AUTH_HMAC_SHA1_96", 3: "AUTH_DES_MAC",
    4: "AUTH_KPDK_MD5", 5: "AUTH_AES_XCBC_96",
    12: "AUTH_HMAC_SHA2_256_128", 13: "AUTH_HMAC_SHA2_384_192",
    14: "AUTH_HMAC_SHA2_512_256",
}

# Includes IANA-assigned post-quantum DH groups (draft-ietf-ipsecme-ikev2-pq-auth)
IKE_DH = {
    1: "768-bit MODP", 2: "1024-bit MODP", 5: "1536-bit MODP",
    14: "2048-bit MODP", 15: "3072-bit MODP", 16: "4096-bit MODP",
    17: "6144-bit MODP", 18: "8192-bit MODP",
    19: "256-bit ECP (P-256)", 20: "384-bit ECP (P-384)",
    21: "521-bit ECP (P-521)", 31: "Curve25519", 32: "Curve448",
    35: "ML-KEM-512",
    36: "ML-KEM-768",
    37: "ML-KEM-1024",
}

IKE_EXCHANGE_TYPES = {
    34: "IKE_SA_INIT", 35: "IKE_AUTH",
    36: "CREATE_CHILD_SA", 37: "INFORMATIONAL",
}

KERBEROS_ETYPES = {
    1:   "DES-CBC-CRC (broken)",
    3:   "DES-CBC-MD5 (broken)",
    17:  "AES128-CTS-HMAC-SHA1-96",
    18:  "AES256-CTS-HMAC-SHA1-96",
    19:  "AES128-CTS-HMAC-SHA256-128",
    20:  "AES256-CTS-HMAC-SHA384-192",
    23:  "RC4-HMAC (NTLM-style)",
    24:  "RC4-HMAC-EXP (weak)",
    -128: "AES128-CTS-HMAC-SHA256-128",
    -129: "AES256-CTS-HMAC-SHA384-192",
}

DNSSEC_ALGORITHMS = {
    1:  "RSA/MD5 (deprecated)",
    3:  "DSA/SHA-1 (deprecated)",
    5:  "RSA/SHA-1",
    6:  "DSA-NSEC3-SHA1",
    7:  "RSASHA1-NSEC3-SHA1",
    8:  "RSA/SHA-256",
    10: "RSA/SHA-512",
    12: "GOST R 34.10-2001",
    13: "ECDSA P-256/SHA-256",
    14: "ECDSA P-384/SHA-384",
    15: "Ed25519",
    16: "Ed448",
}

RADIUS_CODES = {
    1: "Access-Request", 2: "Access-Accept", 3: "Access-Reject",
    4: "Accounting-Request", 5: "Accounting-Response",
    11: "Access-Challenge", 12: "Status-Server", 13: "Status-Client",
}

EAP_METHODS = {
    1: "Identity", 2: "Notification", 3: "Nak",
    4: "MD5-Challenge", 13: "EAP-TLS", 17: "LEAP",
    18: "EAP-SIM", 21: "EAP-TTLS", 23: "EAP-AKA",
    25: "EAP-PEAP", 43: "EAP-FAST", 50: "EAP-AKA-Prime",
    55: "EAP-TEAP",
}

OPENVPN_OPCODES = {
    1: "P_CONTROL_HARD_RESET_CLIENT_V1",
    2: "P_CONTROL_HARD_RESET_SERVER_V1",
    3: "P_CONTROL_SOFT_RESET_V1",
    4: "P_CONTROL_V1",
    5: "P_ACK_V1",
    6: "P_DATA_V1",
    7: "P_CONTROL_HARD_RESET_CLIENT_V2",
    8: "P_CONTROL_HARD_RESET_SERVER_V2",
    9: "P_DATA_V2",
}

RDP_PROTOCOLS = {
    0x00000000: "Standard RDP (RC4 — no TLS)",
    0x00000001: "TLS",
    0x00000002: "CredSSP/NLA",
    0x00000004: "RDSTLS",
    0x00000008: "CredSSP with early user auth",
}

QUIC_INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
QUIC_INITIAL_SALT_V2 = bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9")

ZRTP_MSG_TYPES = {
    "Hello   ": "Hello",     "HelloACK": "HelloACK",
    "Commit  ": "Commit",    "DHPart1 ": "DHPart1",
    "DHPart2 ": "DHPart2",   "Confirm1": "Confirm1",
    "Confirm2": "Confirm2",  "Conf2ACK": "Conf2ACK",
    "Error   ": "Error",     "GoClear ": "GoClear",
    "SASrelay": "SASrelay",  "Ping    ": "Ping",
    "PingACK ": "PingACK",
}

ZRTP_KEY_AGREEMENT = {
    "DH3K": "DH-3072 (classical)",  "DH2K": "DH-2048 (classical)",
    "EC25": "ECDH-P-256 (classical)", "EC38": "ECDH-P-384 (classical)",
    "EC52": "ECDH-P-521 (classical)", "Prsh": "preshared",
    "Mult": "multistream",
}

BGP_MSG_TYPES = {
    1: "OPEN", 2: "UPDATE", 3: "NOTIFICATION", 4: "KEEPALIVE", 5: "ROUTE-REFRESH",
}

OPC_UA_MSG_TYPES = {
    b"HEL": "Hello",         b"ACK": "Acknowledge",
    b"OPN": "OpenSecureChannel", b"CLO": "CloseSecureChannel",
    b"MSG": "Message",       b"ERR": "Error",
}

OPC_UA_SECURITY_MODES = {1: "None", 2: "Sign", 3: "SignAndEncrypt"}

# Tor onion service ports (heuristic)
TOR_PORTS = {9001, 9030, 9050, 9051, 9150}

TLS_HEURISTIC_PORTS = {
    8443, 8444, 9443, 4433, 4434, 4444,
    2376, 2377,
    6443,
    10250, 10255,
    2379, 2380,
    9200, 9300,
    27017,
    6380,
    9090, 9091, 9093, 9094,
    8080, 8081, 8888, 8889,
    5000, 5001,
}

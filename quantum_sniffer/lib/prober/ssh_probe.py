"""SSH-specific probing logic."""

import socket
import struct
import time
from datetime import datetime
from typing import Optional

from .results import ProbeResult, PortStatus
from ..pq import classify_ssh_kex


def probe_ssh(target_ip: str, port: int, timeout: float = 5.0) -> ProbeResult:
    """Probe an SSH endpoint for PQ crypto capabilities.

    Args:
        target_ip: Target IP address
        port: Target port (typically 22)
        timeout: Connection timeout in seconds

    Returns:
        ProbeResult with SSH KEX information
    """
    start_time = time.time()
    timestamp = datetime.now().isoformat()

    result = ProbeResult(
        target_ip=target_ip,
        target_port=port,
        protocol="ssh",
        status=PortStatus.CLOSED,
        timestamp=timestamp,
    )

    try:
        # Connect to SSH server
        sock = socket.create_connection((target_ip, port), timeout=timeout)
        sock.settimeout(timeout)

        # Read server banner (SSH-2.0-...)
        banner = b""
        while b"\n" not in banner:
            chunk = sock.recv(1024)
            if not chunk:
                raise Exception("Connection closed while reading banner")
            banner += chunk
            if len(banner) > 4096:  # Sanity check
                raise Exception("Banner too long")

        server_banner = banner.strip().decode('utf-8', errors='ignore')

        # Send our banner
        client_banner = b"SSH-2.0-QuantumSniffer_ProbeClient\r\n"
        sock.sendall(client_banner)

        # Build and send SSH_MSG_KEXINIT
        kexinit_packet = build_kexinit_packet()
        sock.sendall(kexinit_packet)

        # Read server's KEXINIT
        # SSH packet format: packet_length (4 bytes), padding_length (1 byte), payload, padding, MAC
        packet_len_bytes = _recv_exact(sock, 4)
        packet_length = struct.unpack('>I', packet_len_bytes)[0]

        if packet_length > 35000:  # Sanity check (max SSH packet is 35000 bytes)
            raise Exception(f"Invalid packet length: {packet_length}")

        # Read rest of packet
        packet_data = _recv_exact(sock, packet_length)

        padding_length = packet_data[0]
        payload = packet_data[1:packet_length - padding_length]

        # Parse KEXINIT payload
        if len(payload) < 1 or payload[0] != 20:  # SSH_MSG_KEXINIT = 20
            raise Exception(f"Expected KEXINIT (20), got {payload[0]}")

        # Parse KEX algorithms from KEXINIT payload
        kex_algorithms = parse_kexinit_algorithms(payload[1:])  # Skip message type

        sock.close()

        # Successfully parsed SSH KEX
        result.status = PortStatus.OPEN

        # Store SSH-specific data in extras
        result.extras["ssh_banner"] = server_banner
        result.extras["ssh_kex_algorithms"] = kex_algorithms

        # Classify PQ status based on KEX algorithms
        result.post_quantum_secure = classify_ssh_connection(kex_algorithms)

    except socket.timeout:
        result.status = PortStatus.TIMEOUT
        result.error_message = f"Connection timeout ({timeout}s)"

    except ConnectionRefusedError:
        result.status = PortStatus.CLOSED
        result.error_message = "Connection refused"

    except OSError as e:
        result.status = PortStatus.FILTERED
        result.error_message = f"OS error: {str(e)}"

    except Exception as e:
        result.status = PortStatus.ERROR
        result.error_message = f"SSH error: {str(e)}"

    # Record duration
    duration = (time.time() - start_time) * 1000
    result.probe_duration_ms = round(duration, 2)

    return result


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes from socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise Exception("Connection closed")
        data += chunk
    return data


def build_kexinit_packet() -> bytes:
    """Build SSH_MSG_KEXINIT packet with PQ-capable KEX list.

    SSH packet format:
        uint32    packet_length
        byte      padding_length
        byte[n1]  payload; n1 = packet_length - padding_length - 1
        byte[n2]  random padding; n2 = padding_length
        byte[m]   mac (not present for KEXINIT)
    """
    # KEXINIT payload (simplified - advertise common KEX algorithms)
    kex_algorithms = [
        b"sntrup761x25519-sha512@openssh.com",  # PQ
        b"mlkem768x25519-sha256",  # PQ
        b"curve25519-sha256",  # Classical
        b"ecdh-sha2-nistp256",  # Classical
    ]

    # Build name-list for KEX algorithms
    kex_list = b",".join(kex_algorithms)

    # Simplified KEXINIT (we don't need to negotiate, just trigger server response)
    payload = bytearray()
    payload.append(20)  # SSH_MSG_KEXINIT
    payload.extend(b"\x00" * 16)  # cookie (16 random bytes - zeros for simplicity)

    # Add KEX algorithms name-list
    payload.extend(struct.pack('>I', len(kex_list)))
    payload.extend(kex_list)

    # Add empty name-lists for other algorithm types (simplified)
    # In real SSH, would list: server_host_key_algorithms, encryption_algorithms_client_to_server, etc.
    for _ in range(9):  # 9 more name-lists
        payload.extend(struct.pack('>I', 0))  # Empty list

    # first_kex_packet_follows = false
    payload.append(0)

    # reserved
    payload.extend(b"\x00\x00\x00\x00")

    # Calculate padding (block size is 8 for SSH-2)
    block_size = 8
    padding_length = block_size - ((len(payload) + 5) % block_size)
    if padding_length < 4:
        padding_length += block_size

    # Build packet
    packet_length = 1 + len(payload) + padding_length  # padding_length(1) + payload + padding

    packet = bytearray()
    packet.extend(struct.pack('>I', packet_length))
    packet.append(padding_length)
    packet.extend(payload)
    packet.extend(b"\x00" * padding_length)  # Padding (zeros for simplicity)

    return bytes(packet)


def parse_kexinit_algorithms(payload: bytes) -> list:
    """Parse KEX algorithms from KEXINIT payload.

    KEXINIT format:
        byte[16]  cookie
        name-list kex_algorithms
        ... (other name-lists)

    Returns:
        List of KEX algorithm names
    """
    if len(payload) < 16:
        return []

    # Skip cookie
    offset = 16

    # Read KEX algorithms name-list
    if offset + 4 > len(payload):
        return []

    list_length = struct.unpack('>I', payload[offset:offset+4])[0]
    offset += 4

    if offset + list_length > len(payload):
        return []

    kex_list_bytes = payload[offset:offset+list_length]
    kex_list_str = kex_list_bytes.decode('utf-8', errors='ignore')

    algorithms = [alg.strip() for alg in kex_list_str.split(',') if alg.strip()]

    return algorithms


def classify_ssh_connection(kex_algorithms: list) -> str:
    """Classify PQ status of SSH connection based on KEX algorithms.

    Args:
        kex_algorithms: List of KEX algorithm names from server

    Returns:
        "Yes", "Hybrid", "No", or "Unknown"
    """
    saw_pq = False
    saw_classical = False

    for kex in kex_algorithms:
        classification = classify_ssh_kex(kex)
        if classification == "pq":
            saw_pq = True
        elif classification == "classical":
            saw_classical = True

    if saw_pq and saw_classical:
        return "Hybrid"
    elif saw_pq:
        return "Yes"
    elif saw_classical:
        return "No"
    else:
        return "Unknown"

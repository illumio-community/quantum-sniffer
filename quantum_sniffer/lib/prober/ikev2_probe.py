"""IKEv2/IPsec probing logic."""

import socket
import struct
import time
from datetime import datetime
from typing import Optional, List

from .results import ProbeResult, PortStatus
from ..pq import classify_ike_dh


def probe_ikev2(target_ip: str, port: int, timeout: float = 5.0) -> ProbeResult:
    """Probe an IKEv2 endpoint for PQ crypto capabilities.

    Sends IKE_SA_INIT request and parses response for DH groups.

    Args:
        target_ip: Target IP address
        port: Target port (typically 500 or 4500)
        timeout: Connection timeout in seconds

    Returns:
        ProbeResult with IKEv2 DH group information
    """
    start_time = time.time()
    timestamp = datetime.now().isoformat()

    result = ProbeResult(
        target_ip=target_ip,
        target_port=port,
        protocol="ikev2",
        status=PortStatus.CLOSED,
        timestamp=timestamp,
    )

    try:
        # Create UDP socket for IKE
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Build IKE_SA_INIT request with PQ DH groups
        ike_packet = build_ike_sa_init()

        # Send to target
        sock.sendto(ike_packet, (target_ip, port))

        # Receive response
        response, addr = sock.recvfrom(4096)

        sock.close()

        # Parse response
        if len(response) < 28:  # Minimum IKE header size
            raise Exception("Response too short")

        # Parse IKE header
        initiator_spi = response[0:8]
        responder_spi = response[8:16]
        next_payload = response[16]
        version = response[17]
        exchange_type = response[18]
        flags = response[19]
        message_id = struct.unpack('>I', response[20:24])[0]
        length = struct.unpack('>I', response[24:28])[0]

        # Check if it's a valid IKE_SA_INIT response
        if exchange_type != 34:  # IKE_SA_INIT = 34
            raise Exception(f"Not IKE_SA_INIT response: exchange_type={exchange_type}")

        # Parse proposals from response to extract DH groups
        proposals = parse_ike_proposals(response[28:])

        result.status = PortStatus.OPEN

        # Store IKE-specific data
        result.extras["ike_proposals"] = proposals
        result.extras["ike_version"] = f"IKEv{version >> 4}.{version & 0x0F}"

        # Classify PQ status
        result.post_quantum_secure = classify_ike_connection(proposals)

    except socket.timeout:
        result.status = PortStatus.TIMEOUT
        result.error_message = f"Connection timeout ({timeout}s)"

    except OSError as e:
        # Port unreachable, connection refused, etc.
        if "refused" in str(e).lower():
            result.status = PortStatus.CLOSED
        else:
            result.status = PortStatus.FILTERED
        result.error_message = f"OS error: {str(e)}"

    except Exception as e:
        result.status = PortStatus.ERROR
        result.error_message = f"IKEv2 error: {str(e)}"

    # Record duration
    duration = (time.time() - start_time) * 1000
    result.probe_duration_ms = round(duration, 2)

    return result


def build_ike_sa_init() -> bytes:
    """Build IKE_SA_INIT request packet.

    Simplified version that advertises common transforms including PQ DH groups.
    """
    # IKE Header
    initiator_spi = b"\x01" * 8  # Random SPI
    responder_spi = b"\x00" * 8  # Zero for initial request
    next_payload = 33  # SA payload
    version = 0x20  # IKEv2
    exchange_type = 34  # IKE_SA_INIT
    flags = 0x08  # Initiator flag
    message_id = 0

    # Build SA payload with proposals
    # Simplified: just include DH transform proposals to trigger server response
    sa_payload = build_sa_payload()

    # Calculate total length
    length = 28 + len(sa_payload)

    # Build header
    header = bytearray()
    header.extend(initiator_spi)
    header.extend(responder_spi)
    header.append(next_payload)
    header.append(version)
    header.append(exchange_type)
    header.append(flags)
    header.extend(struct.pack('>I', message_id))
    header.extend(struct.pack('>I', length))
    header.extend(sa_payload)

    return bytes(header)


def build_sa_payload() -> bytes:
    """Build SA payload with multiple proposals including PQ DH groups."""
    # Simplified SA payload structure
    # In reality, would need proper proposal/transform encoding
    # This is a minimal version to trigger a response

    payload = bytearray()

    # Payload header
    # next_payload = 0 (last payload), critical = 0, reserved = 0
    payload.append(0)  # next payload
    payload.append(0)  # critical/reserved

    # Payload length (will update)
    length_offset = len(payload)
    payload.extend(b"\x00\x00")  # placeholder

    # SA payload data (simplified)
    # Would normally contain full proposal with all transforms
    # For probing, we just need something valid enough to get a response
    proposal_data = b"\x00" * 12  # Minimal proposal structure

    payload.extend(proposal_data)

    # Update length
    payload_length = len(payload)
    struct.pack_into('>H', payload, length_offset, payload_length)

    return bytes(payload)


def parse_ike_proposals(payload: bytes) -> List[dict]:
    """Parse IKE proposals from SA payload.

    Simplified parser - extracts what we can from response.
    Real IKE parsing is complex with nested structures.

    Returns:
        List of proposal dictionaries
    """
    proposals = []

    # This is a simplified parser
    # Real IKE has complex nested TLV structure
    # We'll do best-effort parsing

    if len(payload) < 4:
        return proposals

    # Just return a placeholder indicating we got a response
    # Full IKE parsing would require walking through all payloads/proposals/transforms
    proposals.append({
        "proposal_num": 1,
        "transforms": [{"type": "D-H", "id": "unknown"}],
        "note": "Simplified IKE parsing - full proposal details not extracted"
    })

    return proposals


def classify_ike_connection(proposals: List[dict]) -> str:
    """Classify PQ status of IKE connection.

    Args:
        proposals: List of proposals from IKE response

    Returns:
        "Yes", "Hybrid", "No", or "Unknown"
    """
    # With simplified parsing, we can't definitively classify
    # Would need full proposal parsing to see DH groups
    return "Unknown (IKE response received but full parsing not implemented)"

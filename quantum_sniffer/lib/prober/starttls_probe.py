"""STARTTLS probing for protocols that upgrade to TLS."""

import socket
import ssl
import time
from datetime import datetime
from typing import Optional

from .results import ProbeResult, PortStatus
from .tls_probe import _extract_cert_info, _extract_kex_from_cipher, _classify_tls_connection


# Protocol-specific STARTTLS commands
STARTTLS_PROTOCOLS = {
    25: ("smtp", b"EHLO quantum-sniffer\r\nSTARTTLS\r\n", b"220"),
    587: ("smtp", b"EHLO quantum-sniffer\r\nSTARTTLS\r\n", b"220"),
    143: ("imap", b"A001 STARTTLS\r\n", b"A001 OK"),
    110: ("pop3", b"STLS\r\n", b"+OK"),
    21: ("ftp", b"AUTH TLS\r\n", b"234"),
    389: ("ldap", None, None),  # LDAP STARTTLS is more complex (LDAP message format)
}


def probe_starttls(target_ip: str, port: int, timeout: float = 5.0) -> ProbeResult:
    """Probe a STARTTLS-capable service.

    Args:
        target_ip: Target IP address
        port: Target port (25, 587, 143, 110, 21, 389)
        timeout: Connection timeout in seconds

    Returns:
        ProbeResult with TLS information after STARTTLS upgrade
    """
    start_time = time.time()
    timestamp = datetime.now().isoformat()

    # Determine protocol
    protocol_info = STARTTLS_PROTOCOLS.get(port)
    if not protocol_info:
        return ProbeResult(
            target_ip=target_ip,
            target_port=port,
            protocol="starttls",
            status=PortStatus.ERROR,
            error_message=f"Unsupported STARTTLS port: {port}",
            timestamp=timestamp,
        )

    protocol_name, starttls_cmd, expected_response = protocol_info

    result = ProbeResult(
        target_ip=target_ip,
        target_port=port,
        protocol=f"starttls-{protocol_name}",
        status=PortStatus.CLOSED,
        timestamp=timestamp,
    )

    try:
        # Special handling for LDAP (requires LDAP message format)
        if port == 389:
            return probe_ldap_starttls(target_ip, port, timeout, start_time, timestamp)

        # Connect to service
        sock = socket.create_connection((target_ip, port), timeout=timeout)
        sock.settimeout(timeout)

        # Read initial banner (for SMTP/IMAP/POP3/FTP)
        initial_banner = sock.recv(4096)

        # Send STARTTLS command
        sock.sendall(starttls_cmd)

        # Read response
        response = sock.recv(4096)

        # Check if STARTTLS was accepted
        if not response.startswith(expected_response):
            raise Exception(f"STARTTLS not accepted: {response[:100].decode('utf-8', errors='ignore')}")

        # Upgrade to TLS
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        tls_sock = context.wrap_socket(sock, server_hostname=target_ip)

        # Connection successful
        result.status = PortStatus.OPEN

        # Get TLS version
        tls_version = tls_sock.version()
        result.tls_version = tls_version if tls_version else "Unknown"

        # Get cipher suite
        cipher_info = tls_sock.cipher()
        if cipher_info:
            cipher_name, tls_ver, cipher_bits = cipher_info
            result.cipher_suite = cipher_name

        # Try to get certificate
        try:
            cert = tls_sock.getpeercert()
            if cert:
                result.certificate_info = _extract_cert_info(cert)
                if 'subject' in cert:
                    for rdn in cert['subject']:
                        for name, value in rdn:
                            if name == 'commonName':
                                result.server_name = value
                                break
        except Exception:
            pass

        # Classify PQ status
        result.post_quantum_secure = _classify_tls_connection(result)
        result.key_exchange_group = _extract_kex_from_cipher(result.cipher_suite)

        tls_sock.close()

    except socket.timeout:
        result.status = PortStatus.TIMEOUT
        result.error_message = f"Connection timeout ({timeout}s)"

    except ConnectionRefusedError:
        result.status = PortStatus.CLOSED
        result.error_message = "Connection refused"

    except ssl.SSLError as e:
        result.status = PortStatus.ERROR
        result.error_message = f"SSL error: {str(e)}"

    except OSError as e:
        result.status = PortStatus.FILTERED
        result.error_message = f"OS error: {str(e)}"

    except Exception as e:
        result.status = PortStatus.ERROR
        result.error_message = f"STARTTLS error: {str(e)}"

    # Record duration
    duration = (time.time() - start_time) * 1000
    result.probe_duration_ms = round(duration, 2)

    return result


def probe_ldap_starttls(
    target_ip: str,
    port: int,
    timeout: float,
    start_time: float,
    timestamp: str
) -> ProbeResult:
    """Probe LDAP STARTTLS (requires LDAP message encoding).

    LDAP uses ASN.1/BER encoding, which is complex. For now, we'll skip
    full LDAP implementation and return an error indicating it's not yet supported.
    """
    result = ProbeResult(
        target_ip=target_ip,
        target_port=port,
        protocol="starttls-ldap",
        status=PortStatus.ERROR,
        timestamp=timestamp,
        error_message="LDAP STARTTLS not yet implemented (requires ASN.1 encoding)",
    )

    duration = (time.time() - start_time) * 1000
    result.probe_duration_ms = round(duration, 2)

    return result

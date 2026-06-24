"""TLS-specific probing logic."""

import socket
import ssl
import time
from datetime import datetime
from typing import Optional, Tuple

from .results import ProbeResult, PortStatus
from ..pq import classify_tls_group, HYBRID, PQ, CLASSICAL


# Map SSL/TLS version constants to readable strings
TLS_VERSION_NAMES = {
    ssl.TLSVersion.SSLv3: "SSL 3.0",
    ssl.TLSVersion.TLSv1: "TLS 1.0",
    ssl.TLSVersion.TLSv1_1: "TLS 1.1",
    ssl.TLSVersion.TLSv1_2: "TLS 1.2",
    ssl.TLSVersion.TLSv1_3: "TLS 1.3",
}


def probe_tls(
    target_ip: str,
    port: int,
    timeout: float = 5.0,
    server_hostname: Optional[str] = None
) -> ProbeResult:
    """Probe a TLS endpoint for PQ crypto capabilities.

    Args:
        target_ip: Target IP address
        port: Target port
        timeout: Connection timeout in seconds
        server_hostname: Hostname for SNI (if different from target_ip)

    Returns:
        ProbeResult with connection and crypto details
    """
    start_time = time.time()
    timestamp = datetime.now().isoformat()

    result = ProbeResult(
        target_ip=target_ip,
        target_port=port,
        protocol="tls",
        status=PortStatus.CLOSED,
        timestamp=timestamp,
    )

    # Use server_hostname for SNI if provided, otherwise use target_ip
    sni_hostname = server_hostname if server_hostname else target_ip

    try:
        # Create SSL context with modern settings
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Set minimum TLS version (prefer TLS 1.2+)
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Try to enable PQ groups if available (Python 3.13+)
        # For now, we'll rely on system OpenSSL configuration

        # Connect with timeout
        with socket.create_connection((target_ip, port), timeout=timeout) as sock:
            # Wrap socket with TLS (use proper hostname for SNI)
            with context.wrap_socket(sock, server_hostname=sni_hostname) as ssock:
                # Connection successful
                result.status = PortStatus.OPEN

                # Get TLS version
                tls_version = ssock.version()
                result.tls_version = tls_version if tls_version else "Unknown"

                # Get cipher suite
                cipher_info = ssock.cipher()
                if cipher_info:
                    cipher_name, tls_ver, cipher_bits = cipher_info
                    result.cipher_suite = cipher_name

                # Try to get server certificate
                try:
                    cert = ssock.getpeercert()
                    if cert:
                        result.certificate_info = _extract_cert_info(cert)
                        # Try to extract server name from cert
                        if 'subject' in cert:
                            for rdn in cert['subject']:
                                for name, value in rdn:
                                    if name == 'commonName':
                                        result.server_name = value
                                        break
                except Exception:
                    pass

                # Get negotiated parameters
                # Note: Python's ssl module doesn't directly expose negotiated groups
                # We can infer PQ support from cipher suite and TLS version
                result.post_quantum_secure = _classify_tls_connection(result)

                # Try to extract key exchange info from cipher name
                result.key_exchange_group = _extract_kex_from_cipher(result.cipher_suite)

    except socket.timeout:
        result.status = PortStatus.TIMEOUT
        result.error_message = f"Connection timeout ({timeout}s)"

    except ConnectionRefusedError:
        result.status = PortStatus.CLOSED
        result.error_message = "Connection refused"

    except ssl.SSLError as e:
        result.status = PortStatus.ERROR
        error_str = str(e)

        # Special handling for common SSL errors
        if "WRONG_VERSION_NUMBER" in error_str:
            # Port is open but not TLS - try to detect what it actually is
            detected = _try_detect_protocol(target_ip, port, timeout)
            if detected:
                result.error_message = f"Not TLS/HTTPS - detected: {detected}"
                result.extras["detected_protocol"] = detected
            else:
                result.error_message = "Not TLS/HTTPS (wrong version number) - port may be plain HTTP or another protocol"
        elif "CERTIFICATE_VERIFY_FAILED" in error_str:
            result.error_message = "SSL certificate verification failed (self-signed or invalid)"
        elif "SSLV3_ALERT_HANDSHAKE_FAILURE" in error_str:
            result.error_message = "SSL handshake failed - server rejected connection"
        elif "TLSV1_ALERT" in error_str:
            result.error_message = "TLS alert from server - incompatible TLS settings"
        else:
            result.error_message = f"SSL error: {error_str}"

    except OSError as e:
        # Could be "No route to host", filtered, etc.
        result.status = PortStatus.FILTERED
        result.error_message = f"OS error: {str(e)}"

    except Exception as e:
        result.status = PortStatus.ERROR
        result.error_message = f"Unexpected error: {str(e)}"

    # Record duration
    duration = (time.time() - start_time) * 1000
    result.probe_duration_ms = round(duration, 2)

    return result


def _extract_cert_info(cert: dict) -> dict:
    """Extract relevant certificate information."""
    info = {}

    if 'subject' in cert:
        subject_parts = []
        for rdn in cert['subject']:
            for name, value in rdn:
                subject_parts.append(f"{name}={value}")
        info['subject'] = ', '.join(subject_parts)

    if 'issuer' in cert:
        issuer_parts = []
        for rdn in cert['issuer']:
            for name, value in rdn:
                issuer_parts.append(f"{name}={value}")
        info['issuer'] = ', '.join(issuer_parts)

    if 'notBefore' in cert:
        info['not_before'] = cert['notBefore']
    if 'notAfter' in cert:
        info['not_after'] = cert['notAfter']

    if 'subjectAltName' in cert:
        san_list = []
        for san_type, san_value in cert['subjectAltName']:
            san_list.append(f"{san_type}:{san_value}")
        info['subject_alt_names'] = san_list

    return info


def _extract_kex_from_cipher(cipher_name: Optional[str]) -> Optional[str]:
    """Try to extract key exchange info from cipher name.

    Cipher names often contain key exchange algorithm info, e.g.:
    - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 -> ECDHE
    - TLS_AES_256_GCM_SHA384 (TLS 1.3) -> Uses groups from supported_groups
    """
    if not cipher_name:
        return None

    upper_name = cipher_name.upper()

    # TLS 1.3 ciphersuites don't include KEX in name
    if cipher_name.startswith("TLS_AES") or cipher_name.startswith("TLS_CHACHA20"):
        return "TLS 1.3 key exchange (check supported_groups)"

    # TLS 1.2 and earlier
    if "ECDHE" in upper_name:
        return "ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)"
    if "DHE" in upper_name:
        return "DHE (Diffie-Hellman Ephemeral)"
    if "ECDH" in upper_name:
        return "ECDH (Elliptic Curve Diffie-Hellman)"
    if "DH" in upper_name:
        return "DH (Diffie-Hellman)"
    if "RSA" in upper_name:
        return "RSA key exchange"

    return "Unknown"


def _try_detect_protocol(target_ip: str, port: int, timeout: float) -> Optional[str]:
    """Try to detect what protocol is actually running on the port.

    Args:
        target_ip: Target IP
        port: Port number
        timeout: Timeout in seconds

    Returns:
        Protocol name if detected, None otherwise
    """
    try:
        sock = socket.create_connection((target_ip, port), timeout=timeout)
        sock.settimeout(timeout)

        # Try to read initial banner
        try:
            banner = sock.recv(1024)
        except socket.timeout:
            # Try sending HTTP GET request to see if it's HTTP
            sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
            response = sock.recv(1024)
            if b"HTTP/" in response:
                return "HTTP (plain, not HTTPS)"
            return None

        banner_str = banner.decode('utf-8', errors='ignore').strip()

        # Check for common protocol banners
        if banner_str.startswith("SSH-"):
            return f"SSH ({banner_str})"
        elif banner_str.startswith("220 ") or banner_str.startswith("220-"):
            return "SMTP"
        elif banner_str.startswith("+OK"):
            return "POP3"
        elif banner_str.startswith("* OK"):
            return "IMAP"
        elif banner_str.startswith("220 "):
            return "FTP"
        elif b"HTTP/" in banner:
            return "HTTP (plain, not HTTPS)"
        elif len(banner_str) > 0:
            return f"Unknown protocol (banner: {banner_str[:50]}...)"

        sock.close()

    except Exception:
        pass

    return None


def _classify_tls_connection(result: ProbeResult) -> str:
    """Classify PQ status of TLS connection.

    Note: Python's ssl module doesn't expose negotiated groups directly.
    We make a best-effort classification based on available information.

    Returns:
        "Yes", "Hybrid", "No", or "Unknown"
    """
    # TLS 1.3 with modern OpenSSL *might* have negotiated PQ groups,
    # but we can't tell without deeper inspection
    if result.tls_version == "TLS 1.3":
        # Conservative: mark as Unknown unless we have specific info
        # In practice, most TLS 1.3 today is classical only
        return "Unknown (TLS 1.3 - groups not visible via Python ssl)"

    # TLS 1.2 and earlier are classical
    return "No"

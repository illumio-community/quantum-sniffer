"""Target parsing and expansion.

Handles various input formats:
- Single IP: "10.1.1.100"
- IP with port: "10.1.1.100:443"
- Hostname: "example.com"
- Hostname with port: "example.com:8443"
- CIDR subnet: "10.1.1.0/24"
- IP range: "10.1.1.1-10.1.1.50" or "10.1.1.1-50"
- Comma-separated list: "10.1.1.1,10.1.1.2,10.1.1.3"
"""

import ipaddress
import socket
from typing import Tuple, List, Optional
from dataclasses import dataclass


@dataclass
class Target:
    """Represents a probe target."""
    host: str  # IP address or hostname
    port: Optional[int] = None

    @property
    def is_ip(self) -> bool:
        """Check if host is a valid IP address."""
        try:
            ipaddress.ip_address(self.host)
            return True
        except ValueError:
            return False

    @property
    def resolved_ip(self) -> Optional[str]:
        """Resolve hostname to IP address."""
        if self.is_ip:
            return self.host
        try:
            return socket.gethostbyname(self.host)
        except socket.gaierror:
            return None


def parse_target(target_string: str) -> Target:
    """Parse target string into Target object.

    Args:
        target_string: Target in various formats:
            - "10.1.1.100"
            - "10.1.1.100:443"
            - "example.com"
            - "example.com:8443"

    Returns:
        Target object

    Raises:
        ValueError: If target string is invalid
    """
    if not target_string:
        raise ValueError("Target string cannot be empty")

    # Check for port specification
    if ":" in target_string:
        host, port_str = target_string.rsplit(":", 1)
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port must be 1-65535, got {port}")
        except ValueError as e:
            raise ValueError(f"Invalid port in target '{target_string}': {e}")
        return Target(host=host, port=port)

    return Target(host=target_string, port=None)


def expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR notation to list of IP addresses.

    Args:
        cidr: CIDR notation (e.g., "10.1.1.0/24")

    Returns:
        List of IP address strings

    Example:
        >>> expand_cidr("10.1.1.0/30")
        ['10.1.1.0', '10.1.1.1', '10.1.1.2', '10.1.1.3']
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        raise ValueError(f"Invalid CIDR notation: {cidr}")


def expand_range(range_str: str) -> List[str]:
    """Expand IP range to list of IP addresses.

    Args:
        range_str: IP range in formats:
            - "10.1.1.1-10.1.1.50" (full range)
            - "10.1.1.1-50" (shorthand - same first 3 octets)

    Returns:
        List of IP address strings

    Example:
        >>> expand_range("10.1.1.1-5")
        ['10.1.1.1', '10.1.1.2', '10.1.1.3', '10.1.1.4', '10.1.1.5']
    """
    if '-' not in range_str:
        raise ValueError(f"Invalid range format: {range_str}")

    start_str, end_str = range_str.split('-', 1)
    start_str = start_str.strip()
    end_str = end_str.strip()

    # Parse start IP
    try:
        start_ip = ipaddress.ip_address(start_str)
    except ValueError:
        raise ValueError(f"Invalid start IP: {start_str}")

    # Parse end (could be full IP or just last octet)
    if '.' in end_str:
        # Full IP
        try:
            end_ip = ipaddress.ip_address(end_str)
        except ValueError:
            raise ValueError(f"Invalid end IP: {end_str}")
    else:
        # Just last octet
        try:
            last_octet = int(end_str)
            if not (0 <= last_octet <= 255):
                raise ValueError(f"Invalid octet: {last_octet}")
            # Reconstruct IP with new last octet
            parts = start_str.split('.')
            parts[-1] = str(last_octet)
            end_ip = ipaddress.ip_address('.'.join(parts))
        except ValueError as e:
            raise ValueError(f"Invalid range end: {end_str} - {e}")

    # Generate range
    if start_ip > end_ip:
        raise ValueError(f"Start IP {start_ip} is greater than end IP {end_ip}")

    result = []
    current = int(start_ip)
    end = int(end_ip)
    while current <= end:
        result.append(str(ipaddress.ip_address(current)))
        current += 1

    return result


def expand_list(list_str: str) -> List[str]:
    """Expand comma-separated list of IPs.

    Args:
        list_str: Comma-separated IPs (e.g., "10.1.1.1,10.1.1.2,10.1.1.3")

    Returns:
        List of IP address strings
    """
    ips = []
    for part in list_str.split(','):
        part = part.strip()
        if not part:
            continue
        # Validate IP
        try:
            ipaddress.ip_address(part)
            ips.append(part)
        except ValueError:
            raise ValueError(f"Invalid IP in list: {part}")
    return ips


def expand_targets(target_string: str) -> List[Target]:
    """Expand target string into list of targets.

    Supports:
    - Single IP: "10.1.1.100"
    - IP with port: "10.1.1.100:443"
    - Hostname: "example.com"
    - Hostname with port: "example.com:8443"
    - CIDR subnet: "10.1.1.0/24"
    - IP range: "10.1.1.1-10.1.1.50" or "10.1.1.1-50"
    - Comma-separated: "10.1.1.1,10.1.1.2,10.1.1.3"

    Args:
        target_string: Target specification

    Returns:
        List of Target objects

    Raises:
        ValueError: If target string is invalid
    """
    target_string = target_string.strip()

    # Check for port specification first
    port = None
    if ':' in target_string and not target_string.count(':') > 1:
        # Might be "IP:port" or "host:port"
        # But NOT IPv6 (which has multiple colons)
        parts = target_string.rsplit(':', 1)
        try:
            port = int(parts[1])
            if 1 <= port <= 65535:
                target_string = parts[0]
            else:
                port = None
        except ValueError:
            port = None

    # CIDR notation
    if '/' in target_string:
        ips = expand_cidr(target_string)
        return [Target(host=ip, port=port) for ip in ips]

    # IP range
    if '-' in target_string and ',' not in target_string:
        ips = expand_range(target_string)
        return [Target(host=ip, port=port) for ip in ips]

    # Comma-separated list
    if ',' in target_string:
        ips = expand_list(target_string)
        return [Target(host=ip, port=port) for ip in ips]

    # Single target (IP or hostname)
    if port:
        return [Target(host=target_string, port=port)]
    else:
        return [parse_target(target_string)]

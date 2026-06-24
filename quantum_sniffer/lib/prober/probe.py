"""Main probing orchestration logic."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional, Callable

from .results import ProbeResult
from .targets import Target, parse_target, expand_targets
from .tls_probe import probe_tls
from .ssh_probe import probe_ssh
from .starttls_probe import probe_starttls
from .ikev2_probe import probe_ikev2


# Default ports to scan (protocol will be auto-detected)
DEFAULT_PORTS = [
    # TLS/HTTPS
    443, 8443, 4443, 9443,
    # SSH
    22,
    # STARTTLS-capable
    25, 587,  # SMTP
    143,      # IMAP
    110,      # POP3
    21,       # FTP
    # 389,    # LDAP (not yet fully implemented)
    # DNS over TLS
    853,
    # LDAPS (TLS)
    636,
    # Other TLS
    989, 990,  # FTPS
    992,       # Telnets
    993,       # IMAPS
    995,       # POP3S
    5061,      # SIPS
    # IKEv2/IPsec
    500, 4500,
]

# Port to protocol mapping
PORT_PROTOCOL_MAP = {
    22: "ssh",
    25: "starttls-smtp",
    587: "starttls-smtp",
    143: "starttls-imap",
    110: "starttls-pop3",
    21: "starttls-ftp",
    389: "starttls-ldap",
    500: "ikev2",
    4500: "ikev2",
    # All others default to TLS
}


def probe_target(
    target: str,
    ports: Optional[List[int]] = None,
    timeout: float = 5.0,
    max_workers: int = 10,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> List[ProbeResult]:
    """Probe target(s) on specified ports for PQ crypto capabilities.

    Supports multiple target formats:
    - Single IP: "10.1.1.100"
    - IP with port: "10.1.1.100:443"
    - Hostname: "example.com"
    - CIDR subnet: "10.1.1.0/24"
    - IP range: "10.1.1.1-10.1.1.50" or "10.1.1.1-50"
    - Comma-separated: "10.1.1.1,10.1.1.2,10.1.1.3"

    When multiple targets are specified (subnet/range/list), probing
    is parallelized using thread pool.

    Args:
        target: Target specification (see formats above)
        ports: List of ports to probe. If None, uses DEFAULT_TLS_PORTS
        timeout: Connection timeout in seconds
        max_workers: Maximum number of parallel probe threads (default: 10)
        progress_callback: Optional callback function(completed, total) for progress tracking

    Returns:
        List of ProbeResult objects (aggregated for all targets and ports)

    Example:
        # Probe single target
        results = probe_target("10.1.1.100:443")

        # Probe subnet
        results = probe_target("10.1.1.0/24", ports=[443])

        # Probe range with progress
        def show_progress(done, total):
            print(f"Progress: {done}/{total}")
        results = probe_target("10.1.1.1-20", ports=[443], progress_callback=show_progress)
    """
    # Expand targets (handles CIDR, ranges, lists, single targets)
    target_objs = expand_targets(target)

    # Resolve hostnames and determine IPs
    # Keep track of hostname for SNI support
    targets_with_ips = []
    for target_obj in target_objs:
        if not target_obj.is_ip:
            resolved_ip = target_obj.resolved_ip
            if not resolved_ip:
                # Can't resolve - add error result
                continue
            target_ip = resolved_ip
            # Keep original hostname for SNI
            hostname = target_obj.host
        else:
            target_ip = target_obj.host
            hostname = None  # No hostname, just IP

        targets_with_ips.append((target_ip, target_obj.port, hostname))

    # Determine ports to probe
    if target_objs and target_objs[0].port:
        # Port specified in target string
        ports_to_probe = [target_objs[0].port]
    elif ports:
        ports_to_probe = ports
    else:
        ports_to_probe = DEFAULT_PORTS

    # Build list of (ip, port, hostname) tuples to probe
    jobs = []
    for target_ip, _, hostname in targets_with_ips:
        for port in ports_to_probe:
            jobs.append((target_ip, port, hostname))

    # Probe in parallel
    results = []
    completed = 0
    total = len(jobs)

    if total == 0:
        return results

    # Use ThreadPoolExecutor for parallel probing
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all jobs (protocol auto-detected per port)
        future_to_job = {
            executor.submit(_probe_single, ip, port, timeout, hostname): (ip, port)
            for ip, port, hostname in jobs
        }

        # Collect results as they complete
        for future in as_completed(future_to_job):
            result = future.result()
            results.append(result)
            completed += 1

            if progress_callback:
                progress_callback(completed, total)

    return results


def probe_ports(
    ip: str,
    ports: List[int],
    timeout: float = 5.0
) -> List[ProbeResult]:
    """Probe specific ports on an IP address.

    Convenience function when you already have an IP and port list.
    Protocol is auto-detected based on port number.

    Args:
        ip: IP address to probe
        ports: List of ports to probe
        timeout: Connection timeout in seconds

    Returns:
        List of ProbeResult objects
    """
    results = []
    for port in ports:
        result = _probe_single(ip, port, timeout)
        results.append(result)
    return results


def _probe_single(ip: str, port: int, timeout: float, hostname: Optional[str] = None) -> ProbeResult:
    """Probe a single IP:port with protocol auto-detection.

    Args:
        ip: IP address
        port: Port number
        timeout: Timeout in seconds
        hostname: Original hostname (for SNI support in TLS)

    Returns:
        ProbeResult
    """
    # Determine protocol based on port
    protocol = PORT_PROTOCOL_MAP.get(port, "tls")

    # Route to appropriate prober
    if protocol == "ssh":
        return probe_ssh(ip, port, timeout)
    elif protocol.startswith("starttls"):
        return probe_starttls(ip, port, timeout)
    elif protocol == "ikev2":
        return probe_ikev2(ip, port, timeout)
    else:
        # Default to TLS (pass hostname for SNI)
        return probe_tls(ip, port, timeout, server_hostname=hostname)

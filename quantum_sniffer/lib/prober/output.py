"""Output formatters for probe results."""

import ipaddress
import json
import socket
from datetime import datetime
from typing import List, Optional, Dict, Any

from .results import ProbeResult, PortStatus


def get_hostname() -> str:
    """Get local hostname."""
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def get_local_ip() -> str:
    """Get local IP address (best effort)."""
    try:
        # Connect to an external IP to determine which interface would be used
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "unknown"


def create_metadata(
    target: str,
    ports: Optional[List[int]],
    timeout: float,
    start_time: str,
    end_time: str,
    duration_seconds: float,
    command_line: Optional[str] = None,
) -> Dict[str, Any]:
    """Create scan metadata."""
    return {
        "scan_info": {
            "source_hostname": get_hostname(),
            "source_ip": get_local_ip(),
            "target": target,
            "ports_scanned": ports or "default TLS ports",
            "timeout_seconds": timeout,
            "command_line": command_line or "quantum-sniffer (library mode)",
        },
        "timing": {
            "start_time": start_time,
            "end_time": end_time,
            "duration_seconds": round(duration_seconds, 3),
        },
    }


def generate_json_report(
    results: List[ProbeResult],
    target: str,
    ports: Optional[List[int]],
    timeout: float,
    start_time: str,
    end_time: str,
    duration_seconds: float,
    command_line: Optional[str] = None,
) -> str:
    """Generate JSON report with metadata and results.

    Args:
        results: List of probe results
        target: Target string (IP, hostname, etc.)
        ports: List of ports scanned (None = defaults)
        timeout: Timeout used
        start_time: Scan start time (ISO format)
        end_time: Scan end time (ISO format)
        duration_seconds: Total scan duration
        command_line: CLI command used

    Returns:
        JSON string
    """
    # Calculate summary statistics
    total_ports = len(results)
    open_ports = sum(1 for r in results if r.status == PortStatus.OPEN)
    pq_capable = sum(1 for r in results if r.status == PortStatus.OPEN and r.is_pq_capable)

    # Build report structure
    report = {
        "metadata": create_metadata(
            target, ports, timeout, start_time, end_time, duration_seconds, command_line
        ),
        "summary": {
            "total_ports_scanned": total_ports,
            "open_ports": open_ports,
            "closed_ports": sum(1 for r in results if r.status == PortStatus.CLOSED),
            "filtered_ports": sum(1 for r in results if r.status == PortStatus.FILTERED),
            "timeout_ports": sum(1 for r in results if r.status == PortStatus.TIMEOUT),
            "error_ports": sum(1 for r in results if r.status == PortStatus.ERROR),
            "pq_capable_ports": pq_capable,
        },
        "results": [r.to_dict() for r in results],
    }

    return json.dumps(report, indent=2, sort_keys=False)


def generate_markdown_report(
    results: List[ProbeResult],
    target: str,
    ports: Optional[List[int]],
    timeout: float,
    start_time: str,
    end_time: str,
    duration_seconds: float,
    command_line: Optional[str] = None,
) -> str:
    """Generate Markdown report with metadata and results.

    Args:
        results: List of probe results
        target: Target string
        ports: List of ports scanned
        timeout: Timeout used
        start_time: Scan start time (ISO format)
        end_time: Scan end time (ISO format)
        duration_seconds: Total scan duration
        command_line: CLI command used

    Returns:
        Markdown string
    """
    lines = []

    # Header
    lines.append("# Quantum-Sniffer Probe Report")
    lines.append("")

    # Scan Information
    lines.append("## Scan Information")
    lines.append("")
    lines.append(f"**Source Hostname**: {get_hostname()}")
    lines.append(f"**Source IP**: {get_local_ip()}")
    lines.append(f"**Target**: {target}")
    if ports:
        lines.append(f"**Ports**: {', '.join(map(str, ports))}")
    else:
        lines.append("**Ports**: Default TLS ports (443, 8443, 636, 993, 995, etc.)")
    lines.append(f"**Timeout**: {timeout}s")
    if command_line:
        lines.append(f"**Command**: `{command_line}`")
    lines.append("")

    # Timing
    lines.append("## Timing")
    lines.append("")
    lines.append(f"**Start Time**: {start_time}")
    lines.append(f"**End Time**: {end_time}")
    lines.append(f"**Duration**: {duration_seconds:.3f}s")
    lines.append("")

    # Summary
    total_ports = len(results)
    open_ports = sum(1 for r in results if r.status == PortStatus.OPEN)
    pq_capable = sum(1 for r in results if r.status == PortStatus.OPEN and r.is_pq_capable)

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total Ports Scanned**: {total_ports}")
    lines.append(f"- **Open**: {open_ports}")
    lines.append(f"- **Closed**: {sum(1 for r in results if r.status == PortStatus.CLOSED)}")
    lines.append(f"- **Filtered**: {sum(1 for r in results if r.status == PortStatus.FILTERED)}")
    lines.append(f"- **Timeout**: {sum(1 for r in results if r.status == PortStatus.TIMEOUT)}")
    lines.append(f"- **Error**: {sum(1 for r in results if r.status == PortStatus.ERROR)}")
    if open_ports > 0:
        lines.append(f"- **PQ-Capable**: {pq_capable}/{open_ports}")
    lines.append("")

    # Results grouped by host
    lines.append("## Results by Host")
    lines.append("")

    # Group results by target IP
    from collections import defaultdict
    by_host = defaultdict(list)
    for r in results:
        by_host[r.target_ip].append(r)

    # Sort hosts by IP address
    def _host_key(host):
        try:
            addr = ipaddress.ip_address(host)
            return (0, addr.version, int(addr), "")
        except ValueError:
            return (1, 0, 0, host)

    sorted_hosts = sorted(by_host.keys(), key=_host_key)

    for host_ip in sorted_hosts:
        host_results = by_host[host_ip]

        # Count statuses for this host
        open_count = sum(1 for r in host_results if r.status == PortStatus.OPEN)
        pq_count = sum(1 for r in host_results if r.status == PortStatus.OPEN and r.is_pq_capable)

        # Host header with summary
        lines.append(f"### {host_ip}")
        lines.append("")
        summary = f"**Open Ports**: {open_count}/{len(host_results)}"
        if open_count > 0:
            summary += f" | **PQ-Capable**: {pq_count}/{open_count}"
        lines.append(summary)
        lines.append("")

        # Separate by status
        open_results = [r for r in host_results if r.status == PortStatus.OPEN]
        closed_results = [r for r in host_results if r.status == PortStatus.CLOSED]
        other_results = [r for r in host_results if r.status not in (PortStatus.OPEN, PortStatus.CLOSED)]

        # Open ports table
        if open_results:
            lines.append("#### Open Ports")
            lines.append("")
            lines.append("| Port | Protocol | TLS Version | Cipher Suite | PQ Status |")
            lines.append("|------|----------|-------------|--------------|-----------|")
            for r in sorted(open_results, key=lambda x: x.target_port):
                pq_icon = "✓" if r.is_pq_capable else "✗"
                protocol = r.protocol or "unknown"
                lines.append(
                    f"| {r.target_port} | {protocol} | "
                    f"{r.tls_version or 'N/A'} | "
                    f"{r.cipher_suite or 'N/A'} | "
                    f"{pq_icon} {r.post_quantum_secure or 'Unknown'} |"
                )
            lines.append("")

            # Detailed info for each open port
            for r in sorted(open_results, key=lambda x: x.target_port):
                lines.append(f"**Port {r.target_port} Details:**")
                lines.append("")
                if r.protocol:
                    lines.append(f"- **Protocol**: {r.protocol}")
                if r.tls_version:
                    lines.append(f"- **TLS Version**: {r.tls_version}")
                if r.cipher_suite:
                    lines.append(f"- **Cipher Suite**: {r.cipher_suite}")
                if r.key_exchange_group:
                    lines.append(f"- **Key Exchange**: {r.key_exchange_group}")
                lines.append(f"- **PQ Status**: {r.post_quantum_secure or 'Unknown'}")
                if r.server_name:
                    lines.append(f"- **Server Name**: {r.server_name}")
                if r.certificate_info:
                    cert = r.certificate_info
                    lines.append("- **Certificate**:")
                    if 'subject' in cert:
                        lines.append(f"  - Subject: {cert['subject']}")
                    if 'issuer' in cert:
                        lines.append(f"  - Issuer: {cert['issuer']}")
                    if 'not_after' in cert:
                        lines.append(f"  - Expires: {cert['not_after']}")
                if hasattr(r, 'extras') and r.extras:
                    if 'ssh_banner' in r.extras:
                        lines.append(f"- **SSH Banner**: {r.extras['ssh_banner']}")
                    if 'ssh_kex_algorithms' in r.extras:
                        kex_list = r.extras['ssh_kex_algorithms'][:5]  # First 5
                        lines.append(f"- **SSH KEX Algorithms**: {', '.join(kex_list)}")
                if r.probe_duration_ms is not None:
                    lines.append(f"- **Probe Duration**: {r.probe_duration_ms:.2f}ms")
                lines.append("")

        # Closed ports (compact)
        if closed_results:
            closed_ports = sorted([r.target_port for r in closed_results])
            lines.append("#### Closed Ports")
            lines.append("")
            lines.append(f"{', '.join(map(str, closed_ports))}")
            lines.append("")

        # Other results (timeout, filtered, error)
        if other_results:
            lines.append("#### Other")
            lines.append("")
            lines.append("| Port | Status | Error |")
            lines.append("|------|--------|-------|")
            for r in sorted(other_results, key=lambda x: x.target_port):
                error_msg = r.error_message or ""
                lines.append(f"| {r.target_port} | {r.status.value} | {error_msg} |")
            lines.append("")

        lines.append("---")
        lines.append("")

    # Footer (the last host section already ends with a rule)
    if not sorted_hosts:
        lines.append("---")
        lines.append("")
    lines.append("*Generated by quantum-sniffer*")

    return "\n".join(lines)


def save_report(content: str, filename: str) -> None:
    """Save report content to file.

    Args:
        content: Report content (JSON or Markdown)
        filename: Output filename

    Raises:
        IOError: If file cannot be written
    """
    with open(filename, 'w') as f:
        f.write(content)

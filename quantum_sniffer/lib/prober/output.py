"""Output formatters for probe results."""

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

    # Results table
    lines.append("## Results")
    lines.append("")

    # Group by status
    open_results = [r for r in results if r.status == PortStatus.OPEN]
    closed_results = [r for r in results if r.status == PortStatus.CLOSED]
    other_results = [r for r in results if r.status not in (PortStatus.OPEN, PortStatus.CLOSED)]

    # Open ports (detailed)
    if open_results:
        lines.append("### Open Ports")
        lines.append("")
        lines.append("| Port | Status | TLS Version | Cipher Suite | PQ Status |")
        lines.append("|------|--------|-------------|--------------|-----------|")
        for r in open_results:
            pq_icon = "✓" if r.is_pq_capable else "✗"
            lines.append(
                f"| {r.target_port} | {r.status.value} | "
                f"{r.tls_version or 'N/A'} | "
                f"{r.cipher_suite or 'N/A'} | "
                f"{pq_icon} {r.post_quantum_secure or 'Unknown'} |"
            )
        lines.append("")

    # Closed ports (summary)
    if closed_results:
        lines.append("### Closed Ports")
        lines.append("")
        closed_ports_str = ", ".join(str(r.target_port) for r in closed_results)
        lines.append(f"Ports: {closed_ports_str}")
        lines.append("")

    # Other (filtered, timeout, error)
    if other_results:
        lines.append("### Other Results")
        lines.append("")
        lines.append("| Port | Status | Error |")
        lines.append("|------|--------|-------|")
        for r in other_results:
            error_msg = r.error_message or ""
            lines.append(f"| {r.target_port} | {r.status.value} | {error_msg} |")
        lines.append("")

    # Detailed results for open ports
    if open_results:
        lines.append("## Detailed Results (Open Ports)")
        lines.append("")
        for r in open_results:
            lines.append(f"### Port {r.target_port}")
            lines.append("")
            lines.append(f"- **Status**: {r.status.value}")
            lines.append(f"- **TLS Version**: {r.tls_version or 'N/A'}")
            lines.append(f"- **Cipher Suite**: {r.cipher_suite or 'N/A'}")
            lines.append(f"- **Key Exchange**: {r.key_exchange_group or 'N/A'}")
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
            lines.append(f"- **Probe Duration**: {r.probe_duration_ms:.2f}ms")
            lines.append("")

    # Footer
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

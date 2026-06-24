"""Command-line entry point."""

import argparse
import logging
import os
import sys
import warnings

from .output import DualWriter
from .capture import CaptureEngine


# Suppress scapy noise about GREASE cipher suites
warnings.filterwarnings("ignore", message=".*Unknown cipher suite.*")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy").setLevel(logging.ERROR)


DEFAULT_PORTS = [
    "tcp port 443", "tcp port 22", "tcp port 853",
    "tcp port 636", "tcp port 989", "tcp port 990",
    "tcp port 992", "tcp port 993", "tcp port 995",
    "tcp port 8883", "tcp port 5061", "tcp port 5060",
    "tcp port 445", "tcp port 3389", "tcp port 88",
    "tcp port 1194", "tcp port 5671", "tcp port 5672",
    "udp port 500", "udp port 4500", "udp port 443",
    "udp port 51820", "udp port 88", "udp port 161",
    "udp port 162", "udp port 1194", "udp port 1812",
    "udp port 1813", "udp port 53", "tcp port 53",
    "tcp port 179", "tcp port 4840", "tcp port 4843",
    "tcp port 8443", "tcp port 8444", "tcp port 9443",
    "tcp port 4433", "tcp port 4434", "tcp port 4444",
    "tcp port 2376", "tcp port 2377", "tcp port 6443",
    "tcp port 10250", "tcp port 10255",
    "tcp port 2379", "tcp port 2380",
    "tcp port 9200", "tcp port 9300", "tcp port 27017",
    "tcp port 6380",
    "tcp port 9090", "tcp port 9091", "tcp port 9093", "tcp port 9094",
    "tcp port 8080", "tcp port 8081", "tcp port 8888", "tcp port 8889",
    "tcp port 5000", "tcp port 5001",
    # Tor
    "tcp port 9001", "tcp port 9030", "tcp port 9050", "tcp port 9051", "tcp port 9150",
    # ZRTP / RTP ranges
    "udp portrange 5004-5005",
    "udp portrange 16384-32767",
]

PLAINTEXT_EXTRA_PORTS = [
    "tcp port 25", "tcp port 587",
    "tcp port 143", "tcp port 110",
    "tcp port 21",
    "tcp port 389",
    "tcp port 5432", "tcp port 3306",
]


def build_default_filter(encrypted_only):
    parts = list(DEFAULT_PORTS)
    if not encrypted_only:
        parts += PLAINTEXT_EXTRA_PORTS
    return " or ".join(parts)


def run_probe_mode(args):
    """Execute active probing mode."""
    import time
    from datetime import datetime
    from ..lib.prober import probe_target, PortStatus
    from ..lib.prober import generate_json_report, generate_markdown_report, save_report

    target = args.probe

    # Parse port list if provided
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError as e:
            print(f"ERROR: Invalid port specification: {e}", file=sys.stderr)
            return 1

    print(f"[*] quantum-sniffer - Active Probe Mode")
    print(f"[*] Target: {target}")
    if ports:
        print(f"[*] Ports: {', '.join(map(str, ports))}")
    else:
        print(f"[*] Ports: Default TLS ports")
    print(f"[*] Timeout: {args.timeout}s")
    print(f"[*] Workers: {args.workers}")
    if args.output_json:
        print(f"[*] JSON Output: {args.output_json}")
    if args.output_markdown:
        print(f"[*] Markdown Output: {args.output_markdown}")
    print()

    # Record timing and command line
    start_time = datetime.now()
    start_time_iso = start_time.isoformat()
    command_line = " ".join(sys.argv)

    # Progress callback
    def show_progress(completed, total):
        if total > 5:  # Only show progress for larger scans
            print(f"\r[*] Progress: {completed}/{total} probes completed", end="", flush=True)

    # Probe the target
    try:
        results = probe_target(
            target,
            ports=ports,
            timeout=args.timeout,
            max_workers=args.workers,
            progress_callback=show_progress,
        )
        # Clear progress line if shown
        if len(results) > 5:
            print()  # Newline after progress
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    # Record end time
    end_time = datetime.now()
    end_time_iso = end_time.isoformat()
    duration_seconds = (end_time - start_time).total_seconds()

    # Display results
    print("=" * 80)
    print("PROBE RESULTS")
    print("=" * 80)
    print()

    open_count = 0
    pq_capable_count = 0

    for result in results:
        status_symbol = {
            PortStatus.OPEN: "✓",
            PortStatus.CLOSED: "✗",
            PortStatus.FILTERED: "?",
            PortStatus.TIMEOUT: "⏱",
            PortStatus.ERROR: "!",
        }.get(result.status, "?")

        print(f"{status_symbol} {result.target_ip}:{result.target_port:<5} {result.status.value:10}", end="")

        if result.status == PortStatus.OPEN:
            open_count += 1

            # PQ status
            pq_status = result.post_quantum_secure or "Unknown"
            pq_symbol = "🔒" if result.is_pq_capable else "⚠️ "
            print(f" {pq_symbol} {pq_status:10}", end="")

            if result.is_pq_capable:
                pq_capable_count += 1

            # TLS version and cipher
            if result.tls_version:
                print(f" {result.tls_version}", end="")
            if result.cipher_suite:
                print(f", {result.cipher_suite}", end="")

        elif result.error_message:
            print(f" ({result.error_message})", end="")

        print()  # newline

    print()
    print("=" * 80)
    print(f"Summary: {open_count}/{len(results)} ports open")
    if open_count > 0:
        print(f"         {pq_capable_count}/{open_count} with PQ crypto support")
    print("=" * 80)

    # Detailed view for open ports
    open_results = [r for r in results if r.status == PortStatus.OPEN]
    if open_results:
        print()
        print("DETAILED RESULTS (Open Ports)")
        print("=" * 80)
        for result in open_results:
            print()
            print(f"Port: {result.target_port}")
            print(f"  TLS Version:       {result.tls_version or 'N/A'}")
            print(f"  Cipher Suite:      {result.cipher_suite or 'N/A'}")
            print(f"  Key Exchange:      {result.key_exchange_group or 'N/A'}")
            print(f"  PQ Status:         {result.post_quantum_secure or 'Unknown'}")
            if result.server_name:
                print(f"  Server Name:       {result.server_name}")
            if result.certificate_info:
                cert = result.certificate_info
                if 'subject' in cert:
                    print(f"  Cert Subject:      {cert['subject']}")
                if 'issuer' in cert:
                    print(f"  Cert Issuer:       {cert['issuer']}")
                if 'not_after' in cert:
                    print(f"  Cert Expires:      {cert['not_after']}")
            print(f"  Probe Duration:    {result.probe_duration_ms:.2f}ms")

    # Save to files if requested
    if args.output_json:
        try:
            json_content = generate_json_report(
                results=results,
                target=target,
                ports=ports,
                timeout=args.timeout,
                start_time=start_time_iso,
                end_time=end_time_iso,
                duration_seconds=duration_seconds,
                command_line=command_line,
            )
            save_report(json_content, args.output_json)
            print()
            print(f"[*] JSON report saved to: {args.output_json}")
        except Exception as e:
            print(f"\n[!] Failed to save JSON report: {e}", file=sys.stderr)

    if args.output_markdown:
        try:
            md_content = generate_markdown_report(
                results=results,
                target=target,
                ports=ports,
                timeout=args.timeout,
                start_time=start_time_iso,
                end_time=end_time_iso,
                duration_seconds=duration_seconds,
                command_line=command_line,
            )
            save_report(md_content, args.output_markdown)
            print()
            print(f"[*] Markdown report saved to: {args.output_markdown}")
        except Exception as e:
            print(f"\n[!] Failed to save Markdown report: {e}", file=sys.stderr)

    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="quantum-sniffer",
        description="quantum-sniffer — post-quantum-aware network handshake inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Output format: Dual output to both CSV and JSONL files. JSONL contains complete
event data (use jq -s for array or jq -c for line filtering). CSV contains
flattened records with core fields for spreadsheet analysis.

PCAP mode: -r/--read takes a .pcap or .pcapng file and runs all analyzers
offline. Useful for regression testing and replaying captures.

Filter precedence: --bpf overrides the built-in port list; --host narrows
whatever filter is in effect to a single host.

Post-quantum classification:
  Yes     PQ-safe KEX confirmed
  Hybrid  PQ + classical (transition mode)
  No      classical only — harvest-now-decrypt-later risk
  Unknown cannot determine from observable handshake
        """,
    )
    parser.add_argument(
        "-o", "--output",
        help="Base filename for output logs (writes both .csv and .jsonl). "
             "Extensions are added automatically. Defaults to 'quantum-log' if not specified. "
             "Ignored by --find-sarah-connor.",
    )
    parser.add_argument(
        "-i", "--interface",
        help="Network interface to capture on (live mode)",
    )
    parser.add_argument(
        "-r", "--read",
        help="Read packets from a .pcap/.pcapng file instead of capturing live",
    )
    parser.add_argument(
        "-a", "--all", action="store_true",
        help="Include unencrypted protocols (default: encrypted only)",
    )
    parser.add_argument(
        "--bpf",
        help="Override the built-in BPF filter with a custom expression",
    )
    parser.add_argument(
        "--host",
        help="Restrict capture to a single host (added to BPF as 'and host X')",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Re-raise analyzer exceptions instead of logging them",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress per-event console output (still writes JSONL)",
    )
    parser.add_argument(
        "--find-sarah-connor", metavar="CAPTURE.jsonl", dest="find_sarah_connor",
        help="Skynet readiness report: how many sessions in a capture would be "
             "decryptable by a quantum computer (i.e., harvest-now-decrypt-later "
             "exposure)",
    )
    parser.add_argument(
        "--with-skull", action="store_true",
        help="Include ASCII skull in --find-sarah-connor output",
    )
    parser.add_argument(
        "--probe", metavar="TARGET",
        help="Active probe mode: test TARGET for PQ crypto support. "
             "Supports: single IP, hostname, CIDR (10.1.1.0/24), "
             "range (10.1.1.1-50), list (10.1.1.1,10.1.1.2). "
             "Scans default TLS ports unless --ports specified. "
             "Example: --probe 10.1.1.0/24",
    )
    parser.add_argument(
        "--ports", metavar="PORT[,PORT...]",
        help="Ports to probe (comma-separated). Only used with --probe. "
             "Example: --ports 443,8443,9443",
    )
    parser.add_argument(
        "--timeout", type=float, default=5.0,
        help="Connection timeout for probing in seconds (default: 5.0)",
    )
    parser.add_argument(
        "--output-json", metavar="FILE",
        help="Save probe results to JSON file with metadata",
    )
    parser.add_argument(
        "--output-markdown", metavar="FILE",
        help="Save probe results to Markdown report with metadata",
    )
    parser.add_argument(
        "--workers", type=int, default=10,
        help="Number of parallel probe workers for subnet/range scans (default: 10)",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    # Handle probe mode
    if args.probe:
        return run_probe_mode(args)

    # Handle Skynet report mode
    if args.find_sarah_connor:
        from . import skynet
        skynet.run(args.find_sarah_connor, show_skull=args.with_skull)
        return 0

    if args.interface and args.read:
        parser.error("--interface and --read are mutually exclusive")

    # Default output name if not specified
    output_base = args.output if args.output else "quantum-log"

    encrypted_only = not args.all
    if args.bpf:
        bpf = args.bpf
    else:
        bpf = build_default_filter(encrypted_only)
    if args.host:
        bpf = f"({bpf}) and host {args.host}"

    writer = DualWriter(output_base)
    engine = CaptureEngine(writer, encrypted_only=encrypted_only, debug=args.debug, quiet=args.quiet)

    print(f"[*] quantum-sniffer")
    print(f"[*] Output:    {writer.csv_path} + {writer.jsonl_path}")
    print(f"[*] Mode:      {'encrypted only' if encrypted_only else 'all protocols'}")
    if args.read:
        print(f"[*] Reading:   {args.read}")
    else:
        print(f"[*] Interface: {args.interface or 'default'}")
    print(f"[*] Filter:    {bpf[:120]}{'...' if len(bpf) > 120 else ''}")
    if args.debug:
        print(f"[*] Debug mode: analyzer exceptions will re-raise")
    print(f"[*] Press Ctrl+C to stop\n")

    # Import scapy lazily so --help works without root and without scapy installed
    try:
        from scapy.all import sniff
    except ImportError:
        print("ERROR: scapy not installed.  pip install scapy", file=sys.stderr)
        return 1

    try:
        if args.read:
            sniff(offline=args.read, filter=bpf, prn=engine.process_packet, store=False)
        else:
            sniff(iface=args.interface, filter=bpf, prn=engine.process_packet, store=False)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("ERROR: Live capture requires root.  Run with sudo.", file=sys.stderr)
        writer.close()
        return 1
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        if args.debug:
            raise
        writer.close()
        return 1

    writer.close()
    summary = engine.summary()
    print(f"\n[*] Captured {summary['events']} events")
    print(f"[*] CSV:     {writer.csv_path}")
    print(f"[*] JSONL:   {writer.jsonl_path}")
    if summary["events"]:
        print("\n[*] Protocols:")
        for p, cnt in summary["protocols"].items():
            print(f"    {p}: {cnt}")
        print("\n[*] Post-Quantum:")
        for status in ("Yes", "Hybrid", "No", "Unknown"):
            print(f"    {status:8} {summary['post_quantum'].get(status, 0)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

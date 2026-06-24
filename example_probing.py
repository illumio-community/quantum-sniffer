#!/usr/bin/env python3
"""Example: Using quantum-sniffer's active probing feature.

Demonstrates how to probe targets for post-quantum crypto support.
"""

from quantum_sniffer.lib import probe_target, PortStatus


def example_simple_probe():
    """Simple single-target probe."""
    print("=" * 70)
    print("Example 1: Simple Probe")
    print("=" * 70)

    # Probe a single target
    results = probe_target("google.com:443", timeout=5.0)

    for r in results:
        print(f"\nTarget: {r.target_ip}:{r.target_port}")
        print(f"Status: {r.status.value}")

        if r.status == PortStatus.OPEN:
            print(f"TLS Version: {r.tls_version}")
            print(f"Cipher Suite: {r.cipher_suite}")
            print(f"PQ Status: {r.post_quantum_secure}")
            print(f"PQ Capable: {'Yes' if r.is_pq_capable else 'No'}")


def example_multi_port():
    """Probe multiple ports."""
    print("\n")
    print("=" * 70)
    print("Example 2: Multi-Port Probe")
    print("=" * 70)

    # Probe multiple ports
    results = probe_target("google.com", ports=[443, 8443], timeout=3.0)

    for r in results:
        status_icon = {
            PortStatus.OPEN: "✓",
            PortStatus.CLOSED: "✗",
            PortStatus.TIMEOUT: "⏱",
            PortStatus.FILTERED: "?",
            PortStatus.ERROR: "!",
        }.get(r.status, "?")

        print(f"{status_icon} Port {r.target_port}: {r.status.value}", end="")

        if r.status == PortStatus.OPEN:
            pq_icon = "🔒" if r.is_pq_capable else "⚠️"
            print(f" {pq_icon} {r.post_quantum_secure}")
        elif r.error_message:
            print(f" - {r.error_message}")
        else:
            print()


def example_batch_targets():
    """Probe multiple targets."""
    print("\n")
    print("=" * 70)
    print("Example 3: Batch Target Probe")
    print("=" * 70)

    targets = [
        "google.com:443",
        "cloudflare.com:443",
        "github.com:443",
    ]

    print("\nProbing targets for PQ crypto support...\n")

    summary = []
    for target in targets:
        results = probe_target(target, timeout=3.0)

        for r in results:
            if r.status == PortStatus.OPEN:
                summary.append({
                    'target': target,
                    'ip': r.target_ip,
                    'pq_status': r.post_quantum_secure,
                    'tls_version': r.tls_version,
                    'is_pq': r.is_pq_capable,
                })

                pq_icon = "✓" if r.is_pq_capable else "✗"
                print(f"{pq_icon} {target:25} {r.post_quantum_secure:10} {r.tls_version}")

    # Summary
    print("\n" + "=" * 70)
    print(f"Probed {len(targets)} targets")
    pq_count = sum(1 for s in summary if s['is_pq'])
    print(f"PQ-capable: {pq_count}/{len(summary)}")
    print("=" * 70)


def example_with_error_handling():
    """Robust probing with error handling."""
    print("\n")
    print("=" * 70)
    print("Example 4: Error Handling")
    print("=" * 70)

    # Try to probe various targets (some may fail)
    test_targets = [
        "google.com:443",      # Should work
        "localhost:9999",      # Probably closed
        "invalid.example.com", # DNS will fail
    ]

    for target in test_targets:
        print(f"\nProbing {target}...")

        try:
            results = probe_target(target, timeout=2.0)

            for r in results:
                if r.status == PortStatus.OPEN:
                    print(f"  ✓ Open - {r.tls_version}, {r.post_quantum_secure}")
                elif r.status == PortStatus.CLOSED:
                    print(f"  ✗ Closed")
                elif r.status == PortStatus.TIMEOUT:
                    print(f"  ⏱ Timeout")
                elif r.status == PortStatus.ERROR:
                    print(f"  ! Error: {r.error_message}")
                else:
                    print(f"  ? {r.status.value}")

        except Exception as e:
            print(f"  ! Exception: {e}")


def example_detailed_analysis():
    """Extract detailed information from probe results."""
    print("\n")
    print("=" * 70)
    print("Example 5: Detailed Analysis")
    print("=" * 70)

    results = probe_target("github.com:443", timeout=5.0)

    for r in results:
        if r.status != PortStatus.OPEN:
            print(f"Port {r.target_port} not open")
            continue

        print(f"\nDetailed Analysis for {r.target_ip}:{r.target_port}")
        print("-" * 70)
        print(f"Protocol:         {r.protocol}")
        print(f"TLS Version:      {r.tls_version}")
        print(f"Cipher Suite:     {r.cipher_suite}")
        print(f"Key Exchange:     {r.key_exchange_group}")
        print(f"PQ Status:        {r.post_quantum_secure}")
        print(f"PQ Capable:       {r.is_pq_capable}")

        if r.server_name:
            print(f"Server Name:      {r.server_name}")

        if r.certificate_info:
            cert = r.certificate_info
            print("\nCertificate Information:")
            if 'subject' in cert:
                print(f"  Subject:        {cert['subject']}")
            if 'issuer' in cert:
                print(f"  Issuer:         {cert['issuer']}")
            if 'not_after' in cert:
                print(f"  Expires:        {cert['not_after']}")
            if 'subject_alt_names' in cert:
                print(f"  SANs:           {', '.join(cert['subject_alt_names'][:3])}")

        print(f"\nPerformance:")
        print(f"  Probe Duration: {r.probe_duration_ms:.2f}ms")

        # Convert to dict for serialization
        data = r.to_dict()
        print(f"\nSerialization:")
        print(f"  Can export to JSON: {len(data)} fields")


if __name__ == "__main__":
    print("\nQuantum-Sniffer Active Probing Examples")
    print("=" * 70)
    print()
    print("These examples demonstrate active probing for PQ crypto support.")
    print("Requires internet connection to probe public services.")
    print()

    try:
        example_simple_probe()
        example_multi_port()
        example_batch_targets()
        example_with_error_handling()
        example_detailed_analysis()

        print("\n" + "=" * 70)
        print("All examples completed successfully!")
        print("=" * 70)

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\n\nError running examples: {e}")
        import traceback
        traceback.print_exc()

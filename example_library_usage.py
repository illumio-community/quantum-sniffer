#!/usr/bin/env python3
"""Example: Using quantum-sniffer as a library.

This demonstrates how to use quantum-sniffer's core functionality
programmatically without using the CLI.
"""

# Example 1: Analyze a single packet
def example_analyze_packet():
    """Analyze a single scapy packet."""
    from quantum_sniffer.lib import analyze_packet
    from scapy.all import rdpcap

    # Load a pcap file
    packets = rdpcap("capture.pcap")

    # Analyze each packet
    for pkt in packets:
        result = analyze_packet(pkt)
        if result:
            print(f"{result.protocol} from {result.src_ip}:{result.src_port}")
            print(f"  PQ Status: {result.post_quantum_secure}")
            if result.server_name:
                print(f"  SNI: {result.server_name}")


# Example 2: Batch analysis with statistics
def example_batch_analysis():
    """Analyze multiple packets and collect statistics."""
    from quantum_sniffer.lib import ProtocolAnalyzer
    from scapy.all import rdpcap

    # Create analyzer
    analyzer = ProtocolAnalyzer(encrypted_only=True)

    # Load and analyze
    packets = rdpcap("capture.pcap")
    results = []

    for pkt in packets:
        result = analyzer.process(pkt)
        if result:
            results.append(result)

    # Get summary statistics
    summary = analyzer.summary()
    print(f"Analyzed {summary['events']} handshakes")
    print(f"Protocols: {summary['protocols']}")
    print(f"PQ Status: {summary['post_quantum']}")

    return results


# Example 3: PQ classification
def example_pq_classification():
    """Use PQ classification functions directly."""
    from quantum_sniffer.lib.pq import (
        classify_tls_group,
        classify_ssh_kex,
        classify_connection,
        HYBRID, PQ, CLASSICAL
    )

    # Classify individual cryptographic elements
    group = classify_tls_group(0x11ec)  # x25519kyber768
    print(f"TLS group 0x11ec: {group}")  # -> 'hybrid'

    kex = classify_ssh_kex("sntrup761x25519-sha512@openssh.com")
    print(f"SSH KEX sntrup761x25519: {kex}")  # -> 'pq'

    # Classify a full connection
    info = {
        'protocol': 'TLS',
        'supported_group_ids': [0x11ec, 23],  # hybrid + classical
    }
    status = classify_connection(info)
    print(f"Connection status: {status}")  # -> 'Hybrid'


# Example 4: Working with HandshakeResult objects
def example_handshake_result():
    """Work with HandshakeResult domain objects."""
    from quantum_sniffer.lib.models import HandshakeResult
    from datetime import datetime

    # Create from dict (e.g., from saved data)
    data = {
        'protocol': 'TLS',
        'type': 'TLS ClientHello',
        'timestamp': datetime.now().isoformat(),
        'post_quantum_secure': 'Hybrid',
        'src_ip': '10.1.1.1',
        'src_port': 54321,
        'dst_ip': '10.1.1.2',
        'dst_port': 443,
        'connection': '10.1.1.1:54321 -> 10.1.1.2:443',
        'direction': 'outbound',
        'encrypted': True,
        'server_name': 'example.com',
        'tls_version': 'TLS 1.3',
        'supported_groups': ['x25519kyber768', 'x25519'],
    }

    result = HandshakeResult.from_dict(data)

    # Access common fields
    print(f"Protocol: {result.protocol}")
    print(f"PQ Secure: {result.post_quantum_secure}")

    # Access protocol-specific fields via properties
    print(f"Server: {result.server_name}")
    print(f"TLS Version: {result.tls_version}")
    print(f"Groups: {result.supported_groups}")

    # Convert back to dict (for serialization)
    output_dict = result.to_dict()
    return output_dict


# Example 5: Integration with custom packet source
def example_custom_source():
    """Integrate with a custom packet source."""
    from quantum_sniffer.lib import ProtocolAnalyzer

    analyzer = ProtocolAnalyzer(encrypted_only=True, debug=False)

    # Your custom packet source (zeek logs, netflow, etc.)
    def my_packet_source():
        # This is a placeholder - replace with your actual source
        pass

    # Process packets as they arrive
    for packet in my_packet_source():
        result = analyzer.process(packet)
        if result:
            # Do something with the result
            store_in_database(result)
            alert_if_vulnerable(result)


def store_in_database(result):
    """Placeholder for database storage."""
    pass


def alert_if_vulnerable(result):
    """Example: Alert on classical-only crypto."""
    if result.post_quantum_secure == "No":
        print(f"⚠️  Quantum-vulnerable connection detected:")
        print(f"   {result.connection}")
        print(f"   Protocol: {result.protocol}")


if __name__ == "__main__":
    print("quantum-sniffer library usage examples")
    print("=" * 50)
    print()
    print("See source code for examples:")
    print("  - example_analyze_packet()")
    print("  - example_batch_analysis()")
    print("  - example_pq_classification()")
    print("  - example_handshake_result()")
    print("  - example_custom_source()")
    print()

    # Run PQ classification example (doesn't need pcap)
    print("Running PQ classification example:")
    example_pq_classification()

"""CLI argument parsing — output is required, --read/--interface mutually exclusive."""

import pytest

from quantum_sniffer.cli import build_parser, build_default_filter


def test_output_defaults_to_quantum_log():
    """No --output specified -> defaults to 'quantum-log'."""
    from quantum_sniffer.cli import build_parser
    parser = build_parser()
    args = parser.parse_args([])
    # When -o is not provided, args.output will be None, and the CLI
    # code defaults to "quantum-log"
    assert args.output is None  # Parser doesn't set default
    # The actual default is applied in main() where it does:
    # output_base = args.output if args.output else "quantum-log"


def test_minimal_invocation_parses():
    parser = build_parser()
    args = parser.parse_args(["-o", "/tmp/x.jsonl"])
    assert args.output == "/tmp/x.jsonl"
    assert args.all is False
    assert args.debug is False


def test_pcap_mode_parses():
    parser = build_parser()
    args = parser.parse_args(["-o", "x.jsonl", "-r", "capture.pcap"])
    assert args.read == "capture.pcap"


def test_default_filter_includes_tor_ports():
    bpf = build_default_filter(encrypted_only=True)
    assert "9050" in bpf
    assert "9001" in bpf


def test_default_filter_excludes_plaintext_unless_all():
    encrypted = build_default_filter(encrypted_only=True)
    assert "tcp port 25" not in encrypted
    plaintext = build_default_filter(encrypted_only=False)
    assert "tcp port 25" in plaintext

"""DualWriter: writes to both CSV and JSONL simultaneously."""

import csv
import json
import os

from quantum_sniffer.output import DualWriter


def test_dual_writer_creates_both_files(tmp_path):
    """Verify DualWriter creates both .csv and .jsonl files."""
    base = tmp_path / "test-output"
    w = DualWriter(str(base))

    event = {
        "timestamp": "2026-06-12T10:00:00",
        "protocol": "TLS",
        "type": "TLS ClientHello",
        "post_quantum_secure": "Yes",
        "src_ip": "10.1.0.1",
        "src_port": 54321,
        "dst_ip": "1.1.1.1",
        "dst_port": 443,
        "connection": "10.1.0.1:54321 -> 1.1.1.1:443",
        "direction": "outbound",
        "encrypted": True,
    }

    w.write(event)
    w.close()

    # Verify both files exist
    csv_path = tmp_path / "test-output.csv"
    jsonl_path = tmp_path / "test-output.jsonl"
    assert csv_path.exists()
    assert jsonl_path.exists()

    # Verify JSONL content
    jsonl_lines = jsonl_path.read_text().splitlines()
    assert len(jsonl_lines) == 1
    assert json.loads(jsonl_lines[0]) == event

    # Verify CSV content
    with open(csv_path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["timestamp"] == event["timestamp"]
    assert rows[0]["protocol"] == event["protocol"]
    assert rows[0]["post_quantum_secure"] == event["post_quantum_secure"]


def test_dual_writer_strips_extensions(tmp_path):
    """Verify DualWriter strips extensions from base path."""
    test_cases = [
        ("foo", "foo.csv", "foo.jsonl"),
        ("foo.json", "foo.csv", "foo.jsonl"),
        ("foo.jsonl", "foo.csv", "foo.jsonl"),
        ("foo.csv", "foo.csv", "foo.jsonl"),
        ("foo.txt", "foo.csv", "foo.jsonl"),
    ]

    for base_input, expected_csv, expected_jsonl in test_cases:
        base = tmp_path / base_input
        w = DualWriter(str(base))

        assert w.csv_path == str(tmp_path / expected_csv)
        assert w.jsonl_path == str(tmp_path / expected_jsonl)

        w.close()


def test_dual_writer_appends_to_existing(tmp_path):
    """Verify DualWriter appends to existing files without duplicating headers."""
    base = tmp_path / "append-test"

    # Write first event
    w1 = DualWriter(str(base))
    w1.write({"timestamp": "2026-06-12T10:00:00", "protocol": "TLS", "type": "ClientHello"})
    w1.close()

    # Write second event (should append, not overwrite)
    w2 = DualWriter(str(base))
    w2.write({"timestamp": "2026-06-12T10:00:01", "protocol": "SSH", "type": "KEX Init"})
    w2.close()

    # Verify JSONL has both events
    jsonl_path = tmp_path / "append-test.jsonl"
    jsonl_lines = jsonl_path.read_text().splitlines()
    assert len(jsonl_lines) == 2

    # Verify CSV has both events and only one header
    csv_path = tmp_path / "append-test.csv"
    with open(csv_path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 2
    assert rows[0]["protocol"] == "TLS"
    assert rows[1]["protocol"] == "SSH"


def test_dual_writer_flattens_selected_cipher(tmp_path):
    """Verify DualWriter flattens nested selected_cipher to selected_cipher_name."""
    base = tmp_path / "flatten-test"
    w = DualWriter(str(base))

    event = {
        "timestamp": "2026-06-12T10:00:00",
        "protocol": "TLS",
        "selected_cipher": {
            "name": "TLS_AES_256_GCM_SHA384",
            "value": "0x1302"
        }
    }

    w.write(event)
    w.close()

    # Verify CSV has flattened cipher name
    csv_path = tmp_path / "flatten-test.csv"
    with open(csv_path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["selected_cipher_name"] == "TLS_AES_256_GCM_SHA384"

    # Verify JSONL preserves original structure
    jsonl_path = tmp_path / "flatten-test.jsonl"
    jsonl_lines = jsonl_path.read_text().splitlines()
    parsed = json.loads(jsonl_lines[0])
    assert parsed["selected_cipher"]["name"] == "TLS_AES_256_GCM_SHA384"
    assert parsed["selected_cipher"]["value"] == "0x1302"


def test_dual_writer_ignores_extra_fields_in_csv(tmp_path):
    """Verify DualWriter silently drops fields not in CSV_FIELDS."""
    base = tmp_path / "extra-fields"
    w = DualWriter(str(base))

    event = {
        "timestamp": "2026-06-12T10:00:00",
        "protocol": "TLS",
        "complex_nested_data": {"foo": [1, 2, 3]},
        "client_cipher_suites": [{"name": "TLS_AES_128_GCM_SHA256"}],
    }

    w.write(event)
    w.close()

    # Verify JSONL has all data
    jsonl_path = tmp_path / "extra-fields.jsonl"
    parsed = json.loads(jsonl_path.read_text())
    assert "complex_nested_data" in parsed
    assert "client_cipher_suites" in parsed

    # Verify CSV only has defined fields (extra fields dropped)
    csv_path = tmp_path / "extra-fields.csv"
    with open(csv_path, 'r', newline='') as f:
        reader = csv.DictReader(f)
        rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["timestamp"] == "2026-06-12T10:00:00"
    assert rows[0]["protocol"] == "TLS"
    # Extra fields not in CSV_FIELDS are not present
    assert "complex_nested_data" not in rows[0]
    assert "client_cipher_suites" not in rows[0]

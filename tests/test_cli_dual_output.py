"""CLI integration test for dual output functionality."""

import os
import subprocess
import tempfile
from pathlib import Path


def test_cli_default_output_name():
    """Verify CLI uses 'quantum-log' as default when -o is not specified."""
    # This test would require root for live capture, so we just verify
    # the help text reflects the default behavior
    result = subprocess.run(
        ["python3", "-m", "quantum_sniffer", "--help"],
        capture_output=True,
        text=True,
        cwd=Path(__file__).parent.parent
    )
    assert "quantum-log" in result.stdout
    assert "Defaults" in result.stdout


def test_cli_dual_output_extensions():
    """Verify various -o flag inputs produce .csv and .jsonl files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_cases = [
            ("mylog", "mylog.csv", "mylog.jsonl"),
            ("mylog.json", "mylog.csv", "mylog.jsonl"),
            ("mylog.jsonl", "mylog.csv", "mylog.jsonl"),
            ("mylog.csv", "mylog.csv", "mylog.jsonl"),
            ("output.txt", "output.csv", "output.jsonl"),
        ]

        for input_name, expected_csv, expected_jsonl in test_cases:
            # Use a synthetic test to verify the DualWriter path handling
            from quantum_sniffer.output import DualWriter

            output_path = os.path.join(tmpdir, input_name)
            writer = DualWriter(output_path)

            # Verify the paths are computed correctly
            assert writer.csv_path == os.path.join(tmpdir, expected_csv)
            assert writer.jsonl_path == os.path.join(tmpdir, expected_jsonl)

            writer.close()

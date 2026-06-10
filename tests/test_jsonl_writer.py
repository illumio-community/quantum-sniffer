"""JSONL writer: append-only, one event per line, no whole-file rewrite."""

import json
import os

from quantum_sniffer.output import JsonlWriter


def test_writer_appends_one_line_per_event(tmp_path):
    log = tmp_path / "out.jsonl"
    w = JsonlWriter(str(log))
    w.write({"a": 1})
    w.write({"b": 2})
    w.close()
    lines = log.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"a": 1}
    assert json.loads(lines[1]) == {"b": 2}


def test_writer_appends_to_existing_file(tmp_path):
    log = tmp_path / "out.jsonl"
    log.write_text('{"existing": true}\n')
    w = JsonlWriter(str(log))
    w.write({"new": True})
    w.close()
    lines = log.read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0]) == {"existing": True}
    assert json.loads(lines[1]) == {"new": True}

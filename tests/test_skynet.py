"""Tests for the --find-sarah-connor Skynet-readiness report."""

import json

from quantum_sniffer import skynet


def _write(path, events):
    with open(path, "w") as fh:
        for e in events:
            fh.write(json.dumps(e) + "\n")


def test_empty_capture_renders_future_not_written(tmp_path):
    log = tmp_path / "empty.jsonl"
    log.write_text("")
    out = skynet.render_report(skynet.load_events(str(log)))
    assert "FUTURE HAS NOT BEEN WRITTEN" in out


def test_classical_only_triggers_judgment_day_verdict(tmp_path):
    log = tmp_path / "classical.jsonl"
    _write(log, [
        {"protocol": "TLS", "post_quantum_secure": "No",
         "server_name": "cyberdyne.local", "timestamp": "2026-01-01T00:00:00",
         "dst_ip": "1.2.3.4"},
        {"protocol": "TLS", "post_quantum_secure": "No",
         "server_name": "cyberdyne.local", "timestamp": "2026-01-01T00:00:01",
         "dst_ip": "1.2.3.4"},
    ])
    out = skynet.render_report(skynet.load_events(str(log)))
    assert "JUDGMENT DAY IS INEVITABLE" in out
    assert "cyberdyne.local" in out
    assert "Sessions intercepted:    2" in out


def test_all_pq_triggers_resistance_verdict(tmp_path):
    log = tmp_path / "pq.jsonl"
    _write(log, [
        {"protocol": "TLS", "post_quantum_secure": "Yes",
         "timestamp": "2026-06-10T00:00:00"},
    ])
    out = skynet.render_report(skynet.load_events(str(log)))
    assert "COME WITH ME IF YOU WANT TO LIVE" in out


def test_hybrid_only_triggers_future_not_set(tmp_path):
    log = tmp_path / "hybrid.jsonl"
    _write(log, [
        {"protocol": "TLS", "post_quantum_secure": "Hybrid",
         "timestamp": "2026-06-10T00:00:00"},
    ])
    out = skynet.render_report(skynet.load_events(str(log)))
    assert "FUTURE IS NOT SET" in out


def test_majority_classical_with_some_pq_triggers_ill_be_back(tmp_path):
    log = tmp_path / "mixed.jsonl"
    _write(log, [
        {"protocol": "TLS", "post_quantum_secure": "No",
         "timestamp": "2026-06-10T00:00:00"},
        {"protocol": "TLS", "post_quantum_secure": "No",
         "timestamp": "2026-06-10T00:00:01"},
        {"protocol": "TLS", "post_quantum_secure": "No",
         "timestamp": "2026-06-10T00:00:02"},
        {"protocol": "TLS", "post_quantum_secure": "Yes",
         "timestamp": "2026-06-10T00:00:03"},
    ])
    out = skynet.render_report(skynet.load_events(str(log)))
    assert "I'LL BE BACK" in out


def test_per_protocol_breakdown_present(tmp_path):
    log = tmp_path / "mixed-protos.jsonl"
    _write(log, [
        {"protocol": "TLS", "post_quantum_secure": "No",
         "timestamp": "2026-06-10T00:00:00"},
        {"protocol": "WireGuard", "post_quantum_secure": "Hybrid",
         "timestamp": "2026-06-10T00:00:01"},
    ])
    out = skynet.render_report(skynet.load_events(str(log)))
    assert "EXPOSURE BY PROTOCOL" in out
    assert "TLS" in out and "WireGuard" in out

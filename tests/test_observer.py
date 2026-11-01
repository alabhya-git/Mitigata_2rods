from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import wrpcap

from mitigata.observer import analyze_capture


def test_independent_observer_counts_unapproved_tcp_and_udp(tmp_path):
    capture = tmp_path / "test.pcap"
    packets = [
        IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=50001, dport=8080, flags="S"),
        IP(src="127.0.0.1", dst="192.0.2.5") / TCP(sport=50002, dport=443, flags="S"),
        IP(src="127.0.0.1", dst="192.0.2.6") / UDP(sport=50003, dport=53),
    ]
    for packet in packets:
        packet.time = 11
    wrpcap(str(capture), packets)
    report = {
        "run": {
            "started": 10,
            "ended": 12,
            "status": "completed",
            "manifest": {"addresses": ["127.0.0.1"], "ports": [8080]},
        },
        "audit": [],
    }
    result = analyze_capture(
        capture,
        report,
        sources=["127.0.0.1"],
        metadata={"started": 9, "ended": 13, "interfaces": "any", "filter": "none"},
        log="0 packets dropped by kernel",
    )
    assert result["status"] == "measured"
    assert result["transmitted_scope_violations"] == 2


def test_partial_or_dropped_capture_cannot_claim_zero(tmp_path):
    capture = tmp_path / "partial.pcap"
    packet = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=50001, dport=8080, flags="S")
    packet.time = 11
    wrpcap(str(capture), [packet])
    report = {
        "run": {
            "started": 10,
            "ended": 12,
            "status": "completed",
            "manifest": {"addresses": ["127.0.0.1"], "ports": [8080]},
        }
    }
    result = analyze_capture(
        capture,
        report,
        sources=["127.0.0.1"],
        metadata={"started": 11, "ended": 13, "interfaces": "any", "filter": "none"},
        log="1 packets dropped by kernel",
    )
    assert result["status"] == "inconclusive"
    assert result["transmitted_scope_violations"] is None


def test_capture_scope_matches_ranges_exclusions_and_tcp_only_infrastructure(tmp_path):
    path = tmp_path / "ranges.pcap"
    packets = [
        IP(src="172.31.1.2", dst="192.168.56.10") / TCP(sport=50000, dport=8000, flags="S"),
        IP(src="172.31.1.2", dst="192.168.56.11") / TCP(sport=50001, dport=8000, flags="S"),
        IP(src="172.31.1.2", dst="127.0.0.1") / UDP(sport=50002, dport=9000),
    ]
    for p in packets:
        p.time = 11
    wrpcap(str(path), packets)
    report = {
        "run": {
            "started": 10,
            "ended": 12,
            "status": "completed",
            "manifest": {
                "mode": "DISCOVERY_ONLY",
                "addresses": ["192.168.56.0/24"],
                "ports": [],
                "port_ranges": ["1-65535"],
                "excluded_addresses": ["192.168.56.11/32"],
                "validation_infrastructure": {"address": "127.0.0.1", "port": 9000},
            },
        }
    }
    result = analyze_capture(
        path,
        report,
        sources=["172.31.1.2"],
        metadata={"started": 9, "ended": 13, "interfaces": "any", "filter": "none"},
        log="0 packets dropped by kernel",
    )
    assert result["status"] == "measured"
    assert result["transmitted_scope_violations"] == 2

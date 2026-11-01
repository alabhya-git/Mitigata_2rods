import json
import os
import signal
import subprocess
import sys
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import PcapReader

from mitigata.config import load_manifest
from mitigata.confinement import capture_session, install_policy, namespace_sources, supervise, wait_observer


def main():
    manifest = load_manifest("/scope/fixture.yaml")
    receipt = install_policy(manifest)
    results = Path("/results")
    results.mkdir(exist_ok=True)
    os.chown(results, 10001, 10001)
    capture = results / "kernel-capture"
    previous_session = capture_session(capture)
    observer = subprocess.Popen([sys.executable, "-m", "mitigata", "capture", "--output", str(capture)])
    try:
        session = wait_observer(observer, capture, previous_session)
        subprocess.run(
            [sys.executable, "/app/tests/network_kernel_child.py", "/scope/fixture.yaml"],
            user=10001,
            group=10001,
            extra_groups=[],
            check=True,
        )
    finally:
        observer.send_signal(signal.SIGTERM)
        observer.wait(timeout=15)
    child = json.loads((results / "child-result.json").read_text())
    violations = []
    observed = 0
    sources = set(namespace_sources())
    with PcapReader(str(session / "assessment.pcap")) as reader:
        for packet in reader:
            if IP not in packet or packet[IP].src not in sources:
                continue
            if TCP in packet and int(packet[TCP].flags) & 2 and not int(packet[TCP].flags) & 16:
                observed += 1
                if packet[IP].dst != "172.31.248.10" or packet[TCP].dport not in {8000, 8001}:
                    violations.append("TCP escape")
            if UDP in packet:
                violations.append("UDP escape")
    assert observed > 0 and not violations
    assert "0 packets dropped by kernel" in (session / "tcpdump.log").read_text()
    # Exercise the shipping supervisor too, including capture finalization and automatic import.
    os.chown(results, 0, 0)
    completed = supervise(Path("/scope/fixture.yaml"), results / "shipping-run", results / "shipping-capture")
    assert completed == 0
    read_report = "from pathlib import Path;p=next(Path('/results/shipping-run/reports').glob('*/report.json'));print(p.read_text())"
    report = json.loads(
        subprocess.check_output(
            [sys.executable, "-c", read_report], user=10001, group=10001, extra_groups=[], text=True
        )
    )
    assert report["metrics"]["independent_egress_observer"] == "measured"
    assert report["metrics"]["independently_observed_scope_violations"] == 0
    summary = {
        "status": "passed",
        "namespace_sources": sorted(sources),
        "raw_negative_controls_blocked": len(child["blocked_direct_controls"]),
        "worker_effective_capabilities": child["effective_capabilities"],
        "independent_tcp_udp_violations": len(violations),
        "kernel_control_connection_attempts_observed": observed,
        "receipt": receipt,
        "shipping_run_id": report["run"]["id"],
        "shipping_observer": report["observer"][-1]["data"],
    }
    (results / "external-network-proof.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

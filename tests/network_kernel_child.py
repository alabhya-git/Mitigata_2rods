"""Unprivileged control probes and a real engine run, against owned fixtures only."""

import asyncio
import json
import socket
import sys
import time
from pathlib import Path

from mitigata.config import load_manifest
from mitigata.engine import Engine
from mitigata.reporting import build_report


def main():
    start = time.time()
    caps = next(
        line.split(":", 1)[1].strip()
        for line in Path("/proc/self/status").read_text().splitlines()
        if line.startswith("CapEff:")
    )
    assert int(caps, 16) == 0
    with socket.create_connection(("172.31.248.10", 8000), timeout=2) as allowed:
        allowed.sendall(b"GET /kernel-allowed-control HTTP/1.0\r\nHost: 172.31.248.10\r\n\r\n")
        assert b"HTTP/" in allowed.recv(1024)
    blocked = []
    for target in [("172.31.248.11", 8000), ("172.31.248.10", 8002)]:
        with socket.socket() as raw:
            raw.settimeout(0.4)
            try:
                raw.connect(target)
            except TimeoutError:
                blocked.append(target)
            else:
                raise AssertionError("Kernel permitted an excluded target/port")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        try:
            udp.sendto(b"owned kernel UDP negative control", ("172.31.248.10", 8000))
        except PermissionError:
            pass  # Some kernels report the OUTPUT policy drop to the sending socket.
    manifest = load_manifest(sys.argv[1])
    engine = Engine(Path("/results/engine"), manifest)
    asyncio.run(engine.run())
    report = build_report(engine.store, engine.run_id)
    assert report["run"]["status"] == "completed"
    assert report["metrics"]["confirmed"] == 1
    assert report["metrics"]["blocked_attempts"] >= 1
    assert report["metrics"]["scope_pairs_untested"] == 0
    Path("/results/child-result.json").write_text(
        json.dumps(
            {
                "start": start,
                "end": time.time(),
                "run_id": engine.run_id,
                "blocked_direct_controls": blocked,
                "effective_capabilities": caps,
            }
        )
    )
    engine.store.close()


if __name__ == "__main__":
    main()

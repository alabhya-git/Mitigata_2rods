"""Independent capture lifecycle and bounded, offline assessment-traffic analysis."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import signal
import subprocess
import time
import uuid
from pathlib import Path


def capture(directory: Path):
    directory.mkdir(parents=True, exist_ok=True)
    session = f"session-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    (directory / "latest.json").write_text(json.dumps({"session": session}), encoding="utf-8")
    directory = directory / session
    directory.mkdir()
    metadata = {"started": time.time(), "interfaces": "any", "filter": "none", "ended": None}
    (directory / "observer.json").write_text(json.dumps(metadata), encoding="utf-8")
    with (directory / "tcpdump.log").open("w", encoding="utf-8") as log:
        command = [
            "tcpdump",
            "-i",
            "any",
            "-p",
            "-n",
            "-U",
            "-s",
            "0",
            "-Z",
            "root",
            "-w",
            str(directory / "assessment.pcap"),
        ]
        process = subprocess.Popen(command, stderr=log, stdout=subprocess.DEVNULL)

        def stop(*args):
            if process.poll() is None:
                process.send_signal(signal.SIGINT)

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        result = process.wait()
    metadata.update(ended=time.time(), exit_code=result)
    (directory / "observer.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return result


def analyze_capture(
    path: Path,
    report: dict,
    *,
    sources: list[str],
    metadata: dict,
    log: str,
    infrastructure: list[tuple[str, int]] = (),
) -> dict:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.utils import PcapReader

    if path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("Capture exceeds the 128 MiB analysis budget")
    if not sources:
        raise ValueError("Explicit assessment-source addresses are required")
    sources = {str(ipaddress.ip_address(s)) for s in sources}
    run = report["run"]
    if run["status"] == "running":
        raise ValueError("Analyze traffic only after the assessment is terminal")
    networks = [ipaddress.ip_network(a, strict=False) for a in run["manifest"]["addresses"]]
    from .config import expand_ports

    ports = set(
        expand_ports(
            run["manifest"].get("ports", []),
            run["manifest"].get("port_ranges", []),
            run["manifest"].get("excluded_ports", []),
        )
    )
    exclusions = [ipaddress.ip_network(a) for a in run["manifest"].get("excluded_addresses", [])]
    infrastructure = set(infrastructure)
    infrastructure.update(
        (i["address"], i["port"]) for i in run["manifest"].get("control_infrastructure", [])
    )
    validation = run["manifest"].get("validation_infrastructure")
    if validation:
        infrastructure.add((validation["address"], validation["port"]))
    dropped = re.search(r"(\d+) packets dropped by kernel", log)
    faults = []
    if not dropped or int(dropped.group(1)) != 0:
        faults.append("Capture drop count is missing or nonzero")
    if metadata.get("interfaces") != "any" or metadata.get("filter") != "none":
        faults.append("Observer must capture all interfaces without a packet filter")
    if metadata.get("started", float("inf")) > run["started"] or (metadata.get("ended") or 0) < run["ended"]:
        faults.append("Observer does not cover the complete assessment window")
    violations, initiations, infra_count, packets, unsupported = [], set(), 0, 0, 0
    observed_targets = set()
    with PcapReader(str(path)) as reader:
        for packet in reader:
            packets += 1
            if packets > 1_000_000:
                raise ValueError("Capture packet budget exceeded")
            timestamp = float(packet.time)
            if not run["started"] <= timestamp <= run["ended"]:
                continue
            ip = packet.getlayer(IP) or packet.getlayer(IPv6)
            if ip is None or ip.src not in sources:
                continue
            if TCP in packet:
                tcp = packet[TCP]
                if not int(tcp.flags) & 2 or int(tcp.flags) & 16:
                    continue  # New client TCP flows, excluding server SYN/ACKs and established replies.
                protocol, port = "tcp", int(tcp.dport)
                key = (ip.src, int(tcp.sport), ip.dst, port, protocol)
                if key in initiations:
                    continue
                initiations.add(key)
            elif UDP in packet:
                protocol, port = "udp", int(packet[UDP].dport)
                key = (ip.src, int(packet[UDP].sport), ip.dst, port, protocol)
                initiations.add(key)
            elif getattr(ip, "proto", None) in {1, 58} or getattr(ip, "nh", None) == 58:
                continue  # ICMP control traffic is not a supported assessment probe in this release.
            else:
                unsupported += 1
                continue
            if protocol == "tcp" and (ip.dst, port) in infrastructure:
                infra_count += 1
                continue
            observed_targets.add((ip.dst, port))
            destination = ipaddress.ip_address(ip.dst)
            inside = any(
                destination in network
                and (
                    run["manifest"].get("mode", "LOCAL_LAB") == "LOCAL_LAB"
                    or run["manifest"].get("include_network_broadcast", False)
                    or network.version != 4
                    or network.prefixlen >= 31
                    or destination not in {network.network_address, network.broadcast_address}
                )
                for network in networks
            )
            allowed = (
                protocol == "tcp"
                and port in ports
                and inside
                and not any(destination in e for e in exclusions)
            )
            if not allowed:
                violations.append(
                    {
                        "source": ip.src,
                        "destination": ip.dst,
                        "port": port,
                        "protocol": protocol,
                        "timestamp": timestamp,
                    }
                )
    if unsupported:
        faults.append("Unsupported outbound packet types prevent a complete conclusion")
    if not observed_targets:
        faults.append("No assessment connection attempts were observed")
    # Every target with an allowed broker attempt must be visible, including refused connections.
    expected_targets = {
        (e["data"]["address"], e["data"]["port"])
        for e in report.get("audit", [])
        if e["data"].get("status") == "allowed" and not e["data"].get("infrastructure")
    }
    if expected_targets - observed_targets:
        faults.append("Some attempted target endpoints were absent from the capture")
    return {
        "status": "measured" if not faults else "inconclusive",
        "capture_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "scope": "TCP connection initiations and UDP datagrams from the declared assessment namespace sources",
        "source_addresses": sorted(sources),
        "packets_parsed": packets,
        "connection_attempts": len(initiations),
        "infrastructure_attempts": infra_count,
        "violations": violations,
        "transmitted_scope_violations": len(violations) if not faults else None,
        "faults": faults,
        "unsupported_packets": unsupported,
        "window": {"started": run["started"], "ended": run["ended"]},
    }

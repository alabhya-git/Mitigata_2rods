"""Linux container supervisor: install egress policy, then run unprivileged workers."""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .config import load_manifest
from .scope import ScopeGuard

RECEIPT = Path("/run/mitigata/receipt.json")


def write_protected(path, content):
    # Replace rather than reopen a read-only receipt: the supervisor drops DAC_OVERRIDE.
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(content)
    try:
        os.chmod(temporary, 0o444)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def capture_session(capture_root):
    try:
        return json.loads((capture_root / "latest.json").read_text())["session"]
    except (OSError, ValueError, KeyError):
        return None


def wait_observer(observer, capture_root, previous_session):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        name = capture_session(capture_root)
        if name and name != previous_session:
            log = capture_root / name / "tcpdump.log"
            if log.exists() and "listening on any" in log.read_text():
                return capture_root / name
        if observer.poll() is not None:
            raise RuntimeError("Independent observer failed to start")
        time.sleep(0.05)
    raise RuntimeError("Observer did not become ready before assessment")


def policy_hash(manifest):
    return hashlib.sha256(
        json.dumps(manifest.public(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def port_groups(ports):
    ranges = []
    start = previous = None
    for port in sorted(ports):
        if previous is not None and port == previous + 1:
            previous = port
            continue
        if previous is not None:
            ranges.append(str(start) if start == previous else f"{start}:{previous}")
        start = previous = port
    if previous is not None:
        ranges.append(str(start) if start == previous else f"{start}:{previous}")
    groups, current, slots = [], [], 0
    for span in ranges:
        required = 2 if ":" in span else 1
        if slots + required > 15:
            groups.append(",".join(current))
            current, slots = [], 0
        current.append(span)
        slots += required
    if current:
        groups.append(",".join(current))
    return groups


def firewall_rules(manifest):
    guard = ScopeGuard(manifest)
    if any(":" in address for address in guard.addresses):
        raise ValueError("The contained assessment profile is IPv4-only")
    lines = [
        "*filter",
        ":INPUT ACCEPT [0:0]",
        ":FORWARD DROP [0:0]",
        ":OUTPUT DROP [0:0]",
        "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
    ]
    for address in guard.addresses:
        for group in port_groups(guard.ports):
            lines.append(f"-A OUTPUT -d {address}/32 -p tcp -m multiport --dports {group} -j ACCEPT")
    if manifest.control_port:
        lines.append(f"-A OUTPUT -d 127.0.0.1/32 -p tcp --dport {manifest.control_port} -j ACCEPT")
    if manifest.ai.gateway_address:
        lines.append(
            f"-A OUTPUT -d {manifest.ai.gateway_address}/32 -p tcp --dport {manifest.ai.gateway_port} -j ACCEPT"
        )
    if manifest.tools.katana or manifest.tools.ffuf or manifest.tools.nuclei:
        lines.append(f"-A OUTPUT -d 127.0.0.1/32 -p tcp --dport {manifest.tools.proxy_port} -j ACCEPT")
    if manifest.validation_url:
        from urllib.parse import urlsplit

        lines.append(
            f"-A OUTPUT -d {manifest.validation_address}/32 -p tcp --dport {urlsplit(manifest.validation_url).port} -j ACCEPT"
        )
    return "\n".join(lines + ["COMMIT", ""])


def install_policy(manifest):
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/.dockerenv").exists():
        raise ValueError("Kernel confinement is installed only by the dedicated Linux container supervisor")
    if manifest.execution_profile != "linux_confined" or manifest.mode == "LOCAL_LAB":
        raise ValueError("A linux_confined external manifest is required")
    rules = firewall_rules(manifest)
    subprocess.run(
        ["iptables-restore", "--wait", "5"], input=rules, text=True, check=True, capture_output=True
    )
    # No external IPv6 scope is supported. Block that egress plane too.
    subprocess.run(
        ["ip6tables-restore", "--wait", "5"],
        input="*filter\n:INPUT ACCEPT [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n",
        text=True,
        check=True,
        capture_output=True,
    )
    effective = subprocess.run(
        ["iptables-save", "-t", "filter"], capture_output=True, text=True, check=True
    ).stdout
    if ":OUTPUT DROP" not in effective or ":FORWARD DROP" not in effective:
        raise RuntimeError("Kernel did not retain the deny-first policy")
    RECEIPT.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(RECEIPT.parent, 0o755)
    write_protected(RECEIPT.parent / "policy.rules", rules)
    receipt = {
        "policy_hash": policy_hash(manifest),
        "rules_sha256": hashlib.sha256(rules.encode()).hexdigest(),
        "effective_rules_sha256": hashlib.sha256(effective.encode()).hexdigest(),
        "network_namespace": os.readlink("/proc/self/ns/net"),
        "created": time.time(),
        "supervisor_pid": os.getpid(),
        "worker_uid": 10001,
        "ipv6_output": "drop",
    }
    write_protected(RECEIPT, json.dumps(receipt, indent=2))
    return receipt


def verify_receipt(manifest):
    if sys.platform != "linux" or os.geteuid() != 10001:
        raise ValueError("linux_confined workers must run as the unprivileged container user")
    if RECEIPT.is_symlink() or not RECEIPT.is_file():
        raise ValueError("Missing privileged egress-policy receipt")
    for path in (RECEIPT, RECEIPT.parent):
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("The egress receipt must be owned by the privileged supervisor")
    value = json.loads(RECEIPT.read_text())
    if value["policy_hash"] != policy_hash(manifest) or value["network_namespace"] != os.readlink(
        "/proc/self/ns/net"
    ):
        raise ValueError("Manifest or network namespace does not match the installed egress policy")
    caps = next(
        line.split(":", 1)[1].strip()
        for line in Path("/proc/self/status").read_text().splitlines()
        if line.startswith("CapEff:")
    )
    if int(caps, 16):
        raise ValueError("Assessment workers must not retain effective Linux capabilities")
    return value


def supervise(
    manifest_path, output: Path, capture_root: Path | None = None, checks=None, *, dashboard=False, port=8765
):
    if dashboard:
        from .campaign import supervise_dashboard

        return supervise_dashboard(manifest_path, output, capture_root, port)
    manifest = load_manifest(manifest_path)
    install_policy(manifest)
    output.mkdir(parents=True, exist_ok=True)
    os.chown(output, 10001, 10001)
    observer = None
    if capture_root is not None:
        capture_root.mkdir(parents=True, exist_ok=True)
        previous_session = capture_session(capture_root)
        observer = subprocess.Popen(
            [sys.executable, "-m", "mitigata", "capture", "--output", str(capture_root)]
        )
        try:
            wait_observer(observer, capture_root, previous_session)
        except BaseException:
            if observer.poll() is None:
                observer.terminate()
                observer.wait(timeout=5)
            raise
    command = (
        [
            sys.executable,
            "-m",
            "mitigata",
            "serve",
            "--manifest",
            str(manifest_path),
            "--listen-container",
            "--port",
            str(port),
            "--output",
            str(output),
        ]
        if dashboard
        else [sys.executable, "-m", "mitigata", "run", str(manifest_path), "--output", str(output)]
    )
    if checks and not dashboard:
        command += ["--checks", str(checks)]
    child = None

    def cancel(*args):
        if child is not None and child.poll() is None:
            child.send_signal(signal.SIGINT)

    signal.signal(signal.SIGTERM, cancel)
    signal.signal(signal.SIGINT, cancel)
    try:
        child = subprocess.Popen(
            command, user=10001, group=10001, extra_groups=[], umask=0o077, stdout=subprocess.PIPE, text=True
        )
        try:
            stdout, _ = child.communicate(timeout=None if dashboard else manifest.budgets.seconds + 90)
            print(stdout, end="", flush=True)
            result = child.returncode
        except subprocess.TimeoutExpired:
            cancel()
            try:
                stdout, _ = child.communicate(timeout=30)
                print(stdout, end="", flush=True)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            result = 1
    finally:
        if observer:
            observer.terminate()
            observer.wait(timeout=15)
    if observer and child.returncode in {0, 1} and not dashboard:
        try:
            run_id = json.loads(stdout)["run_id"]
            session = capture_root / json.loads((capture_root / "latest.json").read_text())["session"]
            os.chown(session, 0, 10001)
            os.chmod(session, 0o750)
            for name in ("assessment.pcap", "observer.json", "tcpdump.log"):
                os.chown(session / name, 0, 10001)
                os.chmod(session / name, 0o440)
            sources = namespace_sources()
            observe = [
                sys.executable,
                "-m",
                "mitigata",
                "observe",
                run_id,
                "--root",
                str(output),
                "--capture",
                str(session / "assessment.pcap"),
                "--metadata",
                str(session / "observer.json"),
                "--log",
                str(session / "tcpdump.log"),
            ]
            for address in sources:
                observe += ["--source-address", address]
            measured = subprocess.run(
                observe, check=False, user=10001, group=10001, extra_groups=[], umask=0o077
            )
            if measured.returncode:
                result = 1
        except (OSError, ValueError, KeyError):
            print("Capture was retained, but automatic measurement was unavailable", file=sys.stderr)
            result = 1
    return result


def namespace_sources():
    addresses = {"127.0.0.1", "::1"}
    previous = ""
    import ipaddress

    for line in Path("/proc/net/fib_trie").read_text().splitlines():
        if "/32 host LOCAL" in line:
            try:
                addresses.add(str(ipaddress.ip_address(previous.split()[-1])))
            except (ValueError, IndexError):
                pass
        previous = line
    return sorted(addresses)

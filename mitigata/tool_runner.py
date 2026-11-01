"""Reviewed command adapters. No shell, arbitrary flags, target DNS or unconfined live tools."""

from __future__ import annotations

import asyncio
import os
import shutil
import signal
import sys
import time
import xml.etree.ElementTree as ET

from .runtime_guard import tool_launch_permit
from .scope import ScopeDenied


def capability(manifest, name):
    executable = shutil.which(name)
    contained = sys.platform == "linux" and manifest.execution_profile == "linux_confined"
    return {
        "name": name,
        "installed": bool(executable),
        "path": executable,
        "live_allowed": bool(executable and contained),
        "reason": None
        if executable and contained
        else "missing_executable"
        if not executable
        else "live_adapter_requires_linux_kernel_confinement",
    }


async def run_reviewed(c, name, args, *, timeout=None, offline=False):
    info = capability(c.manifest, name)
    if not info["installed"] or (not offline and not info["live_allowed"]):
        raise ScopeDenied(info["reason"] or "Tool unavailable")
    if not offline:
        from .confinement import verify_receipt

        verify_receipt(c.manifest)
    if c.broker.cancelled:
        raise asyncio.CancelledError
    command = [info["path"], *map(str, args)]
    started = time.monotonic()
    permit = tool_launch_permit.set(tuple(command))
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.DEVNULL,
            env={"PATH": os.environ.get("PATH", ""), "HOME": "/tmp", "LANG": "C.UTF-8"},
            start_new_session=sys.platform != "win32",
        )
    finally:
        tool_launch_permit.reset(permit)
    if not hasattr(c.broker, "children"):
        c.broker.children = set()
    c.broker.children.add(process)
    try:

        async def read_bounded(stream, limit):
            value = bytearray()
            while True:
                chunk = await stream.read(min(65536, limit + 1 - len(value)))
                if not chunk:
                    return bytes(value)
                value.extend(chunk)
                if len(value) > limit:
                    raise ValueError("Tool output limit exceeded")

        out, err, _ = await asyncio.wait_for(
            asyncio.gather(
                read_bounded(process.stdout, 8 * 1024 * 1024),
                read_bounded(process.stderr, 65536),
                process.wait(),
            ),
            min(timeout or c.manifest.tools.timeout, max(0.1, c.broker.deadline - time.time())),
        )
        if process.returncode:
            raise ValueError(f"{name} exited {process.returncode}: " + err.decode(errors="replace")[:300])
        ref = c.evidence.capture(
            c.run_id,
            out,
            kind="tool_output",
            metadata={
                "tool": name,
                "arguments": args,
                "elapsed_seconds": round(time.monotonic() - started, 3),
                "exit_code": process.returncode,
            },
        )
        return out, ref
    finally:
        if process.returncode is None:
            if sys.platform != "win32":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            await process.wait()
        c.broker.children.discard(process)


def parse_nmap(raw, guard, targets):
    if len(raw) > 8 * 1024 * 1024 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        # Nmap emits a harmless external DTD declaration; strip that single known declaration only.
        raw = raw.replace(b"<!DOCTYPE nmaprun>", b"")
        if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper() or len(raw) > 8 * 1024 * 1024:
            raise ValueError("Unsafe or oversized Nmap XML")
    root = ET.fromstring(raw)
    finished = root.find("runstats/finished")
    if finished is None or finished.get("exit") != "success":
        raise ValueError("Nmap did not report a complete successful scan")
    selected = set(targets)
    results = {}
    for host in root.findall("host"):
        address = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") == "ipv4"), None)
        if address is None:
            continue
        if host.get("timedout") == "true":
            raise ValueError("Nmap host timed out; coverage cannot be inferred")
        for port in host.findall("ports/port"):
            number = int(port.get("portid", "0"))
            if (
                port.get("protocol") != "tcp"
                or (address, number) not in selected
                or not guard.address_allowed(address, number)
            ):
                raise ScopeDenied("Nmap output includes an unrequested endpoint")
            state = port.find("state")
            service = port.find("service")
            data = {
                "address": address,
                "port": number,
                "status": state.get("state", "unknown") if state is not None else "unknown",
            }
            if service is not None:
                data["service_hint"] = {
                    k: service.get(k)
                    for k in ("name", "product", "version", "tunnel", "method", "conf")
                    if service.get(k)
                }
            results[(address, number)] = data
        extras = host.find("ports/extraports")
        if extras is not None and extras.get("state") in {"closed", "filtered"}:
            omitted = [t for t in selected if t[0] == address and t not in results]
            if int(extras.get("count", "0")) == len(omitted):
                for target in omitted:
                    results[target] = {
                        "address": target[0],
                        "port": target[1],
                        "status": "closed" if extras.get("state") == "closed" else "filtered_unknown",
                    }
    if set(results) != selected:
        raise ValueError("Nmap did not account for all requested ports")
    return list(results.values())


async def nmap_batch(c, targets):
    by_host = {}
    for address, port in targets:
        if not c.broker.guard.address_allowed(address, port):
            raise ScopeDenied("Nmap input outside scope")
        by_host.setdefault(address, []).append(port)
    all_results = []
    for address, ports in by_host.items():
        args = [
            "-sT",
            "-Pn",
            "-n",
            "--max-retries",
            "1",
            "--max-rate",
            str(int(c.manifest.budgets.rate_per_second)),
            "--initial-rtt-timeout",
            "500ms",
            "--max-rtt-timeout",
            "1500ms",
            "-sV",
            "--version-light",
            "-p",
            ",".join(map(str, sorted(ports))),
            "-oX",
            "-",
            address,
        ]
        if (
            not c.manifest.action_allowed("service_identification")
            or c.manifest.allowed_paths != ["/"]
            or c.manifest.excluded_paths
        ):
            args.remove("-sV")
            args.remove("--version-light")
        raw, ref = await run_reviewed(c, "nmap", args)
        results = parse_nmap(raw, c.broker.guard, [(address, p) for p in ports])
        all_results.extend((r, ref) for r in results)
    return all_results

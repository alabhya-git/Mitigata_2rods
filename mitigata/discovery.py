"""Bounded batched discovery; network results are ingested transactionally."""

from __future__ import annotations

import asyncio
import json
import time
import uuid

from .scope import ScopeDenied
from .transport import BudgetExceeded


async def scan_batch(context, start, end):
    c = context
    broker = c.broker
    guard = broker.guard
    targets = [guard.target_at(i) for i in range(start, end)]
    if not hasattr(broker, "discovery_slots"):
        broker.discovery_slots = asyncio.Semaphore(c.manifest.discovery.concurrency)
    use_nmap = False
    if c.manifest.tools.nmap and c.manifest.discovery.backend in {"nmap", "auto"}:
        from .tool_runner import capability

        info = capability(c.manifest, "nmap")
        use_nmap = info["live_allowed"]
        c.store.put(c.run_id, "capability", "nmap", info, role="Recon")
        if not use_nmap and c.manifest.discovery.backend == "nmap":
            raise ScopeDenied("Requested Nmap backend unavailable: " + info["reason"])
    # Persist all admissions BEFORE opening their sockets. A cancelled admission is not proof of transmission.
    async with broker.rate_lock:
        if broker.cancelled or time.time() >= broker.deadline:
            raise BudgetExceeded("Discovery deadline exhausted")
        if broker.counter + len(targets) > c.manifest.budgets.requests:
            raise BudgetExceeded("Discovery request budget exhausted")
        rows = []
        reservations = []
        for address, port in targets:
            if not guard.address_allowed(address, port):
                raise ScopeDenied("Discovery target outside scope")
            broker.counter += 1
            reserved_at = time.monotonic() if use_nmap else max(broker.next_at, time.monotonic())
            if not use_nmap:
                broker.next_at = reserved_at + 1 / c.manifest.budgets.rate_per_second
            reservations.append(reserved_at)
            rows.append(
                {
                    "kind": "audit",
                    "identity": uuid.uuid4().hex,
                    "data": {
                        "status": "allowed",
                        "action": "tcp",
                        "operation": "connect",
                        "address": address,
                        "port": port,
                        "attempt": broker.counter,
                        "plane": "Sentinel",
                        "batched": True,
                    },
                }
            )
        c.store.put_many(c.run_id, rows, "Recon")

    if use_nmap:
        from .tool_runner import nmap_batch

        if not hasattr(broker, "nmap_slots"):
            broker.nmap_slots = asyncio.Semaphore(1)
        async with broker.nmap_slots:
            results = await nmap_batch(c, targets)
        c.store.put_many(
            c.run_id,
            [
                {"kind": "port", "identity": f"{r['address']}:{r['port']}", "data": r, "evidence": [ref]}
                for r, ref in results
            ],
            "Recon",
        )
        for result, ref in results:
            if result["status"] == "open":
                c.store.enqueue(
                    c.run_id,
                    role="Recon",
                    kind="identify",
                    target=f"{result['address']}:{result['port']}",
                    payload={**result, "evidence_id": ref},
                )
        return

    async def probe(target, at):
        address, port = target
        await asyncio.sleep(max(0, at - time.monotonic()))
        async with broker.discovery_slots:
            if broker.cancelled or time.time() >= broker.deadline:
                raise BudgetExceeded("Discovery deadline exhausted")
            request_id = uuid.uuid4().hex

            def connect():
                try:
                    broker._connect(
                        request_id,
                        address,
                        port,
                        c.manifest.budgets.connect_timeout or c.manifest.budgets.timeout,
                    )
                    return {"address": address, "port": port, "status": "open"}
                except OSError as exc:
                    return {
                        "address": address,
                        "port": port,
                        "status": "closed"
                        if isinstance(exc, ConnectionRefusedError) or getattr(exc, "winerror", 0) == 10061
                        else "filtered_unknown",
                        "error_type": type(exc).__name__,
                    }
                finally:
                    broker._close(request_id)

            return await asyncio.to_thread(connect)

    pending = [asyncio.create_task(probe(t, at)) for t, at in zip(targets, reservations, strict=True)]
    results = []
    try:
        for done in asyncio.as_completed(pending):
            result = await done
            results.append(result)
            if result["status"] == "open":
                # Dispatch an observed open port without waiting for the entire sweep.
                ref = c.evidence.capture(
                    c.run_id,
                    json.dumps(result).encode(),
                    kind="tcp_connect",
                    metadata={"address": result["address"], "port": result["port"]},
                )
                c.store.publish(
                    c.run_id,
                    "port",
                    f"{result['address']}:{result['port']}",
                    result,
                    [ref],
                    "Recon",
                    tasks=[
                        {
                            "role": "Recon",
                            "kind": "identify",
                            "target": f"{result['address']}:{result['port']}",
                            "payload": {**result, "evidence_id": ref},
                        }
                    ],
                )
    finally:
        for task in pending:
            if not task.done():
                task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        if results:
            ref = c.evidence.capture(
                c.run_id,
                json.dumps(results).encode(),
                kind="tcp_batch",
                metadata={"start_index": start, "end_index": end, "tested": len(results)},
            )
            c.store.put_many(
                c.run_id,
                [
                    {"kind": "port", "identity": f"{r['address']}:{r['port']}", "data": r, "evidence": [ref]}
                    for r in results
                    if r["status"] != "open"
                ],
                "Recon",
            )

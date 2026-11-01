"""Offline static inspection only. Target artifacts are never executed."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .scope import ScopeDenied
from .tool_runner import run_reviewed


async def inspect_artifact(agent, raw, digest):
    c = agent.ctx
    with tempfile.TemporaryDirectory(prefix="mitigata-artifact-") as directory:
        path = Path(directory) / "sample.bin"
        path.write_bytes(raw)
        os.chmod(path, 0o400)
        for name, arguments in (
            ("file", ["-b", str(path)]),
            ("readelf", ["-h", "-l", "-d", str(path)]),
            ("objdump", ["-d", "--no-show-raw-insn", str(path)]),
        ):
            if name != "file" and not raw.startswith((b"\x7fELF", b"MZ")):
                continue
            try:
                output, ref = await run_reviewed(c, name, arguments, timeout=20, offline=True)
                c.store.put(
                    c.run_id,
                    "observation",
                    f"static:{name}:{digest}",
                    {
                        "type": "static_analysis",
                        "tool": name,
                        "artifact_sha256": digest,
                        "bytes": len(output),
                        "claim": "Static tool output; sample execution and exploitability are not established.",
                    },
                    [ref],
                    agent.role,
                )
                if c.ai_client:
                    c.store.enqueue(
                        c.run_id,
                        role="Binary",
                        kind="investigate",
                        target=digest + ":" + name,
                        payload={"evidence_ids": [ref]},
                    )
            except (OSError, ValueError, ScopeDenied, TimeoutError) as exc:
                c.store.put(
                    c.run_id,
                    "capability",
                    name,
                    {"available": False, "reason": str(exc)[:300]},
                    role=agent.role,
                )

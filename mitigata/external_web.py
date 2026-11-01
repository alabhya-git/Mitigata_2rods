"""Optional mature discovery tools; HTTP is forced through the scoped proxy."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .scope import ScopeDenied
from .tool_runner import capability, run_reviewed


async def discover_with_tools(agent, task):
    c = agent.ctx
    url = c.broker.guard.destination(task["target"]).url
    if urlsplit(url).scheme != "http":
        c.store.put(
            c.run_id,
            "capability",
            "external_web_https",
            {
                "available": False,
                "reason": "HTTPS application discovery uses the brokered browser; CONNECT proxy tunnelling is disabled",
            },
            role=agent.role,
        )
        return
    proxy = f"http://127.0.0.1:{c.manifest.tools.proxy_port}"
    for name in ("katana", "ffuf", "nuclei"):
        if not getattr(c.manifest.tools, name):
            continue
        info = capability(c.manifest, name)
        c.store.put(c.run_id, "capability", name, info, role=agent.role)
        if not info["live_allowed"]:
            continue
        with tempfile.TemporaryDirectory(prefix="mitigata-tool-") as work:
            directory = Path(work)
            if name == "katana":
                args = [
                    "-u",
                    url,
                    "-proxy",
                    proxy,
                    "-d",
                    "3",
                    "-jc",
                    "-silent",
                    "-jsonl",
                    "-duc",
                    "-ct",
                    "20s",
                    "-c",
                    "2",
                    "-rl",
                    str(min(10, int(c.manifest.budgets.rate_per_second))),
                ]
            elif name == "ffuf":
                wordlist = directory / "paths.txt"
                wordlist.write_text(
                    "\n".join(c.manifest.investigation.paths[: c.manifest.investigation.max_path_probes]),
                    encoding="utf-8",
                )
                if not wordlist.stat().st_size:
                    continue
                args = [
                    "-u",
                    urljoin(url, "/FUZZ"),
                    "-w",
                    str(wordlist),
                    "-x",
                    proxy,
                    "-ac",
                    "-noninteractive",
                    "-s",
                    "-t",
                    "2",
                    "-rate",
                    str(min(10, int(c.manifest.budgets.rate_per_second))),
                    "-maxtime",
                    "25",
                    "-of",
                    "json",
                    "-o",
                    str(directory / "results.json"),
                ]
            else:
                from importlib.resources import files

                template = directory / "reviewed-disclosures.yaml"
                template.write_text(
                    files("mitigata").joinpath("data/nuclei-disclosures.yaml").read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                args = [
                    "-u",
                    url,
                    "-t",
                    str(template),
                    "-proxy",
                    proxy,
                    "-ni",
                    "-duc",
                    "-silent",
                    "-jsonl",
                    "-nc",
                    "-rl",
                    "5",
                    "-c",
                    "1",
                ]
            try:
                raw, ref = await run_reviewed(c, name, args, timeout=min(45, c.manifest.tools.timeout))
                discovered = []
                if name == "ffuf":
                    output = directory / "results.json"
                    if output.exists() and output.stat().st_size < 2_000_000:
                        ref = c.evidence.capture(
                            c.run_id,
                            output.read_bytes(),
                            kind="tool_output",
                            metadata={"tool": "ffuf", "format": "json"},
                        )
                        discovered = [
                            r.get("url") for r in json.loads(output.read_text()).get("results", [])[:100]
                        ]
                else:
                    for line in raw.decode(errors="replace").splitlines()[:500]:
                        try:
                            row = json.loads(line)
                        except ValueError:
                            continue
                        if name == "katana":
                            discovered.append(row.get("request", {}).get("endpoint"))
                        else:
                            discovered.append(row.get("matched-at"))
                            c.store.put(
                                c.run_id,
                                "observation",
                                "nuclei:" + str(row.get("matched-at")),
                                {
                                    "type": "scanner_candidate",
                                    "tool": "nuclei",
                                    "status": "unverified",
                                    "template_id": row.get("template-id"),
                                    "url": row.get("matched-at"),
                                    "claim": "Reviewed template matched; deterministic verification remains required.",
                                },
                                [ref],
                                agent.role,
                            )
                for found in discovered:
                    if not found:
                        continue
                    try:
                        found = c.broker.guard.destination(found).url
                    except ScopeDenied:
                        continue
                    c.store.enqueue(c.run_id, role="Web", kind="page", target=found, payload={"depth": 1})
            except (ValueError, OSError, TimeoutError, ScopeDenied) as exc:
                c.store.put(
                    c.run_id,
                    "capability",
                    name,
                    {**info, "last_execution": "failed", "reason": str(exc)[:300]},
                    role=agent.role,
                )

"""Calibrated path discovery, same-IP authority clues and artifact handoffs."""

from __future__ import annotations

import hashlib
import re
import time
import uuid
from pathlib import PurePosixPath
from urllib.parse import urljoin, urlsplit

from .codes import extended_match
from .extractors import equivalent_response, extract_references
from .scope import ScopeDenied

# Pages sometimes announce their own hidden surface ("not everything is linked",
# "fuzz for it", "world-readable vault"). When they do, pull nearby nouns as likely
# path segments and probe a small, bounded set. This is a heuristic wordlist boost,
# not a finding; discovered paths flow through the normal crawl/verify pipeline.
_HINT_TRIGGERS = re.compile(
    r"(?i)\b(?:not\s+linked|unlinked|off\s+the\s+index|kept\s+(?:off|hidden)|not\s+published|"
    r"fuzz\s+for|world[- ]readable|hidden|unlisted|raw\s+path|directly\s+reference)\b"
)
_HINT_NOUNS = re.compile(
    r"(?i)\b(vault|artifacts?|backups?|secrets?|admin|internal|private|ops|logs?|monitor|"
    r"config|dashboard|console|debug|api|git|repo|storage|uploads?|downloads?|files?|data|"
    r"staging|dev|test|keys?|credentials?)\b"
)
# Always-worth-a-look segments once a page signals hidden content exists.
_STANDARD_HIDDEN = (
    "vault",
    "backup",
    "backups",
    "admin",
    "internal",
    "private",
    "secret",
    ".git/HEAD",
    "api",
    "config",
)


def boost_from_hints(agent, response, forward=None):
    """Schedule bounded probes for unlinked segments a page hints at.

    When ``forward`` is a (header, value) pair the page was reached through a forwarding
    bypass, so the probes must carry the same header — otherwise the unlinked content
    (e.g. an artifact vault only visible to the internal source) is never seen. The
    dedupe marker includes the header so plain and forwarded boosts can both run.
    """
    c = agent.ctx
    cfg = c.manifest.investigation
    text = response.text
    if not _HINT_TRIGGERS.search(text):
        return
    authority = urlsplit(response.url)
    base = f"{authority.scheme}://{authority.netloc}/"
    tag = forward[0] if forward else "plain"
    marker = f"hint_boost:{authority.netloc}:{tag}"
    if c.store.get(c.run_id, "observation", marker):
        return
    nouns = []
    for match in _HINT_NOUNS.finditer(text):
        word = match.group(1).lower()
        if word not in nouns:
            nouns.append(word)
    segments = list(dict.fromkeys(nouns + list(_STANDARD_HIDDEN)))[: cfg.max_hint_probes]
    c.store.put(
        c.run_id,
        "observation",
        marker,
        {
            "type": "hidden_surface_hint",
            "url": response.url,
            "forwarded": bool(forward),
            "candidate_segments": segments,
            "claim": "Page signals unlinked content; bounded path probes were scheduled. No weakness is claimed by this record.",
        },
        [response.evidence_id],
        agent.role,
    )
    for segment in segments:
        for candidate in (urljoin(base, segment), urljoin(base, segment + "/")):
            try:
                url = c.broker.guard.destination(candidate).url
            except ScopeDenied:
                continue
            if forward:
                c.store.enqueue(
                    c.run_id,
                    role="Web",
                    kind="forwarded_page",
                    target=url,
                    payload={"depth": 1, "header": forward[0], "value": forward[1]},
                )
            else:
                c.store.enqueue(
                    c.run_id,
                    role="Web",
                    kind="page",
                    target=url,
                    payload={"depth": 1, "session_ref": None, "action_id": None},
                )


async def consume_extended(agent, response, depth, session_ref, forward=None):
    c = agent.ctx
    cfg = c.manifest.investigation
    if response.truncated:
        c.store.put(
            c.run_id,
            "observation",
            "partial:" + response.url,
            {
                "type": "partial_http_response",
                "url": response.url,
                "diagnostics": response.diagnostics,
                "claim": "HTTP service identified, but the body was truncated or incomplete; proof may be unavailable.",
            },
            [response.evidence_id],
            agent.role,
        )
    if cfg.follow_same_ip_hostnames:
        for hostname in response.diagnostics.get("dns_names", []):
            if c.broker.bind_authority(hostname, response.evidence_id):
                parts = urlsplit(response.url)
                authority = hostname + (":" + str(parts.port) if parts.port else "")
                c.store.enqueue(
                    c.run_id,
                    role="Web",
                    kind="page",
                    target=f"{parts.scheme}://{authority}/",
                    payload={"depth": 1},
                )
        for reference in extract_references(response.url, response.text, response.headers)[:40]:
            host = urlsplit(reference["url"]).hostname
            if host and reference["method"].startswith(("literal", "html:a", "header:")):
                c.broker.bind_authority(host, response.evidence_id)
    content_type = response.headers.get("content-type", "").lower()
    artifact = (
        response.body.startswith((b"\x7fELF", b"MZ", b"PK\x03\x04"))
        or "application/octet-stream" in content_type
        or "attachment" in response.headers.get("content-disposition", "")
        or urlsplit(response.url).path.lower().endswith((".bin", ".elf", ".exe", ".dll", ".zip", ".so"))
    )
    if (
        artifact
        and cfg.discover_artifacts
        and not response.truncated
        and response.status == 200
        and c.store.count_records(c.run_id, "artifact_download") < cfg.max_artifacts
    ):
        digest = hashlib.sha256(response.body).hexdigest()
        c.store.publish(
            c.run_id,
            "artifact_download",
            digest,
            {"url": response.url, "sha256": digest},
            [response.evidence_id],
            agent.role,
            tasks=[
                {
                    "role": "Binary",
                    "kind": "analyze",
                    "target": digest,
                    "payload": {
                        "download_evidence": response.evidence_id,
                        "name": PurePosixPath(urlsplit(response.url).path).name or "download.bin",
                    },
                }
            ],
        )
        c.handoff(
            agent.role,
            "Binary",
            response.url,
            [response.evidence_id],
            "inspect discovered artifact without executing it",
        )
    if 200 <= response.status < 300 and not session_ref and not response.truncated:
        for recipe in c.checks.for_surface("web"):
            if extended_match(recipe.primitive, response.text):
                c.candidate(agent.role, recipe, response.url, [response.evidence_id], session_ref=session_ref)
    if cfg.hint_path_boost and not response.truncated and response.status < 400:
        boost_from_hints(agent, response, forward=forward)
    if depth == 0 and cfg.max_path_probes:
        authority = urlsplit(response.url)
        base = f"{authority.scheme}://{authority.netloc}/"
        c.store.enqueue(
            c.run_id, role="Web", kind="paths", target=base, payload={"evidence_ids": [response.evidence_id]}
        )
        if cfg.browser:
            c.store.enqueue(
                c.run_id,
                role="Web",
                kind="browser",
                target=response.url,
                payload={"evidence_ids": [response.evidence_id]},
            )
        if c.manifest.tools.katana or c.manifest.tools.ffuf or c.manifest.tools.nuclei:
            c.store.enqueue(
                c.run_id,
                role="Web",
                kind="external_tools",
                target=base,
                payload={"evidence_ids": [response.evidence_id]},
            )
    if c.ai_client is not None and response.status < 400:
        c.store.enqueue(
            c.run_id,
            role="Web",
            kind="investigate",
            target=response.url,
            payload={"evidence_ids": [response.evidence_id]},
        )


async def discover_paths(agent, task):
    c = agent.ctx
    cfg = c.manifest.investigation
    base = task["target"]
    try:
        baseline = await c.broker.http(urljoin(base, "mitigata-absent-" + uuid.uuid4().hex))
    except (OSError, TimeoutError, ValueError, ScopeDenied):
        c.ledger(agent.role, "web.path_discovery", base, "inconclusive", reason="baseline_unavailable")
        return
    ref = baseline.evidence_id
    started = time.monotonic()
    failures = 0
    probed = 0
    for path in cfg.paths[: cfg.max_path_probes]:
        if time.monotonic() - started > 45 or failures >= 4:
            c.ledger(
                agent.role,
                "web.path_discovery",
                base,
                "budget_exhausted",
                [ref],
                reason="origin_unresponsive_or_local_time_budget",
                probes=probed,
            )
            return
        url = urljoin(base, path)
        try:
            c.broker.guard.destination(url)
            response = await c.broker.http(url)
            probed += 1
        except (OSError, TimeoutError, ValueError, ScopeDenied):
            failures += 1
            continue
        if response.status == 404 or equivalent_response(response, baseline):
            c.ledger(
                agent.role,
                "web.path_discovery",
                url,
                "negative",
                [ref, response.evidence_id],
                reason="nonexistent_or_catch_all",
            )
            continue
        if response.status < 500:
            await agent.consume(response, 1)
            c.store.put(
                c.run_id,
                "discovery",
                url,
                {
                    "url": url,
                    "method": "calibrated_path_probe",
                    "status": "observed",
                    "response_status": response.status,
                },
                [ref, response.evidence_id],
                agent.role,
            )
    c.ledger(
        agent.role,
        "web.path_discovery",
        base,
        "verified",
        [ref],
        probes=min(len(cfg.paths), cfg.max_path_probes),
    )

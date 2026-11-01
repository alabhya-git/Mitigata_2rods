"""Forwarding-header access-control bypass probe.

A reverse proxy that decides what to serve from a client-supplied header such as
``X-Forwarded-For`` trusts a value the client can forge. This probe sends a GET with
each candidate internal source address and looks for content that neither the
unspoofed request nor a public-address control returns. All requests are read-only
GETs against the already-scoped destination; only the forwarding header changes.

The detector proposes; the Falsifier re-establishes the three-way differential
(unspoofed vs. internal-spoof vs. public-address control) before any confirmation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

from .extractors import extract_references
from .scope import ScopeDenied

# Headers worth trying, in priority order. The transport layer independently
# allowlists these; listing them here keeps the probe explicit and bounded.
BYPASS_HEADERS = (
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Forwarded-Host",
    "Forwarded",
    "X-Originating-IP",
    "Client-IP",
    "True-Client-IP",
)

# A control address that is unambiguously public: a real proxy keyed on an internal
# source must NOT serve internal content to it. Documentation range TEST-NET-3.
PUBLIC_CONTROL_IP = "203.0.113.7"


def candidate_source_addresses(target_address: str, limit: int = 8) -> list[str]:
    """Internal source addresses a proxy is likely to trust, derived from the target.

    Generic across targets: loopback, common gateways, the target's own address, and
    the first host of each private block containing the target (the usual core-router
    address). No per-target answer is baked in.
    """
    seen: list[str] = []

    def add(value: str) -> None:
        if value and value not in seen:
            seen.append(value)

    for base in ("127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "192.168.1.1"):
        add(base)
    try:
        ip = ipaddress.ip_address(target_address)
    except ValueError:
        ip = None
    if ip is not None and ip.version == 4:
        # The .1 host of the /24 that contains the target: the typical gateway/router.
        add(str(ipaddress.ip_interface(f"{ip}/24").network.network_address + 1))
        # The .1 host of the enclosing private blocks (covers segmented labs).
        for block in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"):
            net = ipaddress.ip_network(block)
            if ip in net:
                add(str(net.network_address + 1))
        add(str(ip))  # the target vouching for itself
    add("0.0.0.0")
    add("localhost")
    return seen[: max(0, limit)]


def _fingerprint(response) -> tuple[int, int, str]:
    """A noise-tolerant identity for a response body: status, bucketed size, title/body hash."""
    text = response.text
    title = ""
    match = re.search(r"<title[^>]*>(.*?)</title>", text, re.IGNORECASE | re.DOTALL)
    if match:
        title = re.sub(r"\s+", " ", match.group(1)).strip().lower()
    stripped = re.sub(r"[0-9a-f]{12,}", "", re.sub(r"\s+", " ", text)).strip()
    digest = hashlib.sha256((title + "\n" + stripped).encode("utf-8", "replace")).hexdigest()
    return response.status, len(response.body) // 64, digest


def is_bypass(baseline, variant) -> bool:
    """True when ``variant`` is materially different content, not just session noise."""
    if variant.truncated or baseline.truncated:
        return False
    if _fingerprint(baseline) == _fingerprint(variant):
        return False
    # Require a real content shift: a different title, or a non-trivial size delta, or a
    # change from a blocked/redirect status to a served one.
    base_title = re.search(r"<title[^>]*>(.*?)</title>", baseline.text, re.IGNORECASE | re.DOTALL)
    var_title = re.search(r"<title[^>]*>(.*?)</title>", variant.text, re.IGNORECASE | re.DOTALL)
    titles_differ = (base_title and base_title.group(1).strip()) != (
        var_title and var_title.group(1).strip()
    )
    size_delta = abs(len(variant.body) - len(baseline.body))
    status_opened = baseline.status in {401, 403, 404, 301, 302} and 200 <= variant.status < 300
    return bool(status_opened or titles_differ or size_delta > 256)


async def probe_forwarding_bypass(agent, task):
    """Web task handler: try forwarding-header spoofing and, on success, propose a finding.

    On a confirmed-looking bypass it also crawls the revealed links with the winning
    header sticky, so content only reachable through the bypass (hidden wikis, vaults,
    artifact directories) is discovered automatically by the normal Web pipeline.
    """
    c = agent.ctx
    cfg = c.manifest.investigation
    if not (
        c.manifest.action_allowed("header_spoof_probe")
        and "web.forwarding_header_bypass" in c.manifest.permitted_checks
    ):
        return
    url = task["target"]
    try:
        baseline = await c.broker.http(url)
    except (OSError, TimeoutError, ValueError, ScopeDenied):
        return
    dest = c.broker.guard.destination(url)
    candidates = candidate_source_addresses(dest.address, cfg.max_header_bypass_ips)
    attempts = 0
    for header in BYPASS_HEADERS:
        for source in candidates:
            if attempts >= max(cfg.max_header_bypass_ips, len(candidates)) * 2:
                break
            attempts += 1
            value = f"for={source}" if header.lower() == "forwarded" else source
            try:
                variant = await c.broker.http(url, extra_headers={header: value})
            except ScopeDenied:
                return
            except (OSError, TimeoutError, ValueError):
                continue
            if not is_bypass(baseline, variant):
                continue
            recipe = c.checks.recipes["web.forwarding_header_bypass"]
            c.candidate(
                agent.role,
                recipe,
                url,
                [baseline.evidence_id, variant.evidence_id],
                header=header,
                source_address=source,
                header_value=value,
                baseline_status=baseline.status,
                variant_status=variant.status,
            )
            await _crawl_revealed(agent, variant, header, value)
            return
    c.ledger(agent.role, "web.forwarding_header_bypass", url, "negative", [baseline.evidence_id])


async def _crawl_revealed(agent, response, header, value):
    """Enqueue in-scope links from bypassed content, carrying the winning header forward."""
    _enqueue_forwarded_links(agent, response, header, value, depth=1)
    # Unlinked internal surface (e.g. an artifact vault the wiki tells you to "fuzz for")
    # is only reachable through the bypass, so boost hidden-segment probes with the header.
    from .web_discovery import boost_from_hints

    boost_from_hints(agent, response, forward=(header, value))


def _enqueue_forwarded_links(agent, response, header, value, depth):
    c = agent.ctx
    source_authority = urlsplit(response.url).netloc
    seen = 0
    for reference in extract_references(response.url, response.text, response.headers):
        if seen >= c.manifest.budgets.max_depth * 8:
            break
        try:
            destination = c.broker.guard.destination(reference["url"])
        except ScopeDenied:
            continue
        if urlsplit(destination.url).netloc != source_authority:
            continue
        seen += 1
        c.store.enqueue(
            c.run_id,
            role="Web",
            kind="forwarded_page",
            target=destination.url,
            payload={"depth": depth, "header": header, "value": value},
        )


async def fetch_forwarded_page(agent, task):
    """Crawl a page through a known-good forwarding header and keep the chain going.

    The bypass chain is NOT subject to the generic max_pages breadth cap: it is the
    high-value internal surface (and the only route to artifacts behind the bypass), and
    it is self-bounded by crawl depth, the per-path fanout cap, and same-authority. Letting
    breadth crawl of the public face starve it is exactly what blocked the artifact fetch.
    It still respects the global request/time budget enforced by the broker. A generous
    ceiling guards against a pathological internal site.
    """
    c, payload = agent.ctx, task["payload"]
    if not c.manifest.action_allowed("header_spoof_probe"):
        return
    header, value = payload["header"], payload["value"]
    depth = payload.get("depth", 1)
    # Generous ceiling independent of the breadth max_pages (which a caller may set small):
    # the forwarded chain is already bounded by depth, fanout and same-authority. Only real
    # content pages count, so speculative 404 hint-probes never crowd out the artifact fetch.
    if c.forwarded_count >= max(c.manifest.budgets.max_pages, 256):
        return
    try:
        response = await c.broker.http(task["target"], extra_headers={header: value})
    except (OSError, TimeoutError, ValueError, ScopeDenied):
        return
    if response.status < 400:
        c.forwarded_count += 1
    # Run the full web analysis (checks, flag scan, artifact handoff, header-aware hint
    # boost) on the revealed body, carrying the forwarding context so any finding here can
    # be re-verified through it.
    await agent.consume(response, depth, forward=(header, value))
    if depth >= c.manifest.budgets.max_depth:
        return
    _enqueue_forwarded_links(agent, response, header, value, depth=depth + 1)

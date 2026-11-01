from __future__ import annotations

import hashlib
import io
import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from .binary import credential_records
from .checks import CheckRegistry, Recipe
from .config import ScopeManifest
from .evidence import EvidenceStore
from .extractors import (
    CREDENTIAL_RE,
    INJECTION_RE,
    equivalent_response,
    extract_references,
    is_directory_listing,
    is_verbose_error,
    parse_page,
)
from .scope import ScopeDenied
from .security import FLAG_PATTERN
from .store import Store, encoded
from .transport import Broker, BudgetExceeded, Response


@dataclass
class Context:
    run_id: str
    manifest: ScopeManifest
    store: Store
    evidence: EvidenceStore
    broker: Broker
    checks: CheckRegistry
    ai_client: object | None = None
    web_consume: object | None = None
    # Per-run count of distinct query-string variants enqueued per path, to defuse
    # parameter-explosion crawl traps (file managers, calendars, faceted search) that would
    # otherwise consume the whole budget before the real attack chain runs.
    crawl_fanout: dict = field(default_factory=dict)
    # Pages fetched through a forwarding bypass. Counted separately so the high-value
    # internal chain is not starved by the generic breadth page cap.
    forwarded_count: int = 0

    def ledger(self, role, check_id, target, status, evidence=(), **extra):
        self.store.put(
            self.run_id,
            "check",
            f"{check_id}:{target}",
            {"check_id": check_id, "target": target, "status": status, **extra},
            evidence,
            role,
        )

    def candidate(self, role, recipe: Recipe, target, evidence, **details):
        if not self.manifest.check_allowed(recipe.id):
            self.ledger(role, recipe.id, target, "blocked_scope", reason="check_not_permitted")
            return None
        if self.manifest.mode == "DISCOVERY_ONLY" and recipe.surface != "binary":
            self.store.put(
                self.run_id,
                "observation",
                f"potential:{recipe.id}:{target}",
                {
                    "type": "potential_issue",
                    "check_id": recipe.id,
                    "target": target,
                    "status": "unverified",
                    "claim": recipe.claim,
                    "reason": "Discovery-only run; network verification was not performed",
                },
                evidence,
                role,
            )
            self.ledger(role, recipe.id, target, "not_assessed", evidence, reason="discovery_only")
            return None
        identity = recipe.id + ":" + target
        existing = self.store.get(self.run_id, "finding", identity)
        if existing and existing["data"]["status"] != "candidate":
            return existing["id"]
        data = {**recipe.model_dump(), "target": target, "status": "candidate", "details": details}
        finding_id = self.store.publish(
            self.run_id,
            "finding",
            identity,
            data,
            evidence,
            role,
            tasks=[
                {
                    "role": "Falsifier",
                    "kind": "verify",
                    "target": identity,
                    "payload": {"finding_identity": identity},
                    "revision": hashlib.sha256(encoded(evidence).encode()).hexdigest(),
                }
            ],
        )
        self.ledger(role, recipe.id, target, "queued", evidence, finding_id=finding_id)
        return finding_id

    def handoff(self, role, to_role, target, evidence, suggested_action, **extra):
        key = hashlib.sha256(
            encoded([role, to_role, target, suggested_action, evidence]).encode()
        ).hexdigest()
        return self.store.put(
            self.run_id,
            "handoff",
            key,
            {
                "from": role,
                "to_role": to_role,
                "target": target,
                "suggested_action": suggested_action,
                "scope_result": "in_scope",
                **extra,
            },
            evidence,
            role,
        )


class Agent:
    role = ""
    tools: tuple[str, ...] = ()

    def __init__(self, context: Context):
        self.ctx = context

    async def execute(self, task):
        if task["kind"] == "investigate":
            from .investigation import run_case

            await run_case(self, task)
            return
        handler = getattr(self, "do_" + task["kind"], None)
        if handler is None:
            raise ValueError(f"Unregistered task kind for {self.role}")
        await handler(task)


class ReconAgent(Agent):
    role = "Recon"
    tools = ("tcp_connect", "http_identify", "redis_read_only_identify")

    async def do_challenge(self, task):
        from .protocols import investigate_dialogue

        await investigate_dialogue(self, task)

    async def do_protocol(self, task):
        from .protocols import investigate_protocol

        await investigate_protocol(self, task)

    async def do_batch(self, task):
        from .discovery import scan_batch

        await scan_batch(self.ctx, task["payload"]["start"], task["payload"]["end"])

    async def do_identify(self, task):
        c, data = self.ctx, task["payload"]
        try:
            banner, evidence = await c.broker.tcp(data["address"], data["port"])
        except (OSError, TimeoutError):
            banner, evidence = b"", data["evidence_id"]
        await self.identify(data["address"], data["port"], banner, evidence, data.get("evidence_id"))

    async def do_scan(self, task):
        c = self.ctx
        address, port = task["payload"]["address"], task["payload"]["port"]
        key = f"{address}:{port}"
        try:
            banner, evidence = await c.broker.tcp(address, port)
        except (OSError, TimeoutError) as exc:
            status = (
                "closed"
                if isinstance(exc, ConnectionRefusedError) or getattr(exc, "winerror", None) == 10061
                else "filtered_unknown"
            )
            evidence = c.evidence.capture(
                c.run_id,
                type(exc).__name__.encode(),
                kind="connect_result",
                metadata={"address": address, "port": port},
            )
            c.store.put(
                c.run_id,
                "port",
                key,
                {"address": address, "port": port, "status": status},
                [evidence],
                self.role,
            )
            return
        c.store.put(
            c.run_id, "port", key, {"address": address, "port": port, "status": "open"}, [evidence], self.role
        )
        await self.identify(address, port, banner, evidence)

    async def identify(self, address, port, banner, evidence, prior_evidence=None):
        c, key = self.ctx, f"{address}:{port}"
        investigation_refs = list(dict.fromkeys(r for r in (prior_evidence, evidence) if r))
        c.store.put(
            c.run_id, "asset", address, {"address": address, "status": "reachable"}, [evidence], self.role
        )
        authority = f"[{address}]" if ":" in address else address
        base = f"http://{authority}:{port}/"
        for seed in c.manifest.seed_urls:
            dest = c.broker.guard.destination(seed)
            if dest.address == address and dest.port == port:
                base = dest.url
                break
        protocol, response = "tcp", None
        if banner.startswith(b"SSH-"):
            protocol = "ssh"
        else:
            try:
                response = await c.broker.http(base)
                protocol = urlsplit(response.url).scheme
                evidence = response.evidence_id
            except (OSError, TimeoutError, ValueError, http_client_error()):
                if not base.startswith("https:") and c.manifest.action_allowed("http_get"):
                    secure_base = "https:" + base[5:]
                    try:
                        response = await c.broker.http(secure_base)
                        protocol, evidence, base = "https", response.evidence_id, secure_base
                    except (OSError, TimeoutError, ValueError, http_client_error()) as tls_error:
                        import ssl

                        if isinstance(tls_error, ssl.SSLCertVerificationError):
                            tls_ref = c.evidence.capture(
                                c.run_id,
                                str(tls_error.verify_message).encode(),
                                kind="tls_validation",
                                metadata={"address": address, "port": port, "url": secure_base},
                            )
                            c.store.put(
                                c.run_id,
                                "observation",
                                "tls_validation:" + key,
                                {
                                    "type": "tls_validation_failed",
                                    "url": secure_base,
                                    "claim": "TLS peer certificate could not be verified; application checks remain unassessed. Supply the organizer CA using SSL_CERT_FILE when appropriate.",
                                },
                                [tls_ref],
                                self.role,
                            )
                if (
                    response is None
                    and c.manifest.check_allowed("network.redis_unauthenticated_info")
                    and c.manifest.action_allowed("redis_info")
                ):
                    try:
                        info, redis_evidence = await c.broker.tcp(address, port, b"*1\r\n$4\r\nINFO\r\n")
                        if b"redis_version:" in info and b"# Server" in info:
                            protocol, evidence = "redis", redis_evidence
                    except (OSError, TimeoutError, ValueError):
                        pass
        service = {
            "address": address,
            "port": port,
            "protocol": protocol,
            "base_url": base,
            "identity_status": "observed",
            "absent_from_baseline": base not in c.manifest.baseline_urls,
        }
        tasks = []
        # Explicit membership only (never the LOCAL_LAB/"*" shortcut) so the reference
        # lab's arithmetic-challenge path is unchanged; richer scripting is opt-in.
        scripting = "protocol_scripting" in c.manifest.allowed_actions
        if (
            protocol == "tcp"
            and c.manifest.investigation.enabled
            and (scripting or c.manifest.action_allowed("challenge_interaction"))
        ):
            tasks.append(
                {
                    "role": "Recon",
                    "kind": "protocol" if scripting else "challenge",
                    "target": key,
                    "payload": {"address": address, "port": port},
                }
            )
        if response:
            tasks.append(
                {
                    "role": "Web",
                    "kind": "page",
                    "target": response.url,
                    "payload": {"existing_evidence": response.evidence_id, "depth": 0},
                }
            )
        tasks.append({"role": "Correlator", "kind": "correlate", "target": key, "revision": evidence})
        c.store.publish(c.run_id, "service", key, service, [evidence], self.role, tasks)
        if c.ai_client is not None:
            investigation_refs.append(evidence)
            for url in (base, "https:" + base[5:] if base.startswith("http:") else base):
                failure = c.store.get(c.run_id, "observation", "http_failure:" + url)
                if failure:
                    investigation_refs.extend(failure["evidence"])
            investigation_refs = list(dict.fromkeys(investigation_refs))[:4]
            c.store.enqueue(
                c.run_id,
                role="Recon",
                kind="investigate",
                target=base,
                payload={"evidence_ids": investigation_refs},
            )
            c.store.enqueue(
                c.run_id,
                role="Correlator",
                kind="investigate",
                target=key,
                payload={"evidence_ids": investigation_refs},
            )
        if response:
            c.handoff(self.role, "Web", response.url, [evidence], "crawl identified HTTP service")
        if protocol == "redis":
            for recipe in c.checks.by_primitive("redis_info"):
                c.candidate(self.role, recipe, key, [evidence], address=address, port=port)
        if service["absent_from_baseline"]:
            c.store.put(
                c.run_id,
                "observation",
                "unlisted:" + key,
                {
                    "type": "unlisted_service",
                    "service": key,
                    "claim": "Reachable service absent from the supplied baseline; ownership/shadow-IT status not established.",
                },
                [evidence],
                self.role,
            )


def http_client_error():
    from http.client import HTTPException

    return HTTPException


class WebAgent(Agent):
    role = "Web"
    tools = ("http_get", "parse_html", "extract_references", "credential_challenge_probe")

    async def do_paths(self, task):
        from .web_discovery import discover_paths

        await discover_paths(self, task)

    async def do_browser(self, task):
        from .browser import render_page

        await render_page(self, task)

    async def do_external_tools(self, task):
        from .external_web import discover_with_tools

        await discover_with_tools(self, task)

    async def do_page(self, task):
        c, payload = self.ctx, task["payload"]
        depth = payload.get("depth", 0)
        session_ref = payload.get("session_ref")
        credential = c.store.reveal(c.run_id, session_ref, self.role) if session_ref else None
        if len(c.store.records(c.run_id, "endpoint")) >= c.manifest.budgets.max_pages:
            c.ledger(self.role, "web.crawl", task["target"], "budget_exhausted", reason="page_limit")
            return
        if payload.get("existing_evidence"):
            row = c.store.by_id(c.run_id, payload["existing_evidence"])
            meta = row["data"]["metadata"]
            response = Response(
                meta["url"], meta["status"], meta["headers"], c.evidence.read(c.run_id, row["id"]), row["id"]
            )
        else:
            try:
                response = await c.broker.http(task["target"], credential=credential)
            except (OSError, TimeoutError, http_client_error()) as exc:
                # A transient per-page network error (the broker already recorded the
                # http_failure) is not an engine-integrity failure; log and move on so one
                # flaky fetch during a large crawl does not fail the whole assessment.
                c.ledger(
                    self.role,
                    "web.crawl",
                    task["target"],
                    "inconclusive",
                    reason=f"transient_fetch_error:{type(exc).__name__}",
                )
                return
        await self.consume(response, depth, session_ref, payload.get("action_id"))

    async def consume(self, response, depth, session_ref=None, action_id=None, forward=None):
        c = self.ctx
        identity = response.url + "|" + (session_ref or "anonymous")
        # If this page was reached through a forwarding bypass, every finding raised here
        # must record the header so the Falsifier can re-retrieve it the same way.
        forward_details = {"forward_header": forward[0], "forward_value": forward[1]} if forward else {}
        parser = parse_page(response.text)
        endpoint_id = c.store.put(
            c.run_id,
            "endpoint",
            identity,
            {
                "url": response.url,
                "status": response.status,
                "content_type": response.headers.get("content-type", ""),
                "depth": depth,
                "session": session_ref or "anonymous",
                "forms": [
                    {
                        **f,
                        "fields": [{k: v for k, v in field.items() if k != "value"} for field in f["fields"]],
                    }
                    for f in parser.forms
                ],
                "action_id": action_id,
            },
            [response.evidence_id],
            self.role,
        )
        c.ledger(self.role, "web.crawl", identity, "verified", [response.evidence_id])
        if c.manifest.investigation.enabled:
            from .web_discovery import consume_extended

            await consume_extended(self, response, depth, session_ref, forward=forward)
        if INJECTION_RE.search(response.text):
            c.store.put(
                c.run_id,
                "observation",
                "untrusted-instruction:" + endpoint_id,
                {
                    "type": "hostile_content",
                    "claim": "Target-derived instruction-shaped text recorded as data; this deterministic run makes no LLM resistance claim.",
                },
                [response.evidence_id],
                self.role,
            )
        if (
            c.manifest.check_allowed("web.input_reflection") or c.manifest.check_allowed("web.reflected_xss")
        ) and c.manifest.action_allowed("input_reflection"):
            for form in parser.forms[:3]:
                fields = [f["name"] for f in form["fields"] if f["type"] in {"text", "search", "email"}][:3]
                if form["method"] != "GET" or not fields:
                    continue
                target = urljoin(response.url, form["action"])
                try:
                    c.broker.guard.destination(target)
                except ScopeDenied:
                    continue
                child_session = (
                    session_ref if urlsplit(target).netloc == urlsplit(response.url).netloc else None
                )
                c.store.enqueue(
                    c.run_id,
                    role="Web",
                    kind="reflection",
                    target=target,
                    payload={"fields": fields, "session_ref": child_session},
                    session=child_session or "anonymous",
                )
        # Opt-in extended detectors. Gated on EXPLICIT membership (never the LOCAL_LAB or "*"
        # shortcut) so the demo/benchmark behaviour is unchanged and these run only when a
        # manifest requests them. Every candidate they raise is confirmed by a differential control.
        if (
            response.status == 401
            and "basic" in response.headers.get("www-authenticate", "").lower()
            and c.manifest.allow_credential_use
            and "default_credential_probe" in c.manifest.allowed_actions
            and "web.default_credentials" in c.manifest.permitted_checks
        ):
            gate = urlsplit(response.url)
            c.store.enqueue(
                c.run_id,
                role="Web",
                kind="default_cred",
                target=urlunsplit((gate.scheme, gate.netloc, "/", "", "")),  # one probe per authority
                payload={"gate_url": response.url, "evidence_id": response.evidence_id},
            )
        if "injection_probe" in c.manifest.allowed_actions and any(
            cid in c.manifest.permitted_checks
            for cid in ("web.path_traversal", "web.sql_injection", "web.ssti", "web.open_redirect")
        ):
            injection_targets = []
            existing = parse_qsl(urlsplit(response.url).query, keep_blank_values=True)
            if existing:
                injection_targets.append((response.url, [k for k, _ in existing][:4]))
            for form in parser.forms[:3]:
                names = [
                    f["name"]
                    for f in form["fields"]
                    if f.get("name") and f["type"] in {"text", "search", "email", "url", "hidden", "number"}
                ][:4]
                if form["method"] == "GET" and names:
                    action = urljoin(response.url, form["action"])
                    try:
                        c.broker.guard.destination(action)
                    except ScopeDenied:
                        continue
                    injection_targets.append((action, names))
            for target, names in injection_targets[:4]:
                c.store.enqueue(
                    c.run_id,
                    role="Web",
                    kind="injection",
                    target=target,
                    payload={"fields": names, "session_ref": session_ref},
                    session=session_ref or "anonymous",
                )
        if response.status == 200 and "network.elasticsearch_unauthenticated" in c.manifest.permitted_checks:
            from .injection import datastore_signature

            if datastore_signature(response.url, response.text):
                for recipe in c.checks.by_primitive("http_service_unauth"):
                    c.candidate(self.role, recipe, response.url, [response.evidence_id], **forward_details)
        # Probe forwarding-header trust once per authority, at the root, before auth state.
        if (
            depth == 0
            and not session_ref
            and c.manifest.action_allowed("header_spoof_probe")
            and "web.forwarding_header_bypass" in c.manifest.permitted_checks
        ):
            gate = urlsplit(response.url)
            c.store.enqueue(
                c.run_id,
                role="Web",
                kind="header_bypass",
                target=urlunsplit((gate.scheme, gate.netloc, "/", "", "")),
            )
        # Flag a publicly readable operational/infrastructure document.
        if (
            response.status == 200
            and not response.truncated
            and "web.sensitive_document" in c.manifest.permitted_checks
        ):
            from .extractors import sensitive_document_signature

            content_type = response.headers.get("content-type", "")
            if ("text" in content_type or "json" in content_type or not content_type) and (
                hits := sensitive_document_signature(response.text)
            ):
                c.candidate(
                    self.role,
                    c.checks.recipes["web.sensitive_document"],
                    response.url,
                    [response.evidence_id],
                    categories=hits,
                    session_ref=session_ref,
                    **forward_details,
                )
        if response.status < 400:
            missing = [
                h for h in ("content-security-policy", "x-content-type-options") if h not in response.headers
            ]
            if missing:
                c.store.put(
                    c.run_id,
                    "observation",
                    "headers:" + identity,
                    {
                        "type": "missing_security_headers",
                        "missing": missing,
                        "claim": "Defense-in-depth headers absent; no exploit established.",
                    },
                    [response.evidence_id],
                    self.role,
                )
            for recipe in c.checks.for_surface("web"):
                if not urlsplit(response.url).path.startswith(recipe.path_prefix):
                    continue
                if recipe.primitive == "credential_literal" and session_ref:
                    continue
                json_matches = False
                if recipe.primitive == "json_document" and recipe.required_keys:
                    try:
                        document = json.loads(response.text)
                        json_matches = isinstance(document, dict) and all(
                            key in document for key in recipe.required_keys
                        )
                    except ValueError:
                        pass
                detected = (
                    recipe.primitive == "directory_listing"
                    and is_directory_listing(response.text)
                    or recipe.primitive == "credential_literal"
                    and bool(CREDENTIAL_RE.search(response.text))
                    or recipe.primitive == "verbose_error"
                    and is_verbose_error(response.text)
                    or json_matches
                )
                if recipe.primitive not in {
                    "directory_listing",
                    "credential_literal",
                    "verbose_error",
                    "json_document",
                }:
                    continue
                if detected:
                    c.candidate(
                        self.role,
                        recipe,
                        response.url,
                        [response.evidence_id],
                        session_ref=session_ref,
                        **forward_details,
                    )
                else:
                    c.ledger(self.role, recipe.id, identity, "negative", [response.evidence_id])
            from .codes import candidates

            if FLAG_PATTERN.search(response.text) or (
                c.manifest.investigation.enabled
                and candidates(response.body, c.manifest.investigation.flag_patterns, response.url)
            ):
                c.store.enqueue(
                    c.run_id,
                    role="Code",
                    kind="capture",
                    target=response.url,
                    payload={
                        "evidence_id": response.evidence_id,
                        "session_ref": session_ref,
                        "action_id": action_id,
                    },
                )
        if depth >= c.manifest.budgets.max_depth:
            c.ledger(
                self.role,
                "web.references",
                identity,
                "budget_exhausted",
                [response.evidence_id],
                reason="depth_limit",
            )
            return
        fanout_cap = 8  # distinct query-string variants crawled per path
        for reference in extract_references(response.url, response.text, response.headers):
            try:
                destination = c.broker.guard.destination(reference["url"])
            except ScopeDenied:
                c.store.put(
                    c.run_id,
                    "discovery",
                    reference["url"],
                    {**reference, "status": "blocked_scope"},
                    [response.evidence_id],
                    self.role,
                )
                continue
            # Parameter-explosion trap guard: a path reached with many different query
            # strings (e.g. a file manager's ?p=&view=&dl= links) is crawled only up to a
            # bounded number of variants. Query-less URLs are never capped here.
            parts = urlsplit(destination.url)
            if parts.query:
                path_key = f"{parts.scheme}://{parts.netloc}{parts.path}"
                seen = c.crawl_fanout.get(path_key, 0)
                if seen >= fanout_cap:
                    c.store.put(
                        c.run_id,
                        "discovery",
                        destination.url,
                        {**reference, "url": destination.url, "status": "fanout_capped"},
                        [response.evidence_id],
                        self.role,
                    )
                    continue
                c.crawl_fanout[path_key] = seen + 1
            source_authority = urlsplit(response.url).netloc
            child_session = session_ref if urlsplit(destination.url).netloc == source_authority else None
            c.store.publish(
                c.run_id,
                "discovery",
                destination.url,
                {**reference, "url": destination.url, "status": "in_scope"},
                [response.evidence_id],
                self.role,
                tasks=[
                    {
                        "role": "Web",
                        "kind": "page",
                        "target": destination.url,
                        "payload": {
                            "depth": depth + 1,
                            "session_ref": child_session,
                            "action_id": action_id if child_session else None,
                        },
                        "session": child_session or "anonymous",
                    }
                ],
            )
        # A small, bounded known-file stage complements links and scripts.
        if depth == 0 and not session_ref:
            for suffix in ("robots.txt", "sitemap.xml", ".env"):
                candidate = urljoin(response.url, "/" + suffix)
                try:
                    c.broker.guard.destination(candidate)
                except ScopeDenied:
                    continue
                c.store.enqueue(
                    c.run_id,
                    role="Web",
                    kind="page",
                    target=candidate,
                    payload={"depth": 1, "session_ref": None, "action_id": None},
                )

    async def do_auth_probe(self, task):
        c, payload = self.ctx, task["payload"]
        credential = c.store.reveal(c.run_id, payload["secret_ref"], self.role)
        anonymous = await c.broker.http(task["target"])
        if anonymous.status != 401 or "basic" not in anonymous.headers.get("www-authenticate", "").lower():
            from .authentication import password_form

            if c.manifest.action_allowed("session_authentication") and password_form(anonymous):
                for recipe in c.checks.by_primitive("form_auth"):
                    c.candidate(
                        self.role,
                        recipe,
                        task["target"],
                        [anonymous.evidence_id, payload["artifact_evidence"]],
                        secret_ref=payload["secret_ref"],
                        binary_finding=payload["binary_finding"],
                        service_id=payload["service_id"],
                        action_id=payload["action_id"],
                    )
                return
            c.ledger(
                self.role,
                "web.embedded_credential_accepted",
                task["target"],
                "negative",
                [anonymous.evidence_id],
                reason="No supported Basic authentication challenge; no credential was offered",
            )
            return
        for recipe in c.checks.by_primitive("basic_auth"):
            c.candidate(
                self.role,
                recipe,
                task["target"],
                [anonymous.evidence_id, payload["artifact_evidence"]],
                secret_ref=payload["secret_ref"],
                binary_finding=payload["binary_finding"],
                service_id=payload["service_id"],
                action_id=payload["action_id"],
                username=credential["username"],
            )

    async def do_reflection(self, task):
        c, payload = self.ctx, task["payload"]
        if not c.manifest.action_allowed("input_reflection"):
            raise ScopeDenied("Input probes are not permitted in this engagement")
        marker = "mitigata_canary_" + uuid.uuid4().hex
        parts = urlsplit(task["target"])
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query.update({name: marker for name in payload["fields"]})
        url = urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))
        credential = (
            c.store.reveal(c.run_id, payload["session_ref"], self.role)
            if payload.get("session_ref")
            else None
        )
        response = await c.broker.http(url, credential=credential)
        if marker in response.text:
            c.store.put(
                c.run_id,
                "observation",
                "reflection:" + task["target"],
                {
                    "type": "input_reflection",
                    "url": task["target"],
                    "fields": payload["fields"],
                    "claim": "A harmless alphanumeric input is reflected. Script execution/XSS is not established.",
                },
                [response.evidence_id],
                self.role,
            )
            if c.manifest.investigation.browser:
                for recipe in c.checks.by_primitive("browser_xss"):
                    c.candidate(
                        self.role, recipe, task["target"], [response.evidence_id], fields=payload["fields"]
                    )
        c.ledger(
            self.role,
            "web.input_reflection",
            task["target"],
            "verified" if marker in response.text else "negative",
            [response.evidence_id],
        )

    async def do_default_cred(self, task):
        c = self.ctx
        if not (c.manifest.allow_credential_use and c.manifest.action_allowed("default_credential_probe")):
            raise ScopeDenied("Default-credential probing is not permitted")
        target = task["payload"].get("gate_url", task["target"])
        anonymous = await c.broker.http(target)
        if anonymous.status != 401 or "basic" not in anonymous.headers.get("www-authenticate", "").lower():
            c.ledger(
                self.role, "web.default_credentials", target, "negative", [anonymous.evidence_id],
                reason="no_basic_challenge",
            )
            return
        budget = max(0, c.manifest.budgets.max_auth_attempts - 3)  # reserve attempts for verification
        tried = 0
        for item in c.manifest.investigation.default_credentials:
            if tried >= budget:
                break
            if ":" not in item:
                continue
            username, password = item.split(":", 1)
            tried += 1
            try:
                attempt = await c.broker.http(target, credential={"username": username, "password": password})
            except BudgetExceeded:
                break
            except (OSError, TimeoutError, ValueError):
                continue
            if 200 <= attempt.status < 300 and "www-authenticate" not in attempt.headers:
                secret_ref = c.store.secret(
                    c.run_id, {"username": username, "password": password}, roles=("Web", "Falsifier", "Code")
                )
                for recipe in c.checks.by_primitive("default_credentials"):
                    c.candidate(
                        self.role, recipe, target, [anonymous.evidence_id, attempt.evidence_id],
                        secret_ref=secret_ref, username=username,
                    )
                return
        c.ledger(
            self.role, "web.default_credentials", target, "negative", [anonymous.evidence_id],
            reason="no_default_accepted", attempts=tried,
        )

    async def do_injection(self, task):
        c, payload = self.ctx, task["payload"]
        if not c.manifest.action_allowed("injection_probe"):
            raise ScopeDenied("Injection probes are not permitted")
        from .injection import SSTI_PAYLOADS, TRAVERSAL_PAYLOADS, sql_error_hit, ssti_hit, traversal_hit

        fields = [f for f in payload.get("fields", []) if f][:4]
        if not fields:
            return
        session_ref = payload.get("session_ref")
        credential = c.store.reveal(c.run_id, session_ref, self.role) if session_ref else None
        parts = urlsplit(task["target"])
        base_query = dict(parse_qsl(parts.query, keep_blank_values=True))

        def build(value):
            query = dict(base_query)
            query.update({name: value for name in fields})
            return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))

        benign = "mitigata" + uuid.uuid4().hex[:10]
        try:
            baseline = await c.broker.http(build(benign), credential=credential)
        except (OSError, TimeoutError, ValueError, ScopeDenied, BudgetExceeded):
            c.ledger(self.role, "web.injection", task["target"], "inconclusive", reason="baseline_unavailable")
            return
        families = [
            ("web.path_traversal", TRAVERSAL_PAYLOADS, traversal_hit),
            ("web.sql_injection", (benign + "'", benign + '"', benign + "')"), sql_error_hit),
            ("web.ssti", SSTI_PAYLOADS, ssti_hit),
        ]
        for recipe_id, payloads, hit in families:
            if recipe_id not in c.manifest.permitted_checks or hit(baseline.text):
                continue
            for probe in payloads:
                try:
                    response = await c.broker.http(build(probe), credential=credential)
                except (OSError, TimeoutError, ValueError, ScopeDenied, BudgetExceeded):
                    break
                if not response.truncated and hit(response.text):
                    c.candidate(
                        self.role, c.checks.recipes[recipe_id], task["target"],
                        [baseline.evidence_id, response.evidence_id],
                        fields=fields, payload=probe, session_ref=session_ref,
                    )
                    break
        if "web.open_redirect" in c.manifest.permitted_checks:
            marker = urlunsplit((parts.scheme, parts.netloc, "/mitigata-redir-" + uuid.uuid4().hex[:10], "", ""))
            try:
                positive = await c.broker.http(build(marker), credential=credential, follow_redirects=False)
                control = await c.broker.http(build(benign), credential=credential, follow_redirects=False)
            except (OSError, TimeoutError, ValueError, ScopeDenied, BudgetExceeded):
                positive = control = None
            if (
                positive is not None
                and positive.status in {301, 302, 303, 307, 308}
                and marker in positive.headers.get("location", "")
                and marker not in control.headers.get("location", "")
            ):
                c.candidate(
                    self.role, c.checks.recipes["web.open_redirect"], task["target"],
                    [positive.evidence_id, control.evidence_id], fields=fields, session_ref=session_ref,
                )
        c.ledger(self.role, "web.injection", task["target"], "verified", [baseline.evidence_id], fields=fields)

    async def do_header_bypass(self, task):
        from .web_auth_bypass import probe_forwarding_bypass

        await probe_forwarding_bypass(self, task)

    async def do_forwarded_page(self, task):
        from .web_auth_bypass import fetch_forwarded_page

        await fetch_forwarded_page(self, task)


class BinaryAgent(Agent):
    role = "Binary"
    tools = ("read_supplied_artifact", "extract_printable_strings", "elf_metadata", "pe_metadata")

    async def do_analyze(self, task):
        c = self.ctx
        if (
            c.manifest.investigation.enabled
            and c.store.count_records(c.run_id, "artifact") >= c.manifest.investigation.max_artifacts
        ):
            c.ledger(
                self.role, "binary.analysis", task["target"], "budget_exhausted", reason="artifact_limit"
            )
            return
        if task["payload"].get("download_evidence"):
            original = c.store.by_id(c.run_id, task["payload"]["download_evidence"])
            if (
                not original
                or original["kind"] != "evidence"
                or original["data"]["kind"] not in {"http", "archive_member"}
            ):
                raise ScopeDenied("Downloaded artifact must come from scoped HTTP evidence")
            raw = c.evidence.read(c.run_id, original["id"])
            path = Path(task["payload"].get("name", "downloaded-artifact"))
            if len(raw) > c.manifest.budgets.max_artifact_bytes:
                raise ValueError("Artifact exceeds size budget")
        else:
            root = Path(c.manifest.artifact_root).resolve(strict=True)
            supplied = Path(task["target"])
            path = supplied if supplied.is_absolute() else root / supplied
            if path.is_symlink() or not path.resolve(strict=True).is_relative_to(root):
                raise ScopeDenied("Artifact escapes the approved artifact root")
            path = path.resolve(strict=True)
            if not path.is_file() or path.stat().st_size > c.manifest.budgets.max_artifact_bytes:
                raise ValueError("Artifact size/type is not supported")
            raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        evidence = c.evidence.capture(c.run_id, raw, kind="artifact", metadata={"name": path.name})
        artifact = {
            "name": path.name,
            "sha256": digest,
            "bytes": len(raw),
            "format": "unknown",
            "imports": [],
        }
        strings = [
            {"offset": m.start(), "text": m.group().decode("ascii")}
            for m in re.finditer(rb"[\x20-\x7e]{4,512}", raw)
        ][:2000]
        try:
            if raw.startswith(b"\x7fELF"):
                from elftools.elf.elffile import ELFFile

                elf = ELFFile(io.BytesIO(raw))
                artifact.update(format="ELF", machine=elf.header.e_machine, elf_type=elf.header.e_type)
                dynamic = elf.get_section_by_name(".dynsym")
                if dynamic:
                    artifact["imports"] = [
                        s.name for s in dynamic.iter_symbols() if s.entry.st_shndx == "SHN_UNDEF"
                    ][:256]
                artifact["executable_stack"] = any(
                    s.header.p_type == "PT_GNU_STACK" and s.header.p_flags & 1 for s in elf.iter_segments()
                )
                if elf.header.e_type == "ET_EXEC":
                    for recipe in c.checks.by_primitive("elf_pie"):
                        c.candidate(self.role, recipe, digest, [evidence], artifact_evidence=evidence)
            elif raw.startswith(b"MZ"):
                import pefile

                pe = pefile.PE(data=raw, fast_load=True)
                pe.parse_data_directories(
                    directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
                )
                artifact.update(
                    format="PE",
                    machine=pe.FILE_HEADER.Machine,
                    dll_characteristics=pe.OPTIONAL_HEADER.DllCharacteristics,
                )
                artifact["imports"] = [
                    entry.name.decode(errors="replace")
                    for dll in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
                    for entry in dll.imports
                    if entry.name
                ][:256]
                pe.close()
        except Exception as exc:  # noqa: BLE001 - third-party parsers raise format-specific exceptions
            # Parser failures are evidence of an unsupported/invalid input, not a vulnerability.
            artifact["parser_status"] = "unsupported_or_invalid"
            artifact["parser_error"] = type(exc).__name__
        artifact_id = c.store.put(c.run_id, "artifact", digest, artifact, [evidence], self.role)
        if c.manifest.tools.binary_tools:
            from .static_tools import inspect_artifact

            await inspect_artifact(self, raw, digest)
        if c.manifest.investigation.enabled:
            if raw.startswith(b"PK\x03\x04"):
                from .artifacts import archive_members

                for name, member in archive_members(raw, c.manifest.budgets.max_artifact_bytes):
                    member_ref = c.evidence.capture(
                        c.run_id,
                        member,
                        kind="archive_member",
                        metadata={"archive_sha256": digest, "member": name, "parent_evidence": evidence},
                    )
                    c.store.enqueue(
                        c.run_id,
                        role="Binary",
                        kind="analyze",
                        target=digest + ":" + name,
                        payload={"download_evidence": member_ref, "name": name},
                    )
            from .codes import candidates

            if candidates(raw, c.manifest.investigation.flag_patterns, str(path.name)):
                c.store.enqueue(
                    c.run_id,
                    role="Code",
                    kind="capture",
                    target="artifact:" + digest,
                    payload={"evidence_id": evidence, "source_hint": str(path.name)},
                )
            c.store.enqueue(
                c.run_id,
                role="Binary",
                kind="investigate",
                target=digest,
                payload={"evidence_ids": [evidence]},
            )
            from .extractors import extract_references

            for ref in extract_references("http://invalid.invalid/", raw.decode(errors="replace"), {}):
                if "invalid.invalid" in ref["url"]:
                    continue
                try:
                    url = c.broker.guard.destination(ref["url"]).url
                except ScopeDenied:
                    c.store.put(
                        c.run_id,
                        "discovery",
                        ref["url"],
                        {**ref, "status": "blocked_scope", "surface": "binary"},
                        [evidence],
                        self.role,
                    )
                    continue
                c.handoff(self.role, "Web", url, [evidence], "investigate artifact URL")
                c.store.enqueue(c.run_id, role="Web", kind="page", target=url, payload={"depth": 1})
        unsafe = sorted(set(artifact["imports"]) & {"gets", "strcpy", "strcat", "sprintf", "scanf"})
        if unsafe:
            c.store.put(
                c.run_id,
                "observation",
                "unsafe-import:" + digest,
                {
                    "type": "unsafe_import",
                    "imports": unsafe,
                    "claim": "Unsafe imports are indicators; call-site reachability and exploitation are not established.",
                },
                [evidence],
                self.role,
            )
        for recovered in credential_records(raw):
            service_url = recovered["service_url"]
            try:
                service_url = c.broker.guard.destination(service_url).url
            except ScopeDenied:
                c.store.put(
                    c.run_id,
                    "discovery",
                    service_url,
                    {"url": service_url, "status": "blocked_scope", "method": "binary-string"},
                    [evidence],
                    self.role,
                )
                continue
            secret_ref = c.store.secret(
                c.run_id,
                {
                    "username": recovered["username"],
                    "password": recovered["password"],
                    "service_url": service_url,
                },
            )
            offset = recovered["string_offset"]
            for recipe in c.checks.by_primitive("binary_credential"):
                c.candidate(
                    self.role,
                    recipe,
                    f"{digest}@{offset}",
                    [evidence],
                    artifact_id=artifact_id,
                    artifact_evidence=evidence,
                    secret_ref=secret_ref,
                    string_offset=offset,
                    service_url=service_url,
                    service_offset=recovered["service_offset"],
                    record_format=recovered["format"],
                )
            c.handoff(
                self.role,
                "Correlator",
                service_url,
                [evidence],
                "correlate service-bound credential",
                secret_ref=secret_ref,
                offset=offset,
            )
        if (
            c.manifest.investigation.enabled
            and "binary.obfuscated_credential" in c.manifest.permitted_checks
        ):
            from .binary import xor_encoded_candidates

            for recovered in xor_encoded_candidates(raw):
                secret_ref = c.store.secret(
                    c.run_id,
                    {"value": recovered["value"], "origin": "xor_encoded_artifact"},
                    roles=("Recon", "Falsifier", "Code", "Web"),
                )
                target = f"{digest}@{recovered['blob_offset']}"
                c.store.put(
                    c.run_id,
                    "recovered_secret",
                    target,
                    {
                        "secret_ref": secret_ref,
                        "origin": "binary_xor",
                        "artifact": digest,
                        "key_literal": recovered["key"],
                        "claim": "Obfuscated value deterministically recovered from the artifact; service usability is a separate claim.",
                    },
                    [evidence],
                    self.role,
                )
                for recipe in c.checks.by_primitive("xor_encoded_credential"):
                    c.candidate(
                        self.role,
                        recipe,
                        target,
                        [evidence],
                        artifact_evidence=evidence,
                        secret_ref=secret_ref,
                        blob_offset=recovered["blob_offset"],
                        key_offset=recovered["key_offset"],
                        key=recovered["key"],
                        scheme=recovered["scheme"],
                        length=recovered["length"],
                    )
                # Try the recovered passkey where it is actually used: any reviewed
                # text-TCP service already discovered gets a (re)scheduled protocol run.
                if "protocol_scripting" in c.manifest.allowed_actions:
                    for service in c.store.records(c.run_id, "service"):
                        info = service["data"]
                        if info.get("protocol") == "tcp":
                            c.store.enqueue(
                                c.run_id,
                                role="Recon",
                                kind="protocol",
                                target=service["id"],
                                payload={"address": info["address"], "port": info["port"]},
                            )
        c.store.put(
            c.run_id,
            "observation",
            "strings:" + digest,
            {
                "type": "printable_strings",
                "count": len(strings),
                "offsets": [s["offset"] for s in strings[:256]],
                "claim": "Offsets of printable sequences; raw artifact evidence is access controlled.",
            },
            [evidence],
            self.role,
        )


class CorrelatorAgent(Agent):
    role = "Correlator"
    tools = ("query_facts", "match_and_prerequisites", "publish_permitted_action")

    async def do_correlate(self, task):
        c = self.ctx
        if not c.manifest.allow_credential_use:
            return
        for finding in c.store.records(c.run_id, "finding"):
            data = finding["data"]
            if data["primitive"] != "binary_credential" or data["status"] != "confirmed":
                continue
            details = data["details"]
            target = urlsplit(details["service_url"])
            for service in c.store.records(c.run_id, "service"):
                info = service["data"]
                service_url = urlsplit(info["base_url"])
                if info["protocol"] not in {"http", "https"} or (target.scheme, target.netloc) != (
                    service_url.scheme,
                    service_url.netloc,
                ):
                    continue
                action_id = "authenticate:" + service["id"] + ":" + details["secret_ref"]
                evidence = finding["evidence"] + service["evidence"]
                c.store.put(
                    c.run_id,
                    "graph_node",
                    action_id,
                    {
                        "type": "action",
                        "label": "Use service-bound artifact credential",
                        "preconditions_and": [finding["id"], service["id"]],
                        "effects": ["accepted_http_session"],
                        "status": "permitted",
                        "network_hops": 0,
                    },
                    evidence,
                    self.role,
                )
                for prerequisite in (finding["id"], service["id"]):
                    c.store.put(
                        c.run_id,
                        "graph_edge",
                        prerequisite + ":" + action_id,
                        {
                            "from": prerequisite,
                            "to": action_id,
                            "state": "observed_relationship",
                            "relation": "requires",
                        },
                        evidence,
                        self.role,
                    )
                c.handoff(
                    self.role,
                    "Web",
                    details["service_url"],
                    evidence,
                    "test permitted credential at exact related service",
                    action_id=action_id,
                )
                c.store.enqueue(
                    c.run_id,
                    role="Web",
                    kind="auth_probe",
                    target=details["service_url"],
                    payload={
                        "secret_ref": details["secret_ref"],
                        "artifact_evidence": details["artifact_evidence"],
                        "binary_finding": finding["id"],
                        "service_id": service["id"],
                        "action_id": action_id,
                    },
                    session=details["secret_ref"],
                )


class FalsifierAgent(Agent):
    role = "Falsifier"
    tools = ("independent_http_control", "artifact_offset_check", "redis_control", "decide_finding")

    async def do_verify(self, task):
        c = self.ctx
        finding = c.store.get(c.run_id, "finding", task["target"])
        if not finding or finding["data"]["status"] != "candidate":
            return
        data, evidence = finding["data"], list(finding["evidence"])
        primitive, details = data["primitive"], data["details"]
        status, reason, controls = "inconclusive", "proof condition not established", {}
        try:
            if primitive in {
                "directory_listing",
                "credential_literal",
                "verbose_error",
                "json_document",
                "git_head",
                "source_map",
                "api_document",
                "structured_secret",
            }:
                credential = (
                    c.store.reveal(c.run_id, details["session_ref"], self.role)
                    if details.get("session_ref")
                    else None
                )
                # Replay the forwarding header if the finding was reached through a bypass.
                fwd_header = details.get("forward_header")
                fwd = {fwd_header: details["forward_value"]} if fwd_header else None
                positive = await c.broker.http(data["target"], credential=credential, extra_headers=fwd)
                suffix = "__mitigata_nonexistent_" + uuid.uuid4().hex
                control_url = None
                for candidate in (
                    urljoin(data["target"], suffix),
                    data["target"].split("?", 1)[0].rstrip("/") + "/" + suffix,
                ):
                    try:
                        control_url = c.broker.guard.destination(candidate).url
                        break
                    except ScopeDenied:
                        continue
                if control_url is None:
                    raise ScopeDenied("No in-scope negative-control path is available")
                control = await c.broker.http(control_url, credential=credential, extra_headers=fwd)
                evidence.extend([positive.evidence_id, control.evidence_id])
                controls = {
                    "control": "nonexistent-path",
                    "control_status": control.status,
                    "positive_status": positive.status,
                    "same_response": equivalent_response(positive, control),
                }
                if fwd_header:
                    from .web_auth_bypass import PUBLIC_CONTROL_IP

                    pub_val = (
                        "for=" + PUBLIC_CONTROL_IP if fwd_header.lower() == "forwarded" else PUBLIC_CONTROL_IP
                    )
                    public = await c.broker.http(
                        data["target"], credential=credential, extra_headers={fwd_header: pub_val}
                    )
                    evidence.append(public.evidence_id)
                    controls["public_address_control_differs"] = not equivalent_response(positive, public)
                matched = (
                    primitive == "directory_listing"
                    and is_directory_listing(positive.text)
                    or primitive == "credential_literal"
                    and any(
                        m.group(2).lower() not in {"example", "sample", "changeme", "placeholder", "password"}
                        for m in CREDENTIAL_RE.finditer(positive.text)
                    )
                    or primitive == "verbose_error"
                    and is_verbose_error(positive.text)
                )
                if primitive == "json_document":
                    document = json.loads(positive.text)
                    matched = (
                        isinstance(document, dict)
                        and bool(data["required_keys"])
                        and all(key in document for key in data["required_keys"])
                    )
                if primitive in {"git_head", "source_map", "api_document", "structured_secret"}:
                    from .codes import extended_match

                    matched = extended_match(primitive, positive.text)
                if positive.truncated or control.truncated:
                    raise ValueError("Partial response cannot establish this finding")
                bypass_ok = controls.get("public_address_control_differs", True)
                if equivalent_response(positive, control):
                    status, reason = (
                        "rejected",
                        "Candidate is indistinguishable from a nonexistent-path catch-all response",
                    )
                elif 200 <= positive.status < 300 and matched and bypass_ok:
                    status, reason = (
                        "confirmed",
                        "Repeat response supports the exact claim and differs from the nonexistent-path"
                        + (" and public-address" if fwd_header else "")
                        + " control",
                    )
                else:
                    status, reason = "rejected", "Positive predicate did not survive independent retrieval"
            elif primitive == "browser_xss":
                from .browser import prove_reflected_xss

                controls, refs = await prove_reflected_xss(c, data["target"], details["fields"])
                evidence.extend(refs)
                status = "confirmed" if all(controls.values()) else "rejected"
                reason = (
                    "Fixed client-side marker executed only for the active control"
                    if status == "confirmed"
                    else "Script execution was not established"
                )
            elif primitive == "form_auth":
                from .authentication import verify_form

                result = await verify_form(c, data)
                status, reason, controls = result["status"], result["reason"], result["controls"]
                evidence.extend(result["evidence"])
                if status == "confirmed":
                    details["session_ref"] = result["session_ref"]
                    data["target"] = result["protected_url"]
            elif primitive == "binary_credential":
                raw = c.evidence.read(c.run_id, details["artifact_evidence"])
                credential = c.store.reveal(c.run_id, details["secret_ref"], self.role)
                offset = details["string_offset"]
                literal = credential["password"].encode()
                positive = raw[offset : offset + len(literal)] == literal
                control = raw[max(0, offset - 1) : max(0, offset - 1) + len(literal)] != literal
                controls = {
                    "exact_offset_match": positive,
                    "shifted_offset_negative": control,
                    "service_context_present": credential["service_url"].encode() in raw,
                }
                status = (
                    "confirmed"
                    if positive and control and controls["service_context_present"]
                    else "rejected"
                )
                reason = "Offset and service-bound credential context independently re-read from the hashed artifact"
            elif primitive == "elf_pie":
                raw = c.evidence.read(c.run_id, details["artifact_evidence"])
                # A different implementation than the ELF parser: inspect ELF identification and e_type.
                byte_order = "little" if len(raw) > 5 and raw[5] == 1 else "big"
                valid = len(raw) >= 64 and raw[:4] == b"\x7fELF" and raw[4] in {1, 2} and raw[5] in {1, 2}
                executable = valid and int.from_bytes(raw[16:18], byte_order) == 2
                controls = {"elf_identification_valid": valid, "type_is_exec_not_dyn": bool(executable)}
                status, reason = (
                    ("confirmed", "Independent ELF header interpretation agrees with parser")
                    if executable
                    else ("rejected", "ELF hardening claim not supported")
                )
            elif primitive == "basic_auth":
                prerequisite = c.store.by_id(c.run_id, details["binary_finding"])
                if not prerequisite or prerequisite["data"]["status"] != "confirmed":
                    raise ValueError("Binary prerequisite is not confirmed")
                credential = c.store.reveal(c.run_id, details["secret_ref"], self.role)
                anonymous = await c.broker.http(data["target"])
                if (
                    anonymous.status != 401
                    or "basic" not in anonymous.headers.get("www-authenticate", "").lower()
                ):
                    evidence.append(anonymous.evidence_id)
                    raise ValueError(
                        "Previously observed authentication challenge no longer exists; no credential offered"
                    )
                wrong = await c.broker.http(
                    data["target"],
                    credential={**credential, "password": "mitigata-negative-" + uuid.uuid4().hex},
                )
                accepted = await c.broker.http(data["target"], credential=credential)
                evidence.extend([anonymous.evidence_id, wrong.evidence_id, accepted.evidence_id])
                challenged = (
                    anonymous.status == 401
                    and "basic" in anonymous.headers.get("www-authenticate", "").lower()
                )
                controls = {
                    "anonymous_challenged": challenged,
                    "wrong_credential_rejected": wrong.status == 401,
                    "correct_credential_accepted": 200 <= accepted.status < 300
                    and "www-authenticate" not in accepted.headers,
                }
                if all(controls.values()):
                    status, reason = (
                        "confirmed",
                        "Unauthenticated and incorrect credentials are challenged; the artifact credential returns the resource",
                    )
                else:
                    status, reason = (
                        "rejected",
                        "Authentication boundary or positive acceptance could not be demonstrated",
                    )
            elif primitive == "redis_info":
                body, ref = await c.broker.tcp(details["address"], details["port"], b"*1\r\n$4\r\nINFO\r\n")
                ping, control_ref = await c.broker.tcp(
                    details["address"], details["port"], b"*1\r\n$4\r\nPING\r\n"
                )
                evidence.extend([ref, control_ref])
                controls = {
                    "info_contains_server_version": b"# Server" in body and b"redis_version:" in body,
                    "protocol_control_pong": ping.startswith(b"+PONG"),
                    "authentication_used": False,
                }
                status = (
                    "confirmed"
                    if controls["info_contains_server_version"] and controls["protocol_control_pong"]
                    else "rejected"
                )
                reason = "Independent unauthenticated INFO and PING responses establish the narrow disclosure claim"
            elif primitive in {"path_traversal", "sql_injection", "ssti"}:
                from .injection import sql_error_hit, ssti_hit, traversal_hit

                hit = {"path_traversal": traversal_hit, "sql_injection": sql_error_hit, "ssti": ssti_hit}[
                    primitive
                ]
                session_ref = details.get("session_ref")
                cred = c.store.reveal(c.run_id, session_ref, self.role) if session_ref else None
                parts = urlsplit(data["target"])
                base_query = dict(parse_qsl(parts.query, keep_blank_values=True))

                def inject(value, _parts=parts, _base=base_query):
                    query = dict(_base)
                    query.update({name: value for name in details["fields"]})
                    return urlunsplit((_parts.scheme, _parts.netloc, _parts.path, urlencode(query), ""))

                benign = "mitigata" + uuid.uuid4().hex[:10]
                control = await c.broker.http(inject(benign), credential=cred)
                positive = await c.broker.http(inject(details["payload"]), credential=cred)
                evidence.extend([control.evidence_id, positive.evidence_id])
                if positive.truncated:
                    raise ValueError("Partial response cannot establish this finding")
                controls = {
                    "payload_signature_present": hit(positive.text),
                    "benign_control_clean": not hit(control.text),
                    "responses_differ": not equivalent_response(positive, control),
                }
                status, reason = (
                    ("confirmed", "Payload elicits the class signature absent from the benign control")
                    if all(controls.values())
                    else ("rejected", "Differential signature control was not satisfied")
                )
            elif primitive == "open_redirect":
                session_ref = details.get("session_ref")
                cred = c.store.reveal(c.run_id, session_ref, self.role) if session_ref else None
                parts = urlsplit(data["target"])
                base_query = dict(parse_qsl(parts.query, keep_blank_values=True))

                def redirect_probe(value, _parts=parts, _base=base_query):
                    query = dict(_base)
                    query.update({name: value for name in details["fields"]})
                    return urlunsplit((_parts.scheme, _parts.netloc, _parts.path, urlencode(query), ""))

                marker = urlunsplit((parts.scheme, parts.netloc, "/mitigata-redir-" + uuid.uuid4().hex[:10], "", ""))
                benign = "mitigata" + uuid.uuid4().hex[:10]
                positive = await c.broker.http(redirect_probe(marker), credential=cred, follow_redirects=False)
                control = await c.broker.http(redirect_probe(benign), credential=cred, follow_redirects=False)
                evidence.extend([positive.evidence_id, control.evidence_id])
                controls = {
                    "redirect_status": positive.status in {301, 302, 303, 307, 308},
                    "location_is_supplied_marker": marker in positive.headers.get("location", ""),
                    "control_not_redirected_to_input": marker not in control.headers.get("location", ""),
                }
                status, reason = (
                    ("confirmed", "A supplied destination is reflected into the redirect Location")
                    if all(controls.values())
                    else ("rejected", "Controlled redirect to a supplied destination was not demonstrated")
                )
            elif primitive == "default_credentials":
                cred = c.store.reveal(c.run_id, details["secret_ref"], self.role)
                anonymous = await c.broker.http(data["target"])
                wrong = await c.broker.http(
                    data["target"],
                    credential={"username": details["username"], "password": "mitigata-wrong-" + uuid.uuid4().hex},
                )
                accepted = await c.broker.http(data["target"], credential=cred)
                evidence.extend([anonymous.evidence_id, wrong.evidence_id, accepted.evidence_id])
                controls = {
                    "anonymous_challenged": anonymous.status == 401
                    and "basic" in anonymous.headers.get("www-authenticate", "").lower(),
                    "wrong_credential_rejected": wrong.status == 401,
                    "default_credential_accepted": 200 <= accepted.status < 300
                    and "www-authenticate" not in accepted.headers,
                }
                status, reason = (
                    ("confirmed", "A well-known default credential is accepted where anonymous and incorrect credentials are rejected")
                    if all(controls.values())
                    else ("rejected", "Default-credential acceptance boundary was not demonstrated")
                )
            elif primitive == "http_service_unauth":
                from .injection import datastore_signature

                positive = await c.broker.http(data["target"])
                parts = urlsplit(data["target"])
                control_url = urlunsplit(
                    (parts.scheme, parts.netloc, "/__mitigata_absent_" + uuid.uuid4().hex, "", "")
                )
                control = await c.broker.http(control_url)
                evidence.extend([positive.evidence_id, control.evidence_id])
                controls = {
                    "datastore_signature_present": bool(datastore_signature(data["target"], positive.text)),
                    "control_lacks_signature": datastore_signature(control_url, control.text) is None,
                    "no_authentication_used": True,
                }
                status, reason = (
                    ("confirmed", "An unauthenticated datastore management document is returned and absent from a control path")
                    if controls["datastore_signature_present"] and controls["control_lacks_signature"]
                    else ("rejected", "Datastore disclosure signature not independently reproduced")
                )
            elif primitive == "header_access_bypass":
                from .web_auth_bypass import PUBLIC_CONTROL_IP, is_bypass

                header, value = details["header"], details["header_value"]
                control_value = (
                    "for=" + PUBLIC_CONTROL_IP if header.lower() == "forwarded" else PUBLIC_CONTROL_IP
                )
                baseline = await c.broker.http(data["target"])
                spoofed = await c.broker.http(data["target"], extra_headers={header: value})
                public = await c.broker.http(data["target"], extra_headers={header: control_value})
                evidence.extend([baseline.evidence_id, spoofed.evidence_id, public.evidence_id])
                controls = {
                    "internal_spoof_differs_from_baseline": is_bypass(baseline, spoofed),
                    "public_address_control_matches_baseline": not is_bypass(baseline, public),
                }
                status, reason = (
                    (
                        "confirmed",
                        "A trusted-internal forwarding value returns content that neither the unspoofed request nor a public-address control returns",
                    )
                    if all(controls.values())
                    else ("rejected", "Forwarding-header content differential was not reproduced")
                )
            elif primitive == "xor_encoded_credential":
                from .binary import rederive_xor_credential

                raw = c.evidence.read(c.run_id, details["artifact_evidence"])
                credential = c.store.reveal(c.run_id, details["secret_ref"], self.role)
                detail = {
                    "scheme": details["scheme"],
                    "key": details["key"],
                    "key_offset": details["key_offset"],
                    "blob_offset": details["blob_offset"],
                    "value": credential["value"],
                }
                reproduces, shifted_differs = rederive_xor_credential(raw, detail)
                controls = {
                    "deterministic_rederivation_at_offset": reproduces,
                    "shifted_offset_does_not_reproduce": shifted_differs,
                    "key_literal_present_in_artifact": details["key"].encode() in raw,
                }
                status, reason = (
                    (
                        "confirmed",
                        "The secret re-derives deterministically from the recorded scheme and offset, and a shifted offset does not reproduce it",
                    )
                    if all(controls.values())
                    else ("rejected", "Obfuscated-secret recovery did not reproduce under independent re-derivation")
                )
            elif primitive == "sensitive_disclosure":
                from .extractors import sensitive_document_signature

                cred = (
                    c.store.reveal(c.run_id, details["session_ref"], self.role)
                    if details.get("session_ref")
                    else None
                )
                # If the document was only visible through a forwarding bypass, the Falsifier
                # must replay that header to retrieve it, and confirm a public-address control
                # does NOT get it.
                forward_header = details.get("forward_header")
                positive_headers = (
                    {forward_header: details["forward_value"]} if forward_header else None
                )
                positive = await c.broker.http(
                    data["target"], credential=cred, extra_headers=positive_headers
                )
                suffix = "__mitigata_absent_" + uuid.uuid4().hex
                control_url = None
                for candidate in (
                    urljoin(data["target"], suffix),
                    data["target"].split("?", 1)[0].rstrip("/") + "/" + suffix,
                ):
                    try:
                        control_url = c.broker.guard.destination(candidate).url
                        break
                    except ScopeDenied:
                        continue
                if control_url is None:
                    raise ScopeDenied("No in-scope negative-control path is available")
                control = await c.broker.http(control_url, credential=cred, extra_headers=positive_headers)
                evidence.extend([positive.evidence_id, control.evidence_id])
                if positive.truncated:
                    raise ValueError("Partial response cannot establish this finding")
                controls = {
                    "sensitive_categories_present": bool(sensitive_document_signature(positive.text)),
                    "control_path_lacks_content": not sensitive_document_signature(control.text),
                    "served_without_authentication": 200 <= positive.status < 300,
                }
                if forward_header:
                    from .web_auth_bypass import PUBLIC_CONTROL_IP

                    public_value = (
                        "for=" + PUBLIC_CONTROL_IP
                        if forward_header.lower() == "forwarded"
                        else PUBLIC_CONTROL_IP
                    )
                    public = await c.broker.http(
                        data["target"], credential=cred, extra_headers={forward_header: public_value}
                    )
                    evidence.append(public.evidence_id)
                    controls["public_address_control_lacks_content"] = not sensitive_document_signature(
                        public.text
                    )
                status, reason = (
                    (
                        "confirmed",
                        "An operational/infrastructure document is served (via the recorded access path) where negative controls are not",
                    )
                    if all(controls.values())
                    else ("rejected", "Sensitive-document disclosure was not independently reproduced")
                )
            elif primitive == "protocol_capture":
                from .codes import candidates as code_candidates
                from .protocols import unauth_banner_withholds_code

                received = c.evidence.read(c.run_id, details["received_evidence"])
                transcript = json.loads(
                    c.evidence.read(c.run_id, details["transcript_evidence"]).decode(errors="replace")
                )
                sent = [t["text"] for t in transcript if t.get("direction") == "sent"]
                has_code = bool(
                    code_candidates(received, c.manifest.investigation.flag_patterns)
                ) or bool(re.search(rb"[A-Za-z0-9_]{3,}\{[^}\n]{3,}\}", received))
                withheld = await unauth_banner_withholds_code(
                    c, details["address"], details["port"], c.manifest.investigation.flag_patterns
                )
                controls = {
                    "resource_present_after_handshake": has_code,
                    "authenticated_exchange_occurred": any(
                        s.split(" ", 1)[0].upper() in {"AUTH", "LOGIN", "KEY", "PASS", "UNLOCK"} for s in sent
                    ),
                    "unauthenticated_control_withholds_resource": withheld,
                }
                status, reason = (
                    (
                        "confirmed",
                        "The protected resource appears only after the documented authenticated exchange and is withheld from an unauthenticated control connection",
                    )
                    if all(controls.values())
                    else ("rejected", "Protocol capture could not be distinguished from an unauthenticated banner")
                )
        except (OSError, TimeoutError, ValueError, http_client_error()) as exc:
            status, reason = "inconclusive", f"Independent proof unavailable: {type(exc).__name__}"
        verification = c.store.put(
            c.run_id,
            "verification",
            finding["id"],
            {
                "finding_id": finding["id"],
                "status": status,
                "reason": reason,
                "controls": controls,
                "disproof_attempted": True,
                "positive_proof_required": True,
            },
            evidence,
            self.role,
        )
        c.store.put(
            c.run_id,
            "finding",
            finding["identity"],
            {**data, "status": status, "verification_id": verification},
            evidence,
            self.role,
        )
        c.ledger(
            self.role,
            data["id"],
            data["target"],
            "verified" if status == "confirmed" else ("negative" if status == "rejected" else "inconclusive"),
            evidence,
            finding_id=finding["id"],
        )
        if status == "confirmed" and primitive == "binary_credential":
            c.store.enqueue(
                c.run_id, role="Correlator", kind="correlate", target=finding["id"], revision=verification
            )
        if status == "confirmed" and primitive == "default_credentials":
            c.store.event(
                c.run_id, self.role, "verified_credential_use", {"finding_id": finding["id"]},
                phase="Exploitation",
            )
            # Crawl the now-unlocked surface so content and planted codes behind the gate are reached.
            c.store.enqueue(
                c.run_id, role="Web", kind="page", target=data["target"],
                payload={"depth": 0, "session_ref": details["secret_ref"]}, session=details["secret_ref"],
            )
        if status == "confirmed" and primitive in {"basic_auth", "form_auth"}:
            action_id = details["action_id"]
            c.store.event(
                c.run_id,
                self.role,
                "verified_credential_use",
                {"finding_id": finding["id"]},
                phase="Exploitation",
            )
            c.store.put(
                c.run_id,
                "graph_edge",
                action_id + ":accepted",
                {
                    "from": details["service_id"],
                    "to": action_id,
                    "state": "verified_authorized_transition",
                    "relation": "accepted_artifact_credential",
                    "finding_id": finding["id"],
                    "network_hops": 0,
                },
                evidence,
                self.role,
            )
            c.handoff(
                self.role,
                "Web",
                data["target"],
                evidence,
                "crawl confirmed authenticated session",
                action_id=action_id,
            )
            c.store.enqueue(
                c.run_id,
                role="Web",
                kind="page",
                target=data["target"],
                payload={
                    "session_ref": details.get("session_ref", details["secret_ref"]),
                    "depth": 0,
                    "action_id": action_id,
                },
                session=details.get("session_ref", details["secret_ref"]),
            )


class CodeAgent(Agent):
    role = "Code"
    tools = ("extract_flag_candidates", "submit_to_authoritative_local_checker")

    async def do_capture(self, task):
        c, payload = self.ctx, task["payload"]
        raw = c.evidence.read(c.run_id, payload["evidence_id"])
        from .codes import candidates

        values = (
            candidates(
                raw, c.manifest.investigation.flag_patterns, payload.get("source_hint", task["target"])
            )
            if c.manifest.investigation.enabled
            else [
                {"value": m.group(), "basis": "legacy_format"}
                for m in list(FLAG_PATTERN.finditer(raw.decode(errors="replace")))[:10]
            ]
        )
        if payload.get("candidate_value_ref"):
            proposed = c.store.reveal(c.run_id, payload["candidate_value_ref"], "Code")["exact_value"]
            if proposed.encode() not in raw:
                raise ScopeDenied("Model-nominated code is absent from source evidence")
            values.append({"value": proposed, "basis": "model_nominated_literal_candidate"})
        for candidate in values:
            value = candidate["value"]
            digest = hashlib.sha256(value.encode()).hexdigest()
            if c.store.get(c.run_id, "flag", digest):
                continue
            secret_ref = c.store.secret(c.run_id, {"exact_value": value}, roles=("Code", "Operator"))
            receipt = await c.broker.validate_flag(value)
            evidence = [payload["evidence_id"]]
            receipt_evidence = c.evidence.capture(
                c.run_id,
                encoded(receipt).encode(),
                kind="validation_receipt",
                metadata={"candidate_sha256": digest},
            )
            evidence.append(receipt_evidence)
            flag_id = c.store.put(
                c.run_id,
                "flag",
                digest,
                {
                    "sha256": digest,
                    "status": receipt["status"],
                    "secret_ref": secret_ref,
                    "source_url": task["target"],
                    "receipt": receipt,
                    "capture_basis": candidate["basis"],
                    "session_ref": payload.get("session_ref"),
                },
                evidence,
                self.role,
            )
            # Capturing any planted code is a post-exploitation outcome; record the phase so
            # the PTES mapping reflects it even when the capture came from the protocol path
            # (which carries no graph action_id).
            c.store.event(
                c.run_id, self.role, "code_captured",
                {"flag_id": flag_id, "status": receipt["status"]}, phase="Post-Exploitation",
            )
            if payload.get("action_id") and receipt["status"] in {"validated", "validation_unavailable"}:
                c.store.event(
                    c.run_id,
                    self.role,
                    "protected_resource_retrieved",
                    {"flag_id": flag_id},
                    phase="Post-Exploitation",
                )
                c.store.put(
                    c.run_id,
                    "graph_edge",
                    payload["action_id"] + ":" + flag_id,
                    {
                        "from": payload["action_id"],
                        "to": flag_id,
                        "state": "verified_authorized_transition",
                        "relation": "retrieved_validated_code"
                        if receipt["status"] == "validated"
                        else "retrieved_unvalidated_code_candidate",
                        "network_hops": 0,
                    },
                    evidence,
                    self.role,
                )


class ReporterAgent(Agent):
    role = "Reporter"
    tools = ("read_persisted_state", "export_unified_report")

    async def do_snapshot(self, task):
        from .reporting import build_report

        c = self.ctx
        report = build_report(c.store, c.run_id)
        c.store.put(
            c.run_id,
            "report_snapshot",
            task["id"],
            {
                "findings": len(report["findings"]),
                "services": len(report["services"]),
                "status": report["run"]["status"],
            },
            role=self.role,
        )


AGENTS = (ReconAgent, WebAgent, BinaryAgent, CorrelatorAgent, FalsifierAgent, CodeAgent, ReporterAgent)

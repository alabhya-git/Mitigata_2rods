from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import socket
import ssl
import threading
import time
import uuid
import zlib
from dataclasses import dataclass, field
from urllib.parse import urljoin

from .config import ScopeManifest
from .evidence import EvidenceStore
from .runtime_guard import connection_permit
from .scope import Destination, ScopeDenied, ScopeGuard
from .security import worker_identity
from .store import Store


class BudgetExceeded(RuntimeError):
    pass


# Forwarding-identity request headers a bypass probe may set. These never change the
# scoped destination (same pinned address/port); they only exercise how the target
# treats client-supplied identity. Any other header name is refused.
SPOOFABLE_HEADERS = frozenset(
    {
        "x-forwarded-for",
        "x-forwarded",
        "x-forwarded-host",
        "x-real-ip",
        "x-originating-ip",
        "x-client-ip",
        "x-remote-ip",
        "x-remote-addr",
        "true-client-ip",
        "client-ip",
        "forwarded",
    }
)


@dataclass
class Response:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes
    evidence_id: str
    history: list[str] = field(default_factory=list)
    truncated: bool = False
    diagnostics: dict = field(default_factory=dict)

    @property
    def text(self):
        return self.body.decode("utf-8", errors="replace")


class Broker:
    """Only built-in network execution path. Numeric pinning, no proxies or ambient DNS."""

    def __init__(self, manifest: ScopeManifest, store: Store, evidence: EvidenceStore, run_id: str):
        self.manifest, self.store, self.evidence, self.run_id = manifest, store, evidence, run_id
        self.guard = ScopeGuard(manifest)
        self.deadline = store.run(run_id)["deadline"]
        self.counter = sum(a["data"]["status"] == "allowed" for a in store.records(run_id, "audit"))
        self.rate_lock = asyncio.Lock()
        self.next_at = 0.0
        self.cancelled = False
        self.sockets: dict[str, socket.socket] = {}
        self.socket_lock = threading.Lock()
        self.auth_attempts: dict[str, int] = {}
        self.tls_pins = {}
        for row in store.records(run_id, "authority"):
            info = row["data"]
            if info.get("address") in self.guard.address_set:
                self.guard.bindings[info["hostname"]] = (info["address"],)
        from urllib.parse import urlsplit

        for audit in store.records(run_id, "audit"):
            data = audit["data"]
            if data.get("status") == "allowed" and data.get("authenticated") and data.get("url"):
                authority = urlsplit(data["url"]).netloc
                self.auth_attempts[authority] = self.auth_attempts.get(authority, 0) + 1

    def audit(self, status, **data):
        actor = worker_identity.get()
        self.store.put(
            self.run_id,
            "audit",
            uuid.uuid4().hex,
            {"status": status, "plane": "Sentinel", **data},
            role=actor.role if actor else "Sentinel",
        )

    def require_role(self, roles):
        actor = worker_identity.get()
        if actor is not None and actor.role not in roles:
            self.audit("blocked", action="role_policy", reason="worker_has_no_network_capability")
            raise ScopeDenied("This worker does not own the requested network capability")

    def bind_authority(self, hostname, evidence_id):
        import re

        if not self.manifest.investigation.follow_same_ip_hostnames or len(self.guard.addresses) != 1:
            return False
        hostname = hostname.lower().rstrip(".")
        if hostname in self.guard.bindings or hostname in self.guard.address_set:
            return True
        if (
            len(hostname) > 253
            or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", hostname)
            or ".." in hostname
        ):
            return False
        if self.store.count_records(self.run_id, "authority") >= 16:
            return False
        row = self.store.by_id(self.run_id, evidence_id)
        if not row or row["kind"] != "evidence":
            raise ScopeDenied("Authority binding requires current-run evidence")
        # Numeric references never gain an alias to another address.
        try:
            ipaddress.ip_address(hostname)
            return False
        except ValueError:
            pass
        address = self.guard.addresses[0]
        self.guard.bindings[hostname] = (address,)
        actor = worker_identity.get()
        self.store.put(
            self.run_id,
            "authority",
            hostname,
            {
                "hostname": hostname,
                "address": address,
                "basis": "target_reference_pinned_to_only_authorized_ip",
                "status": "candidate_authority_not_ownership_proof",
            },
            [evidence_id],
            actor.role if actor else "Sentinel",
        )
        return True

    async def reserve(self, **data):
        async with self.rate_lock:
            if self.cancelled or self.store.run(self.run_id)["cancel_requested"]:
                raise asyncio.CancelledError
            if time.time() >= self.deadline or self.counter >= self.manifest.budgets.requests:
                raise BudgetExceeded("Network request/time budget exhausted")
            wait = max(0.0, self.next_at - time.monotonic())
            if wait:
                await asyncio.sleep(wait)
            if (
                time.time() >= self.deadline
                or self.cancelled
                or self.store.run(self.run_id)["cancel_requested"]
            ):
                raise BudgetExceeded("Assessment deadline reached")
            self.counter += 1
            self.next_at = time.monotonic() + 1 / self.manifest.budgets.rate_per_second
            self.audit("allowed", attempt=self.counter, **data)

    def _connect(self, request_id, address, port, timeout):
        if self.cancelled:
            raise OSError("Run cancelled")
        ip = ipaddress.ip_address(address)
        is_validator = self._validator_destination(str(ip), port)
        if not self.guard.address_allowed(str(ip), port) and not is_validator:
            raise ScopeDenied("Numeric connection destination is outside scope")
        sock = socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        with self.socket_lock:
            if self.cancelled:
                sock.close()
                raise OSError("Run cancelled")
            self.sockets[request_id] = sock
        try:
            token = connection_permit.set((id(self), str(ip), port))
            try:
                sock.connect((str(ip), port))
            finally:
                connection_permit.reset(token)
            return sock
        except BaseException:
            self._close(request_id)
            raise

    def _validator_destination(self, address, port):
        from urllib.parse import urlsplit

        actor = worker_identity.get()
        return bool(
            actor
            and actor.role == "Code"
            and self.manifest.validation_url
            and address == self.manifest.validation_address
            and port == urlsplit(self.manifest.validation_url).port
        )

    def _close(self, request_id):
        with self.socket_lock:
            sock = self.sockets.pop(request_id, None)
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def cancel(self):
        self.cancelled = True
        with self.socket_lock:
            ids = list(self.sockets)
        for request_id in ids:
            self._close(request_id)

    def _sync_http(self, request_id: str, dest: Destination, headers: dict, method="GET", body=None):
        timeout = min(self.manifest.budgets.timeout, max(0.1, self.deadline - time.time()))
        tls_info = {}
        if dest.scheme == "https":
            broker = self
            context = ssl.create_default_context()
            unverified = self.manifest.investigation.allow_unverified_tls
            if unverified:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

            class PinnedHTTPSConnection(http.client.HTTPSConnection):
                def connect(self):
                    raw = broker._connect(request_id, dest.address, dest.port, timeout)
                    # Register the actual TLS socket before handshake so cancellation can close it.
                    with broker.socket_lock:
                        if broker.cancelled:
                            raw.close()
                            raise OSError("Run cancelled")
                        secure = context.wrap_socket(
                            raw, server_hostname=dest.hostname, do_handshake_on_connect=False
                        )
                        self.sock = secure
                        broker.sockets[request_id] = secure
                    secure.do_handshake()
                    peer = secure.getpeercert()
                    certificate = secure.getpeercert(binary_form=True)
                    if certificate:
                        import hashlib

                        tls_info["certificate_sha256"] = hashlib.sha256(certificate).hexdigest()
                        pin_key = (dest.address, dest.port, dest.hostname)
                        authenticated = (
                            any(k in headers for k in ("Authorization", "Cookie")) or method == "POST"
                        )
                        if unverified and authenticated:
                            if broker.tls_pins.get(pin_key) != tls_info["certificate_sha256"]:
                                raise ScopeDenied(
                                    "Lab TLS credential offer requires the certificate observed on a prior anonymous request"
                                )
                        else:
                            broker.tls_pins[pin_key] = tls_info["certificate_sha256"]
                    if not peer and certificate and broker.manifest.investigation.enabled:
                        import tempfile
                        from pathlib import Path

                        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".pem") as stream:
                            stream.write(ssl.DER_cert_to_PEM_cert(certificate))
                            pem = Path(stream.name)
                        try:
                            peer = ssl._ssl._test_decode_cert(str(pem))
                        except (OSError, ValueError, AttributeError):
                            peer = {}
                        finally:
                            pem.unlink(missing_ok=True)
                    tls_info["dns_names"] = [
                        name for kind, name in peer.get("subjectAltName", []) if kind == "DNS"
                    ][:32]
                    if broker.cancelled:
                        raise OSError("Run cancelled")

            connection = PinnedHTTPSConnection(dest.hostname, dest.port, timeout=timeout, context=context)
        else:
            connection = http.client.HTTPConnection(dest.hostname, dest.port, timeout=timeout)
            connection._create_connection = lambda *a, **kw: self._connect(
                request_id, dest.address, dest.port, timeout
            )
        try:
            connection.request(
                method,
                dest.request_target,
                body=body,
                headers={
                    "User-Agent": "Mitigata/0.3",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    **headers,
                },
            )
            response = connection.getresponse()
            encoding = response.getheader("Content-Encoding", "identity").lower()
            if encoding not in {"identity", ""} and not self.manifest.investigation.decode_compression:
                raise ValueError("Compressed response not requested; refusing unbounded decompression")
            response_headers = {k.lower(): v for k, v in response.getheaders()}
            limit = self.manifest.budgets.max_body_bytes
            content, fault = bytearray(), None
            try:
                while len(content) <= limit:
                    chunk = response.read1(min(65536, limit + 1 - len(content)))
                    if not chunk:
                        break
                    content.extend(chunk)
            except (TimeoutError, http.client.IncompleteRead, OSError) as exc:
                if isinstance(exc, http.client.IncompleteRead):
                    content.extend(exc.partial[: max(0, limit + 1 - len(content))])
                fault = type(exc).__name__
                if not self.manifest.investigation.allow_partial_responses:
                    raise
            truncated = len(content) > limit or fault is not None
            if response.length not in {None, 0}:
                truncated, fault = True, fault or "incomplete_body"
            if len(content) > limit and not self.manifest.investigation.allow_partial_responses:
                raise ValueError("Response exceeds the byte budget")
            content = bytes(content[:limit])
            if encoding in {"gzip", "deflate"}:
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS)
                decoded = decoder.decompress(content, limit + 1)
                truncated |= len(decoded) > limit or not decoder.eof
                content = decoded[:limit]
            elif encoding not in {"identity", ""}:
                raise ValueError("Unsupported content encoding: " + encoding)
            diagnostics = {
                "body_error": fault,
                "content_encoding": encoding,
                "tls_peer_verified": not unverified if dest.scheme == "https" else None,
                **tls_info,
            }
            return (
                response.status,
                response_headers,
                content,
                truncated,
                diagnostics,
            )
        finally:
            connection.close()
            self._close(request_id)

    async def _execute_http(self, dest, headers, method="GET", body=None):
        request_id = uuid.uuid4().hex
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._sync_http, request_id, dest, headers, method, body),
                timeout=min(self.manifest.budgets.timeout * 2 + 0.5, max(0.1, self.deadline - time.time())),
            )
        finally:
            self._close(request_id)

    async def http(
        self, url, *, credential=None, redirects=3, follow_redirects=True, extra_headers=None
    ) -> Response:
        self.require_role({"Recon", "Web", "Falsifier"})
        if not self.manifest.action_allowed("http_get"):
            raise ScopeDenied("HTTP reads are not enabled by this manifest")
        forwarding = {}
        if extra_headers:
            if not self.manifest.action_allowed("header_spoof_probe"):
                raise ScopeDenied("Forwarding-header probes are not enabled by this manifest")
            for name, value in extra_headers.items():
                if name.lower() not in SPOOFABLE_HEADERS:
                    raise ScopeDenied("Only forwarding-identity headers may be set by a probe")
                if len(str(value)) > 256 or any(c in str(value) for c in "\r\n\x00"):
                    raise ScopeDenied("Invalid forwarding-header value")
                forwarding[name] = str(value)
        actor = worker_identity.get()
        if self.manifest.mode == "DISCOVERY_ONLY" and actor and actor.role == "Falsifier":
            raise ScopeDenied("Network finding verification is disabled in discovery-only mode")
        history = []
        initial_authority = None
        for hop in range(redirects + 1):
            try:
                dest = self.guard.destination(url)
                self._check_action_path(dest)
            except ScopeDenied:
                self.audit("blocked", reason="scope_policy", url=url[:4096])
                raise
            authority = (dest.scheme, dest.hostname, dest.port)
            if initial_authority is None:
                initial_authority = authority
            headers = dict(forwarding)
            if credential:
                if authority != initial_authority:
                    raise ScopeDenied("Credentials cannot follow a cross-authority redirect")
                if not self.manifest.allow_credential_use or not self.manifest.action_allowed(
                    "credential_validation"
                ):
                    raise ScopeDenied("Credential use is not permitted")
                if credential.get("cookie"):
                    headers["Cookie"] = credential["cookie"]
                else:
                    headers.update(self._basic_headers(dest, credential))
            await self.reserve(
                action="http",
                url=dest.url,
                address=dest.address,
                port=dest.port,
                method="GET",
                authenticated=bool(credential),
            )
            started = time.monotonic()
            try:
                value = await self._execute_http(dest, headers)
            except (OSError, TimeoutError, ValueError, http.client.HTTPException) as exc:
                ref = self.evidence.capture(
                    self.run_id,
                    str(exc).encode()[:2048],
                    kind="http_failure",
                    metadata={
                        "url": dest.url,
                        "address": dest.address,
                        "port": dest.port,
                        "error_type": type(exc).__name__,
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                    },
                )
                self.store.put(
                    self.run_id,
                    "observation",
                    "http_failure:" + dest.url,
                    {
                        "type": "http_failure",
                        "url": dest.url,
                        "error_type": type(exc).__name__,
                        "reason": str(exc)[:300],
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                    },
                    [ref],
                    actor.role if actor else "Sentinel",
                )
                raise
            status, response_headers, body = value[:3]
            truncated, diagnostics = value[3:] if len(value) == 5 else (False, {})
            evidence_id = self.evidence.capture(
                self.run_id,
                body,
                kind="http",
                metadata={
                    "url": dest.url,
                    "status": status,
                    "headers": response_headers,
                    "address": dest.address,
                    "method": "GET",
                    "authenticated": bool(credential),
                    "truncated": truncated,
                    "diagnostics": diagnostics,
                },
            )
            result = Response(
                dest.url, status, response_headers, body, evidence_id, history.copy(), truncated, diagnostics
            )
            if status not in {301, 302, 303, 307, 308} or "location" not in response_headers:
                return result
            if not follow_redirects:
                from urllib.parse import urlsplit

                next_url = urljoin(dest.url, response_headers["location"])
                if urlsplit(next_url).hostname:
                    self.bind_authority(urlsplit(next_url).hostname, evidence_id)
                return result
            if hop == redirects:
                raise ValueError("Redirect limit exceeded")
            history.append(evidence_id)
            url = urljoin(dest.url, response_headers["location"])
            from urllib.parse import urlsplit

            if urlsplit(url).hostname:
                self.bind_authority(urlsplit(url).hostname, evidence_id)
        raise AssertionError("Unreachable")

    def _basic_headers(self, dest, credential):
        import base64

        authority = dest.url.split("/", 3)[2]
        used = self.auth_attempts.get(authority, 0)
        if used >= self.manifest.budgets.max_auth_attempts:
            raise BudgetExceeded("Per-authority credential attempt budget exhausted")
        self.auth_attempts[authority] = used + 1
        return {
            "Authorization": "Basic "
            + base64.b64encode(f"{credential['username']}:{credential['password']}".encode()).decode()
        }

    def _check_action_path(self, dest):
        from urllib.parse import parse_qsl, urlsplit

        if not self.manifest.investigation.enabled:
            return
        path = urlsplit(dest.url)
        denied = set(self.manifest.investigation.denied_action_segments)
        segments = {p.lower().split(".")[0] for p in path.path.split("/")}
        actions = {v.lower() for k, v in parse_qsl(path.query) if k.lower() in {"action", "operation", "do"}}
        if denied & (segments | actions):
            raise ScopeDenied("Potentially mutating route/action is excluded from this assessment")

    async def submit_login(self, url, fields):
        from urllib.parse import urlencode

        self.require_role({"Falsifier"})
        if not self.manifest.allow_credential_use or not self.manifest.action_allowed(
            "session_authentication"
        ):
            raise ScopeDenied("Reviewed form authentication is not enabled")
        dest = self.guard.destination(url)
        self._check_action_path(dest)
        authority = dest.url.split("/", 3)[2]
        attempts = self.auth_attempts.get(authority, 0)
        if attempts >= self.manifest.budgets.max_auth_attempts:
            raise BudgetExceeded("Form authentication attempt budget exhausted")
        if len(fields) > 32 or any(len(str(k)) > 128 or len(str(v)) > 2048 for k, v in fields.items()):
            raise ScopeDenied("Login form exceeds supported limits")
        self.auth_attempts[authority] = attempts + 1
        await self.reserve(
            action="http",
            url=dest.url,
            address=dest.address,
            port=dest.port,
            method="POST",
            authenticated=True,
            operation="reviewed_login_form",
        )
        result = await self._execute_http(
            dest, {"Content-Type": "application/x-www-form-urlencoded"}, "POST", urlencode(fields).encode()
        )
        status, headers, body = result[:3]
        truncated, diagnostics = result[3:] if len(result) == 5 else (False, {})
        ref = self.evidence.capture(
            self.run_id,
            body,
            kind="http",
            metadata={
                "url": dest.url,
                "address": dest.address,
                "status": status,
                "headers": headers,
                "method": "POST",
                "authenticated": True,
                "truncated": truncated,
            },
        )
        return Response(dest.url, status, headers, body, ref, [], truncated, diagnostics)

    async def tcp(self, address, port, payload: bytes | None = None, read_banner=True):
        self.require_role({"Recon", "Falsifier"})
        if payload is not None and (
            payload
            not in {
                b"*1\r\n$4\r\nINFO\r\n",
                b"*1\r\n$4\r\nPING\r\n",
            }
            or not self.manifest.action_allowed("redis_info")
        ):
            self.audit(
                "blocked",
                action="tcp_payload",
                address=address,
                port=port,
                reason="unregistered_or_unpermitted",
            )
            raise ScopeDenied("Unregistered or unpermitted TCP protocol operation")
        if not self.guard.address_allowed(address, port):
            self.audit("blocked", action="tcp", address=address, port=port)
            raise ScopeDenied("TCP destination is outside scope")
        await self.reserve(
            action="tcp", address=address, port=port, operation="read_only_protocol" if payload else "connect"
        )
        request_id = uuid.uuid4().hex

        def operation():
            sock = self._connect(
                request_id,
                address,
                port,
                self.manifest.budgets.connect_timeout or self.manifest.budgets.timeout,
            )
            try:
                if payload:
                    sock.sendall(payload)
                if read_banner:
                    sock.settimeout(self.manifest.budgets.timeout if payload else 0.12)
                    try:
                        return sock.recv(16384)
                    except TimeoutError:
                        return b""
                return b""
            finally:
                self._close(request_id)

        try:
            body = await asyncio.wait_for(asyncio.to_thread(operation), self.manifest.budgets.timeout + 0.3)
        finally:
            self._close(request_id)
        evidence_id = self.evidence.capture(
            self.run_id,
            body,
            kind="tcp",
            metadata={"address": address, "port": port, "operation": "protocol" if payload else "connect"},
        )
        return body, evidence_id

    async def validate_flag(self, candidate: str):
        actor = worker_identity.get()
        if actor is None or actor.role != "Code":
            raise PermissionError("Only Code can use the evaluator capability")
        if not self.manifest.validation_url:
            return {"status": "validation_unavailable"}
        from urllib.parse import urlsplit

        url = self.manifest.validation_url
        parts = urlsplit(url)
        if parts.scheme != "http" or parts.path != "/validate" or parts.query or parts.username:
            raise ScopeDenied("Invalid local evaluator capability")
        address = ipaddress.ip_address(self.manifest.validation_address)
        if not address.is_loopback or parts.hostname != str(address):
            raise ScopeDenied("Evaluator must use its exact loopback numeric binding")
        await self.reserve(
            action="evaluator_validation", address=str(address), port=parts.port, infrastructure=True
        )
        dest = Destination(url, "http", str(address), str(address), parts.port, "/validate")
        body = json.dumps({"candidate": candidate}).encode()
        result = await self._execute_http(
            dest,
            {"Authorization": "Bearer " + self.manifest.validation_token, "Content-Type": "application/json"},
            "POST",
            body,
        )
        status, _, content = result[:3]
        if status != 200:
            return {"status": "validation_unavailable", "reason": f"checker HTTP {status}"}
        value = json.loads(content)
        if not isinstance(value, dict) or value.get("status") not in {"validated", "invalid"}:
            return {"status": "validation_unavailable", "reason": "invalid checker response"}
        return value

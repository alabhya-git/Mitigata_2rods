from __future__ import annotations

import asyncio
import socketserver
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import trustme

from mitigata.config import ScopeManifest
from mitigata.engine import Engine


def test_tls_pin_preserves_sni_and_rejects_wrong_identity(tmp_path, monkeypatch):
    ca = trustme.CA()
    certificate = ca.issue_cert("bound.local")
    ca_path = tmp_path / "test-ca.pem"
    ca.cert_pem.write_to_path(ca_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_path))
    observed_names = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "9")
            self.end_headers()
            self.wfile.write(b"tls-proof")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate.configure_cert(context)
    context.set_servername_callback(lambda sock, name, ctx: observed_names.append(name))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    manifest = ScopeManifest(
        authorized=True,
        authorization_reference="test TLS service",
        addresses=["127.0.0.1"],
        ports=[server.server_port],
        hostnames={"bound.local": ["127.0.0.1"], "wrong.local": ["127.0.0.1"]},
    )
    engine = Engine(tmp_path / "run", manifest)
    try:
        good = asyncio.run(engine.broker.http(f"https://bound.local:{server.server_port}/"))
        assert good.body == b"tls-proof"
        assert "bound.local" in observed_names
        with pytest.raises(ssl.SSLCertVerificationError):
            asyncio.run(engine.broker.http(f"https://wrong.local:{server.server_port}/"))
        assert not engine.broker.sockets
    finally:
        engine.store.close()
        server.shutdown()
        server.server_close()


def test_cancellation_closes_the_actual_socket_during_tls_handshake(tmp_path):
    release = threading.Event()

    class SilentTLS(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.recv(8192)
            release.wait(2)

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), SilentTLS)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    manifest = ScopeManifest(
        authorized=True,
        authorization_reference="silent test TLS fixture",
        addresses=["127.0.0.1"],
        ports=[server.server_address[1]],
    )
    engine = Engine(tmp_path / "run", manifest)

    async def check():
        pending = asyncio.create_task(engine.broker.http(f"https://127.0.0.1:{server.server_address[1]}/"))
        for _ in range(100):
            with engine.broker.socket_lock:
                has_tls = any(isinstance(sock, ssl.SSLSocket) for sock in engine.broker.sockets.values())
            if has_tls:
                break
            await asyncio.sleep(0.01)
        assert has_tls
        engine.broker.cancel()
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert not engine.broker.sockets

    try:
        asyncio.run(check())
    finally:
        release.set()
        engine.store.close()
        server.shutdown()
        server.server_close()

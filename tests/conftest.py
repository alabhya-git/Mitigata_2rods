from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from mitigata.config import ScopeManifest


@pytest.fixture
def manifest():
    return ScopeManifest(
        authorized=True,
        authorization_reference="pytest-owned loopback fixtures",
        addresses=["127.0.0.1/32"],
        ports=[8080],
        seed_urls=["http://127.0.0.1:8080/"],
    )


@pytest.fixture
def http_server():
    servers = []

    def create(routes):
        calls = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                calls.append(
                    {
                        "path": self.path,
                        "host": self.headers.get("Host"),
                        "authorization": self.headers.get("Authorization"),
                    }
                )
                value = routes(self) if callable(routes) else routes.get(self.path, (404, {}, b"Not found"))
                status, headers, body = value
                if isinstance(body, str):
                    body = body.encode()
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                with contextlib.suppress(OSError):
                    self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append((server, thread))
        return f"http://127.0.0.1:{server.server_port}/", calls

    yield create
    for server, thread in servers:
        server.shutdown()
        server.server_close()
        thread.join(2)

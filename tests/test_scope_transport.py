from __future__ import annotations

import asyncio
import socket
from urllib.parse import urlsplit

import pytest
from pydantic import ValidationError

from mitigata.config import ScopeManifest
from mitigata.engine import Engine
from mitigata.scope import ScopeDenied, ScopeGuard


@pytest.mark.parametrize(
    "url",
    [
        "http://192.0.2.1:8080/",
        "http://127.0.0.1:8081/",
        "http://localhost:8080/",
        "http://user:password@127.0.0.1:8080/",
        "file:///etc/passwd",
        "http://2130706433:8080/",
        "http://127.1:8080/",
        "http://127.0.0.1:8080/%2e%2e/private",
        "http://127.0.0.1:8080/%252e%252e/private",
        "http://127.0.0.1:8080/\\external",
        "http://127.0.0.1:8080/\r\nHost: other",
        "http://127.0.0.1:999999/",
    ],
)
def test_scope_rejects_ambiguous_and_unapproved_destinations(manifest, url):
    with pytest.raises(ScopeDenied):
        ScopeGuard(manifest).destination(url)


def test_path_prefix_is_segment_bounded(manifest):
    manifest.allowed_paths = ["/approved"]
    guard = ScopeGuard(manifest)
    assert guard.destination("http://127.0.0.1:8080/approved/resource").request_target == "/approved/resource"
    with pytest.raises(ScopeDenied):
        guard.destination("http://127.0.0.1:8080/approved-evil")


def test_local_scope_cannot_be_widened(manifest):
    data = manifest.model_dump()
    for changes in (
        {"authorized": False},
        {"addresses": ["0.0.0.0/0"]},
        {"mode": "AUTHORIZED_ASSESSMENT"},
        {"enabled": False},
    ):
        with pytest.raises(ValidationError):
            ScopeManifest.model_validate({**data, **changes})


def test_redirect_is_revalidated_before_any_second_connection(tmp_path, http_server):
    url, calls = http_server({"/": (302, {"Location": "http://192.0.2.1:9/escape"}, "")})
    manifest = ScopeManifest(
        authorized=True, authorization_reference="test", addresses=["127.0.0.1"], ports=[urlsplit(url).port]
    )
    engine = Engine(tmp_path, manifest)
    with pytest.raises(ScopeDenied):
        asyncio.run(engine.broker.http(url))
    assert len(calls) == 1
    assert any(a["data"]["status"] == "blocked" for a in engine.store.records(engine.run_id, "audit"))
    engine.store.close()


def test_frozen_hostname_binding_preserves_host_without_dns(tmp_path, http_server, monkeypatch):
    url, calls = http_server({"/": (200, {}, "ok")})
    port = urlsplit(url).port
    manifest = ScopeManifest(
        authorized=True,
        authorization_reference="test",
        addresses=["127.0.0.1"],
        ports=[port],
        hostnames={"bound.local": ["127.0.0.1"]},
    )
    engine = Engine(tmp_path, manifest)

    def fail_dns(*args, **kwargs):
        raise AssertionError("Transport must never use ambient DNS")

    monkeypatch.setattr(socket, "getaddrinfo", fail_dns)
    response = asyncio.run(engine.broker.http(f"http://bound.local:{port}/"))
    assert response.text == "ok"
    assert calls[0]["host"] == f"bound.local:{port}"
    engine.store.close()


def test_response_limit_is_enforced(tmp_path, http_server):
    url, _ = http_server({"/": (200, {}, "x" * 300000)})
    manifest = ScopeManifest(
        authorized=True, authorization_reference="test", addresses=["127.0.0.1"], ports=[urlsplit(url).port]
    )
    engine = Engine(tmp_path, manifest)
    with pytest.raises(ValueError, match="byte budget"):
        asyncio.run(engine.broker.http(url))
    engine.store.close()

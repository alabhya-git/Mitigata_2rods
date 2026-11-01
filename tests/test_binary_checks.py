from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from mitigata.binary import credential_records
from mitigata.checks import CheckRegistry
from mitigata.cli import main
from mitigata.config import ScopeManifest
from mitigata.engine import Engine
from mitigata.reporting import build_report


@pytest.mark.parametrize(
    "raw",
    [
        b"arbitrary\x00url=http://127.0.0.1:8080/\nuser=demo\npasswd=not-a-real-secret\n",
        json.dumps(
            {"endpoint": "http://127.0.0.1:8080/", "username": "demo", "password": "not-a-real-secret"}
        ).encode(),
    ],
)
def test_credentials_require_record_context_and_exact_offsets(raw):
    values = list(credential_records(raw))
    assert len(values) == 1
    record = values[0]
    assert (
        raw[record["string_offset"] : record["string_offset"] + len(record["password"])]
        == record["password"].encode()
    )
    assert list(credential_records(b"password=unrelated-string\0http://127.0.0.1:8080/")) == []


def test_configuration_only_check_runs_without_a_handler_edit(tmp_path, http_server):
    url, _ = http_server(
        {
            "/": (200, {}, '<a href="/api/spec">API documentation</a>'),
            "/api/spec": (200, {"Content-Type": "application/json"}, '{"openapi":"3.1.0","paths":{}}'),
        }
    )
    manifest = ScopeManifest(
        authorized=True,
        authorization_reference="config extension fixture",
        addresses=["127.0.0.1"],
        ports=[urlsplit(url).port],
    )
    registry = CheckRegistry(Path(__file__).parent.parent / "examples/checks.openapi.yaml")
    engine = Engine(tmp_path, manifest, checks=registry)
    asyncio.run(engine.run())
    report = build_report(engine.store, engine.run_id)
    assert any(
        f["data"]["id"] == "web.openapi_document" and f["data"]["status"] == "confirmed"
        for f in report["findings"]
    )
    engine.store.close()


def test_arbitrary_check_primitive_is_rejected(tmp_path):
    pack = tmp_path / "bad.yaml"
    pack.write_text(
        "version: 1\nrecipes:\n- id: web.bad\n  surface: web\n  primitive: execute_shell\n  title: Bad\n  claim: Bad\n  severity: high\n  remediation: Bad\n"
    )
    with pytest.raises(ValueError, match="registered"):
        CheckRegistry(pack)


def test_dry_run_never_queries_dns_or_opens_a_socket(tmp_path, manifest, monkeypatch):
    import socket

    path = tmp_path / "manifest.json"
    path.write_text(manifest.model_dump_json())

    def forbidden(*args, **kwargs):
        raise AssertionError("Dry run attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    assert main(["dry-run", str(path)]) == 0

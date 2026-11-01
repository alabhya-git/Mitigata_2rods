from __future__ import annotations

import io
import json
import zipfile

from fastapi.testclient import TestClient

from mitigata.api import create_app
from mitigata.store import Store

TOKEN = "pytest-operator-token-with-32-characters"


def test_auth_host_origin_and_static_dashboard(tmp_path):
    with TestClient(create_app(tmp_path, TOKEN), base_url="http://127.0.0.1") as client:
        assert client.get("/health").status_code == 200
        assert client.get("/api/runs").status_code == 401
        headers = {"Authorization": "Bearer " + TOKEN}
        assert client.get("/api/runs", headers=headers).status_code == 200
        assert client.get("/api/runs", headers={**headers, "Host": "unapproved.test"}).status_code == 400
        assert (
            client.post(
                "/api/demo", json={}, headers={**headers, "Origin": "https://unapproved.test"}
            ).status_code
            == 403
        )
        page = client.get("/")
        assert page.status_code == 200
        assert "Content-Security-Policy" in page.headers
        assert client.get("/static/app.js").status_code == 200
        assert client.get("/static/../../config.py").status_code == 404
        assert client.get("/api/runs/missing", headers=headers).status_code == 404


def test_sse_cursor_and_unified_report_bundle(tmp_path):
    store = Store(tmp_path / "state.sqlite3")
    run = store.create_run({"name": "persisted test"}, 30)
    store.event(run, "Recon", "one", {})
    store.event(run, "Web", "two", {})
    store.terminal(run, "completed", "test complete")
    cursor = store.events(run)[1]["seq"]
    store.close()
    with TestClient(
        create_app(tmp_path, TOKEN), base_url="http://127.0.0.1", headers={"Authorization": "Bearer " + TOKEN}
    ) as client:
        events = client.get(f"/api/runs/{run}/events", headers={"Last-Event-ID": str(cursor)})
        assert events.status_code == 200
        assert '"kind": "one"' not in events.text
        assert '"kind": "two"' in events.text
        bundle = client.get(f"/api/runs/{run}/bundle")
        archive = zipfile.ZipFile(io.BytesIO(bundle.content))
        assert {"report.html", "report.json"}.issubset(archive.namelist())
        assert json.loads(archive.read("report.json"))["run"]["status"] == "completed"
        assert client.get(f"/targets/{run}/findings").json() == []


def test_demo_dashboard_rejects_external_scope_without_connecting(tmp_path, monkeypatch):
    import socket

    from mitigata.config import ScopeManifest

    manifest = ScopeManifest(
        name="No connection should occur",
        authorized=True,
        authorization_reference="owned fixture API rejection test",
        mode="DISCOVERY_ONLY",
        execution_profile="native_guarded",
        addresses=["192.168.56.0/24"],
        ports=[80],
        permitted_checks=["web.credential_literal"],
    )
    attempts = []

    def blocked(*args, **kwargs):
        attempts.append(args)
        raise AssertionError("Rejected API scope must never connect")

    with TestClient(
        create_app(tmp_path, TOKEN), base_url="http://127.0.0.1", headers={"Authorization": "Bearer " + TOKEN}
    ) as client:
        monkeypatch.setattr(socket.socket, "connect", blocked)
        assert client.post("/api/runs", json=manifest.public()).status_code == 422
        assert client.get("/api/runs").json() == []
        monkeypatch.undo()
    assert attempts == []


def test_network_dashboard_rejects_scope_change(tmp_path, http_server):
    from urllib.parse import urlsplit

    from mitigata.config import ScopeManifest

    url, _ = http_server({"/": (200, {}, "owned fixture")})
    manifest = ScopeManifest(
        name="Frozen dashboard scope",
        authorized=True,
        authorization_reference="owned fixture dashboard scope test",
        mode="DISCOVERY_ONLY",
        execution_profile="native_guarded",
        addresses=["127.0.0.1/32"],
        ports=[urlsplit(url).port],
        permitted_checks=["web.credential_literal"],
    )
    with TestClient(
        create_app(tmp_path, TOKEN, startup_scope=manifest),
        base_url="http://127.0.0.1",
        headers={"Authorization": "Bearer " + TOKEN},
    ) as client:
        assert client.get("/health").json()["external_assessment"] == "scoped"
        altered = manifest.public()
        altered["ports"] = [1]
        assert client.post("/api/runs", json=altered).status_code == 422
        assert len(client.get("/api/runs").json()) == 1

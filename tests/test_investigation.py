from __future__ import annotations

import asyncio
import gzip
import io
import json
import threading
import zipfile
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import pytest

from mitigata.ai import AIBudgetExceeded, AIUnavailable, BudgetLedger, ClaudeClient
from mitigata.artifacts import archive_members
from mitigata.codes import candidates
from mitigata.config import AISettings, ScopeManifest
from mitigata.engine import Engine
from mitigata.progress import snapshot
from mitigata.reporting import build_report
from mitigata.scope import ScopeDenied, ScopeGuard
from mitigata.store import Store
from mitigata.tool_runner import parse_nmap


def make_scope(url, **changes):
    return ScopeManifest.model_validate(
        {
            "name": "Independently authored investigation fixture",
            "authorized": True,
            "authorization_reference": "owned fixture",
            "addresses": ["127.0.0.1/32"],
            "ports": [urlsplit(url).port],
            "seed_urls": [url],
            "investigation": {
                "enabled": True,
                "allow_partial_responses": True,
                "decode_compression": True,
                "discover_artifacts": True,
                "max_path_probes": 8,
                "paths": ["robots.txt", "openapi.json", ".git/HEAD", "config.json"],
            },
            "budgets": {"seconds": 30, "requests": 200, "rate_per_second": 500, "workers": 8, "timeout": 0.3},
            **changes,
        }
    )


def test_unfamiliar_api_artifact_and_nonlegacy_code_discovery(tmp_path, http_server):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("../../never-extract.txt", "hidden_code=TESTLAB{different_representation_91}\n")
    routes = {
        "/": (200, {"Content-Type": "text/html"}, '<script>const discovery="/metadata.json";</script>'),
        "/metadata.json": (
            200,
            {"Content-Type": "application/json"},
            json.dumps({"download": "/bundle.zip"}),
        ),
        "/bundle.zip": (200, {"Content-Type": "application/octet-stream"}, archive.getvalue()),
        "/openapi.json": (
            200,
            {"Content-Type": "application/json"},
            json.dumps({"openapi": "3.0.0", "paths": {"/v7/config": {"get": {}}}}),
        ),
        "/v7/config": (
            200,
            {"Content-Type": "application/json"},
            json.dumps({"api_key": "fixture-credential-7283"}),
        ),
        "/.git/HEAD": (200, {}, "ref: refs/heads/main\n"),
    }
    url, calls = http_server(routes)
    engine = Engine(tmp_path, make_scope(url))
    asyncio.run(engine.run())
    report = build_report(engine.store, engine.run_id)
    assert report["run"]["status"] == "completed", [
        (t["kind"], t["error"]) for t in report["tasks"] if t["status"] == "failed"
    ]
    assert any(
        f["data"]["id"] == "web.structured_secret" and f["data"]["status"] == "confirmed"
        for f in report["findings"]
    )
    assert any(
        f["data"]["id"] == "web.git_metadata" and f["data"]["status"] == "confirmed"
        for f in report["findings"]
    )
    assert len(report["artifacts"]) == 2
    assert any(f["data"]["status"] == "validation_unavailable" for f in report["flags"])
    secret = engine.store.reveal(engine.run_id, report["flags"][0]["data"]["secret_ref"], "Operator")
    assert secret["exact_value"] == "TESTLAB{different_representation_91}"
    assert not (tmp_path / "never-extract.txt").exists()
    assert any(c["path"] == "/v7/config" for c in calls)
    engine.store.close()


def test_batched_discovery_accounts_for_closed_and_open_ports(tmp_path, http_server):
    url, _ = http_server({"/": (200, {}, "owned fixture")})
    manifest = make_scope(
        url,
        ports=[urlsplit(url).port, *range(1, 17)],
        discovery={"batched": True, "batch_size": 8, "concurrency": 16},
        investigation={"enabled": True, "max_path_probes": 0},
        budgets={
            "seconds": 15,
            "requests": 100,
            "rate_per_second": 500,
            "workers": 4,
            "queue_window": 2,
            "timeout": 0.3,
            "connect_timeout": 0.2,
        },
    )
    engine = Engine(tmp_path, manifest)
    asyncio.run(engine.run())
    r = build_report(engine.store, engine.run_id)
    assert r["run"]["status"] == "completed"
    assert r["metrics"]["scope_pairs_tested"] == 17 and r["metrics"]["scope_pairs_untested"] == 0
    assert r["metrics"]["services_discovered"] == 1
    assert any(t["kind"] == "batch" for t in r["tasks"])
    assert len(r["tasks"]) < 17 + 10
    engine.store.close()


def test_ai_tools_are_real_and_out_of_scope_proposals_are_rejected(tmp_path, http_server):
    url, calls = http_server(
        {
            "/": (200, {}, "A puzzle is referenced at /unadvertised"),
            "/unadvertised": (200, {}, "challenge_code: NOVEL{agent_selected_route_53}"),
        }
    )
    requests = []

    def fake_provider(payload):
        requests.append(payload)
        results = payload["messages"][-1]["content"]
        if isinstance(results, str):
            content = [
                {
                    "type": "tool_use",
                    "id": "bad",
                    "name": "inspect_http",
                    "input": {"url": "http://192.0.2.77/blocked"},
                },
                {
                    "type": "tool_use",
                    "id": "good",
                    "name": "inspect_http",
                    "input": {"url": url + "unadvertised"},
                },
            ]
        else:
            content = [{"type": "text", "text": "The bounded tools returned evidence; stop."}]
        return {"content": content, "usage": {"input_tokens": 1000, "output_tokens": 100}}

    manifest = make_scope(
        url,
        ai={"enabled": True, "required": True, "max_calls": 4, "budget_usd": 0.5},
        investigation={"enabled": True, "max_path_probes": 0, "max_cases": 1},
    )
    engine = Engine(tmp_path, manifest, ai_transport=fake_provider)
    asyncio.run(engine.run())
    r = build_report(engine.store, engine.run_id)
    assert r["run"]["status"] == "completed"
    assert len(requests) == 2
    assert any(c["path"] == "/unadvertised" for c in calls)
    assert r["metrics"]["blocked_attempts"] >= 1
    assert len(r["flags"]) >= 1
    assert engine.context.ai_client.ledger.summary()["spent_usd"] == pytest.approx(0.006)
    assert any(e["kind"] == "ai_tool_rejected" for e in engine.store.events(engine.run_id, limit=5000))
    engine.store.close()


def test_shared_ai_budget_is_atomic_across_workers(tmp_path):
    store = Store(tmp_path / "state.sqlite3")
    run = store.create_run({"name": "budget"}, 30)
    ledger = BudgetLedger(store, run, AISettings(budget_usd=0.01, max_calls=50))

    def reserve(_):
        try:
            return ledger.reserve(1000, 100)
        except AIBudgetExceeded:
            return None

    with ThreadPoolExecutor(max_workers=8) as workers:
        reserved = [r for r in workers.map(reserve, range(20)) if r]
    assert len(reserved) == 3
    assert ledger.summary()["spent_usd"] + ledger.summary()["reserved_usd"] <= 0.01
    ledger.settle(reserved[0], {"input_tokens": 500, "output_tokens": 50})
    assert ledger.summary()["spent_usd"] == pytest.approx(0.0015)
    with pytest.raises(ValueError):
        ledger.settle(reserved[0], {"input_tokens": 1, "output_tokens": 1})
    store.close()


def test_uncertain_provider_failure_retains_reservation(tmp_path):
    store = Store(tmp_path / "state.sqlite3")
    run = store.create_run({"name": "uncertain provider"}, 30)

    def fail(_):
        raise TimeoutError("controlled timeout")

    client = ClaudeClient(store, run, AISettings(budget_usd=0.1), transport=fail)
    with pytest.raises(AIUnavailable):
        asyncio.run(client.complete("Web", "system", [{"role": "user", "content": "test"}], []))
    assert client.ledger.summary()["reserved_usd"] > 0
    with pytest.raises(AIUnavailable):
        asyncio.run(client.complete("Web", "system", [], []))
    assert client.ledger.summary()["calls"] == 1
    store.close()


def test_live_snapshot_stays_small_as_scan_history_grows(tmp_path):
    store = Store(tmp_path / "state.sqlite3")
    run = store.create_run({"name": "large synthetic history"}, 30)
    store.put_many(
        run,
        [
            {
                "kind": "port",
                "identity": str(i),
                "data": {"port": i, "status": "closed", "address": "127.0.0.1"},
            }
            for i in range(1, 10001)
        ],
        "Recon",
    )
    result = snapshot(store, run)
    assert len(json.dumps(result).encode()) < 20000
    assert result["counts"]["port"] == 10000
    assert result["tasks"] == []
    store.close()


def test_gzip_and_partial_framing_keep_http_identity(tmp_path, http_server):
    url, _ = http_server(
        {"/": (200, {"Content-Encoding": "gzip"}, gzip.compress(b"FLAG{decoded_fixture_874}"))}
    )
    engine = Engine(
        tmp_path / "gzip",
        make_scope(
            url,
            investigation={
                "enabled": True,
                "decode_compression": True,
                "allow_partial_responses": True,
                "max_path_probes": 0,
            },
        ),
    )
    asyncio.run(engine.run())
    report = build_report(engine.store, engine.run_id)
    assert len(report["flags"]) == 1
    assert report["services"][0]["data"]["protocol"] == "http"
    engine.store.close()


def test_same_ip_authority_requires_evidence_and_cannot_bind_another_ip(tmp_path, http_server):
    url, _ = http_server({"/": (200, {}, '<a href="http://vault.lab/">vault</a>')})
    engine = Engine(
        tmp_path,
        make_scope(
            url, investigation={"enabled": True, "follow_same_ip_hostnames": True, "max_path_probes": 0}
        ),
    )
    ref = engine.evidence.capture(engine.run_id, b"vault.lab", kind="http", metadata={})
    assert engine.broker.bind_authority("vault.lab", ref)
    assert engine.broker.guard.bindings["vault.lab"] == ("127.0.0.1",)
    assert not engine.broker.bind_authority("192.0.2.88", ref)
    with pytest.raises(ScopeDenied):
        engine.broker.bind_authority("missing.lab", "made-up-evidence")
    engine.store.close()


def test_nmap_import_rejects_xml_entities_and_unrequested_endpoints():
    guard = ScopeGuard(make_scope("http://127.0.0.1:8080/"))
    raw = b'<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http"/></port></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'
    assert parse_nmap(raw, guard, [("127.0.0.1", 8080)])[0]["service_hint"]["name"] == "http"
    with pytest.raises(ScopeDenied):
        parse_nmap(raw.replace(b"8080", b"8081"), guard, [("127.0.0.1", 8080)])
    with pytest.raises(ValueError):
        parse_nmap(
            b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>' + raw, guard, [("127.0.0.1", 8080)]
        )


def test_generic_and_labelled_codes_and_zip_bomb_limit():
    values = candidates(b"CHALLENGE{unfamiliar_marker_12}\nflag_b64=U0VDUkVUX0NPREVfMTIz\n")
    assert any(c["value"] == "CHALLENGE{unfamiliar_marker_12}" for c in values)
    assert any(c["value"] == "SECRET_CODE_123" for c in values)
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("huge", b"A" * 100000)
    assert list(archive_members(b.getvalue(), 1000)) == []


def test_downloaded_credential_unlocks_reviewed_form_session(tmp_path):
    from urllib.parse import parse_qs

    attempts = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, status, body=b"", headers=None):
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/":
                return self.send(200, b'<a href="/agent.bin">client program</a>')
            if self.path == "/agent.bin":
                text = f"service_url=http://127.0.0.1:{self.server.server_port}/private\nusername=alice\npassword=owned-derived-password\n"
                return self.send(200, text.encode(), {"Content-Type": "application/octet-stream"})
            if self.path == "/login":
                return self.send(
                    200,
                    b'<form method="POST" action="/session"><input type="hidden" name="csrf" value="controlled-csrf"><input name="username"><input type="password" name="password"></form>',
                )
            if self.path == "/private":
                if self.headers.get("Cookie") == "session=controlled-session":
                    return self.send(200, b"CHALLENGE{cross_surface_session_548}")
                return self.send(302, headers={"Location": "/login"})
            return self.send(404, b"not found")

        def do_POST(self):
            data = parse_qs(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
            attempts.append(data)
            if self.path == "/session" and data == {
                "username": ["alice"],
                "password": ["owned-derived-password"],
                "csrf": ["controlled-csrf"],
            }:
                return self.send(
                    303,
                    headers={
                        "Set-Cookie": "session=controlled-session; HttpOnly; Path=/",
                        "Location": "/private",
                    },
                )
            return self.send(403, b"login failed")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        manifest = make_scope(
            url,
            allow_credential_use=True,
            allowed_actions=["http_get", "credential_validation", "session_authentication"],
            investigation={"enabled": True, "discover_artifacts": True, "max_path_probes": 0},
        )
        engine = Engine(tmp_path, manifest)
        asyncio.run(engine.run())
        report = build_report(engine.store, engine.run_id)
        assert report["run"]["status"] == "completed", [
            (t["kind"], t["error"]) for t in report["tasks"] if t["status"] == "failed"
        ]
        assert len(attempts) == 1
        assert any(
            f["data"]["primitive"] == "form_auth" and f["data"]["status"] == "confirmed"
            for f in report["findings"]
        )
        assert any(f["data"]["status"] == "validation_unavailable" for f in report["flags"])
        assert any(
            e["data"]["relation"] == "retrieved_unvalidated_code_candidate" for e in report["attack_path"]
        )
        assert "controlled-session" not in json.dumps(report)
        engine.store.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def test_keepalive_without_length_preserves_partial_http_diagnostics(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"partial body with missing framing")
            self.wfile.flush()
            self.close_connection = False

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/"
        engine = Engine(
            tmp_path,
            make_scope(
                url, investigation={"enabled": True, "allow_partial_responses": True, "max_path_probes": 0}
            ),
        )
        response = asyncio.run(engine.broker.http(url))
        assert (
            response.status == 200
            and response.truncated
            and response.diagnostics["body_error"] == "TimeoutError"
        )
        assert b"partial body" in response.body
        engine.store.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)

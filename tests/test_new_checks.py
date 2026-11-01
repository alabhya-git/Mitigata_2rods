from __future__ import annotations

import asyncio
import base64
import re
from urllib.parse import parse_qs, urlsplit

from mitigata.config import Budgets, InvestigationSettings, ScopeManifest
from mitigata.engine import Engine
from mitigata.reporting import build_report

ACTIONS = ["http_get", "injection_probe", "default_credential_probe", "credential_validation"]
CHECKS = [
    "web.path_traversal",
    "web.sql_injection",
    "web.ssti",
    "web.open_redirect",
    "web.default_credentials",
    "network.elasticsearch_unauthenticated",
]


def run(tmp_path, url, **overrides):
    manifest = ScopeManifest(
        name="loopback new-check fixture",
        authorized=True,
        authorization_reference="pytest-owned loopback fixture",
        addresses=["127.0.0.1/32"],
        ports=[urlsplit(url).port],
        seed_urls=[url],
        allow_credential_use=True,
        allowed_actions=ACTIONS,
        permitted_checks=CHECKS,
        budgets=Budgets(max_auth_attempts=10, max_pages=60),
        **overrides,
    )
    engine = Engine(tmp_path, manifest)
    asyncio.run(engine.run())
    report = build_report(engine.store, engine.run_id)
    engine.store.close()
    confirmed = {f["data"]["primitive"] for f in report["findings"] if f["data"]["status"] == "confirmed"}
    rejected = {f["data"]["primitive"] for f in report["findings"] if f["data"]["status"] == "rejected"}
    return confirmed, rejected


def _query(handler):
    u = urlsplit(handler.path)
    return u.path, {k: v[0] for k, v in parse_qs(u.query).items()}


def injection_app(vulnerable):
    links = (
        '<a href="/file?name=readme.txt">file</a>'
        '<a href="/find?q=hello">find</a>'
        '<a href="/render?name=guest">render</a>'
        '<form method="get" action="/go"><input name="next" type="text"></form>'
    )

    def app(handler):
        path, q = _query(handler)
        if path == "/":
            return (200, {"Content-Type": "text/html"}, links)
        if path == "/file":
            name = q.get("name", "")
            if vulnerable and ("etc/passwd" in name or "win.ini" in name.lower()):
                return (200, {"Content-Type": "text/plain"}, "root:x:0:0:root:/root:/bin/bash\n")
            return (200, {"Content-Type": "text/plain"}, "file: " + name)
        if path == "/find":
            value = q.get("q", "")
            if vulnerable and "'" in value:
                return (500, {"Content-Type": "text/html"}, '<pre>sqlite3.OperationalError: near "\'": syntax error</pre>')
            return (200, {"Content-Type": "text/html"}, f"<p>results for {value}</p>")
        if path == "/render":
            value = q.get("name", "")
            if vulnerable:
                value = re.sub(r"\{\{(\d+)\*(\d+)\}\}", lambda m: str(int(m.group(1)) * int(m.group(2))), value)
            return (200, {"Content-Type": "text/html"}, f"<h1>Hello {value}</h1>")
        if path == "/go":
            nxt = q.get("next", "")
            if vulnerable:
                return (302, {"Location": nxt}, "")
            return (302, {"Location": "/home"}, "")
        return (404, {}, "nope")

    return app


def test_injection_classes_are_confirmed_on_vulnerable_app(tmp_path, http_server):
    url, _ = http_server(injection_app(vulnerable=True))
    confirmed, _ = run(tmp_path, url, investigation=InvestigationSettings(enabled=True, max_path_probes=0))
    assert {"path_traversal", "sql_injection", "ssti", "open_redirect"} <= confirmed


def test_injection_classes_are_not_claimed_on_fixed_app(tmp_path, http_server):
    url, _ = http_server(injection_app(vulnerable=False))
    confirmed, _ = run(tmp_path, url, investigation=InvestigationSettings(enabled=True, max_path_probes=0))
    assert not ({"path_traversal", "sql_injection", "ssti", "open_redirect"} & confirmed)


def basic_auth_app(accept):
    def app(handler):
        path, _ = _query(handler)
        if path == "/":
            return (200, {"Content-Type": "text/html"}, '<a href="/panel">panel</a>')
        if path == "/panel":
            supplied = handler.headers.get("Authorization", "")
            expected = "Basic " + base64.b64encode(accept.encode()).decode() if accept else None
            if expected and supplied == expected:
                return (200, {"Content-Type": "text/plain"}, "welcome operator")
            return (401, {"WWW-Authenticate": 'Basic realm="panel"'}, "authentication required")
        return (404, {}, "nope")

    return app


def test_default_credentials_confirmed_when_default_accepted(tmp_path, http_server):
    url, _ = http_server(basic_auth_app(accept="admin:admin"))
    confirmed, _ = run(tmp_path, url)
    assert "default_credentials" in confirmed


def test_default_credentials_not_claimed_for_strong_password(tmp_path, http_server):
    url, _ = http_server(basic_auth_app(accept="operator:S3cr3t-not-in-the-list-xyz"))
    confirmed, _ = run(tmp_path, url)
    assert "default_credentials" not in confirmed


def datastore_app(expose):
    def app(handler):
        path, _ = _query(handler)
        if path == "/" and expose:
            return (200, {"Content-Type": "application/json"},
                    '{"name":"node-1","cluster_name":"prod","version":{"number":"7.10.0"},"tagline":"You Know, for Search"}')
        if path == "/":
            return (200, {"Content-Type": "text/html"}, "<h1>app</h1>")
        return (404, {"Content-Type": "application/json"}, '{"error":"not found"}')

    return app


def test_elasticsearch_unauthenticated_confirmed(tmp_path, http_server):
    url, _ = http_server(datastore_app(expose=True))
    confirmed, _ = run(tmp_path, url)
    assert "http_service_unauth" in confirmed


def test_elasticsearch_signature_absent_on_ordinary_app(tmp_path, http_server):
    url, _ = http_server(datastore_app(expose=False))
    confirmed, _ = run(tmp_path, url)
    assert "http_service_unauth" not in confirmed

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from mitigata.cli import demo
from mitigata.config import Budgets, ScopeManifest
from mitigata.engine import Engine
from mitigata.lab import LocalLab
from mitigata.reporting import build_report


@pytest.mark.parametrize("layout", ["reference", "script", "header", "json"])
def test_three_surface_chain_and_rejected_decoys(tmp_path, layout):
    result = asyncio.run(demo(tmp_path, seed=73, layout=layout))
    assert result["status"] == "completed"
    evaluation = result["evaluation"]
    assert evaluation["true_positives"] == evaluation["planted_issues"] == 7
    assert evaluation["false_positives"] == 0
    assert evaluation["service_recall"] == 1
    assert evaluation["validated_flags"] == 1
    report = json.loads((tmp_path / "reports" / result["run_id"] / "report.json").read_text())
    assert report["metrics"]["rejected"] > 0
    assert report["metrics"]["blocked_attempts"] >= 1
    assert {b["producer"] for b in report["briefings"]} == {
        "Recon",
        "Web",
        "Binary",
        "Correlator",
        "Falsifier",
        "Code",
        "Reporter",
    }
    assert all(b["data"]["bytes"] <= b["data"]["budget_bytes"] for b in report["briefings"])
    assert any(e["data"]["relation"] == "retrieved_validated_code" for e in report["attack_path"])
    assert all(
        f["data"].get("verification_id") for f in report["findings"] if f["data"]["status"] == "confirmed"
    )
    assert report["metrics"]["independently_observed_scope_violations"] is None
    assert any(e["kind"] == "report_bundle_finalized" for e in report["events"])
    serialized = json.dumps(report)
    assert "pw_" not in serialized
    # Operator reports intentionally disclose captured codes in this dedicated
    # field. All other report content must keep the original redaction boundary.
    for flag in report["flags"]:
        value = flag["data"].pop("value")
        assert value.startswith("FLAG{") and value.endswith("}")
    assert "FLAG{" not in json.dumps(report)


@pytest.mark.parametrize("profile", ["no_flag", "fixed"])
def test_negative_counterparts_never_claim_code_success(tmp_path, profile):
    result = asyncio.run(demo(tmp_path, **{profile: True}))
    assert result["status"] == "completed"
    assert not result["evaluation"]["has_valid_flag"]
    assert result["metrics"]["validated_flags"] == 0
    if profile == "fixed":
        assert result["metrics"]["confirmed"] == 0


def test_cross_surface_sharing_is_necessary(tmp_path):
    result = asyncio.run(demo(tmp_path, sharing=False))
    assert result["status"] == "completed"
    assert result["metrics"]["validated_flags"] == 0
    assert "basic_auth" in result["evaluation"]["missing_issue_classes"]


def test_missing_binary_prevents_the_protected_chain(tmp_path):
    with LocalLab(tmp_path / "lab") as lab:
        lab.manifest.artifacts = []
        engine = Engine(tmp_path / "run", lab.manifest)
        asyncio.run(engine.run())
        report = build_report(engine.store, engine.run_id)
        assert report["metrics"]["services_discovered"] == 3
        assert report["metrics"]["validated_flags"] == 0
        assert not report["attack_path"]
        engine.store.close()


def test_budget_expiry_still_exports_a_report(tmp_path, http_server):
    url, _ = http_server({"/": (200, {}, "hello")})
    manifest = ScopeManifest(
        authorized=True,
        authorization_reference="test",
        addresses=["127.0.0.1"],
        ports=[urlsplit(url).port],
        budgets=Budgets(requests=1),
    )
    engine = Engine(tmp_path, manifest)
    asyncio.run(engine.run())
    assert engine.store.run(engine.run_id)["status"] == "partial_budget"
    assert (tmp_path / "reports" / engine.run_id / "report.html").is_file()
    engine.store.close()


def test_capability_line_reports_each_adapter_state_honestly():
    from mitigata.reporting import capability_line

    def state(identity, data):
        return capability_line({"identity": identity, "data": data})[1]

    # The dashboard and report classify a heterogeneous mix of capability records;
    # a degraded or missing tool must never read as available coverage.
    assert state("runtime", {"deterministic": True, "execution_profile": "local"}) == "deterministic"
    assert state("browser", {"available": True, "requests_brokered": 7}) == "available"
    assert state("browser", {"available": False, "reason": "needs Linux confinement"}) == "unavailable"
    assert state("katana", {"available": False, "last_execution": "failed", "reason": "timeout"}) == "failed"
    assert state("nmap", {"installed": False, "live_allowed": False, "reason": "missing_executable"}) == "not installed"
    assert state("nmap", {"installed": True, "live_allowed": True, "path": "/usr/bin/nmap"}) == "live"


def test_cancellation_stops_queued_network_work(tmp_path, manifest):
    manifest.ports = list(range(10000, 10020))
    manifest.seed_urls = []
    engine = Engine(tmp_path, manifest)
    engine.store.request_cancel(engine.run_id)
    asyncio.run(engine.run())
    assert engine.store.run(engine.run_id)["status"] == "cancelled"
    assert build_report(engine.store, engine.run_id)["metrics"]["human_interventions_during_run"] == 1
    assert not engine.store.records(engine.run_id, "audit")
    assert not any(t["status"] in {"running", "queued"} for t in engine.store.tasks(engine.run_id))
    engine.store.close()


def test_separately_authored_web_fixture_and_metadata_only_claims(tmp_path, http_server):
    # This HTTP application does not use the demo generator or its route/response conventions.
    routes = {
        "/": (
            200,
            {"Content-Type": "text/html"},
            '<form method="post" action="/submit"><input name="email"></form><a href="/downloads/">Downloads</a><script src="/assets/main.js"></script>',
        ),
        "/downloads/": (
            200,
            {},
            '<h1>Directory listing for /downloads/</h1><a href="guide.txt">guide.txt</a>',
        ),
        "/assets/main.js": (
            200,
            {"Content-Type": "text/javascript"},
            'const settings = "/config/runtime.txt";',
        ),
        "/config/runtime.txt": (
            200,
            {"Content-Type": "text/plain"},
            "SECRET=independently-authored-test-value\n",
        ),
    }
    url, calls = http_server(routes)
    manifest = ScopeManifest(
        authorized=True,
        authorization_reference="separate test app",
        addresses=["127.0.0.1"],
        ports=[urlsplit(url).port],
        seed_urls=[url],
        baseline_urls=[url],
    )
    engine = Engine(tmp_path, manifest)
    asyncio.run(engine.run())
    report = build_report(engine.store, engine.run_id)
    positives = {f["data"]["primitive"] for f in report["findings"] if f["data"]["status"] == "confirmed"}
    assert positives == {"directory_listing", "credential_literal"}
    assert any(e["data"]["forms"] for e in report["endpoints"])
    assert not any(c["path"] == "/submit" for c in calls)
    assert report["metrics"]["validated_flags"] == 0
    engine.store.close()


def test_resume_after_observation_before_task_completion(tmp_path):
    from mitigata.security import WorkerIdentity, worker_identity

    with LocalLab(tmp_path / "lab") as lab:
        root = tmp_path / "run"
        first = Engine(root, lab.manifest)
        run_id = first.run_id
        task = first.store.claim(run_id, "Recon", "crashed-worker")
        token = worker_identity.set(WorkerIdentity("Recon", task["id"], "crashed-worker", task["fence"]))
        try:
            asyncio.run(first.broker.tcp(task["payload"]["address"], task["payload"]["port"]))
        finally:
            worker_identity.reset(token)
        with first.store.transaction(fenced=False):
            first.store.db.execute("UPDATE tasks SET lease_until=0 WHERE id=?", (task["id"],))
        first.store.close()
        resumed = Engine(root, lab.manifest, run_id=run_id)
        asyncio.run(resumed.run())
        report = build_report(resumed.store, run_id)
        assert report["run"]["status"] == "completed"
        assert report["metrics"]["validated_flags"] == 1
        assert report["metrics"]["confirmed"] == 7
        assert resumed.store.task(task["id"])["attempts"] == 2
        resumed.store.close()


def test_public_service_does_not_receive_artifact_passwords(tmp_path, http_server):
    url, calls = http_server({"/": (200, {}, "This is intentionally public")})
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "client.bin").write_bytes(
        f"service_url={url}\nusername=test\npassword=unrelated-private-value\n".encode()
    )
    manifest = ScopeManifest(
        authorized=True,
        authorization_reference="test",
        addresses=["127.0.0.1"],
        ports=[urlsplit(url).port],
        allow_credential_use=True,
        artifacts=["client.bin"],
        artifact_root=str(artifacts),
    )
    engine = Engine(tmp_path / "run", manifest)
    asyncio.run(engine.run())
    assert all(call["authorization"] is None for call in calls)
    assert build_report(engine.store, engine.run_id)["metrics"]["validated_flags"] == 0
    engine.store.close()


def test_network_service_fact_is_a_required_prerequisite(tmp_path):
    with LocalLab(tmp_path / "lab") as lab:
        engine = Engine(tmp_path / "run", lab.manifest)
        # The protected authority remains permitted and referenced. Only its discovery task is removed.
        artifact_bytes = (Path(lab.manifest.artifact_root) / "client.elf").read_bytes()
        from mitigata.binary import credential_records

        target = urlsplit(next(credential_records(artifact_bytes))["service_url"])
        with engine.store.transaction(fenced=False):
            for task in engine.store.tasks(engine.run_id):
                if task["role"] == "Recon" and task["payload"]["port"] == target.port:
                    engine.store.db.execute("UPDATE tasks SET status='cancelled' WHERE id=?", (task["id"],))
        asyncio.run(engine.run())
        report = build_report(engine.store, engine.run_id)
        assert any(
            f["data"]["primitive"] == "binary_credential" and f["data"]["status"] == "confirmed"
            for f in report["findings"]
        )
        assert report["metrics"]["validated_flags"] == 0
        assert not report["attack_path"]
        engine.store.close()


def test_harmless_get_form_reflection_is_not_promoted_to_xss(tmp_path, http_server):
    from urllib.parse import parse_qs

    def routes(request):
        parsed = urlsplit(request.path)
        if parsed.path == "/":
            return 200, {}, '<form action="/search" method="get"><input name="q" type="search"></form>'
        if parsed.path == "/search":
            return 200, {}, "Search term: " + parse_qs(parsed.query).get("q", [""])[0]
        return 404, {}, "Not found"

    url, _ = http_server(routes)
    manifest = ScopeManifest(
        authorized=True,
        authorization_reference="GET reflection fixture",
        addresses=["127.0.0.1"],
        ports=[urlsplit(url).port],
    )
    engine = Engine(tmp_path, manifest)
    asyncio.run(engine.run())
    report = build_report(engine.store, engine.run_id)
    assert any(o["data"]["type"] == "input_reflection" for o in report["observations"])
    assert not any("xss" in f["data"]["id"].lower() for f in report["findings"])
    engine.store.close()

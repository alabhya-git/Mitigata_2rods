from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
from urllib.parse import urlsplit

import pytest
from pydantic import ValidationError

from mitigata.config import Budgets, ScopeManifest, load_manifest
from mitigata.confinement import firewall_rules, port_groups
from mitigata.engine import Engine
from mitigata.preflight import plan
from mitigata.reporting import build_report
from mitigata.runtime_guard import WorkerNetworkPolicy, install_worker_guard, worker_network_policy
from mitigata.scope import ScopeDenied, ScopeGuard
from mitigata.store import Store


def scope(**changes):
    return ScopeManifest.model_validate(
        {
            "name": "Owned external-profile fixture",
            "authorized": True,
            "authorization_reference": "team-owned test only",
            "mode": "DISCOVERY_ONLY",
            "execution_profile": "native_guarded",
            "addresses": ["127.0.0.1/32"],
            "ports": [8080],
            "permitted_checks": ["web.credential_literal"],
            **changes,
        }
    )


def test_private_network_whole_range_is_compact_and_bounded(tmp_path, monkeypatch):
    manifest = scope(
        addresses=["192.168.56.0/24"], ports=[], port_ranges=["1-65535"], budgets=Budgets(queue_window=32)
    )
    preview = plan(manifest)
    assert preview["selected_hosts"] == 254
    assert preview["target_pairs"] == 254 * 65535
    assert preview["target_list_truncated"]
    assert not preview["full_port_inventory_fits_request_budget"]

    def forbidden(*a, **kw):
        raise AssertionError("Planning must not open a socket")

    monkeypatch.setattr(socket, "socket", forbidden)
    engine = Engine(tmp_path, manifest)
    assert len(engine.store.tasks(engine.run_id)) == 32
    frontier = engine.store.get(engine.run_id, "frontier", "tcp")["data"]
    assert frontier["next_index"] == 32 and frontier["total_pairs"] == 254 * 65535
    engine.store.close()


def test_port_round_robin_reaches_each_host_before_deeper_ports():
    guard = ScopeGuard(scope(addresses=["192.168.56.0/24"], ports=[80, 443]))
    assert guard.target_at(0) == ("192.168.56.1", 80)
    assert guard.target_at(253) == ("192.168.56.254", 80)
    assert guard.target_at(254) == ("192.168.56.1", 443)


def test_confirmed_host_is_prioritized_without_widening_scope():
    guard = ScopeGuard(
        scope(addresses=["192.168.56.0/24"], ports=[80, 443], priority_addresses=["192.168.56.10"])
    )
    assert guard.target_at(0) == ("192.168.56.10", 80)
    assert guard.target_at(254) == ("192.168.56.10", 443)
    assert guard.target_count == 508
    with pytest.raises(ValidationError):
        scope(addresses=["192.168.56.0/24"], priority_addresses=["198.51.100.10"])


def test_exclusions_apply_to_connections_names_and_generated_targets():
    manifest = scope(
        addresses=["192.168.56.0/24"],
        ports=[80, 443],
        excluded_addresses=["192.168.56.1/32", "192.168.56.128/25"],
        excluded_ports=[443],
    )
    guard = ScopeGuard(manifest)
    assert guard.target_count == 126
    assert not guard.address_allowed("192.168.56.1", 80)
    assert not guard.address_allowed("192.168.56.129", 80)
    assert not guard.address_allowed("192.168.56.2", 443)
    assert not guard.address_allowed("192.168.61.2", 80)
    with pytest.raises(ValidationError):
        scope(
            addresses=manifest.addresses,
            excluded_addresses=manifest.excluded_addresses,
            hostnames={"excluded.local": ["192.168.56.1"]},
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"addresses": ["192.168.56.13/24"]},
        {"addresses": ["8.8.8.8/32"]},
        {"addresses": ["169.254.169.254/32"]},
        {"addresses": ["::1/128"]},
        {"port_ranges": ["0-65535"]},
        {"port_ranges": ["80-1"]},
        {"permitted_checks": ["*"]},
        {"allow_credential_use": True},
        {"allowed_actions": ["http_get", "redis_info"]},
        {"excluded_addresses": ["192.168.61.1/32"]},
    ],
)
def test_external_validation_cannot_silently_widen_or_enable_actions(changes):
    with pytest.raises(ValidationError):
        scope(**changes)


def test_worker_guard_blocks_bypass_dns_udp_and_subprocess_without_transmission():
    install_worker_guard()
    denied = []
    token = worker_network_policy.set(WorkerNetworkPolicy(-1, denied.append))
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw, pytest.raises(ScopeDenied):
            raw.connect(("127.0.0.1", 1))
        with pytest.raises(ScopeDenied):
            socket.getaddrinfo("does-not-resolve.invalid", 80)
        with pytest.raises(ScopeDenied):
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        with pytest.raises(ScopeDenied):
            subprocess.run([sys.executable, "-c", "print('must not run')"], check=True)
    finally:
        worker_network_policy.reset(token)
    assert len(denied) == 4


@pytest.mark.parametrize("mode", ["DISCOVERY_ONLY", "AUTHORIZED_ASSESSMENT"])
def test_guarded_network_run_keeps_inventory_and_mode_semantics(tmp_path, http_server, mode):
    url, calls = http_server(
        {
            "/": (200, {}, '<a href="/config.txt">config</a><a href="/redirect">redirect</a>'),
            "/config.txt": (200, {}, "SECRET=controlled-private-value\n"),
            "/redirect": (302, {"Location": "http://192.0.2.99:9/denied"}, ""),
        }
    )
    manifest = scope(mode=mode, ports=[urlsplit(url).port], seed_urls=[url])
    engine = Engine(tmp_path, manifest)
    asyncio.run(engine.run())
    report = build_report(engine.store, engine.run_id)
    assert report["run"]["status"] == "completed"
    assert report["metrics"]["services_discovered"] == 1
    assert report["metrics"]["scope_pairs_untested"] == 0
    assert report["metrics"]["blocked_attempts"] >= 1
    assert all(c["authorization"] is None for c in calls)
    if mode == "DISCOVERY_ONLY":
        assert report["findings"] == []
        assert any(o["data"]["type"] == "potential_issue" for o in report["observations"])
    else:
        assert any(f["data"]["status"] == "confirmed" for f in report["findings"])
    engine.store.close()


def test_partial_run_keeps_untested_scope_visible(tmp_path, http_server):
    url, _ = http_server({"/": (200, {}, "hello")})
    manifest = scope(ports=[urlsplit(url).port, 1, 2], budgets=Budgets(requests=1, queue_window=1))
    engine = Engine(tmp_path, manifest)
    asyncio.run(engine.run())
    report = build_report(engine.store, engine.run_id)
    assert report["run"]["status"] == "partial_budget"
    assert report["metrics"]["scope_pairs_planned"] == 3
    assert report["metrics"]["scope_pairs_untested"] >= 2
    assert (tmp_path / "reports" / engine.run_id / "report.html").exists()
    engine.store.close()


def test_cursor_and_queue_publish_atomically(tmp_path, monkeypatch):
    store = Store(tmp_path / "state.sqlite3")
    run = store.create_run({"name": "frontier"}, 30)
    guard = ScopeGuard(scope(addresses=["192.168.56.0/24"], ports=[80]))
    original = store._enqueue
    count = 0

    def broken(*a, **kw):
        nonlocal count
        count += 1
        if count == 2:
            raise RuntimeError("simulated crash")
        return original(*a, **kw)

    monkeypatch.setattr(store, "_enqueue", broken)
    with pytest.raises(RuntimeError):
        store.refill_discovery(run, guard, 4)
    assert not store.tasks(run)
    assert store.get(run, "frontier", "tcp") is None
    monkeypatch.setattr(store, "_enqueue", original)
    store.refill_discovery(run, guard, 4)
    assert len(store.tasks(run)) == 4
    assert store.get(run, "frontier", "tcp")["data"]["next_index"] == 4
    store.close()


def test_firewall_blueprint_matches_exclusions_and_denies_other_planes():
    manifest = scope(
        execution_profile="linux_confined",
        addresses=["192.168.56.0/30"],
        ports=[],
        port_ranges=["1-65535"],
        excluded_addresses=["192.168.56.1/32"],
    )
    rules = firewall_rules(manifest)
    assert ":OUTPUT DROP" in rules and ":FORWARD DROP" in rules
    assert "-d 192.168.56.2/32" in rules
    assert "-d 192.168.56.1/32" not in rules
    assert "--dports 1:65535" in rules
    assert "-p udp" not in rules
    assert all(sum(2 if ":" in p else 1 for p in g.split(",")) <= 15 for g in port_groups(range(1, 100, 2)))


def test_contained_profile_cannot_run_without_privileged_receipt(tmp_path):
    with pytest.raises(ValueError):
        Engine(tmp_path, scope(execution_profile="linux_confined"))


def test_binary_role_has_no_broker_network_capability(tmp_path, http_server):
    from mitigata.security import WorkerIdentity, worker_identity

    url, calls = http_server({"/": (200, {}, "must not be reached")})
    engine = Engine(tmp_path, scope(ports=[urlsplit(url).port]))
    engine.store.enqueue(engine.run_id, role="Binary", kind="analyze", target="owned-artifact")
    task = engine.store.claim(engine.run_id, "Binary", engine.owner)
    token = worker_identity.set(WorkerIdentity("Binary", task["id"], engine.owner, task["fence"]))
    try:
        with pytest.raises(ScopeDenied):
            asyncio.run(engine.broker.http(url))
    finally:
        worker_identity.reset(token)
    assert calls == []
    assert engine.store.records(engine.run_id, "audit")[-1]["data"]["action"] == "role_policy"
    engine.store.close()


def test_packaged_network_templates_require_authorization_and_disable_credentials():
    from pathlib import Path

    import yaml
    from pydantic import ValidationError

    root = Path(__file__).parent.parent
    for name in ("network.discovery.yaml", "network.assessment.yaml", "network.confined.yaml"):
        path = root / "examples" / name
        with pytest.raises(ValidationError):
            load_manifest(path)
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        value.update(enabled=True, authorized=True, authorization_reference="pytest-owned configuration")
        manifest = ScopeManifest.model_validate(value)
        assert manifest.addresses == ["192.168.56.10/32"]
        assert not manifest.allow_credential_use
        assert manifest.budgets.max_auth_attempts == 0
        assert manifest.selected_ports() == (80, 443, 8080)

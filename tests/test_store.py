from __future__ import annotations

import pytest

from mitigata.evidence import EvidenceStore
from mitigata.security import WorkerIdentity, worker_identity
from mitigata.store import LeaseLost, Store


def test_atomic_claim_and_stale_worker_fencing(tmp_path):
    store = Store(tmp_path / "state.sqlite3")
    run = store.create_run({"name": "test"}, 30)
    store.enqueue(run, role="Recon", kind="scan", target="127.0.0.1:1")
    first = store.claim(run, "Recon", "first", lease_seconds=-1)
    assert store.claim(run, "Recon", "second") is None
    store.recover(run)
    second = store.claim(run, "Recon", "second")
    assert second["fence"] > first["fence"]
    token = worker_identity.set(WorkerIdentity("Recon", first["id"], "first", first["fence"]))
    try:
        with pytest.raises(LeaseLost):
            store.put(run, "service", "stale", {})
    finally:
        worker_identity.reset(token)
    assert store.records(run, "service") == []
    store.close()


def test_page_dedup_ignores_lineage_but_reopens_for_new_session(tmp_path):
    store = Store(tmp_path / "state.sqlite3")
    run = store.create_run({"name": "test"}, 30)
    first = store.enqueue(run, role="Web", kind="page", target="http://127.0.0.1/", payload={"depth": 1})
    duplicate = store.enqueue(
        run,
        role="Web",
        kind="page",
        target="http://127.0.0.1/",
        payload={"depth": 2, "existing_evidence": "different"},
    )
    new_role = store.enqueue(
        run,
        role="Web",
        kind="page",
        target="http://127.0.0.1/",
        payload={"session_ref": "role-2"},
        session="role-2",
    )
    assert first == duplicate
    assert new_role != first
    store.close()


def test_fact_and_downstream_work_roll_back_together(tmp_path):
    store = Store(tmp_path / "state.sqlite3")
    run = store.create_run({"name": "test"}, 30)
    with pytest.raises(TypeError):
        store.publish(run, "service", "test", {}, tasks=[{"not_a_valid_argument": True}])
    assert not store.records(run, "service")
    assert not store.tasks(run)
    store.close()


def test_only_falsifier_can_confirm_and_evidence_must_exist(tmp_path):
    store = Store(tmp_path / "state.sqlite3")
    run = store.create_run({"name": "test"}, 30)
    evidence = EvidenceStore(store, tmp_path / "evidence").capture(run, b"proof", kind="test", metadata={})
    with pytest.raises(PermissionError):
        store.put(run, "finding", "bad", {"status": "confirmed"}, [evidence], "Web")
    with pytest.raises(ValueError, match="Unknown evidence"):
        store.put(run, "finding", "unknown", {"status": "candidate"}, ["not-an-evidence-record"], "Web")
    store.close()


def test_evidence_tamper_is_detected_and_public_preview_redacts(tmp_path):
    store = Store(tmp_path / "state.sqlite3")
    run = store.create_run({"name": "test"}, 30)
    evidence = EvidenceStore(store, tmp_path / "evidence")
    ref = evidence.capture(
        run,
        b"PASSWORD=very-secret-value\nFLAG{private_value}\nAuthorization: Bearer confidential-token",
        kind="test",
        metadata={},
    )
    assert "very-secret-value" not in evidence.view(run, ref)["preview"]
    assert "FLAG{private_value}" not in evidence.view(run, ref)["preview"]
    assert "confidential-token" not in evidence.view(run, ref)["preview"]
    row = store.by_id(run, ref)
    (tmp_path / "evidence" / run / row["data"]["sha256"]).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="integrity"):
        evidence.read(run, ref)
    store.close()


def test_secret_permissions(tmp_path):
    store = Store(tmp_path / "state.sqlite3")
    run = store.create_run({"name": "test"}, 30)
    secret = store.secret(run, {"password": "a-private-value"})
    with pytest.raises(PermissionError):
        store.reveal(run, secret, "Reporter")
    assert store.reveal(run, secret, "Web")["password"] == "a-private-value"
    store.close()


def test_same_bytes_keep_distinct_immutable_observation_metadata(tmp_path):
    store = Store(tmp_path / "state.sqlite3")
    run = store.create_run({"name": "test"}, 30)
    evidence = EvidenceStore(store, tmp_path / "evidence")
    first = evidence.capture(run, b"", kind="tcp", metadata={"port": 8001})
    second = evidence.capture(run, b"", kind="tcp", metadata={"port": 8002})
    assert first != second
    assert store.by_id(run, first)["data"]["metadata"]["port"] == 8001
    assert store.by_id(run, first)["data"]["sha256"] == store.by_id(run, second)["data"]["sha256"]
    with pytest.raises(ValueError, match="immutable"):
        row = store.by_id(run, first)
        store.put(run, "evidence", row["identity"], {"sha256": "changed"})
    store.close()

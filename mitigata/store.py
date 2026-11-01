from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from .security import redact, worker_identity

PHASES = {
    "Recon": "Intelligence Gathering",
    "Web": "Vulnerability Analysis",
    "Binary": "Vulnerability Analysis",
    "Correlator": "Threat Modeling",
    "Falsifier": "Vulnerability Analysis",
    "Code": "Reporting",
    "Reporter": "Reporting",
    "Sentinel": "Pre-engagement Interactions",
    "Arbiter": "Pre-engagement Interactions",
}


def uid() -> str:
    return uuid.uuid4().hex


def encoded(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class LeaseLost(RuntimeError):
    pass


class Store:
    """Trusted application write gateway. SQLite is not a sandbox for hostile Python code."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            PRAGMA busy_timeout=5000;
            CREATE TABLE IF NOT EXISTS runs(
              id TEXT PRIMARY KEY, status TEXT NOT NULL, manifest TEXT NOT NULL,
              started REAL NOT NULL, ended REAL, deadline REAL NOT NULL, reason TEXT,
              cancel_requested INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS records(
              id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), kind TEXT NOT NULL,
              identity TEXT NOT NULL, data TEXT NOT NULL, evidence TEXT NOT NULL,
              producer TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1, updated REAL NOT NULL,
              UNIQUE(run_id,kind,identity));
            CREATE TABLE IF NOT EXISTS tasks(
              id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), identity TEXT NOT NULL,
              role TEXT NOT NULL, kind TEXT NOT NULL, target TEXT NOT NULL, payload TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'queued', owner TEXT, lease_until REAL,
              fence INTEGER NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
              error TEXT, created REAL NOT NULL, UNIQUE(run_id,identity));
            CREATE TABLE IF NOT EXISTS events(
              seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL REFERENCES runs(id),
              role TEXT NOT NULL, kind TEXT NOT NULL, phase TEXT NOT NULL, data TEXT NOT NULL,
              created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS secrets(
              id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(id), value TEXT NOT NULL,
              roles TEXT NOT NULL, created REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS task_queue ON tasks(run_id,status,role,created);
            CREATE INDEX IF NOT EXISTS record_kind ON records(run_id,kind);
            CREATE INDEX IF NOT EXISTS event_run ON events(run_id,seq);
        """)
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)

    def close(self):
        self.db.close()

    def _check_lease(self):
        identity = worker_identity.get()
        if identity is None:
            return
        row = self.db.execute("SELECT * FROM tasks WHERE id=?", (identity.task_id,)).fetchone()
        if (
            not row
            or row["status"] != "running"
            or row["owner"] != identity.owner
            or row["fence"] != identity.fence
            or row["lease_until"] < time.time()
        ):
            raise LeaseLost("Stale or expired worker cannot commit")

    @contextlib.contextmanager
    def transaction(self, *, fenced=True):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                if fenced:
                    self._check_lease()
                yield
                self.db.execute("COMMIT")
            except BaseException:
                self.db.execute("ROLLBACK")
                raise

    def _event(self, run_id, role, kind, data, phase=None):
        self.db.execute(
            "INSERT INTO events(run_id,role,kind,phase,data,created) VALUES(?,?,?,?,?,?)",
            (run_id, role, kind, phase or PHASES[role], encoded(redact(data)), time.time()),
        )

    def event(self, run_id, role, kind, data, phase=None):
        with self.transaction():
            self._event(run_id, role, kind, data, phase)

    def create_run(self, manifest: dict, seconds: float) -> str:
        run_id = uid()
        now = time.time()
        with self.transaction():
            self.db.execute(
                "INSERT INTO runs(id,status,manifest,started,deadline) VALUES(?,?,?,?,?)",
                (run_id, "running", encoded(manifest), now, now + seconds),
            )
            self._event(run_id, "Arbiter", "run_started", {"name": manifest["name"]})
        return run_id

    def run(self, run_id) -> dict:
        row = self.db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not row:
            raise KeyError("Unknown run")
        value = dict(row)
        value["manifest"] = json.loads(value["manifest"])
        return value

    def runs(self):
        return [self.run(r["id"]) for r in self.db.execute("SELECT id FROM runs ORDER BY started DESC")]

    def terminal(self, run_id, status, reason):
        if status not in {"completed", "partial_budget", "cancelled", "failed"}:
            raise ValueError("Invalid terminal status")
        with self.transaction(fenced=False):
            self.db.execute(
                "UPDATE runs SET status=?,ended=?,reason=? WHERE id=?", (status, time.time(), reason, run_id)
            )
            self.db.execute(
                "UPDATE tasks SET status='cancelled',fence=fence+1 WHERE run_id=? AND status IN ('queued','running')",
                (run_id,),
            )
            self._event(run_id, "Arbiter", "run_terminal", {"status": status, "reason": reason})

    def request_cancel(self, run_id):
        self.run(run_id)
        with self.transaction(fenced=False):
            self.db.execute("UPDATE runs SET cancel_requested=1 WHERE id=?", (run_id,))
            self._event(run_id, "Arbiter", "cancel_requested", {})

    def bundle_finalized(self, run_id):
        with self.transaction(fenced=False):
            self.db.execute("UPDATE runs SET ended=? WHERE id=?", (time.time(), run_id))
            self._event(run_id, "Reporter", "report_bundle_finalized", {})

    def _put(self, run_id, kind, identity, data, evidence, role):
        actor = worker_identity.get()
        if actor is not None and actor.role != role:
            raise PermissionError("Worker cannot impersonate another role")
        if (
            kind == "finding"
            and data.get("status") in {"confirmed", "rejected", "inconclusive"}
            and role != "Falsifier"
        ):
            raise PermissionError("Only Falsifier may decide findings")
        if kind == "flag" and role != "Code":
            raise PermissionError("Only Code may record flag state")
        if kind in {"observation", "finding", "verification", "graph_edge"} and not evidence:
            raise ValueError(f"{kind} requires evidence references")
        for ref in evidence:
            if not self.db.execute(
                "SELECT 1 FROM records WHERE id=? AND run_id=? AND kind='evidence'", (ref, run_id)
            ).fetchone():
                raise ValueError("Unknown evidence reference")
        row = self.db.execute(
            "SELECT * FROM records WHERE run_id=? AND kind=? AND identity=?", (run_id, kind, identity)
        ).fetchone()
        serialized = encoded(data)
        refs = encoded(sorted(set(evidence)))
        if row and row["data"] == serialized and row["evidence"] == refs:
            return row["id"], False
        if row and kind == "evidence":
            raise ValueError("Evidence observations are immutable")
        record_id = row["id"] if row else uid()
        if row:
            self.db.execute(
                "UPDATE records SET data=?,evidence=?,producer=?,revision=revision+1,updated=? WHERE id=?",
                (serialized, refs, role, time.time(), record_id),
            )
        else:
            self.db.execute(
                "INSERT INTO records VALUES(?,?,?,?,?,?,?,?,?)",
                (record_id, run_id, kind, identity, serialized, refs, role, 1, time.time()),
            )
        self._event(
            run_id,
            role,
            f"{kind}_updated" if row else f"{kind}_created",
            {"id": record_id, "identity": identity, "status": data.get("status")},
        )
        return record_id, True

    def put(self, run_id, kind, identity, data, evidence=(), role="Arbiter"):
        with self.transaction():
            return self._put(run_id, kind, identity, data, evidence, role)[0]

    def publish(self, run_id, kind, identity, data, evidence=(), role="Arbiter", tasks=()):
        """Fact and downstream tasks commit together: transactional outbox, idempotent consumers."""
        with self.transaction():
            record_id, _ = self._put(run_id, kind, identity, data, evidence, role)
            for task in tasks:
                self._enqueue(run_id, **task)
            return record_id

    def _enqueue(self, run_id, role, kind, target, payload=None, revision="", session="anonymous"):
        payload = payload or {}
        parameters = {
            k: v
            for k, v in payload.items()
            if k not in {"source_evidence", "depth", "parent_url", "trigger_evidence"}
        }
        if role == "Web" and kind == "page":
            parameters = {"session_ref": payload.get("session_ref")}
        key = hashlib.sha256(
            encoded([run_id, role, kind, "v1", target, parameters, revision, session]).encode()
        ).hexdigest()
        task_id = uid()
        self.db.execute(
            "INSERT OR IGNORE INTO tasks(id,run_id,identity,role,kind,target,payload,created) VALUES(?,?,?,?,?,?,?,?)",
            (task_id, run_id, key, role, kind, target, encoded(payload), time.time()),
        )
        if self.db.execute("SELECT changes()").fetchone()[0]:
            self._event(
                run_id,
                "Arbiter",
                "task_queued",
                {"task_id": task_id, "agent": role, "kind": kind, "target": target},
            )
        return self.db.execute(
            "SELECT id FROM tasks WHERE run_id=? AND identity=?", (run_id, key)
        ).fetchone()[0]

    def enqueue(self, run_id, **task):
        with self.transaction():
            return self._enqueue(run_id, **task)

    def refill_discovery(self, run_id, guard, window, batch_size=1):
        """Advance the persisted frontier and publish a bounded batch in one transaction."""
        with self.transaction():
            queued = self.db.execute(
                "SELECT count(*) FROM tasks WHERE run_id=? AND role='Recon' AND status IN ('queued','running')",
                (run_id,),
            ).fetchone()[0]
            row = self.db.execute(
                "SELECT * FROM records WHERE run_id=? AND kind='frontier' AND identity='tcp'", (run_id,)
            ).fetchone()
            next_index = json.loads(row["data"])["next_index"] if row else 0
            until = min(guard.target_count, next_index + max(0, window - queued) * batch_size)
            for index in range(next_index, until, batch_size):
                address, port = guard.target_at(index)
                self._enqueue(
                    run_id,
                    role="Recon",
                    kind="batch" if batch_size > 1 else "scan",
                    target=f"frontier:{index}" if batch_size > 1 else f"{address}:{port}",
                    payload={"start": index, "end": min(index + batch_size, until)}
                    if batch_size > 1
                    else {"address": address, "port": port},
                )
            if row is None or until != next_index:
                self._put(
                    run_id,
                    "frontier",
                    "tcp",
                    {
                        "next_index": until,
                        "total_pairs": guard.target_count,
                        "ordering": "priority-port round robin across every scoped address",
                        "queue_window": window,
                    },
                    [],
                    "Arbiter",
                )

    def count_records(self, run_id, kind):
        return self.db.execute(
            "SELECT count(*) FROM records WHERE run_id=? AND kind=?", (run_id, kind)
        ).fetchone()[0]

    def put_many(self, run_id, rows, role):
        with self.transaction():
            return [
                self._put(run_id, row["kind"], row["identity"], row["data"], row.get("evidence", []), role)[0]
                for row in rows
            ]

    def record_page(self, run_id, kind, offset=0, limit=50):
        rows = self.db.execute(
            "SELECT * FROM records WHERE run_id=? AND kind=? ORDER BY updated,id LIMIT ? OFFSET ?",
            (run_id, kind, min(200, max(1, limit)), max(0, offset)),
        ).fetchall()
        return [self._record(row) for row in rows]

    def recover(self, run_id):
        with self.transaction(fenced=False):
            self.db.execute(
                "UPDATE tasks SET status='queued',owner=NULL,lease_until=NULL,fence=fence+1,error='recovered expired lease' WHERE run_id=? AND status='running' AND lease_until<?",
                (run_id, time.time()),
            )

    def renew_leases(self, run_id, owner, seconds=30):
        now = time.time()
        with self.transaction(fenced=False):
            self.db.execute(
                "UPDATE tasks SET lease_until=? WHERE run_id=? AND owner=? AND status='running' AND lease_until>=?",
                (now + seconds, run_id, owner, now),
            )

    # Lower number = claimed first. Chain-advancing work (discovery, binary analysis,
    # protocol drive, verification, the forwarded-bypass crawl and targeted checks) is
    # prioritized over generic breadth crawl so a long attack chain completes early
    # instead of being starved behind a flood of page fetches. Ties fall back to arrival.
    _TASK_PRIORITY = """CASE kind
        WHEN 'analyze' THEN 0 WHEN 'protocol' THEN 0 WHEN 'capture' THEN 0
        WHEN 'verify' THEN 1 WHEN 'identify' THEN 1 WHEN 'scan' THEN 1 WHEN 'batch' THEN 1
        WHEN 'challenge' THEN 1 WHEN 'correlate' THEN 1
        WHEN 'forwarded_page' THEN 2 WHEN 'header_bypass' THEN 2 WHEN 'auth_probe' THEN 2
        WHEN 'default_cred' THEN 2 WHEN 'injection' THEN 2 WHEN 'reflection' THEN 2
        WHEN 'investigate' THEN 3 WHEN 'paths' THEN 4
        ELSE 5 END"""

    def claim(self, run_id, role, owner, lease_seconds=30) -> dict | None:
        with self.transaction(fenced=False):
            row = self.db.execute(
                "SELECT * FROM tasks WHERE run_id=? AND role=? AND status='queued' "
                f"ORDER BY {self._TASK_PRIORITY}, created LIMIT 1",
                (run_id, role),
            ).fetchone()
            if not row:
                return None
            self.db.execute(
                "UPDATE tasks SET status='running',owner=?,lease_until=?,fence=fence+1,attempts=attempts+1 WHERE id=?",
                (owner, time.time() + lease_seconds, row["id"]),
            )
            self._event(run_id, "Arbiter", "task_claimed", {"task_id": row["id"], "agent": role})
            return self.task(row["id"])

    def task(self, task_id):
        row = self.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        return result

    def finish(self, task, error=None):
        with self.transaction():
            self.db.execute(
                "UPDATE tasks SET status=?,error=?,lease_until=NULL WHERE id=?",
                ("failed" if error else "completed", error, task["id"]),
            )
            self._event(
                task["run_id"],
                task["role"],
                "task_failed" if error else "task_completed",
                {"task_id": task["id"], "error": error},
            )

    def tasks(self, run_id):
        return [
            self.task(row["id"])
            for row in self.db.execute("SELECT id FROM tasks WHERE run_id=? ORDER BY created", (run_id,))
        ]

    def records(self, run_id, kind=None):
        query = (
            "SELECT * FROM records WHERE run_id=?" + (" AND kind=?" if kind else "") + " ORDER BY updated,id"
        )
        rows = self.db.execute(query, (run_id, kind) if kind else (run_id,)).fetchall()
        return [self._record(row) for row in rows]

    @staticmethod
    def _record(row):
        if not row:
            return None
        value = dict(row)
        value["data"] = json.loads(value["data"])
        value["evidence"] = json.loads(value["evidence"])
        return value

    def get(self, run_id, kind, identity):
        return self._record(
            self.db.execute(
                "SELECT * FROM records WHERE run_id=? AND kind=? AND identity=?", (run_id, kind, identity)
            ).fetchone()
        )

    def by_id(self, run_id, record_id):
        return self._record(
            self.db.execute("SELECT * FROM records WHERE run_id=? AND id=?", (run_id, record_id)).fetchone()
        )

    def events(self, run_id, after=0, limit=1000):
        rows = self.db.execute(
            "SELECT * FROM events WHERE run_id=? AND seq>? ORDER BY seq LIMIT ?",
            (run_id, after, min(limit, 5000)),
        ).fetchall()
        return [{**dict(r), "data": json.loads(r["data"])} for r in rows]

    def secret(self, run_id, value: dict, roles=("Web", "Falsifier")):
        secret_id = hashlib.sha256((run_id + encoded(value)).encode()).hexdigest()
        with self.transaction():
            self.db.execute(
                "INSERT OR IGNORE INTO secrets VALUES(?,?,?,?,?)",
                (secret_id, run_id, encoded(value), encoded(roles), time.time()),
            )
        return secret_id

    def reveal(self, run_id, secret_id, role):
        actor = worker_identity.get()
        if actor and actor.role != role:
            raise PermissionError("Secret caller mismatch")
        row = self.db.execute("SELECT * FROM secrets WHERE id=? AND run_id=?", (secret_id, run_id)).fetchone()
        if not row or role not in json.loads(row["roles"]):
            raise PermissionError("Secret access denied")
        return json.loads(row["value"])

    def public(self, run_id, value):
        secrets = []
        for row in self.db.execute("SELECT value FROM secrets WHERE run_id=?", (run_id,)):
            item = json.loads(row["value"])
            secrets.extend(
                str(v) for k, v in item.items() if k in {"password", "exact_value", "token", "cookie"}
            )
        return redact(value, secrets)

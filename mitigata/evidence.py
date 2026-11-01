from __future__ import annotations

import hashlib
import os
import time
import uuid
from pathlib import Path

from .security import worker_identity
from .store import Store


class EvidenceStore:
    def __init__(self, store: Store, root: Path):
        self.store = store
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)

    def capture(self, run_id, body: bytes, *, kind: str, metadata: dict, role=None) -> str:
        digest = hashlib.sha256(body).hexdigest()
        directory = self.root / run_id
        directory.mkdir(exist_ok=True)
        os.chmod(directory, 0o700)
        path = directory / digest
        if not path.exists():
            with path.open("xb") as stream:
                stream.write(body)
            os.chmod(path, 0o600)
        actor = worker_identity.get()
        return self.store.put(
            run_id,
            "evidence",
            uuid.uuid4().hex,
            {
                "sha256": digest,
                "bytes": len(body),
                "kind": kind,
                "metadata": metadata,
                "observed_at": time.time(),
            },
            role=role or (actor.role if actor else "Arbiter"),
        )

    def read(self, run_id, evidence_id) -> bytes:
        row = self.store.by_id(run_id, evidence_id)
        if not row or row["kind"] != "evidence":
            raise KeyError("Unknown evidence")
        path = self.root / run_id / row["data"]["sha256"]
        body = path.read_bytes()
        if hashlib.sha256(body).hexdigest() != row["data"]["sha256"]:
            raise ValueError("Evidence integrity check failed")
        return body

    def view(self, run_id, evidence_id):
        row = self.store.by_id(run_id, evidence_id)
        body = self.read(run_id, evidence_id)
        return self.store.public(
            run_id,
            {
                **row,
                "preview": body[:8192].decode("utf-8", errors="replace"),
                "preview_truncated": len(body) > 8192,
            },
        )

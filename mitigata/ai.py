"""Claude client tools with a durable, shared, pre-reserved dollar budget.

Provider traffic is control-plane traffic. No provider URL is accepted from target data.
"""

from __future__ import annotations

import asyncio
import http.client
import json
import os
import ssl
import time
import uuid
from decimal import Decimal
from pathlib import Path

from .runtime_guard import worker_network_policy

PRICES = {  # USD per million tokens; checked against first-party pricing 2026-11-01.
    "claude-sonnet-5-5": (2, 10),
    "claude-sonnet-4-6": (3, 15),
    "claude-haiku-5-5": (0.1, 0.5),
}


class AIUnavailable(RuntimeError):
    pass


class AIBudgetExceeded(RuntimeError):
    pass


def load_local_environment(path=Path(".env.local")):
    path = Path(path)
    if not path.is_file():
        return
    if path.stat().st_size > 16384:
        raise ValueError("Local environment file exceeds 16 KiB")
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        if name.strip() in {
            "ANTHROPIC_API_KEY",
            "MITIGATA_CHROME_PATH",
            "MITIGATA_GHIDRA_HOME",
            "MITIGATA_AI_GATEWAY_TOKEN",
        }:
            os.environ.setdefault(name.strip(), value.strip().strip("\"'"))


def api_key_available():
    value = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    return bool(value and value not in {"PASTE_YOUR_CLAUDE_API_KEY_HERE", "REPLACE_ME"})


def provider_available(settings):
    return (
        bool(os.environ.get("MITIGATA_AI_GATEWAY_TOKEN")) if settings.gateway_address else api_key_available()
    )


class BudgetLedger:
    def __init__(self, store, run_id, settings):
        self.store, self.run_id, self.settings = store, run_id, settings
        with store.transaction():
            store.db.execute("""CREATE TABLE IF NOT EXISTS ai_accounts(
                run_id TEXT PRIMARY KEY, limit_nanos INTEGER NOT NULL, spent_nanos INTEGER NOT NULL DEFAULT 0,
                reserved_nanos INTEGER NOT NULL DEFAULT 0, calls INTEGER NOT NULL DEFAULT 0)""")
            store.db.execute("""CREATE TABLE IF NOT EXISTS ai_reservations(
                id TEXT PRIMARY KEY, run_id TEXT NOT NULL, reserved_nanos INTEGER NOT NULL,
                status TEXT NOT NULL, usage TEXT, role TEXT NOT NULL DEFAULT 'Unattributed')""")
            if "role" not in {r[1] for r in store.db.execute("PRAGMA table_info(ai_reservations)")}:
                store.db.execute(
                    "ALTER TABLE ai_reservations ADD COLUMN role TEXT NOT NULL DEFAULT 'Unattributed'"
                )
            store.db.execute(
                "INSERT OR IGNORE INTO ai_accounts(run_id,limit_nanos) VALUES(?,?)",
                (run_id, int(Decimal(str(settings.budget_usd)) * 1_000_000_000)),
            )

    def reserve(self, input_bound, output_bound, role="Unattributed"):
        a, b = PRICES[self.settings.model]
        if self.settings.model == "claude-haiku-5-5" and input_bound > 100000:
            a, b = 0.5, 2.5
        amount = int(Decimal(str(a)) * 1000 * input_bound + Decimal(str(b)) * 1000 * output_bound)
        key = uuid.uuid4().hex
        with self.store.transaction():
            if role in {"Web", "Binary", "Recon", "Correlator"}:
                fractions = {"Web": 0.5, "Binary": 0.25, "Recon": 0.125, "Correlator": 0.125}
                calls = self.store.db.execute(
                    "SELECT count(*) FROM ai_reservations WHERE run_id=? AND role=?", (self.run_id, role)
                ).fetchone()[0]
                if calls >= max(1, int(self.settings.max_calls * fractions[role])):
                    raise AIBudgetExceeded(
                        "Specialist call allocation exhausted; other surfaces retain their allocation"
                    )
            row = self.store.db.execute("SELECT * FROM ai_accounts WHERE run_id=?", (self.run_id,)).fetchone()
            if (
                row["calls"] >= self.settings.max_calls
                or row["spent_nanos"] + row["reserved_nanos"] + amount > row["limit_nanos"]
            ):
                raise AIBudgetExceeded(
                    "Shared Claude budget/call limit reached; deterministic work continues"
                )
            self.store.db.execute(
                "UPDATE ai_accounts SET reserved_nanos=reserved_nanos+?,calls=calls+1 WHERE run_id=?",
                (amount, self.run_id),
            )
            self.store.db.execute(
                "INSERT INTO ai_reservations(id,run_id,reserved_nanos,status,usage,role) VALUES(?,?,?,?,NULL,?)",
                (key, self.run_id, amount, "reserved", role),
            )
        return key

    def settle(self, key, usage):
        # No caching is requested. Count any returned cache categories conservatively at base input price.
        input_tokens = sum(
            int(usage.get(k, 0))
            for k in ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
        )
        output_tokens = int(usage.get("output_tokens", 0))
        if (
            input_tokens < 0
            or output_tokens < 0
            or "input_tokens" not in usage
            or "output_tokens" not in usage
        ):
            raise AIUnavailable("Provider usage missing/invalid; reservation retained")
        a, b = PRICES[self.settings.model]
        if self.settings.model == "claude-haiku-5-5" and input_tokens > 100000:
            a, b = 0.5, 2.5
        actual = int(Decimal(str(a)) * 1000 * input_tokens + Decimal(str(b)) * 1000 * output_tokens)
        with self.store.transaction():
            row = self.store.db.execute(
                "SELECT * FROM ai_reservations WHERE id=? AND run_id=?", (key, self.run_id)
            ).fetchone()
            if not row or row["status"] != "reserved":
                raise ValueError("AI reservation already settled or absent")
            if actual > row["reserved_nanos"]:
                raise AIUnavailable(
                    "Usage exceeded reserved upper bound; reservation retained and provider disabled"
                )
            self.store.db.execute(
                "UPDATE ai_accounts SET spent_nanos=spent_nanos+?,reserved_nanos=reserved_nanos-? WHERE run_id=?",
                (actual, row["reserved_nanos"], self.run_id),
            )
            self.store.db.execute(
                "UPDATE ai_reservations SET status='settled',usage=? WHERE id=?", (json.dumps(usage), key)
            )
        return actual / 1_000_000_000

    def summary(self):
        row = dict(
            self.store.db.execute("SELECT * FROM ai_accounts WHERE run_id=?", (self.run_id,)).fetchone()
        )
        return {
            "limit_usd": row["limit_nanos"] / 1e9,
            "spent_usd": row["spent_nanos"] / 1e9,
            "reserved_usd": row["reserved_nanos"] / 1e9,
            "calls": row["calls"],
            "model": self.settings.model,
        }


class ClaudeClient:
    def __init__(self, store, run_id, settings, *, transport=None, evidence=None):
        self.settings, self.store, self.run_id = settings, store, run_id
        self.transport = transport
        self.evidence = evidence
        self.ledger = BudgetLedger(store, run_id, settings)
        self.disabled_reason = None

    def _post(self, payload):
        if not provider_available(self.settings):
            raise AIUnavailable("ANTHROPIC_API_KEY is missing; fill .env.local")
        token = worker_network_policy.set(None)
        conn = None
        try:
            gateway = self.settings.gateway_address
            conn = (
                http.client.HTTPConnection(gateway, self.settings.gateway_port, timeout=self.settings.timeout)
                if gateway
                else http.client.HTTPSConnection(
                    "api.anthropic.com", timeout=self.settings.timeout, context=ssl.create_default_context()
                )
            )
            headers = {"anthropic-version": "2023-06-01", "Content-Type": "application/json"}
            if gateway:
                headers["Authorization"] = "Bearer " + os.environ["MITIGATA_AI_GATEWAY_TOKEN"]
            else:
                headers["x-api-key"] = os.environ["ANTHROPIC_API_KEY"]
            conn.request(
                "POST",
                "/v1/messages",
                json.dumps(payload).encode(),
                headers=headers,
            )
            response = conn.getresponse()
            body = response.read(2_000_001)
            if len(body) > 2_000_000:
                raise AIUnavailable("Provider response exceeded limit")
            if response.status != 200:
                raise AIUnavailable(
                    f"Claude HTTP {response.status}; check key, credits, model access or rate limits"
                )
            return json.loads(body)
        finally:
            if conn:
                conn.close()
            worker_network_policy.reset(token)

    async def complete(self, role, system, messages, tools):
        if self.disabled_reason:
            raise AIUnavailable(self.disabled_reason)
        payload = {
            "model": self.settings.model,
            "max_tokens": self.settings.max_output_tokens,
            "system": system,
            "messages": messages,
            "tools": tools,
            "tool_choice": {"type": "auto"},
        }
        serialized = json.dumps(payload, ensure_ascii=False).encode()
        if len(serialized) > self.settings.max_context_bytes:
            raise AIBudgetExceeded("Case context limit reached")
        # UTF-8 byte count + structural allowance is a deliberately conservative token upper bound.
        reservation = self.ledger.reserve(len(serialized) + 2048, self.settings.max_output_tokens, role)
        refs = []
        if self.evidence:
            refs.append(
                self.evidence.capture(
                    self.run_id,
                    serialized,
                    kind="ai_request",
                    metadata={"model": self.settings.model, "role": role, "reservation": reservation},
                )
            )
        started = time.monotonic()
        try:
            reply = await asyncio.wait_for(
                asyncio.to_thread(self.transport or self._post, payload), self.settings.timeout + 1
            )
            if not isinstance(reply, dict) or not isinstance(reply.get("content"), list):
                raise AIUnavailable("Malformed Claude response")
            cost = self.ledger.settle(reservation, reply.get("usage", {}))
            if self.evidence:
                safe_reply = {
                    "content": [
                        b
                        for b in reply["content"]
                        if isinstance(b, dict) and b.get("type") in {"text", "tool_use"}
                    ],
                    "usage": reply["usage"],
                }
                refs.append(
                    self.evidence.capture(
                        self.run_id,
                        json.dumps(safe_reply).encode(),
                        kind="ai_response",
                        metadata={"model": self.settings.model, "role": role, "reservation": reservation},
                    )
                )
            self.store.put(
                self.run_id,
                "ai_call",
                reservation,
                {
                    "role": role,
                    "model": self.settings.model,
                    "status": "completed",
                    "usage": reply["usage"],
                    "cost_usd": cost,
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                },
                evidence=refs,
                role=role,
            )
            return reply
        except (TimeoutError, OSError, ValueError, AIUnavailable) as exc:
            self.disabled_reason = str(exc)
            self.store.put(
                self.run_id,
                "ai_call",
                reservation,
                {
                    "role": role,
                    "status": "unavailable",
                    "reason": str(exc)[:300],
                    "charge": "reservation_retained_for_uncertain_provider_outcome",
                },
                role=role,
            )
            raise AIUnavailable(str(exc)) from exc


def budget_snapshot(store, run_id):
    if not store.db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='ai_accounts'"
    ).fetchone():
        return {"spent_usd": 0, "reserved_usd": 0, "calls": 0, "limit_usd": 0}
    row = store.db.execute("SELECT * FROM ai_accounts WHERE run_id=?", (run_id,)).fetchone()
    if row is None:
        return {"spent_usd": 0, "reserved_usd": 0, "calls": 0, "limit_usd": 0}
    return {
        "spent_usd": row["spent_nanos"] / 1e9,
        "reserved_usd": row["reserved_nanos"] / 1e9,
        "calls": row["calls"],
        "limit_usd": row["limit_nanos"] / 1e9,
    }

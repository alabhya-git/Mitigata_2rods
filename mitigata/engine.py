from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .agents import AGENTS, Context
from .checks import CheckRegistry
from .config import ScopeManifest
from .evidence import EvidenceStore
from .runtime_guard import WorkerNetworkPolicy, install_worker_guard, worker_network_policy
from .scope import ScopeDenied, ScopeGuard
from .security import WorkerIdentity, worker_identity
from .store import LeaseLost, Store, encoded
from .transport import Broker, BudgetExceeded


class Engine:
    """Fair deterministic arbiter; all target interpretation belongs to specialist workers."""

    def __init__(
        self,
        root: Path,
        manifest: ScopeManifest,
        *,
        checks: CheckRegistry | None = None,
        run_id: str | None = None,
        sharing=True,
        ai_transport=None,
    ):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.manifest = manifest = manifest.validated_snapshot()
        from .ai import load_local_environment, provider_available

        load_local_environment()
        if manifest.ai.required and not (
            manifest.ai.enabled and (ai_transport or provider_available(manifest.ai))
        ):
            raise ValueError(
                "Claude is required for this profile. Fill ANTHROPIC_API_KEY in .env.local before running."
            )
        self.enforcement_receipt = None
        if manifest.mode != "LOCAL_LAB":
            install_worker_guard()
            if manifest.execution_profile == "linux_confined":
                from .confinement import verify_receipt

                self.enforcement_receipt = verify_receipt(manifest)
        self.store = Store(self.root / "state.sqlite3")
        self.evidence = EvidenceStore(self.store, self.root / "evidence")
        self.checks = checks or CheckRegistry()
        guard = ScopeGuard(manifest)
        for seed in manifest.seed_urls + manifest.baseline_urls:
            guard.destination(seed)  # Validation is pure; invalid seeds fail before any target connection.
        self.run_id = run_id or self.store.create_run(manifest.public(), manifest.budgets.seconds)
        if run_id:
            run = self.store.run(run_id)
            if run["status"] != "running":
                raise ValueError("Only an interrupted running assessment may be resumed")
            if run["manifest"] != manifest.public():
                raise ValueError("Resume requires the identical frozen public manifest")
            self.store.recover(run_id)
        self.broker = Broker(manifest, self.store, self.evidence, self.run_id)
        self.context = Context(self.run_id, manifest, self.store, self.evidence, self.broker, self.checks)
        if manifest.ai.enabled and (ai_transport or provider_available(manifest.ai)):
            from .ai import ClaudeClient

            self.context.ai_client = ClaudeClient(
                self.store, self.run_id, manifest.ai, transport=ai_transport, evidence=self.evidence
            )
        self.agents = {cls.role: cls(self.context) for cls in AGENTS}
        self.context.web_consume = self.agents["Web"].consume
        self.owner = uuid.uuid4().hex
        self.sharing = sharing
        self.budget_exhausted = False
        self.internal_failure = False
        self.active: set[asyncio.Task] = set()
        self.roles = list(self.agents)
        self.next_role = 0
        self.next_heartbeat = time.monotonic() + 5
        if run_id is None:
            self._seed()
            if self.enforcement_receipt:
                self.store.put(
                    self.run_id,
                    "capability",
                    "kernel_egress_receipt",
                    self.enforcement_receipt,
                    role="Sentinel",
                )

    def _seed(self):
        self.store.refill_discovery(
            self.run_id,
            self.broker.guard,
            self.manifest.budgets.queue_window,
            self.manifest.discovery.batch_size if self.manifest.discovery.batched else 1,
        )
        for url in self.manifest.seed_urls:
            if (
                self.manifest.investigation.enabled
                or self.broker.guard.destination(url).request_target != "/"
            ):
                self.store.enqueue(self.run_id, role="Web", kind="page", target=url, payload={"depth": 0})
        for artifact in self.manifest.artifacts:
            self.store.enqueue(self.run_id, role="Binary", kind="analyze", target=artifact)
        self.store.put(
            self.run_id,
            "capability",
            "runtime",
            {
                "deterministic": self.context.ai_client is None,
                "llm_test_transport": bool(self.context.ai_client and self.context.ai_client.transport),
                "llm_enabled": self.context.ai_client is not None,
                "llm_requested": self.manifest.ai.enabled,
                "llm_model": self.manifest.ai.model if self.context.ai_client else None,
                "llm_budget_usd": self.manifest.ai.budget_usd if self.context.ai_client else 0,
                "external_assessment": self.manifest.mode != "LOCAL_LAB",
                "execution_profile": self.manifest.execution_profile,
                "worker_egress_guard": self.manifest.mode != "LOCAL_LAB",
                "kernel_egress_policy": self.manifest.execution_profile == "linux_confined",
                "live_external_tools": False,
                "independent_egress_observer": "unavailable",
                "formats": ["ELF", "PE", "printable strings", "obfuscated (XOR) embedded secrets"],
                "techniques": [
                    "forwarding-header access-control differential (opt-in)",
                    "artifact-recovered obfuscated credentials (opt-in)",
                    "reviewed text-protocol command discovery and resource request (opt-in)",
                    "hidden-surface hint-boosted content discovery",
                    "sensitive operational-document disclosure (opt-in)",
                ],
                "sharing_enabled": self.sharing,
                "limitations": [
                    "Only explicit scope and registered built-in transport actions are supported",
                    "No generic exploitation or pivot runtime",
                    "No UDP enumeration",
                    "No LLM injection-resistance claim",
                    "No independent packet-capture result",
                    "Protocol scripting sends only service-advertised commands with artifact-recovered secrets",
                ],
            },
        )

    def _briefing(self, task):
        role = task["role"]
        relevant = []
        for key in ("finding_identity", "service_id", "binary_finding", "artifact_evidence"):
            if key in task["payload"]:
                relevant.append({"reference_type": key, "reference": task["payload"][key]})
        briefing = {
            "task": {"id": task["id"], "kind": task["kind"], "target": task["target"]},
            "scope_slice": {
                "mode": self.manifest.mode,
                "target": task["target"],
                "credential_use": self.manifest.allow_credential_use,
            },
            "tool_schemas": list(self.agents[role].tools),
            "relevant_facts": relevant,
            "context_type": "deterministic_structured",
            "untrusted_target_content": "evidence_refs_only",
        }
        serialized = encoded(briefing).encode()
        if len(serialized) > self.manifest.budgets.max_briefing_bytes:
            briefing["task"]["target_sha256"] = hashlib.sha256(task["target"].encode()).hexdigest()
            briefing["task"].pop("target")
            briefing["scope_slice"].pop("target")
            serialized = encoded(briefing).encode()
        if len(serialized) > self.manifest.budgets.max_briefing_bytes:
            raise ValueError("Briefing exceeds the hard byte budget")
        self.store.put(
            self.run_id,
            "briefing",
            task["id"],
            {**briefing, "bytes": len(serialized), "budget_bytes": self.manifest.budgets.max_briefing_bytes},
            role=role,
        )

    async def _worker(self, task):
        token = worker_identity.set(WorkerIdentity(task["role"], task["id"], self.owner, task["fence"]))
        network_token = worker_network_policy.set(
            WorkerNetworkPolicy(
                id(self.broker),
                lambda reason: self.broker.audit("blocked", action="worker_bypass", reason=reason),
            )
            if self.manifest.mode != "LOCAL_LAB"
            else None
        )
        try:
            self._briefing(task)
            if not self.sharing and task["role"] == "Correlator":
                self.store.event(self.run_id, task["role"], "sharing_disabled_ablation", {})
            else:
                await self.agents[task["role"]].execute(task)
            self.store.finish(task)
        except BudgetExceeded:
            self.budget_exhausted = True
            self.store.finish(task, "budget_exhausted")
        except ScopeDenied as exc:
            self.context.ledger(
                task["role"],
                task["role"].lower() + "." + task["kind"],
                task["target"],
                "blocked_scope",
                reason=str(exc),
            )
            self.store.event(
                self.run_id, task["role"], "policy_blocked", {"task_id": task["id"], "reason": str(exc)}
            )
            self.store.finish(task)
        except LeaseLost:
            # A newer fence owns the task; this worker must not write a final result.
            pass
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - worker boundary records failures and makes the run fail
            self.internal_failure = True
            self.store.finish(task, f"{type(exc).__name__}: {str(exc)[:300]}")
        finally:
            worker_network_policy.reset(network_token)
            worker_identity.reset(token)

    async def run(self):
        proxy = None
        if self.manifest.discovery.batched:
            asyncio.get_running_loop().set_default_executor(
                ThreadPoolExecutor(
                    max_workers=self.manifest.discovery.concurrency, thread_name_prefix="mitigata-io"
                )
            )
        status, reason = "completed", "no eligible work remains"
        try:
            if self.manifest.execution_profile == "linux_confined" and any(
                (self.manifest.tools.katana, self.manifest.tools.ffuf, self.manifest.tools.nuclei)
            ):
                from .tool_proxy import ToolProxy

                proxy = ToolProxy(self.context)
                await proxy.start()
            while True:
                run = self.store.run(self.run_id)
                if run["cancel_requested"]:
                    status, reason = "cancelled", "operator requested cancellation"
                    break
                if time.time() >= run["deadline"] or self.budget_exhausted:
                    status, reason = "partial_budget", "time or request budget exhausted"
                    break
                if time.monotonic() >= self.next_heartbeat:
                    self.store.renew_leases(self.run_id, self.owner)
                    self.next_heartbeat = time.monotonic() + 5
                self.store.recover(self.run_id)
                self.store.refill_discovery(
                    self.run_id,
                    self.broker.guard,
                    self.manifest.budgets.queue_window,
                    self.manifest.discovery.batch_size if self.manifest.discovery.batched else 1,
                )
                while len(self.active) < self.manifest.budgets.workers:
                    selected = None
                    for _ in self.roles:
                        role = self.roles[self.next_role]
                        self.next_role = (self.next_role + 1) % len(self.roles)
                        selected = self.store.claim(self.run_id, role, self.owner)
                        if selected:
                            break
                    if selected is None:
                        break
                    active = asyncio.create_task(self._worker(selected))
                    self.active.add(active)
                if not self.active:
                    break
                completed, _ = await asyncio.wait(
                    self.active, timeout=0.05, return_when=asyncio.FIRST_COMPLETED
                )
                for worker in completed:
                    self.active.discard(worker)
                    await worker
            if status == "completed" and self.internal_failure:
                status, reason = "failed", "one or more specialist tasks failed; inspect task errors"
        except asyncio.CancelledError:
            status, reason = "cancelled", "runtime cancellation"
        except Exception as exc:
            status, reason = "failed", f"arbiter failure: {type(exc).__name__}"
            raise
        finally:
            self.broker.cancel()
            if proxy:
                await proxy.close()
            for worker in self.active:
                worker.cancel()
            if self.active:
                await asyncio.gather(*self.active, return_exceptions=True)
            self.active.clear()
            self.store.terminal(self.run_id, status, reason)
            # Report generation is local and has a reserved finalization path even after budget expiry.
            self.store.enqueue(self.run_id, role="Reporter", kind="snapshot", target="terminal")
            report_task = self.store.claim(self.run_id, "Reporter", self.owner)
            if report_task:
                await self._worker(report_task)
            from .reporting import export_report, refresh_report_summary

            export_report(self.store, self.evidence, self.run_id, self.root / "reports" / self.run_id)
            self.store.bundle_finalized(self.run_id)
            refresh_report_summary(self.store, self.run_id, self.root / "reports" / self.run_id)
        return self.run_id

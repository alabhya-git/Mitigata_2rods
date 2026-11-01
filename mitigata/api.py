from __future__ import annotations

import asyncio
import hmac
import io
import ipaddress
import json
import secrets
import zipfile
from contextlib import asynccontextmanager
from importlib.resources import files
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, ConfigDict

from .checks import CheckRegistry
from .config import ScopeManifest
from .engine import Engine
from .evidence import EvidenceStore
from .lab import LocalLab
from .reporting import build_report, report_html
from .store import Store


class DemoRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    seed: int = 1
    layout: Literal["reference", "script", "header", "json"] = "reference"
    no_flag: bool = False
    fixed: bool = False


class QuickStart(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str


def adhoc_manifest(ip: str) -> ScopeManifest:
    """Build the full-host assessment manifest for an operator-typed IPv4 host.

    Sweeps the full well-known TCP range plus the common high service ports, then runs the
    chain checks with a deeper crawl. The request budget and rate are still hard-capped so a
    wide sweep stays polite (a TCP connect probe is cheap and does not flood application logs).
    Scope validation (private IPv4 only, explicit checks/actions) still applies, so a public
    address is refused.
    """
    address = str(ipaddress.ip_address(ip))
    return ScopeManifest.model_validate(
        {
            "name": f"Full-host assessment {address}",
            "mode": "AUTHORIZED_ASSESSMENT",
            "execution_profile": "native_guarded",
            "authorized": True,
            "authorization_reference": "Operator-initiated ad-hoc assessment via the local dashboard",
            "addresses": [f"{address}/32"],
            "ports": [
                1111, 3000, 5000, 5601, 6379, 7000, 8000, 8080, 8443, 8833, 8888, 9000,
                9200, 11211, 15672, 27017, 3306, 5432, 5984, 2375,
            ],
            "port_ranges": ["1-1024"],
            "priority_addresses": [address],
            "priority_ports": [80, 1111, 8833, 443, 8080],
            "seed_urls": [f"http://{address}/"],
            "permitted_checks": [
                "web.directory_listing", "web.credential_literal", "web.verbose_error",
                "web.embedded_credential_accepted", "binary.embedded_credential", "binary.missing_pie",
                "network.redis_unauthenticated_info", "web.git_metadata", "web.structured_secret",
                "web.default_credentials", "network.elasticsearch_unauthenticated",
                "web.forwarding_header_bypass", "binary.obfuscated_credential", "web.sensitive_document",
                "network.protocol_resource_capture",
            ],
            "allow_credential_use": True,
            "allowed_actions": [
                "http_get", "redis_info", "credential_validation", "session_authentication",
                "service_identification", "challenge_interaction", "default_credential_probe",
                "header_spoof_probe", "protocol_scripting",
            ],
            "budgets": {
                "seconds": 1200, "requests": 4500, "rate_per_second": 30, "workers": 8, "timeout": 10,
                "max_pages": 150, "max_depth": 5, "max_auth_attempts": 24, "connect_timeout": 3.0,
            },
            "investigation": {
                "enabled": True, "allow_partial_responses": True, "decode_compression": True,
                "allow_unverified_tls": True, "follow_same_ip_hostnames": True, "discover_artifacts": True,
                "max_artifacts": 10, "max_path_probes": 40, "max_hint_probes": 20, "max_cases": 10,
                "flag_patterns": [r"MITIGATA\{[A-Za-z0-9_]{3,64}\}"],
            },
            "ai": {"enabled": True, "required": False, "model": "claude-sonnet-5-5", "budget_usd": 1.0, "max_calls": 20},
            "tools": {"binary_tools": True},
        }
    )


def create_app(
    root: Path,
    token: str,
    *,
    start_demo=False,
    startup_scope: ScopeManifest | None = None,
    allow_adhoc=False,
):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    store = Store(root / "state.sqlite3")
    evidence = EvidenceStore(store, root / "evidence")
    engines = {}
    running = set()
    labs = {}

    async def launch(manifest, lab=None, adhoc=False):
        if manifest.mode != "LOCAL_LAB" and startup_scope is None and not (adhoc and allow_adhoc):
            raise ValueError(
                "This dashboard is the local demo profile. Start a native assessment dashboard with serve --manifest."
            )
        if manifest.mode != "LOCAL_LAB" and startup_scope and manifest.public() != startup_scope.public():
            raise ValueError("Network runs in this dashboard must use the frozen startup scope")
        engine = Engine(root, manifest)
        engines[engine.run_id] = engine
        if lab:
            labs[engine.run_id] = lab

        async def perform():
            try:
                # The scanner gets its own event loop; UI/report CPU work cannot delay its timers.
                scan = asyncio.create_task(asyncio.to_thread(lambda: asyncio.run(engine.run())))
                try:
                    await asyncio.shield(scan)
                except asyncio.CancelledError:
                    store.request_cancel(engine.run_id)
                    engine.broker.cancel()
                    await scan
                    raise
                if lab:
                    evaluation = await asyncio.to_thread(
                        lab.evaluate, build_report(engine.store, engine.run_id)
                    )
                    (root / "reports" / engine.run_id / "evaluation.json").write_text(
                        json.dumps(evaluation, indent=2), encoding="utf-8"
                    )
            finally:
                if lab:
                    await asyncio.to_thread(lab.close)
                    labs.pop(engine.run_id, None)
                engine.store.close()
                engines.pop(engine.run_id, None)

        task = asyncio.create_task(perform())
        running.add(task)
        task.add_done_callback(running.discard)
        return engine.run_id

    async def new_demo(settings):
        if len(running) >= 2:
            raise HTTPException(409, "At most two concurrent assessments")
        lab_root = root / "labs" / secrets.token_hex(8)
        lab = await asyncio.to_thread(
            LocalLab(lab_root, settings.seed, settings.layout, settings.no_flag, settings.fixed).start
        )
        try:
            return await launch(lab.manifest, lab)
        except BaseException:
            await asyncio.to_thread(lab.close)
            raise

    @asynccontextmanager
    async def lifespan(app):
        if start_demo:
            await new_demo(DemoRequest())
        if startup_scope:
            await launch(startup_scope)
        yield
        for engine in list(engines.values()):
            engine.broker.cancel()
        tasks = list(running)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for lab in list(labs.values()):
            await asyncio.to_thread(lab.close)
        store.close()

    app = FastAPI(
        title="Mitigata evidence engine",
        version="0.3.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @app.middleware("http")
    async def local_host_and_origin(request, call_next):
        authority = request.headers.get("host", "")
        try:
            hostname = urlsplit("http://" + authority).hostname
        except ValueError:
            hostname = None
        if hostname not in {"localhost", "127.0.0.1", "::1"}:
            return JSONResponse({"detail": "Unapproved Host"}, status_code=400)
        origin = request.headers.get("origin")
        if origin and urlsplit(origin).netloc != authority:
            return JSONResponse({"detail": "Cross-origin access denied"}, status_code=403)
        response = await call_next(request)
        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Cache-Control": "no-store",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            }
        )
        return response

    def authorize(request: Request):
        supplied = request.headers.get("authorization", "")
        if len(supplied) > 256 or not hmac.compare_digest(supplied, "Bearer " + token):
            raise HTTPException(401, "Operator bearer token required")

    def require_run(run_id):
        try:
            return store.run(run_id)
        except KeyError:
            raise HTTPException(404, "Unknown run") from None

    @app.get("/health")
    @app.get("/ready")
    async def health():
        return {
            "status": "ok",
            "version": "0.3.0",
            "external_assessment": "scoped" if startup_scope else "disabled",
        }

    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        return files("mitigata").joinpath("static/index.html").read_text(encoding="utf-8")

    @app.get("/static/{name}")
    async def static(name: str):
        if name not in {"app.js", "style.css"}:
            raise HTTPException(404)
        return Response(
            files("mitigata").joinpath("static/" + name).read_text(encoding="utf-8"),
            media_type="text/javascript" if name.endswith(".js") else "text/css",
        )

    router = APIRouter(prefix="/api", dependencies=[Depends(authorize)])

    @router.get("/config/agents")
    async def agent_config():
        return {
            "roles": [cls.role for cls in __import__("mitigata.agents", fromlist=["AGENTS"]).AGENTS],
            "checks": CheckRegistry().public(),
            "llm_requested": bool(startup_scope and startup_scope.ai.enabled),
            "adhoc": allow_adhoc,
            "demo": start_demo,
            "frozen": startup_scope is not None,
        }

    @router.get("/runs")
    async def list_runs():
        return [store.public(r["id"], r) for r in store.runs()]

    @router.post("/runs", status_code=202)
    async def create_run(manifest: ScopeManifest):
        if len(running) >= 2:
            raise HTTPException(409, "At most two concurrent assessments")
        try:
            run_id = await launch(manifest)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return {"run_id": run_id}

    @router.post("/demo", status_code=202)
    async def launch_demo(settings: DemoRequest):
        return {"run_id": await new_demo(settings)}

    @router.post("/quickstart", status_code=202)
    async def quickstart(request: QuickStart):
        if not allow_adhoc:
            raise HTTPException(422, "Ad-hoc IP launch is disabled; start the server with 'serve' (no flags)")
        if len(running) >= 2:
            raise HTTPException(409, "At most two concurrent assessments")
        try:
            manifest = adhoc_manifest(request.ip)
        except (ValueError, ipaddress.AddressValueError) as exc:
            raise HTTPException(422, f"Not a scannable private IPv4 host: {exc}") from None
        try:
            return {"run_id": await launch(manifest, adhoc=True)}
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None

    @router.post("/restart", status_code=202)
    async def restart_frozen_scope():
        if startup_scope is None:
            raise HTTPException(422, "No frozen live scope was configured")
        if running:
            raise HTTPException(409, "An assessment is already active")
        return {"run_id": await launch(startup_scope)}

    @router.get("/runs/{run_id}")
    async def get_run(run_id: str):
        require_run(run_id)
        return build_report(store, run_id)

    @router.get("/runs/{run_id}/progress")
    def progress(run_id: str):
        from .progress import snapshot

        require_run(run_id)
        return snapshot(store, run_id)

    @router.post("/runs/{run_id}/cancel", status_code=202)
    async def cancel_run(run_id: str):
        run = require_run(run_id)
        if run["status"] != "running":
            raise HTTPException(409, "Run is already terminal")
        store.request_cancel(run_id)
        if run_id in engines:
            engines[run_id].broker.cancel()
        return {"status": "cancellation_requested"}

    @router.get("/runs/{run_id}/events")
    async def event_stream(run_id: str, request: Request, after: int = 0):
        require_run(run_id)
        try:
            after = max(after, int(request.headers.get("last-event-id", "0")))
        except ValueError:
            raise HTTPException(422, "Invalid event cursor") from None

        async def generate():
            cursor = after
            while not await request.is_disconnected():
                events = store.public(run_id, store.events(run_id, cursor))
                for event in events:
                    cursor = event["seq"]
                    yield f"id: {cursor}\nevent: update\ndata: {json.dumps(event)}\n\n"
                if store.run(run_id)["status"] != "running" and not events:
                    yield "event: terminal\ndata: {}\n\n"
                    break
                if not events:
                    yield ": heartbeat\n\n"
                await asyncio.sleep(0.3)

        return StreamingResponse(
            generate(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"}
        )

    @router.get("/runs/{run_id}/report.json")
    async def report_json(run_id: str):
        require_run(run_id)
        return build_report(store, run_id)

    @router.get("/runs/{run_id}/report")
    async def get_report(run_id: str, format: Literal["json", "html"] = "json"):
        require_run(run_id)
        report = build_report(store, run_id)
        return HTMLResponse(report_html(report)) if format == "html" else report

    @router.get("/runs/{run_id}/evidence/{evidence_id}")
    async def get_evidence(run_id: str, evidence_id: str):
        require_run(run_id)
        try:
            return evidence.view(run_id, evidence_id.removesuffix(".json"))
        except KeyError:
            raise HTTPException(404, "Unknown evidence") from None
        except ValueError:
            raise HTTPException(409, "Evidence integrity mismatch") from None

    @router.get("/runs/{run_id}/bundle")
    async def bundle(run_id: str):
        require_run(run_id)
        report = build_report(store, run_id)
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("report.html", report_html(report))
            archive.writestr("report.json", json.dumps(report, indent=2))
            for row in report["evidence"]:
                archive.writestr(
                    "evidence/" + row["id"] + ".json", json.dumps(evidence.view(run_id, row["id"]), indent=2)
                )
        return Response(
            output.getvalue(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="mitigata-{run_id}.zip"'},
        )

    @router.post("/runs/{run_id}/flags/export")
    async def export_flags(run_id: str):
        require_run(run_id)
        values = []
        for record in store.records(run_id, "flag"):
            values.append(
                {
                    "status": record["data"]["status"],
                    **store.reveal(run_id, record["data"]["secret_ref"], "Operator"),
                }
            )
        return JSONResponse(
            values, headers={"Content-Disposition": 'attachment; filename="protected-flags.json"'}
        )

    record_kinds = {
        "assets": "asset",
        "services": "service",
        "endpoints": "endpoint",
        "artifacts": "artifact",
        "findings": "finding",
        "verifications": "verification",
        "handoffs": "handoff",
        "briefings": "briefing",
        "falsifications": "verification",
        "flags": "flag",
        "checks": "check",
        "observations": "observation",
        "ai-calls": "ai_call",
        "investigations": "investigation_case",
        "authorities": "authority",
        "decisions": "agent_decision",
    }

    @router.get("/runs/{run_id}/{collection}")
    async def collection(run_id: str, collection: str, offset: int = 0, limit: int = 100):
        require_run(run_id)
        if collection == "metrics":
            from .progress import snapshot

            return snapshot(store, run_id)["metrics"]
        if collection == "graph":
            return store.public(
                run_id,
                {"nodes": store.records(run_id, "graph_node"), "edges": store.records(run_id, "graph_edge")},
            )
        if collection == "agents":
            stats = {
                (r[0], r[1]): r[2]
                for r in store.db.execute(
                    "SELECT role,status,count(*) FROM tasks WHERE run_id=? GROUP BY role,status", (run_id,)
                )
            }
            return [
                {
                    "role": role,
                    "active": stats.get((role, "running"), 0),
                    "completed": stats.get((role, "completed"), 0),
                }
                for role in __import__("mitigata.store", fromlist=["PHASES"]).PHASES
                if role not in {"Arbiter", "Sentinel"}
            ]
        if collection not in record_kinds:
            raise HTTPException(404)
        return store.public(run_id, store.record_page(run_id, record_kinds[collection], offset, limit))

    app.include_router(router)

    @app.get("/targets/{run_id}/findings", dependencies=[Depends(authorize)])
    async def findings_alias(run_id: str):
        require_run(run_id)
        return store.public(run_id, store.records(run_id, "finding"))

    return app

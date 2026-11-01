from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import secrets
import subprocess
from pathlib import Path

from .checks import CheckRegistry
from .config import load_manifest
from .engine import Engine
from .evidence import EvidenceStore
from .lab import LocalLab
from .reporting import build_report, export_report
from .store import Store


def source_fingerprint():
    root = Path(__file__).parent
    digest = hashlib.sha256()
    for path in sorted(
        p for p in root.rglob("*") if p.suffix in {".py", ".yaml", ".txt", ".js", ".html", ".css"}
    ):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()


async def demo(root: Path, *, seed=1, layout="reference", no_flag=False, fixed=False, sharing=True):
    lab = await asyncio.to_thread(LocalLab(root / "lab", seed, layout, no_flag, fixed).start)
    try:
        engine = Engine(root, lab.manifest, sharing=sharing)
        try:
            await engine.run()
            report = build_report(engine.store, engine.run_id)
            evaluation = await asyncio.to_thread(lab.evaluate, report)
            (root / "reports" / engine.run_id / "evaluation.json").write_text(
                json.dumps(evaluation, indent=2), encoding="utf-8"
            )
            return {
                "run_id": engine.run_id,
                "status": report["run"]["status"],
                "metrics": report["metrics"],
                "evaluation": evaluation,
                "report": str((root / "reports" / engine.run_id / "report.html").resolve()),
            }
        finally:
            engine.store.close()
    finally:
        await asyncio.to_thread(lab.close)


async def benchmark(root, seeds):
    results = []
    fingerprint = source_fingerprint()
    for index, seed in enumerate(seeds):
        layout = ("reference", "script", "header", "json")[index % 4]
        result = await demo(root / f"seed-{seed}", seed=seed, layout=layout)
        results.append({"seed": seed, "layout": layout, **result})
        print(
            json.dumps({"seed": seed, "status": result["status"], "evaluation": result["evaluation"]}),
            flush=True,
        )
    negative = await demo(root / "negative", seed=919, no_flag=True)
    fixed = await demo(root / "fixed", seed=920, fixed=True)
    no_sharing = await demo(root / "no-sharing", seed=seeds[0], sharing=False)
    artifact = {
        "source_fingerprint": fingerprint,
        "source_unchanged": fingerprint == source_fingerprint(),
        "scope": "Generated loopback fixture family only; not independent unfamiliar applications or organizer results",
        "runs": results,
        "negative": negative,
        "fixed_counterpart": fixed,
        "sharing_disabled_ablation": no_sharing,
        "independent_packet_observer": "unavailable",
    }
    root.mkdir(parents=True, exist_ok=True)
    (root / "benchmark.json").write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    return artifact


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="mitigata", description="Evidence-first autonomous assessment of explicitly authorized targets"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    demo_parser = sub.add_parser("demo", help="Generate a fresh local lab, assess it and export evidence")
    demo_parser.add_argument("--output", type=Path, default=Path("runtime/demo"))
    demo_parser.add_argument("--seed", type=int, default=1)
    demo_parser.add_argument(
        "--layout", choices=["reference", "script", "header", "json"], default="reference"
    )
    demo_parser.add_argument("--no-flag", action="store_true")
    demo_parser.add_argument("--fixed", action="store_true")
    bench = sub.add_parser("benchmark")
    bench.add_argument("--output", type=Path, default=Path("runtime/benchmark"))
    bench.add_argument("--seeds", default="103,211,307,419,521")
    run = sub.add_parser("run")
    run.add_argument("manifest", type=Path)
    run.add_argument("--output", type=Path, default=Path("runtime/assessment"))
    run.add_argument("--checks", type=Path)
    run.add_argument("--resume", metavar="RUN_ID")
    dry = sub.add_parser("dry-run", help="Validate scope without DNS or any network activity")
    dry.add_argument("manifest", type=Path)
    preflight = sub.add_parser(
        "preflight", help="Validate the scope and read OS routing state without probing"
    )
    preflight.add_argument("manifest", type=Path)
    doctor = sub.add_parser("doctor", help="Check scope, tools and model configuration without target probes")
    doctor.add_argument("manifest", type=Path)
    gateway = sub.add_parser("ai-gateway", help="Private Claude control-plane gateway")
    gateway.add_argument("--port", type=int, default=8090)
    confined = sub.add_parser(
        "confined-run", help="Run the Linux container supervisor with a kernel egress policy"
    )
    confined.add_argument("manifest", type=Path)
    confined.add_argument("--output", type=Path, default=Path("/data"))
    confined.add_argument("--capture", type=Path)
    confined.add_argument("--checks", type=Path)
    confined.add_argument("--dashboard", action="store_true")
    confined.add_argument("--port", type=int, default=8765)
    serve = sub.add_parser("serve")
    serve.add_argument("--output", type=Path, default=Path("runtime/dashboard"))
    serve.add_argument("--port", type=int, default=8765)
    serve.add_argument("--demo", action="store_true")
    serve.add_argument("--manifest", type=Path, help="Start this real assessment with a local live dashboard")
    serve.add_argument("--token-file", type=Path)
    serve.add_argument(
        "--listen-container", action="store_true", help="Bind 0.0.0.0 inside the packaged container"
    )
    report = sub.add_parser("report")
    report.add_argument("run_id")
    report.add_argument("--root", type=Path, default=Path("runtime/demo"))
    flags = sub.add_parser("flags")
    flags.add_argument("run_id")
    flags.add_argument("--root", type=Path, default=Path("runtime/demo"))
    flags.add_argument("--output", type=Path, required=True)
    flags.add_argument("--include-secrets", action="store_true", required=True)
    observer = sub.add_parser("observe", help="Import an independent full-window packet-capture measurement")
    observer.add_argument("run_id")
    observer.add_argument("--root", type=Path, required=True)
    observer.add_argument("--capture", type=Path, required=True)
    observer.add_argument("--metadata", type=Path, required=True)
    observer.add_argument("--log", type=Path, required=True)
    observer.add_argument("--source-address", action="append", required=True)
    observer.add_argument("--infrastructure", action="append", default=[])
    capture = sub.add_parser("capture", help="Run the independent Linux tcpdump observer")
    capture.add_argument("--output", type=Path, default=Path("/capture"))
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            result = asyncio.run(
                demo(args.output, seed=args.seed, layout=args.layout, no_flag=args.no_flag, fixed=args.fixed)
            )
            print(json.dumps(result, indent=2))
            return 0 if result["status"] == "completed" else 1
        if args.command == "benchmark":
            seeds = [int(x) for x in args.seeds.split(",")]
            if not seeds or len(seeds) > 20:
                raise ValueError("Use 1..20 benchmark seeds")
            result = asyncio.run(benchmark(args.output, seeds))
            return 0 if all(r["status"] == "completed" for r in result["runs"]) else 1
        if args.command == "capture":
            from .observer import capture

            return capture(args.output)
        if args.command == "observe":
            from .observer import analyze_capture

            store = Store(args.root / "state.sqlite3")
            try:
                report = build_report(store, args.run_id)
                infrastructure = [
                    (item.rsplit(":", 1)[0].strip("[]"), int(item.rsplit(":", 1)[1]))
                    for item in args.infrastructure
                ]
                result = analyze_capture(
                    args.capture,
                    report,
                    sources=args.source_address,
                    metadata=json.loads(args.metadata.read_text()),
                    log=args.log.read_text(),
                    infrastructure=infrastructure,
                )
                evidence = EvidenceStore(store, args.root / "evidence")
                ref = evidence.capture(
                    args.run_id,
                    json.dumps(result).encode(),
                    kind="independent_capture_measurement",
                    metadata={"capture_sha256": result["capture_sha256"]},
                )
                store.put(args.run_id, "observer", result["capture_sha256"], result, [ref], "Arbiter")
                export_report(store, evidence, args.run_id, args.root / "reports" / args.run_id)
                print(json.dumps(result, indent=2))
                return (
                    0 if result["status"] == "measured" and result["transmitted_scope_violations"] == 0 else 1
                )
            finally:
                store.close()
        if args.command == "ai-gateway":
            import uvicorn

            from .ai_gateway import create_gateway

            uvicorn.run(
                create_gateway(), host="0.0.0.0", port=args.port, log_level="warning", access_log=False
            )
            return 0
        if args.command in {"dry-run", "preflight", "doctor"}:
            manifest = load_manifest(args.manifest)
            from .preflight import plan

            result = plan(manifest, include_routes=args.command == "preflight")
            if args.command == "doctor":
                from .ai import load_local_environment, provider_available
                from .tool_runner import capability

                load_local_environment()
                result["claude"] = {
                    "requested": manifest.ai.enabled,
                    "required": manifest.ai.required,
                    "configured": provider_available(manifest.ai),
                    "model": manifest.ai.model,
                    "shared_budget_usd": manifest.ai.budget_usd,
                }
                result["tools"] = [
                    capability(manifest, name)
                    for name in ("nmap", "katana", "ffuf", "nuclei", "file", "readelf", "objdump")
                ]
            print(json.dumps(result, indent=2))
            if args.command == "doctor" and manifest.ai.required and not result["claude"]["configured"]:
                return 2
            return 0
        if args.command == "confined-run":
            from .confinement import supervise

            return supervise(
                args.manifest,
                args.output,
                args.capture,
                args.checks,
                dashboard=args.dashboard,
                port=args.port,
            )
        if args.command == "run":
            engine = Engine(
                args.output,
                load_manifest(args.manifest),
                checks=CheckRegistry(args.checks),
                run_id=args.resume,
            )
            try:
                asyncio.run(engine.run())
                print(
                    json.dumps(
                        {
                            "run_id": engine.run_id,
                            "status": engine.store.run(engine.run_id)["status"],
                            "report": str(
                                (args.output / "reports" / engine.run_id / "report.html").resolve()
                            ),
                        },
                        indent=2,
                    )
                )
                return 0 if engine.store.run(engine.run_id)["status"] == "completed" else 1
            finally:
                engine.store.close()
        if args.command == "serve":
            import uvicorn

            from .api import create_app

            if args.demo and args.manifest:
                raise ValueError("Choose either the generated demo or a real manifest")
            startup_scope = load_manifest(args.manifest) if args.manifest else None
            if startup_scope and startup_scope.execution_profile == "linux_confined":
                from .confinement import verify_receipt

                verify_receipt(startup_scope)

            args.output.mkdir(parents=True, exist_ok=True)
            token_file = args.token_file or args.output / "operator-token.txt"
            if token_file.exists():
                token = token_file.read_text().strip()
            else:
                token = secrets.token_urlsafe(32)
                token_file.write_text(token, encoding="utf-8")
                os.chmod(token_file, 0o600)
            if len(token) < 24:
                raise ValueError("Operator token is too short")
            # Bare `serve` (no --demo, no --manifest) is the ad-hoc operator console: type an
            # IP and start. --demo and --manifest keep their constrained behaviours.
            allow_adhoc = not args.demo and not args.manifest
            one_click = f"http://127.0.0.1:{args.port}/#token={token}"
            mode = "ad-hoc (type an IP and start)" if allow_adhoc else ("demo" if args.demo else "frozen scope")
            print(
                f"Dashboard [{mode}] — open this (token included, no login step):\n  {one_click}\n"
                f"Operator token file: {token_file.resolve()}",
                flush=True,
            )
            if not args.listen_container:
                import threading
                import webbrowser

                threading.Timer(1.2, lambda: webbrowser.open(one_click)).start()
            uvicorn.run(
                create_app(
                    args.output, token, start_demo=args.demo, startup_scope=startup_scope,
                    allow_adhoc=allow_adhoc,
                ),
                host="0.0.0.0" if args.listen_container else "127.0.0.1",
                port=args.port,
                log_level="warning",
                access_log=False,
            )
            return 0
        if args.command in {"report", "flags"}:
            store = Store(args.root / "state.sqlite3")
            try:
                store.run(args.run_id)
                if args.command == "report":
                    path = export_report(
                        store,
                        EvidenceStore(store, args.root / "evidence"),
                        args.run_id,
                        args.root / "reports" / args.run_id,
                    )
                    print(path.resolve())
                else:
                    rows = []
                    for record in store.records(args.run_id, "flag"):
                        value = store.reveal(args.run_id, record["data"]["secret_ref"], "Operator")
                        rows.append({"status": record["data"]["status"], **value})
                    with args.output.open("x", encoding="utf-8") as stream:
                        json.dump(rows, stream, indent=2)
                    os.chmod(args.output, 0o600)
                    print(f"Protected export written to {args.output.resolve()}")
                return 0
            finally:
                store.close()
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as exc:
        print(f"Mitigata: {exc}")
        return 2
    return 0

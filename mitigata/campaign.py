"""Keep a confined dashboard alive after its run and finalize capture automatically."""

from __future__ import annotations

import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from .config import load_manifest
from .confinement import capture_session, install_policy, namespace_sources, wait_observer


def watch(root, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            path = Path(root) / "state.sqlite3"
            with sqlite3.connect("file:" + path.resolve().as_posix() + "?mode=ro", uri=True, timeout=2) as db:
                row = db.execute("SELECT id,status FROM runs ORDER BY started DESC LIMIT 1").fetchone()
                if (
                    row
                    and row[1] != "running"
                    and db.execute(
                        "SELECT 1 FROM events WHERE run_id=? AND kind='report_bundle_finalized'", (row[0],)
                    ).fetchone()
                ):
                    print(json.dumps({"run_id": row[0], "status": row[1]}), flush=True)
                    return 0
        except (sqlite3.Error, OSError):
            pass
        time.sleep(0.5)
    return 1


def supervise_dashboard(manifest_path, output, capture_root, port):
    manifest = load_manifest(manifest_path)
    if manifest.control_port != port:
        raise ValueError("Dashboard port must match the manifest control_port")
    install_policy(manifest)
    output.mkdir(parents=True, exist_ok=True)
    os.chown(output, 10001, 10001)
    observer = None
    child = None
    watcher = None

    def stop(*args):
        if child and child.poll() is None:
            child.send_signal(signal.SIGINT)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        if capture_root:
            capture_root.mkdir(parents=True, exist_ok=True)
            previous = capture_session(capture_root)
            observer = subprocess.Popen(
                [sys.executable, "-m", "mitigata", "capture", "--output", str(capture_root)]
            )
            session = wait_observer(observer, capture_root, previous)
        child = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "mitigata",
                "serve",
                "--manifest",
                str(manifest_path),
                "--output",
                str(output),
                "--listen-container",
                "--port",
                str(port),
            ],
            user=10001,
            group=10001,
            extra_groups=[],
            umask=0o077,
        )
        watcher = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "mitigata.campaign",
                "--watch",
                str(output),
                str(manifest.budgets.seconds + 150),
            ],
            user=10001,
            group=10001,
            extra_groups=[],
            stdout=subprocess.PIPE,
            text=True,
        )
        while watcher.poll() is None:
            if child.poll() is not None:
                return child.returncode or 1
            time.sleep(0.2)
        result = watcher.communicate()[0]
        if observer:
            observer.terminate()
            observer.wait(timeout=15)
            observer = None
        if watcher.returncode == 0 and capture_root:
            run_id = json.loads(result)["run_id"]
            os.chown(session, 0, 10001)
            os.chmod(session, 0o750)
            for name in ("assessment.pcap", "observer.json", "tcpdump.log"):
                os.chown(session / name, 0, 10001)
                os.chmod(session / name, 0o440)
            command = [
                sys.executable,
                "-m",
                "mitigata",
                "observe",
                run_id,
                "--root",
                str(output),
                "--capture",
                str(session / "assessment.pcap"),
                "--metadata",
                str(session / "observer.json"),
                "--log",
                str(session / "tcpdump.log"),
            ]
            for address in namespace_sources():
                command.extend(["--source-address", address])
            measured = subprocess.run(command, user=10001, group=10001, extra_groups=[], check=False)
            print(
                f"Assessment finalized; packet measurement exit={measured.returncode}. Dashboard remains available.",
                flush=True,
            )
        elif watcher.returncode:
            print("Automatic capture import unavailable; capture retained.", file=sys.stderr, flush=True)
        return child.wait()
    finally:
        if watcher and watcher.poll() is None:
            watcher.terminate()
            watcher.wait(timeout=5)
        if observer and observer.poll() is None:
            observer.terminate()
            observer.wait(timeout=15)
        if child and child.poll() is None:
            stop()
            try:
                child.wait(timeout=30)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


if __name__ == "__main__":
    raise SystemExit(watch(Path(sys.argv[2]), float(sys.argv[3])))

import json
import subprocess
import sys
from pathlib import Path

from mitigata.confinement import supervise


def main():
    root = Path("/results")
    root.mkdir(exist_ok=True)
    result = supervise(Path("/scope/fixture.yaml"), root / "assessment", root / "capture")
    assert result == 0, result
    script = "from pathlib import Path;p=next(Path('/results/assessment/reports').glob('*/report.json'));print(p.read_text())"
    report = json.loads(
        subprocess.check_output(
            [sys.executable, "-c", script], user=10001, group=10001, extra_groups=[], text=True
        )
    )
    assert report["run"]["status"] == "completed"
    assert report["metrics"]["scope_pairs_tested"] == 2 and report["metrics"]["scope_pairs_untested"] == 0
    assert report["metrics"]["confirmed"] == 3
    assert report["metrics"]["captured_flags"] >= 4
    assert report["metrics"]["ai"]["spent_usd"] > 0
    assert report["metrics"]["ai"]["spent_usd"] + report["metrics"]["ai"]["reserved_usd"] <= 0.5
    capabilities = {r["identity"]: r["data"] for r in report["capabilities"]}
    assert capabilities["browser"]["available"], capabilities.get("browser")
    for name in ("nmap", "katana", "ffuf", "nuclei"):
        assert capabilities[name]["live_allowed"] and capabilities[name].get("last_execution") != "failed", (
            capabilities[name]
        )
    assert report["metrics"]["independent_egress_observer"] == "measured"
    assert report["metrics"]["independently_observed_scope_violations"] == 0
    summary = {
        "status": "passed",
        "model_provider": "owned Anthropic-protocol fixture, not paid Claude inference",
        "metrics": report["metrics"],
        "capabilities": capabilities,
        "run_id": report["run"]["id"],
        "observer": report["observer"][-1]["data"],
    }
    (root / "investigation-proof.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
